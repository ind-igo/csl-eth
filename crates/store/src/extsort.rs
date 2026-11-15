//! An external sort of `(32-byte key, value)` records for several tables
//! under one memory budget, for the full-state export ([`crate::export`]).
//!
//! Records of every table go into one chunk: an arena of `len: u32 ‖ value`
//! bytes and an index of `(key, table, arena offset)`, both allocated once
//! at their full size on the first push and reused after every spill, so a
//! push allocates nothing and the memory held is the budget, not a history
//! of grown and freed buffers (which some allocators keep resident). When
//! either is full the chunk is spilled: the index is sorted by table then
//! key, duplicates are dropped per the table's [`Dups`], and each table's
//! records go to a spill file of its own as `key ‖ len: u32 LE ‖ value`
//! through one large sequential buffer.
//!
//! [`ExtSort::prepare`] makes every table readable: if anything was spilled
//! the rest of the chunk is too and the chunk is freed, then each table's
//! spills are merged in groups of [`Budget::fan_in`] into new spills until
//! one merge can read them all, and the entry count is fixed (the run writer
//! needs it before the first entry). Where duplicates are kept once,
//! counting is a merge of its own; otherwise the count is what was spilled.
//! If nothing was spilled the sorted chunk is read in place.
//! [`ExtSort::merge`] then feeds one table's records in key order.
//!
//! Several sorters can fill in parallel, one per thread, each with its own
//! chunk ([`ExtSort::with_chunk`]) and spill directory; one of them then
//! [`absorb`](ExtSort::absorb)s the others, so each table's spills from every
//! thread merge as one.
//!
//! The scratch directory ([`Scratch`]) is removed when dropped, and
//! [`remove_stale`] clears ones a killed process left behind.

use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    fmt,
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write},
    ops::Range,
    path::{Path, PathBuf},
};

pub const KEY: usize = 32;

/// Prefix of a scratch directory's name.
pub const SCRATCH_PREFIX: &str = "csl-export-";
/// The smallest read buffer per merged spill.
const MIN_READ_BUF: u64 = 64 << 10;
/// The most spills one merge reads at once.
const MAX_FAN_IN: u64 = 1024;
/// Index bytes per buffered record.
pub const INDEX_BYTES: u64 = std::mem::size_of::<Rec>() as u64;
/// The arena's share of the chunk, in thirds. A storage leaf is 70 to 110
/// bytes of RLP and most branches near the leaves are sparse, so a record
/// averages about 90 bytes of arena against 40 of index (measured on the
/// synthetic state of `examples/export_bench.rs`).
const ARENA_THIRDS: u64 = 2;

/// What a memory budget allows each phase.
///
/// Ingest holds the chunk, [`chunk_bytes`](Self::chunk_bytes), and one
/// spill's write buffer. A merge holds one read buffer per spill it reads,
/// [`fan_in`](Self::fan_in) of them within the budget; the chunk is gone by
/// then, or there are no spills to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budget {
    pub bytes: u64,
}

impl Budget {
    pub const fn new(bytes: u64) -> Budget {
        Budget { bytes }
    }

    /// The budget less one write buffer, at least 4 KiB.
    pub const fn chunk_bytes(&self) -> u64 {
        let b = self.bytes.saturating_sub(self.write_buf() as u64);
        if b < 4096 {
            4096
        } else {
            b
        }
    }

    /// Spills one merge reads: buffers of at least 64 KiB, between 2 and
    /// 1,024.
    pub const fn fan_in(&self) -> usize {
        let n = self.bytes / MIN_READ_BUF;
        if n < 2 {
            2
        } else if n > MAX_FAN_IN {
            MAX_FAN_IN as usize
        } else {
            n as usize
        }
    }

    /// The read buffer of each merged spill.
    pub const fn read_buf(&self) -> usize {
        let b = self.bytes / self.fan_in() as u64;
        if b < 4096 {
            4096
        } else {
            b as usize
        }
    }

    /// The write buffer of a spill: a sixteenth of the budget, 4 KiB to
    /// 8 MiB.
    pub const fn write_buf(&self) -> usize {
        let b = self.bytes / 16;
        if b < 4 << 10 {
            4 << 10
        } else if b > 8 << 20 {
            8 << 20
        } else {
            b as usize
        }
    }
}

/// What equal keys within a table mean.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dups {
    /// Keys are unique; a repeat is an error.
    Error,
    /// Equal keys carry equal values (a content-addressed table); one is
    /// kept. Equal keys with different values are an error.
    KeepOne,
}

#[derive(Debug)]
pub enum SortError {
    Io(io::Error),
    Duplicate { table: usize, key: [u8; KEY] },
    /// Two records under one key in a `KeepOne` table with different values.
    Conflict { table: usize, key: [u8; KEY] },
}

impl fmt::Display for SortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SortError::Io(e) => write!(f, "sort scratch: {e}"),
            SortError::Duplicate { table, key } => write!(f, "table {table}: duplicate key {}", hex::encode(key)),
            SortError::Conflict { table, key } => {
                write!(f, "table {table}: key {} with two different values", hex::encode(key))
            }
        }
    }
}

impl std::error::Error for SortError {}

impl From<io::Error> for SortError {
    fn from(e: io::Error) -> Self {
        SortError::Io(e)
    }
}

/// One table's counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SortStats {
    /// Records pushed.
    pub records: u64,
    /// Spill files written in the ingest; 0 when everything fit in memory.
    pub spills: u64,
    /// Intermediate merge passes.
    pub merge_passes: u64,
    /// Bytes written to spill files over every pass.
    pub spill_bytes: u64,
    /// Records in key order after duplicates are dropped (set by `prepare`).
    pub entries: u64,
}

/// A scratch directory `csl-export-<pid>-<ns>` under a parent, removed on
/// drop.
pub struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    pub fn new(parent: &Path) -> io::Result<Scratch> {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos());
        let dir = parent.join(format!("{SCRATCH_PREFIX}{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(Scratch { dir })
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Remove scratch directories a killed export left under `parent`. Call it
/// only when no export is using `parent`. Returns how many were removed.
pub fn remove_stale(parent: &Path) -> usize {
    let Ok(rd) = std::fs::read_dir(parent) else {
        return 0;
    };
    let mut n = 0;
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(SCRATCH_PREFIX) && std::fs::remove_dir_all(e.path()).is_ok() {
            n += 1;
        }
    }
    n
}

/// A buffered record: its key, and its table in the top byte of the arena
/// offset of `len ‖ value`.
#[derive(Clone, Copy)]
struct Rec {
    key: [u8; KEY],
    tagged: u64,
}

const OFF_BITS: u32 = 56;
const OFF_MASK: u64 = (1 << OFF_BITS) - 1;

impl Rec {
    fn table(&self) -> usize {
        (self.tagged >> OFF_BITS) as usize
    }
    fn off(&self) -> usize {
        (self.tagged & OFF_MASK) as usize
    }
}

struct Spill {
    path: PathBuf,
    records: u64,
}

struct Table {
    dups: Dups,
    spills: Vec<Spill>,
    stats: SortStats,
    /// Its records in the sorted chunk, when nothing was spilled.
    range: Range<usize>,
}

pub struct ExtSort {
    dir: PathBuf,
    budget: Budget,
    /// The chunk's size, bytes: `budget.chunk_bytes()` unless set.
    chunk: u64,
    idx: Vec<Rec>,
    arena: Vec<u8>,
    /// The chunk is sorted and free of duplicates.
    settled: bool,
    tables: Vec<Table>,
    next_spill: u64,
    /// Bytes of the chunk in use at its fullest.
    peak: u64,
    /// The peaks of absorbed sorters, which held their chunks beside this one.
    absorbed_peak: u64,
}

impl ExtSort {
    /// A sorter for `dups.len()` tables (at most 255) whose spills go to
    /// `dir` (a [`Scratch`] path) as `t<table>-<n>.spill`.
    pub fn new(dir: &Path, budget: Budget, dups: &[Dups]) -> ExtSort {
        assert!(dups.len() < 256);
        ExtSort {
            dir: dir.to_path_buf(),
            budget,
            chunk: budget.chunk_bytes(),
            idx: Vec::new(),
            arena: Vec::new(),
            settled: true,
            tables: dups.iter().map(|&dups| Table { dups, spills: Vec::new(), stats: SortStats::default(), range: 0..0 }).collect(),
            next_spill: 0,
            peak: 0,
            absorbed_peak: 0,
        }
    }

    /// A sorter whose chunk is `chunk` bytes (at least 4 KiB) while merges
    /// still read with the whole budget: one of several that fill at once
    /// and share the budget, before it absorbs the others.
    pub fn with_chunk(dir: &Path, budget: Budget, chunk: u64, dups: &[Dups]) -> ExtSort {
        let mut s = ExtSort::new(dir, budget, dups);
        s.chunk = chunk.max(4096);
        s
    }

    pub fn stats(&self, table: usize) -> SortStats {
        self.tables[table].stats
    }

    /// Bytes the chunk occupies at its fullest so far, plus the peaks of
    /// the sorters absorbed (their chunks were held at the same time).
    pub fn peak_bytes(&self) -> u64 {
        self.peak.max(self.used_bytes()) + self.absorbed_peak
    }

    fn used_bytes(&self) -> u64 {
        self.idx.len() as u64 * INDEX_BYTES + self.arena.len() as u64
    }

    /// Buffer one record, spilling the chunk first when it is full.
    pub fn push(&mut self, table: usize, key: &[u8; KEY], val: &[u8]) -> Result<(), SortError> {
        self.push_uncounted(table, key, val)?;
        self.tables[table].stats.records += 1;
        Ok(())
    }

    fn push_uncounted(&mut self, table: usize, key: &[u8; KEY], val: &[u8]) -> Result<(), SortError> {
        debug_assert!(table < self.tables.len());
        if self.idx.capacity() == 0 {
            let chunk = self.chunk;
            let arena = chunk / 3 * ARENA_THIRDS;
            self.idx = Vec::with_capacity(((chunk - arena) / INDEX_BYTES).max(1) as usize);
            self.arena = Vec::with_capacity(arena as usize);
        }
        let need = 4 + val.len();
        if self.idx.len() == self.idx.capacity() || self.arena.capacity() - self.arena.len() < need {
            self.peak = self.peak.max(self.used_bytes());
            self.spill()?;
            if self.arena.capacity() < need {
                // A value larger than the whole arena (a tiny budget).
                self.arena.reserve_exact(need);
            }
        }
        let off = self.arena.len() as u64;
        assert!(off <= OFF_MASK, "arena offset above 2^56");
        self.arena.extend_from_slice(&(val.len() as u32).to_le_bytes());
        self.arena.extend_from_slice(val);
        self.idx.push(Rec { key: *key, tagged: (table as u64) << OFF_BITS | off });
        self.settled = false;
        Ok(())
    }

    /// Take over another sorter's records, so that [`prepare`](Self::prepare)
    /// and [`merge`](Self::merge) read them with this one's. If the other
    /// spilled, the rest of its chunk is spilled too and its spill files
    /// become this sorter's (they stay where they are, so give each sorter
    /// a directory of its own); if not, its records are pushed into this
    /// chunk. Its counters add to this one's, and its chunk is freed.
    /// Call before `prepare`, with the same tables.
    pub fn absorb(&mut self, mut other: ExtSort) -> Result<(), SortError> {
        assert_eq!(self.tables.len(), other.tables.len(), "the same tables");
        self.absorbed_peak += other.peak_bytes();
        if other.spilled() {
            other.spill()?;
        } else {
            for r in std::mem::take(&mut other.idx) {
                self.push_uncounted(r.table(), &r.key, Self::val(&other.arena, r.off()))?;
            }
        }
        other.arena = Vec::new();
        for (mine, theirs) in self.tables.iter_mut().zip(&mut other.tables) {
            mine.spills.append(&mut theirs.spills);
            let (a, b) = (&mut mine.stats, theirs.stats);
            a.records += b.records;
            a.spills += b.spills;
            a.merge_passes += b.merge_passes;
            a.spill_bytes += b.spill_bytes;
        }
        Ok(())
    }

    fn val(arena: &[u8], off: usize) -> &[u8] {
        let len = u32::from_le_bytes(arena[off..off + 4].try_into().expect("4 bytes")) as usize;
        &arena[off + 4..off + 4 + len]
    }

    /// Sort the chunk by table then key, drop repeated keys, and note each
    /// table's range.
    fn settle(&mut self) -> Result<(), SortError> {
        if self.settled {
            return Ok(());
        }
        self.idx.sort_unstable_by(|a, b| (a.tagged >> OFF_BITS).cmp(&(b.tagged >> OFF_BITS)).then_with(|| a.key.cmp(&b.key)));
        let mut w = 0usize;
        for r in 0..self.idx.len() {
            let cur = self.idx[r];
            if w > 0 && self.idx[w - 1].key == cur.key && self.idx[w - 1].table() == cur.table() {
                let table = cur.table();
                match self.tables[table].dups {
                    Dups::Error => return Err(SortError::Duplicate { table, key: cur.key }),
                    Dups::KeepOne => {
                        if Self::val(&self.arena, self.idx[w - 1].off()) != Self::val(&self.arena, cur.off()) {
                            return Err(SortError::Conflict { table, key: cur.key });
                        }
                        continue;
                    }
                }
            }
            self.idx[w] = cur;
            w += 1;
        }
        self.idx.truncate(w);
        for (t, table) in self.tables.iter_mut().enumerate() {
            let lo = self.idx.partition_point(|r| r.table() < t);
            let hi = self.idx.partition_point(|r| r.table() <= t);
            table.range = lo..hi;
        }
        self.settled = true;
        Ok(())
    }

    fn spill_path(&mut self, table: usize) -> PathBuf {
        let p = self.dir.join(format!("t{table}-{}.spill", self.next_spill));
        self.next_spill += 1;
        p
    }

    /// Sort the chunk and write each table's part to a new spill. The
    /// chunk's buffers are kept for the next records.
    pub fn spill(&mut self) -> Result<(), SortError> {
        self.settle()?;
        for t in 0..self.tables.len() {
            let range = self.tables[t].range.clone();
            if range.is_empty() {
                continue;
            }
            let path = self.spill_path(t);
            let mut w = SpillWriter::create(&path, self.budget.write_buf())?;
            for r in &self.idx[range] {
                w.write(&r.key, Self::val(&self.arena, r.off()))?;
            }
            let table = &mut self.tables[t];
            table.stats.spill_bytes += w.bytes;
            table.spills.push(w.finish(path)?);
            table.stats.spills += 1;
        }
        for t in &mut self.tables {
            t.range = 0..0;
        }
        self.idx.clear();
        self.arena.clear();
        Ok(())
    }

    fn spilled(&self) -> bool {
        self.tables.iter().any(|t| !t.spills.is_empty())
    }

    /// Make every table readable in key order and fix its entry count.
    pub fn prepare(&mut self) -> Result<(), SortError> {
        self.peak = self.peak.max(self.used_bytes());
        if !self.spilled() {
            self.settle()?;
            for t in &mut self.tables {
                t.stats.entries = t.range.len() as u64;
            }
            return Ok(());
        }
        self.spill()?;
        self.idx = Vec::new();
        self.arena = Vec::new();
        let fan_in = self.budget.fan_in();
        for t in 0..self.tables.len() {
            while self.tables[t].spills.len() > fan_in {
                let old = std::mem::take(&mut self.tables[t].spills);
                for group in old.chunks(fan_in) {
                    let path = self.spill_path(t);
                    let mut w = SpillWriter::create(&path, self.budget.write_buf())?;
                    let srcs = open(group, self.budget.read_buf())?;
                    merge::<SortError>(srcs, t, self.tables[t].dups, |k, v| w.write(k, v).map_err(SortError::Io))?;
                    self.tables[t].stats.spill_bytes += w.bytes;
                    self.tables[t].spills.push(w.finish(path)?);
                    for s in group {
                        let _ = std::fs::remove_file(&s.path);
                    }
                }
                self.tables[t].stats.merge_passes += 1;
            }
            let entries = match self.tables[t].dups {
                // Each spill is free of repeats; a repeat across spills is
                // found by the final merge, which then fails.
                Dups::Error => self.tables[t].spills.iter().map(|s| s.records).sum(),
                Dups::KeepOne => self.merge::<SortError>(t, |_, _| Ok(()))?,
            };
            self.tables[t].stats.entries = entries;
        }
        Ok(())
    }

    /// One table's records in key order, once per key. Call after
    /// [`prepare`](Self::prepare). Returns how many were emitted.
    pub fn merge<E: From<SortError>>(&self, table: usize, emit: impl FnMut(&[u8; KEY], &[u8]) -> Result<(), E>) -> Result<u64, E> {
        debug_assert!(self.settled, "prepare first");
        let t = &self.tables[table];
        let srcs = if t.spills.is_empty() {
            vec![Src::Mem { idx: &self.idx[t.range.clone()], arena: &self.arena, at: 0 }]
        } else {
            open(&t.spills, self.budget.read_buf()).map_err(SortError::Io)?
        };
        merge(srcs, table, t.dups, emit)
    }

    /// Remove a table's spills once it is written.
    pub fn clear(&mut self, table: usize) {
        for s in self.tables[table].spills.drain(..) {
            let _ = std::fs::remove_file(&s.path);
        }
    }
}

impl Drop for ExtSort {
    fn drop(&mut self) {
        for t in 0..self.tables.len() {
            self.clear(t);
        }
    }
}

struct SpillWriter {
    w: BufWriter<File>,
    records: u64,
    bytes: u64,
}

impl SpillWriter {
    fn create(path: &Path, buf: usize) -> io::Result<SpillWriter> {
        Ok(SpillWriter { w: BufWriter::with_capacity(buf, File::create(path)?), records: 0, bytes: 0 })
    }

    fn write(&mut self, key: &[u8; KEY], val: &[u8]) -> io::Result<()> {
        self.w.write_all(key)?;
        self.w.write_all(&(val.len() as u32).to_le_bytes())?;
        self.w.write_all(val)?;
        self.records += 1;
        self.bytes += (KEY + 4 + val.len()) as u64;
        Ok(())
    }

    fn finish(self, path: PathBuf) -> io::Result<Spill> {
        let records = self.records;
        self.w.into_inner().map_err(|e| e.into_error())?;
        Ok(Spill { path, records })
    }
}

/// A merge input: the sorted chunk's part for one table, or a spill file.
enum Src<'a> {
    Mem { idx: &'a [Rec], arena: &'a [u8], at: usize },
    File { r: BufReader<File>, left: u64, key: [u8; KEY], val: Vec<u8> },
}

impl Src<'_> {
    /// Load the next record; `false` at the end.
    fn advance(&mut self, first: bool) -> io::Result<bool> {
        match self {
            Src::Mem { idx, at, .. } => {
                if !first {
                    *at += 1;
                }
                Ok(*at < idx.len())
            }
            Src::File { r, left, key, val } => {
                if *left == 0 {
                    return Ok(false);
                }
                *left -= 1;
                r.read_exact(key)?;
                let mut len = [0u8; 4];
                r.read_exact(&mut len)?;
                val.resize(u32::from_le_bytes(len) as usize, 0);
                r.read_exact(val)?;
                Ok(true)
            }
        }
    }

    fn key(&self) -> &[u8; KEY] {
        match self {
            Src::Mem { idx, at, .. } => &idx[*at].key,
            Src::File { key, .. } => key,
        }
    }

    fn val(&self) -> &[u8] {
        match self {
            Src::Mem { idx, arena, at } => ExtSort::val(arena, idx[*at].off()),
            Src::File { val, .. } => val,
        }
    }
}

fn open<'a>(spills: &[Spill], buf: usize) -> io::Result<Vec<Src<'a>>> {
    spills
        .iter()
        .map(|s| Ok(Src::File { r: BufReader::with_capacity(buf, File::open(&s.path)?), left: s.records, key: [0; KEY], val: Vec::new() }))
        .collect()
}

/// k-way merge by key. Equal keys across sources follow `dups`.
fn merge<E: From<SortError>>(mut srcs: Vec<Src<'_>>, table: usize, dups: Dups, mut emit: impl FnMut(&[u8; KEY], &[u8]) -> Result<(), E>) -> Result<u64, E> {
    let mut heap: BinaryHeap<Reverse<([u8; KEY], usize)>> = BinaryHeap::with_capacity(srcs.len());
    for (i, s) in srcs.iter_mut().enumerate() {
        if s.advance(true).map_err(SortError::Io)? {
            heap.push(Reverse((*s.key(), i)));
        }
    }
    let mut last: Option<[u8; KEY]> = None;
    let mut last_val: Vec<u8> = Vec::new();
    let mut n = 0u64;
    while let Some(Reverse((key, i))) = heap.pop() {
        let s = &mut srcs[i];
        if last == Some(key) {
            match dups {
                Dups::Error => return Err(SortError::Duplicate { table, key }.into()),
                Dups::KeepOne => {
                    if s.val() != last_val.as_slice() {
                        return Err(SortError::Conflict { table, key }.into());
                    }
                }
            }
        } else {
            emit(&key, s.val())?;
            n += 1;
            last = Some(key);
            if dups == Dups::KeepOne {
                last_val.clear();
                last_val.extend_from_slice(s.val());
            }
        }
        if s.advance(false).map_err(SortError::Io)? {
            heap.push(Reverse((*s.key(), i)));
        }
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn rng(seed: &mut u64) -> u64 {
        // xorshift64*
        *seed ^= *seed >> 12;
        *seed ^= *seed << 25;
        *seed ^= *seed >> 27;
        seed.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    type Recs = Vec<([u8; KEY], Vec<u8>)>;

    fn records(n: usize, seed: u64, key_space: u64) -> Recs {
        let mut s = seed | 1;
        (0..n)
            .map(|_| {
                let k = rng(&mut s) % key_space;
                let mut key = [0u8; KEY];
                key[..8].copy_from_slice(&k.to_be_bytes());
                key[31] = (k % 251) as u8;
                // The value is a function of the key, so repeats agree.
                let len = (k % 700) as usize;
                let val: Vec<u8> = (0..len).map(|j| (k as usize + j) as u8).collect();
                (key, val)
            })
            .collect()
    }

    /// Push `tables[t]` interleaved, sort, read every table back.
    fn run(tables: &[(Dups, &Recs)], budget: u64) -> Result<(Vec<Recs>, Vec<SortStats>), SortError> {
        let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
        let dir = scratch.path().to_path_buf();
        let dups: Vec<Dups> = tables.iter().map(|t| t.0).collect();
        let mut s = ExtSort::new(&dir, Budget::new(budget), &dups);
        let longest = tables.iter().map(|t| t.1.len()).max().unwrap_or(0);
        let r = (|| {
            for i in 0..longest {
                for (t, (_, recs)) in tables.iter().enumerate() {
                    if let Some((k, v)) = recs.get(i) {
                        s.push(t, k, v)?;
                    }
                }
            }
            s.prepare()?;
            let largest = tables.iter().flat_map(|t| t.1.iter()).map(|r| r.1.len() as u64 + 4 + INDEX_BYTES).max().unwrap_or(0);
            assert!(s.peak_bytes() <= Budget::new(budget).chunk_bytes().max(largest), "chunk within the budget");
            let mut out = Vec::new();
            for t in 0..tables.len() {
                let mut got = Vec::new();
                let n = s.merge::<SortError>(t, |k, v| {
                    got.push((*k, v.to_vec()));
                    Ok(())
                })?;
                assert_eq!(n, s.stats(t).entries, "the count fixed by prepare is what the merge emits");
                out.push(got);
            }
            Ok((out, (0..tables.len()).map(|t| s.stats(t)).collect()))
        })();
        drop(s);
        drop(scratch);
        assert!(!dir.exists(), "scratch removed on drop");
        r
    }

    fn expected(recs: &Recs) -> Recs {
        let m: BTreeMap<[u8; KEY], Vec<u8>> = recs.iter().cloned().collect();
        m.into_iter().collect()
    }

    #[test]
    fn in_memory_spilled_and_multi_pass_agree_with_a_sort() {
        // Unique keys in one table, repeating keys in another, the same
        // keys in both (tables never mix).
        let a = records(20_000, 7, u64::MAX);
        let b = records(8_000, 11, 1_500);
        let (wa, wb) = (expected(&a), expected(&b));
        assert_eq!(wa.len(), a.len());
        assert!(wb.len() < b.len());
        let c = a[..3000].to_vec();
        for budget in [1 << 30, 4 << 20, 256 << 10, 32 << 10] {
            let (got, st) = run(&[(Dups::Error, &a), (Dups::KeepOne, &b), (Dups::KeepOne, &c)], budget).unwrap();
            assert!(got[0] == wa, "budget {budget}");
            assert!(got[1] == wb, "budget {budget}");
            assert!(got[2] == expected(&c), "budget {budget}");
            eprintln!("budget {budget}: {st:?}");
            if budget == 1 << 30 {
                assert!(st.iter().all(|s| s.spills == 0));
            }
            if budget == 32 << 10 {
                // Fan-in 2 with many spills: several intermediate passes.
                assert!(st[0].spills > 2 && st[0].merge_passes >= 2, "{st:?}");
            }
        }
    }

    #[test]
    fn repeats_are_errors_where_keys_are_unique() {
        let mut recs = records(5_000, 3, u64::MAX);
        recs.push(recs[17].clone());
        // In one chunk, and across spills.
        for budget in [1 << 30, 16 << 10] {
            let r = run(&[(Dups::Error, &recs)], budget);
            assert!(matches!(r, Err(SortError::Duplicate { table: 0, key }) if key == recs[17].0), "budget {budget}");
        }
        // KeepOne with a different value under a repeated key.
        let mut recs = records(5_000, 3, u64::MAX);
        let mut bad = recs[9].clone();
        bad.1.push(1);
        recs.push(bad);
        for budget in [1 << 30, 16 << 10] {
            let r = run(&[(Dups::Error, &records(10, 1, u64::MAX)), (Dups::KeepOne, &recs)], budget);
            assert!(matches!(r, Err(SortError::Conflict { table: 1, .. })), "budget {budget}");
        }
    }

    #[test]
    fn absorbed_sorters_merge_as_one() {
        // Records dealt round-robin to four sorters, some of which spill and
        // some not; the KeepOne table repeats keys across sorters.
        let a = records(12_000, 21, u64::MAX);
        let b = records(6_000, 23, 900);
        let scratch = Scratch::new(&std::env::temp_dir()).unwrap();
        let dups = [Dups::Error, Dups::KeepOne];
        for (chunks, budget) in [([16 << 20; 4], 1 << 30), ([24 << 10, 1 << 20, 8 << 10, 1 << 20], 64 << 10), ([8 << 10; 4], 16 << 10)] {
            let dirs: Vec<PathBuf> = (0..4).map(|k| scratch.path().join(format!("w{k}-{budget}"))).collect();
            let mut sorters: Vec<ExtSort> = dirs
                .iter()
                .zip(chunks)
                .map(|(d, c)| {
                    std::fs::create_dir_all(d).unwrap();
                    ExtSort::with_chunk(d, Budget::new(budget), c, &dups)
                })
                .collect();
            for (i, (k, v)) in a.iter().enumerate() {
                sorters[i % 4].push(0, k, v).unwrap();
            }
            for (i, (k, v)) in b.iter().enumerate() {
                sorters[(i * 7) % 4].push(1, k, v).unwrap();
            }
            let mut rest = sorters.split_off(1);
            let mut main = sorters.pop().unwrap();
            let peaks: u64 = rest.iter().map(|s| s.peak_bytes()).sum::<u64>() + main.peak_bytes();
            for s in rest.drain(..) {
                main.absorb(s).unwrap();
            }
            main.prepare().unwrap();
            assert!(main.peak_bytes() >= peaks && main.peak_bytes() <= chunks.iter().sum::<u64>() + 2 * INDEX_BYTES + 1404, "peaks add up");
            for (t, want) in [(0, expected(&a)), (1, expected(&b))] {
                let mut got = Vec::new();
                let n = main
                    .merge::<SortError>(t, |k, v| {
                        got.push((*k, v.to_vec()));
                        Ok(())
                    })
                    .unwrap();
                assert!(got == want, "table {t}, chunks {chunks:?}");
                assert_eq!(n, main.stats(t).entries);
                assert_eq!(main.stats(t).records, if t == 0 { a.len() } else { b.len() } as u64);
            }
            if budget == 1 << 30 {
                assert_eq!(main.stats(0).spills + main.stats(1).spills, 0, "in memory throughout");
            } else {
                assert!(main.stats(0).spills > 4);
            }
            // A repeat across sorters in a unique-key table is still found.
            let mut x = ExtSort::with_chunk(&dirs[0], Budget::new(budget), chunks[0], &dups);
            let mut y = ExtSort::with_chunk(&dirs[1], Budget::new(budget), chunks[1], &dups);
            for (k, v) in &a[..2000] {
                x.push(0, k, v).unwrap();
            }
            y.push(0, &a[1500].0, &a[1500].1).unwrap();
            x.absorb(y).unwrap();
            let r = x.prepare().and_then(|_| x.merge::<SortError>(0, |_, _| Ok(())));
            assert!(matches!(r, Err(SortError::Duplicate { table: 0, key }) if key == a[1500].0), "chunks {chunks:?}");
        }
    }

    #[test]
    fn empty_tables_and_stale_scratch() {
        let none = Recs::new();
        let one = records(1, 5, u64::MAX);
        let (got, st) = run(&[(Dups::KeepOne, &none), (Dups::Error, &one)], 1 << 20).unwrap();
        assert!(got[0].is_empty() && got[1] == one);
        assert_eq!((st[0].entries, st[1].entries, st[1].spills), (0, 1, 0));
        // A table with nothing in it beside one that spills.
        let many = records(3_000, 9, u64::MAX);
        let (got, st) = run(&[(Dups::Error, &many), (Dups::KeepOne, &none)], 16 << 10).unwrap();
        assert!(st[0].spills > 1 && got[0] == expected(&many) && got[1].is_empty());
        // A value larger than a tiny arena.
        let big = vec![([1u8; KEY], vec![7u8; 5000])];
        let (got, _) = run(&[(Dups::Error, &big), (Dups::Error, &one)], 4096).unwrap();
        assert!(got[0] == big);

        let parent = std::env::temp_dir().join(format!("csl-extsort-stale-{}", std::process::id()));
        std::fs::create_dir_all(parent.join(format!("{SCRATCH_PREFIX}1-2"))).unwrap();
        std::fs::write(parent.join(format!("{SCRATCH_PREFIX}1-2/x.spill")), b"x").unwrap();
        std::fs::create_dir_all(parent.join("keep")).unwrap();
        assert_eq!(remove_stale(&parent), 1);
        assert!(parent.join("keep").exists());
        std::fs::remove_dir_all(&parent).unwrap();
    }
}
