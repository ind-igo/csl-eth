//! The full-state export, profile §5, for state too large for memory.
//!
//! [`produce_with`](crate::produce_with) takes leaves that each hold their
//! storage, keeps every node in memory and every bytecode in a map. That
//! serves a 1/4096 slice; full mainnet (about 3 × 10^8 accounts, 1.5 × 10^9
//! slots, contracts with tens of millions of slots, path-keyed tables near
//! 180 GB) needs it streamed. [`export`] reads a [`StateSource`] (reth's
//! hashed tables, through an adapter crate) and:
//!
//! 1. **Build.** For each account in ascending hashed-address order it
//!    streams the account's slots into the trie builder and takes the
//!    storage root from the build (the source has none to check it
//!    against), then pushes the account leaf. Every emitted node goes to
//!    the external sorter ([`crate::extsort`]) under its table key and,
//!    unless omitted, under its hash; each non-empty `codeHash` goes to it
//!    as a table of its own. One memory budget covers all of them.
//! 2. **State root.** The account trie's root must be the header's
//!    `state_root`.
//! 3. **Sort.** Each table is made readable and its entry count fixed.
//! 4. **Code.** Every referenced `codeHash` must have bytecode whose
//!    keccak matches.
//! 5. **Write.** Only now is anything written under `root`: the runs in key
//!    order through the `csl-run` writer, code inline up to
//!    [`CODE_BLOB_THRESHOLD`] and as `blobs/<blake3>` above, then the
//!    manifest, then `snapshots/latest`.
//!
//! Any failure before step 5 leaves `root` untouched; a failure during it
//! leaves table files but no manifest for the block (one from an earlier
//! export of the same block is removed before the tables are rewritten) and
//! `latest` as it was. For the same state the files and manifest are byte
//! for byte those of `produce_with` (the run writer is canonical over the
//! sorted entry set), and [`ExportOptions::by_hash`] may omit the
//! content-addressed baseline table, which roughly doubles the output at
//! full state.
//!
//! An export holds no snapshot's worth of anything in memory: one storage
//! trie's open branches, the account trie's, the sort chunk, and one
//! bytecode. Bytecode is read twice (checked, then written), in ascending
//! hash order both times.
//!
//! Storage tries of different accounts are independent. Building them on
//! several threads is the obvious speedup and the interfaces allow it: see
//! [`StateSource`] and the TODO on [`export`].

use crate::extsort::{Budget, Dups, ExtSort, Scratch, SortError, SortStats};
use crate::producer::{write_atomic, Head, TableStats};
use crate::{
    manifest_path, profile_id, snapshot_dir, Manifest, TableRef, CODE_BLOB_THRESHOLD, EPSILON, FORMAT_VERSION, LATEST_FILE, RUN_FORMAT, TABLE_ACCOUNT_NODES, TABLE_CODE, TABLE_COUNT,
    TABLE_FILES, TABLE_NODES_BY_HASH, TABLE_STORAGE_NODES,
};
use crate::{blob_path, AccountLeaf};
use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::KECCAK_EMPTY;
use csl_eth_trie::{code_key, encode_word, path_of, Account, BuildError, Builder, NodeKey, Sink, TooDeep, EMPTY_ROOT, MAX_NODE_BYTES};
use csl_run::{Config, Entry, Writer};
use std::{
    cell::RefCell,
    collections::HashMap,
    convert::Infallible,
    fmt,
    fs::{self, File},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// One account as reth's hashed state holds it: no storage root (the
/// exporter computes it from the slots).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceAccount {
    /// `keccak(address)`.
    pub hashed: B256,
    pub nonce: u64,
    pub balance: U256,
    /// `KECCAK_EMPTY` for an account without code.
    pub code_hash: B256,
}

/// Bytecodes in ascending hash order, for [`StateSource::codes`].
pub type CodeIter<'a, E> = Box<dyn Iterator<Item = Result<(B256, Vec<u8>), E>> + 'a>;

/// The state of one block, as the exporter reads it.
///
/// Every stream must be complete: an error is returned as an item (or from
/// the call that opens the stream) and aborts the export. A stream that
/// ends early without one cannot be told from a smaller state, so an
/// adapter must turn every interruption into an error; the state root
/// check catches the rest.
///
/// The exporter calls [`accounts`](Self::accounts) once, and
/// [`storage`](Self::storage) once per account while that iterator is
/// alive (both borrow `&self`), so it must be cheap for an account without
/// storage. A parallel exporter would call `storage` from several threads
/// for different accounts; an adapter that can serve that should be `Sync`
/// (for reth, a read transaction per thread at the same block).
pub trait StateSource {
    type Error: std::error::Error + Send + Sync + 'static;
    type Accounts<'a>: Iterator<Item = Result<SourceAccount, Self::Error>>
    where
        Self: 'a;
    type Storage<'a>: Iterator<Item = Result<(B256, U256), Self::Error>>
    where
        Self: 'a;

    /// Every account, strictly ascending by hashed address.
    fn accounts(&self) -> Result<Self::Accounts<'_>, Self::Error>;

    /// One account's non-zero slots `(keccak(slot), word)`, strictly
    /// ascending by hashed slot; empty for an account without storage.
    fn storage(&self, hashed: &B256) -> Result<Self::Storage<'_>, Self::Error>;

    /// The bytecode under `code_hash`, if the source has it.
    fn code(&self, code_hash: &B256) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Optionally every bytecode, strictly ascending by hash (it may hold
    /// codes no account references). When given, the exporter merges it
    /// with the referenced hashes instead of looking each one up.
    fn codes(&self) -> Option<Result<CodeIter<'_, Self::Error>, Self::Error>> {
        None
    }
}

/// What the export may vary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportOptions {
    /// The learned index bound for every table, as in `produce_with`.
    pub epsilon: u16,
    /// Write the content-addressed baseline table (`nodes_by_hash`, profile
    /// §9). At full state it roughly doubles the output; without it the
    /// manifest has no table 3 and the client's baseline reads answer
    /// `Insufficient(NoTable(3))`.
    pub by_hash: bool,
    /// Memory for sorting, bytes: one chunk shared by every table while
    /// building, read buffers while merging. Trie builders, the run
    /// writer's model and page, a 4 MiB file buffer and the current
    /// bytecode come on top and are small.
    pub memory_bytes: u64,
    /// Where the scratch directory goes. Spills total about the size of
    /// the tables written, more with intermediate merge passes.
    pub scratch: PathBuf,
    /// How often the progress callback runs during long phases.
    pub progress_every: Duration,
}

impl ExportOptions {
    pub fn new(scratch: impl Into<PathBuf>) -> ExportOptions {
        ExportOptions { epsilon: EPSILON, by_hash: true, memory_bytes: 1 << 30, scratch: scratch.into(), progress_every: Duration::from_secs(10) }
    }
}

/// Where an export is.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Build,
    Sort,
    CheckCode,
    Write(u16),
    Done,
}

/// Progress and the final report. Node counts are nodes pushed to the
/// sorters; table entries are in `sort[t].entries` once sorted and in
/// `tables` once written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportStats {
    pub phase: Phase,
    pub accounts: u64,
    pub storage_slots: u64,
    /// Accounts with at least one slot.
    pub storage_tries: u64,
    /// The most slots in one account, and whose.
    pub largest_storage: (u64, B256),
    /// While a large storage trie is being built: whose, and its slots so
    /// far (not yet in `storage_slots`).
    pub building: (B256, u64),
    /// Accounts with code.
    pub code_refs: u64,
    pub code_entries: u64,
    pub code_blobs: u64,
    pub code_bytes: u64,
    pub account_nodes: u64,
    pub storage_nodes: u64,
    pub embedded: u64,
    /// Per table, the sorter: records, spills, merge passes, bytes spilled.
    pub sort: [SortStats; TABLE_COUNT],
    /// The most chunk memory held at once, bytes.
    pub peak_sort_bytes: u64,
    pub tables: [Option<TableStats>; TABLE_COUNT],
    /// Entries written so far in the current `Write` phase.
    pub written: u64,
    pub build: Duration,
    pub sort_time: Duration,
    pub check_code: Duration,
    pub write: [Duration; TABLE_COUNT],
    pub elapsed: Duration,
}

impl ExportStats {
    pub fn spill_bytes(&self) -> u64 {
        self.sort.iter().map(|s| s.spill_bytes).sum()
    }
}

#[derive(Clone, Debug)]
pub struct Exported {
    pub manifest: Manifest,
    pub stats: ExportStats,
    pub dir: PathBuf,
}

#[derive(Debug)]
pub enum ExportError {
    /// The source failed; `during` says which stream.
    Source { during: String, error: Box<dyn std::error::Error + Send + Sync> },
    UnsortedAccounts { prev: B256, next: B256 },
    UnsortedSlots { owner: B256, prev: B256, next: B256 },
    /// A zero word is an absent slot; the source must not list it.
    ZeroSlot { owner: B256, slot: B256 },
    UnsortedCode { prev: B256, next: B256 },
    Build(BuildError),
    TooDeep(TooDeep),
    NodeTooLarge { key: [u8; 32], len: usize },
    /// The account trie did not hash to the header's `state_root`.
    StateRoot { expected: B256, got: B256 },
    /// A `codeHash` without bytecode, or with bytecode that hashes
    /// differently.
    Code { hash: B256, what: &'static str },
    /// Two entries under one key of a table (a keccak collision), or the
    /// scratch directory failed.
    Sort(SortError),
    Io(io::Error),
    Run(csl_run::Error),
}

impl fmt::Display for ExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExportError::Source { during, error } => write!(f, "source, {during}: {error}"),
            ExportError::UnsortedAccounts { prev, next } => write!(f, "accounts out of order: {prev} then {next}"),
            ExportError::UnsortedSlots { owner, prev, next } => write!(f, "slots of {owner} out of order: {prev} then {next}"),
            ExportError::ZeroSlot { owner, slot } => write!(f, "slot {slot} of {owner} is zero"),
            ExportError::UnsortedCode { prev, next } => write!(f, "bytecodes out of order: {prev} then {next}"),
            ExportError::Build(e) => write!(f, "trie build: {e}"),
            ExportError::TooDeep(e) => write!(f, "{e}"),
            ExportError::NodeTooLarge { key, len } => write!(f, "node {} is {len} bytes", hex::encode(key)),
            ExportError::StateRoot { expected, got } => write!(f, "state root: header says {expected}, the source builds {got}"),
            ExportError::Code { hash, what } => write!(f, "code {hash}: {what}"),
            ExportError::Sort(e) => write!(f, "sort: {e}"),
            ExportError::Io(e) => write!(f, "io: {e}"),
            ExportError::Run(e) => write!(f, "run: {e}"),
        }
    }
}

impl std::error::Error for ExportError {}

impl From<io::Error> for ExportError {
    fn from(e: io::Error) -> Self {
        ExportError::Io(e)
    }
}
impl From<BuildError> for ExportError {
    fn from(e: BuildError) -> Self {
        ExportError::Build(e)
    }
}
impl From<csl_run::Error> for ExportError {
    fn from(e: csl_run::Error) -> Self {
        ExportError::Run(e)
    }
}

impl From<SortError> for ExportError {
    fn from(e: SortError) -> Self {
        ExportError::Sort(e)
    }
}

fn source<E: std::error::Error + Send + Sync + 'static>(during: impl Fn() -> String) -> impl FnOnce(E) -> ExportError {
    move |e| ExportError::Source { during: during(), error: Box::new(e) }
}

/// One sorter for the four tables (indexed by table id), and the first
/// error a build's sink hit, which the builder cannot return.
struct Sorters {
    s: ExtSort,
    err: Option<ExportError>,
}

impl Sorters {
    fn new(dir: &Path, budget: Budget) -> Sorters {
        let mut dups = [Dups::Error; TABLE_COUNT];
        // Code hashes with empty values (many accounts share one code), and
        // nodes by hash (identical subtrees recur).
        dups[TABLE_CODE as usize] = Dups::KeepOne;
        dups[TABLE_NODES_BY_HASH as usize] = Dups::KeepOne;
        Sorters { s: ExtSort::new(dir, budget, &dups), err: None }
    }

    fn push(&mut self, t: u16, key: &[u8; 32], val: &[u8]) {
        if let Err(e) = self.s.push(t as usize, key, val) {
            self.err.get_or_insert(e.into());
        }
    }

    fn take_err(&mut self) -> Result<(), ExportError> {
        match self.err.take() {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    fn sort_stats(&self) -> [SortStats; TABLE_COUNT] {
        std::array::from_fn(|t| self.s.stats(t))
    }
}

/// Receives a build's nodes: the path-keyed table, and by hash.
struct NodeSink<'a> {
    sorters: &'a RefCell<Sorters>,
    /// `None` for the account trie; the owner's hashed address for storage.
    owner: Option<B256>,
    by_hash: bool,
}

impl Sink for NodeSink<'_> {
    fn node(&mut self, key: NodeKey, rlp: &[u8]) {
        self.node_hashed(key, rlp, None)
    }

    fn node_hashed(&mut self, key: NodeKey, rlp: &[u8], hash: Option<B256>) {
        let mut s = self.sorters.borrow_mut();
        if s.err.is_some() {
            return;
        }
        let (table, k) = match self.owner {
            None => (TABLE_ACCOUNT_NODES, key.table_key()),
            Some(owner) => (TABLE_STORAGE_NODES, key.storage_table_key(&owner)),
        };
        let k = match k {
            Ok(k) => k,
            Err(e) => {
                s.err = Some(ExportError::TooDeep(e));
                return;
            }
        };
        if rlp.len() > MAX_NODE_BYTES {
            s.err = Some(ExportError::NodeTooLarge { key: k, len: rlp.len() });
            return;
        }
        s.push(table, &k, rlp);
        if self.by_hash {
            let h = hash.unwrap_or_else(|| keccak256(rlp));
            s.push(TABLE_NODES_BY_HASH, &h.0, rlp);
        }
    }
}

/// Calls the progress callback at most every `every`, checking the clock
/// once per 4,096 calls.
struct Ticker {
    every: Duration,
    last: Instant,
    n: u32,
}

impl Ticker {
    fn due(&mut self) -> bool {
        self.n = self.n.wrapping_add(1);
        self.n & 4095 == 0 && self.due_now()
    }

    fn due_now(&mut self) -> bool {
        if self.last.elapsed() >= self.every {
            self.last = Instant::now();
            true
        } else {
            false
        }
    }
}

/// Bytecode by hash, asked in ascending order: point lookups, or a merge
/// with the source's ordered stream.
enum CodeLookup<'a, S: StateSource + ?Sized> {
    Point(&'a S),
    Ordered { it: CodeIter<'a, S::Error>, peek: Option<(B256, Vec<u8>)>, prev: Option<B256> },
}

impl<'a, S: StateSource + ?Sized> CodeLookup<'a, S> {
    fn new(src: &'a S) -> Result<Self, ExportError> {
        Ok(match src.codes() {
            None => CodeLookup::Point(src),
            Some(it) => CodeLookup::Ordered { it: it.map_err(source(|| "bytecodes".into()))?, peek: None, prev: None },
        })
    }

    fn get(&mut self, hash: &B256) -> Result<Option<Vec<u8>>, ExportError> {
        match self {
            CodeLookup::Point(src) => src.code(hash).map_err(source(|| format!("code {hash}"))),
            CodeLookup::Ordered { it, peek, prev } => loop {
                if peek.is_none() {
                    match it.next() {
                        None => return Ok(None),
                        Some(r) => {
                            let (h, c) = r.map_err(source(|| "bytecodes".into()))?;
                            if let Some(p) = *prev {
                                if h <= p {
                                    return Err(ExportError::UnsortedCode { prev: p, next: h });
                                }
                            }
                            *prev = Some(h);
                            *peek = Some((h, c));
                        }
                    }
                }
                let h = peek.as_ref().expect("filled").0;
                if h < *hash {
                    *peek = None;
                } else if h == *hash {
                    return Ok(peek.take().map(|(_, c)| c));
                } else {
                    return Ok(None);
                }
            },
        }
    }
}

/// The bytecode under `hash`, checked.
fn checked_code<S: StateSource + ?Sized>(look: &mut CodeLookup<'_, S>, hash: &B256) -> Result<Vec<u8>, ExportError> {
    let Some(bytes) = look.get(hash)? else {
        return Err(ExportError::Code { hash: *hash, what: "no bytecode" });
    };
    if code_key(&bytes) != hash.0 {
        return Err(ExportError::Code { hash: *hash, what: "bytecode hashes differently" });
    }
    if bytes.is_empty() {
        return Err(ExportError::Code { hash: *hash, what: "empty bytecode under a non-empty hash" });
    }
    Ok(bytes)
}

/// One account's storage trie, built.
struct StorageBuilt {
    root: B256,
    slots: u64,
    nodes: u64,
    embedded: u64,
}

/// Build one account's storage trie from its slot stream; its nodes go to
/// the sorters. `tick` hears the slot count every 65,536 slots, so a
/// contract with tens of millions of them still reports progress.
///
/// This is the unit a parallel exporter would run per account on worker
/// threads, each with sorters of its own (spills from every worker merge
/// the same way), handing roots back in account order.
fn build_storage<S: StateSource + ?Sized>(src: &S, owner: &B256, sorters: &RefCell<Sorters>, by_hash: bool, tick: &mut dyn FnMut(u64)) -> Result<StorageBuilt, ExportError> {
    let during = || format!("storage of {owner}");
    let slots = src.storage(owner).map_err(source(during))?;
    let mut b: Option<Builder<NodeSink<'_>>> = None;
    let mut prev: Option<B256> = None;
    let mut n = 0u64;
    for item in slots {
        let (slot, word) = item.map_err(source(during))?;
        if let Some(p) = prev {
            if slot <= p {
                return Err(ExportError::UnsortedSlots { owner: *owner, prev: p, next: slot });
            }
        }
        if word.is_zero() {
            return Err(ExportError::ZeroSlot { owner: *owner, slot });
        }
        prev = Some(slot);
        let b = b.get_or_insert_with(|| Builder::new(NodeSink { sorters, owner: Some(*owner), by_hash }));
        b.push(path_of(&slot), encode_word(&word))?;
        n += 1;
        if n & 0xFFFF == 0 {
            // A spill failure deep inside a large contract ends it early.
            sorters.borrow_mut().take_err()?;
            tick(n);
        }
    }
    let Some(b) = b else {
        return Ok(StorageBuilt { root: EMPTY_ROOT, slots: 0, nodes: 0, embedded: 0 });
    };
    let (built, _) = b.finish();
    sorters.borrow_mut().take_err()?;
    Ok(StorageBuilt { root: built.root, slots: n, nodes: built.nodes, embedded: built.embedded })
}

/// Write the snapshot of `head` under `root` from `source`. See the module
/// docs; `progress` runs at each phase change and every
/// `opts.progress_every` within the long ones.
///
/// TODO(parallel): storage tries are built one at a time on this thread.
/// The speedup is a pool of workers over account ranges, each calling
/// [`build_storage`] with its own sorters (spills from every worker merge as
/// one table), the account trie fed in order from their roots. It needs a
/// `Sync` source or one opened per thread.
pub fn export<S: StateSource + ?Sized>(root: &Path, head: &Head, src: &S, opts: &ExportOptions, progress: &mut dyn FnMut(&ExportStats)) -> Result<Exported, ExportError> {
    let t0 = Instant::now();
    let budget = Budget::new(opts.memory_bytes);
    fs::create_dir_all(&opts.scratch)?;
    let scratch = Scratch::new(&opts.scratch)?;
    let sorters = RefCell::new(Sorters::new(scratch.path(), budget));
    let mut stats = ExportStats::default();
    let mut tick = Ticker { every: opts.progress_every, last: Instant::now(), n: 0 };
    let snap = |stats: &mut ExportStats, s: &Sorters| {
        stats.sort = s.sort_stats();
        stats.peak_sort_bytes = s.s.peak_bytes();
        stats.elapsed = t0.elapsed();
    };
    progress(&stats);

    // 1. Build.
    let t = Instant::now();
    let mut account_builder = Builder::new(NodeSink { sorters: &sorters, owner: None, by_hash: opts.by_hash });
    let mut prev: Option<B256> = None;
    for item in src.accounts().map_err(source(|| "accounts".into()))? {
        let a = item.map_err(source(|| "accounts".into()))?;
        if let Some(p) = prev {
            if a.hashed <= p {
                return Err(ExportError::UnsortedAccounts { prev: p, next: a.hashed });
            }
        }
        prev = Some(a.hashed);
        stats.accounts += 1;

        let mut on_slots = |n: u64| {
            if tick.due_now() {
                stats.building = (a.hashed, n);
                stats.build = t.elapsed();
                snap(&mut stats, &sorters.borrow());
                progress(&stats);
            }
        };
        let st = build_storage(src, &a.hashed, &sorters, opts.by_hash, &mut on_slots)?;
        stats.building = (B256::ZERO, 0);
        let (storage_root, slots) = (st.root, st.slots);
        stats.storage_nodes += st.nodes;
        stats.embedded += st.embedded;
        if slots > 0 {
            stats.storage_tries += 1;
            stats.storage_slots += slots;
            if slots > stats.largest_storage.0 {
                stats.largest_storage = (slots, a.hashed);
            }
        }
        if a.code_hash != KECCAK_EMPTY {
            stats.code_refs += 1;
            sorters.borrow_mut().push(TABLE_CODE, &a.code_hash.0, &[]);
        }
        let leaf = Account { nonce: a.nonce, balance: a.balance, storage_root, code_hash: a.code_hash };
        account_builder.push(path_of(&a.hashed), leaf.encode())?;
        sorters.borrow_mut().take_err()?;
        if tick.due() {
            stats.build = t.elapsed();
            snap(&mut stats, &sorters.borrow());
            progress(&stats);
        }
    }

    // 2. State root.
    let (built, _) = account_builder.finish();
    sorters.borrow_mut().take_err()?;
    if built.root != head.state_root {
        return Err(ExportError::StateRoot { expected: head.state_root, got: built.root });
    }
    stats.account_nodes = built.nodes;
    stats.embedded += built.embedded;
    stats.build = t.elapsed();
    stats.phase = Phase::Sort;
    snap(&mut stats, &sorters.borrow());
    progress(&stats);

    // 3. Sort.
    let t = Instant::now();
    let mut sorters = sorters.into_inner();
    sorters.s.prepare()?;
    stats.sort_time = t.elapsed();
    stats.phase = Phase::CheckCode;
    snap(&mut stats, &sorters);
    progress(&stats);

    // 4. Code: every referenced hash has its bytecode.
    let t = Instant::now();
    let mut look = CodeLookup::new(src)?;
    let (mut entries, mut blobs, mut bytes) = (0u64, 0u64, 0u64);
    sorters.s.merge(TABLE_CODE as usize, |k, _| {
        let code = checked_code(&mut look, &B256::from(*k))?;
        entries += 1;
        blobs += u64::from(code.len() > CODE_BLOB_THRESHOLD);
        bytes += code.len() as u64;
        Ok::<(), ExportError>(())
    })?;
    drop(look);
    (stats.code_entries, stats.code_blobs, stats.code_bytes) = (entries, blobs, bytes);
    stats.check_code = t.elapsed();

    // 5. Write.
    let dir = root.join(snapshot_dir(&head.block_hash));
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(root.join("blobs"))?;
    // An earlier export of this block must not name tables that are about
    // to be rewritten: until the new manifest lands there is none.
    let manifest_file = root.join(manifest_path(&head.block_hash));
    match fs::remove_file(&manifest_file) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    if !opts.by_hash {
        // A stale baseline from an earlier export of this block must not
        // sit beside a manifest that does not name it.
        match fs::remove_file(dir.join(TABLE_FILES[TABLE_NODES_BY_HASH as usize])) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    let mut tables = Vec::new();
    let order = [TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES, TABLE_NODES_BY_HASH, TABLE_CODE];
    for table in order {
        if table == TABLE_NODES_BY_HASH && !opts.by_hash {
            continue;
        }
        let count = sorters.s.stats(table as usize).entries;
        if count == 0 {
            continue;
        }
        stats.phase = Phase::Write(table);
        stats.written = 0;
        stats.sort = sorters.sort_stats();
        stats.elapsed = t0.elapsed();
        progress(&stats);
        let t = Instant::now();
        let path = dir.join(TABLE_FILES[table as usize]);
        let mut file = BufFile::new(File::options().read(true).write(true).create(true).truncate(true).open(&path)?, 4 << 20);
        let cfg = Config { profile_id: profile_id(), table_id: table, value_size: 0, epsilon: opts.epsilon };
        let mut w = Writer::with_format(&mut file, cfg, RUN_FORMAT, count)?;
        let mut look = if table == TABLE_CODE { Some(CodeLookup::new(src)?) } else { None };
        let mut written = 0u64;
        sorters
            .s
            .merge(table as usize, |k, v| {
                let e = match look.as_mut() {
                    None => Entry::value(*k, v.to_vec()),
                    Some(look) => {
                        // Read again and checked again: the source must not
                        // change between the passes.
                        let code = checked_code(look, &B256::from(*k))?;
                        if code.len() > CODE_BLOB_THRESHOLD {
                            let h = *blake3::hash(&code).as_bytes();
                            write_atomic(&root.join(blob_path(&h)), &code)?;
                            Entry::blob(*k, h)
                        } else {
                            Entry::value(*k, code)
                        }
                    }
                };
                w.push(e)?;
                written += 1;
                if tick.due() {
                    stats.written = written;
                    stats.elapsed = t0.elapsed();
                    progress(&stats);
                }
                Ok::<(), ExportError>(())
            })?;
        let built = w.finish()?;
        file.flush()?;
        file.f.sync_all()?;
        tables.push(TableRef {
            table_id: table,
            root: built.root,
            page_count: built.page_count,
            entry_count: built.entry_count,
            epsilon_pages: opts.epsilon,
            model_bytes: built.layout.model_bytes as u32,
            model_root: built.model_root,
        });
        stats.tables[table as usize] = Some(TableStats { entries: built.entry_count, pages: built.page_count, model_bytes: built.layout.model_bytes, file_bytes: built.layout.total_len });
        stats.write[table as usize] = t.elapsed();
        stats.written = written;
        stats.sort = sorters.sort_stats();
        sorters.s.clear(table as usize);
    }
    tables.sort_by_key(|t| t.table_id);

    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        profile_id: profile_id(),
        block_hash: head.block_hash,
        block_number: head.block_number,
        timestamp: head.timestamp,
        state_root: head.state_root,
        prefix: String::new(),
        tables,
    };
    write_atomic(&manifest_file, manifest.to_json().as_bytes())?;
    write_atomic(&root.join(LATEST_FILE), hex::encode(head.block_hash).as_bytes())?;
    drop(sorters);
    drop(scratch);
    stats.phase = Phase::Done;
    stats.elapsed = t0.elapsed();
    progress(&stats);
    Ok(Exported { manifest, stats, dir })
}

/// A file with one write buffer and one read buffer, for the run writer:
/// it writes each page with its own seek and `write_all`, and reads them
/// back one by one. Positions are tracked here, so a seek to where the
/// buffer already ends costs no system call. Buffered writes reach the file
/// on `flush` (or a read, or a non-sequential write); dropping it unflushed
/// loses them, which only an aborted run does.
struct BufFile {
    f: File,
    cap: usize,
    pos: u64,
    wbuf: Vec<u8>,
    wstart: u64,
    rbuf: Vec<u8>,
    rstart: u64,
}

impl BufFile {
    fn new(f: File, cap: usize) -> BufFile {
        BufFile { f, cap, pos: 0, wbuf: Vec::with_capacity(cap), wstart: 0, rbuf: Vec::new(), rstart: 0 }
    }

    fn flush_writes(&mut self) -> io::Result<()> {
        if !self.wbuf.is_empty() {
            self.f.seek(SeekFrom::Start(self.wstart))?;
            self.f.write_all(&self.wbuf)?;
            self.wbuf.clear();
        }
        Ok(())
    }
}

impl Write for BufFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.rbuf.clear();
        if !self.wbuf.is_empty() && self.wstart + self.wbuf.len() as u64 != self.pos {
            self.flush_writes()?;
        }
        if self.wbuf.is_empty() {
            self.wstart = self.pos;
        }
        self.wbuf.extend_from_slice(buf);
        self.pos += buf.len() as u64;
        if self.wbuf.len() >= self.cap {
            self.flush_writes()?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_writes()?;
        self.f.flush()
    }
}

impl Read for BufFile {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.flush_writes()?;
        let end = self.rstart + self.rbuf.len() as u64;
        if self.pos < self.rstart || self.pos >= end {
            self.f.seek(SeekFrom::Start(self.pos))?;
            self.rbuf.resize(self.cap, 0);
            let mut n = 0;
            while n < self.cap {
                match self.f.read(&mut self.rbuf[n..]) {
                    Ok(0) => break,
                    Ok(k) => n += k,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
            self.rbuf.truncate(n);
            self.rstart = self.pos;
            if n == 0 {
                return Ok(0);
            }
        }
        let at = (self.pos - self.rstart) as usize;
        let k = out.len().min(self.rbuf.len() - at);
        out[..k].copy_from_slice(&self.rbuf[at..at + k]);
        self.pos += k as u64;
        Ok(k)
    }
}

impl Seek for BufFile {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        self.pos = match to {
            SeekFrom::Start(p) => p,
            SeekFrom::Current(d) => self.pos.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?,
            SeekFrom::End(d) => {
                self.flush_writes()?;
                let len = self.f.seek(SeekFrom::End(0))?;
                len.checked_add_signed(d).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before start"))?
            }
        };
        Ok(self.pos)
    }
}

/// A source over leaves in memory, as `produce_with` takes them (their
/// `storage_root` is ignored: the export computes it). For tests, and to
/// export small states through the same path.
pub struct VecSource<'a> {
    accounts: &'a [AccountLeaf],
    code: &'a HashMap<B256, Vec<u8>>,
    index: HashMap<B256, usize>,
    /// Offer [`StateSource::codes`].
    pub ordered_code: bool,
}

impl<'a> VecSource<'a> {
    pub fn new(accounts: &'a [AccountLeaf], code: &'a HashMap<B256, Vec<u8>>) -> VecSource<'a> {
        let index = accounts.iter().enumerate().map(|(i, a)| (a.hashed, i)).collect();
        VecSource { accounts, code, index, ordered_code: false }
    }
}

type SlotIter<'a> = std::iter::Map<std::slice::Iter<'a, (B256, U256)>, fn(&(B256, U256)) -> Result<(B256, U256), Infallible>>;
type AccountIter<'a> = std::iter::Map<std::slice::Iter<'a, AccountLeaf>, fn(&AccountLeaf) -> Result<SourceAccount, Infallible>>;

impl StateSource for VecSource<'_> {
    type Error = Infallible;
    type Accounts<'b>
        = AccountIter<'b>
    where
        Self: 'b;
    type Storage<'b>
        = SlotIter<'b>
    where
        Self: 'b;

    fn accounts(&self) -> Result<AccountIter<'_>, Infallible> {
        fn f(a: &AccountLeaf) -> Result<SourceAccount, Infallible> {
            Ok(SourceAccount { hashed: a.hashed, nonce: a.account.nonce, balance: a.account.balance, code_hash: a.account.code_hash })
        }
        Ok(self.accounts.iter().map(f as fn(&AccountLeaf) -> _))
    }

    fn storage(&self, hashed: &B256) -> Result<SlotIter<'_>, Infallible> {
        fn f(s: &(B256, U256)) -> Result<(B256, U256), Infallible> {
            Ok(*s)
        }
        let slots: &[(B256, U256)] = self.index.get(hashed).map_or(&[], |&i| &self.accounts[i].storage);
        Ok(slots.iter().map(f as fn(&(B256, U256)) -> _))
    }

    fn code(&self, code_hash: &B256) -> Result<Option<Vec<u8>>, Infallible> {
        Ok(self.code.get(code_hash).cloned())
    }

    fn codes(&self) -> Option<Result<CodeIter<'_, Infallible>, Infallible>> {
        if !self.ordered_code {
            return None;
        }
        let mut all: Vec<(&B256, &Vec<u8>)> = self.code.iter().collect();
        all.sort_by_key(|(h, _)| **h);
        Some(Ok(Box::new(all.into_iter().map(|(h, c)| Ok((*h, c.clone()))))))
    }
}
