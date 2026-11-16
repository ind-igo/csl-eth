//! The tracker (`csl-eth track`): keeps a bucket's state current with no node
//! and no RPC, one layer per verified attested head
//! (`docs/delta-producer.md`).
//!
//! It holds the published state locally: the base's runs (the bucket's
//! files, copied once) and every layer since, read by position like the
//! client reads them. Each step takes the newest head the beacon light
//! client verifies, and diffs that head's state trie against the state it
//! holds, from the root down. A child whose reference at a path equals the
//! one held at the same path is the same subtree and is skipped; anything
//! else is fetched from mainnet peers with snap/1 `GetTrieNodes`, checked
//! by hash against its parent, and written to the step's layer. A changed
//! account leads into its storage trie by owner; a new code hash is
//! fetched with `GetByteCodes`. The step is complete when no reference is
//! unresolved, which makes the layer the new root's trie by construction:
//! the old state need not be the new one's ancestor, so a reorg or a
//! backlog is just a bigger diff.
//!
//! Peers serve roots from about the last 128 blocks. A step that runs out
//! of time gives up its root, keeps every node it fetched (they are named
//! by hash, so they serve any later root that has them) and starts again at
//! the newest head: a re-pivot.
//!
//! A step is published only after its changed accounts, a sample of its
//! changed slots and its new code read back through the client over the
//! local files at the new root. Layers are merged in tiers (`fanout` of a
//! tier make one of the next, the top tier is one run since the base), so
//! a reader asks a bounded number of runs.

use crate::{
    heal::{self, shape, Fetch, Group, Need, Pool, Ref, Shape},
    produce::{Program, Publish},
};
use alloy_primitives::{keccak256, Bytes, B256, U256};
use clap::Args as ClapArgs;
use csl_eth_client::{DirDriver, Read, Snapshot};
use csl_eth_head::{
    fetch::{named_of, Beacon},
    paths, verify_tier, Chain, DirSource, HeadSource, Tier, VerifiedHead,
};
use csl_eth_store::{
    blob_path, layer_sorter, manifest_path, merge_layers, write_layer_sorted,
    write_layered_manifest, Head, Layer, LayerRows, Manifest, CODE_BLOB_THRESHOLD, EPSILON,
    LATEST_FILE, RUN_FORMAT, SORT_ACCOUNT, SORT_STORAGE, TABLE_ACCOUNT_NODES, TABLE_CODE,
    TABLE_STORAGE_NODES,
};
use csl_eth_trie::{decode_word, Account, Nibbles, NodeKey, EMPTY_ROOT, KECCAK_EMPTY};
use csl_run::Reader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fs::{self, File},
    io::{Read as _, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

// ---------------------------------------------------------------------------
// Owners by storage root

/// Owners by storage root, so a storage trie another owner already holds
/// is copied locally, not fetched: `roots.idx`, built from the held
/// state's account leaves (40-byte records, the root's first eight bytes
/// then the owner, sorted), and `roots.log`, the tries steps have created
/// since (root ‖ owner). A hit is a lead the caller checks against the
/// store; a stale one costs a lookup.
pub struct RootIndex {
    file: Option<(File, u64)>,
    recent: HashMap<B256, B256>,
    log: File,
}

const ROOT_REC: u64 = 40;
/// Owners tried per root.
const ROOT_TRIES: usize = 4;

impl RootIndex {
    pub fn open(dir: &Path) -> Result<RootIndex, String> {
        let file = match File::open(dir.join("roots.idx")) {
            Ok(f) => {
                let n = f.metadata().map_err(|e| e.to_string())?.len() / ROOT_REC;
                Some((f, n))
            }
            Err(_) => None,
        };
        let lp = dir.join("roots.log");
        let mut recent = HashMap::new();
        if let Ok(b) = fs::read(&lp) {
            for r in b.chunks_exact(64) {
                recent.insert(B256::from_slice(&r[..32]), B256::from_slice(&r[32..]));
            }
        }
        let log = File::options()
            .create(true)
            .append(true)
            .open(&lp)
            .map_err(|e| format!("{}: {e}", lp.display()))?;
        Ok(RootIndex { file, recent, log })
    }

    /// Indexed owners and tries noted since.
    pub fn len(&self) -> (u64, usize) {
        (self.file.as_ref().map_or(0, |f| f.1), self.recent.len())
    }

    /// Owners that had storage root `r`, the newest first.
    pub fn find(&mut self, r: &B256) -> Result<Vec<B256>, String> {
        use std::os::unix::fs::FileExt;
        let mut out: Vec<B256> = self.recent.get(r).copied().into_iter().collect();
        let Some((f, n)) = &self.file else {
            return Ok(out);
        };
        let want = &r[..8];
        let read = |i: u64| -> Result<[u8; 40], String> {
            let mut b = [0u8; 40];
            f.read_exact_at(&mut b, i * ROOT_REC)
                .map_err(|e| format!("roots.idx: {e}"))?;
            Ok(b)
        };
        let (mut lo, mut hi) = (0u64, *n);
        while lo < hi {
            let mid = (lo + hi) / 2;
            if &read(mid)?[..8] < want {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        while lo < *n && out.len() < ROOT_TRIES {
            let b = read(lo)?;
            if &b[..8] != want {
                break;
            }
            let o = B256::from_slice(&b[8..]);
            if !out.contains(&o) {
                out.push(o);
            }
            lo += 1;
        }
        Ok(out)
    }

    /// A storage trie created with root `r` under `owner`.
    pub fn note(&mut self, r: B256, owner: B256) -> Result<(), String> {
        if self.recent.insert(r, owner) == Some(owner) {
            return Ok(());
        }
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(r.as_slice());
        b[32..].copy_from_slice(owner.as_slice());
        self.log
            .write_all(&b)
            .map_err(|e| format!("roots.log: {e}"))
    }
}

/// Build `dir/roots.idx` from every account leaf with storage in the
/// account runs of `manifest` under `root`. Returns the records written.
pub fn build_root_index(
    root: &Path,
    manifest: &Manifest,
    dir: &Path,
    budget: u64,
) -> Result<u64, String> {
    use csl_eth_store::extsort::{Budget, Dups, ExtSort, Scratch};
    let scratch = Scratch::new(dir).map_err(|e| format!("scratch: {e}"))?;
    let mut sort = ExtSort::new(scratch.path(), Budget::new(budget), &[Dups::KeepOne]);
    for at in manifest.runs(TABLE_ACCOUNT_NODES) {
        let f = File::open(root.join(&at.path)).map_err(|e| format!("{}: {e}", at.path))?;
        let mut rref = at.table.run_ref(at.block_lo);
        rref.block_hi = at.block_hi;
        let mut r = Reader::try_with_format(f, rref, RUN_FORMAT).map_err(|e| e.to_string())?;
        r.prepare().map_err(|e| e.to_string())?;
        for page in 1..=at.table.page_count {
            let p = r
                .fetch_page(page)
                .map_err(|e| format!("{}: {e}", at.path))?;
            for e in p.entries {
                if e.tag != 0 {
                    continue;
                }
                let depth = (e.key[31] as usize).min(62);
                let path = Nibbles::unpack(&e.key[..31]).slice(..depth);
                let Ok(Shape::Leaf { key, value }) = shape(&path, &e.value) else {
                    continue;
                };
                if key.len() != 64 {
                    continue;
                }
                let Ok(a) = Account::decode(&value) else {
                    continue;
                };
                if a.storage_root == EMPTY_ROOT {
                    continue;
                }
                let owner = key.pack();
                let mut k = [0u8; 32];
                k[..24].copy_from_slice(&a.storage_root[..24]);
                k[24..].copy_from_slice(&owner[..8]);
                sort.push(0, &k, &owner)
                    .map_err(|e| format!("root index: {e}"))?;
            }
        }
    }
    sort.prepare().map_err(|e| format!("root index: {e}"))?;
    let tmp = dir.join("roots.idx.tmp");
    let mut w = std::io::BufWriter::new(File::create(&tmp).map_err(|e| e.to_string())?);
    let n = sort
        .merge::<csl_eth_store::extsort::SortError>(0, |k, v| {
            w.write_all(&k[..8])?;
            w.write_all(v)?;
            Ok(())
        })
        .map_err(|e| format!("root index: {e}"))?;
    w.flush().map_err(|e| e.to_string())?;
    drop(w);
    fs::rename(&tmp, dir.join("roots.idx")).map_err(|e| e.to_string())?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// The local store

/// The published state on local disk: per table, every run (the base's and
/// each layer's), newest first. A position's node is the candidate that
/// hashes to what its parent committed to, as in the client.
pub struct Store {
    runs: [Vec<Reader<File>>; 3],
    pub lookups: u64,
}

fn table_index(t: u16) -> usize {
    match t {
        TABLE_ACCOUNT_NODES => 0,
        TABLE_STORAGE_NODES => 1,
        _ => 2,
    }
}

impl Store {
    /// The runs `manifest` names, under `root`.
    pub fn open(root: &Path, manifest: &Manifest) -> Result<Store, String> {
        Store::open_with(root, manifest, true)
    }

    /// The runs `manifest` names, under `root`; the base's only when
    /// `base` (a tracker without a local base reads it by range, see
    /// [`crate::remote`]).
    pub fn open_with(root: &Path, manifest: &Manifest, base: bool) -> Result<Store, String> {
        let mut runs: [Vec<Reader<File>>; 3] = Default::default();
        for t in [TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES, TABLE_CODE] {
            for at in manifest.runs(t).into_iter().rev() {
                if !base && at.layer.is_none() {
                    continue;
                }
                let f = File::open(root.join(&at.path)).map_err(|e| format!("{}: {e}", at.path))?;
                let mut rref = at.table.run_ref(at.block_lo);
                rref.block_hi = at.block_hi;
                let mut r = Reader::try_with_format(f, rref, RUN_FORMAT)
                    .map_err(|e| format!("{}: {e}", at.path))?;
                r.prepare().map_err(|e| format!("{}: {e}", at.path))?;
                runs[table_index(t)].push(r);
            }
        }
        Ok(Store { runs, lookups: 0 })
    }

    /// The node at `path` of the account trie (`owner` none) or of
    /// `owner`'s storage trie that hashes to `hash`, if a run holds it.
    pub fn node(
        &mut self,
        owner: Option<B256>,
        path: &Nibbles,
        hash: &B256,
    ) -> Result<Option<Bytes>, String> {
        let nk = NodeKey::prefix(path, path.len());
        let (t, key) = match owner {
            None => (0, nk.table_key()),
            Some(o) => (1, nk.storage_table_key(&o)),
        };
        let Ok(key) = key else { return Ok(None) };
        self.lookups += 1;
        for r in self.runs[t].iter_mut() {
            let (e, _) = r.get_entry(&key).map_err(|e| format!("local run: {e}"))?;
            if let Some(e) = e.filter(|e| e.tag == 0) {
                if keccak256(&e.value) == *hash {
                    return Ok(Some(Bytes::from(e.value)));
                }
            }
        }
        Ok(None)
    }

    /// Does a run hold the code under `hash`?
    pub fn has_code(&mut self, hash: &B256) -> Result<bool, String> {
        for r in self.runs[2].iter_mut() {
            if r.get_entry(&hash.0)
                .map_err(|e| format!("local run: {e}"))?
                .0
                .is_some()
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Runs per table.
    pub fn run_counts(&self) -> [usize; 3] {
        [self.runs[0].len(), self.runs[1].len(), self.runs[2].len()]
    }
}

// ---------------------------------------------------------------------------
// Where new nodes come from

/// The new root's nodes and code: peers, or (in tests) a state in memory.
pub trait Source {
    /// The nodes found for `needs` at `root`, by need index, each checked
    /// against its hash.
    fn nodes(
        &mut self,
        root: B256,
        needs: &[Need],
        deadline: Instant,
    ) -> impl std::future::Future<Output = HashMap<usize, Bytes>>;
    /// Bytecodes by hash, each checked against it.
    fn codes(
        &mut self,
        hashes: &[B256],
        deadline: Instant,
    ) -> impl std::future::Future<Output = HashMap<B256, Bytes>>;
}

impl Source for Pool {
    async fn nodes(
        &mut self,
        root: B256,
        needs: &[Need],
        deadline: Instant,
    ) -> HashMap<usize, Bytes> {
        let g = [Group {
            root,
            kind: "new",
            age: 0,
            needs: needs.to_vec(),
        }];
        let (mut got, _) = Fetch::fetch(self, &g, 384, 4, deadline).await;
        got.pop().unwrap_or_default()
    }

    async fn codes(&mut self, hashes: &[B256], deadline: Instant) -> HashMap<B256, Bytes> {
        Pool::codes(self, hashes, 4, deadline).await
    }
}

// ---------------------------------------------------------------------------
// Fetched nodes, on disk

/// Every node and code fetched toward a root not yet committed, by hash,
/// and the subtrees known complete: what survives a re-pivot and a
/// restart, as snap sync's healing keeps its fetched nodes.
///
/// The log holds records `hash ‖ len: u32 LE ‖ bytes`, each checked by
/// hash on the way in and again when the log is reopened (a torn tail is
/// cut off). The index keeps eight bytes of each hash and a read checks
/// the full hash, so the index costs about 20 bytes a node in memory.
///
/// A subtree is complete when its node and everything under it, storage
/// tries and code of its accounts included, is local: in this log, or
/// unchanged at its position in the held state. Completeness is relative
/// to that state, so the directory names the root it was built against and
/// starts empty when the held state is another. A marker is eight bytes of
/// a hash of (owner, path, node hash); a false match only makes the
/// materializing walk miss a node, which clears the markers and syncs
/// again.
pub struct NodeDb {
    dir: PathBuf,
    log: File,
    end: u64,
    idx: HashMap<u64, u64>,
    extra: HashMap<B256, u64>,
    pending: Vec<u8>,
    done_f: File,
    done: HashSet<u64>,
    done_pending: Vec<u8>,
}

fn prefix8(b: &[u8]) -> u64 {
    u64::from_le_bytes(b[..8].try_into().expect("8 bytes"))
}

fn done_key(owner: &Option<B256>, path: &Nibbles, hash: &B256) -> u64 {
    let mut b = Vec::with_capacity(32 + 33 + 32 + 2);
    match owner {
        Some(o) => {
            b.push(1);
            b.extend_from_slice(o.as_slice());
        }
        None => b.push(0),
    }
    b.push(path.len() as u8);
    b.extend_from_slice(&path.pack());
    b.extend_from_slice(hash.as_slice());
    prefix8(keccak256(&b).as_slice())
}

impl NodeDb {
    /// The log in `dir`, kept when it was built against `against` and
    /// started empty otherwise.
    pub fn open(dir: &Path, against: B256) -> Result<NodeDb, String> {
        let err = |e: std::io::Error| format!("{}: {e}", dir.display());
        fs::create_dir_all(dir).map_err(err)?;
        let tag = dir.join("against");
        if fs::read_to_string(&tag).ok().as_deref().map(str::trim) != Some(&against.to_string()) {
            for f in ["log", "done"] {
                let _ = fs::remove_file(dir.join(f));
            }
            write_atomic(&tag, against.to_string().as_bytes())?;
        }
        let log = File::options()
            .read(true)
            .append(true)
            .create(true)
            .open(dir.join("log"))
            .map_err(err)?;
        let done_f = File::options()
            .read(true)
            .append(true)
            .create(true)
            .open(dir.join("done"))
            .map_err(err)?;
        let mut db = NodeDb {
            dir: dir.to_path_buf(),
            log,
            end: 0,
            idx: HashMap::new(),
            extra: HashMap::new(),
            pending: Vec::new(),
            done_f,
            done: HashSet::new(),
            done_pending: Vec::new(),
        };
        // The log: every whole record that hashes to its name, read
        // through a buffer so a log bigger than memory still reopens.
        let size = fs::metadata(dir.join("log")).map_err(err)?.len();
        let mut r =
            std::io::BufReader::with_capacity(1 << 20, File::open(dir.join("log")).map_err(err)?);
        let (mut at, mut head, mut body) = (0u64, [0u8; 36], Vec::new());
        while at + 36 <= size {
            if r.read_exact(&mut head).is_err() {
                break;
            }
            let len = u32::from_le_bytes(head[32..36].try_into().expect("4")) as u64;
            if at + 36 + len > size {
                break;
            }
            body.resize(len as usize, 0);
            if r.read_exact(&mut body).is_err() {
                break;
            }
            let h = B256::from_slice(&head[..32]);
            if keccak256(&body) != h {
                break;
            }
            db.index(h, at);
            at += 36 + len;
        }
        if at < size {
            db.log.set_len(at).map_err(err)?;
        }
        db.end = at;
        let done = fs::read(dir.join("done")).map_err(err)?;
        let whole = done.len() / 8 * 8;
        for c in done[..whole].chunks(8) {
            db.done.insert(prefix8(c));
        }
        if whole < done.len() {
            db.done_f.set_len(whole as u64).map_err(err)?;
        }
        Ok(db)
    }

    fn index(&mut self, h: B256, off: u64) {
        match self.idx.entry(prefix8(h.as_slice())) {
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(off);
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                self.extra.insert(h, off);
            }
        }
    }

    fn read_at(&self, off: u64) -> Result<(B256, Bytes), String> {
        use std::os::unix::fs::FileExt;
        let mut head = [0u8; 36];
        self.log
            .read_exact_at(&mut head, off)
            .map_err(|e| format!("node log: {e}"))?;
        let len = u32::from_le_bytes(head[32..36].try_into().expect("4")) as usize;
        let mut b = vec![0u8; len];
        self.log
            .read_exact_at(&mut b, off + 36)
            .map_err(|e| format!("node log: {e}"))?;
        Ok((B256::from_slice(&head[..32]), Bytes::from(b)))
    }

    /// The node (or code) under `h`, if fetched.
    pub fn get(&self, h: &B256) -> Result<Option<Bytes>, String> {
        if let Some(&off) = self.idx.get(&prefix8(h.as_slice())) {
            if off < self.end {
                let (got, b) = self.read_at(off)?;
                if got == *h {
                    return Ok(Some(b));
                }
            }
        }
        match self.extra.get(h) {
            Some(&off) => Ok(Some(self.read_at(off)?.1)),
            None => Ok(None),
        }
    }

    pub fn contains(&self, h: &B256) -> Result<bool, String> {
        Ok(self.get(h)?.is_some())
    }

    /// Keep `b` under `h` if it hashes to it; written at the next
    /// [`flush`](Self::flush).
    pub fn put(&mut self, h: B256, b: &[u8]) -> Result<bool, String> {
        if keccak256(b) != h || self.contains(&h)? {
            return Ok(false);
        }
        let off = self.end + self.pending.len() as u64;
        self.pending.extend_from_slice(h.as_slice());
        self.pending
            .extend_from_slice(&(b.len() as u32).to_le_bytes());
        self.pending.extend_from_slice(b);
        self.flush_log()?;
        self.index(h, off);
        Ok(true)
    }

    fn flush_log(&mut self) -> Result<(), String> {
        if !self.pending.is_empty() {
            self.log
                .write_all(&self.pending)
                .map_err(|e| format!("node log: {e}"))?;
            self.end += self.pending.len() as u64;
            self.pending.clear();
        }
        Ok(())
    }

    pub fn is_done(&self, k: u64) -> bool {
        self.done.contains(&k)
    }

    fn mark_done(&mut self, k: u64) {
        if self.done.insert(k) {
            self.done_pending.extend_from_slice(&k.to_le_bytes());
        }
    }

    /// Write what is buffered.
    pub fn flush(&mut self) -> Result<(), String> {
        self.flush_log()?;
        if !self.done_pending.is_empty() {
            self.done_f
                .write_all(&self.done_pending)
                .map_err(|e| format!("done log: {e}"))?;
            self.done_pending.clear();
        }
        Ok(())
    }

    /// Forget the completeness markers (the nodes stay).
    pub fn clear_done(&mut self) -> Result<(), String> {
        self.done.clear();
        self.done_pending.clear();
        self.done_f.set_len(0).map_err(|e| format!("done log: {e}"))
    }

    /// Start empty, against `against`: the held state moved.
    pub fn reset(&mut self, against: B256) -> Result<(), String> {
        self.clear_done()?;
        self.log.set_len(0).map_err(|e| format!("node log: {e}"))?;
        self.idx.clear();
        self.extra.clear();
        self.pending.clear();
        self.end = 0;
        write_atomic(&self.dir.join("against"), against.to_string().as_bytes())
    }

    /// Nodes held, and bytes of log.
    pub fn len(&self) -> usize {
        self.idx.len() + self.extra.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn log_bytes(&self) -> u64 {
        self.end
    }
    pub fn done_len(&self) -> usize {
        self.done.len()
    }
}

// ---------------------------------------------------------------------------
// One step: sync, then materialize

#[derive(Default, Debug, Clone, Serialize)]
pub struct StepStats {
    pub account_nodes: u64,
    pub storage_nodes: u64,
    pub node_bytes: u64,
    pub codes: u64,
    pub code_bytes: u64,
    /// Nodes asked of peers, and served by them.
    pub asked: u64,
    pub fetched: u64,
    /// Nodes the sync found on disk (fetched before a re-pivot or restart,
    /// or held at the position), and subtrees it skipped as complete.
    pub local: u64,
    pub done_skips: u64,
    /// Old nodes the local store did not have: the subtree was fetched
    /// whole instead (more bytes, same result).
    pub old_missing: u64,
    /// Without a local base: old nodes asked for, and served by peers at
    /// the old root and by the base in the bucket.
    pub old_asked: u64,
    pub old_peers: u64,
    pub old_bucket: u64,
    pub accounts_changed: u64,
    pub storage_tries: u64,
    /// Storage tries copied from another owner with the same root.
    pub storage_copied: u64,
    /// Waves of requests: dependent round trips.
    pub levels: u32,
    pub local_lookups: u64,
    pub sync_s: f64,
    pub materialize_s: f64,
}

/// A step's rows: nodes streamed into a sorter (spilling under its
/// budget), code by hash.
pub struct Rows {
    pub sort: csl_eth_store::extsort::ExtSort,
    pub code: BTreeMap<[u8; 32], Vec<u8>>,
    pub account_rows: u64,
    pub storage_rows: u64,
    /// Owners with storage rows, for the layer's hint; `None` past the
    /// hint's cap.
    pub owners: Option<BTreeSet<[u8; 32]>>,
    _scratch: csl_eth_store::extsort::Scratch,
}

impl Rows {
    fn new(dir: &Path, budget: u64) -> Result<Rows, String> {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let scratch =
            csl_eth_store::extsort::Scratch::new(dir).map_err(|e| format!("scratch: {e}"))?;
        Ok(Rows {
            sort: layer_sorter(scratch.path(), budget),
            code: BTreeMap::new(),
            account_rows: 0,
            storage_rows: 0,
            owners: Some(BTreeSet::new()),
            _scratch: scratch,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.account_rows == 0 && self.storage_rows == 0 && self.code.is_empty()
    }

    /// Every row in memory (tests).
    pub fn collect(&mut self) -> LayerRows {
        self.sort.prepare().expect("prepare");
        let mut out = LayerRows {
            code: self.code.clone(),
            owners: self.owners.clone(),
            ..LayerRows::default()
        };
        for (t, m) in [
            (SORT_ACCOUNT, &mut out.account),
            (SORT_STORAGE, &mut out.storage),
        ] {
            self.sort
                .merge::<csl_eth_store::extsort::SortError>(t, |k, v| {
                    m.insert(*k, v.to_vec());
                    Ok(())
                })
                .expect("merge");
        }
        out
    }
}

/// A complete step: the layer's rows, and the keys to read back.
pub struct Tracked {
    pub rows: Rows,
    /// Changed accounts with their new values.
    pub accounts: Vec<(B256, Account)>,
    /// Changed slots seen: (owner, slot, value), up to the sample size.
    pub slots: Vec<(B256, B256, U256)>,
    /// Storage tries the step created: (root, owner).
    pub new_tries: Vec<(B256, B256)>,
    pub stats: StepStats,
}

#[derive(Debug)]
pub enum StepError {
    /// Nodes or code no peer served.
    Unresolved { nodes: usize, codes: usize },
    /// Past the deadline (the root is about to leave the peers' window).
    Deadline,
    /// The materializing walk missed a node the sync counted as local.
    Missing,
    /// The local store could not be read.
    Store(String),
    /// A node too deep for a table key.
    TooDeep,
    /// The held state's node at a position is not local: ask for it.
    Old(Need),
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepError::Unresolved { nodes, codes } => {
                write!(f, "{nodes} nodes and {codes} codes no peer served")
            }
            StepError::Deadline => write!(f, "deadline"),
            StepError::Missing => write!(f, "a node the sync counted as local is missing"),
            StepError::Store(e) => write!(f, "local store: {e}"),
            StepError::TooDeep => write!(f, "a node too deep for a table key"),
            StepError::Old(n) => write!(f, "old node {} not local", n.hash),
        }
    }
}

/// Paths of the account trie inside a slice base's prefix, or on the way
/// to it; every path when there is no prefix.
fn compatible(prefix: Option<&Nibbles>, owner: &Option<B256>, path: &Nibbles) -> bool {
    match (prefix, owner) {
        (Some(p), None) => path.starts_with(p) || p.starts_with(path),
        _ => true,
    }
}

/// The account under `key` in the trie at `root`, walked through the local
/// store; none when absent or when the store lacks a node on the way (the
/// caller then treats the account as new, which fetches more, never less).
fn old_account(
    store: &mut Store,
    db: Option<&NodeDb>,
    remote: bool,
    root: B256,
    key: &Nibbles,
) -> Result<Option<Account>, StepError> {
    let mut path = Nibbles::default();
    let mut at = Ref::Hash(root);
    loop {
        let rlp = match &at {
            Ref::Inline(b) => b.clone(),
            Ref::Hash(h) => match old_node(store, db, None, &path, h)? {
                Some(b) => b,
                None if remote => {
                    return Err(StepError::Old(Need {
                        owner: None,
                        path,
                        hash: *h,
                    }))
                }
                None => return Ok(None),
            },
        };
        match shape(&path, &rlp) {
            Ok(Shape::Inner(kids)) => match kids.into_iter().find(|(q, _)| key.starts_with(q)) {
                Some((q, r)) => {
                    path = q;
                    at = r;
                }
                None => return Ok(None),
            },
            Ok(Shape::Leaf { key: k, value }) => {
                return Ok(if k == *key {
                    Account::decode(&value).ok()
                } else {
                    None
                });
            }
            Ok(Shape::Empty) | Err(_) => return Ok(None),
        }
    }
}

/// The held state's node at a position: fetched for this step (old nodes
/// a tracker without a local base asked for), or in the local runs.
fn old_node(
    store: &mut Store,
    db: Option<&NodeDb>,
    owner: Option<B256>,
    path: &Nibbles,
    h: &B256,
) -> Result<Option<Bytes>, StepError> {
    if let Some(db) = db {
        if let Some(b) = db.get(h).map_err(StepError::Store)? {
            return Ok(Some(b));
        }
    }
    store.node(owner, path, h).map_err(StepError::Store)
}

/// A position to diff: the new state's reference there, and the held
/// state's.
#[derive(Clone, Debug)]
struct Pos {
    owner: Option<B256>,
    path: Nibbles,
    new: Ref,
    old: Option<Ref>,
    /// Another owner whose held storage trie has the new root: nodes the
    /// held state lacks for `owner` are copied from it, not fetched.
    src: Option<B256>,
}

/// What a node leads to: its children to diff (an account's storage trie
/// among them), the account or slot it is a leaf of, and new code.
#[derive(Default)]
struct Opened {
    kids: Vec<Pos>,
    account: Option<(B256, Account)>,
    slot: Option<(B256, B256, U256)>,
    code: Option<B256>,
    storage: bool,
    /// The storage trie under it is copied from another owner's.
    copied: bool,
    /// A storage trie where the account had none: (root, owner).
    new_trie: Option<(B256, B256)>,
}

/// What the walks share: the held state, where it is, and the prefix.
struct Ctx<'a> {
    store: &'a mut Store,
    old_root: B256,
    prefix: Option<&'a Nibbles>,
    roots: Option<&'a mut RootIndex>,
    /// Where old nodes the local runs lack come from.
    old: OldSide<'a>,
}

/// Where a step's old side comes from when the base is not on disk: peers
/// at the old root while it is in their window, then the base's runs in
/// the bucket. Neither (the default) means the local runs hold the whole
/// held state, and an old node they lack is diffed as absent.
#[derive(Default)]
pub struct OldSide<'a> {
    pub peers: bool,
    pub remote: Option<&'a mut crate::remote::RemoteBase>,
}

impl OldSide<'_> {
    fn any(&self) -> bool {
        self.peers || self.remote.is_some()
    }
}

impl Ctx<'_> {
    /// The node under `h` at a position: fetched (on disk) or held there.
    fn local(&mut self, db: &NodeDb, p: &Pos, h: &B256) -> Result<Option<Bytes>, StepError> {
        if let Some(b) = db.get(h).map_err(StepError::Store)? {
            return Ok(Some(b));
        }
        if let Some(b) = self
            .store
            .node(p.owner, &p.path, h)
            .map_err(StepError::Store)?
        {
            return Ok(Some(b));
        }
        match p.src {
            Some(o) => self
                .store
                .node(Some(o), &p.path, h)
                .map_err(StepError::Store),
            None => Ok(None),
        }
    }

    /// An owner other than `owner` whose held storage trie has root `r`.
    fn copy_source(&mut self, r: &B256, owner: &B256) -> Result<Option<B256>, StepError> {
        let Some(ix) = self.roots.as_mut() else {
            return Ok(None);
        };
        for o in ix.find(r).map_err(StepError::Store)? {
            if o != *owner
                && self
                    .store
                    .node(Some(o), &Nibbles::default(), r)
                    .map_err(StepError::Store)?
                    .is_some()
            {
                return Ok(Some(o));
            }
        }
        Ok(None)
    }

    /// The new node `rlp` at `p`, diffed against the held state's.
    fn open(
        &mut self,
        db: &NodeDb,
        p: &Pos,
        rlp: &[u8],
        st: &mut StepStats,
    ) -> Result<Opened, StepError> {
        let mut out = Opened::default();
        let remote = self.old.any();
        let old_rlp: Option<Bytes> = match &p.old {
            None => None,
            Some(Ref::Inline(b)) => Some(b.clone()),
            Some(Ref::Hash(h)) => {
                let b = old_node(self.store, Some(db), p.owner, &p.path, h)?;
                if b.is_none() {
                    if remote {
                        return Err(StepError::Old(Need {
                            owner: p.owner,
                            path: p.path,
                            hash: *h,
                        }));
                    }
                    st.old_missing += 1;
                }
                b
            }
        };
        let Ok(new_shape) = shape(&p.path, rlp) else {
            return Ok(out);
        };
        let old_shape = old_rlp.as_ref().and_then(|b| shape(&p.path, b).ok());
        match new_shape {
            Shape::Empty => {}
            Shape::Inner(kids) => {
                let old_kids: HashMap<Nibbles, Ref> = match &old_shape {
                    Some(Shape::Inner(k)) => k.iter().cloned().collect(),
                    _ => HashMap::new(),
                };
                for (q, r) in kids {
                    if !compatible(self.prefix, &p.owner, &q) {
                        continue;
                    }
                    let o = old_kids.get(&q).cloned();
                    if o.as_ref() == Some(&r) {
                        continue;
                    }
                    out.kids.push(Pos {
                        owner: p.owner,
                        path: q,
                        new: r,
                        old: o,
                        src: p.src,
                    });
                }
            }
            Shape::Leaf { key, value } => {
                if key.len() != 64 {
                    return Ok(out);
                }
                let hash = B256::from_slice(&key.pack());
                if let Some(owner) = p.owner {
                    if let Ok(v) = decode_word(&value) {
                        out.slot = Some((owner, hash, v));
                    }
                    return Ok(out);
                }
                let Ok(acct) = Account::decode(&value) else {
                    return Ok(out);
                };
                let old = match &old_shape {
                    Some(Shape::Leaf { key: ok, value: ov }) if *ok == key => {
                        Account::decode(ov).ok()
                    }
                    _ => old_account(self.store, Some(db), remote, self.old_root, &key)?,
                };
                let old_root = old.map(|a| a.storage_root).unwrap_or(EMPTY_ROOT);
                if acct.storage_root != EMPTY_ROOT && acct.storage_root != old_root {
                    out.storage = true;
                    let src = self.copy_source(&acct.storage_root, &hash)?;
                    out.copied = src.is_some();
                    if old_root == EMPTY_ROOT {
                        out.new_trie = Some((acct.storage_root, hash));
                    }
                    out.kids.push(Pos {
                        owner: Some(hash),
                        path: Nibbles::default(),
                        new: Ref::Hash(acct.storage_root),
                        old: (old_root != EMPTY_ROOT).then_some(Ref::Hash(old_root)),
                        src,
                    });
                }
                if acct.code_hash != KECCAK_EMPTY
                    && old.map(|a| a.code_hash) != Some(acct.code_hash)
                {
                    out.code = Some(acct.code_hash);
                }
                out.account = Some((hash, acct));
            }
        }
        Ok(out)
    }
}

/// A node of the sync's tree: complete once opened and every child is.
struct Pend {
    key: u64,
    parent: Option<u32>,
    deps: u32,
    opened: bool,
}

#[derive(Default)]
struct Tree {
    v: Vec<Option<Pend>>,
    free: Vec<u32>,
}

impl Tree {
    fn add(&mut self, key: u64, parent: Option<u32>) -> u32 {
        let p = Pend {
            key,
            parent,
            deps: 0,
            opened: false,
        };
        match self.free.pop() {
            Some(i) => {
                self.v[i as usize] = Some(p);
                i
            }
            None => {
                self.v.push(Some(p));
                (self.v.len() - 1) as u32
            }
        }
    }
    fn dep(&mut self, p: Option<u32>) {
        if let Some(i) = p {
            self.v[i as usize].as_mut().expect("live").deps += 1;
        }
    }
    /// A child of `p` is complete; so, then, may `p` and its ancestors be.
    fn child_done(&mut self, db: &mut NodeDb, mut p: Option<u32>) {
        while let Some(i) = p {
            let n = self.v[i as usize].as_mut().expect("live");
            n.deps -= 1;
            if n.deps > 0 || !n.opened {
                return;
            }
            p = self.finish(db, i);
        }
    }
    /// `i` is complete: mark it, free it, and return its parent.
    fn finish(&mut self, db: &mut NodeDb, i: u32) -> Option<u32> {
        let n = self.v[i as usize].take().expect("live");
        db.mark_done(n.key);
        self.free.push(i);
        n.parent
    }
    fn opened(&mut self, db: &mut NodeDb, i: u32) {
        let n = self.v[i as usize].as_mut().expect("live");
        n.opened = true;
        if n.deps == 0 {
            let parent = self.finish(db, i);
            self.child_done(db, parent);
        }
    }
}

struct Item {
    pos: Pos,
    parent: Option<u32>,
}

/// A node whose opening waits for an old node (a tracker without a local
/// base): its position, its slot (hashed) or its parent's (inline), its
/// bytes, and the old node it waits for.
struct Waiting {
    pos: Pos,
    slot: Option<u32>,
    inline: bool,
    rlp: Bytes,
    need: Need,
    tries: u8,
}

/// Needs one wave asks for at most.
const WAVE: usize = 4096;
const MAX_TRIES: u8 = 4;

/// Fetch onto disk every node of `new_root`'s trie (and every new code)
/// that the held state does not have at its position, skipping subtrees
/// already complete. Depth first, so subtrees complete and leave memory
/// early; each wave asks for up to [`WAVE`] nodes at once.
#[allow(clippy::too_many_arguments)]
async fn sync<S: Source>(
    src: &mut S,
    cx: &mut Ctx<'_>,
    db: &mut NodeDb,
    new_root: B256,
    deadline: Instant,
    st: &mut StepStats,
) -> Result<(), StepError> {
    let mut tree = Tree::default();
    let mut stack = vec![Item {
        pos: Pos {
            owner: None,
            path: Nibbles::default(),
            new: Ref::Hash(new_root),
            old: Some(Ref::Hash(cx.old_root)),
            src: None,
        },
        parent: None,
    }];
    let mut fetch: Vec<(Pos, u32, u8)> = Vec::new();
    let mut codes: HashMap<B256, (Vec<u32>, u8)> = HashMap::new();
    let mut steps = 0u64;
    // Open a node: its children go on the stack, new code waits; then it
    // is complete if nothing under it is outstanding.
    fn open_slot(
        cx: &mut Ctx<'_>,
        db: &mut NodeDb,
        tree: &mut Tree,
        stack: &mut Vec<Item>,
        codes: &mut HashMap<B256, (Vec<u32>, u8)>,
        st: &mut StepStats,
        pos: &Pos,
        slot: Option<u32>,
        rlp: &[u8],
    ) -> Result<(), StepError> {
        let o = cx.open(db, pos, rlp, st)?;
        for k in o.kids {
            tree.dep(slot);
            stack.push(Item {
                pos: k,
                parent: slot,
            });
        }
        if let Some(c) = o.code {
            if !cx.store.has_code(&c).map_err(StepError::Store)?
                && !db.contains(&c).map_err(StepError::Store)?
            {
                tree.dep(slot);
                codes
                    .entry(c)
                    .or_default()
                    .0
                    .push(slot.expect("an account leaf is hashed"));
            }
        }
        Ok(())
    }
    // Open, or wait for the old node it needs. The slot is completed
    // (hashed) or the parent told (inline) once it opens.
    #[allow(clippy::too_many_arguments)]
    fn open_or_wait(
        cx: &mut Ctx<'_>,
        db: &mut NodeDb,
        tree: &mut Tree,
        stack: &mut Vec<Item>,
        codes: &mut HashMap<B256, (Vec<u32>, u8)>,
        st: &mut StepStats,
        waiting: &mut Vec<Waiting>,
        pos: &Pos,
        slot: Option<u32>,
        inline: bool,
        rlp: &Bytes,
        tries: u8,
    ) -> Result<(), StepError> {
        match open_slot(cx, db, tree, stack, codes, st, pos, slot, rlp) {
            Ok(()) => {
                if inline {
                    tree.child_done(db, slot);
                } else {
                    tree.opened(db, slot.expect("a hashed node has a slot"));
                }
                Ok(())
            }
            Err(StepError::Old(need)) => {
                waiting.push(Waiting {
                    pos: pos.clone(),
                    slot,
                    inline,
                    rlp: rlp.clone(),
                    need,
                    tries,
                });
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
    let mut waiting: Vec<Waiting> = Vec::new();
    loop {
        while fetch.len() + waiting.len() < WAVE {
            let Some(it) = stack.pop() else { break };
            steps += 1;
            if steps % 65_536 == 0 && Instant::now() > deadline {
                return Err(StepError::Deadline);
            }
            let p = &it.pos;
            if p.old.as_ref() == Some(&p.new) {
                tree.child_done(db, it.parent);
                continue;
            }
            match &p.new {
                Ref::Inline(b) => {
                    let b = b.clone();
                    open_or_wait(
                        cx,
                        db,
                        &mut tree,
                        &mut stack,
                        &mut codes,
                        st,
                        &mut waiting,
                        p,
                        it.parent,
                        true,
                        &b,
                        0,
                    )?;
                }
                Ref::Hash(h) => {
                    let key = done_key(&p.owner, &p.path, h);
                    if db.is_done(key) {
                        st.done_skips += 1;
                        tree.child_done(db, it.parent);
                        continue;
                    }
                    let slot = tree.add(key, it.parent);
                    match cx.local(db, p, h)? {
                        Some(b) => {
                            st.local += 1;
                            open_or_wait(
                                cx,
                                db,
                                &mut tree,
                                &mut stack,
                                &mut codes,
                                st,
                                &mut waiting,
                                p,
                                Some(slot),
                                false,
                                &b,
                                0,
                            )?;
                        }
                        None => fetch.push((it.pos, slot, 0)),
                    }
                }
            }
        }
        if fetch.is_empty() && codes.is_empty() && waiting.is_empty() {
            break;
        }
        if Instant::now() > deadline {
            return Err(StepError::Deadline);
        }
        st.levels += 1;
        let mut needs = Vec::new();
        let mut asked: HashSet<(Option<B256>, Nibbles, B256)> = HashSet::new();
        for (p, _, _) in &fetch {
            let Ref::Hash(h) = p.new else {
                unreachable!("only hashed nodes are fetched")
            };
            if asked.insert((p.owner, p.path, h)) {
                needs.push(Need {
                    owner: p.owner,
                    path: p.path,
                    hash: h,
                });
            }
        }
        if !needs.is_empty() {
            st.asked += needs.len() as u64;
            for (i, b) in src.nodes(new_root, &needs, deadline).await {
                if db.put(needs[i].hash, &b).map_err(StepError::Store)? {
                    st.fetched += 1;
                }
            }
        }
        if !codes.is_empty() {
            let want: Vec<B256> = codes.keys().copied().collect();
            for (h, c) in src.codes(&want, deadline).await {
                db.put(h, &c).map_err(StepError::Store)?;
            }
        }
        // The old side, in the same wave: peers at the old root while it is
        // in their window, then the base in the bucket.
        if !waiting.is_empty() {
            let mut olds: Vec<Need> = Vec::new();
            let mut seen: HashSet<B256> = HashSet::new();
            for w in &waiting {
                if seen.insert(w.need.hash)
                    && !db.contains(&w.need.hash).map_err(StepError::Store)?
                {
                    olds.push(w.need.clone());
                }
            }
            st.old_asked += olds.len() as u64;
            let mut got: HashMap<usize, Bytes> = HashMap::new();
            if cx.old.peers && !olds.is_empty() {
                got = src.nodes(cx.old_root, &olds, deadline).await;
                st.old_peers += got.len() as u64;
            }
            if let Some(rb) = cx.old.remote.as_mut() {
                let rest: Vec<usize> = (0..olds.len()).filter(|i| !got.contains_key(i)).collect();
                if !rest.is_empty() {
                    let sub: Vec<Need> = rest.iter().map(|&i| olds[i].clone()).collect();
                    let from = rb.nodes(&sub).await.map_err(StepError::Store)?;
                    st.old_bucket += from.len() as u64;
                    for (j, b) in from {
                        got.insert(rest[j], b);
                    }
                }
            }
            for (i, b) in got {
                db.put(olds[i].hash, &b).map_err(StepError::Store)?;
            }
        }
        let mut unresolved = (0usize, 0usize);
        for (p, slot, tries) in std::mem::take(&mut fetch) {
            let Ref::Hash(h) = p.new else { unreachable!() };
            match db.get(&h).map_err(StepError::Store)? {
                Some(b) => {
                    open_or_wait(
                        cx,
                        db,
                        &mut tree,
                        &mut stack,
                        &mut codes,
                        st,
                        &mut waiting,
                        &p,
                        Some(slot),
                        false,
                        &b,
                        0,
                    )?;
                }
                None if tries + 1 >= MAX_TRIES => unresolved.0 += 1,
                None => fetch.push((p, slot, tries + 1)),
            }
        }
        // Retry what waited; a node that waits for the same old node again
        // counts a try (an account walk may wait for several in turn).
        for w in std::mem::take(&mut waiting) {
            let before = waiting.len();
            open_or_wait(
                cx,
                db,
                &mut tree,
                &mut stack,
                &mut codes,
                st,
                &mut waiting,
                &w.pos,
                w.slot,
                w.inline,
                &w.rlp,
                0,
            )?;
            if waiting.len() > before {
                let again = waiting.last_mut().expect("just pushed");
                if again.need.hash == w.need.hash {
                    again.tries = w.tries + 1;
                    if again.tries >= MAX_TRIES {
                        waiting.pop();
                        unresolved.0 += 1;
                    }
                }
            }
        }
        for (h, (slots, tries)) in std::mem::take(&mut codes) {
            if db.contains(&h).map_err(StepError::Store)? {
                for s in slots {
                    tree.child_done(db, Some(s));
                }
            } else if tries + 1 >= MAX_TRIES {
                unresolved.1 += 1;
            } else {
                codes.insert(h, (slots, tries + 1));
            }
        }
        db.flush().map_err(StepError::Store)?;
        if unresolved != (0, 0) {
            return Err(StepError::Unresolved {
                nodes: unresolved.0,
                codes: unresolved.1,
            });
        }
    }
    db.flush().map_err(StepError::Store)?;
    Ok(())
}

/// Walk `new_root`'s trie against the held state with every node local,
/// streaming each hashed node that differs at its position into the rows.
#[allow(clippy::too_many_arguments)]
fn materialize(
    cx: &mut Ctx<'_>,
    db: &NodeDb,
    new_root: B256,
    slot_sample: usize,
    sort_dir: &Path,
    sort_budget: u64,
    st: &mut StepStats,
) -> Result<Tracked, StepError> {
    let mut rows = Rows::new(sort_dir, sort_budget).map_err(StepError::Store)?;
    let mut accounts = Vec::new();
    let mut slots = Vec::new();
    let mut new_tries = Vec::new();
    let mut stack = vec![Pos {
        owner: None,
        path: Nibbles::default(),
        new: Ref::Hash(new_root),
        old: Some(Ref::Hash(cx.old_root)),
        src: None,
    }];
    let sort_err = |e: csl_eth_store::extsort::SortError| StepError::Store(e.to_string());
    while let Some(p) = stack.pop() {
        if p.old.as_ref() == Some(&p.new) {
            continue;
        }
        let rlp = match &p.new {
            Ref::Inline(b) => b.clone(),
            Ref::Hash(h) => {
                let b = cx.local(db, &p, h)?.ok_or(StepError::Missing)?;
                let nk = NodeKey::prefix(&p.path, p.path.len());
                match p.owner {
                    None => {
                        let k = nk.table_key().map_err(|_| StepError::TooDeep)?;
                        rows.sort.push(SORT_ACCOUNT, &k, &b).map_err(sort_err)?;
                        rows.account_rows += 1;
                        st.account_nodes += 1;
                    }
                    Some(o) => {
                        let k = nk.storage_table_key(&o).map_err(|_| StepError::TooDeep)?;
                        rows.sort.push(SORT_STORAGE, &k, &b).map_err(sort_err)?;
                        rows.storage_rows += 1;
                        if let Some(s) = rows.owners.as_mut() {
                            s.insert(o.0);
                            if s.len() > csl_eth_store::hints::HINT_CAP {
                                rows.owners = None;
                            }
                        }
                        st.storage_nodes += 1;
                    }
                }
                st.node_bytes += b.len() as u64;
                b
            }
        };
        // Every old node the sync needed is on disk; one that is not means
        // the markers lied, as for a missing new node.
        let o = cx.open(db, &p, &rlp, st).map_err(|e| match e {
            StepError::Old(_) => StepError::Missing,
            e => e,
        })?;
        if o.storage {
            st.storage_tries += 1;
        }
        if o.copied {
            st.storage_copied += 1;
        }
        new_tries.extend(o.new_trie);
        stack.extend(o.kids);
        if let Some(s) = o.slot {
            if slots.len() < slot_sample {
                slots.push(s);
            }
        }
        if let Some(c) = o.code {
            if !rows.code.contains_key(&c.0) && !cx.store.has_code(&c).map_err(StepError::Store)? {
                let b = db
                    .get(&c)
                    .map_err(StepError::Store)?
                    .ok_or(StepError::Missing)?;
                st.codes += 1;
                st.code_bytes += b.len() as u64;
                rows.code.insert(c.0, b.to_vec());
            }
        }
        if let Some(a) = o.account {
            st.accounts_changed += 1;
            accounts.push(a);
        }
    }
    Ok(Tracked {
        rows,
        accounts,
        slots,
        new_tries,
        stats: std::mem::take(st),
    })
}

/// Step from the held state at `old_root` to `new_root`: sync what is
/// missing onto `db` from `src`, then materialize the step's rows locally.
/// On any error the fetched nodes stay in `db` for the next attempt.
#[allow(clippy::too_many_arguments)]
pub async fn track_step<S: Source>(
    src: &mut S,
    store: &mut Store,
    db: &mut NodeDb,
    old_root: B256,
    new_root: B256,
    prefix: Option<&Nibbles>,
    slot_sample: usize,
    deadline: Instant,
    sort_dir: &Path,
    sort_budget: u64,
    roots: Option<&mut RootIndex>,
    old: OldSide<'_>,
) -> Result<Tracked, StepError> {
    let lookups0 = store.lookups;
    let mut st = StepStats::default();
    let mut cx = Ctx {
        store,
        old_root,
        prefix,
        roots,
        old,
    };
    let t0 = Instant::now();
    sync(src, &mut cx, db, new_root, deadline, &mut st).await?;
    st.sync_s = t0.elapsed().as_secs_f64();
    let t1 = Instant::now();
    let fetched = (
        st.asked,
        st.fetched,
        st.local,
        st.done_skips,
        st.levels,
        st.old_missing,
        (st.old_asked, st.old_peers, st.old_bucket),
    );
    let mut sm = StepStats::default();
    let r = materialize(
        &mut cx,
        db,
        new_root,
        slot_sample,
        sort_dir,
        sort_budget,
        &mut sm,
    );
    match r {
        Ok(mut h) => {
            let s = &mut h.stats;
            (s.asked, s.fetched, s.local, s.done_skips, s.levels) =
                (fetched.0, fetched.1, fetched.2, fetched.3, fetched.4);
            s.old_missing += fetched.5;
            (s.old_asked, s.old_peers, s.old_bucket) = fetched.6;
            s.sync_s = st.sync_s;
            s.materialize_s = t1.elapsed().as_secs_f64();
            s.local_lookups = cx.store.lookups - lookups0;
            Ok(h)
        }
        Err(StepError::Missing) => {
            db.clear_done().map_err(StepError::Store)?;
            Err(StepError::Missing)
        }
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Layers in tiers

/// A layer and its tier: 0 for a step, `n + 1` for a merge of `fanout`
/// layers of tier `n`; the top tier holds one layer, everything since the
/// base.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tiered {
    pub layer: Layer,
    pub tier: u8,
}

/// Merge the newest layers while a tier is full. The list stays ordered
/// oldest first with tiers non-increasing, since merges only ever take the
/// newest suffix. Returns the merges made.
pub fn compact(
    root: &Path,
    layers: &mut Vec<Tiered>,
    fanout: usize,
    top: u8,
) -> Result<usize, String> {
    let mut merges = 0;
    loop {
        let Some(last) = layers.last() else { break };
        let tier = last.tier;
        let same = layers.iter().rev().take_while(|l| l.tier == tier).count();
        let take = if tier >= top {
            if same < 2 {
                break;
            }
            same
        } else if same >= fanout.max(2) {
            fanout.max(2)
        } else {
            break;
        };
        let from = layers.len() - take;
        let group: Vec<Layer> = layers[from..].iter().map(|l| l.layer.clone()).collect();
        let merged = merge_layers(root, &group, EPSILON).map_err(|e| format!("merge: {e}"))?;
        layers.truncate(from);
        layers.push(Tiered {
            layer: merged,
            tier: (tier + 1).min(top),
        });
        merges += 1;
    }
    Ok(merges)
}

// ---------------------------------------------------------------------------
// Heads

/// The head files as they would read with `optimistic` as the attested
/// update: the local mirror, with that one file replaced.
struct Overlay<'a> {
    dir: &'a Path,
    rel: &'a str,
    bytes: &'a [u8],
}

/// The head file a tier is verified from.
fn tier_file(tier: Tier) -> &'static str {
    match tier {
        Tier::Finalized => paths::FINALITY,
        Tier::Attested => paths::OPTIMISTIC,
    }
}

impl HeadSource for Overlay<'_> {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        if rel == self.rel {
            return Ok(Some(self.bytes.to_vec()));
        }
        DirSource(self.dir.to_path_buf()).read_head(rel)
    }
}

/// Verified heads from a beacon node's light-client objects, laid out in
/// `root/head/` as the bucket holds them.
pub struct Heads {
    beacon: Beacon,
    checkpoint: B256,
    root: PathBuf,
    chain: Chain,
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

impl Heads {
    pub fn new(beacon: &str, checkpoint: B256, root: &Path) -> Heads {
        Heads {
            beacon: Beacon::new(beacon),
            checkpoint,
            root: root.to_path_buf(),
            chain: Chain::mainnet(),
        }
    }

    fn bootstrap_period(&self) -> Result<u64, String> {
        let p = self.root.join(paths::bootstrap(&self.checkpoint));
        let boot = match fs::read(&p) {
            Ok(b) => b,
            Err(_) => {
                let (b, _) = self.beacon.bootstrap(self.checkpoint)?;
                write_atomic(&p, &b)?;
                b
            }
        };
        let slot = serde_json::from_slice::<Value>(&boot)
            .ok()
            .and_then(|v| {
                v["data"]["header"]["beacon"]["slot"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .ok_or("bootstrap without a slot")?;
        Ok(csl_eth_head::period_of(slot))
    }

    /// Fetch period updates `lo..=hi` into the mirror; with `all`, also
    /// those already there.
    fn updates(&self, lo: u64, hi: u64, all: bool) -> Result<(), String> {
        let need: Vec<u64> = (lo..=hi)
            .filter(|p| all || !self.root.join(paths::update(*p)).exists())
            .collect();
        let (Some(&a), Some(&b)) = (need.first(), need.last()) else {
            return Ok(());
        };
        for u in self.beacon.updates(a, b)? {
            if need.contains(&u.period) {
                write_atomic(&self.root.join(paths::update(u.period)), &u.bytes)?;
            }
        }
        Ok(())
    }

    /// The newest head of `tier`, verified from the checkpoint over the
    /// mirror's files: the update's bytes (optimistic or finality) and what
    /// they prove.
    pub fn latest(&self, tier: Tier) -> Result<(Vec<u8>, VerifiedHead), String> {
        let first = self.bootstrap_period()?;
        let upd = self.beacon.head_update(tier)?;
        let named = named_of(tier, &upd)?;
        let current = csl_eth_head::period_of(named.signature_slot);
        self.updates(first, current, false)?;
        let verify = || {
            verify_tier(
                &Overlay {
                    dir: &self.root,
                    rel: tier_file(tier),
                    bytes: &upd,
                },
                &self.chain,
                self.checkpoint,
                SystemTime::now(),
                tier,
            )
            .map_err(|e| e.to_string())
        };
        match verify() {
            Ok(h) => Ok((upd, h)),
            Err(_) => {
                // The open period's update improves until the period ends;
                // fetch the last two again and retry once.
                self.updates(current.saturating_sub(1).max(first), current, true)?;
                verify().map(|h| (upd, h))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Publishing

/// Copy into a local directory: a bucket's layout on disk.
pub struct DirPublish(pub PathBuf);

impl Publish for DirPublish {
    fn put(&self, key: &str, file: &Path) -> Result<(), String> {
        let to = self.0.join(key);
        if let Some(d) = to.parent() {
            fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        let tmp = to.with_extension("tmp-put");
        fs::copy(file, &tmp).map_err(|e| format!("{key}: {e}"))?;
        fs::rename(&tmp, &to).map_err(|e| format!("{key}: {e}"))
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        match fs::remove_file(self.0.join(key)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("{key}: {e}")),
        }
    }
}

/// Upload nothing; log what would go up.
pub struct DryRun;

impl Publish for DryRun {
    fn put(&self, key: &str, file: &Path) -> Result<(), String> {
        info!(
            key,
            bytes = fs::metadata(file).map(|m| m.len()).unwrap_or(0),
            "dry run: put"
        );
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), String> {
        info!(key, "dry run: delete");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The run

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    /// The local copy of the published prefix (`full/` of the bucket): the
    /// base's `snapshots/<hash>/` tables, and the tracker's `runs/`,
    /// `blobs/`, `head/` and manifests, laid out as published.
    #[arg(long)]
    pub root: PathBuf,
    /// The tracker's state (`track.json`) and log (`track.jsonl`,
    /// `peers.jsonl`).
    #[arg(long)]
    pub work: PathBuf,
    /// The base snapshot's block hash under `root` (a plain snapshot).
    /// Only on the first run; `track.json` remembers it.
    #[arg(long)]
    pub base: Option<B256>,
    /// The weak-subjectivity checkpoint root the head is verified from.
    #[arg(long)]
    pub checkpoint: B256,
    /// Beacon node with the light-client endpoints.
    #[arg(long, default_value = "https://lodestar-mainnet.chainsafe.io")]
    pub beacon: String,
    /// Invoked as `<program> put <key> <file>` / `<program> delete <key>`
    /// (`scripts/gcs-publish.sh`). Without it or `--to-dir`, a dry run.
    #[arg(long)]
    pub publish: Option<String>,
    /// Publish by copying into this directory instead.
    #[arg(long, conflicts_with = "publish")]
    pub to_dir: Option<PathBuf>,
    /// Prefix of every published key, e.g. `full/`.
    #[arg(long, default_value = "")]
    pub key_prefix: String,
    /// Layers of a tier merged into one of the next.
    #[arg(long, default_value_t = 4)]
    pub fanout: usize,
    /// The top tier (one layer, everything since the base). At 5 and
    /// fanout 4 the tiers below hold 1, 4, 16 and 64 blocks a layer, all
    /// small enough to carry hints (see `HINT_CAP`), and the since-base
    /// layer is rewritten every 256 blocks.
    #[arg(long, default_value_t = 5)]
    pub tiers: u8,
    /// Manifests kept published; runs only they reach are collected.
    /// At one block a step, 128 reaches back past the finalized block
    /// (two to three epochs), so that block's manifest is usually still
    /// there to pin.
    #[arg(long, default_value_t = 128)]
    pub keep: usize,
    /// Step only when the head is at least this many blocks past ours.
    #[arg(long, default_value_t = 1)]
    pub every_blocks: u64,
    /// Do not index owners by storage root (a new contract's storage trie
    /// another owner already holds is then fetched, not copied). The
    /// index is built from the held state at the first start (a scan of
    /// the account table).
    #[arg(long)]
    pub no_root_index: bool,
    /// Read the base's runs by range from here instead of keeping them
    /// under `--root`: the bucket's prefix over HTTPS (e.g.
    /// `https://storage.googleapis.com/csl-eth-demo/full/`) or a
    /// directory. The root then holds the base's manifest (fetched from
    /// here when missing), the layers and the head files. A step's old
    /// side comes from peers at the old root while it is in their window,
    /// and from here after a gap. There is no storage-root index then.
    #[arg(long)]
    pub base_url: Option<String>,
    /// Stop after this many published steps (0: never).
    #[arg(long, default_value_t = 0)]
    pub steps: u64,
    /// Stop after this many minutes (0: never).
    #[arg(long, default_value_t = 0)]
    pub max_wall_mins: u64,
    /// Peers to hold.
    #[arg(long, default_value_t = 12)]
    pub peers: usize,
    #[arg(long, default_value_t = 30303)]
    pub udp_port: u16,
    /// Memory for sorting a step's rows; a bigger step spills to
    /// `<work>/sort/`.
    #[arg(long, default_value_t = 1024)]
    pub sort_mib: u64,
    /// Changed slots read back through the client per step.
    #[arg(long, default_value_t = 2000)]
    pub verify_slots: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HeadRec {
    block_hash: B256,
    block_number: u64,
    timestamp: u64,
    state_root: B256,
}

impl HeadRec {
    fn head(&self) -> Head {
        Head {
            block_hash: self.block_hash,
            block_number: self.block_number,
            timestamp: self.timestamp,
            state_root: self.state_root,
        }
    }
}

/// What survives a restart.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct TrackState {
    base: B256,
    head: HeadRec,
    layers: Vec<Tiered>,
    steps: u64,
    /// Published runs (hex roots) and blobs.
    published_runs: BTreeSet<String>,
    /// Period updates published, with the blake3 of their bytes.
    published_updates: BTreeMap<u64, String>,
    bootstrap_published: bool,
    /// Published manifests, oldest first, with the runs each reaches.
    manifests: VecDeque<(B256, Vec<String>)>,
    /// The finalized block `head/finality` names, and the last two such
    /// blocks, whose manifests collection keeps.
    #[serde(default)]
    finalized: Option<HeadRec>,
    #[serde(default)]
    pinned: VecDeque<B256>,
    /// The block `head/optimistic` and `snapshots/latest` name.
    #[serde(default)]
    optimistic: Option<B256>,
}

impl TrackState {
    fn load(p: &Path) -> Result<Option<TrackState>, String> {
        match fs::read(p) {
            Ok(b) => serde_json::from_slice::<TrackState>(&b)
                .map(|mut st| {
                    st.published_runs = st.published_runs.iter().map(|r| run_name(r)).collect();
                    for (_, rs) in st.manifests.iter_mut() {
                        *rs = rs.iter().map(|r| run_name(r)).collect();
                    }
                    Some(st)
                })
                .map_err(|e| format!("{}: {e}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn save(&self, p: &Path) -> Result<(), String> {
        write_atomic(
            p,
            &serde_json::to_vec_pretty(self).expect("state serializes"),
        )
    }
}

struct Log(File);

impl Log {
    fn emit(&mut self, mut v: Value) {
        v["t"] = json!(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or(0.0));
        let _ = serde_json::to_writer(&mut self.0, &v);
        let _ = self.0.write_all(b"\n");
        let _ = self.0.flush();
    }
}

/// Seconds until a root of a block at `ts` is about to leave the peers'
/// window (about 128 blocks; stop at 110).
fn window_secs(ts: u64) -> u64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (ts + 110 * 12).saturating_sub(now)
}

/// A finalized block is stepped onto only with this much of its window
/// left; a catch-up longer than that targets the attested head instead.
const FINALIZED_MIN_WINDOW: u64 = 300;

/// Manifests to collect: the oldest past `keep`, never a pinned one.
fn collectable(
    manifests: &VecDeque<(B256, Vec<String>)>,
    keep: usize,
    protected: &HashSet<B256>,
) -> Vec<B256> {
    let newest = manifests.back().map(|(h, _)| *h);
    let over = manifests.len().saturating_sub(keep);
    manifests
        .iter()
        .map(|(h, _)| *h)
        .filter(|h| !protected.contains(h) && Some(*h) != newest)
        .take(over)
        .collect()
}

/// The files under `runs/` a manifest reaches: its layers' runs
/// (`<root>.run`) and hint files (`<blake3>.hints`).
fn manifest_runs(m: &Manifest) -> Vec<String> {
    m.layers
        .iter()
        .flat_map(|l| {
            l.tables
                .iter()
                .map(|t| format!("{}.run", hex::encode(t.root)))
                .chain(l.hints_file.map(|n| format!("{}.hints", hex::encode(n))))
        })
        .collect()
}

/// A state saved before hint files named runs by their bare root.
fn run_name(r: &str) -> String {
    if r.contains('.') {
        r.to_string()
    } else {
        format!("{r}.run")
    }
}

/// Read back what a step changed, through the client over the local files
/// at the new root: every changed account, the sampled slots, new code.
fn read_back(root: &Path, head: &Head, h: &Tracked) -> Result<Value, String> {
    let mut snap = Snapshot::open(DirDriver::new(root), Some(head.block_hash), head.state_root)
        .map_err(|e| format!("open: {e}"))?;
    for (k, a) in &h.accounts {
        match snap.account(k).0 {
            Read::Verified(got) if got == *a => {}
            other => return Err(format!("account {k}: {other:?}")),
        }
    }
    for (o, s, v) in &h.slots {
        match snap.storage(o, s).0 {
            Read::Verified(got) if got == *v => {}
            other => return Err(format!("slot {o}/{s}: {other:?}")),
        }
    }
    for k in h.rows.code.keys() {
        match snap.code(&B256::from(*k)).0 {
            Read::Verified(_) => {}
            other => return Err(format!("code {}: {other:?}", B256::from(*k))),
        }
    }
    Ok(json!({"accounts": h.accounts.len(), "slots": h.slots.len(), "codes": h.rows.code.len()}))
}

struct Tracker {
    args: Args,
    root: PathBuf,
    state_path: PathBuf,
    st: TrackState,
    base: Manifest,
    prefix: Option<Nibbles>,
    store: Store,
    publish: Box<dyn Publish>,
    log: Log,
}

impl Tracker {
    fn manifest(&self, head: &Head, latest: bool) -> Result<Manifest, String> {
        write_layered_manifest(
            &self.root,
            head,
            &self.base,
            self.st.layers.iter().map(|l| l.layer.clone()).collect(),
            latest,
        )
        .map_err(|e| format!("manifest: {e}"))
    }

    /// Write the step's layer, merge tiers, write the manifest, read the
    /// changes back through the client, publish, collect, save.
    /// A finalized step publishes `head/finality` and pins its manifest,
    /// and leaves `head/optimistic` and `snapshots/latest` alone.
    fn commit(
        &mut self,
        h: &mut Tracked,
        update: &[u8],
        vh: &VerifiedHead,
        tier: Tier,
    ) -> Result<Value, String> {
        let t0 = Instant::now();
        let e = &vh.execution;
        let head = Head {
            block_hash: e.block_hash,
            block_number: e.block_number,
            timestamp: e.timestamp,
            state_root: e.state_root,
        };
        let before = self.st.layers.clone();
        if !h.rows.is_empty() {
            let layer = write_layer_sorted(
                &self.root,
                self.st.head.block_number,
                head.block_number,
                &mut h.rows.sort,
                &h.rows.code,
                h.rows.owners.as_ref(),
                EPSILON,
            )
            .map_err(|e| format!("layer: {e}"))?;
            self.st.layers.push(Tiered { layer, tier: 0 });
        }
        let merges = compact(
            &self.root,
            &mut self.st.layers,
            self.args.fanout,
            self.args.tiers,
        )?;
        let manifest = self.manifest(&head, tier == Tier::Attested)?;
        let check = match read_back(&self.root, &head, h) {
            Ok(v) => v,
            Err(err) => {
                // Not published; the layers go back to what they were.
                self.st.layers = before;
                return Err(format!("read-back failed, step not published: {err}"));
            }
        };
        let built_s = t0.elapsed().as_secs_f64();
        let t1 = Instant::now();
        let sent = self.publish_step(&head, &manifest, h, update, tier)?;
        self.st.head = HeadRec {
            block_hash: head.block_hash,
            block_number: head.block_number,
            timestamp: head.timestamp,
            state_root: head.state_root,
        };
        self.st.steps += 1;
        let collected = self.collect(&manifest)?;
        self.st.save(&self.state_path)?;
        self.store = Store::open_with(&self.root, &manifest, self.args.base_url.is_none())?;
        Ok(json!({
            "merges": merges, "runs": self.store.run_counts(), "check": check, "sent": sent,
            "collected": collected, "build_s": built_s, "publish_s": t1.elapsed().as_secs_f64(),
        }))
    }

    fn key(&self, rel: &str) -> String {
        format!("{}{rel}", self.args.key_prefix)
    }

    fn put(&self, rel: &str, sent: &mut (u64, u64)) -> Result<(), String> {
        let f = self.root.join(rel);
        self.publish.put(&self.key(rel), &f)?;
        sent.0 += 1;
        sent.1 += fs::metadata(&f).map(|m| m.len()).unwrap_or(0);
        Ok(())
    }

    /// Hash-named files first (runs, blobs), then the manifest, the head's
    /// files, and `snapshots/latest` last: a reader who sees a pointer
    /// finds everything it names.
    fn publish_step(
        &mut self,
        head: &Head,
        m: &Manifest,
        h: &Tracked,
        update: &[u8],
        tier: Tier,
    ) -> Result<Value, String> {
        let mut sent = (0u64, 0u64);
        for r in manifest_runs(m) {
            if !self.st.published_runs.contains(&r) {
                self.put(&format!("runs/{r}"), &mut sent)?;
                self.st.published_runs.insert(r);
            }
        }
        for c in h
            .rows
            .code
            .values()
            .filter(|c| c.len() > CODE_BLOB_THRESHOLD)
        {
            self.put(&blob_path(blake3::hash(c).as_bytes()), &mut sent)?;
        }
        self.put(&manifest_path(&head.block_hash), &mut sent)?;
        self.publish_updates(&mut sent)?;
        self.st
            .manifests
            .push_back((head.block_hash, manifest_runs(m)));
        match tier {
            Tier::Attested => {
                write_atomic(&self.root.join(paths::OPTIMISTIC), update)?;
                self.put(paths::OPTIMISTIC, &mut sent)?;
                self.put(LATEST_FILE, &mut sent)?;
                self.st.optimistic = Some(head.block_hash);
            }
            Tier::Finalized => self.publish_finality(head, update, &mut sent)?,
        }
        Ok(json!({"files": sent.0, "bytes": sent.1}))
    }

    /// The bootstrap once, and each period update whose bytes changed.
    fn publish_updates(&mut self, sent: &mut (u64, u64)) -> Result<(), String> {
        let cp = paths::bootstrap(&self.args.checkpoint);
        if !self.st.bootstrap_published {
            self.put(&cp, sent)?;
            self.st.bootstrap_published = true;
        }
        let dir = self.root.join("head/updates");
        if let Ok(rd) = fs::read_dir(&dir) {
            for e in rd.flatten() {
                let Some(p) = e.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) else {
                    continue;
                };
                let b = fs::read(e.path()).map_err(|e| e.to_string())?;
                let hx = blake3::hash(&b).to_hex().to_string();
                if self.st.published_updates.get(&p) != Some(&hx) {
                    self.put(&paths::update(p), sent)?;
                    self.st.published_updates.insert(p, hx);
                }
            }
        }
        Ok(())
    }

    /// Pin the finalized block's published manifest and point
    /// `head/finality` at it.
    fn publish_finality(
        &mut self,
        head: &Head,
        update: &[u8],
        sent: &mut (u64, u64),
    ) -> Result<(), String> {
        // The pin is saved before the pointer moves, so a crash between
        // the two never leaves a published `head/finality` unprotected;
        // the block the old pointer names stays the other pin.
        if !self.st.pinned.contains(&head.block_hash) {
            self.st.pinned.push_back(head.block_hash);
            while self.st.pinned.len() > 2 {
                self.st.pinned.pop_front();
            }
        }
        self.st.save(&self.state_path)?;
        write_atomic(&self.root.join(paths::FINALITY), update)?;
        self.put(paths::FINALITY, sent)?;
        self.st.finalized = Some(HeadRec {
            block_hash: head.block_hash,
            block_number: head.block_number,
            timestamp: head.timestamp,
            state_root: head.state_root,
        });
        Ok(())
    }

    /// The finalized block's manifest is already published (a step landed
    /// on it): pin it and publish `head/finality`.
    fn pin_finalized(&mut self, update: &[u8], vh: &VerifiedHead) -> Result<Value, String> {
        let e = &vh.execution;
        let head = Head {
            block_hash: e.block_hash,
            block_number: e.block_number,
            timestamp: e.timestamp,
            state_root: e.state_root,
        };
        let mut sent = (0, 0);
        self.publish_updates(&mut sent)?;
        self.publish_finality(&head, update, &mut sent)?;
        self.st.save(&self.state_path)?;
        Ok(json!({"files": sent.0, "bytes": sent.1}))
    }

    /// Manifests past `keep`, and runs no kept manifest reaches, deleted
    /// from the bucket and the local copy.
    fn collect(&mut self, current: &Manifest) -> Result<Value, String> {
        let mut gone_manifests = 0;
        // Never what a public pointer names: the pinned finalized blocks
        // (`head/finality`), the attested head (`head/optimistic`,
        // `snapshots/latest`) and the newest manifest, whatever `keep`.
        let protected: HashSet<B256> = self
            .st
            .pinned
            .iter()
            .copied()
            .chain(self.st.optimistic)
            .collect();
        for h in collectable(&self.st.manifests, self.args.keep.max(2), &protected) {
            self.st.manifests.retain(|(m, _)| *m != h);
            self.publish.delete(&self.key(&manifest_path(&h)))?;
            let _ = fs::remove_file(self.root.join(manifest_path(&h)));
            let _ = fs::remove_dir(self.root.join(manifest_path(&h)).parent().expect("dir"));
            gone_manifests += 1;
        }
        let live: HashSet<&String> = self
            .st
            .manifests
            .iter()
            .flat_map(|(_, r)| r.iter())
            .collect();
        let cur: HashSet<String> = manifest_runs(current).into_iter().collect();
        let dead: Vec<String> = self
            .st
            .published_runs
            .iter()
            .filter(|r| !live.contains(r) && !cur.contains(*r))
            .cloned()
            .collect();
        for r in &dead {
            let rel = format!("runs/{r}");
            self.publish.delete(&self.key(&rel))?;
            let _ = fs::remove_file(self.root.join(&rel));
            self.st.published_runs.remove(r);
        }
        // Runs merged away before they were ever published.
        let known: HashSet<String> = self.st.published_runs.iter().cloned().chain(cur).collect();
        let mut local = 0;
        if let Ok(rd) = fs::read_dir(self.root.join("runs")) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if (n.ends_with(".run") || n.ends_with(".hints")) && !known.contains(&n) {
                    let _ = fs::remove_file(e.path());
                    local += 1;
                }
            }
        }
        Ok(json!({"manifests": gone_manifests, "runs": dead.len(), "unpublished_runs": local}))
    }
}

pub async fn run(args: Args) -> Result<(), String> {
    let started = Instant::now();
    fs::create_dir_all(&args.work).map_err(|e| e.to_string())?;
    let state_path = args.work.join("track.json");
    let root = args.root.clone();
    let ranges: Option<Arc<dyn crate::remote::RangeGet>> = args.base_url.as_ref().map(|u| {
        if u.starts_with("http://") || u.starts_with("https://") {
            Arc::new(crate::remote::HttpRanges::new(u)) as Arc<dyn crate::remote::RangeGet>
        } else {
            Arc::new(crate::remote::DirRanges(PathBuf::from(u)))
        }
    });
    // Without a local base, its manifest comes from the bucket once.
    if let (Some(g), Some(b)) = (&ranges, args.base) {
        let p = root.join(manifest_path(&b));
        if !p.exists() {
            let bytes = g.file(&manifest_path(&b))?;
            Manifest::from_json(&bytes).map_err(|e| format!("base manifest: {e}"))?;
            fs::create_dir_all(p.parent().expect("dir")).map_err(|e| e.to_string())?;
            write_atomic(&p, &bytes)?;
        }
    }
    let st = match TrackState::load(&state_path)? {
        Some(st) => {
            if args.base.is_some_and(|b| b != st.base) {
                return Err(format!(
                    "track.json is for base {}, not {}",
                    st.base,
                    args.base.unwrap()
                ));
            }
            st
        }
        None => {
            let base = args
                .base
                .ok_or("no track.json yet: name the base with --base")?;
            let m = Manifest::from_json(
                &fs::read(root.join(manifest_path(&base)))
                    .map_err(|e| format!("base manifest: {e}"))?,
            )
            .map_err(|e| e.to_string())?;
            TrackState {
                base,
                head: HeadRec {
                    block_hash: m.block_hash,
                    block_number: m.block_number,
                    timestamp: m.timestamp,
                    state_root: m.state_root,
                },
                layers: Vec::new(),
                steps: 0,
                published_runs: BTreeSet::new(),
                published_updates: BTreeMap::new(),
                bootstrap_published: false,
                manifests: VecDeque::new(),
                finalized: None,
                pinned: VecDeque::new(),
                optimistic: None,
            }
        }
    };
    let base = Manifest::from_json(
        &fs::read(root.join(manifest_path(&st.base))).map_err(|e| format!("base manifest: {e}"))?,
    )
    .map_err(|e| e.to_string())?;
    if base.is_layered() {
        return Err("the base must be a plain snapshot".into());
    }
    let prefix = if base.prefix.is_empty() {
        None
    } else {
        Some(crate::produce::parse_prefix(&base.prefix)?)
    };
    let publish: Box<dyn Publish> = match (&args.publish, &args.to_dir) {
        (Some(p), _) => Box::new(Program {
            program: p.clone(),
            timeout: Duration::from_secs(300),
        }),
        (None, Some(d)) => Box::new(DirPublish(d.clone())),
        (None, None) => Box::new(DryRun),
    };
    let log = Log(File::options()
        .create(true)
        .append(true)
        .open(args.work.join("track.jsonl"))
        .map_err(|e| e.to_string())?);
    let head = st.head.head();
    let (store, held) = {
        let m = if st.layers.is_empty() {
            base.clone()
        } else {
            write_layered_manifest(
                &root,
                &head,
                &base,
                st.layers.iter().map(|l| l.layer.clone()).collect(),
                false,
            )
            .map_err(|e| e.to_string())?
        };
        (Store::open_with(&root, &m, ranges.is_none())?, m)
    };
    let mut remote = match &ranges {
        Some(g) => Some(crate::remote::RemoteBase::new(g.clone(), &base)?),
        None => None,
    };
    let mut h = Tracker {
        args: args.clone(),
        root: root.clone(),
        state_path,
        st,
        base,
        prefix,
        store,
        publish,
        log,
    };
    h.log.emit(json!({"ev": "start", "base": h.st.base, "head": h.st.head.block_number, "layers": h.st.layers.len(), "runs": h.store.run_counts()}));
    let heads = Heads::new(&args.beacon, args.checkpoint, &root);
    let peer_cfg = heal::Config {
        peers: args.peers,
        udp_port: args.udp_port,
        out: args.work.join("peers.jsonl"),
        ..heal::Config::default()
    };
    let mut pool = Pool::start(&peer_cfg).map_err(|e| e.to_string())?;
    // Fetched nodes, against the held state: kept across re-pivots and
    // restarts, emptied when a step commits.
    let mut db = NodeDb::open(&args.work.join("nodes"), h.st.head.state_root)?;
    let mut roots = if args.no_root_index || remote.is_some() {
        None
    } else {
        if !args.work.join("roots.idx").exists() {
            let t = Instant::now();
            let n = tokio::task::block_in_place(|| {
                build_root_index(&h.root, &held, &args.work, args.sort_mib << 20)
            })?;
            h.log
                .emit(json!({"ev": "root_index", "owners": n, "secs": t.elapsed().as_secs_f64()}));
        }
        Some(RootIndex::open(&args.work)?)
    };
    h.log.emit(json!({"ev": "nodes", "held": db.len(), "log_bytes": db.log_bytes(), "complete": db.done_len()}));
    let over = |s: u64| {
        (args.steps > 0 && s >= args.steps)
            || (args.max_wall_mins > 0
                && started.elapsed() > Duration::from_secs(args.max_wall_mins * 60))
    };
    let mut attempt = 0u64;
    let mut fin_checked: Option<Instant> = None;
    let mut fin_missed = 0u64;
    while !over(h.st.steps) {
        // The finalized tier, checked every 30 s (it moves once an epoch).
        let mut fin = None;
        if fin_checked.is_none_or(|t| t.elapsed() > Duration::from_secs(30)) {
            fin_checked = Some(Instant::now());
            match tokio::task::block_in_place(|| heads.latest(Tier::Finalized)) {
                Ok((fu, fvh)) => {
                    let fe = fvh.execution;
                    let newer =
                        h.st.finalized
                            .as_ref()
                            .is_none_or(|r| fe.block_number > r.block_number);
                    if !newer {
                    } else if h.st.manifests.iter().any(|(m, _)| *m == fe.block_hash) {
                        // A step landed on it: pin its manifest.
                        let v = tokio::task::block_in_place(|| h.pin_finalized(&fu, &fvh))?;
                        h.log.emit(json!({"ev": "finalized", "block": fe.block_number, "block_hash": fe.block_hash, "how": "pinned", "commit": v}));
                    } else if fe.block_number > h.st.head.block_number
                        && window_secs(fe.timestamp) >= FINALIZED_MIN_WINDOW
                    {
                        // Ahead of us with time left in the window: step
                        // to it first.
                        fin = Some((fu, fvh));
                    } else if fe.block_number != fin_missed {
                        // Passed over (or too old to reach): the next
                        // epoch's, about 6.4 minutes on, is stepped onto
                        // or pinned.
                        fin_missed = fe.block_number;
                        h.log.emit(json!({"ev": "finalized_missed", "block": fe.block_number, "head": h.st.head.block_number}));
                    }
                }
                Err(e) => h.log.emit(json!({"ev": "no_finalized", "error": e})),
            }
        }
        let tier = if fin.is_some() {
            Tier::Finalized
        } else {
            Tier::Attested
        };
        let latest = match fin {
            Some(x) => Ok(x),
            None => tokio::task::block_in_place(|| heads.latest(Tier::Attested)),
        };
        let (update, vh) = match latest {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "no verified head");
                h.log.emit(json!({"ev": "no_head", "error": e}));
                tokio::time::sleep(Duration::from_secs(6)).await;
                continue;
            }
        };
        let target = vh.execution;
        if target.block_number < h.st.head.block_number + args.every_blocks.max(1)
            || target.block_hash == h.st.head.block_hash
        {
            tokio::time::sleep(Duration::from_secs(3)).await;
            continue;
        }
        if pool.connected() == 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
            continue;
        }
        attempt += 1;
        // Peers keep about 128 blocks of roots; stop a little short.
        let deadline = Instant::now() + Duration::from_secs(window_secs(target.timestamp).max(60));
        let t0 = Instant::now();
        let from = h.st.head.block_number;
        let held_before = db.len();
        let r = track_step(
            &mut pool,
            &mut h.store,
            &mut db,
            h.st.head.state_root,
            target.state_root,
            h.prefix.as_ref(),
            args.verify_slots,
            deadline,
            &args.work.join("sort"),
            args.sort_mib << 20,
            roots.as_mut(),
            OldSide {
                // The held head is in the peers' window (with a minute to
                // spare): ask them for the old side first.
                peers: remote.is_some() && window_secs(h.st.head.timestamp) >= 60,
                remote: remote.as_mut(),
            },
        )
        .await;
        let step_s = t0.elapsed().as_secs_f64();
        let lag = |t: u64| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
                - t as f64
        };
        match r {
            Err(e) => {
                warn!(from, to = target.block_number, error = %e, held = db.len(), "step failed; re-pivoting");
                h.log.emit(json!({
                    "ev": "repivot", "attempt": attempt, "from": from, "to": target.block_number, "error": e.to_string(),
                    "step_s": step_s, "held": db.len(), "held_before": held_before, "complete": db.done_len(),
                    "log_bytes": db.log_bytes(), "peers": pool.connected(),
                }));
                if let StepError::Store(_) | StepError::TooDeep = e {
                    return Err(e.to_string());
                }
            }
            Ok(mut tracked) => {
                let res =
                    tokio::task::block_in_place(|| h.commit(&mut tracked, &update, &vh, tier));
                if res.is_ok() {
                    db.reset(h.st.head.state_root)?;
                    if let Some(ix) = roots.as_mut() {
                        for (r, o) in &tracked.new_tries {
                            ix.note(*r, *o)?;
                        }
                    }
                }
                match res {
                    Ok(v) => {
                        info!(
                            from,
                            to = target.block_number,
                            blocks = target.block_number - from,
                            nodes = tracked.stats.account_nodes + tracked.stats.storage_nodes,
                            mib = tracked.stats.node_bytes as f64 / 1048576.0,
                            step_s,
                            lag_s = lag(target.timestamp),
                            peers = pool.connected(),
                            "step"
                        );
                        h.log.emit(json!({
                            "ev": "step", "tier": format!("{tier:?}"), "step": h.st.steps, "attempt": attempt, "from": from, "to": target.block_number,
                            "blocks": target.block_number - from, "block_hash": target.block_hash, "state_root": target.state_root,
                            "step_s": step_s, "lag_s": lag(target.timestamp), "peers": pool.connected(),
                            "head_lag_s": vh.lag_secs, "participants": vh.participants, "stats": tracked.stats, "commit": v,
                        }));
                    }
                    Err(e) => {
                        h.log.emit(
                            json!({"ev": "commit_failed", "to": target.block_number, "error": e}),
                        );
                        return Err(e);
                    }
                }
            }
        }
    }
    h.log
        .emit(json!({"ev": "end", "steps": h.st.steps, "elapsed_s": started.elapsed().as_secs()}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::HashBuilder;
    use csl_eth_store::{build_rows, produce, AccountLeaf, ProduceOptions, Rows4};
    use csl_eth_trie::{encode_word, path_of};
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct Acct {
        balance: U256,
        storage: BTreeMap<B256, U256>,
        code: Option<Vec<u8>>,
    }

    type State = BTreeMap<B256, Acct>;

    fn storage_root(slots: &BTreeMap<B256, U256>) -> B256 {
        let mut hb = HashBuilder::default();
        for (k, v) in slots {
            hb.add_leaf(path_of(k), &encode_word(v));
        }
        hb.root()
    }

    fn account_of(a: &Acct) -> Account {
        Account {
            nonce: 1,
            balance: a.balance,
            storage_root: storage_root(&a.storage),
            code_hash: a.code.as_ref().map_or(KECCAK_EMPTY, keccak256),
        }
    }

    fn leaves(s: &State) -> Vec<AccountLeaf> {
        s.iter()
            .map(|(h, a)| AccountLeaf {
                hashed: *h,
                account: account_of(a),
                storage: a.storage.iter().map(|(k, v)| (*k, *v)).collect(),
            })
            .collect()
    }

    fn code_of(s: &State) -> HashMap<B256, Vec<u8>> {
        s.values()
            .filter_map(|a| a.code.clone())
            .map(|c| (keccak256(&c), c))
            .collect()
    }

    fn head_of(s: &State, n: u64) -> Head {
        let mut hb = HashBuilder::default();
        for (h, a) in s {
            hb.add_leaf(path_of(h), &account_of(a).encode());
        }
        Head {
            block_hash: B256::with_last_byte(n as u8 + 1),
            block_number: 100 + n,
            timestamp: 1_761_800_000 + 12 * n,
            state_root: hb.root(),
        }
    }

    fn rows(s: &State, h: &Head) -> Rows4 {
        build_rows(h, leaves(s), &code_of(s), ProduceOptions::default())
            .unwrap()
            .0
    }

    fn key(rng: &mut ChaCha8Rng) -> B256 {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        B256::from(h)
    }

    fn bytes(rng: &mut ChaCha8Rng, n: usize) -> Vec<u8> {
        let mut c = vec![0u8; n];
        rng.fill_bytes(&mut c);
        c
    }

    /// S0, and a step to S1 and on to S2 covering an owner whose storage
    /// root another already has, a deletion then recreation, a branch
    /// collapse, an extension split and hashed/embedded transitions.
    fn states() -> Vec<State> {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut s0 = State::new();
        for i in 0..800 {
            let mut storage = BTreeMap::new();
            if i % 3 == 0 {
                for _ in 0..rng.random_range(1..20) {
                    storage.insert(key(&mut rng), U256::from(rng.random::<u64>() | 1));
                }
            }
            let code = (i % 7 == 1).then(|| bytes(&mut rng, if i % 2 == 0 { 500 } else { 5000 }));
            s0.insert(
                key(&mut rng),
                Acct {
                    balance: U256::from(i),
                    storage,
                    code,
                },
            );
        }
        let mut p = [0x33u8; 32];
        p[30] = 0x10;
        let p1 = B256::from(p);
        p[30] = 0x70;
        let p2 = B256::from(p);
        let mut p = [0x33u8; 32];
        p[15] = 0x44;
        let p3 = B256::from(p);
        for k in [p1, p2] {
            s0.insert(
                k,
                Acct {
                    balance: U256::from(5u64),
                    storage: BTreeMap::new(),
                    code: None,
                },
            );
        }
        let shared = key(&mut rng);
        let mut bs = BTreeMap::new();
        for _ in 0..100 {
            bs.insert(key(&mut rng), U256::from(rng.random::<u64>() | 1));
        }
        s0.insert(
            shared,
            Acct {
                balance: U256::ZERO,
                storage: bs,
                code: Some(bytes(&mut rng, 900)),
            },
        );
        let recreated = key(&mut rng);
        let mut rs = BTreeMap::new();
        for _ in 0..40 {
            rs.insert(key(&mut rng), U256::from(rng.random::<u64>() | 1));
        }
        s0.insert(
            recreated,
            Acct {
                balance: U256::from(9u64),
                storage: rs.clone(),
                code: None,
            },
        );
        let embedded = key(&mut rng);
        let mut es = BTreeMap::new();
        let mut a = [0x21u8; 32];
        a[30] = 0x10;
        es.insert(B256::from(a), U256::from(1u64));
        a[30] = 0x20;
        es.insert(B256::from(a), U256::from(2u64));
        s0.insert(
            embedded,
            Acct {
                balance: U256::ZERO,
                storage: es,
                code: None,
            },
        );

        let mut s1 = churn(&s0, &mut rng);
        s1.insert(
            p3,
            Acct {
                balance: U256::from(3u64),
                storage: BTreeMap::new(),
                code: None,
            },
        );
        let x = s1[&shared].clone();
        s1.insert(
            key(&mut rng),
            Acct {
                balance: U256::from(2u64),
                ..x
            },
        );
        s1.remove(&recreated);
        a[30] = 0x10;
        s1.get_mut(&embedded)
            .unwrap()
            .storage
            .insert(B256::from(a), U256::MAX - U256::from(5u64));

        let mut s2 = churn(&s1, &mut rng);
        s2.remove(&p2);
        let mut rs2: BTreeMap<B256, U256> = rs.into_iter().take(20).collect();
        rs2.insert(key(&mut rng), U256::from(5u64));
        s2.insert(
            recreated,
            Acct {
                balance: U256::from(1u64),
                storage: rs2,
                code: Some(bytes(&mut rng, 6000)),
            },
        );
        s2.get_mut(&embedded)
            .unwrap()
            .storage
            .insert(B256::from(a), U256::from(3u64));
        vec![s0, s1, s2]
    }

    fn churn(s: &State, rng: &mut ChaCha8Rng) -> State {
        let mut next = s.clone();
        let keys: Vec<B256> = next.keys().copied().collect();
        for _ in 0..keys.len() / 25 {
            let k = keys[rng.random_range(0..keys.len())];
            let a = next.get_mut(&k).unwrap();
            a.balance += U256::from(1u64);
            if !a.storage.is_empty() && rng.random_bool(0.4) {
                a.storage
                    .insert(key(rng), U256::from(rng.random::<u64>() | 1));
                let first = *a.storage.keys().next().unwrap();
                a.storage.remove(&first);
            }
        }
        for _ in 0..4 {
            let c = rng.random_bool(0.5).then(|| bytes(rng, 300));
            next.insert(
                key(rng),
                Acct {
                    balance: U256::from(1u64),
                    storage: BTreeMap::new(),
                    code: c,
                },
            );
        }
        next
    }

    /// A state's nodes and code in memory, served like peers serve a root;
    /// `budget` nodes, then nothing (a root that left the window).
    struct Mem {
        acct: HashMap<[u8; 32], Vec<u8>>,
        stor: HashMap<[u8; 32], Vec<u8>>,
        code: HashMap<B256, Vec<u8>>,
        budget: usize,
        /// An older root the peers still serve (the old side).
        older: Option<Box<Mem>>,
    }

    impl Mem {
        fn of(s: &State, h: &Head) -> Mem {
            let r = rows(s, h);
            Mem {
                acct: r.account.into_iter().collect(),
                stor: r.storage.into_iter().collect(),
                code: code_of(s),
                budget: usize::MAX,
                older: None,
            }
        }

        fn get(&self, n: &Need) -> Option<&Vec<u8>> {
            let nk = NodeKey::prefix(&n.path, n.path.len());
            let b = match n.owner {
                None => self.acct.get(&nk.table_key().unwrap()),
                Some(o) => self.stor.get(&nk.storage_table_key(&o).unwrap()),
            };
            b.filter(|b| keccak256(b) == n.hash)
                .or_else(|| self.older.as_ref().and_then(|m| m.get(n)))
        }
    }

    impl Source for Mem {
        async fn nodes(&mut self, _: B256, needs: &[Need], _: Instant) -> HashMap<usize, Bytes> {
            let mut out = HashMap::new();
            for (i, n) in needs.iter().enumerate() {
                if self.budget == 0 {
                    break;
                }
                if let Some(b) = self.get(n) {
                    out.insert(i, Bytes::from(b.clone()));
                    self.budget -= 1;
                }
            }
            out
        }
        async fn codes(&mut self, hashes: &[B256], _: Instant) -> HashMap<B256, Bytes> {
            hashes
                .iter()
                .filter_map(|h| self.code.get(h).map(|c| (*h, Bytes::from(c.clone()))))
                .collect()
        }
    }

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "csl-eth-tracker-{}-{}-{name}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(3600)
    }

    /// Every account of `s`, a slot of each, and the deleted ones, read
    /// through the client at `h`.
    fn reads_as(dir: &Path, s: &State, gone: &[B256], h: &Head) {
        let mut snap =
            Snapshot::open(DirDriver::new(dir), Some(h.block_hash), h.state_root).unwrap();
        for (k, a) in s {
            assert_eq!(
                snap.account(k).0,
                Read::Verified(account_of(a)),
                "account {k}"
            );
            for (slot, v) in a.storage.iter().take(3) {
                assert_eq!(
                    snap.storage(k, slot).0,
                    Read::Verified(*v),
                    "slot {k}/{slot}"
                );
            }
            if let Some(c) = &a.code {
                assert_eq!(snap.code(&keccak256(c)).0, Read::Verified(c.clone()));
            }
        }
        for k in gone.iter().filter(|k| !s.contains_key(*k)) {
            assert!(snap.account(k).0.is_absent(), "{k} should be gone");
        }
    }

    /// One step committed as the tracker does, minus heads and
    /// publishing.
    #[allow(clippy::too_many_arguments)]
    fn commit(
        dir: &Path,
        base: &Manifest,
        layers: &mut Vec<Tiered>,
        from: &Head,
        to: &Head,
        h: &mut Tracked,
        fanout: usize,
        top: u8,
    ) -> (Store, Manifest) {
        if !h.rows.is_empty() {
            let layer = write_layer_sorted(
                dir,
                from.block_number,
                to.block_number,
                &mut h.rows.sort,
                &h.rows.code,
                h.rows.owners.as_ref(),
                EPSILON,
            )
            .unwrap();
            layers.push(Tiered { layer, tier: 0 });
        }
        compact(dir, layers, fanout, top).unwrap();
        let m = write_layered_manifest(
            dir,
            to,
            base,
            layers.iter().map(|l| l.layer.clone()).collect(),
            true,
        )
        .unwrap();
        read_back(dir, to, h).unwrap();
        // A tracker without a local base keeps only the layers.
        let local = m
            .runs(TABLE_ACCOUNT_NODES)
            .first()
            .is_some_and(|at| dir.join(&at.path).exists());
        (Store::open_with(dir, &m, local).unwrap(), m)
    }

    /// The bucket serving pages short or wrong for a while: the asks then
    /// come back empty, and once it serves them right the same base answers
    /// every node (nothing bad stays cached), each checked by hash.
    #[tokio::test]
    async fn a_bad_bucket_page_is_fetched_again() {
        use crate::remote::{DirRanges, RangeGet, RemoteBase};
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Flaky(DirRanges, AtomicBool);
        impl RangeGet for Flaky {
            fn get(&self, rel: &str, off: u64, len: usize) -> Result<Vec<u8>, String> {
                let mut b = self.0.get(rel, off, len)?;
                if self.1.load(Ordering::Relaxed) {
                    // Every other page short, the rest with a flipped byte.
                    if off % 2 == 0 {
                        b.truncate(b.len() / 2);
                    } else if let Some(x) = b.get_mut(len / 2) {
                        *x ^= 0x40;
                    }
                }
                Ok(b)
            }
            fn file(&self, rel: &str) -> Result<Vec<u8>, String> {
                self.0.file(rel)
            }
        }
        let s = states();
        let h0 = head_of(&s[0], 0);
        let bucket = scratch("flaky");
        let base = produce(&bucket, &h0, "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let r = rows(&s[0], &h0);
        let needs: Vec<Need> = r
            .account
            .iter()
            .map(|(k, v)| {
                // The account table's key: packed path, then its depth.
                let nibs: Vec<u8> = (0..k[31] as usize)
                    .map(|i| (k[i / 2] >> if i % 2 == 0 { 4 } else { 0 }) & 0xf)
                    .collect();
                Need {
                    owner: None,
                    path: Nibbles::from_nibbles(&nibs),
                    hash: keccak256(v),
                }
            })
            .collect();
        let flaky = Arc::new(Flaky(DirRanges(bucket.clone()), AtomicBool::new(true)));
        let mut rb = RemoteBase::new(flaky.clone(), &base).unwrap();
        let bad = rb.nodes(&needs).await.unwrap();
        eprintln!("bad pages: {} of {} answered", bad.len(), needs.len());
        assert!(bad.len() < needs.len());
        flaky.1.store(false, Ordering::Relaxed);
        let good = rb.nodes(&needs).await.unwrap();
        assert_eq!(
            good.len(),
            needs.len(),
            "every node once the pages are right"
        );
        for (i, b) in good {
            assert_eq!(keccak256(&b), needs[i].hash);
        }
        fs::remove_dir_all(&bucket).ok();
    }

    /// Without the base on disk: across a gap the old side comes from the
    /// base's runs by range (a directory standing in for the bucket); in
    /// the window, from peers at the old root. The layers are what a
    /// tracker with the base on disk writes, and read back without it.
    #[tokio::test]
    async fn tracks_without_a_local_base() {
        use crate::remote::{DirRanges, RemoteBase};
        let s = states();
        let heads: Vec<Head> = s
            .iter()
            .enumerate()
            .map(|(i, x)| head_of(x, i as u64))
            .collect();
        let bucket = scratch("bucket");
        let base = produce(&bucket, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let root = scratch("diskless");
        let mp = manifest_path(&base.block_hash);
        fs::create_dir_all(root.join(&mp).parent().unwrap()).unwrap();
        fs::copy(bucket.join(&mp), root.join(&mp)).unwrap();
        fs::create_dir_all(root.join("runs")).unwrap();
        let mut store = Store::open_with(&root, &base, false).unwrap();
        assert_eq!(store.run_counts(), [0, 0, 0]);
        let mut rb = RemoteBase::new(Arc::new(DirRanges(bucket.clone())), &base).unwrap();
        let mut db = NodeDb::open(&root.join("nodes"), heads[0].state_root).unwrap();
        let mut layers = Vec::new();
        // The same steps with the base on disk, for comparison.
        let local = scratch("local");
        let lbase = produce(&local, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut lstore = Store::open(&local, &lbase).unwrap();
        let mut ldb = NodeDb::open(&local.join("nodes"), heads[0].state_root).unwrap();
        let mut llayers = Vec::new();
        for i in 1..=2 {
            let mut lh = step(
                &mut Mem::of(&s[i], &heads[i]),
                &mut lstore,
                &mut ldb,
                &heads[i - 1],
                &heads[i],
                &local,
                64 << 20,
            )
            .await
            .unwrap();
            let lgot = lh.rows.collect();
            (lstore, _) = commit(
                &local,
                &lbase,
                &mut llayers,
                &heads[i - 1],
                &heads[i],
                &mut lh,
                4,
                3,
            );
            ldb.reset(heads[i].state_root).unwrap();
            let mut src = Mem::of(&s[i], &heads[i]);
            // Step 1 crosses a gap: no peer has S0. Step 2 is in the window.
            let peers = i == 2;
            if peers {
                src.older = Some(Box::new(Mem::of(&s[i - 1], &heads[i - 1])));
            }
            let before = rb.requests;
            let mut h = track_step(
                &mut src,
                &mut store,
                &mut db,
                heads[i - 1].state_root,
                heads[i].state_root,
                None,
                10_000,
                far(),
                &root.join("sort"),
                64 << 20,
                None,
                OldSide {
                    peers,
                    remote: Some(&mut rb),
                },
            )
            .await
            .unwrap();
            eprintln!(
                "diskless step {i}: {:?}, bucket {} requests",
                h.stats, rb.requests
            );
            if peers {
                assert!(h.stats.old_peers > 0);
                assert_eq!(rb.requests, before, "peers served the old side");
            } else {
                assert!(h.stats.old_bucket > 0 && rb.requests > before);
            }
            assert_eq!(h.stats.old_missing, 0);
            let want = LayerRows::diff(&rows(&s[i - 1], &heads[i - 1]), &rows(&s[i], &heads[i]));
            let r = rows(&s[i], &heads[i]);
            let acct: HashMap<_, _> = r.account.iter().cloned().collect();
            let stor: HashMap<_, _> = r.storage.iter().cloned().collect();
            let code = code_of(&s[i]);
            let got = h.rows.collect();
            assert_eq!(got.account, lgot.account, "account rows as with the base");
            assert_eq!(got.storage, lgot.storage, "storage rows as with the base");
            assert!(want
                .account
                .iter()
                .all(|(k, v)| got.account.get(k) == Some(v)));
            assert!(want
                .storage
                .iter()
                .all(|(k, v)| got.storage.get(k) == Some(v)));
            assert!(got.account.iter().all(|(k, v)| acct.get(k) == Some(v)));
            assert!(got.storage.iter().all(|(k, v)| stor.get(k) == Some(v)));
            // Code the base holds may be written again (the tracker cannot
            // see the base's code table); nothing else.
            assert!(want.code.keys().all(|k| got.code.contains_key(k)));
            assert!(got.code.keys().all(|k| code.contains_key(&B256::from(*k))));
            let m;
            (store, m) = commit(
                &root,
                &base,
                &mut layers,
                &heads[i - 1],
                &heads[i],
                &mut h,
                4,
                3,
            );
            assert_eq!(store.run_counts()[0], m.runs(TABLE_ACCOUNT_NODES).len() - 1);
            db.reset(heads[i].state_root).unwrap();
        }
        // With the base back in place (its runs and blobs) every key
        // reads as S2.
        fn put_back(from: &Path, to: &Path) {
            for e in fs::read_dir(from).unwrap().flatten() {
                let t = to.join(e.file_name());
                if e.file_type().unwrap().is_dir() {
                    fs::create_dir_all(&t).unwrap();
                    put_back(&e.path(), &t);
                } else if !t.exists() {
                    fs::copy(e.path(), &t).unwrap();
                }
            }
        }
        put_back(&bucket, &root);
        let all: Vec<B256> = s.iter().flat_map(|x| x.keys().copied()).collect();
        reads_as(&root, &s[2], &all, &heads[2]);
        fs::remove_dir_all(&local).ok();
        fs::remove_dir_all(&bucket).ok();
        fs::remove_dir_all(&root).ok();
    }

    async fn step(
        src: &mut Mem,
        store: &mut Store,
        db: &mut NodeDb,
        old: &Head,
        new: &Head,
        dir: &Path,
        budget: u64,
    ) -> Result<Tracked, StepError> {
        track_step(
            src,
            store,
            db,
            old.state_root,
            new.state_root,
            None,
            10_000,
            far(),
            &dir.join("sort"),
            budget,
            None,
            OldSide::default(),
        )
        .await
    }

    /// Does some run of `m` hold `v` under `k` in table `t`?
    fn holds(dir: &Path, m: &Manifest, t: u16, k: &[u8; 32], v: &[u8]) -> bool {
        m.runs(t).into_iter().any(|at| {
            let f = File::open(dir.join(&at.path)).unwrap();
            let mut rref = at.table.run_ref(at.block_lo);
            rref.block_hi = at.block_hi;
            let mut r = Reader::try_with_format(f, rref, RUN_FORMAT).unwrap();
            r.prepare().unwrap();
            r.get_entry(k)
                .unwrap()
                .0
                .is_some_and(|e| e.tag == 0 && e.value == v)
        })
    }

    /// Every node of a fresh build of `s` is held, byte for byte, at its
    /// position by the base or a layer of `m`, and every code is held.
    fn byte_identical(dir: &Path, m: &Manifest, s: &State, h: &Head) {
        let r = rows(s, h);
        for (k, v) in &r.account {
            assert!(
                holds(dir, m, TABLE_ACCOUNT_NODES, k, v),
                "account row {}",
                hex::encode(k)
            );
        }
        for (k, v) in &r.storage {
            assert!(
                holds(dir, m, TABLE_STORAGE_NODES, k, v),
                "storage row {}",
                hex::encode(k)
            );
        }
        let mut store = Store::open(dir, m).unwrap();
        for c in code_of(s).keys() {
            assert!(store.has_code(c).unwrap(), "code {c}");
        }
    }

    #[tokio::test]
    async fn tracks_step_by_step_and_across_a_gap() {
        let s = states();
        let heads: Vec<Head> = s
            .iter()
            .enumerate()
            .map(|(i, x)| head_of(x, i as u64))
            .collect();
        let dir = scratch("steps");
        let base = produce(&dir, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&dir, &base).unwrap();
        let mut db = NodeDb::open(&dir.join("nodes"), heads[0].state_root).unwrap();
        let mut layers = Vec::new();
        let all: Vec<B256> = s.iter().flat_map(|x| x.keys().copied()).collect();
        for i in 1..s.len() {
            let mut src = Mem::of(&s[i], &heads[i]);
            let mut h = step(
                &mut src,
                &mut store,
                &mut db,
                &heads[i - 1],
                &heads[i],
                &dir,
                64 << 20,
            )
            .await
            .unwrap();
            // Everything a diff of the full rows says changed, and nothing
            // that is not the new state's.
            let want = LayerRows::diff(&rows(&s[i - 1], &heads[i - 1]), &rows(&s[i], &heads[i]));
            let r = rows(&s[i], &heads[i]);
            let acct: HashMap<_, _> = r.account.iter().cloned().collect();
            let stor: HashMap<_, _> = r.storage.iter().cloned().collect();
            let got = h.rows.collect();
            for (k, v) in &want.account {
                assert_eq!(got.account.get(k), Some(v), "account row missing");
            }
            for (k, v) in &want.storage {
                assert_eq!(got.storage.get(k), Some(v), "storage row missing");
            }
            assert!(got.account.iter().all(|(k, v)| acct.get(k) == Some(v)));
            assert!(got.storage.iter().all(|(k, v)| stor.get(k) == Some(v)));
            assert_eq!(
                got.code.keys().collect::<BTreeSet<_>>(),
                want.code.keys().collect::<BTreeSet<_>>()
            );
            eprintln!("step {i}: {:?}", h.stats);
            let m;
            (store, m) = commit(
                &dir,
                &base,
                &mut layers,
                &heads[i - 1],
                &heads[i],
                &mut h,
                4,
                3,
            );
            db.reset(heads[i].state_root).unwrap();
            reads_as(&dir, &s[i], &all, &heads[i]);
            byte_identical(&dir, &m, &s[i], &heads[i]);
        }
        // S0 straight to S2 from the base alone: a gap is a bigger diff.
        let gap = scratch("gap");
        let base2 = produce(&gap, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&gap, &base2).unwrap();
        let mut db = NodeDb::open(&gap.join("nodes"), heads[0].state_root).unwrap();
        let mut src = Mem::of(&s[2], &heads[2]);
        let mut h = step(
            &mut src,
            &mut store,
            &mut db,
            &heads[0],
            &heads[2],
            &gap,
            64 << 20,
        )
        .await
        .unwrap();
        let mut layers = Vec::new();
        let (_, m) = commit(
            &gap,
            &base2,
            &mut layers,
            &heads[0],
            &heads[2],
            &mut h,
            4,
            3,
        );
        reads_as(&gap, &s[2], &all, &heads[2]);
        byte_identical(&gap, &m, &s[2], &heads[2]);
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&gap).ok();
    }

    #[tokio::test]
    async fn a_step_bigger_than_its_sort_budget_spills() {
        let s = states();
        let heads: Vec<Head> = s
            .iter()
            .enumerate()
            .map(|(i, x)| head_of(x, i as u64))
            .collect();
        let dir = scratch("spill");
        let base = produce(&dir, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&dir, &base).unwrap();
        let mut db = NodeDb::open(&dir.join("nodes"), heads[0].state_root).unwrap();
        let mut src = Mem::of(&s[2], &heads[2]);
        let mut h = step(
            &mut src,
            &mut store,
            &mut db,
            &heads[0],
            &heads[2],
            &dir,
            8 << 10,
        )
        .await
        .unwrap();
        assert!(
            h.rows.sort.stats(SORT_STORAGE).spills > 0
                || h.rows.sort.stats(SORT_ACCOUNT).spills > 0
        );
        let mut layers = Vec::new();
        let (_, m) = commit(&dir, &base, &mut layers, &heads[0], &heads[2], &mut h, 4, 3);
        byte_identical(&dir, &m, &s[2], &heads[2]);
        reads_as(&dir, &s[2], &[], &heads[2]);
        fs::remove_dir_all(&dir).ok();
    }

    /// A long backlog: each root leaves the window before its step is
    /// done, the process restarts in the middle (with a torn record at the
    /// log's end), and the last root completes from what is on disk plus
    /// the few nodes it adds.
    #[tokio::test]
    async fn catch_up_across_pivots_and_a_restart() {
        let s0 = states().remove(0);
        let mut rng = ChaCha8Rng::seed_from_u64(5);
        let mut chain = vec![s0];
        for _ in 0..6 {
            let next = churn(chain.last().unwrap(), &mut rng);
            chain.push(next);
        }
        let heads: Vec<Head> = chain
            .iter()
            .enumerate()
            .map(|(i, x)| head_of(x, i as u64))
            .collect();
        let last = chain.len() - 1;
        // What one step from S0 to the last state fetches with nothing on
        // disk.
        let fresh = scratch("fresh");
        let fbase = produce(
            &fresh,
            &heads[0],
            "",
            leaves(&chain[0]),
            &code_of(&chain[0]),
        )
        .unwrap()
        .manifest;
        let mut fstore = Store::open(&fresh, &fbase).unwrap();
        let mut fdb = NodeDb::open(&fresh.join("nodes"), heads[0].state_root).unwrap();
        let full = step(
            &mut Mem::of(&chain[last], &heads[last]),
            &mut fstore,
            &mut fdb,
            &heads[0],
            &heads[last],
            &fresh,
            64 << 20,
        )
        .await
        .unwrap()
        .stats;
        fs::remove_dir_all(&fresh).ok();

        let dir = scratch("catchup");
        let base = produce(&dir, &heads[0], "", leaves(&chain[0]), &code_of(&chain[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&dir, &base).unwrap();
        let nodes = dir.join("nodes");
        let mut db = NodeDb::open(&nodes, heads[0].state_root).unwrap();
        let budget = (full.fetched / 4) as usize;
        let mut fetched = 0;
        for (i, target) in [2usize, 3].into_iter().enumerate() {
            let mut src = Mem::of(&chain[target], &heads[target]);
            src.budget = budget;
            let e = step(
                &mut src,
                &mut store,
                &mut db,
                &heads[0],
                &heads[target],
                &dir,
                64 << 20,
            )
            .await;
            assert!(
                matches!(e, Err(StepError::Unresolved { .. })),
                "attempt {i}: {:?}",
                e.as_ref().err()
            );
            fetched += budget;
        }
        let (held, complete) = (db.len(), db.done_len());
        assert!(held > 0 && complete > 0, "{held} {complete}");
        // Restart: the process dies mid-write.
        drop(db);
        File::options()
            .append(true)
            .open(nodes.join("log"))
            .unwrap()
            .write_all(&[7u8; 50])
            .unwrap();
        let mut db = NodeDb::open(&nodes, heads[0].state_root).unwrap();
        assert_eq!((db.len(), db.done_len()), (held, complete));
        let mut src = Mem::of(&chain[4], &heads[4]);
        src.budget = budget;
        assert!(step(
            &mut src,
            &mut store,
            &mut db,
            &heads[0],
            &heads[4],
            &dir,
            64 << 20
        )
        .await
        .is_err());
        fetched += budget;
        // The last root completes.
        let mut src = Mem::of(&chain[last], &heads[last]);
        let mut h = step(
            &mut src,
            &mut store,
            &mut db,
            &heads[0],
            &heads[last],
            &dir,
            64 << 20,
        )
        .await
        .unwrap();
        eprintln!(
            "full {} fetched; catch-up {} before, {} in the last attempt: {:?}",
            full.fetched, fetched, h.stats.fetched, h.stats
        );
        assert!(h.stats.local + h.stats.done_skips > 0);
        assert!(
            h.stats.fetched < full.fetched,
            "{} vs {}",
            h.stats.fetched,
            full.fetched
        );
        let mut layers = Vec::new();
        let (_, m) = commit(
            &dir,
            &base,
            &mut layers,
            &heads[0],
            &heads[last],
            &mut h,
            4,
            3,
        );
        byte_identical(&dir, &m, &chain[last], &heads[last]);
        reads_as(&dir, &chain[last], &[], &heads[last]);
        // A held state that moved empties the directory.
        drop(db);
        let db = NodeDb::open(&nodes, heads[last].state_root).unwrap();
        assert_eq!((db.len(), db.done_len()), (0, 0));
        fs::remove_dir_all(&dir).ok();
    }

    /// Markers that claim more than the disk holds (a false eight-byte
    /// match, or a lost log) make the materializing walk miss a node: the
    /// markers are dropped and the next attempt completes.
    #[tokio::test]
    async fn a_marker_without_its_nodes_is_recovered() {
        let s = states();
        let heads: Vec<Head> = s
            .iter()
            .enumerate()
            .map(|(i, x)| head_of(x, i as u64))
            .collect();
        let dir = scratch("markers");
        let base = produce(&dir, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&dir, &base).unwrap();
        let mut db = NodeDb::open(&dir.join("nodes"), heads[0].state_root).unwrap();
        let mut src = Mem::of(&s[1], &heads[1]);
        src.budget = 200;
        assert!(step(
            &mut src,
            &mut store,
            &mut db,
            &heads[0],
            &heads[1],
            &dir,
            64 << 20
        )
        .await
        .is_err());
        // Lose the log, keep the markers.
        let complete = db.done_len();
        assert!(complete > 0);
        db.log.set_len(0).unwrap();
        db.end = 0;
        db.idx.clear();
        let mut src = Mem::of(&s[1], &heads[1]);
        let e = step(
            &mut src,
            &mut store,
            &mut db,
            &heads[0],
            &heads[1],
            &dir,
            64 << 20,
        )
        .await;
        assert!(
            matches!(e, Err(StepError::Missing)),
            "{:?}",
            e.as_ref().err()
        );
        assert_eq!(db.done_len(), 0);
        let mut h = step(
            &mut src,
            &mut store,
            &mut db,
            &heads[0],
            &heads[1],
            &dir,
            64 << 20,
        )
        .await
        .unwrap();
        let mut layers = Vec::new();
        let (_, m) = commit(&dir, &base, &mut layers, &heads[0], &heads[1], &mut h, 4, 3);
        byte_identical(&dir, &m, &s[1], &heads[1]);
        fs::remove_dir_all(&dir).ok();
    }

    /// A new account whose storage another account already holds: with
    /// the root index the trie is copied from the store, nothing of it
    /// fetched, and the layer is the same as without.
    #[tokio::test]
    async fn a_new_trie_another_owner_holds_is_copied() {
        let s0 = states().remove(0);
        let (_, big) = s0
            .iter()
            .max_by_key(|(_, a)| a.storage.len())
            .map(|(k, a)| (*k, a.clone()))
            .unwrap();
        let mut s1 = s0.clone();
        let mut rng = ChaCha8Rng::seed_from_u64(11);
        let fresh = key(&mut rng);
        s1.insert(
            fresh,
            Acct {
                balance: U256::from(5u64),
                storage: big.storage.clone(),
                code: None,
            },
        );
        let (h0, h1) = (head_of(&s0, 0), head_of(&s1, 1));
        let mut got = Vec::new();
        for with_index in [false, true] {
            let dir = scratch(if with_index { "copy-ix" } else { "copy" });
            let base = produce(&dir, &h0, "", leaves(&s0), &code_of(&s0))
                .unwrap()
                .manifest;
            let mut store = Store::open(&dir, &base).unwrap();
            let mut db = NodeDb::open(&dir.join("nodes"), h0.state_root).unwrap();
            let mut ix = None;
            if with_index {
                let n = build_root_index(&dir, &base, &dir, 16 << 20).unwrap();
                assert_eq!(
                    n as usize,
                    s0.values().filter(|a| !a.storage.is_empty()).count()
                );
                ix = Some(RootIndex::open(&dir).unwrap());
            }
            let mut src = Mem::of(&s1, &h1);
            let mut h = track_step(
                &mut src,
                &mut store,
                &mut db,
                h0.state_root,
                h1.state_root,
                None,
                10_000,
                far(),
                &dir.join("sort"),
                64 << 20,
                ix.as_mut(),
                OldSide::default(),
            )
            .await
            .unwrap();
            eprintln!("index {with_index}: {:?}", h.stats);
            assert_eq!(h.stats.storage_copied, with_index as u64);
            assert_eq!(h.new_tries, vec![(account_of(&big).storage_root, fresh)]);
            let mut layers = Vec::new();
            let (_, m) = commit(&dir, &base, &mut layers, &h0, &h1, &mut h, 4, 3);
            byte_identical(&dir, &m, &s1, &h1);
            if let Some(ix) = ix.as_mut() {
                ix.note(account_of(&big).storage_root, fresh).unwrap();
                assert_eq!(ix.find(&account_of(&big).storage_root).unwrap()[0], fresh);
                assert_eq!(RootIndex::open(&dir).unwrap().len().1, 1);
            }
            got.push((h.stats.fetched, h.rows.collect()));
            fs::remove_dir_all(&dir).ok();
        }
        assert!(
            got[1].0 + big.storage.len() as u64 <= got[0].0,
            "{} vs {}",
            got[1].0,
            got[0].0
        );
        assert_eq!(got[0].1, got[1].1);
    }

    #[test]
    fn collection_keeps_pinned_manifests() {
        let m: VecDeque<(B256, Vec<String>)> = (1..=6u8)
            .map(|i| (B256::with_last_byte(i), vec![]))
            .collect();
        let pinned: HashSet<B256> = [B256::with_last_byte(1), B256::with_last_byte(3)].into();
        // Three over the three kept: the oldest three that are not pinned.
        let gone = collectable(&m, 3, &pinned);
        assert_eq!(
            gone,
            vec![
                B256::with_last_byte(2),
                B256::with_last_byte(4),
                B256::with_last_byte(5)
            ]
        );
        assert!(collectable(&m, 6, &pinned).is_empty());
        // The newest is kept even when everything else is pinned.
        let all_but_newest: HashSet<B256> = (1..=5u8).map(B256::with_last_byte).collect();
        assert!(collectable(&m, 2, &all_but_newest).is_empty());
    }

    #[tokio::test]
    async fn tiers_merge_and_every_state_still_reads() {
        let s0 = states().remove(0);
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        let dir = scratch("tiers");
        let h0 = head_of(&s0, 0);
        let base = produce(&dir, &h0, "", leaves(&s0), &code_of(&s0))
            .unwrap()
            .manifest;
        let mut store = Store::open(&dir, &base).unwrap();
        let mut db = NodeDb::open(&dir.join("nodes"), h0.state_root).unwrap();
        let mut layers: Vec<Tiered> = Vec::new();
        let (mut s, mut h) = (s0, h0);
        let mut max_layers = 0;
        for n in 1..=20u64 {
            let next = churn(&s, &mut rng);
            let hn = head_of(&next, n);
            let mut src = Mem::of(&next, &hn);
            let mut tracked = step(&mut src, &mut store, &mut db, &h, &hn, &dir, 64 << 20)
                .await
                .unwrap();
            (store, _) = commit(&dir, &base, &mut layers, &h, &hn, &mut tracked, 2, 3);
            db.reset(hn.state_root).unwrap();
            max_layers = max_layers.max(layers.len());
            // Tiers never increase toward the newest.
            assert!(
                layers.windows(2).all(|w| w[0].tier >= w[1].tier),
                "{:?}",
                layers.iter().map(|l| l.tier).collect::<Vec<_>>()
            );
            assert!(layers.iter().filter(|l| l.tier == 3).count() <= 1);
            reads_as(&dir, &next, &[], &hn);
            (s, h) = (next, hn);
        }
        // Fanout 2 and a top tier of 3: at most one run per tier below it.
        assert!(max_layers <= 4, "{max_layers}");
        assert!(layers.iter().any(|l| l.tier == 3));
        fs::remove_dir_all(&dir).ok();
    }
}

/// A tracked directory against the slice its base was built from:
/// `CSL_TRACK_SLICE=<slice> CSL_TRACK_DIR=<published dir> cargo test
/// --release -p csl-eth-snap --lib tracked_dir_is_complete -- --ignored
/// --nocapture`. Every account, slot and code of the slice must read at
/// the published head as verified or proven absent; none insufficient.
#[cfg(test)]
mod mainnet {
    use super::*;
    use crate::slice::Slice;

    #[test]
    #[ignore]
    fn tracked_dir_is_complete() {
        let (Ok(s), Ok(d)) = (
            std::env::var("CSL_TRACK_SLICE"),
            std::env::var("CSL_TRACK_DIR"),
        ) else {
            return;
        };
        let slice = Slice::read(Path::new(&s)).unwrap();
        let dir = PathBuf::from(d);
        let latest = fs::read_to_string(dir.join(LATEST_FILE)).unwrap();
        let hash: B256 = format!("0x{}", latest.trim().trim_start_matches("0x"))
            .parse()
            .unwrap();
        let m = Manifest::from_json(&fs::read(dir.join(manifest_path(&hash))).unwrap()).unwrap();
        let mut snap = Snapshot::open(DirDriver::new(&dir), Some(hash), m.state_root).unwrap();
        let (mut same, mut changed, mut gone, mut slots, mut slots_changed, mut codes) =
            (0, 0, 0, 0, 0, 0);
        let mut bad = Vec::new();
        for (k, a) in &slice.accounts {
            let now = match snap.account(k).0 {
                Read::Verified(n) => n,
                r if r.is_absent() => {
                    gone += 1;
                    continue;
                }
                r => {
                    bad.push(format!("account {k}: {r:?}"));
                    continue;
                }
            };
            if now == *a {
                same += 1
            } else {
                changed += 1
            }
            if let Some(ss) = slice.storage.get(&a.storage_root) {
                for (h, v) in ss.iter().take(50) {
                    match snap.storage_of(&now, k, h).0 {
                        Read::Verified(x) => {
                            slots += 1;
                            if x != *v {
                                slots_changed += 1;
                            }
                        }
                        r if r.is_absent() => slots_changed += 1,
                        r => bad.push(format!("slot {k}/{h}: {r:?}")),
                    }
                }
            }
        }
        for h in slice.code.keys() {
            match snap.code(h).0 {
                Read::Verified(_) => codes += 1,
                r => bad.push(format!("code {h}: {r:?}")),
            }
        }
        eprintln!(
            "block {} accounts: {same} same, {changed} changed, {gone} gone; slots: {slots} read, {slots_changed} changed; codes {codes}; insufficient {}",
            m.block_number,
            bad.len()
        );
        for b in bad.iter().take(10) {
            eprintln!("{b}");
        }
        assert!(bad.is_empty());
    }
}
