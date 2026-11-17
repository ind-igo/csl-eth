//! The client, profile §2: one speculative round, the walk, repair rounds,
//! and nothing accepted that does not hash to `state_root`.
//!
//! The caller supplies the `state_root` it verified (from the head files;
//! a supplied checkpoint in tests). The snapshot's manifest says which
//! root its files claim to serve, and the client refuses to open a
//! snapshot for a different root rather than silently walking files that
//! cannot match.
//!
//! Every read returns `Verified`, `VerifiedAbsent` (proven by the trie's
//! shape) or `Insufficient` (something was missing or wrong), with the
//! requests, bytes and rounds it took. Fences, models, tombstones and
//! missing files never become absence.
//!
//! The client does no I/O (see [`store`]): `try_account` and its siblings
//! compute over what the [`Store`] holds and return [`Pending`] with the
//! round's wants noted when they need more; `account` and its siblings
//! drive that loop with the snapshot's [`Driver`]. A round's wants are
//! the pages the model predicts for every depth the walk may touch,
//! widened by the [`Hint`], and later rounds carry only what the walk
//! found missing, so a read is one round trip when the prediction holds
//! and one more per miss, however many pages each round has.
//!
//! The content-addressed baseline (profile §9) reads the same state the
//! way a hash-addressed store must: `account_by_hash` and
//! `storage_by_hash` walk from the root fetching each node by its hash
//! from `nodes_by_hash`, so a read is one dependent round per node on the
//! path. Same host, same files, same verification; only the key changes.
//! It is measured beside the path-keyed read, not used by wallets.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{Nibbles, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use csl_eth_store::{
    blob_path,
    hints::{hints_path, top8, Holds, OwnerIndex},
    manifest_path, table_path, Manifest, D_ACCOUNT, D_STORAGE, FORMAT_VERSION,
    FORMAT_VERSION_LAYERED, LATEST_FILE, RUN_FORMAT, TABLE_COUNT,
};
use csl_eth_trie::{
    decode_word, path_of, walk, walk_traced, AbsentBy, Account, Invalid, NodeKey, NodeSource,
    Outcome, Shape, Step,
};
use csl_run::{Reader, PAGE};
use std::{
    cell::RefCell,
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

pub mod store;
/// The trie crate the trace's steps come from.
pub use csl_eth_store::{
    TABLE_ACCOUNT_NODES, TABLE_CODE, TABLE_NODES_BY_HASH, TABLE_STORAGE_NODES,
};
pub use csl_eth_trie as trie;
#[cfg(not(target_arch = "wasm32"))]
pub use store::DirDriver;
pub use store::{drive, is_pending, Driver, Got, NoDriver, Pending, RunView, Store, Want, PENDING};

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub use http::HttpDriver;

pub mod beacon;
pub mod head;
pub mod history;
pub use head::{
    open_at_head, open_at_head_with, FcrReport, HeadOpenError, HeadOpener, TierChoice, VerifiedHead,
};

/// Why a read could not be answered. None of these is evidence of absence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The snapshot has no run for this table.
    NoTable(u16),
    /// A node the walk needs is not in its table.
    Missing {
        table: u16,
        key: [u8; 32],
    },
    /// A node that was served does not verify.
    Invalid {
        table: u16,
        key: [u8; 32],
        what: Invalid,
    },
    /// The run file misbehaved (short read, malformed page, I/O).
    Run {
        table: u16,
        error: String,
    },
    /// Code or a blob that does not hash to the verified `codeHash`.
    Code(&'static str),
    Blob(String),
    /// More repair rounds than the walk bound allows.
    Budget,
    /// A verified leaf whose value does not decode as the profile says.
    Value(&'static str),
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reason::NoTable(t) => write!(f, "snapshot has no table {t}"),
            Reason::Missing { table, key } => write!(f, "table {table} lacks {}", hex::encode(key)),
            Reason::Invalid { table, key, what } => write!(
                f,
                "table {table} node {} invalid: {what:?}",
                hex::encode(key)
            ),
            Reason::Run { table, error } => write!(f, "table {table}: {error}"),
            Reason::Code(w) => write!(f, "code: {w}"),
            Reason::Blob(w) => write!(f, "blob: {w}"),
            Reason::Budget => write!(f, "repair budget exhausted"),
            Reason::Value(w) => write!(f, "value: {w}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read<T> {
    Verified(T),
    VerifiedAbsent(AbsentBy),
    Insufficient(Reason),
}

impl<T> Read<T> {
    pub fn verified(self) -> Option<T> {
        match self {
            Read::Verified(v) => Some(v),
            _ => None,
        }
    }
    pub fn is_absent(&self) -> bool {
        matches!(self, Read::VerifiedAbsent(_))
    }
    pub fn is_insufficient(&self) -> bool {
        matches!(self, Read::Insufficient(_))
    }
    fn map<U>(self, f: impl FnOnce(T) -> Read<U>) -> Read<U> {
        match self {
            Read::Verified(v) => f(v),
            Read::VerifiedAbsent(b) => Read::VerifiedAbsent(b),
            Read::Insufficient(r) => Read::Insufficient(r),
        }
    }
}

/// What one read cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    /// Requests the host made: one per want of every round, merged ranges
    /// counting once.
    pub requests: u64,
    pub bytes: u64,
    /// Dependent network rounds: the speculative round plus one per round
    /// of misses. Zero when every node came from the cache.
    pub rounds: u32,
    /// Nodes the speculative round missed and a later round fetched.
    pub repairs: u32,
    /// Trie nodes decoded on the final walk(s).
    pub nodes: usize,
    /// Model pages this read fetched (page 0 is the open's): the cold part
    /// of a read, zero once the key's neighbourhoods are known.
    pub model_pages: u64,
    /// Layer runs this read asked for anything (the base not counted):
    /// what the layers' hints save.
    pub layers: u32,
}

/// Which trie a traced walk is in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Trie {
    Account,
    Storage,
}

/// Where a node on a traced walk came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The snapshot's top-level cache: bytes an earlier read's verified walk
    /// kept (they are hashed again by this walk all the same).
    Cache,
    /// Read from data page `page` (1-based, as `csl-run` numbers records)
    /// of `table`'s run file `run`: 0 the base, `i` the `i`th run after it
    /// (a layered snapshot's layers, oldest first).
    Page { table: u16, run: u16, page: u64 },
    /// Inside its parent's bytes, so covered by the parent's hash.
    Embedded,
    /// Not served. `searched` is the page whose fences cover the node's key
    /// and which does not hold it, when the lookup got that far.
    NotServed { searched: Option<(u16, u64)> },
}

/// One node of a traced walk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceNode {
    /// What the walk found there (see [`csl_eth_trie::Step`]).
    pub step: Step,
    /// The table key it was looked up by: its position's key, or for the
    /// baseline the hash its parent committed to. `None` when embedded.
    pub table_key: Option<[u8; 32]>,
    pub origin: Origin,
    /// The attempt whose walk first checked this node: 0 for the call that
    /// began the read, `n` for the one after round `n`. `None` when no walk
    /// accepted it (the node the walk stopped at, when it failed).
    pub checked_at: Option<u32>,
}

/// The final walk over one trie, node by node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalkTrace {
    pub trie: Trie,
    /// The table its nodes are read from: 0 or 1 path-keyed, 3 by hash.
    pub table: u16,
    pub by_hash: bool,
    /// The root it starts from: `state_root`, or the account's storage root.
    pub root: B256,
    /// The hashed key (or hashed slot) whose path it follows.
    pub key: B256,
    pub nodes: Vec<TraceNode>,
}

/// A code read: the entry's page in the code table, and the blob it names
/// when the code is above the inline size.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodeTrace {
    pub code_hash: B256,
    /// The page whose fences cover the code hash, when the lookup got that
    /// far.
    pub page: Option<u64>,
    pub blob: Option<String>,
    /// The bytecode's length, when it was served.
    pub len: Option<usize>,
}

/// What the last read did, for a host that shows it: the walk(s) whose
/// outcome is the answer, in order (a storage read's account walk, then
/// its storage walk), or the code lookup. Recording it changes nothing
/// the client fetches or decides.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Trace {
    pub walks: Vec<WalkTrace>,
    pub code: Option<CodeTrace>,
}

/// A table key the current attempt asked for: the path's speculated or
/// repaired positions, or the baseline's next hash. A host that alters a
/// round's bytes on purpose (the page's tamper demonstration) uses these to
/// find which entries in a response the read will walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundKey {
    pub table: u16,
    pub trie: Trie,
    /// The depth of the position (the baseline's: of the node it expects).
    pub depth: usize,
    pub key: [u8; 32],
}

/// One table's run file as the open snapshot sees it: where page 0, the
/// data pages and the model pages sit (`csl_run::Layout` with the paged
/// model, core §4.1).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TableInfo {
    pub table_id: u16,
    pub name: &'static str,
    pub path: String,
    /// Data pages, numbered `1..=page_count`; page 0 is at offset 0.
    pub page_count: u64,
    pub entry_count: u64,
    pub epsilon_pages: u16,
    /// Data page `i` is `record_bytes` at `PAGE + (i - 1) * record_bytes`.
    pub record_bytes: u64,
    /// The model section: `model_pages` records of `model_record_bytes`
    /// (a 4 KB model page and its inline proof) from `model_off`.
    pub model_off: u64,
    pub model_bytes: u64,
    pub model_pages: u64,
    pub model_record_bytes: u64,
    pub total_len: u64,
    /// Why the table cannot serve, if it cannot.
    pub error: Option<String>,
}

/// Where an entry the current read asked for sits in a response body: a
/// [`RoundKey`] found on a data page of a fetched range, with its value's
/// bytes (the node, or the code) at `value_off..value_off + value_len` of
/// the body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryAt {
    pub at: RoundKey,
    pub page: u64,
    pub value_off: usize,
    pub value_len: usize,
}

/// A table's name: its run file without the extension.
pub fn trie_table_name(table: u16) -> &'static str {
    csl_eth_store::TABLE_FILES
        .get(table as usize)
        .map_or("?", |f| f.trim_end_matches(".run"))
}

/// Model pages and their record size for a paged model section of
/// `model_bytes`: `m` records of `PAGE + DIGEST * depth(m)` bytes, as
/// `csl_run::Reader` checks on page 0.
fn model_pages_of(model_bytes: u64) -> Option<(u64, u64)> {
    (1..=model_bytes / PAGE as u64).find_map(|m| {
        let rec = PAGE as u64 + (csl_run::DIGEST * csl_run::tree::depth(m)) as u64;
        (m * rec == model_bytes).then_some((m, rec))
    })
}

/// Repairs a single read may take: one per node the speculative round
/// missed, bounded by the walk's own node limit.
pub const MAX_REPAIRS: u32 = csl_eth_trie::MAX_WALK_NODES as u32;

/// How a round is widened: the predicted page of every depth, `below` and
/// `above` pages each side, and whether pages that touch are asked for as
/// one range (one request) or one each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hint {
    pub below: u64,
    pub above: u64,
    pub merge: bool,
}

impl Hint {
    /// The prediction and `span` pages each side, touching pages merged.
    pub fn symmetric(span: u64) -> Hint {
        Hint {
            below: span,
            above: span,
            merge: true,
        }
    }

    /// The predicted pages only, touching pages merged.
    pub fn none() -> Hint {
        Hint::symmetric(0)
    }
}

impl Default for Hint {
    fn default() -> Hint {
        Hint::none()
    }
}

/// Which snapshot to open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum At {
    /// The one `latest` names.
    Latest,
    Block(B256),
}

/// A snapshot being opened: the manifest, then every table's model, each
/// a round.
/// A manifest's bytes as the snapshot of block `hash` with `state_root`,
/// in the format this client reads: every check the opener makes before
/// it reads a table, so a caller choosing between snapshots can make them
/// on manifests it already holds.
pub(crate) fn check_manifest(
    bytes: &[u8],
    hash: B256,
    state_root: B256,
) -> Result<Manifest, String> {
    let manifest = Manifest::from_json(bytes).map_err(|e| e.to_string())?;
    if manifest.block_hash != hash {
        return Err("manifest names a different block".into());
    }
    // Version 2 is a plain snapshot; version 3 names another block's plain
    // tables as its base, plus layers (none when nothing changed), and has
    // no by-hash table. A manifest whose version and shape disagree is
    // refused.
    let layered = manifest.is_layered();
    let well_layered = manifest.base.is_some_and(|b| b != hash)
        && manifest.table(TABLE_NODES_BY_HASH).is_none()
        && manifest
            .layers
            .iter()
            .all(|l| l.tables.iter().all(|t| t.table_id != TABLE_NODES_BY_HASH));
    if !(manifest.format_version == FORMAT_VERSION && !layered
        || manifest.format_version == FORMAT_VERSION_LAYERED && well_layered)
    {
        return Err(format!(
            "manifest format version {}{}, this client reads {FORMAT_VERSION} (plain) and {FORMAT_VERSION_LAYERED} (layered)",
            manifest.format_version,
            if layered { " with layers" } else { "" }
        ));
    }
    if manifest.state_root != state_root {
        return Err(format!(
            "snapshot claims state_root {}, caller verified {state_root}",
            manifest.state_root
        ));
    }
    Ok(manifest)
}

pub struct Opener<D> {
    driver: Option<D>,
    store: Arc<Store>,
    at: At,
    state_root: B256,
}

impl<D: Driver> Opener<D> {
    pub fn new(driver: D, store: Arc<Store>, at: At, state_root: B256) -> Opener<D> {
        Opener {
            driver: Some(driver),
            store,
            at,
            state_root,
        }
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// One synchronous round through the driver.
    pub fn round(&self) {
        if let Some(d) = &self.driver {
            drive(d, &self.store, true);
        }
    }

    /// Open from what the store holds, or `Pending` with the next round
    /// wanted. `Ok(Err)` is a refusal: the snapshot is not there, or not
    /// at the caller's root.
    pub fn try_open(&mut self) -> Result<Result<Snapshot<D>, String>, Pending> {
        let hash = match self.at {
            At::Block(h) => h,
            At::Latest => match self.store.file(LATEST_FILE)? {
                Ok(Some(s)) => {
                    let s = match String::from_utf8(s) {
                        Ok(s) => s,
                        Err(e) => return Ok(Err(e.to_string())),
                    };
                    match hex::decode(s.trim())
                        .ok()
                        .and_then(|v| <[u8; 32]>::try_from(v).ok())
                        .map(B256::from)
                    {
                        Some(h) => h,
                        None => return Ok(Err("latest is not a block hash".into())),
                    }
                }
                Ok(None) => return Ok(Err("no latest file".into())),
                Err(e) => return Ok(Err(e)),
            },
        };
        let mut manifest = match self.store.file(&manifest_path(&hash))? {
            Ok(Some(m)) => match check_manifest(&m, hash, self.state_root) {
                Ok(m) => m,
                Err(e) => return Ok(Err(e)),
            },
            Ok(None) => return Ok(Err(format!("no snapshot at {hash}"))),
            Err(e) => return Ok(Err(e)),
        };
        // Hints too large for the manifest, in one round with the page 0s
        // below. They only schedule: one that is missing or does not hash
        // leaves its layer asked for everything.
        let mut pending = false;
        for l in manifest.layers.iter_mut() {
            let Some(name) = l.hints_file else { continue };
            l.hints = Default::default();
            match self.store.file(&hints_path(&name)) {
                Err(Pending) => pending = true,
                Ok(Ok(Some(b))) => {
                    if let Ok(h) = csl_eth_store::hints::Hints::from_file(&b, &name) {
                        l.hints = h;
                    }
                }
                Ok(_) => {}
            }
        }
        // Every table's page 0 (the top model and the model tree's root) in
        // one round: each is a range the store may lack, and a reader's
        // `prepare` is the read that wants it. A table that fails here (a
        // page 0 that does not hash, a truncated file) does not refuse the
        // snapshot: its reads are `Insufficient` with that reason, and the
        // other tables still serve.
        //
        // A layered snapshot has a run per table in the base and in each
        // layer that changed it; each is opened the same way, and one that
        // fails only takes its own candidates away.
        let mut runs: Vec<Vec<RunSlot>> = Vec::with_capacity(TABLE_COUNT);
        for t in 0..TABLE_COUNT as u16 {
            let mut slots = Vec::new();
            for at in manifest.runs(t) {
                let view = RunView {
                    store: self.store.clone(),
                    rel: at.path.clone(),
                };
                let broken = |e: csl_run::Error| Reason::Run {
                    table: t,
                    error: e.to_string(),
                };
                let mut rref = at.table.run_ref(at.block_lo);
                rref.block_hi = at.block_hi;
                let reader = match Reader::try_with_format(view, rref, RUN_FORMAT) {
                    Ok(mut r) => match r.prepare() {
                        Ok(()) => Ok(r),
                        Err(e) if is_pending(&e) => {
                            pending = true;
                            Ok(r)
                        }
                        Err(e) => Err(broken(e)),
                    },
                    Err(e) => Err(broken(e)),
                };
                slots.push(RunSlot {
                    rel: at.path,
                    reader,
                    layer: at.layer,
                });
            }
            runs.push(slots);
        }
        if pending {
            return Err(Pending);
        }
        let driver = self.driver.take().expect("opened once");
        Ok(Ok(Snapshot {
            driver,
            store: self.store.clone(),
            manifest,
            runs,
            d_account: D_ACCOUNT,
            d_storage: D_STORAGE,
            hint: Hint::default(),
            top_levels: 0,
            top: HashMap::new(),
            model_at_begin: 0,
            trace: Trace::default(),
            attempts: 0,
            checked: HashMap::new(),
            round_keys: Vec::new(),
            asked: HashSet::new(),
            tracing: false,
        }))
    }
}

/// One run a table is read from: its path and its reader, or why it
/// cannot serve.
struct RunSlot {
    rel: String,
    reader: Result<Reader<RunView>, Reason>,
    /// Its layer's index in the manifest; `None` for the base.
    layer: Option<usize>,
}

/// Which trie a walk reads, for the layers' hints: the account trie at a
/// path (its first eight nibbles), or an owner's storage trie.
#[derive(Clone, Copy)]
enum Scope {
    Account { top8: u32 },
    Storage { owner: B256, top8: u32 },
}

/// What every run of a table holds at one key: the candidates, each with
/// where it came from, and the page searched when none had it.
struct Found {
    cands: Vec<(Vec<u8>, Origin)>,
    searched: Option<(u16, u64)>,
}

pub struct Snapshot<D> {
    driver: D,
    store: Arc<Store>,
    manifest: Manifest,
    /// Per table, its runs: the base's first, then the layers', oldest
    /// first. Empty when no run has the table.
    runs: Vec<Vec<RunSlot>>,
    pub d_account: usize,
    pub d_storage: usize,
    /// How each round is widened around the predicted pages.
    pub hint: Hint,
    /// Account-trie nodes at depths below this are kept across reads of
    /// this snapshot once a verified walk has passed them, and neither
    /// hinted nor fetched again (`0`: off). Every block rewrites the top of
    /// the trie, so the cache is the snapshot's and dies with it.
    pub top_levels: usize,
    /// `Some(node)` or `None` for "no node at this depth, an extension
    /// spans it", both verified by the walk that stored them.
    top: HashMap<NodeKey, Option<Vec<u8>>>,
    /// The readers' model requests when the current read began.
    model_at_begin: u64,
    /// The current attempt's trace; the last read's once it is answered.
    trace: Trace,
    /// Attempts of the current read so far (each `try_` call is one).
    attempts: u32,
    /// Per node, the attempt whose walk first accepted it, this read.
    checked: HashMap<(Trie, bool, NodeKey), u32>,
    /// The table keys the current attempt asked for.
    round_keys: Vec<RoundKey>,
    /// Layer runs (table, run) the current read asked.
    asked: HashSet<(u16, usize)>,
    /// Keep a [`Trace`] of each read's final walk(s) and the attempt's
    /// table keys (off by default). Tracing only records: what is fetched,
    /// every answer and every [`Cost`] are the same either way.
    pub tracing: bool,
}

/// Nodes fetched so far, by position: every run's candidate there, with
/// where it came from. A plain snapshot has at most one.
type Nodes = HashMap<NodeKey, Vec<(Vec<u8>, Origin)>>;

/// The walk's view of [`Nodes`]: at each position the candidate that
/// hashes to what the parent committed to, and a record of which one each
/// position gave, so that only nodes the walk accepted are ever cached.
struct Cands<'a> {
    nodes: &'a Nodes,
    chosen: RefCell<HashMap<NodeKey, usize>>,
}

impl<'a> Cands<'a> {
    fn new(nodes: &'a Nodes) -> Cands<'a> {
        Cands {
            nodes,
            chosen: RefCell::new(HashMap::new()),
        }
    }

    /// The candidate the walk took at each position it asked for.
    fn selected(&self) -> HashMap<NodeKey, (&'a [u8], Origin)> {
        self.chosen
            .borrow()
            .iter()
            .filter_map(|(k, i)| {
                let c = self.nodes.get(k)?.get(*i)?;
                Some((*k, (c.0.as_slice(), c.1)))
            })
            .collect()
    }
}

impl NodeSource for Cands<'_> {
    fn node(&self, key: &NodeKey) -> Option<&[u8]> {
        self.nodes.get(key)?.first().map(|c| c.0.as_slice())
    }

    fn node_hashed(&self, key: &NodeKey, hash: &B256) -> Option<&[u8]> {
        let c = self.nodes.get(key)?;
        let i = if c.len() == 1 {
            0
        } else {
            c.iter()
                .position(|(b, _)| keccak256(b) == *hash)
                .unwrap_or(0)
        };
        self.chosen.borrow_mut().insert(*key, i);
        c.get(i).map(|x| x.0.as_slice())
    }
}

/// Each position's origin for a trace: the candidate the walk took, else
/// the first one, else the page searched.
fn origins(
    nodes: &Nodes,
    selected: &HashMap<NodeKey, (Vec<u8>, Origin)>,
    mut missed: HashMap<NodeKey, Origin>,
) -> HashMap<NodeKey, Origin> {
    for (k, c) in nodes {
        let o = selected
            .get(k)
            .map(|s| s.1)
            .or_else(|| c.first().map(|x| x.1));
        if let Some(o) = o {
            missed.insert(*k, o);
        }
    }
    missed
}

impl<D: Driver> Snapshot<D> {
    /// Open the snapshot at `block_hash` (the newest when `None`) and
    /// require that it claims `state_root`, the root the caller verified.
    /// Synchronous: the driver fetches each round.
    pub fn open(
        driver: D,
        block_hash: Option<B256>,
        state_root: B256,
    ) -> Result<Snapshot<D>, String> {
        let at = block_hash.map_or(At::Latest, At::Block);
        let mut o = Opener::new(driver, Store::new(), at, state_root);
        loop {
            match o.try_open() {
                Ok(r) => return r,
                Err(Pending) => o.round(),
            }
        }
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn state_root(&self) -> B256 {
        self.manifest.state_root
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    pub fn driver(&self) -> &D {
        &self.driver
    }

    /// A read is starting: the store drops the last read's pages. The
    /// `try_` methods compute from the store; call this before the first
    /// attempt of a read, not between its rounds.
    pub fn begin_read(&mut self) {
        self.store.begin_read();
        self.model_at_begin = self.model_requests();
        self.asked.clear();
        self.attempts = 0;
        self.checked.clear();
        self.trace = Trace::default();
        self.round_keys.clear();
    }

    /// One `try_` call of the current read is starting.
    fn attempt(&mut self) {
        self.attempts += 1;
        self.trace = Trace::default();
        self.round_keys.clear();
    }

    /// What the last read did, node by node (see [`Trace`]): complete once
    /// a `try_` call has returned the answer.
    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    /// The table keys the last attempt asked for (see [`RoundKey`]).
    pub fn round_keys(&self) -> &[RoundKey] {
        &self.round_keys
    }

    /// The entries of the last attempt's [`RoundKey`]s on the data pages
    /// of `body`, the bytes of `rel` from offset `off`. Pages are parsed
    /// with the run format's own decoder and nothing is verified: this is
    /// for a host that alters a response on purpose to show the client
    /// refusing it, never for reading.
    pub fn entries_in(&self, rel: &str, off: u64, body: &[u8]) -> Vec<EntryAt> {
        let mut out = Vec::new();
        if RUN_FORMAT.layout != csl_run::EntryLayout::Variable {
            return out;
        }
        let Some((t, layout)) = self.runs.iter().enumerate().find_map(|(t, slots)| {
            slots
                .iter()
                .find(|r| r.rel == rel)
                .and_then(|r| r.reader.as_ref().ok()?.layout().copied())
                .map(|l| (t as u16, l))
        }) else {
            return out;
        };
        let info = TableInfo {
            page_count: layout.page_count,
            record_bytes: layout.record_bytes,
            ..TableInfo::default()
        };
        if info.page_count == 0 || info.record_bytes != PAGE as u64 {
            return out;
        }
        let end = off + body.len() as u64;
        let first = off.saturating_sub(PAGE as u64).div_ceil(PAGE as u64) + 1;
        for i in first..=info.page_count {
            let ro = PAGE as u64 + (i - 1) * PAGE as u64;
            if ro < off {
                continue;
            }
            if ro + PAGE as u64 > end {
                break;
            }
            let b = &body[(ro - off) as usize..(ro - off) as usize + PAGE];
            let Ok(page) =
                csl_run::Page::decode_with(b, RUN_FORMAT.layout, i == info.page_count, i)
            else {
                continue;
            };
            for (j, e) in page.entries.iter().enumerate() {
                let Some(at) = self
                    .round_keys
                    .iter()
                    .find(|k| k.table == t && k.key == e.key)
                else {
                    continue;
                };
                if e.tag != 0 {
                    continue;
                }
                // Variable layout: `n`, the fences, `n` u16 entry offsets,
                // then `key ‖ tag ‖ len: u16 ‖ value` per entry (the
                // decoder above has checked every offset).
                let at_off = csl_run::PAGE_HEADER + 2 * j;
                let o = u16::from_le_bytes([b[at_off], b[at_off + 1]]) as usize;
                // Only a non-empty value lying wholly inside this page, and
                // holding exactly the entry's bytes, is a target: a flip
                // there changes that node's bytes and nothing else.
                let start = o + 32 + 1 + 2;
                let len = e.value.len();
                if len == 0 || start + len > PAGE || b[start..start + len] != e.value[..] {
                    continue;
                }
                out.push(EntryAt {
                    at: *at,
                    page: i,
                    value_off: (ro - off) as usize + start,
                    value_len: len,
                });
            }
        }
        out
    }

    /// Layers over the base (0 for a plain snapshot).
    pub fn layers(&self) -> usize {
        self.manifest.layers.len()
    }

    /// Every table's base run file and where its pages sit. A layered
    /// snapshot's layer runs are not listed.
    pub fn tables(&self) -> Vec<TableInfo> {
        let m = &self.manifest;
        (0..TABLE_COUNT as u16)
            .map(|t| {
                let path = table_path(&m.base_hash(), t);
                let name = trie_table_name(t);
                let tr = m.table(t);
                let layout = tr.and_then(|tr| {
                    csl_run::Layout::try_new_with(
                        tr.page_count,
                        u64::from(tr.model_bytes),
                        RUN_FORMAT.inline_proofs,
                    )
                    .ok()
                });
                let (model_pages, model_record_bytes) = layout
                    .and_then(|l| model_pages_of(l.model_bytes))
                    .unwrap_or((0, 0));
                let base = self.runs[t as usize].iter().find(|r| r.rel == path);
                let error = match (base.map(|r| &r.reader), tr, layout) {
                    (None, _, _) => Some(Reason::NoTable(t).to_string()),
                    (Some(Err(r)), _, _) => Some(r.to_string()),
                    (Some(Ok(_)), None, _) => Some("not in the manifest".into()),
                    (Some(Ok(_)), Some(_), None) => Some("no valid run layout".into()),
                    (Some(Ok(_)), Some(_), Some(_)) => None,
                };
                TableInfo {
                    table_id: t,
                    name,
                    path,
                    page_count: tr.map_or(0, |tr| tr.page_count),
                    entry_count: tr.map_or(0, |tr| tr.entry_count),
                    epsilon_pages: tr.map_or(0, |tr| tr.epsilon_pages),
                    record_bytes: layout.map_or(0, |l| l.record_bytes),
                    model_off: layout.map_or(0, |l| l.model_off),
                    model_bytes: layout.map_or(0, |l| l.model_bytes),
                    model_pages,
                    model_record_bytes,
                    total_len: layout.map_or(0, |l| l.total_len),
                    error,
                }
            })
            .collect()
    }

    /// Model section reads so far: page 0 per table at open, then one per
    /// model page fetched.
    pub fn model_requests(&self) -> u64 {
        self.runs
            .iter()
            .flatten()
            .filter_map(|r| r.reader.as_ref().ok())
            .map(|r| r.stats.model_requests)
            .sum()
    }

    /// One synchronous round through the driver.
    pub fn round(&self) {
        drive(&self.driver, &self.store, self.hint.merge);
    }

    fn run<T>(&mut self, mut f: impl FnMut(&mut Self) -> Result<T, Pending>) -> T {
        self.begin_read();
        loop {
            match f(self) {
                Ok(v) => return v,
                Err(Pending) => self.round(),
            }
        }
    }

    fn cost(&self, repairs: u32, nodes: usize) -> Cost {
        let (requests, bytes, rounds) = self.store.cost();
        Cost {
            requests,
            bytes,
            rounds,
            repairs,
            nodes,
            model_pages: self.model_requests().saturating_sub(self.model_at_begin),
            layers: self.asked.len() as u32,
        }
    }

    /// One table key from the store, in every run of the table: each run's
    /// entry as a candidate, with the data page whose fences cover it, and
    /// the first page searched when none holds it (which the walk will
    /// report as `Missing`). The lookup is the reader's `get_entry`
    /// (`locate`, then the entry on the page), keeping the page index.
    /// Every run is asked before a `Pending`, so one round wants them all.
    /// A run that cannot answer gives no candidate; its reason is the
    /// answer only when no run gives one.
    fn fetch(
        &mut self,
        table: u16,
        key: &[u8; 32],
        ask: Option<&[bool]>,
    ) -> Result<Result<Found, Reason>, Pending> {
        let slots = &mut self.runs[table as usize];
        if slots.is_empty() {
            return Ok(Err(Reason::NoTable(table)));
        }
        let mut found = Found {
            cands: Vec::new(),
            searched: None,
        };
        let mut err: Option<Reason> = None;
        let mut pending = false;
        for (i, slot) in slots.iter_mut().enumerate() {
            if ask.is_some_and(|a| !a[i]) {
                continue;
            }
            if slot.layer.is_some() {
                self.asked.insert((table, i));
            }
            let r = match slot.reader.as_mut() {
                Ok(r) => r,
                Err(why) => {
                    err.get_or_insert_with(|| why.clone());
                    continue;
                }
            };
            match r.locate(key) {
                Ok((page, p, _)) => match p.find(key) {
                    Some(e) if e.tag == 0 => found.cands.push((
                        e.value.clone(),
                        Origin::Page {
                            table,
                            run: i as u16,
                            page,
                        },
                    )),
                    Some(_) => {
                        err.get_or_insert(Reason::Invalid {
                            table,
                            key: *key,
                            what: Invalid::Rlp,
                        });
                    }
                    None => {
                        found.searched.get_or_insert((table, page));
                    }
                },
                Err(e) if is_pending(&e) => pending = true,
                Err(e) => {
                    err.get_or_insert(Reason::Run {
                        table,
                        error: e.to_string(),
                    });
                }
            }
        }
        if pending {
            return Err(Pending);
        }
        match err {
            Some(e) if found.cands.is_empty() => Ok(Err(e)),
            _ => Ok(Ok(found)),
        }
    }

    /// Note a key of this attempt (see [`RoundKey`]).
    fn note_key(&mut self, table: u16, trie: Trie, depth: usize, key: [u8; 32]) {
        if !self.tracing {
            return;
        }
        self.round_keys.push(RoundKey {
            table,
            trie,
            depth,
            key,
        });
    }

    /// After a walk: every node it accepted is checked as of this attempt,
    /// unless an earlier attempt's walk already checked it.
    fn mark_checked(&mut self, trie: Trie, by_hash: bool, steps: &[Step]) {
        if !self.tracing {
            return;
        }
        let at = self.attempts.saturating_sub(1);
        for s in steps {
            if !matches!(s.shape, Shape::Missing | Shape::Invalid { .. }) {
                self.checked.entry((trie, by_hash, s.key)).or_insert(at);
            }
        }
    }

    /// The final walk's steps as a [`WalkTrace`], appended to the trace.
    #[allow(clippy::too_many_arguments)]
    fn keep_trace(
        &mut self,
        trie: Trie,
        table: u16,
        by_hash: bool,
        root: B256,
        key: B256,
        steps: Vec<Step>,
        origin: &HashMap<NodeKey, Origin>,
        key_of: impl Fn(&Step) -> [u8; 32],
    ) {
        if !self.tracing {
            return;
        }
        let nodes = steps
            .into_iter()
            .map(|s| {
                let embedded = s.hash.is_none();
                let origin = if embedded {
                    Origin::Embedded
                } else {
                    origin
                        .get(&s.key)
                        .copied()
                        .unwrap_or(Origin::NotServed { searched: None })
                };
                let failed = matches!(s.shape, Shape::Missing | Shape::Invalid { .. });
                TraceNode {
                    table_key: (!embedded).then(|| key_of(&s)),
                    origin,
                    checked_at: if failed {
                        None
                    } else {
                        self.checked.get(&(trie, by_hash, s.key)).copied()
                    },
                    step: s,
                }
            })
            .collect();
        self.trace.walks.push(WalkTrace {
            trie,
            table,
            by_hash,
            root,
            key,
            nodes,
        });
    }

    /// Want the pages the model predicts for `keys`, widened as the hint
    /// says, so the round fetches them together with whatever else it
    /// finds missing. Pages the store holds are not wanted again. A key
    /// whose model page the store lacks wants that page instead (the
    /// reader's prediction is the read that notes it) and its data pages
    /// come in the next round: a cold neighbourhood is two rounds, a warm
    /// one is one.
    fn want_pages(&mut self, table: u16, keys: &[[u8; 32]]) {
        self.want_pages_of(table, keys, None)
    }

    /// [`Self::want_pages`] in the runs `asks[i]` names for `keys[i]`
    /// (`None`: every run).
    fn want_pages_of(&mut self, table: u16, keys: &[[u8; 32]], asks: Option<&[Vec<bool>]>) {
        let h = self.hint;
        let store = &self.store;
        for (si, slot) in self.runs[table as usize].iter_mut().enumerate() {
            let Ok(reader) = slot.reader.as_mut() else {
                continue;
            };
            let Some(layout) = reader.layout().copied() else {
                continue;
            };
            let len = layout.record_bytes as usize;
            for (ki, k) in keys.iter().enumerate() {
                if asks.is_some_and(|a| !a[ki][si]) {
                    continue;
                }
                let Ok(p) = reader.predict_page(csl_run::k64(k)) else {
                    continue;
                };
                let lo = p.saturating_sub(h.below).max(1);
                let hi = (p + h.above).min(layout.page_count);
                for q in lo..=hi {
                    if let Some(off) = layout.checked_record_off(q) {
                        store.want_range(&slot.rel, off, len);
                    }
                }
            }
        }
    }

    /// The cached answer for an account-trie node, when the cache applies.
    fn top_get(&self, cache: bool, nk: &NodeKey) -> Option<&Option<Vec<u8>>> {
        if cache && nk.depth() < self.top_levels {
            self.top.get(nk)
        } else {
            None
        }
    }

    /// After a verified walk: every node the walk took (and every gap)
    /// above the deepest one lies on the path and was hashed by the walk,
    /// so those at the cached depths are kept for the snapshot's later
    /// reads. Only the candidates the walk selected are kept: a stale
    /// candidate from another run, at a position the walk took or skipped,
    /// never is.
    fn top_keep(&mut self, path: &Nibbles, selected: &HashMap<NodeKey, Vec<u8>>, max_depth: usize) {
        let Some(leaf) = selected.keys().map(NodeKey::depth).max() else {
            return;
        };
        for d in 0..leaf.min(self.top_levels).min(max_depth + 1) {
            let nk = NodeKey::prefix(path, d);
            self.top
                .entry(nk)
                .or_insert_with(|| selected.get(&nk).cloned());
        }
    }

    /// The depths of `path` the speculative round asks `table` for: every
    /// depth up to `max_depth` the cache does not answer.
    /// The runs of `table` a position at `depth` is asked of, by the
    /// layers' hints, newest first: a layer that may hold it is asked; one
    /// that holds it for sure ends the search, older runs then holding
    /// nothing newer; the base is asked unless that happened. A layer
    /// without a hint for the table is always asked.
    fn plan(&self, table: u16, scope: Scope, depth: usize) -> Vec<bool> {
        let slots = &self.runs[table as usize];
        let mut ask = vec![false; slots.len()];
        for i in (0..slots.len()).rev() {
            let Some(li) = slots[i].layer else {
                ask[i] = true;
                break;
            };
            let h = &self.manifest.layers[li].hints;
            let v = match scope {
                Scope::Account { top8 } => h
                    .account
                    .as_ref()
                    .map_or(Holds::Maybe, |p| p.holds(top8, depth)),
                Scope::Storage { owner, top8 } => match &h.owners {
                    Some(idx) if h.storage.is_none() => self.owner_holds(idx, &owner),
                    _ => h.storage_holds(&owner.0, top8, depth),
                },
            };
            match v {
                Holds::No => {}
                Holds::Maybe => ask[i] = true,
                Holds::Yes => {
                    ask[i] = true;
                    break;
                }
            }
        }
        ask
    }

    /// Whether a layer with an owner index may hold `owner`'s storage: the
    /// page it would be on lists it. That page is wanted with the round
    /// that first asks (a storage read's first, with the account's pages);
    /// until it is here the layer is not asked, and a read that needs it
    /// then asks every run, as for any hint that was wrong. A page that
    /// failed or does not fit the index costs the skip, not the answer.
    fn owner_holds(&self, idx: &OwnerIndex, owner: &B256) -> Holds {
        if !idx.is_well_formed() {
            return Holds::Maybe;
        }
        let Some(i) = idx.page_of(&owner.0) else {
            return Holds::No;
        };
        let (off, len) = idx.page_range(i);
        match self.store.range(&idx.path(), off, len) {
            Err(Pending) => Holds::No,
            Ok(Ok(page)) => match idx.page_lists(i, &page, &owner.0) {
                Some(false) => Holds::No,
                Some(true) | None => Holds::Maybe,
            },
            Ok(Err(_)) => Holds::Maybe,
        }
    }

    fn speculative(&self, path: &Nibbles, max_depth: usize, cache: bool) -> (Vec<NodeKey>, Nodes) {
        let mut wanted = Vec::with_capacity(max_depth + 1);
        let mut nodes = Nodes::new();
        for d in 0..=max_depth {
            let nk = NodeKey::prefix(path, d);
            match self.top_get(cache, &nk) {
                Some(Some(v)) => {
                    nodes.insert(nk, vec![(v.clone(), Origin::Cache)]);
                }
                Some(None) => {}
                None => wanted.push(nk),
            }
        }
        (wanted, nodes)
    }

    /// The walk of profile §2 over `table`: speculate `0..=max_depth`,
    /// walk, repair until the trie answers. `Pending` when the round needs
    /// pages; the next attempt starts over from the store, which now has
    /// them.
    #[allow(clippy::too_many_arguments)]
    fn walk_table(
        &mut self,
        trie: Trie,
        table: u16,
        root: B256,
        key: B256,
        path: &Nibbles,
        scope: Scope,
        key_of: impl Fn(&NodeKey) -> [u8; 32],
        max_depth: usize,
        cache: bool,
    ) -> Result<(Read<Vec<u8>>, u32, usize), Pending> {
        if root == EMPTY_ROOT_HASH {
            let none = HashMap::new();
            self.keep_trace(trie, table, false, root, key, Vec::new(), &none, |_| {
                [0; 32]
            });
            return Ok((Read::VerifiedAbsent(AbsentBy::EmptyTrie), 0, 0));
        }
        let (wanted, mut nodes) = self.speculative(path, max_depth, cache);
        // Where a position's candidates came from is in `nodes`; a
        // position no run holds keeps the page searched.
        let mut missed: HashMap<NodeKey, Origin> = HashMap::new();
        let keys: Vec<[u8; 32]> = wanted.iter().map(&key_of).collect();
        for (nk, tk) in wanted.iter().zip(&keys) {
            self.note_key(table, trie, nk.depth(), *tk);
        }
        // Each depth asks the runs the hints name; a position whose plan
        // skipped a run is asked of every run before the walk gives up on
        // it.
        let asks: Vec<Vec<bool>> = wanted
            .iter()
            .map(|nk| self.plan(table, scope, nk.depth()))
            .collect();
        let mut fetched: HashSet<NodeKey> = wanted.iter().copied().collect();
        // Positions asked of only some runs so far.
        let mut partial: HashSet<NodeKey> = wanted
            .iter()
            .zip(&asks)
            .filter(|(_, a)| a.iter().any(|x| !x))
            .map(|(nk, _)| *nk)
            .collect();
        self.want_pages_of(table, &keys, Some(&asks));
        // Every depth of the round, errors deferred to the repair that
        // would need the node; a depth the store cannot answer yet does
        // not stop the others from being wanted in the same round.
        let mut pending = false;
        for ((nk, tk), a) in wanted.into_iter().zip(&keys).zip(&asks) {
            match self.fetch(table, tk, Some(a)) {
                Ok(Ok(f)) if !f.cands.is_empty() => {
                    nodes.insert(nk, f.cands);
                }
                Ok(Ok(f)) => {
                    missed.insert(
                        nk,
                        Origin::NotServed {
                            searched: f.searched,
                        },
                    );
                }
                Ok(Err(_)) => {}
                Err(Pending) => pending = true,
            }
        }
        if pending {
            return Err(Pending);
        }
        let mut repairs = 0u32;
        let mut steps = Vec::new();
        let mut selected: HashMap<NodeKey, (Vec<u8>, Origin)>;
        let (outcome, walked) = loop {
            steps.clear();
            let src = Cands::new(&nodes);
            let w = if self.tracing {
                walk_traced(root, path, &src, &mut steps)
            } else {
                walk(root, path, &src)
            };
            selected = src
                .selected()
                .into_iter()
                .map(|(k, (b, o))| (k, (b.to_vec(), o)))
                .collect();
            self.mark_checked(trie, false, &steps);
            let walked = w.nodes;
            match w.outcome {
                Outcome::Present(v) => break (Read::Verified(v), walked),
                Outcome::Absent(by) => break (Read::VerifiedAbsent(by), walked),
                // A position whose candidates came from only some runs (a
                // stale node there, say, and the right one in a run the
                // hints skipped) is asked of every run before it fails.
                // This is not charged to the repair budget: it happens at
                // most once a position (it leaves `partial`), so it is
                // bounded by the walk's length, and a budget spent on
                // hint-scheduled asks must not stop a needed widening.
                Outcome::Invalid(nk, _) | Outcome::Missing(nk) if partial.contains(&nk) => {
                    let tk = key_of(&nk);
                    self.note_key(table, trie, nk.depth(), tk);
                    self.want_pages(table, &[tk]);
                    match self.fetch(table, &tk, None)? {
                        Ok(f) if !f.cands.is_empty() => {
                            partial.remove(&nk);
                            nodes.insert(nk, f.cands);
                        }
                        Ok(f) => {
                            missed.insert(
                                nk,
                                Origin::NotServed {
                                    searched: f.searched,
                                },
                            );
                            break (
                                Read::Insufficient(Reason::Missing { table, key: tk }),
                                walked,
                            );
                        }
                        Err(r) => break (Read::Insufficient(r), walked),
                    }
                }
                Outcome::Invalid(nk, what) => {
                    let r = Reason::Invalid {
                        table,
                        key: key_of(&nk),
                        what,
                    };
                    break (Read::Insufficient(r), walked);
                }
                Outcome::Missing(nk) => {
                    if repairs >= MAX_REPAIRS {
                        break (Read::Insufficient(Reason::Budget), walked);
                    }
                    repairs += 1;
                    let tk = key_of(&nk);
                    self.note_key(table, trie, nk.depth(), tk);
                    // A position not yet asked: the runs its plan names
                    // first, then, if none has it, every run. One asked of
                    // only some: every run now.
                    let mut got = None;
                    if fetched.insert(nk) {
                        let a = self.plan(table, scope, nk.depth());
                        if a.iter().any(|x| !x) {
                            self.want_pages_of(table, &[tk], Some(std::slice::from_ref(&a)));
                            match self.fetch(table, &tk, Some(&a))? {
                                Ok(f) if !f.cands.is_empty() => {
                                    partial.insert(nk);
                                    got = Some(f.cands);
                                }
                                _ => {}
                            }
                        }
                    }
                    if let Some(c) = got {
                        nodes.insert(nk, c);
                        continue;
                    }
                    self.want_pages(table, &[tk]);
                    match self.fetch(table, &tk, None)? {
                        Ok(f) if !f.cands.is_empty() => {
                            nodes.insert(nk, f.cands);
                        }
                        Ok(f) => {
                            missed.insert(
                                nk,
                                Origin::NotServed {
                                    searched: f.searched,
                                },
                            );
                            break (
                                Read::Insufficient(Reason::Missing { table, key: tk }),
                                walked,
                            );
                        }
                        Err(r) => break (Read::Insufficient(r), walked),
                    }
                }
            }
        };
        if self.tracing {
            let origin = origins(&nodes, &selected, missed);
            self.keep_trace(trie, table, false, root, key, steps, &origin, |s| {
                key_of(&s.key)
            });
        }
        if cache && self.top_levels > 0 && !outcome.is_insufficient() {
            let kept = selected.into_iter().map(|(k, (b, _))| (k, b)).collect();
            self.top_keep(path, &kept, max_depth);
        }
        Ok((outcome, repairs, walked))
    }

    fn account_walk(&mut self, hashed: &B256) -> Result<(Read<Account>, u32, usize), Pending> {
        let path = path_of(hashed);
        let d = self.d_account;
        let (r, repairs, nodes) = self.walk_table(
            Trie::Account,
            TABLE_ACCOUNT_NODES,
            self.state_root(),
            *hashed,
            &path,
            Scope::Account {
                top8: top8(&hashed.0),
            },
            |nk| nk.table_key().expect("walk depth ≤ 62"),
            d,
            true,
        )?;
        let r = r.map(|v| match Account::decode(&v) {
            Ok(a) => Read::Verified(a),
            Err(_) => Read::Insufficient(Reason::Value("account leaf")),
        });
        Ok((r, repairs, nodes))
    }

    fn storage_walk(
        &mut self,
        account: &Account,
        hashed: &B256,
        hashed_slot: &B256,
    ) -> Result<(Read<U256>, u32, usize), Pending> {
        let path = path_of(hashed_slot);
        let owner = *hashed;
        let d = self.d_storage;
        let (r, repairs, nodes) = self.walk_table(
            Trie::Storage,
            TABLE_STORAGE_NODES,
            account.storage_root,
            *hashed_slot,
            &path,
            Scope::Storage {
                owner,
                top8: top8(&hashed_slot.0),
            },
            |nk| nk.storage_table_key(&owner).expect("walk depth ≤ 62"),
            d,
            false,
        )?;
        let r = r.map(|v| match decode_word(&v) {
            Ok(w) => Read::Verified(w),
            Err(_) => Read::Insufficient(Reason::Value("storage leaf")),
        });
        Ok((r, repairs, nodes))
    }

    /// The baseline's walk: no speculation, every node fetched by the hash
    /// its parent committed to, one dependent round each (two when the
    /// node's model page is cold). `repairs` counts the nodes fetched. The
    /// top-level cache applies when `cache`, as it does to the path-keyed
    /// walk, so the two are compared on equal terms.
    fn walk_by_hash(
        &mut self,
        trie: Trie,
        root: B256,
        key: B256,
        cache: bool,
    ) -> Result<(Read<Vec<u8>>, u32, usize), Pending> {
        let path = &path_of(&key);
        let table = TABLE_NODES_BY_HASH;
        if root == EMPTY_ROOT_HASH {
            let none = HashMap::new();
            self.keep_trace(trie, table, true, root, key, Vec::new(), &none, |_| [0; 32]);
            return Ok((Read::VerifiedAbsent(AbsentBy::EmptyTrie), 0, 0));
        }
        let mut nodes = Nodes::new();
        let mut missed: HashMap<NodeKey, Origin> = HashMap::new();
        if cache {
            for d in 0..self.top_levels {
                let nk = NodeKey::prefix(path, d);
                if let Some(Some(v)) = self.top.get(&nk) {
                    nodes.insert(nk, vec![(v.clone(), Origin::Cache)]);
                }
            }
        }
        let mut fetched = 0u32;
        let mut steps = Vec::new();
        let mut selected: HashMap<NodeKey, (Vec<u8>, Origin)>;
        let (outcome, walked) = loop {
            steps.clear();
            let src = Cands::new(&nodes);
            let w = if self.tracing {
                walk_traced(root, path, &src, &mut steps)
            } else {
                walk(root, path, &src)
            };
            selected = src
                .selected()
                .into_iter()
                .map(|(k, (b, o))| (k, (b.to_vec(), o)))
                .collect();
            self.mark_checked(trie, true, &steps);
            let walked = w.nodes;
            match w.outcome {
                Outcome::Present(v) => break (Read::Verified(v), walked),
                Outcome::Absent(by) => break (Read::VerifiedAbsent(by), walked),
                Outcome::Invalid(nk, what) => {
                    let key = w
                        .expected
                        .map(|h| h.0)
                        .unwrap_or_else(|| nk.table_key().unwrap_or([0; 32]));
                    let r = Reason::Invalid {
                        table: TABLE_NODES_BY_HASH,
                        key,
                        what,
                    };
                    break (Read::Insufficient(r), walked);
                }
                Outcome::Missing(nk) => {
                    if fetched >= MAX_REPAIRS {
                        break (Read::Insufficient(Reason::Budget), walked);
                    }
                    let h = w
                        .expected
                        .expect("a missing node has the hash its parent committed to");
                    fetched += 1;
                    self.note_key(table, trie, nk.depth(), h.0);
                    self.want_pages(TABLE_NODES_BY_HASH, &[h.0]);
                    match self.fetch(TABLE_NODES_BY_HASH, &h.0, None)? {
                        Ok(f) if !f.cands.is_empty() => {
                            nodes.insert(nk, f.cands);
                        }
                        Ok(f) => {
                            missed.insert(
                                nk,
                                Origin::NotServed {
                                    searched: f.searched,
                                },
                            );
                            let r = Reason::Missing {
                                table: TABLE_NODES_BY_HASH,
                                key: h.0,
                            };
                            break (Read::Insufficient(r), walked);
                        }
                        Err(r) => break (Read::Insufficient(r), walked),
                    }
                }
            }
        };
        // The baseline looks a node up by the hash its parent committed to,
        // which is the hash the step records.
        if self.tracing {
            let origin = origins(&nodes, &selected, missed);
            self.keep_trace(trie, table, true, root, key, steps, &origin, |s| {
                s.hash.map_or([0; 32], |h| h.0)
            });
        }
        if cache && self.top_levels > 0 && !outcome.is_insufficient() {
            let kept = selected.into_iter().map(|(k, (b, _))| (k, b)).collect();
            self.top_keep(path, &kept, self.top_levels);
        }
        Ok((outcome, fetched, walked))
    }

    /// The account under `hashed`, read the baseline's way (see the crate
    /// doc): the same answer as `try_account`, one round per node.
    pub fn try_account_by_hash(&mut self, hashed: &B256) -> Result<(Read<Account>, Cost), Pending> {
        self.attempt();
        self.account_by_hash_inner(hashed)
    }

    fn account_by_hash_inner(&mut self, hashed: &B256) -> Result<(Read<Account>, Cost), Pending> {
        let (r, fetched, nodes) =
            self.walk_by_hash(Trie::Account, self.state_root(), *hashed, true)?;
        let r = r.map(|v| match Account::decode(&v) {
            Ok(a) => Read::Verified(a),
            Err(_) => Read::Insufficient(Reason::Value("account leaf")),
        });
        Ok((r, self.cost(fetched, nodes)))
    }

    /// Storage slot `hashed_slot` of the account under `hashed`, the
    /// baseline's way: the account's nodes, then the slot's, one round each.
    pub fn try_storage_by_hash(
        &mut self,
        hashed: &B256,
        hashed_slot: &B256,
    ) -> Result<(Read<U256>, Cost), Pending> {
        self.attempt();
        let (acct, af, an) = self
            .account_by_hash_inner(hashed)
            .map(|(r, c)| (r, c.repairs, c.nodes))?;
        let acct = match acct {
            Read::Verified(a) => a,
            Read::VerifiedAbsent(b) => return Ok((Read::VerifiedAbsent(b), self.cost(af, an))),
            Read::Insufficient(r) => return Ok((Read::Insufficient(r), self.cost(af, an))),
        };
        let (r, sf, sn) =
            self.walk_by_hash(Trie::Storage, acct.storage_root, *hashed_slot, false)?;
        let r = r.map(|v| match decode_word(&v) {
            Ok(w) => Read::Verified(w),
            Err(_) => Read::Insufficient(Reason::Value("storage leaf")),
        });
        Ok((r, self.cost(af + sf, an + sn)))
    }

    /// The account under `hashed = keccak(address)`, from the store.
    pub fn try_account(&mut self, hashed: &B256) -> Result<(Read<Account>, Cost), Pending> {
        self.attempt();
        let (r, repairs, nodes) = self.account_walk(hashed)?;
        Ok((r, self.cost(repairs, nodes)))
    }

    /// Storage slot `hashed_slot = keccak(slot)` of the account under
    /// `hashed`, from the store. The storage trie's predicted pages are
    /// wanted in the account's round (its table keys need only the owner),
    /// so the two walks share one round when the predictions hold; an
    /// account that is absent or has the empty root answers without
    /// walking storage.
    pub fn try_storage(
        &mut self,
        hashed: &B256,
        hashed_slot: &B256,
    ) -> Result<(Read<U256>, Cost), Pending> {
        self.attempt();
        let spath = path_of(hashed_slot);
        let owner = *hashed;
        let skeys: Vec<[u8; 32]> = (0..=self.d_storage)
            .map(|d| {
                NodeKey::prefix(&spath, d)
                    .storage_table_key(&owner)
                    .expect("walk depth ≤ 62")
            })
            .collect();
        for (d, k) in skeys.iter().enumerate() {
            self.note_key(TABLE_STORAGE_NODES, Trie::Storage, d, *k);
        }
        let asks: Vec<Vec<bool>> = (0..skeys.len())
            .map(|d| {
                let scope = Scope::Storage {
                    owner,
                    top8: top8(&hashed_slot.0),
                };
                self.plan(TABLE_STORAGE_NODES, scope, d)
            })
            .collect();
        self.want_pages_of(TABLE_STORAGE_NODES, &skeys, Some(&asks));
        let (acct, ar, an) = self.account_walk(hashed)?;
        let acct = match acct {
            Read::Verified(a) => a,
            Read::VerifiedAbsent(b) => return Ok((Read::VerifiedAbsent(b), self.cost(ar, an))),
            Read::Insufficient(r) => return Ok((Read::Insufficient(r), self.cost(ar, an))),
        };
        let (r, sr, sn) = self.storage_walk(&acct, hashed, hashed_slot)?;
        Ok((r, self.cost(ar + sr, an + sn)))
    }

    /// Storage of an account the caller has already verified, from the
    /// store.
    pub fn try_storage_of(
        &mut self,
        account: &Account,
        hashed: &B256,
        hashed_slot: &B256,
    ) -> Result<(Read<U256>, Cost), Pending> {
        self.attempt();
        let (r, repairs, nodes) = self.storage_walk(account, hashed, hashed_slot)?;
        Ok((r, self.cost(repairs, nodes)))
    }

    /// Bytecode under a `codeHash` the caller verified, from the store.
    /// `KECCAK_EMPTY` is empty code with no fetch; a blob (code above the
    /// inline size) is a second round.
    pub fn try_code(&mut self, code_hash: &B256) -> Result<(Read<Vec<u8>>, Cost), Pending> {
        self.attempt();
        let r = self.code_inner(code_hash);
        if let Ok((Read::Verified(b), _)) = &r {
            if let Some(c) = self.trace.code.as_mut() {
                c.len = Some(b.len());
            }
        }
        r
    }

    /// The code table's runs to ask for `code_hash`, newest first: the
    /// newest layer whose hint names it (any copy that hashes is the
    /// code), else every layer without a hint, and the base.
    fn code_plan(&self, code_hash: &B256) -> Vec<bool> {
        let slots = &self.runs[TABLE_CODE as usize];
        let mut ask = vec![false; slots.len()];
        for i in (0..slots.len()).rev() {
            let Some(li) = slots[i].layer else {
                ask[i] = true;
                break;
            };
            match &self.manifest.layers[li].hints.code {
                None => ask[i] = true,
                Some(k) if k.contains(&code_hash.0) => {
                    ask[i] = true;
                    break;
                }
                Some(_) => {}
            }
        }
        ask
    }

    /// The runs the hints name first; if none of them gives the code,
    /// every run.
    fn code_inner(&mut self, code_hash: &B256) -> Result<(Read<Vec<u8>>, Cost), Pending> {
        let ask = self.code_plan(code_hash);
        if ask.iter().all(|a| *a) {
            return self.code_pass(code_hash, None);
        }
        match self.code_pass(code_hash, Some(&ask))? {
            (Read::Verified(b), c) => Ok((Read::Verified(b), c)),
            _ => self.code_pass(code_hash, None),
        }
    }

    fn code_pass(
        &mut self,
        code_hash: &B256,
        ask: Option<&[bool]>,
    ) -> Result<(Read<Vec<u8>>, Cost), Pending> {
        if self.tracing {
            self.trace.code = Some(CodeTrace {
                code_hash: *code_hash,
                page: None,
                blob: None,
                len: None,
            });
        }
        if *code_hash == KECCAK_EMPTY {
            return Ok((Read::Verified(Vec::new()), self.cost(0, 0)));
        }
        self.note_key(TABLE_CODE, Trie::Account, 0, code_hash.0);
        match ask {
            Some(a) => self.want_pages_of(TABLE_CODE, &[code_hash.0], Some(&[a.to_vec()])),
            None => self.want_pages(TABLE_CODE, &[code_hash.0]),
        }
        // Every run of the code table: a layer adds code the base lacks,
        // and any copy that hashes to `codeHash` is the code.
        let slots = &mut self.runs[TABLE_CODE as usize];
        if slots.is_empty() {
            return Ok((
                Read::Insufficient(Reason::NoTable(TABLE_CODE)),
                self.cost(0, 0),
            ));
        }
        let mut entries = Vec::new();
        let mut err: Option<Reason> = None;
        let mut first_page = None;
        let mut pending = false;
        for (i, slot) in slots.iter_mut().enumerate() {
            if ask.is_some_and(|a| !a[i]) {
                continue;
            }
            if slot.layer.is_some() {
                self.asked.insert((TABLE_CODE, i));
            }
            let reader = match slot.reader.as_mut() {
                Ok(r) => r,
                Err(why) => {
                    err.get_or_insert_with(|| why.clone());
                    continue;
                }
            };
            // `get_entry`, keeping the page index for the trace.
            match reader.locate(&code_hash.0) {
                Ok((page, p, _)) => {
                    first_page.get_or_insert(page);
                    if let Some(e) = p.find(&code_hash.0) {
                        entries.push((page, e.clone()));
                    }
                }
                Err(e) if is_pending(&e) => pending = true,
                Err(e) => {
                    err.get_or_insert(Reason::Run {
                        table: TABLE_CODE,
                        error: e.to_string(),
                    });
                }
            }
        }
        if pending {
            return Err(Pending);
        }
        if let Some(c) = self.trace.code.as_mut() {
            c.page = first_page;
        }
        if entries.is_empty() {
            let r = err.unwrap_or(Reason::Missing {
                table: TABLE_CODE,
                key: code_hash.0,
            });
            return Ok((Read::Insufficient(r), self.cost(0, 0)));
        }
        // The trace names the candidate that answered, or else the first
        // that failed.
        let mut why: Option<Reason> = None;
        let mut failed: Option<(u64, Option<String>)> = None;
        for (page, e) in entries {
            let blob = (e.tag == 2).then(|| {
                let h: [u8; 32] = e.value.as_slice().try_into().expect("tag 2 is 32 bytes");
                blob_path(&h)
            });
            let mut fail = |why: &mut Option<Reason>, r: Reason| {
                why.get_or_insert(r);
                failed.get_or_insert((page, blob.clone()));
            };
            let bytes = match e.tag {
                0 => e.value,
                2 => {
                    let h: [u8; 32] = e.value.as_slice().try_into().expect("tag 2 is 32 bytes");
                    match self.store.file(&blob_path(&h))? {
                        Ok(Some(b)) if *blake3::hash(&b).as_bytes() == h => b,
                        Ok(Some(_)) => {
                            fail(
                                &mut why,
                                Reason::Blob("blob does not hash to its name".into()),
                            );
                            continue;
                        }
                        Ok(None) => {
                            fail(
                                &mut why,
                                Reason::Blob(format!("{} is not in the bucket", blob_path(&h))),
                            );
                            continue;
                        }
                        Err(e) => {
                            fail(&mut why, Reason::Blob(e));
                            continue;
                        }
                    }
                }
                _ => {
                    fail(&mut why, Reason::Code("tombstone in the code table"));
                    continue;
                }
            };
            if keccak256(&bytes) != *code_hash {
                fail(&mut why, Reason::Code("bytecode does not hash to codeHash"));
                continue;
            }
            if let Some(c) = self.trace.code.as_mut() {
                c.page = Some(page);
                c.blob = blob;
            }
            return Ok((Read::Verified(bytes), self.cost(0, 0)));
        }
        if let (Some(c), Some((page, blob))) = (self.trace.code.as_mut(), failed) {
            c.page = Some(page);
            c.blob = blob;
        }
        Ok((
            Read::Insufficient(why.expect("a candidate failed")),
            self.cost(0, 0),
        ))
    }

    /// The account under `hashed = keccak(address)`.
    pub fn account(&mut self, hashed: &B256) -> (Read<Account>, Cost) {
        self.run(|s| s.try_account(hashed))
    }

    /// Storage slot `hashed_slot = keccak(slot)` of the account under
    /// `hashed`.
    pub fn storage(&mut self, hashed: &B256, hashed_slot: &B256) -> (Read<U256>, Cost) {
        self.run(|s| s.try_storage(hashed, hashed_slot))
    }

    /// Storage of an account the caller has already verified.
    pub fn storage_of(
        &mut self,
        account: &Account,
        hashed: &B256,
        hashed_slot: &B256,
    ) -> (Read<U256>, Cost) {
        self.run(|s| s.try_storage_of(account, hashed, hashed_slot))
    }

    /// Bytecode under a `codeHash` the caller verified.
    pub fn code(&mut self, code_hash: &B256) -> (Read<Vec<u8>>, Cost) {
        self.run(|s| s.try_code(code_hash))
    }

    /// The account, the content-addressed baseline's way.
    pub fn account_by_hash(&mut self, hashed: &B256) -> (Read<Account>, Cost) {
        self.run(|s| s.try_account_by_hash(hashed))
    }

    /// The storage slot, the content-addressed baseline's way.
    pub fn storage_by_hash(&mut self, hashed: &B256, hashed_slot: &B256) -> (Read<U256>, Cost) {
        self.run(|s| s.try_storage_by_hash(hashed, hashed_slot))
    }
}
