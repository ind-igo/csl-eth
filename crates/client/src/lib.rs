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
    blob_path, manifest_path, table_path, Manifest, D_ACCOUNT, D_STORAGE, FORMAT_VERSION,
    LATEST_FILE, RUN_FORMAT, TABLE_ACCOUNT_NODES, TABLE_CODE, TABLE_COUNT, TABLE_NODES_BY_HASH,
    TABLE_STORAGE_NODES,
};
use csl_eth_trie::{decode_word, path_of, walk, AbsentBy, Account, Invalid, NodeKey, Outcome};
use csl_run::Reader;
use std::{collections::HashMap, fmt, sync::Arc};

pub mod store;
#[cfg(not(target_arch = "wasm32"))]
pub use store::DirDriver;
pub use store::{drive, is_pending, Driver, Got, NoDriver, Pending, RunView, Store, Want, PENDING};

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub use http::HttpDriver;

pub mod head;
pub use head::{open_at_head, HeadOpenError, HeadOpener, VerifiedHead};

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
        let manifest = match self.store.file(&manifest_path(&hash))? {
            Ok(Some(m)) => match Manifest::from_json(&m) {
                Ok(m) => m,
                Err(e) => return Ok(Err(e.to_string())),
            },
            Ok(None) => return Ok(Err(format!("no snapshot at {hash}"))),
            Err(e) => return Ok(Err(e)),
        };
        if manifest.block_hash != hash {
            return Ok(Err("manifest names a different block".into()));
        }
        if manifest.format_version != FORMAT_VERSION {
            return Ok(Err(format!(
                "manifest format version {}, this client reads {FORMAT_VERSION}",
                manifest.format_version
            )));
        }
        if manifest.state_root != self.state_root {
            return Ok(Err(format!(
                "snapshot claims state_root {}, caller verified {}",
                manifest.state_root, self.state_root
            )));
        }
        // Every table's page 0 (the top model and the model tree's root) in
        // one round: each is a range the store may lack, and a reader's
        // `prepare` is the read that wants it. A table that fails here (a
        // page 0 that does not hash, a truncated file) does not refuse the
        // snapshot: its reads are `Insufficient` with that reason, and the
        // other tables still serve.
        let mut readers = Vec::with_capacity(TABLE_COUNT);
        let mut pending = false;
        for t in 0..TABLE_COUNT as u16 {
            let Some(tr) = manifest.table(t) else {
                readers.push(Err(Reason::NoTable(t)));
                continue;
            };
            let view = RunView {
                store: self.store.clone(),
                rel: table_path(&hash, t),
            };
            let broken = |e: csl_run::Error| Reason::Run {
                table: t,
                error: e.to_string(),
            };
            let mut reader = match Reader::try_with_format(
                view,
                tr.run_ref(manifest.block_number),
                RUN_FORMAT,
            ) {
                Ok(r) => r,
                Err(e) => {
                    readers.push(Err(broken(e)));
                    continue;
                }
            };
            match reader.prepare() {
                Ok(()) => readers.push(Ok(reader)),
                Err(e) if is_pending(&e) => {
                    pending = true;
                    readers.push(Ok(reader));
                }
                Err(e) => readers.push(Err(broken(e))),
            }
        }
        if pending {
            return Err(Pending);
        }
        let driver = self.driver.take().expect("opened once");
        Ok(Ok(Snapshot {
            driver,
            store: self.store.clone(),
            manifest,
            readers,
            d_account: D_ACCOUNT,
            d_storage: D_STORAGE,
            hint: Hint::default(),
            top_levels: 0,
            top: HashMap::new(),
            model_at_begin: 0,
        }))
    }
}

pub struct Snapshot<D> {
    driver: D,
    store: Arc<Store>,
    manifest: Manifest,
    readers: Vec<Result<Reader<RunView>, Reason>>,
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
}

/// Nodes fetched so far, by position.
type Nodes = HashMap<NodeKey, Vec<u8>>;

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
    }

    /// Model section reads so far: page 0 per table at open, then one per
    /// model page fetched.
    pub fn model_requests(&self) -> u64 {
        self.readers
            .iter()
            .filter_map(|r| r.as_ref().ok())
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
        }
    }

    /// One table key from the store: `Ok(None)` when the table's page for
    /// it holds no such entry (which the walk will report as `Missing`).
    fn fetch(
        &mut self,
        table: u16,
        key: &[u8; 32],
    ) -> Result<Result<Option<Vec<u8>>, Reason>, Pending> {
        let r = match self.readers[table as usize].as_mut() {
            Ok(r) => r,
            Err(why) => return Ok(Err(why.clone())),
        };
        Ok(match r.get_entry(key) {
            Ok((Some(e), _)) if e.tag == 0 => Ok(Some(e.value)),
            Ok((Some(_), _)) => Err(Reason::Invalid {
                table,
                key: *key,
                what: Invalid::Rlp,
            }),
            Ok((None, _)) => Ok(None),
            Err(e) if is_pending(&e) => return Err(Pending),
            Err(e) => Err(Reason::Run {
                table,
                error: e.to_string(),
            }),
        })
    }

    /// Want the pages the model predicts for `keys`, widened as the hint
    /// says, so the round fetches them together with whatever else it
    /// finds missing. Pages the store holds are not wanted again. A key
    /// whose model page the store lacks wants that page instead (the
    /// reader's prediction is the read that notes it) and its data pages
    /// come in the next round: a cold neighbourhood is two rounds, a warm
    /// one is one.
    fn want_pages(&mut self, table: u16, keys: &[[u8; 32]]) {
        let h = self.hint;
        let Ok(reader) = self.readers[table as usize].as_mut() else {
            return;
        };
        let Some(layout) = reader.layout().copied() else {
            return;
        };
        let rel = table_path(&self.manifest.block_hash, table);
        let len = layout.record_bytes as usize;
        for k in keys {
            let Ok(p) = reader.predict_page(csl_run::k64(k)) else {
                continue;
            };
            let lo = p.saturating_sub(h.below).max(1);
            let hi = (p + h.above).min(layout.page_count);
            for q in lo..=hi {
                if let Some(off) = layout.checked_record_off(q) {
                    self.store.want_range(&rel, off, len);
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

    /// After a verified walk: every node (and every gap) above the deepest
    /// node fetched lies on the path and was hashed by the walk, so those
    /// at the cached depths are kept for the snapshot's later reads.
    fn top_keep(&mut self, path: &Nibbles, nodes: &Nodes, max_depth: usize) {
        let Some(leaf) = nodes.keys().map(NodeKey::depth).max() else {
            return;
        };
        for d in 0..leaf.min(self.top_levels).min(max_depth + 1) {
            let nk = NodeKey::prefix(path, d);
            self.top
                .entry(nk)
                .or_insert_with(|| nodes.get(&nk).cloned());
        }
    }

    /// The depths of `path` the speculative round asks `table` for: every
    /// depth up to `max_depth` the cache does not answer.
    fn speculative(&self, path: &Nibbles, max_depth: usize, cache: bool) -> (Vec<NodeKey>, Nodes) {
        let mut wanted = Vec::with_capacity(max_depth + 1);
        let mut nodes = Nodes::new();
        for d in 0..=max_depth {
            let nk = NodeKey::prefix(path, d);
            match self.top_get(cache, &nk) {
                Some(Some(v)) => {
                    nodes.insert(nk, v.clone());
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
    fn walk_table(
        &mut self,
        table: u16,
        root: B256,
        path: &Nibbles,
        key_of: impl Fn(&NodeKey) -> [u8; 32],
        max_depth: usize,
        cache: bool,
    ) -> Result<(Read<Vec<u8>>, u32, usize), Pending> {
        if root == EMPTY_ROOT_HASH {
            return Ok((Read::VerifiedAbsent(AbsentBy::EmptyTrie), 0, 0));
        }
        let (wanted, mut nodes) = self.speculative(path, max_depth, cache);
        let keys: Vec<[u8; 32]> = wanted.iter().map(&key_of).collect();
        self.want_pages(table, &keys);
        // Every depth of the round, errors deferred to the repair that
        // would need the node; a depth the store cannot answer yet does
        // not stop the others from being wanted in the same round.
        let mut pending = false;
        for (nk, tk) in wanted.into_iter().zip(&keys) {
            match self.fetch(table, tk) {
                Ok(Ok(Some(v))) => {
                    nodes.insert(nk, v);
                }
                Ok(_) => {}
                Err(Pending) => pending = true,
            }
        }
        if pending {
            return Err(Pending);
        }
        let mut repairs = 0u32;
        let (outcome, walked) = loop {
            let w = walk(root, path, &nodes);
            let walked = w.nodes;
            match w.outcome {
                Outcome::Present(v) => break (Read::Verified(v), walked),
                Outcome::Absent(by) => break (Read::VerifiedAbsent(by), walked),
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
                    self.want_pages(table, &[tk]);
                    match self.fetch(table, &tk)? {
                        Ok(Some(v)) => {
                            nodes.insert(nk, v);
                        }
                        Ok(None) => {
                            break (
                                Read::Insufficient(Reason::Missing { table, key: tk }),
                                walked,
                            )
                        }
                        Err(r) => break (Read::Insufficient(r), walked),
                    }
                }
            }
        };
        if cache && self.top_levels > 0 && !outcome.is_insufficient() {
            self.top_keep(path, &nodes, max_depth);
        }
        Ok((outcome, repairs, walked))
    }

    fn account_walk(&mut self, hashed: &B256) -> Result<(Read<Account>, u32, usize), Pending> {
        let path = path_of(hashed);
        let d = self.d_account;
        let (r, repairs, nodes) = self.walk_table(
            TABLE_ACCOUNT_NODES,
            self.state_root(),
            &path,
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
            TABLE_STORAGE_NODES,
            account.storage_root,
            &path,
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
        root: B256,
        path: &Nibbles,
        cache: bool,
    ) -> Result<(Read<Vec<u8>>, u32, usize), Pending> {
        if root == EMPTY_ROOT_HASH {
            return Ok((Read::VerifiedAbsent(AbsentBy::EmptyTrie), 0, 0));
        }
        let mut nodes = Nodes::new();
        if cache {
            for d in 0..self.top_levels {
                let nk = NodeKey::prefix(path, d);
                if let Some(Some(v)) = self.top.get(&nk) {
                    nodes.insert(nk, v.clone());
                }
            }
        }
        let mut fetched = 0u32;
        let (outcome, walked) = loop {
            let w = walk(root, path, &nodes);
            let walked = w.nodes;
            match w.outcome {
                Outcome::Present(v) => break (Read::Verified(v), walked),
                Outcome::Absent(by) => break (Read::VerifiedAbsent(by), walked),
                Outcome::Invalid(nk, what) => {
                    let key = w.expected.map(|h| h.0).unwrap_or_else(|| nk.table_key().unwrap_or([0; 32]));
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
                    let h = w.expected.expect("a missing node has the hash its parent committed to");
                    fetched += 1;
                    self.want_pages(TABLE_NODES_BY_HASH, &[h.0]);
                    match self.fetch(TABLE_NODES_BY_HASH, &h.0)? {
                        Ok(Some(v)) => {
                            nodes.insert(nk, v);
                        }
                        Ok(None) => {
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
        if cache && self.top_levels > 0 && !outcome.is_insufficient() {
            self.top_keep(path, &nodes, self.top_levels);
        }
        Ok((outcome, fetched, walked))
    }

    /// The account under `hashed`, read the baseline's way (see the crate
    /// doc): the same answer as `try_account`, one round per node.
    pub fn try_account_by_hash(
        &mut self,
        hashed: &B256,
    ) -> Result<(Read<Account>, Cost), Pending> {
        let path = path_of(hashed);
        let (r, fetched, nodes) = self.walk_by_hash(self.state_root(), &path, true)?;
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
        let (acct, af, an) = self.try_account_by_hash(hashed).map(|(r, c)| (r, c.repairs, c.nodes))?;
        let acct = match acct {
            Read::Verified(a) => a,
            Read::VerifiedAbsent(b) => return Ok((Read::VerifiedAbsent(b), self.cost(af, an))),
            Read::Insufficient(r) => return Ok((Read::Insufficient(r), self.cost(af, an))),
        };
        let (r, sf, sn) = self.walk_by_hash(acct.storage_root, &path_of(hashed_slot), false)?;
        let r = r.map(|v| match decode_word(&v) {
            Ok(w) => Read::Verified(w),
            Err(_) => Read::Insufficient(Reason::Value("storage leaf")),
        });
        Ok((r, self.cost(af + sf, an + sn)))
    }

    /// The account under `hashed = keccak(address)`, from the store.
    pub fn try_account(&mut self, hashed: &B256) -> Result<(Read<Account>, Cost), Pending> {
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
        let spath = path_of(hashed_slot);
        let owner = *hashed;
        let skeys: Vec<[u8; 32]> = (0..=self.d_storage)
            .map(|d| {
                NodeKey::prefix(&spath, d)
                    .storage_table_key(&owner)
                    .expect("walk depth ≤ 62")
            })
            .collect();
        self.want_pages(TABLE_STORAGE_NODES, &skeys);
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
        let (r, repairs, nodes) = self.storage_walk(account, hashed, hashed_slot)?;
        Ok((r, self.cost(repairs, nodes)))
    }

    /// Bytecode under a `codeHash` the caller verified, from the store.
    /// `KECCAK_EMPTY` is empty code with no fetch; a blob (code above the
    /// inline size) is a second round.
    pub fn try_code(&mut self, code_hash: &B256) -> Result<(Read<Vec<u8>>, Cost), Pending> {
        if *code_hash == KECCAK_EMPTY {
            return Ok((Read::Verified(Vec::new()), self.cost(0, 0)));
        }
        self.want_pages(TABLE_CODE, &[code_hash.0]);
        let reader = match self.readers[TABLE_CODE as usize].as_mut() {
            Ok(r) => r,
            Err(why) => {
                let why = why.clone();
                return Ok((Read::Insufficient(why), self.cost(0, 0)));
            }
        };
        let entry = match reader.get_entry(&code_hash.0) {
            Ok((e, _)) => e,
            Err(e) if is_pending(&e) => return Err(Pending),
            Err(e) => {
                let r = Reason::Run {
                    table: TABLE_CODE,
                    error: e.to_string(),
                };
                return Ok((Read::Insufficient(r), self.cost(0, 0)));
            }
        };
        let bytes = match entry {
            None => {
                let r = Reason::Missing {
                    table: TABLE_CODE,
                    key: code_hash.0,
                };
                return Ok((Read::Insufficient(r), self.cost(0, 0)));
            }
            Some(e) if e.tag == 0 => e.value,
            Some(e) if e.tag == 2 => {
                let h: [u8; 32] = e.value.as_slice().try_into().expect("tag 2 is 32 bytes");
                match self.store.file(&blob_path(&h))? {
                    Ok(Some(b)) if *blake3::hash(&b).as_bytes() == h => b,
                    Ok(Some(_)) => {
                        let r = Reason::Blob("blob does not hash to its name".into());
                        return Ok((Read::Insufficient(r), self.cost(0, 0)));
                    }
                    Ok(None) => {
                        let r = Reason::Blob(format!("{} is not in the bucket", blob_path(&h)));
                        return Ok((Read::Insufficient(r), self.cost(0, 0)));
                    }
                    Err(e) => return Ok((Read::Insufficient(Reason::Blob(e)), self.cost(0, 0))),
                }
            }
            Some(_) => {
                let r = Reason::Code("tombstone in the code table");
                return Ok((Read::Insufficient(r), self.cost(0, 0)));
            }
        };
        if keccak256(&bytes) != *code_hash {
            let r = Reason::Code("bytecode does not hash to codeHash");
            return Ok((Read::Insufficient(r), self.cost(0, 0)));
        }
        Ok((Read::Verified(bytes), self.cost(0, 0)))
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
