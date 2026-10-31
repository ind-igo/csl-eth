//! The client, profile §2: one speculative round, the walk, repair rounds,
//! and nothing accepted that does not hash to `state_root`.
//!
//! The caller supplies the `state_root` it verified (from the head files in
//! milestone 2; a supplied checkpoint in milestone 1). The snapshot's
//! manifest says which root its files claim to serve, and the client
//! refuses to open a snapshot for a different root rather than silently
//! walking files that cannot match.
//!
//! Every read returns `Verified`, `VerifiedAbsent` (proven by the trie's
//! shape) or `Insufficient` (something was missing or wrong), with the
//! requests, bytes and rounds it took. Fences, models, tombstones and
//! missing files never become absence.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{Nibbles, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use csl_eth_store::{
    blob_path, manifest_path, table_path, Manifest, D_ACCOUNT, D_STORAGE, LATEST_FILE,
    TABLE_ACCOUNT_NODES, TABLE_CODE, TABLE_COUNT, TABLE_STORAGE_NODES,
};
use csl_eth_trie::{
    decode_word, path_of, walk, AbsentBy, Account, Invalid, NodeKey, NodeSource, Outcome,
};
use csl_run::{Format, Reader, Source};
use std::{
    collections::HashMap,
    fmt,
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "http")]
pub use http::HttpBucket;

pub mod head;
pub use head::{open_at_head, HeadOpenError, VerifiedHead};

/// Where the files are. Runs are read by byte range through
/// [`csl_run::Source`]; manifests, `latest` and blobs are read whole.
pub trait Bucket {
    type Run: Source + Prefetch;
    fn open_run(&self, rel: &str) -> Result<Self::Run, String>;
    fn read_file(&self, rel: &str) -> Result<Vec<u8>, String>;
    /// `Ok(None)` when the file is not there, as distinct from a failure to
    /// read it; the head verifier treats the two differently.
    fn read_file_opt(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        self.read_file(rel).map(Some)
    }
}

/// A hint a source may act on: these byte ranges are about to be read, in
/// no particular order, so a remote source fetches them now in parallel
/// and serves the reads that follow from what came back. One speculative
/// round is one `prefetch` call. A local source ignores it.
pub trait Prefetch {
    fn prefetch(&self, _ranges: &[(u64, usize)]) {}
    /// A read is starting: drop whatever the last one fetched. What a
    /// source keeps is one read's pages, never a cache across reads, so
    /// every read is measured and verified on its own.
    fn forget(&self) {}
}

impl Prefetch for File {}

/// A source the snapshot and its reader both hold: the reader reads
/// through it, the snapshot hands it prefetch hints.
pub struct Shared<S>(pub Arc<S>);

impl<S: Source> Source for Shared<S> {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, csl_run::Error> {
        self.0.read_at(off, len)
    }
}

/// A directory on disk (the producer's output, or a mirror).
pub struct DirBucket(pub PathBuf);

impl DirBucket {
    pub fn new(p: impl AsRef<Path>) -> DirBucket {
        DirBucket(p.as_ref().to_path_buf())
    }
}

impl Bucket for DirBucket {
    type Run = File;
    fn open_run(&self, rel: &str) -> Result<File, String> {
        File::open(self.0.join(rel)).map_err(|e| format!("{rel}: {e}"))
    }
    fn read_file(&self, rel: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.0.join(rel)).map_err(|e| format!("{rel}: {e}"))
    }
    fn read_file_opt(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(self.0.join(rel)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{rel}: {e}")),
        }
    }
}

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
}

/// What one read cost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cost {
    /// Range requests for records and model sections.
    pub requests: u64,
    pub bytes: u64,
    /// Dependent network rounds: the speculative round plus one per repair.
    pub rounds: u32,
    pub repairs: u32,
    /// Trie nodes decoded on the final walk(s).
    pub nodes: usize,
}

impl Cost {
    fn add(&mut self, o: Cost) {
        self.requests += o.requests;
        self.bytes += o.bytes;
        self.rounds += o.rounds;
        self.repairs += o.repairs;
        self.nodes += o.nodes;
    }
}

/// Repairs a single read may take: one per node the speculative round
/// missed, bounded by the walk's own node limit.
pub const MAX_REPAIRS: u32 = csl_eth_trie::MAX_WALK_NODES as u32;

/// How a speculative round is hinted to the source: the predicted page of
/// every depth, widened `below` and `above` pages, and whether pages that
/// touch are asked for as one range (one request) or one each.
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
}

pub struct Snapshot<B: Bucket> {
    bucket: B,
    manifest: Manifest,
    tables: Vec<Option<Reader<Shared<B::Run>>>>,
    sources: Vec<Option<Arc<B::Run>>>,
    pub d_account: usize,
    pub d_storage: usize,
    /// Before a speculative round, hint the table's source with the pages
    /// the model predicts (`None`: no hint, the reader fetches as it walks).
    pub prefetch: Option<Hint>,
    /// Account-trie nodes at depths below this are kept across reads of
    /// this snapshot once a verified walk has passed them, and neither
    /// hinted nor fetched again (`0`: off). Every block rewrites the top of
    /// the trie, so the cache is the snapshot's and dies with it.
    pub top_levels: usize,
    /// `Some(node)` or `None` for "no node at this depth, an extension
    /// spans it", both verified by the walk that stored them.
    top: HashMap<NodeKey, Option<Vec<u8>>>,
}

impl<B: Bucket> Snapshot<B> {
    /// Open the snapshot at `block_hash` (the newest when `None`) and
    /// require that it claims `state_root`, the root the caller verified.
    pub fn open(
        bucket: B,
        block_hash: Option<B256>,
        state_root: B256,
    ) -> Result<Snapshot<B>, String> {
        let hash = match block_hash {
            Some(h) => h,
            None => {
                let s = bucket.read_file(LATEST_FILE)?;
                let s = String::from_utf8(s).map_err(|e| e.to_string())?;
                hex::decode(s.trim())
                    .ok()
                    .and_then(|v| <[u8; 32]>::try_from(v).ok())
                    .map(B256::from)
                    .ok_or("latest is not a block hash")?
            }
        };
        let manifest = Manifest::from_json(&bucket.read_file(&manifest_path(&hash))?)
            .map_err(|e| e.to_string())?;
        if manifest.block_hash != hash {
            return Err("manifest names a different block".into());
        }
        if manifest.state_root != state_root {
            return Err(format!(
                "snapshot claims state_root {}, caller verified {}",
                manifest.state_root, state_root
            ));
        }
        let mut tables = Vec::with_capacity(TABLE_COUNT);
        let mut sources = Vec::with_capacity(TABLE_COUNT);
        for t in 0..TABLE_COUNT as u16 {
            let (r, src) = match manifest.table(t) {
                Some(tr) => {
                    let src = Arc::new(bucket.open_run(&table_path(&hash, t))?);
                    let reader = Reader::try_with_format(
                        Shared(src.clone()),
                        tr.run_ref(manifest.block_number),
                        Format::variable(),
                    )
                    .map_err(|e| format!("table {t}: {e}"))?;
                    (Some(reader), Some(src))
                }
                None => (None, None),
            };
            tables.push(r);
            sources.push(src);
        }
        Ok(Snapshot {
            bucket,
            manifest,
            tables,
            sources,
            d_account: D_ACCOUNT,
            d_storage: D_STORAGE,
            prefetch: None,
            top_levels: 0,
            top: HashMap::new(),
        })
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn state_root(&self) -> B256 {
        self.manifest.state_root
    }

    /// Cumulative request statistics per table.
    pub fn stats(&self, table: u16) -> Option<&csl_run::Stats> {
        self.tables[table as usize].as_ref().map(|r| &r.stats)
    }

    fn requests_so_far(&self) -> (u64, u64) {
        self.tables.iter().flatten().fold((0, 0), |(r, b), t| {
            (
                r + t.stats.record_requests + t.stats.model_requests,
                b + t.stats.record_bytes,
            )
        })
    }

    /// Fetch one table key; `Ok(None)` when the table's page for it holds
    /// no such entry (which the walk will report as `Missing`).
    fn fetch(&mut self, table: u16, key: &[u8; 32]) -> Result<Option<Vec<u8>>, Reason> {
        let Some(r) = self.tables[table as usize].as_mut() else {
            return Err(Reason::NoTable(table));
        };
        match r.get_entry(key) {
            Ok((Some(e), _)) if e.tag == 0 => Ok(Some(e.value)),
            Ok((Some(_), _)) => Err(Reason::Invalid {
                table,
                key: *key,
                what: Invalid::Rlp,
            }),
            Ok((None, _)) => Ok(None),
            Err(e) => Err(Reason::Run {
                table,
                error: e.to_string(),
            }),
        }
    }

    /// One read's pages are kept by a remote source for that read only.
    fn begin_read(&self) {
        for src in self.sources.iter().flatten() {
            src.forget();
        }
    }

    /// Hand the table's source the byte ranges of the pages the model
    /// predicts for `keys`, widened as the hint says. Pages that touch are
    /// one range when the hint merges: the depths of one path share pages
    /// in a pre-order table, so a read's pages come in a few runs. Errors
    /// here are not errors: the reads that follow report them.
    fn hint(&mut self, table: u16, keys: &[[u8; 32]], h: Hint) {
        let (Some(reader), Some(src)) = (
            self.tables[table as usize].as_mut(),
            self.sources[table as usize].as_ref(),
        ) else {
            return;
        };
        let Some(layout) = reader.layout().copied() else {
            return;
        };
        let Ok(model) = reader.load_model() else {
            return;
        };
        let mut pages = Vec::with_capacity(keys.len() * (h.below + h.above + 1) as usize);
        for k in keys {
            let p = model.predict(csl_run::k64(k));
            let lo = p.saturating_sub(h.below).max(1);
            let hi = (p + h.above).min(layout.page_count);
            pages.extend(lo..=hi);
        }
        pages.sort_unstable();
        pages.dedup();
        let len = layout.record_bytes as usize;
        let mut ranges: Vec<(u64, usize)> = Vec::with_capacity(pages.len());
        for q in pages {
            let Some(off) = layout.checked_record_off(q) else {
                continue;
            };
            match ranges.last_mut() {
                Some((o, l)) if h.merge && *o + *l as u64 == off => *l += len,
                _ => ranges.push((off, len)),
            }
        }
        src.prefetch(&ranges);
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
    fn top_keep<F: Fn(&NodeKey) -> [u8; 32]>(&mut self, path: &Nibbles, nodes: &Nodes<'_, F>, max_depth: usize) {
        let Some(leaf) = nodes.map.keys().map(NodeKey::depth).max() else {
            return;
        };
        for d in 0..leaf.min(self.top_levels).min(max_depth + 1) {
            let nk = NodeKey::prefix(path, d);
            self.top.entry(nk).or_insert_with(|| nodes.map.get(&nk).cloned());
        }
    }

    /// The walk of profile §2 over `table`: speculate `0..=max_depth`,
    /// walk, repair until the trie answers.
    fn walk_table(
        &mut self,
        table: u16,
        root: B256,
        path: &Nibbles,
        key_of: impl Fn(&NodeKey) -> [u8; 32],
        max_depth: usize,
        cache: bool,
    ) -> (Read<Vec<u8>>, Cost) {
        let mut cost = Cost::default();
        if root == EMPTY_ROOT_HASH {
            return (Read::VerifiedAbsent(AbsentBy::EmptyTrie), cost);
        }
        self.begin_read();
        let (r0, b0) = self.requests_so_far();
        let mut nodes: Nodes<_> = Nodes {
            map: HashMap::new(),
            key_of: &key_of,
        };
        // Speculative round: every depth not already known from the cache,
        // errors deferred to the repair that would need the node.
        cost.rounds = 1;
        let mut wanted: Vec<NodeKey> = Vec::with_capacity(max_depth + 1);
        for d in 0..=max_depth {
            let nk = NodeKey::prefix(path, d);
            match self.top_get(cache, &nk) {
                Some(Some(v)) => {
                    nodes.map.insert(nk, v.clone());
                }
                Some(None) => {}
                None => wanted.push(nk),
            }
        }
        if let Some(h) = self.prefetch {
            let keys: Vec<[u8; 32]> = wanted.iter().map(&key_of).collect();
            self.hint(table, &keys, h);
        }
        for nk in wanted {
            let tk = key_of(&nk);
            if let Ok(Some(v)) = self.fetch(table, &tk) {
                nodes.map.insert(nk, v);
            }
        }
        let outcome = loop {
            let w = walk(root, path, &nodes);
            cost.nodes = w.nodes;
            match w.outcome {
                Outcome::Present(v) => break Read::Verified(v),
                Outcome::Absent(by) => break Read::VerifiedAbsent(by),
                Outcome::Invalid(nk, what) => {
                    break Read::Insufficient(Reason::Invalid {
                        table,
                        key: key_of(&nk),
                        what,
                    })
                }
                Outcome::Missing(nk) => {
                    if cost.repairs >= MAX_REPAIRS {
                        break Read::Insufficient(Reason::Budget);
                    }
                    cost.repairs += 1;
                    cost.rounds += 1;
                    let tk = key_of(&nk);
                    match self.fetch(table, &tk) {
                        Ok(Some(v)) => {
                            nodes.map.insert(nk, v);
                        }
                        Ok(None) => break Read::Insufficient(Reason::Missing { table, key: tk }),
                        Err(r) => break Read::Insufficient(r),
                    }
                }
            }
        };
        if cache && self.top_levels > 0 && !outcome.is_insufficient() {
            self.top_keep(path, &nodes, max_depth);
        }
        let (r1, b1) = self.requests_so_far();
        cost.requests = r1 - r0;
        cost.bytes = b1 - b0;
        (outcome, cost)
    }

    /// The account under `hashed = keccak(address)`.
    pub fn account(&mut self, hashed: &B256) -> (Read<Account>, Cost) {
        let path = path_of(hashed);
        let d = self.d_account;
        let (r, cost) = self.walk_table(
            TABLE_ACCOUNT_NODES,
            self.state_root(),
            &path,
            |nk| nk.table_key().expect("walk depth ≤ 62"),
            d,
            true,
        );
        let r = match r {
            Read::Verified(v) => match Account::decode(&v) {
                Ok(a) => Read::Verified(a),
                Err(_) => Read::Insufficient(Reason::Value("account leaf")),
            },
            Read::VerifiedAbsent(b) => Read::VerifiedAbsent(b),
            Read::Insufficient(r) => Read::Insufficient(r),
        };
        (r, cost)
    }

    /// Storage slot `hashed_slot = keccak(slot)` of the account under
    /// `hashed`. The account walk comes first; an account that is absent or
    /// has the empty root answers without a storage fetch.
    pub fn storage(&mut self, hashed: &B256, hashed_slot: &B256) -> (Read<U256>, Cost) {
        let (acct, mut cost) = self.account(hashed);
        let acct = match acct {
            Read::Verified(a) => a,
            Read::VerifiedAbsent(b) => return (Read::VerifiedAbsent(b), cost),
            Read::Insufficient(r) => return (Read::Insufficient(r), cost),
        };
        let (r, c) = self.storage_of(&acct, hashed, hashed_slot);
        // The account's speculative round and the storage's are one round
        // in profile §2; count them so.
        cost.add(Cost {
            rounds: c.rounds.saturating_sub(1),
            ..c
        });
        (r, cost)
    }

    /// Storage of an account the caller has already verified.
    pub fn storage_of(
        &mut self,
        account: &Account,
        hashed: &B256,
        hashed_slot: &B256,
    ) -> (Read<U256>, Cost) {
        let path = path_of(hashed_slot);
        let owner = *hashed;
        let d = self.d_storage;
        let (r, cost) = self.walk_table(
            TABLE_STORAGE_NODES,
            account.storage_root,
            &path,
            |nk| nk.storage_table_key(&owner).expect("walk depth ≤ 62"),
            d,
            false,
        );
        let r = match r {
            Read::Verified(v) => match decode_word(&v) {
                Ok(w) => Read::Verified(w),
                Err(_) => Read::Insufficient(Reason::Value("storage leaf")),
            },
            Read::VerifiedAbsent(b) => Read::VerifiedAbsent(b),
            Read::Insufficient(r) => Read::Insufficient(r),
        };
        (r, cost)
    }

    /// Bytecode under a `codeHash` the caller verified. `KECCAK_EMPTY` is
    /// empty code with no fetch.
    pub fn code(&mut self, code_hash: &B256) -> (Read<Vec<u8>>, Cost) {
        self.begin_read();
        let mut cost = Cost::default();
        if *code_hash == KECCAK_EMPTY {
            return (Read::Verified(Vec::new()), cost);
        }
        let (r0, b0) = self.requests_so_far();
        cost.rounds = 1;
        let Some(reader) = self.tables[TABLE_CODE as usize].as_mut() else {
            return (Read::Insufficient(Reason::NoTable(TABLE_CODE)), cost);
        };
        let entry = match reader.get_entry(&code_hash.0) {
            Ok((e, _)) => e,
            Err(e) => {
                return (
                    Read::Insufficient(Reason::Run {
                        table: TABLE_CODE,
                        error: e.to_string(),
                    }),
                    cost,
                )
            }
        };
        let bytes = match entry {
            None => {
                return (
                    Read::Insufficient(Reason::Missing {
                        table: TABLE_CODE,
                        key: code_hash.0,
                    }),
                    cost,
                )
            }
            Some(e) if e.tag == 0 => e.value,
            Some(e) if e.tag == 2 => {
                cost.rounds = 2;
                let h: [u8; 32] = e.value.as_slice().try_into().expect("tag 2 is 32 bytes");
                match self.bucket.read_file(&blob_path(&h)) {
                    Ok(b) if *blake3::hash(&b).as_bytes() == h => {
                        cost.requests += 1;
                        cost.bytes += b.len() as u64;
                        b
                    }
                    Ok(_) => {
                        return (
                            Read::Insufficient(Reason::Blob(
                                "blob does not hash to its name".into(),
                            )),
                            cost,
                        )
                    }
                    Err(e) => return (Read::Insufficient(Reason::Blob(e)), cost),
                }
            }
            Some(_) => {
                return (
                    Read::Insufficient(Reason::Code("tombstone in the code table")),
                    cost,
                )
            }
        };
        let (r1, b1) = self.requests_so_far();
        cost.requests += r1 - r0;
        cost.bytes += b1 - b0;
        if keccak256(&bytes) != *code_hash {
            return (
                Read::Insufficient(Reason::Code("bytecode does not hash to codeHash")),
                cost,
            );
        }
        (Read::Verified(bytes), cost)
    }
}

/// Nodes fetched so far, by position.
struct Nodes<'a, F: Fn(&NodeKey) -> [u8; 32]> {
    map: HashMap<NodeKey, Vec<u8>>,
    #[allow(dead_code)]
    key_of: &'a F,
}

impl<F: Fn(&NodeKey) -> [u8; 32]> NodeSource for Nodes<'_, F> {
    fn node(&self, key: &NodeKey) -> Option<&[u8]> {
        self.map.get(key).map(Vec::as_slice)
    }
}
