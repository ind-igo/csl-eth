//! The healer (`csl-eth heal`): keeps a bucket's state current with no node
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
    blob_path, manifest_path, merge_layers, run_path, write_layer, write_layered_manifest, Head,
    Layer, LayerRows, Manifest, CODE_BLOB_THRESHOLD, EPSILON, LATEST_FILE, RUN_FORMAT,
    TABLE_ACCOUNT_NODES, TABLE_CODE, TABLE_STORAGE_NODES,
};
use csl_eth_trie::{decode_word, Account, Nibbles, NodeKey, EMPTY_ROOT, KECCAK_EMPTY};
use csl_run::Reader;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{info, warn};

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
        let mut runs: [Vec<Reader<File>>; 3] = Default::default();
        for t in [TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES, TABLE_CODE] {
            for at in manifest.runs(t).into_iter().rev() {
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

/// Nodes fetched and not yet in a layer, by hash: what a re-pivot keeps.
#[derive(Default)]
pub struct Cache {
    map: HashMap<B256, Bytes>,
    bytes: usize,
    pub cap: usize,
}

impl Cache {
    pub fn new(cap: usize) -> Cache {
        Cache {
            cap,
            ..Cache::default()
        }
    }
    fn get(&self, h: &B256) -> Option<&Bytes> {
        self.map.get(h)
    }
    /// Keep `b` under `h` unless the cache is full; it is checked by hash
    /// on the way in, so a cached node is always the node of its hash.
    fn put(&mut self, h: B256, b: Bytes) {
        if self.bytes + b.len() > self.cap || keccak256(&b) != h {
            return;
        }
        self.bytes += b.len();
        self.map.insert(h, b);
    }
    pub fn clear(&mut self) {
        self.map.clear();
        self.bytes = 0;
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

// ---------------------------------------------------------------------------
// One step

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
    /// Nodes found in the cache (fetched by an attempt that re-pivoted).
    pub cached: u64,
    /// Old nodes the local store did not have: the subtree was fetched
    /// whole instead (more bytes, same result).
    pub old_missing: u64,
    pub accounts_changed: u64,
    pub storage_tries: u64,
    /// Waves of requests: dependent round trips.
    pub levels: u32,
    pub local_lookups: u64,
}

/// A complete step: the layer's rows, and the keys to read back.
pub struct Healed {
    pub rows: LayerRows,
    /// Changed accounts with their new values.
    pub accounts: Vec<(B256, Account)>,
    /// Changed slots seen: (owner, slot, value), up to the sample size.
    pub slots: Vec<(B256, B256, U256)>,
    pub stats: StepStats,
}

#[derive(Debug)]
pub enum StepError {
    /// Nodes or code no peer served.
    Unresolved { nodes: usize, codes: usize },
    /// Past the deadline (the root is about to leave the peers' window).
    Deadline,
    /// The local store could not be read.
    Store(String),
    /// A node too deep for a table key.
    TooDeep,
}

impl std::fmt::Display for StepError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepError::Unresolved { nodes, codes } => {
                write!(f, "{nodes} nodes and {codes} codes no peer served")
            }
            StepError::Deadline => write!(f, "deadline"),
            StepError::Store(e) => write!(f, "local store: {e}"),
            StepError::TooDeep => write!(f, "a node too deep for a table key"),
        }
    }
}

#[derive(Clone, Debug)]
struct Pair {
    owner: Option<B256>,
    path: Nibbles,
    new: Ref,
    old: Option<Ref>,
    tries: u8,
}

/// Paths of the account trie inside a slice base's prefix, or on the way
/// to it; every path when there is no prefix.
fn compatible(prefix: Option<&Nibbles>, owner: &Option<B256>, path: &Nibbles) -> bool {
    match (prefix, owner) {
        (Some(p), None) => path.starts_with(p) || p.starts_with(path),
        _ => true,
    }
}

fn storage_pair(owner: B256, new: &Account, old: Option<&Account>) -> Option<Pair> {
    let old_root = old.map(|a| a.storage_root).unwrap_or(EMPTY_ROOT);
    if new.storage_root == EMPTY_ROOT || new.storage_root == old_root {
        return None;
    }
    let old = (old_root != EMPTY_ROOT).then_some(Ref::Hash(old_root));
    Some(Pair {
        owner: Some(owner),
        path: Nibbles::default(),
        new: Ref::Hash(new.storage_root),
        old,
        tries: 0,
    })
}

/// The account under `key` in the trie at `root`, walked through the local
/// store; none when absent or when the store lacks a node on the way (the
/// caller then treats the account as new, which fetches more, never less).
fn old_account(store: &mut Store, root: B256, key: &Nibbles) -> Result<Option<Account>, String> {
    let mut path = Nibbles::default();
    let mut at = Ref::Hash(root);
    loop {
        let rlp = match &at {
            Ref::Inline(b) => b.clone(),
            Ref::Hash(h) => match store.node(None, &path, h)? {
                Some(b) => b,
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

/// Heal from the state at `old_root` (in `store`) to `new_root` (from
/// `src`), level by level. Returns the step's layer rows when every
/// reference resolved.
#[allow(clippy::too_many_arguments)]
pub async fn heal_step<S: Source>(
    src: &mut S,
    store: &mut Store,
    cache: &mut Cache,
    old_root: B256,
    new_root: B256,
    prefix: Option<&Nibbles>,
    slot_sample: usize,
    deadline: Instant,
) -> Result<Healed, StepError> {
    const MAX_TRIES: u8 = 4;
    let lookups0 = store.lookups;
    let mut st = StepStats::default();
    let mut rows = LayerRows::default();
    let mut accounts = Vec::new();
    let mut slots = Vec::new();
    let mut want_code: BTreeSet<B256> = BTreeSet::new();
    let mut frontier = vec![Pair {
        owner: None,
        path: Nibbles::default(),
        new: Ref::Hash(new_root),
        old: Some(Ref::Hash(old_root)),
        tries: 0,
    }];
    let store_err = StepError::Store;
    while !frontier.is_empty() {
        if Instant::now() > deadline {
            return Err(StepError::Deadline);
        }
        st.levels += 1;
        frontier.retain(|p| p.old.as_ref() != Some(&p.new));
        let mut needs = Vec::new();
        let mut asked: HashSet<B256> = HashSet::new();
        let mut wave: HashMap<B256, Bytes> = HashMap::new();
        for p in &frontier {
            if let Ref::Hash(h) = p.new {
                if cache.get(&h).is_none() && asked.insert(h) {
                    needs.push(Need {
                        owner: p.owner,
                        path: p.path,
                        hash: h,
                    });
                }
            }
        }
        if !needs.is_empty() {
            st.asked += needs.len() as u64;
            let got = src.nodes(new_root, &needs, deadline).await;
            for (i, b) in got {
                // Checked by hash here, so a full cache never costs a node
                // a peer served; the cache only decides what outlives a
                // re-pivot.
                if keccak256(&b) == needs[i].hash {
                    st.fetched += 1;
                    cache.put(needs[i].hash, b.clone());
                    wave.insert(needs[i].hash, b);
                }
            }
        }
        let mut next = Vec::new();
        let mut unresolved = 0usize;
        for mut p in std::mem::take(&mut frontier) {
            let new_rlp = match &p.new {
                Ref::Inline(b) => b.clone(),
                Ref::Hash(h) => match wave.get(h).or_else(|| cache.get(h)) {
                    Some(b) => {
                        if !asked.contains(h) {
                            st.cached += 1;
                        }
                        b.clone()
                    }
                    None => {
                        p.tries += 1;
                        if p.tries >= MAX_TRIES {
                            unresolved += 1;
                        } else {
                            next.push(p);
                        }
                        continue;
                    }
                },
            };
            if let Ref::Hash(_) = p.new {
                let nk = NodeKey::prefix(&p.path, p.path.len());
                match p.owner {
                    None => {
                        let k = nk.table_key().map_err(|_| StepError::TooDeep)?;
                        st.account_nodes += 1;
                        st.node_bytes += new_rlp.len() as u64;
                        rows.account.insert(k, new_rlp.to_vec());
                    }
                    Some(o) => {
                        let k = nk.storage_table_key(&o).map_err(|_| StepError::TooDeep)?;
                        st.storage_nodes += 1;
                        st.node_bytes += new_rlp.len() as u64;
                        rows.storage.insert(k, new_rlp.to_vec());
                    }
                }
            }
            let old_rlp: Option<Bytes> = match &p.old {
                None => None,
                Some(Ref::Inline(b)) => Some(b.clone()),
                Some(Ref::Hash(h)) => {
                    let b = store.node(p.owner, &p.path, h).map_err(store_err)?;
                    if b.is_none() {
                        st.old_missing += 1;
                    }
                    b
                }
            };
            let Ok(new_shape) = shape(&p.path, &new_rlp) else {
                continue;
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
                        if !compatible(prefix, &p.owner, &q) {
                            continue;
                        }
                        let o = old_kids.get(&q).cloned();
                        if o.as_ref() == Some(&r) {
                            continue;
                        }
                        next.push(Pair {
                            owner: p.owner,
                            path: q,
                            new: r,
                            old: o,
                            tries: 0,
                        });
                    }
                }
                Shape::Leaf { key, value } => {
                    if key.len() != 64 {
                        continue;
                    }
                    let hash = B256::from_slice(&key.pack());
                    if let Some(owner) = p.owner {
                        if slots.len() < slot_sample {
                            if let Ok(v) = decode_word(&value) {
                                slots.push((owner, hash, v));
                            }
                        }
                        continue;
                    }
                    let Ok(acct) = Account::decode(&value) else {
                        continue;
                    };
                    st.accounts_changed += 1;
                    let old = match &old_shape {
                        Some(Shape::Leaf { key: ok, value: ov }) if *ok == key => {
                            Account::decode(ov).ok()
                        }
                        _ => old_account(store, old_root, &key).map_err(store_err)?,
                    };
                    if let Some(pair) = storage_pair(hash, &acct, old.as_ref()) {
                        st.storage_tries += 1;
                        next.push(pair);
                    }
                    if acct.code_hash != KECCAK_EMPTY
                        && old.map(|a| a.code_hash) != Some(acct.code_hash)
                        && !rows.code.contains_key(&acct.code_hash.0)
                        && !store.has_code(&acct.code_hash).map_err(store_err)?
                    {
                        want_code.insert(acct.code_hash);
                    }
                    accounts.push((hash, acct));
                }
            }
        }
        if unresolved > 0 {
            return Err(StepError::Unresolved {
                nodes: unresolved,
                codes: 0,
            });
        }
        frontier = next;
    }
    // New code, a few tries.
    let mut left: Vec<B256> = want_code.into_iter().collect();
    for _ in 0..3 {
        if left.is_empty() {
            break;
        }
        let got = src.codes(&left, deadline).await;
        for (h, c) in got {
            if keccak256(&c) == h {
                st.codes += 1;
                st.code_bytes += c.len() as u64;
                rows.code.insert(h.0, c.to_vec());
            }
        }
        left.retain(|h| !rows.code.contains_key(&h.0));
    }
    if !left.is_empty() {
        return Err(StepError::Unresolved {
            nodes: 0,
            codes: left.len(),
        });
    }
    st.local_lookups = store.lookups - lookups0;
    Ok(Healed {
        rows,
        accounts,
        slots,
        stats: st,
    })
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
    optimistic: &'a [u8],
}

impl HeadSource for Overlay<'_> {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        if rel == paths::OPTIMISTIC {
            return Ok(Some(self.optimistic.to_vec()));
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

    /// The newest attested head, verified from the checkpoint over the
    /// mirror's files: the optimistic update's bytes and what they prove.
    pub fn latest(&self) -> Result<(Vec<u8>, VerifiedHead), String> {
        let first = self.bootstrap_period()?;
        let upd = self.beacon.head_update(Tier::Attested)?;
        let named = named_of(Tier::Attested, &upd)?;
        let current = csl_eth_head::period_of(named.signature_slot);
        self.updates(first, current, false)?;
        let verify = || {
            verify_tier(
                &Overlay {
                    dir: &self.root,
                    optimistic: &upd,
                },
                &self.chain,
                self.checkpoint,
                SystemTime::now(),
                Tier::Attested,
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
    /// base's `snapshots/<hash>/` tables, and the healer's `runs/`,
    /// `blobs/`, `head/` and manifests, laid out as published.
    #[arg(long)]
    pub root: PathBuf,
    /// The healer's state (`heal.json`) and log (`heal.jsonl`,
    /// `peers.jsonl`).
    #[arg(long)]
    pub work: PathBuf,
    /// The base snapshot's block hash under `root` (a plain snapshot).
    /// Only on the first run; `heal.json` remembers it.
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
    /// The top tier (one layer, everything since the base).
    #[arg(long, default_value_t = 5)]
    pub tiers: u8,
    /// Manifests kept published; runs only they reach are collected.
    #[arg(long, default_value_t = 64)]
    pub keep: usize,
    /// Heal only when the head is at least this many blocks past ours.
    #[arg(long, default_value_t = 1)]
    pub every_blocks: u64,
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
    /// Bytes of fetched nodes kept across a re-pivot.
    #[arg(long, default_value_t = 2048)]
    pub cache_mib: usize,
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
struct HealState {
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
}

impl HealState {
    fn load(p: &Path) -> Result<Option<HealState>, String> {
        match fs::read(p) {
            Ok(b) => serde_json::from_slice(&b)
                .map(Some)
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

fn manifest_runs(m: &Manifest) -> Vec<String> {
    m.layers
        .iter()
        .flat_map(|l| l.tables.iter().map(|t| hex::encode(t.root)))
        .collect()
}

/// Read back what a step changed, through the client over the local files
/// at the new root: every changed account, the sampled slots, new code.
fn read_back(root: &Path, head: &Head, h: &Healed) -> Result<Value, String> {
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

struct Healer {
    args: Args,
    root: PathBuf,
    state_path: PathBuf,
    st: HealState,
    base: Manifest,
    prefix: Option<Nibbles>,
    store: Store,
    publish: Box<dyn Publish>,
    log: Log,
}

impl Healer {
    fn manifest(&self, head: &Head) -> Result<Manifest, String> {
        write_layered_manifest(
            &self.root,
            head,
            &self.base,
            self.st.layers.iter().map(|l| l.layer.clone()).collect(),
            true,
        )
        .map_err(|e| format!("manifest: {e}"))
    }

    /// Write the step's layer, merge tiers, write the manifest, read the
    /// changes back through the client, publish, collect, save.
    fn commit(&mut self, h: &Healed, update: &[u8], vh: &VerifiedHead) -> Result<Value, String> {
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
            let layer = write_layer(
                &self.root,
                self.st.head.block_number,
                head.block_number,
                &h.rows,
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
        let manifest = self.manifest(&head)?;
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
        let sent = self.publish_step(&head, &manifest, h, update)?;
        self.st.head = HeadRec {
            block_hash: head.block_hash,
            block_number: head.block_number,
            timestamp: head.timestamp,
            state_root: head.state_root,
        };
        self.st.steps += 1;
        let collected = self.collect(&manifest)?;
        self.st.save(&self.state_path)?;
        self.store = Store::open(&self.root, &manifest)?;
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
        h: &Healed,
        update: &[u8],
    ) -> Result<Value, String> {
        let mut sent = (0u64, 0u64);
        for r in manifest_runs(m) {
            if !self.st.published_runs.contains(&r) {
                let mut root = [0u8; 32];
                hex::decode_to_slice(&r, &mut root).map_err(|e| e.to_string())?;
                self.put(&run_path(&root), &mut sent)?;
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
        let cp = paths::bootstrap(&self.args.checkpoint);
        if !self.st.bootstrap_published {
            self.put(&cp, &mut sent)?;
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
                    self.put(&paths::update(p), &mut sent)?;
                    self.st.published_updates.insert(p, hx);
                }
            }
        }
        write_atomic(&self.root.join(paths::OPTIMISTIC), update)?;
        self.put(paths::OPTIMISTIC, &mut sent)?;
        self.put(LATEST_FILE, &mut sent)?;
        self.st
            .manifests
            .push_back((head.block_hash, manifest_runs(m)));
        Ok(json!({"files": sent.0, "bytes": sent.1}))
    }

    /// Manifests past `keep`, and runs no kept manifest reaches, deleted
    /// from the bucket and the local copy.
    fn collect(&mut self, current: &Manifest) -> Result<Value, String> {
        let mut gone_manifests = 0;
        while self.st.manifests.len() > self.args.keep.max(2) {
            let (h, _) = self.st.manifests.pop_front().expect("len");
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
            let mut root = [0u8; 32];
            hex::decode_to_slice(r, &mut root).map_err(|e| e.to_string())?;
            self.publish.delete(&self.key(&run_path(&root)))?;
            let _ = fs::remove_file(self.root.join(run_path(&root)));
            self.st.published_runs.remove(r);
        }
        // Runs merged away before they were ever published.
        let known: HashSet<String> = self.st.published_runs.iter().cloned().chain(cur).collect();
        let mut local = 0;
        if let Ok(rd) = fs::read_dir(self.root.join("runs")) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_string();
                if let Some(hx) = n.strip_suffix(".run") {
                    if !known.contains(hx) {
                        let _ = fs::remove_file(e.path());
                        local += 1;
                    }
                }
            }
        }
        Ok(json!({"manifests": gone_manifests, "runs": dead.len(), "unpublished_runs": local}))
    }
}

pub async fn run(args: Args) -> Result<(), String> {
    let started = Instant::now();
    fs::create_dir_all(&args.work).map_err(|e| e.to_string())?;
    let state_path = args.work.join("heal.json");
    let root = args.root.clone();
    let st = match HealState::load(&state_path)? {
        Some(st) => {
            if args.base.is_some_and(|b| b != st.base) {
                return Err(format!(
                    "heal.json is for base {}, not {}",
                    st.base,
                    args.base.unwrap()
                ));
            }
            st
        }
        None => {
            let base = args
                .base
                .ok_or("no heal.json yet: name the base with --base")?;
            let m = Manifest::from_json(
                &fs::read(root.join(manifest_path(&base)))
                    .map_err(|e| format!("base manifest: {e}"))?,
            )
            .map_err(|e| e.to_string())?;
            HealState {
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
        .open(args.work.join("heal.jsonl"))
        .map_err(|e| e.to_string())?);
    let head = st.head.head();
    let store = {
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
        Store::open(&root, &m)?
    };
    let mut h = Healer {
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
    let mut cache = Cache::new(args.cache_mib << 20);
    let over = |s: u64| {
        (args.steps > 0 && s >= args.steps)
            || (args.max_wall_mins > 0
                && started.elapsed() > Duration::from_secs(args.max_wall_mins * 60))
    };
    let mut attempt = 0u64;
    while !over(h.st.steps) {
        let (update, vh) = match tokio::task::block_in_place(|| heads.latest()) {
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
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let window = (target.timestamp + 110 * 12).saturating_sub(now).max(60);
        let deadline = Instant::now() + Duration::from_secs(window);
        let t0 = Instant::now();
        let from = h.st.head.block_number;
        let cached_before = cache.len();
        let r = heal_step(
            &mut pool,
            &mut h.store,
            &mut cache,
            h.st.head.state_root,
            target.state_root,
            h.prefix.as_ref(),
            args.verify_slots,
            deadline,
        )
        .await;
        let heal_s = t0.elapsed().as_secs_f64();
        let lag = |t: u64| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0)
                - t as f64
        };
        match r {
            Err(e) => {
                warn!(from, to = target.block_number, error = %e, cached = cache.len(), "step failed; re-pivoting");
                h.log.emit(json!({
                    "ev": "repivot", "attempt": attempt, "from": from, "to": target.block_number, "error": e.to_string(),
                    "heal_s": heal_s, "cached": cache.len(), "cached_before": cached_before, "peers": pool.connected(),
                }));
                if let StepError::Store(_) | StepError::TooDeep = e {
                    return Err(e.to_string());
                }
            }
            Ok(healed) => {
                let res = tokio::task::block_in_place(|| h.commit(&healed, &update, &vh));
                cache.clear();
                match res {
                    Ok(v) => {
                        info!(
                            from,
                            to = target.block_number,
                            blocks = target.block_number - from,
                            nodes = healed.stats.account_nodes + healed.stats.storage_nodes,
                            mib = healed.stats.node_bytes as f64 / 1048576.0,
                            heal_s,
                            lag_s = lag(target.timestamp),
                            peers = pool.connected(),
                            "step"
                        );
                        h.log.emit(json!({
                            "ev": "step", "step": h.st.steps, "attempt": attempt, "from": from, "to": target.block_number,
                            "blocks": target.block_number - from, "block_hash": target.block_hash, "state_root": target.state_root,
                            "heal_s": heal_s, "lag_s": lag(target.timestamp), "peers": pool.connected(),
                            "head_lag_s": vh.lag_secs, "participants": vh.participants, "stats": healed.stats, "commit": v,
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
    }

    impl Mem {
        fn of(s: &State, h: &Head) -> Mem {
            let r = rows(s, h);
            Mem {
                acct: r.account.into_iter().collect(),
                stor: r.storage.into_iter().collect(),
                code: code_of(s),
                budget: usize::MAX,
            }
        }
    }

    impl Source for Mem {
        async fn nodes(&mut self, _: B256, needs: &[Need], _: Instant) -> HashMap<usize, Bytes> {
            let mut out = HashMap::new();
            for (i, n) in needs.iter().enumerate() {
                if self.budget == 0 {
                    break;
                }
                let nk = NodeKey::prefix(&n.path, n.path.len());
                let b = match n.owner {
                    None => self.acct.get(&nk.table_key().unwrap()),
                    Some(o) => self.stor.get(&nk.storage_table_key(&o).unwrap()),
                };
                if let Some(b) = b.filter(|b| keccak256(b) == n.hash) {
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
            "csl-eth-healer-{}-{}-{name}",
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

    /// One healed step committed as the healer does, minus heads and
    /// publishing.
    fn commit(
        dir: &Path,
        base: &Manifest,
        layers: &mut Vec<Tiered>,
        from: &Head,
        to: &Head,
        h: &Healed,
        fanout: usize,
        top: u8,
    ) -> Store {
        if !h.rows.is_empty() {
            layers.push(Tiered {
                layer: write_layer(dir, from.block_number, to.block_number, &h.rows, EPSILON)
                    .unwrap(),
                tier: 0,
            });
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
        Store::open(dir, &m).unwrap()
    }

    #[tokio::test]
    async fn heals_step_by_step_and_across_a_gap() {
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
        let mut layers = Vec::new();
        let mut cache = Cache::new(1 << 30);
        let all: Vec<B256> = s.iter().flat_map(|x| x.keys().copied()).collect();
        for i in 1..s.len() {
            let mut src = Mem::of(&s[i], &heads[i]);
            let h = heal_step(
                &mut src,
                &mut store,
                &mut cache,
                heads[i - 1].state_root,
                heads[i].state_root,
                None,
                10_000,
                far(),
            )
            .await
            .unwrap();
            // Everything a diff of the full rows says changed, and nothing
            // that is not the new state's.
            let want = LayerRows::diff(&rows(&s[i - 1], &heads[i - 1]), &rows(&s[i], &heads[i]));
            let r = rows(&s[i], &heads[i]);
            let acct: HashMap<_, _> = r.account.iter().cloned().collect();
            let stor: HashMap<_, _> = r.storage.iter().cloned().collect();
            for (k, v) in &want.account {
                assert_eq!(h.rows.account.get(k), Some(v), "account row missing");
            }
            for (k, v) in &want.storage {
                assert_eq!(h.rows.storage.get(k), Some(v), "storage row missing");
            }
            assert!(h.rows.account.iter().all(|(k, v)| acct.get(k) == Some(v)));
            assert!(h.rows.storage.iter().all(|(k, v)| stor.get(k) == Some(v)));
            assert_eq!(
                h.rows.code.keys().collect::<BTreeSet<_>>(),
                want.code.keys().collect::<BTreeSet<_>>()
            );
            eprintln!("step {i}: {:?}", h.stats);
            cache.clear();
            store = commit(&dir, &base, &mut layers, &heads[i - 1], &heads[i], &h, 4, 3);
            reads_as(&dir, &s[i], &all, &heads[i]);
        }
        // S0 straight to S2 from the base alone: a gap is a bigger diff.
        let gap = scratch("gap");
        let base2 = produce(&gap, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&gap, &base2).unwrap();
        let mut src = Mem::of(&s[2], &heads[2]);
        let h = heal_step(
            &mut src,
            &mut store,
            &mut cache,
            heads[0].state_root,
            heads[2].state_root,
            None,
            10_000,
            far(),
        )
        .await
        .unwrap();
        let mut layers = Vec::new();
        commit(&gap, &base2, &mut layers, &heads[0], &heads[2], &h, 4, 3);
        reads_as(&gap, &s[2], &all, &heads[2]);
        fs::remove_dir_all(&dir).ok();
        fs::remove_dir_all(&gap).ok();
    }

    #[tokio::test]
    async fn a_step_heals_with_no_cache() {
        let s = states();
        let heads: Vec<Head> = s
            .iter()
            .enumerate()
            .map(|(i, x)| head_of(x, i as u64))
            .collect();
        let dir = scratch("nocache");
        let base = produce(&dir, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&dir, &base).unwrap();
        let mut cache = Cache::new(0);
        let mut src = Mem::of(&s[1], &heads[1]);
        let h = heal_step(
            &mut src,
            &mut store,
            &mut cache,
            heads[0].state_root,
            heads[1].state_root,
            None,
            100,
            far(),
        )
        .await
        .unwrap();
        assert!(cache.is_empty());
        let mut layers = Vec::new();
        commit(&dir, &base, &mut layers, &heads[0], &heads[1], &h, 4, 3);
        reads_as(&dir, &s[1], &[], &heads[1]);
        fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_repivot_keeps_what_was_fetched() {
        let s = states();
        let heads: Vec<Head> = s
            .iter()
            .enumerate()
            .map(|(i, x)| head_of(x, i as u64))
            .collect();
        let dir = scratch("repivot");
        let base = produce(&dir, &heads[0], "", leaves(&s[0]), &code_of(&s[0]))
            .unwrap()
            .manifest;
        let mut store = Store::open(&dir, &base).unwrap();
        let mut cache = Cache::new(1 << 30);
        // S1's root leaves the window after 60 nodes.
        let mut src = Mem::of(&s[1], &heads[1]);
        src.budget = 60;
        let e = heal_step(
            &mut src,
            &mut store,
            &mut cache,
            heads[0].state_root,
            heads[1].state_root,
            None,
            100,
            far(),
        )
        .await;
        assert!(
            matches!(e, Err(StepError::Unresolved { .. })),
            "{:?}",
            e.as_ref().err()
        );
        assert_eq!(cache.len(), 60);
        // Re-pivot to S2: nodes S1 and S2 share come from the cache.
        let mut src = Mem::of(&s[2], &heads[2]);
        let h = heal_step(
            &mut src,
            &mut store,
            &mut cache,
            heads[0].state_root,
            heads[2].state_root,
            None,
            100,
            far(),
        )
        .await
        .unwrap();
        assert!(h.stats.cached > 0, "{:?}", h.stats);
        let mut layers = Vec::new();
        commit(&dir, &base, &mut layers, &heads[0], &heads[2], &h, 4, 3);
        reads_as(&dir, &s[2], &[], &heads[2]);
        fs::remove_dir_all(&dir).ok();
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
        let mut layers: Vec<Tiered> = Vec::new();
        let mut cache = Cache::new(1 << 30);
        let (mut s, mut h) = (s0, h0);
        let mut max_layers = 0;
        for n in 1..=20u64 {
            let next = churn(&s, &mut rng);
            let hn = head_of(&next, n);
            let mut src = Mem::of(&next, &hn);
            let healed = heal_step(
                &mut src,
                &mut store,
                &mut cache,
                h.state_root,
                hn.state_root,
                None,
                10_000,
                far(),
            )
            .await
            .unwrap();
            cache.clear();
            store = commit(&dir, &base, &mut layers, &h, &hn, &healed, 2, 3);
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

/// A healed directory against the slice its base was built from:
/// `CSL_HEAL_SLICE=<slice> CSL_HEAL_DIR=<published dir> cargo test
/// --release -p csl-eth-snap --lib healed_dir_is_complete -- --ignored
/// --nocapture`. Every account, slot and code of the slice must read at
/// the published head as verified or proven absent; none insufficient.
#[cfg(test)]
mod mainnet {
    use super::*;
    use crate::slice::Slice;

    #[test]
    #[ignore]
    fn healed_dir_is_complete() {
        let (Ok(s), Ok(d)) = (
            std::env::var("CSL_HEAL_SLICE"),
            std::env::var("CSL_HEAL_DIR"),
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
