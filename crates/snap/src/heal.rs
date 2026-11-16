//! The healing probe (`csl-eth heal-probe`): can a stateless process keep a
//! path-keyed copy of mainnet state current by asking peers for trie nodes?
//! (`docs/delta-producer.md`, "heal".)
//!
//! Every cycle it takes a recent block's state root from peers' headers and
//! diffs the trie at that root against the previous cycle's root, over
//! snap/1 `GetTrieNodes` only: from the root down, a node whose hash at a
//! path differs from the old trie's node at that path is fetched at the new
//! root (that is the healer's download) and its old counterpart at the old
//! root (which a real healer has on disk; the probe has nothing). Children
//! whose hash at the same path is unchanged are not visited. Changed
//! accounts lead into their storage tries the same way. The diff counts
//! what a path-keyed store would rewrite: hashed nodes whose (trie, path,
//! hash) is new. Inline nodes live inside their parent and are counted
//! apart.
//!
//! Each cycle also asks every connected peer for the root node of headers
//! at fixed ages behind the head, to measure how far back a root stays
//! servable.
//!
//! Output: JSON lines (`ev`: `peer_up`, `peer_down`, `dials`, `req`,
//! `age`, `cycle`, `note`) to `out`; `scripts/heal-probe-summary.py`
//! reduces them.

use crate::{
    discovery,
    peer::{self, Peer, PeerError},
};
use alloy_consensus::Header;
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_trie::nodes::{encode_path_leaf, RlpNode, TrieNode};
use csl_eth_trie::{Account, Nibbles, EMPTY_ROOT};
use futures::{stream::FuturesUnordered, StreamExt};
use reth_network_peers::PeerId;
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

#[derive(Clone, Debug)]
pub struct Config {
    /// Connected peers to hold.
    pub peers: usize,
    pub dial_parallel: usize,
    pub udp_port: u16,
    pub dial_timeout: Duration,
    /// Per request.
    pub timeout: Duration,
    /// Start a cycle this often (one epoch: 384 s).
    pub every: Duration,
    /// Diff to the block this far behind the estimated head.
    pub confirm: u64,
    /// Stop after this many cycles (0: never) or this long (zero: never).
    pub cycles: usize,
    pub max_wall: Duration,
    /// Paths per `GetTrieNodes`.
    pub batch: usize,
    /// Response byte limit asked for.
    pub bytes: u64,
    /// Restrict the account-trie diff to this path prefix (storage tries
    /// of the accounts under it are diffed whole). None: all of it.
    pub prefix: Option<Nibbles>,
    /// Header ages, in blocks behind the head, whose roots each peer is
    /// asked for.
    pub ages: Vec<u64>,
    /// Give up on a cycle's diff after this long.
    pub max_cycle: Duration,
    pub out: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            peers: 12,
            dial_parallel: 24,
            udp_port: 30303,
            dial_timeout: Duration::from_secs(8),
            timeout: Duration::from_secs(15),
            every: Duration::from_secs(384),
            confirm: 2,
            cycles: 0,
            max_wall: Duration::ZERO,
            batch: 384,
            bytes: 2 * 1024 * 1024,
            prefix: None,
            ages: vec![0, 16, 32, 64, 96, 112, 120, 124, 127, 128, 129, 132, 160, 192, 256, 512, 1024],
            max_cycle: Duration::from_secs(1200),
            out: PathBuf::from("heal-probe.jsonl"),
        }
    }
}

/// One JSON line per event, each stamped with the unix time.
#[derive(Clone)]
struct Log(Arc<Mutex<BufWriter<File>>>);

impl Log {
    fn emit(&self, mut v: Value) {
        v["t"] = json!(unix_f64());
        let mut w = self.0.lock().expect("log lock");
        let _ = serde_json::to_writer(&mut *w, &v);
        let _ = w.write_all(b"\n");
        let _ = w.flush();
    }
}

fn unix_f64() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs_f64()).unwrap_or(0.0)
}

/// A trie node wanted: in the account trie (`owner` none) or the storage
/// trie of account hash `owner`, at `path`, hashing to `hash`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Need {
    pub owner: Option<B256>,
    pub path: Nibbles,
    pub hash: B256,
}

/// The `GetTrieNodes` path sets for `needs`: one `[compact(path)]` per
/// account-trie node, one `[owner, compact(path)...]` per storage trie.
pub fn path_sets(needs: &[Need]) -> Vec<Vec<Bytes>> {
    let mut sets: Vec<Vec<Bytes>> = Vec::new();
    let mut by_owner: HashMap<B256, usize> = HashMap::new();
    for n in needs {
        let compact = Bytes::copy_from_slice(&encode_path_leaf(&n.path, false));
        match n.owner {
            None => sets.push(vec![compact]),
            Some(o) => match by_owner.get(&o) {
                Some(&i) => sets[i].push(compact),
                None => {
                    by_owner.insert(o, sets.len());
                    sets.push(vec![Bytes::copy_from_slice(o.as_slice()), compact]);
                }
            },
        }
    }
    sets
}

/// Match a reply to `needs` by hash (positions are not trusted: a peer may
/// skip a set it cannot open). Returns the node for each need it covers,
/// and the count of non-empty nodes that matched nothing.
pub fn match_reply(needs: &[Need], nodes: &[Bytes]) -> (HashMap<usize, Bytes>, usize) {
    let mut want: HashMap<B256, Vec<usize>> = HashMap::new();
    for (i, n) in needs.iter().enumerate() {
        want.entry(n.hash).or_default().push(i);
    }
    let mut got = HashMap::new();
    let mut stray = 0;
    for node in nodes.iter().filter(|n| !n.is_empty()) {
        match want.get(&keccak256(node)) {
            Some(ix) => {
                for &i in ix {
                    got.insert(i, node.clone());
                }
            }
            None => stray += 1,
        }
    }
    (got, stray)
}

// ---------------------------------------------------------------------------
// Peers

enum Job {
    Nodes { root: B256, kind: &'static str, age: i64, needs: Vec<Need>, reply: oneshot::Sender<NodesDone> },
    HeaderAt { number: u64, reply: oneshot::Sender<Option<Header>> },
    Ages { roots: Vec<(u64, B256)>, reply: oneshot::Sender<()> },
}

struct NodesDone {
    got: HashMap<usize, Bytes>,
    failed: bool,
}

#[derive(Clone)]
struct Worker {
    id: PeerId,
    tx: mpsc::Sender<Job>,
}

struct Shared {
    cfg: Config,
    log: Log,
    connected: AtomicUsize,
    /// Best head seen in a peer's status: number and timestamp.
    head_number: AtomicU64,
    head_time: AtomicU64,
    dialed: AtomicUsize,
    accepted: AtomicUsize,
    no_snap: AtomicUsize,
    dial_errors: Mutex<HashMap<String, usize>>,
}

fn error_kind(e: &PeerError) -> String {
    let s = e.to_string();
    s.chars().take(90).collect()
}

async fn worker_task(mut peer: Peer, shared: Arc<Shared>, idle_tx: mpsc::Sender<Worker>) {
    let id = peer.id();
    let client = peer.client.clone();
    let log = shared.log.clone();
    let head = peer.own_head().await.ok().flatten();
    if let Some(h) = head.as_ref().filter(|h| unix_f64() - h.timestamp as f64 <= 300.0) {
        if shared.head_number.fetch_max(h.number, Ordering::Relaxed) < h.number {
            shared.head_time.store(h.timestamp, Ordering::Relaxed);
        }
    }
    log.emit(json!({
        "ev": "peer_up", "peer": id.to_string()[..16], "client": client,
        "addr": peer.record.address.to_string(), "eth": peer.eth_version(),
        "head": head.as_ref().map(|h| h.number), "head_age_s": head.as_ref().map(|h| unix_f64() - h.timestamp as f64),
    }));
    // A peer whose head is old is syncing or stuck: it has no recent state.
    let behind = head.as_ref().is_none_or(|h| unix_f64() - h.timestamp as f64 > 300.0);
    if behind {
        shared.connected.fetch_sub(1, Ordering::Relaxed);
        log.emit(json!({"ev": "peer_down", "peer": id.to_string()[..16], "client": client, "reason": "behind", "served": 0}));
        peer.close().await;
        return;
    }
    let (tx, mut rx) = mpsc::channel::<Job>(1);
    let me = Worker { id, tx };
    let mut served = 0u64;
    let mut empty_streak = 0u32;
    let reason: String = 'life: loop {
        if idle_tx.send(me.clone()).await.is_err() {
            break 'life "shutdown".into();
        }
        let job = loop {
            tokio::select! {
                j = rx.recv() => match j {
                    Some(j) => break j,
                    None => break 'life "shutdown".into(),
                },
                r = peer.idle(Duration::from_secs(5)) => if let Err(e) = r { break 'life error_kind(&e) },
            }
        };
        match job {
            Job::Nodes { root, kind, age, needs, reply } => {
                let t0 = Instant::now();
                let bytes_before = peer.bytes_in;
                let r = peer.trie_nodes(root, path_sets(&needs), shared.cfg.bytes).await;
                let ms = t0.elapsed().as_millis() as u64;
                let wire = peer.bytes_in - bytes_before;
                match r {
                    Ok(nodes) => {
                        let (got, stray) = match_reply(&needs, &nodes);
                        let nonempty = nodes.iter().filter(|n| !n.is_empty()).count();
                        log.emit(json!({
                            "ev": "req", "peer": id.to_string()[..16], "client": client, "kind": kind, "age": age,
                            "asked": needs.len(), "nodes": nodes.len(), "nonempty": nonempty, "matched": got.len(),
                            "stray": stray, "bytes": wire, "ms": ms,
                        }));
                        if got.is_empty() {
                            empty_streak += 1;
                        } else {
                            empty_streak = 0;
                            served += 1;
                        }
                        let _ = reply.send(NodesDone { got, failed: false });
                        // A peer that has answered nothing for many current
                        // roots in a row frees its slot.
                        if empty_streak >= 6 {
                            break 'life "serves nothing".into();
                        }
                    }
                    Err(e) => {
                        log.emit(json!({
                            "ev": "req", "peer": id.to_string()[..16], "client": client, "kind": kind, "age": age,
                            "asked": needs.len(), "error": error_kind(&e), "ms": ms,
                        }));
                        let _ = reply.send(NodesDone { got: HashMap::new(), failed: true });
                        if !matches!(e, PeerError::Timeout) {
                            break 'life error_kind(&e);
                        }
                        empty_streak += 1;
                        if empty_streak >= 6 {
                            break 'life "times out".into();
                        }
                    }
                }
            }
            Job::HeaderAt { number, reply } => {
                let h = peer.header_at(number).await;
                let failed = h.is_err();
                let _ = reply.send(h.ok().flatten());
                if failed {
                    break 'life "header failed".into();
                }
            }
            Job::Ages { roots, reply } => {
                for (age, root) in roots {
                    let need = vec![Need { owner: None, path: Nibbles::default(), hash: root }];
                    let t0 = Instant::now();
                    let r = peer.trie_nodes(root, path_sets(&need), 4096).await;
                    let ms = t0.elapsed().as_millis() as u64;
                    let (served, error) = match &r {
                        Ok(nodes) => (!match_reply(&need, nodes).0.is_empty(), None),
                        Err(e) => (false, Some(error_kind(e))),
                    };
                    log.emit(json!({
                        "ev": "age", "peer": id.to_string()[..16], "client": client, "age": age, "served": served,
                        "ms": ms, "error": error,
                    }));
                    if matches!(r, Err(ref e) if !matches!(e, PeerError::Timeout)) {
                        let _ = reply.send(());
                        break 'life "age probe failed".into();
                    }
                }
                let _ = reply.send(());
            }
        }
    };
    shared.connected.fetch_sub(1, Ordering::Relaxed);
    log.emit(json!({"ev": "peer_down", "peer": id.to_string()[..16], "client": client, "reason": reason, "served": served}));
    peer.close().await;
}

fn spawn_connector(shared: Arc<Shared>, idle_tx: mpsc::Sender<Worker>) {
    tokio::spawn(async move {
        let key = peer::random_key();
        let (status, fork_filter) = peer::mainnet_status(None);
        let mut candidates = discovery::start(key, shared.cfg.udp_port, fork_filter.clone(), true, true).await;
        let dials = Arc::new(tokio::sync::Semaphore::new(shared.cfg.dial_parallel));
        while let Some(record) = candidates.recv().await {
            while shared.connected.load(Ordering::Relaxed) >= shared.cfg.peers {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            let permit = dials.clone().acquire_owned().await.expect("semaphore open");
            let shared = shared.clone();
            let idle_tx = idle_tx.clone();
            let fork_filter = fork_filter.clone();
            tokio::spawn(async move {
                let _permit = permit;
                shared.dialed.fetch_add(1, Ordering::Relaxed);
                match Peer::connect_snap1(record, &key, status, fork_filter, shared.cfg.dial_timeout).await {
                    Ok(mut peer) => {
                        shared.accepted.fetch_add(1, Ordering::Relaxed);
                        if shared.connected.fetch_add(1, Ordering::Relaxed) >= shared.cfg.peers {
                            shared.connected.fetch_sub(1, Ordering::Relaxed);
                            peer.close().await;
                            return;
                        }
                        peer.timeout = shared.cfg.timeout;
                        drop(_permit);
                        worker_task(peer, shared, idle_tx).await;
                    }
                    Err(PeerError::NoSnap) => {
                        shared.no_snap.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        debug!(addr = %record.address, error = %e, "dial failed");
                        *shared.dial_errors.lock().expect("lock").entry(error_kind(&e)).or_default() += 1;
                    }
                }
            });
        }
        warn!("discovery ended");
    });
}

// ---------------------------------------------------------------------------
// Scheduling requests over the idle peers

struct Pool {
    shared: Arc<Shared>,
    idle_rx: mpsc::Receiver<Worker>,
    idle: Vec<Worker>,
}

struct Chunk {
    root: B256,
    kind: &'static str,
    age: i64,
    /// Indices into the group's needs.
    group: usize,
    idx: Vec<usize>,
    tried: HashSet<PeerId>,
}

/// One root's worth of needs for [`Pool::fetch`].
pub struct Group {
    pub root: B256,
    pub kind: &'static str,
    pub age: i64,
    pub needs: Vec<Need>,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct FetchStats {
    pub requests: u64,
    pub failed: u64,
    pub unservable: u64,
}

/// Where the diff gets its nodes: peers, or (in tests) two tries in memory.
pub trait Fetch {
    /// The nodes found, per group and need index.
    fn fetch(&mut self, groups: &[Group], batch: usize, attempts: usize, deadline: Instant) -> impl std::future::Future<Output = (Vec<HashMap<usize, Bytes>>, FetchStats)>;
}

impl Fetch for Pool {
    async fn fetch(&mut self, groups: &[Group], batch: usize, attempts: usize, deadline: Instant) -> (Vec<HashMap<usize, Bytes>>, FetchStats) {
        self.fetch_from_peers(groups, batch, attempts, deadline).await
    }
}

impl Pool {
    fn connected(&self) -> usize {
        self.shared.connected.load(Ordering::Relaxed)
    }

    /// An idle worker, waiting up to `wait`.
    async fn worker(&mut self, wait: Duration) -> Option<Worker> {
        while let Ok(w) = self.idle_rx.try_recv() {
            self.idle.push(w);
        }
        self.idle.retain(|w| !w.tx.is_closed());
        if let Some(w) = self.idle.pop() {
            return Some(w);
        }
        match tokio::time::timeout(wait, self.idle_rx.recv()).await {
            Ok(Some(w)) => Some(w),
            _ => None,
        }
    }

    async fn header_at(&mut self, number: u64) -> Option<Header> {
        for _ in 0..3 {
            let w = self.worker(Duration::from_secs(60)).await?;
            let (tx, rx) = oneshot::channel();
            if w.tx.send(Job::HeaderAt { number, reply: tx }).await.is_err() {
                continue;
            }
            if let Ok(Some(h)) = rx.await {
                return Some(h);
            }
        }
        None
    }

    /// The highest block number some peer has a header for, from the best
    /// status head moved forward by the clock.
    async fn head(&mut self) -> Option<Header> {
        let n = self.shared.head_number.load(Ordering::Relaxed);
        let t = self.shared.head_time.load(Ordering::Relaxed);
        if n == 0 {
            return None;
        }
        let now = unix_f64() as u64;
        let mut guess = n + now.saturating_sub(t) / 12;
        let mut found = None;
        for _ in 0..24 {
            match self.header_at(guess).await {
                Some(h) => {
                    guess += 1;
                    found = Some(h);
                    if guess > n + now.saturating_sub(t) / 12 + 2 {
                        break;
                    }
                }
                None if found.is_some() => break,
                None => guess = guess.saturating_sub(2),
            }
        }
        if let Some(h) = &found {
            if self.shared.head_number.fetch_max(h.number, Ordering::Relaxed) < h.number {
                self.shared.head_time.store(h.timestamp, Ordering::Relaxed);
            }
        }
        found
    }

    /// Every need in `groups`, spread over idle peers, retried on other
    /// peers when missing (up to `attempts` peers each). Returns the nodes
    /// found per group and need index.
    async fn fetch_from_peers(&mut self, groups: &[Group], batch: usize, attempts: usize, deadline: Instant) -> (Vec<HashMap<usize, Bytes>>, FetchStats) {
        let mut out: Vec<HashMap<usize, Bytes>> = groups.iter().map(|_| HashMap::new()).collect();
        let mut stats = FetchStats::default();
        let mut pending: VecDeque<Chunk> = VecDeque::new();
        for (g, grp) in groups.iter().enumerate() {
            // Keep a storage trie's paths together: one set per owner.
            let mut idx: Vec<usize> = (0..grp.needs.len()).collect();
            idx.sort_by(|a, b| (grp.needs[*a].owner, grp.needs[*a].path).cmp(&(grp.needs[*b].owner, grp.needs[*b].path)));
            for c in idx.chunks(batch) {
                pending.push_back(Chunk { root: grp.root, kind: grp.kind, age: grp.age, group: g, idx: c.to_vec(), tried: HashSet::new() });
            }
        }
        let mut inflight = FuturesUnordered::new();
        let mut stuck_since: Option<Instant> = None;
        while (!pending.is_empty() || !inflight.is_empty()) && Instant::now() < deadline {
            while let Ok(w) = self.idle_rx.try_recv() {
                self.idle.push(w);
            }
            self.idle.retain(|w| !w.tx.is_closed());
            // Give each idle peer a chunk it has not tried.
            let mut keep = Vec::new();
            for w in std::mem::take(&mut self.idle) {
                let Some(i) = pending.iter().position(|c| !c.tried.contains(&w.id)) else {
                    keep.push(w);
                    continue;
                };
                let mut c = pending.remove(i).expect("index");
                let needs: Vec<Need> = c.idx.iter().map(|&i| groups[c.group].needs[i].clone()).collect();
                let (tx, rx) = oneshot::channel();
                let job = Job::Nodes { root: c.root, kind: c.kind, age: c.age, needs, reply: tx };
                if w.tx.try_send(job).is_err() {
                    pending.push_front(c);
                    continue;
                }
                stats.requests += 1;
                c.tried.insert(w.id);
                inflight.push(async move { (c, rx.await) });
            }
            self.idle = keep;
            if !pending.is_empty() && inflight.is_empty() {
                // Every idle peer has tried what is left. Wait for a new
                // peer a while, then give it up.
                let since = *stuck_since.get_or_insert_with(Instant::now);
                if since.elapsed() > Duration::from_secs(30) || self.connected() == 0 && since.elapsed() > Duration::from_secs(5) {
                    for c in pending.drain(..) {
                        stats.unservable += c.idx.len() as u64;
                    }
                    break;
                }
            } else {
                stuck_since = None;
            }
            tokio::select! {
                Some((c, r)) = inflight.next(), if !inflight.is_empty() => {
                    let done = r.unwrap_or(NodesDone { got: HashMap::new(), failed: true });
                    if done.failed {
                        stats.failed += 1;
                    }
                    let mut missing = Vec::new();
                    for (pos, &i) in c.idx.iter().enumerate() {
                        match done.got.get(&pos) {
                            Some(n) => {
                                out[c.group].insert(i, n.clone());
                            }
                            None => missing.push(i),
                        }
                    }
                    if !missing.is_empty() {
                        if c.tried.len() >= attempts {
                            stats.unservable += missing.len() as u64;
                        } else {
                            pending.push_back(Chunk { idx: missing, ..c });
                        }
                    }
                }
                Some(w) = self.idle_rx.recv() => self.idle.push(w),
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
        for c in pending {
            stats.unservable += c.idx.len() as u64;
        }
        (out, stats)
    }

    /// Ask every idle peer for the root node at each `(age, root)`.
    async fn ages(&mut self, roots: Vec<(u64, B256)>) -> usize {
        let mut waits = Vec::new();
        while let Some(w) = self.worker(Duration::ZERO).await {
            let (tx, rx) = oneshot::channel();
            if w.tx.send(Job::Ages { roots: roots.clone(), reply: tx }).await.is_ok() {
                waits.push(rx);
            }
        }
        let n = waits.len();
        for w in waits {
            let _ = tokio::time::timeout(Duration::from_secs(300), w).await;
        }
        n
    }
}

// ---------------------------------------------------------------------------
// The diff

/// A child reference: a node hash, or a node small enough to sit inline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ref {
    Hash(B256),
    Inline(Bytes),
}

impl Ref {
    fn of(r: &RlpNode) -> Ref {
        match r.as_hash() {
            Some(h) => Ref::Hash(h),
            None => Ref::Inline(Bytes::copy_from_slice(r.as_ref())),
        }
    }
}

/// A node's children by absolute path; a leaf's full key and value.
pub enum Shape {
    Inner(Vec<(Nibbles, Ref)>),
    Leaf { key: Nibbles, value: Vec<u8> },
    Empty,
}

pub fn shape(path: &Nibbles, rlp: &[u8]) -> Result<Shape, alloy_rlp::Error> {
    let mut buf = rlp;
    Ok(match TrieNode::decode(&mut buf)? {
        TrieNode::EmptyRoot => Shape::Empty,
        TrieNode::Branch(b) => {
            let mut kids = Vec::with_capacity(16);
            for (nib, child) in b.as_ref().children() {
                if let Some(c) = child {
                    let mut p = *path;
                    p.push(nib);
                    kids.push((p, Ref::of(c)));
                }
            }
            Shape::Inner(kids)
        }
        TrieNode::Extension(e) => Shape::Inner(vec![(path.join(&e.key), Ref::of(&e.child))]),
        TrieNode::Leaf(l) => Shape::Leaf { key: path.join(&l.key), value: l.value },
    })
}

use alloy_rlp::Decodable;

#[derive(Clone, Debug)]
struct Pair {
    owner: Option<B256>,
    path: Nibbles,
    new: Ref,
    old: Option<Ref>,
}

#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct TrieCount {
    /// Hashed nodes at a (path, hash) the old trie lacks.
    pub nodes: u64,
    pub bytes: u64,
    /// Inline nodes changed (stored inside their parent).
    pub inline: u64,
    /// Changed leaves.
    pub leaves: u64,
    /// Old children at paths the new node no longer has.
    pub dropped: u64,
    /// New nodes by depth (path length).
    pub by_depth: Vec<u64>,
}

impl TrieCount {
    fn node(&mut self, depth: usize, len: usize) {
        self.nodes += 1;
        self.bytes += len as u64;
        if self.by_depth.len() <= depth {
            self.by_depth.resize(depth + 1, 0);
        }
        self.by_depth[depth] += 1;
    }
}

#[derive(Default, Debug, Clone, serde::Serialize)]
pub struct DiffCount {
    pub account: TrieCount,
    pub storage: TrieCount,
    pub accounts_changed: u64,
    pub accounts_created: u64,
    pub storage_tries_changed: u64,
    /// The storage trie with the most new nodes: owner and count.
    pub top_storage: Vec<(String, u64)>,
    /// Nodes fetched at the old root (the probe's cost, not the healer's).
    pub old_nodes: u64,
    pub old_bytes: u64,
    pub accounts_resolved: u64,
    pub levels: u32,
    pub requests: u64,
    pub failed_requests: u64,
    /// Needs no peer served: new side, old side.
    pub unservable_new: u64,
    pub unservable_old: u64,
    pub complete: bool,
}

fn compatible(prefix: &Option<Nibbles>, owner: &Option<B256>, path: &Nibbles) -> bool {
    match (prefix, owner) {
        (Some(p), None) => path.starts_with(p) || p.starts_with(path),
        _ => true,
    }
}

/// Diff the state trie at `new_root` against `old_root`.
async fn diff<F: Fetch>(pool: &mut F, cfg: &Config, old_root: B256, new_root: B256, ages: (i64, i64), deadline: Instant) -> DiffCount {
    let mut count = DiffCount::default();
    let mut per_owner: HashMap<B256, u64> = HashMap::new();
    let mut old_cache: HashMap<Nibbles, Bytes> = HashMap::new();
    let mut frontier = vec![Pair { owner: None, path: Nibbles::default(), new: Ref::Hash(new_root), old: Some(Ref::Hash(old_root)) }];
    // Accounts whose old leaf is not at the new leaf's path: resolved by a
    // walk of the old trie once the account trie is done.
    let mut moved: Vec<(B256, Account)> = Vec::new();
    loop {
        while !frontier.is_empty() {
            if Instant::now() > deadline {
                return count;
            }
            count.levels += 1;
            frontier.retain(|p| p.old.as_ref() != Some(&p.new));
            let mut new_needs = Vec::new();
            let mut old_needs = Vec::new();
            let mut new_ix = vec![None; frontier.len()];
            let mut old_ix = vec![None; frontier.len()];
            for (i, p) in frontier.iter().enumerate() {
                if let Ref::Hash(h) = p.new {
                    new_ix[i] = Some(new_needs.len());
                    new_needs.push(Need { owner: p.owner, path: p.path, hash: h });
                }
                if let Some(Ref::Hash(h)) = p.old {
                    if p.owner.is_none() && old_cache.get(&p.path).is_some_and(|b| keccak256(b) == h) {
                        continue;
                    }
                    old_ix[i] = Some(old_needs.len());
                    old_needs.push(Need { owner: p.owner, path: p.path, hash: h });
                }
            }
            let groups = [
                Group { root: new_root, kind: "new", age: ages.1, needs: new_needs },
                Group { root: old_root, kind: "old", age: ages.0, needs: old_needs },
            ];
            let (got, st) = pool.fetch(&groups, cfg.batch, 4, deadline).await;
            count.requests += st.requests;
            count.failed_requests += st.failed;
            let unservable_new = groups[0].needs.len() - got[0].len();
            let unservable_old = groups[1].needs.len() - got[1].len();
            count.unservable_new += unservable_new as u64;
            count.unservable_old += unservable_old as u64;
            for (_, b) in got[1].iter() {
                count.old_nodes += 1;
                count.old_bytes += b.len() as u64;
            }
            let mut next = Vec::new();
            for (i, p) in frontier.iter().enumerate() {
                let new_rlp: Bytes = match (&p.new, new_ix[i]) {
                    (Ref::Inline(b), _) => b.clone(),
                    (Ref::Hash(_), Some(j)) => match got[0].get(&j) {
                        Some(b) => b.clone(),
                        None => continue,
                    },
                    _ => continue,
                };
                let old_rlp: Option<Bytes> = match (&p.old, old_ix[i]) {
                    (None, _) => None,
                    (Some(Ref::Inline(b)), _) => Some(b.clone()),
                    (Some(Ref::Hash(h)), None) => old_cache.get(&p.path).filter(|b| keccak256(b) == *h).cloned(),
                    (Some(Ref::Hash(_)), Some(j)) => got[1].get(&j).cloned(),
                };
                if p.owner.is_none() {
                    if let Some(b) = &old_rlp {
                        old_cache.insert(p.path, b.clone());
                    }
                }
                let trie = if p.owner.is_none() { &mut count.account } else { &mut count.storage };
                match p.new {
                    Ref::Hash(_) => {
                        trie.node(p.path.len(), new_rlp.len());
                        if let Some(o) = p.owner {
                            *per_owner.entry(o).or_default() += 1;
                        }
                    }
                    Ref::Inline(_) => trie.inline += 1,
                }
                let Ok(new_shape) = shape(&p.path, &new_rlp) else { continue };
                let old_shape = old_rlp.as_ref().and_then(|b| shape(&p.path, b).ok());
                match new_shape {
                    Shape::Empty => {}
                    Shape::Inner(kids) => {
                        let old_kids: HashMap<Nibbles, Ref> = match &old_shape {
                            Some(Shape::Inner(k)) => k.iter().cloned().collect(),
                            _ => HashMap::new(),
                        };
                        let new_paths: HashSet<Nibbles> = kids.iter().map(|(q, _)| *q).collect();
                        trie.dropped += old_kids.keys().filter(|q| !new_paths.contains(q)).count() as u64;
                        for (q, r) in kids {
                            if !compatible(&cfg.prefix, &p.owner, &q) {
                                continue;
                            }
                            let o = old_kids.get(&q).cloned();
                            if o.as_ref() == Some(&r) {
                                continue;
                            }
                            next.push(Pair { owner: p.owner, path: q, new: r, old: o });
                        }
                    }
                    Shape::Leaf { key, value } => {
                        trie.leaves += 1;
                        if p.owner.is_some() || key.len() != 64 {
                            continue;
                        }
                        let Ok(acct) = Account::decode(&value) else { continue };
                        let hash = B256::from_slice(&key.pack());
                        count.accounts_changed += 1;
                        let old_acct = match &old_shape {
                            Some(Shape::Leaf { key: ok, value: ov }) if *ok == key => Account::decode(ov).ok(),
                            _ => {
                                moved.push((hash, acct));
                                continue;
                            }
                        };
                        if let Some(pair) = storage_pair(hash, &acct, old_acct.as_ref()) {
                            count.storage_tries_changed += 1;
                            next.push(pair);
                        }
                    }
                }
            }
            frontier = next;
        }
        if moved.is_empty() {
            break;
        }
        // Moved or created accounts: their old leaf, if any, by walking the
        // old trie from its root.
        let batch = std::mem::take(&mut moved);
        count.accounts_resolved += batch.len() as u64;
        let olds = resolve_accounts(pool, cfg, old_root, ages.0, &batch, &mut old_cache, deadline, &mut count).await;
        for ((hash, acct), old) in batch.iter().zip(olds) {
            match old {
                Resolved::Absent => count.accounts_created += 1,
                Resolved::Unknown => continue,
                Resolved::Found(_) => {}
            }
            let old = if let Resolved::Found(a) = old { Some(a) } else { None };
            if let Some(pair) = storage_pair(*hash, acct, old.as_ref()) {
                count.storage_tries_changed += 1;
                frontier.push(pair);
            }
        }
    }
    let mut top: Vec<(B256, u64)> = per_owner.into_iter().collect();
    top.sort_by(|a, b| b.1.cmp(&a.1));
    count.top_storage = top.into_iter().take(5).map(|(o, n)| (o.to_string(), n)).collect();
    count.complete = count.unservable_new == 0 && count.unservable_old == 0;
    count
}

fn storage_pair(owner: B256, new: &Account, old: Option<&Account>) -> Option<Pair> {
    let old_root = old.map(|a| a.storage_root).unwrap_or(EMPTY_ROOT);
    if new.storage_root == EMPTY_ROOT || new.storage_root == old_root {
        return None;
    }
    let old = (old_root != EMPTY_ROOT).then_some(Ref::Hash(old_root));
    Some(Pair { owner: Some(owner), path: Nibbles::default(), new: Ref::Hash(new.storage_root), old })
}

#[derive(Clone, Copy)]
enum Resolved {
    Found(Account),
    Absent,
    Unknown,
}

/// Each account's leaf in the old trie, walked from `old_root` level by
/// level with the walks batched together.
#[allow(clippy::too_many_arguments)]
async fn resolve_accounts<F: Fetch>(
    pool: &mut F,
    cfg: &Config,
    old_root: B256,
    age: i64,
    accounts: &[(B256, Account)],
    cache: &mut HashMap<Nibbles, Bytes>,
    deadline: Instant,
    count: &mut DiffCount,
) -> Vec<Resolved> {
    let mut out = vec![Resolved::Unknown; accounts.len()];
    // (account index, path reached, ref at that path)
    let mut walks: Vec<(usize, Nibbles, Ref)> = (0..accounts.len()).map(|i| (i, Nibbles::default(), Ref::Hash(old_root))).collect();
    while !walks.is_empty() && Instant::now() < deadline {
        let mut needs = Vec::new();
        let mut seen = HashSet::new();
        for (_, path, r) in &walks {
            if let Ref::Hash(h) = r {
                if cache.get(path).map(|b| keccak256(b) == *h) != Some(true) && seen.insert(*path) {
                    needs.push(Need { owner: None, path: *path, hash: *h });
                }
            }
        }
        if !needs.is_empty() {
            let groups = [Group { root: old_root, kind: "old", age, needs }];
            let (got, st) = pool.fetch(&groups, cfg.batch, 4, deadline).await;
            count.requests += st.requests;
            count.failed_requests += st.failed;
            count.unservable_old += st.unservable;
            for (i, b) in got[0].iter() {
                count.old_nodes += 1;
                count.old_bytes += b.len() as u64;
                cache.insert(groups[0].needs[*i].path, b.clone());
            }
        }
        let mut next = Vec::new();
        for (i, path, r) in walks {
            let key = Nibbles::unpack(accounts[i].0);
            let rlp = match &r {
                Ref::Inline(b) => b.clone(),
                Ref::Hash(h) => match cache.get(&path).filter(|b| keccak256(b) == *h) {
                    Some(b) => b.clone(),
                    None => continue,
                },
            };
            match shape(&path, &rlp) {
                Ok(Shape::Inner(kids)) => match kids.into_iter().find(|(q, _)| key.starts_with(q)) {
                    Some((q, r)) => next.push((i, q, r)),
                    None => out[i] = Resolved::Absent,
                },
                Ok(Shape::Leaf { key: k, value }) => {
                    out[i] = if k == key { Account::decode(&value).map(Resolved::Found).unwrap_or(Resolved::Unknown) } else { Resolved::Absent };
                }
                Ok(Shape::Empty) => out[i] = Resolved::Absent,
                Err(_) => {}
            }
        }
        walks = next;
    }
    out
}

// ---------------------------------------------------------------------------
// The run

pub async fn run(cfg: Config) -> std::io::Result<()> {
    let started = Instant::now();
    let log = Log(Arc::new(Mutex::new(BufWriter::new(File::create(&cfg.out)?))));
    log.emit(json!({
        "ev": "note", "what": "start", "peers": cfg.peers, "every_s": cfg.every.as_secs(), "batch": cfg.batch,
        "prefix": cfg.prefix.map(|p| p.iter().map(|n| format!("{n:x}")).collect::<String>()), "ages": cfg.ages,
    }));
    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        log: log.clone(),
        connected: AtomicUsize::new(0),
        head_number: AtomicU64::new(0),
        head_time: AtomicU64::new(0),
        dialed: AtomicUsize::new(0),
        accepted: AtomicUsize::new(0),
        no_snap: AtomicUsize::new(0),
        dial_errors: Mutex::new(HashMap::new()),
    });
    let (idle_tx, idle_rx) = mpsc::channel::<Worker>(1024);
    spawn_connector(shared.clone(), idle_tx);
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let errors = shared.dial_errors.lock().expect("lock").clone();
                shared.log.emit(json!({
                    "ev": "dials", "dialed": shared.dialed.load(Ordering::Relaxed),
                    "snap1": shared.accepted.load(Ordering::Relaxed), "no_snap1": shared.no_snap.load(Ordering::Relaxed),
                    "connected": shared.connected.load(Ordering::Relaxed), "errors": errors,
                }));
            }
        });
    }
    let mut pool = Pool { shared: shared.clone(), idle_rx, idle: Vec::new() };

    // Wait for a few peers and a head.
    while pool.connected() == 0 || shared.head_number.load(Ordering::Relaxed) == 0 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !cfg.max_wall.is_zero() && started.elapsed() > cfg.max_wall {
            return Ok(());
        }
    }
    info!(peers = pool.connected(), "peers up; starting cycles");
    let mut headers: HashMap<u64, Header> = HashMap::new();
    let mut prev: Option<Header> = None;
    let mut cycle = 0usize;
    let mut next_at = Instant::now();
    loop {
        if !cfg.max_wall.is_zero() && started.elapsed() > cfg.max_wall {
            break;
        }
        if cfg.cycles > 0 && cycle >= cfg.cycles {
            break;
        }
        let now = Instant::now();
        if now < next_at {
            tokio::time::sleep(next_at - now).await;
        }
        next_at = Instant::now() + cfg.every;
        let Some(head) = pool.head().await else {
            log.emit(json!({"ev": "note", "what": "no head", "connected": pool.connected()}));
            tokio::time::sleep(Duration::from_secs(10)).await;
            next_at = Instant::now();
            continue;
        };
        headers.insert(head.number, head.clone());
        let target_n = head.number.saturating_sub(cfg.confirm);
        let target = match headers.get(&target_n).cloned() {
            Some(h) => Some(h),
            None => pool.header_at(target_n).await,
        };
        let Some(target) = target else {
            log.emit(json!({"ev": "note", "what": "no target header", "number": target_n}));
            next_at = Instant::now();
            continue;
        };
        headers.insert(target.number, target.clone());

        // Root ages: each peer asked for each age's root.
        let mut roots = Vec::new();
        for &age in &cfg.ages {
            let n = head.number.saturating_sub(age);
            let h = match headers.get(&n).cloned() {
                Some(h) => Some(h),
                None => pool.header_at(n).await,
            };
            if let Some(h) = h {
                roots.push((age, h.state_root));
                headers.insert(n, h);
            }
        }
        let asked = pool.ages(roots).await;
        headers.retain(|n, _| *n + 4096 > head.number);

        if let Some(p) = prev.take() {
            let t0 = Instant::now();
            let deadline = t0 + cfg.max_cycle;
            let ages = ((head.number - p.number) as i64, (head.number - target.number) as i64);
            let count = diff(&mut pool, &cfg, p.state_root, target.state_root, ages, deadline).await;
            let secs = t0.elapsed().as_secs_f64();
            let lag = unix_f64() - target.timestamp as f64;
            info!(
                from = p.number,
                to = target.number,
                acct_nodes = count.account.nodes,
                storage_nodes = count.storage.nodes,
                mib = (count.account.bytes + count.storage.bytes) as f64 / 1048576.0,
                secs,
                complete = count.complete,
                peers = pool.connected(),
                "cycle"
            );
            log.emit(json!({
                "ev": "cycle", "cycle": cycle, "from": p.number, "to": target.number, "blocks": target.number - p.number,
                "from_root": p.state_root.to_string(), "to_root": target.state_root.to_string(),
                "secs": secs, "lag_s": lag, "peers": pool.connected(), "age_peers": asked, "count": count,
            }));
            cycle += 1;
        }
        prev = Some(target);
    }
    log.emit(json!({"ev": "note", "what": "end", "elapsed_s": started.elapsed().as_secs()}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_trie::{HashBuilder, Nibbles};

    #[test]
    fn path_sets_group_storage_paths_by_owner() {
        let a = B256::repeat_byte(0xaa);
        let needs = vec![
            Need { owner: None, path: Nibbles::from_nibbles([1, 2, 3]), hash: B256::ZERO },
            Need { owner: Some(a), path: Nibbles::default(), hash: B256::ZERO },
            Need { owner: Some(a), path: Nibbles::from_nibbles([0xf]), hash: B256::ZERO },
        ];
        let sets = path_sets(&needs);
        assert_eq!(sets.len(), 2);
        // Odd path: flag nibble 1, then the path.
        assert_eq!(sets[0], vec![Bytes::from_static(&[0x11, 0x23])]);
        assert_eq!(sets[1][0].as_ref(), a.as_slice());
        assert_eq!(sets[1][1], Bytes::from_static(&[0x00]));
        assert_eq!(sets[1][2], Bytes::from_static(&[0x1f]));
    }

    #[test]
    fn replies_match_by_hash_not_position() {
        let n1 = Bytes::from_static(b"node one, long enough to be hashed..");
        let n2 = Bytes::from_static(b"node two, long enough to be hashed..");
        let needs = vec![
            Need { owner: None, path: Nibbles::default(), hash: keccak256(&n1) },
            Need { owner: None, path: Nibbles::from_nibbles([1]), hash: keccak256(&n2) },
        ];
        let (got, stray) = match_reply(&needs, &[n2.clone(), Bytes::new(), Bytes::from_static(b"junk")]);
        assert_eq!(got.len(), 1);
        assert_eq!(got[&1], n2);
        assert_eq!(stray, 1);
    }

    #[test]
    fn trie_node_messages_round_trip() {
        use crate::peer::{GetTrieNodesMessage, TrieNodesMessage};
        let m = GetTrieNodesMessage { request_id: 7, root: B256::repeat_byte(1), paths: vec![vec![Bytes::from_static(&[0])]], bytes: 1 << 20 };
        let enc = alloy_rlp::encode(&m);
        assert_eq!(GetTrieNodesMessage::decode(&mut enc.as_slice()).unwrap(), m);
        let r = TrieNodesMessage { request_id: 7, nodes: vec![Bytes::from_static(b"abc"), Bytes::new()] };
        let enc = alloy_rlp::encode(&r);
        assert_eq!(TrieNodesMessage::decode(&mut enc.as_slice()).unwrap(), r);
    }

    /// Build a small trie, read every node back by path, and check that
    /// [`shape`] walks it: every leaf reached, keys whole.
    #[test]
    fn shape_walks_a_built_trie() {
        let mut leaves: Vec<(B256, Vec<u8>)> = (0u8..40).map(|i| (keccak256([i]), vec![i + 1; 40])).collect();
        leaves.sort();
        let paths: Vec<Nibbles> = leaves.iter().map(|(k, _)| Nibbles::unpack(k)).collect();
        let mut hb = HashBuilder::default().with_proof_retainer(alloy_trie::proof::ProofRetainer::new(paths.clone()));
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        let root = hb.root();
        let nodes: HashMap<Nibbles, Bytes> = hb.take_proof_nodes().into_inner().into_iter().collect();
        let mut stack = vec![(Nibbles::default(), Ref::Hash(root))];
        let mut found = 0;
        while let Some((path, r)) = stack.pop() {
            let rlp = match r {
                Ref::Hash(h) => {
                    let b = nodes[&path].clone();
                    assert_eq!(keccak256(&b), h);
                    b
                }
                Ref::Inline(b) => b,
            };
            match shape(&path, &rlp).unwrap() {
                Shape::Inner(kids) => stack.extend(kids),
                Shape::Leaf { key, .. } => {
                    assert_eq!(key.len(), 64);
                    found += 1;
                }
                Shape::Empty => unreachable!(),
            }
        }
        assert_eq!(found, leaves.len());
    }

    /// Nodes of two tries in memory, served by root.
    struct Mem(HashMap<B256, HashMap<(Option<B256>, Nibbles), Bytes>>);

    impl Fetch for Mem {
        async fn fetch(&mut self, groups: &[Group], _: usize, _: usize, _: Instant) -> (Vec<HashMap<usize, Bytes>>, FetchStats) {
            let out = groups
                .iter()
                .map(|g| {
                    let nodes = &self.0[&g.root];
                    g.needs.iter().enumerate().filter_map(|(i, n)| nodes.get(&(n.owner, n.path)).filter(|b| keccak256(b) == n.hash).map(|b| (i, b.clone()))).collect()
                })
                .collect();
            (out, FetchStats::default())
        }
    }

    /// Every node of the trie over `leaves`, by path, and its root.
    fn trie(leaves: &[(B256, Vec<u8>)]) -> (B256, HashMap<Nibbles, Bytes>) {
        let mut leaves = leaves.to_vec();
        leaves.sort();
        let paths: Vec<Nibbles> = leaves.iter().map(|(k, _)| Nibbles::unpack(k)).collect();
        let mut hb = HashBuilder::default().with_proof_retainer(alloy_trie::proof::ProofRetainer::new(paths));
        for (k, v) in &leaves {
            hb.add_leaf(Nibbles::unpack(k), v);
        }
        let root = hb.root();
        (root, hb.take_proof_nodes().into_inner().into_iter().collect())
    }

    struct State {
        root: B256,
        nodes: HashMap<(Option<B256>, Nibbles), Bytes>,
    }

    fn state(accounts: &[(u32, u64, Vec<(u32, u8)>)]) -> State {
        let mut nodes = HashMap::new();
        let mut leaves = Vec::new();
        for (a, balance, slots) in accounts {
            let owner = keccak256(a.to_be_bytes());
            let mut storage_root = EMPTY_ROOT;
            if !slots.is_empty() {
                let sl: Vec<(B256, Vec<u8>)> = slots.iter().map(|(k, v)| (keccak256(k.to_be_bytes()), csl_eth_trie::encode_word(&alloy_primitives::U256::from(*v)))).collect();
                let (r, n) = trie(&sl);
                storage_root = r;
                nodes.extend(n.into_iter().map(|(p, b)| ((Some(owner), p), b)));
            }
            let acct = Account { nonce: 1, balance: alloy_primitives::U256::from(*balance), storage_root, code_hash: csl_eth_trie::KECCAK_EMPTY };
            leaves.push((owner, acct.encode()));
        }
        let (root, n) = trie(&leaves);
        nodes.extend(n.into_iter().map(|(p, b)| ((None, p), b)));
        State { root, nodes }
    }

    /// The truth: hashed nodes of `new` whose (trie, path, hash) `old` lacks.
    fn truth(old: &State, new: &State) -> (u64, u64) {
        let old_set: HashSet<(Option<B256>, Nibbles, B256)> = old.nodes.iter().filter(|(_, b)| b.len() >= 32).map(|((o, p), b)| (*o, *p, keccak256(b))).collect();
        let mut acct = 0;
        let mut stor = 0;
        for ((o, p), b) in &new.nodes {
            if b.len() >= 32 && !old_set.contains(&(*o, *p, keccak256(b))) {
                if o.is_none() {
                    acct += 1;
                } else {
                    stor += 1;
                }
            }
        }
        (acct, stor)
    }

    #[tokio::test]
    async fn diff_counts_exactly_the_new_nodes() {
        // 300 accounts, every 7th with storage.
        let base: Vec<(u32, u64, Vec<(u32, u8)>)> =
            (0..300u32).map(|a| (a, a as u64 * 10 + 1, if a % 7 == 0 { (0..(a % 50 + 3)).map(|k| (k, (k % 200 + 1) as u8)).collect() } else { vec![] })).collect();
        let mut next = base.clone();
        // Balances changed, slots written and cleared, accounts created
        // (moving neighbours' leaves deeper), a new contract.
        for a in [3usize, 50, 77, 140, 299] {
            next[a].1 += 1;
        }
        next[14].2.push((999, 9));
        next[21].2[0].1 = 77;
        next[28].2.pop();
        next[35].2.clear();
        for a in 300..340u32 {
            next.push((a, 5, if a == 310 { vec![(1, 1), (2, 2)] } else { vec![] }));
        }
        let old = state(&base);
        let new = state(&next);
        let (want_acct, want_stor) = truth(&old, &new);
        let mut mem = Mem(HashMap::from([(old.root, old.nodes), (new.root, new.nodes)]));
        let cfg = Config::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        let c = diff(&mut mem, &cfg, old.root, new.root, (0, 0), deadline).await;
        assert!(c.complete);
        assert_eq!(c.account.nodes, want_acct);
        assert_eq!(c.storage.nodes, want_stor);
        assert!(c.accounts_created >= 40, "{}", c.accounts_created);
        assert!(want_stor > 0 && want_acct > 0);
        // Nothing changed: nothing fetched.
        let c = diff(&mut mem, &cfg, new.root, new.root, (0, 0), deadline).await;
        assert_eq!(c.account.nodes + c.storage.nodes, 0);
    }
}
