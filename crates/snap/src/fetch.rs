//! The slice fetcher: every account under a path prefix at one root, their
//! storage and bytecode, from mainnet peers over `snap`, verified as it
//! arrives.
//!
//! Work is a queue of jobs any connected peer may take: an account
//! sub-range (the prefix split by its next nibble so sixteen ranges run in
//! parallel, each a chain of `GetAccountRange` chunks), a batch of storage
//! tries by owner, a tail of one large storage trie from an origin, a batch
//! of bytecodes. A peer verifies what it is given before reporting it: a
//! range by its boundary proof (`verify_range`), a whole storage trie by
//! its root, code by its hash; a peer whose answer fails verification is
//! dropped and the job goes back on the queue.
//!
//! The pivot is a block one peer claims as its head, and peers serve snap
//! only for roots within about 128 blocks of theirs. When three peers
//! answer an account request with nothing (the sign they no longer have the
//! root), the fetch re-pivots to a fresh head: accounts are refetched,
//! storage tries already verified are kept by root, and code is kept by
//! hash.
//!
//! Trust: the pivot header is self-consistent (it hashes to the hash the
//! peer announced) but not verified against the chain; milestone 1's head
//! verifier over the light-client files supplies the root a client
//! trusts, and the producer's `state_root` check ties the slice to it.

use crate::{
    discovery,
    peer::{self, Peer, PeerError},
    slice::{Slice, SliceHead},
};
use alloy_consensus::Header;
use alloy_primitives::{keccak256, B256, U256};
use csl_eth_trie::{decode_word, verify_range, Account, Nibbles, Sealed, EMPTY_ROOT, KECCAK_EMPTY};
use reth_network_peers::{NodeRecord, PeerId};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tracing::{debug, info, warn};

/// A peer's announced head older than this is not a pivot candidate.
const MAX_PIVOT_AGE_SECS: u64 = 15 * 60;

#[derive(Clone, Debug)]
pub struct Config {
    /// Hex nibbles of the slice, 1 to 62 of them.
    pub prefix: Nibbles,
    /// Connected peers to aim for.
    pub peers: usize,
    /// Dials in flight.
    pub dial_parallel: usize,
    /// Soft response size asked of peers (geth caps at 2 MiB).
    pub response_bytes: u64,
    /// Per request.
    pub timeout: Duration,
    /// Per dial (TCP, ECIES, hello, status together).
    pub dial_timeout: Duration,
    pub storage_batch: usize,
    pub code_batch: usize,
    pub udp_port: u16,
    pub use_dns: bool,
    pub use_discv4: bool,
    /// A block hash to pivot on instead of the first peer's head.
    pub pivot: Option<B256>,
    /// Stop after this long without completing (0: never).
    pub max_wall: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            prefix: Nibbles::from_nibbles([0]),
            peers: 8,
            dial_parallel: 192,
            response_bytes: 2 * 1024 * 1024,
            timeout: Duration::from_secs(20),
            dial_timeout: Duration::from_secs(10),
            storage_batch: 48,
            code_batch: 48,
            udp_port: 30399,
            use_dns: true,
            use_discv4: true,
            pivot: None,
            max_wall: Duration::from_secs(0),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("no peers could be reached")]
    NoPeers,
    #[error("gave up after {0:?}")]
    Timeout(Duration),
    #[error("bytecode {0} missing from every peer")]
    CodeMissing(B256),
    #[error("{0}")]
    Other(String),
}

#[derive(Clone, Copy, Debug)]
struct Pivot {
    hash: B256,
    number: u64,
    timestamp: u64,
    state_root: B256,
}

#[derive(Clone, Debug)]
enum Job {
    /// Fetch a header: the peer's own head, or a given hash.
    Head(Option<B256>),
    Accounts {
        sub: usize,
        origin: B256,
        limit: B256,
    },
    /// Storage tries by (owner, storage root). With `origin`, one owner's
    /// slots from there on.
    Storage {
        items: Vec<(B256, B256)>,
        origin: Option<B256>,
    },
    Codes(Vec<B256>),
}

/// One owner's fetched storage: (owner, storage root, slots, next origin
/// if the trie continues past this response).
pub type StorageTrie = (B256, B256, Vec<(B256, U256)>, Option<B256>);

enum Done {
    Head {
        peer: PeerId,
        from_job: bool,
        header: Box<Header>,
    },
    Accounts {
        root: B256,
        sub: usize,
        origin: B256,
        /// Every leaf the peer returned, in order.
        leaves: Vec<(B256, Account)>,
        left: Vec<Sealed>,
        right: Vec<Sealed>,
        more: bool,
        last_ref: Option<Sealed>,
    },
    Storage {
        root: B256,
        tries: Vec<StorageTrie>,
        uncovered: Vec<(B256, B256)>,
    },
    Codes {
        found: Vec<(B256, Vec<u8>)>,
        missing: Vec<B256>,
    },
    Failed {
        job: Job,
        peer: PeerId,
        stale: bool,
        err: String,
    },
    PeerGone {
        peer: PeerId,
        err: Option<String>,
    },
}

struct Fail {
    stale: bool,
    fatal: bool,
    err: String,
}

impl From<PeerError> for Fail {
    fn from(e: PeerError) -> Self {
        Fail { stale: false, fatal: true, err: e.to_string() }
    }
}

struct Shared {
    cfg: Config,
    queue: Mutex<VecDeque<Job>>,
    notify: Notify,
    pivot: RwLock<Option<Pivot>>,
    outstanding: AtomicUsize,
    connected: AtomicUsize,
    finished: AtomicBool,
    requests: AtomicU64,
    bytes_in: AtomicU64,
}

struct Sub {
    lo: B256,
    hi: B256,
    done: bool,
}

/// Fetch the slice described by `cfg`.
pub async fn fetch(cfg: Config) -> Result<Slice, FetchError> {
    let started = Instant::now();
    let key = peer::random_key();
    let (status, fork_filter) = peer::mainnet_status(None);
    let mut candidates = discovery::start(key, cfg.udp_port, fork_filter.clone(), cfg.use_dns, cfg.use_discv4).await;

    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        queue: Mutex::new(VecDeque::new()),
        notify: Notify::new(),
        pivot: RwLock::new(None),
        outstanding: AtomicUsize::new(0),
        connected: AtomicUsize::new(0),
        finished: AtomicBool::new(false),
        requests: AtomicU64::new(0),
        bytes_in: AtomicU64::new(0),
    });
    let (tx, mut rx) = mpsc::channel::<Done>(256);

    // Connector: keep dialing candidates until enough peers are up.
    {
        let shared = shared.clone();
        let tx = tx.clone();
        let fork_filter = fork_filter.clone();
        tokio::spawn(async move {
            let dials = Arc::new(tokio::sync::Semaphore::new(shared.cfg.dial_parallel));
            let (tried, ok) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
            while let Some(record) = candidates.recv().await {
                if shared.finished.load(Ordering::Relaxed) {
                    break;
                }
                while shared.connected.load(Ordering::Relaxed) >= shared.cfg.peers {
                    if shared.finished.load(Ordering::Relaxed) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                let permit = dials.clone().acquire_owned().await.expect("semaphore open");
                let shared = shared.clone();
                let tx = tx.clone();
                let status = status;
                let fork_filter = fork_filter.clone();
                let (tried, ok) = (tried.clone(), ok.clone());
                tokio::spawn(async move {
                    let _permit = permit;
                    let n = tried.fetch_add(1, Ordering::Relaxed) + 1;
                    match Peer::connect(record, &key, status, fork_filter, shared.cfg.dial_timeout).await {
                        Ok(mut peer) => {
                            peer.timeout = shared.cfg.timeout;
                            let k = ok.fetch_add(1, Ordering::Relaxed) + 1;
                            if shared.connected.fetch_add(1, Ordering::Relaxed) >= shared.cfg.peers {
                                shared.connected.fetch_sub(1, Ordering::Relaxed);
                                peer.close().await;
                                return;
                            }
                            info!(
                                client = %peer.client,
                                snap = peer.snap_version,
                                addr = %record.address,
                                dialed = n,
                                accepted = k,
                                "peer up"
                            );
                            peer_task(peer, shared, tx).await;
                        }
                        Err(e) => debug!(addr = %record.address, dialed = n, error = %e, "dial failed"),
                    }
                });
            }
        });
    }

    // Progress line.
    {
        let shared = shared.clone();
        tokio::spawn(async move {
            while !shared.finished.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_secs(10)).await;
                let queued = shared.queue.lock().await.len();
                info!(
                    peers = shared.connected.load(Ordering::Relaxed),
                    queued,
                    in_flight = shared.outstanding.load(Ordering::Relaxed),
                    requests = shared.requests.load(Ordering::Relaxed),
                    mib_in = shared.bytes_in.load(Ordering::Relaxed) / (1024 * 1024),
                    elapsed_s = started.elapsed().as_secs(),
                    "progress"
                );
            }
        });
    }

    let mut co = Coordinator::new(cfg.clone(), shared.clone());
    if let Some(h) = cfg.pivot {
        co.push(Job::Head(Some(h))).await;
    }
    let result = loop {
        let timeout = if cfg.max_wall.is_zero() { Duration::from_secs(3600 * 24) } else { cfg.max_wall.saturating_sub(started.elapsed()) };
        if timeout.is_zero() {
            break Err(FetchError::Timeout(cfg.max_wall));
        }
        let done = match tokio::time::timeout(timeout, rx.recv()).await {
            Err(_) => break Err(FetchError::Timeout(cfg.max_wall)),
            Ok(None) => break Err(FetchError::NoPeers),
            Ok(Some(d)) => d,
        };
        match co.handle(done).await {
            Ok(true) => break Ok(()),
            Ok(false) => {}
            Err(e) => break Err(e),
        }
    };
    shared.finished.store(true, Ordering::Relaxed);
    shared.notify.notify_waiters();
    result?;
    Ok(co.into_slice(started.elapsed()))
}

struct Coordinator {
    cfg: Config,
    shared: Arc<Shared>,
    pivot: Option<Pivot>,
    subs: Vec<Sub>,
    slice_lo: B256,
    slice_hi: B256,
    accounts: BTreeMap<B256, Account>,
    left: Vec<Sealed>,
    right: Vec<Sealed>,
    storage: HashMap<B256, Vec<(B256, U256)>>,
    partial: HashMap<B256, Vec<(B256, U256)>>,
    storage_pending: HashSet<B256>,
    storage_want: Vec<(B256, B256)>,
    code: HashMap<B256, Vec<u8>>,
    code_pending: HashSet<B256>,
    code_want: Vec<B256>,
    code_misses: HashMap<B256, u32>,
    stale_peers: HashSet<PeerId>,
    peers_seen: HashSet<PeerId>,
    repivots: u64,
    waiting_for_head: bool,
}

impl Coordinator {
    fn new(cfg: Config, shared: Arc<Shared>) -> Self {
        let (slice_lo, slice_hi) = bounds(&cfg.prefix, None);
        let subs = (0u8..16)
            .map(|n| {
                let (lo, hi) = bounds(&cfg.prefix, Some(n));
                Sub { lo, hi, done: false }
            })
            .collect();
        Coordinator {
            cfg,
            shared,
            pivot: None,
            subs,
            slice_lo,
            slice_hi,
            accounts: BTreeMap::new(),
            left: Vec::new(),
            right: Vec::new(),
            storage: HashMap::new(),
            partial: HashMap::new(),
            storage_pending: HashSet::new(),
            storage_want: Vec::new(),
            code: HashMap::new(),
            code_pending: HashSet::new(),
            code_want: Vec::new(),
            code_misses: HashMap::new(),
            stale_peers: HashSet::new(),
            peers_seen: HashSet::new(),
            repivots: 0,
            waiting_for_head: true,
        }
    }

    async fn push(&self, job: Job) {
        self.shared.queue.lock().await.push_back(job);
        self.shared.notify.notify_one();
    }

    async fn push_front(&self, job: Job) {
        self.shared.queue.lock().await.push_front(job);
        self.shared.notify.notify_one();
    }

    async fn set_pivot(&mut self, header: &Header) {
        let p = Pivot { hash: header.hash_slow(), number: header.number, timestamp: header.timestamp, state_root: header.state_root };
        info!(number = p.number, hash = %p.hash, state_root = %p.state_root, "pivot");
        self.pivot = Some(p);
        *self.shared.pivot.write().await = Some(p);
        self.waiting_for_head = false;
        self.stale_peers.clear();
        self.accounts.clear();
        self.left.clear();
        self.right.clear();
        self.partial.clear();
        self.storage_pending.clear();
        self.storage_want.clear();
        let mut q = self.shared.queue.lock().await;
        q.clear();
        for (i, s) in self.subs.iter_mut().enumerate() {
            s.done = false;
            q.push_back(Job::Accounts { sub: i, origin: s.lo, limit: s.hi });
        }
        drop(q);
        self.shared.notify.notify_waiters();
    }

    async fn repivot(&mut self) {
        self.repivots += 1;
        warn!(repivots = self.repivots, "pivot stale on three peers; re-pivoting");
        self.pivot = None;
        *self.shared.pivot.write().await = None;
        self.shared.queue.lock().await.clear();
        self.waiting_for_head = true;
        self.stale_peers.clear();
        self.push(Job::Head(None)).await;
    }

    async fn flush_storage(&mut self, all: bool) {
        while self.storage_want.len() >= self.cfg.storage_batch || (all && !self.storage_want.is_empty()) {
            let n = self.storage_want.len().min(self.cfg.storage_batch);
            let items: Vec<(B256, B256)> = self.storage_want.drain(..n).collect();
            self.push(Job::Storage { items, origin: None }).await;
        }
    }

    async fn flush_code(&mut self, all: bool) {
        while self.code_want.len() >= self.cfg.code_batch || (all && !self.code_want.is_empty()) {
            let n = self.code_want.len().min(self.cfg.code_batch);
            let hashes: Vec<B256> = self.code_want.drain(..n).collect();
            self.push(Job::Codes(hashes)).await;
        }
    }

    fn accounts_done(&self) -> bool {
        self.pivot.is_some() && self.subs.iter().all(|s| s.done)
    }

    /// Returns `Ok(true)` when the slice is complete.
    async fn handle(&mut self, done: Done) -> Result<bool, FetchError> {
        let mut job_finished = true;
        match done {
            Done::Head { peer, from_job, header } => {
                self.peers_seen.insert(peer);
                job_finished = from_job;
                // A head is a pivot candidate only when it is the one asked
                // for, or recent: syncing peers announce genesis or an old
                // block, and nobody serves snap for those roots.
                let wanted = match self.cfg.pivot {
                    Some(h) => header.hash_slow() == h,
                    None => {
                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
                        header.number >= peer::FORK_HEAD_NUMBER && header.timestamp + MAX_PIVOT_AGE_SECS >= now
                    }
                };
                info!(peer = %peer, number = header.number, usable = wanted, "peer head");
                if self.waiting_for_head && wanted {
                    self.set_pivot(&header).await;
                } else if let Some(p) = self.pivot {
                    if header.number + 128 < p.number {
                        debug!(peer = %peer, number = header.number, "peer far behind the pivot");
                    }
                }
            }
            Done::Accounts { root, sub, origin, leaves, left, right, more, last_ref } => {
                if self.pivot.map(|p| p.state_root) != Some(root) || self.subs[sub].done {
                    // From a previous pivot, or a duplicate after a requeue.
                } else {
                    let (lo, hi) = (self.subs[sub].lo, self.subs[sub].hi);
                    let last_raw = leaves.last().map(|(h, _)| *h);
                    for (h, a) in leaves {
                        if h > hi {
                            break;
                        }
                        if a.storage_root != EMPTY_ROOT && !self.storage.contains_key(&a.storage_root) && self.storage_pending.insert(a.storage_root) {
                            self.storage_want.push((h, a.storage_root));
                        }
                        if a.code_hash != KECCAK_EMPTY && !self.code.contains_key(&a.code_hash) && self.code_pending.insert(a.code_hash) {
                            self.code_want.push(a.code_hash);
                        }
                        self.accounts.insert(h, a);
                    }
                    if sub == 0 && origin == lo {
                        self.left = left;
                    }
                    let is_last_sub = sub == self.subs.len() - 1;
                    match last_raw {
                        Some(last) if more && last < hi => {
                            let next = B256::from(U256::from_be_bytes(last.0) + U256::from(1));
                            self.push(Job::Accounts { sub, origin: next, limit: hi }).await;
                        }
                        _ => {
                            self.subs[sub].done = true;
                            if is_last_sub {
                                self.right = right;
                                if let Some(last) = last_raw {
                                    if last > self.slice_hi {
                                        if let Some(r) = last_ref {
                                            self.right.push(r);
                                        }
                                    }
                                }
                            }
                            let n = self.subs.iter().filter(|s| s.done).count();
                            info!(sub, subs_done = n, accounts = self.accounts.len(), "sub-range complete");
                        }
                    }
                    let all = self.accounts_done();
                    self.flush_storage(all).await;
                    self.flush_code(all).await;
                }
            }
            Done::Storage { root, tries, uncovered } => {
                if self.pivot.map(|p| p.state_root) != Some(root) {
                    // Stale pivot; the roots still verified, keep complete ones.
                }
                for (owner, sroot, slots, next) in tries {
                    match next {
                        Some(o) => {
                            self.partial.entry(sroot).or_default().extend(slots);
                            self.push(Job::Storage { items: vec![(owner, sroot)], origin: Some(o) }).await;
                        }
                        None => {
                            let mut all = self.partial.remove(&sroot).unwrap_or_default();
                            all.extend(slots);
                            self.storage.insert(sroot, all);
                            self.storage_pending.remove(&sroot);
                        }
                    }
                }
                if !uncovered.is_empty() {
                    self.push(Job::Storage { items: uncovered, origin: None }).await;
                }
            }
            Done::Codes { found, missing } => {
                for (h, c) in found {
                    self.code.insert(h, c);
                    self.code_pending.remove(&h);
                    self.code_misses.remove(&h);
                }
                if !missing.is_empty() {
                    for h in &missing {
                        let n = self.code_misses.entry(*h).or_default();
                        *n += 1;
                        if *n > 12 {
                            return Err(FetchError::CodeMissing(*h));
                        }
                    }
                    self.push(Job::Codes(missing)).await;
                }
            }
            Done::Failed { job, peer, stale, err } => {
                debug!(peer = %peer, stale, error = %err, "job failed; requeued");
                if stale {
                    self.stale_peers.insert(peer);
                }
                let three_stale =
                    self.stale_peers.len() >= 3 || (!self.stale_peers.is_empty() && self.stale_peers.len() >= self.shared.connected.load(Ordering::Relaxed));
                if stale && self.pivot.is_some() && three_stale {
                    self.repivot().await;
                } else {
                    self.push_front(job).await;
                }
            }
            Done::PeerGone { peer, err } => {
                job_finished = false;
                if let Some(e) = err {
                    info!(peer = %peer, error = %e, "peer gone");
                }
            }
        }
        if job_finished {
            self.shared.outstanding.fetch_sub(1, Ordering::Relaxed);
        }
        let complete = self.accounts_done()
            && self.storage_pending.is_empty()
            && self.code_pending.is_empty()
            && self.shared.outstanding.load(Ordering::Relaxed) == 0
            && self.shared.queue.lock().await.is_empty();
        Ok(complete)
    }

    fn into_slice(self, wall: Duration) -> Slice {
        let p = self.pivot.expect("complete fetch has a pivot");
        let mut boundary = self.left;
        boundary.extend(self.right);
        boundary.sort_by_key(|a| a.0);
        let storage_slots: u64 = self.storage.values().map(|v| v.len() as u64).sum();
        let head = SliceHead {
            block_hash: p.hash,
            block_number: p.number,
            timestamp: p.timestamp,
            state_root: p.state_root,
            prefix: self.cfg.prefix.iter().map(|n| format!("{n:x}")).collect(),
            fetched_at: SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0),
            accounts: self.accounts.len() as u64,
            storage_tries: self.storage.len() as u64,
            storage_slots,
            codes: self.code.len() as u64,
            peers_used: self.peers_seen.len() as u64,
            bytes_in: self.shared.bytes_in.load(Ordering::Relaxed),
            requests: self.shared.requests.load(Ordering::Relaxed),
            wall_ms: wall.as_millis() as u64,
            repivots: self.repivots,
        };
        let _ = (self.slice_lo, self.slice_hi);
        Slice { head, accounts: self.accounts.into_iter().collect(), storage: self.storage, code: self.code, boundary }
    }
}

/// The hashed-key range of `prefix`, or of `prefix` followed by `nibble`.
fn bounds(prefix: &Nibbles, nibble: Option<u8>) -> (B256, B256) {
    let mut p = *prefix;
    if let Some(n) = nibble {
        p.push(n);
    }
    let mut lo = [0u8; 32];
    let mut hi = [0xffu8; 32];
    let packed = p.pack();
    let full = p.len() / 2;
    lo[..full].copy_from_slice(&packed[..full]);
    hi[..full].copy_from_slice(&packed[..full]);
    if p.len() % 2 == 1 {
        let nib = p.get_unchecked(p.len() - 1);
        lo[full] = nib << 4;
        hi[full] = (nib << 4) | 0x0f;
    }
    (B256::from(lo), B256::from(hi))
}

async fn peer_task(mut peer: Peer, shared: Arc<Shared>, tx: mpsc::Sender<Done>) {
    let id = peer.id();
    let mut err: Option<String> = None;
    match peer.own_head().await {
        Ok(Some(h)) => {
            let _ = tx.send(Done::Head { peer: id, from_job: false, header: Box::new(h) }).await;
        }
        Ok(None) => {}
        Err(e) => err = Some(e.to_string()),
    }
    if err.is_none() {
        loop {
            if shared.finished.load(Ordering::Relaxed) {
                break;
            }
            let job = shared.queue.lock().await.pop_front();
            let Some(job) = job else {
                tokio::select! {
                    _ = shared.notify.notified() => {}
                    r = peer.idle(Duration::from_millis(500)) => {
                        if let Err(e) = r {
                            err = Some(e.to_string());
                            break;
                        }
                    }
                }
                continue;
            };
            shared.outstanding.fetch_add(1, Ordering::Relaxed);
            let pivot = *shared.pivot.read().await;
            let before = peer.bytes_in;
            shared.requests.fetch_add(1, Ordering::Relaxed);
            let r = run_job(&mut peer, &job, pivot, &shared.cfg).await;
            shared.bytes_in.fetch_add(peer.bytes_in - before, Ordering::Relaxed);
            match r {
                Ok(done) => {
                    if tx.send(done).await.is_err() {
                        break;
                    }
                }
                Err(f) => {
                    let fatal = f.fatal;
                    let _ = tx.send(Done::Failed { job, peer: id, stale: f.stale, err: f.err }).await;
                    if fatal {
                        err = Some("dropped after a failed job".into());
                        break;
                    }
                }
            }
        }
    }
    shared.connected.fetch_sub(1, Ordering::Relaxed);
    peer.close().await;
    let _ = tx.send(Done::PeerGone { peer: id, err }).await;
}

async fn run_job(peer: &mut Peer, job: &Job, pivot: Option<Pivot>, cfg: &Config) -> Result<Done, Fail> {
    let no_pivot = || Fail { stale: false, fatal: false, err: "no pivot yet".into() };
    match job {
        Job::Head(hash) => {
            let h = match hash {
                Some(h) => peer.header(*h).await?,
                None => peer.own_head().await?,
            };
            match h {
                Some(h) => Ok(Done::Head { peer: peer.id(), from_job: true, header: Box::new(h) }),
                None => Err(Fail { stale: false, fatal: false, err: "peer has no such header".into() }),
            }
        }
        Job::Accounts { sub, origin, limit } => {
            let p = pivot.ok_or_else(no_pivot)?;
            let resp = peer.account_range(p.state_root, *origin, *limit, cfg.response_bytes).await?;
            if resp.accounts.is_empty() && resp.proof.is_empty() {
                return Err(Fail { stale: true, fatal: false, err: "empty account range: peer lacks the root".into() });
            }
            let mut leaves = Vec::with_capacity(resp.accounts.len());
            let mut rlp = Vec::with_capacity(resp.accounts.len());
            for a in &resp.accounts {
                let ta = a.trie_account();
                rlp.push((a.hash, alloy_rlp::encode(ta)));
                leaves.push((a.hash, Account { nonce: ta.nonce, balance: ta.balance, storage_root: ta.storage_root, code_hash: ta.code_hash }));
            }
            let v = verify_range(p.state_root, origin, &rlp, &resp.proof).map_err(|e| Fail {
                stale: false,
                fatal: true,
                err: format!("account range failed verification: {e}"),
            })?;
            Ok(Done::Accounts { root: p.state_root, sub: *sub, origin: *origin, leaves, left: v.left, right: v.right, more: v.more, last_ref: v.last })
        }
        Job::Storage { items, origin } => {
            let p = pivot.ok_or_else(no_pivot)?;
            let owners: Vec<B256> = items.iter().map(|(o, _)| *o).collect();
            let resp = peer.storage_ranges(p.state_root, owners, *origin, cfg.response_bytes).await?;
            if resp.slots.is_empty() {
                return Err(Fail { stale: true, fatal: false, err: "empty storage ranges: peer lacks the root or the accounts".into() });
            }
            if resp.slots.len() > items.len() {
                return Err(Fail { stale: false, fatal: true, err: "more storage tries than requested".into() });
            }
            let n = resp.slots.len();
            let mut tries = Vec::with_capacity(n);
            let mut uncovered: Vec<(B256, B256)> = items[n..].to_vec();
            for (i, slots) in resp.slots.into_iter().enumerate() {
                let (owner, sroot) = items[i];
                let is_last = i == n - 1;
                let start = if is_last { origin.unwrap_or(B256::ZERO) } else { B256::ZERO };
                let proof: &[alloy_primitives::Bytes] = if is_last { &resp.proof } else { &[] };
                let rlp: Vec<(B256, Vec<u8>)> = slots.iter().map(|s| (s.hash, s.data.to_vec())).collect();
                let v = match verify_range(sroot, &start, &rlp, proof) {
                    Ok(v) => v,
                    Err(e) => {
                        if is_last || slots.is_empty() {
                            // A claim this peer could not back; another peer may.
                            debug!(owner = %owner, error = %e, "storage range not verified; requeued");
                            uncovered.push((owner, sroot));
                            continue;
                        }
                        return Err(Fail { stale: false, fatal: true, err: format!("storage trie {sroot} failed verification: {e}") });
                    }
                };
                let mut out = Vec::with_capacity(slots.len());
                for s in &slots {
                    let w = decode_word(&s.data).map_err(|_| Fail { stale: false, fatal: true, err: "storage value is not a canonical word".into() })?;
                    out.push((s.hash, w));
                }
                let next = if v.more {
                    let last = slots.last().map(|s| s.hash).unwrap_or(start);
                    Some(B256::from(U256::from_be_bytes(last.0) + U256::from(1)))
                } else {
                    None
                };
                tries.push((owner, sroot, out, next));
            }
            Ok(Done::Storage { root: p.state_root, tries, uncovered })
        }
        Job::Codes(hashes) => {
            let resp = peer.byte_codes(hashes.clone(), cfg.response_bytes).await?;
            if resp.codes.is_empty() {
                return Err(Fail { stale: false, fatal: false, err: "no bytecodes returned".into() });
            }
            let want: HashSet<B256> = hashes.iter().copied().collect();
            let mut found = Vec::with_capacity(resp.codes.len());
            let mut got = HashSet::new();
            for c in resp.codes {
                let h = keccak256(&c);
                if !want.contains(&h) {
                    return Err(Fail { stale: false, fatal: true, err: "bytecode not requested".into() });
                }
                if got.insert(h) {
                    found.push((h, c.to_vec()));
                }
            }
            let missing: Vec<B256> = hashes.iter().copied().filter(|h| !got.contains(h)).collect();
            Ok(Done::Codes { found, missing })
        }
    }
}

/// Dial up to `count` peers, ask each for its head, and report what they
/// run. A connectivity check before a fetch.
pub async fn probe(count: usize, timeout: Duration, udp_port: u16) -> Vec<(NodeRecord, String, u8, Option<u64>)> {
    let key = peer::random_key();
    let (status, fork_filter) = peer::mainnet_status(None);
    let mut candidates = discovery::start(key, udp_port, fork_filter.clone(), true, true).await;
    let mut out = Vec::new();
    let sem = Arc::new(tokio::sync::Semaphore::new(32));
    let (tx, mut rx) = mpsc::channel(64);
    let deadline = Instant::now() + Duration::from_secs(120);
    tokio::spawn(async move {
        while let Some(record) = candidates.recv().await {
            let permit = sem.clone().acquire_owned().await.expect("open");
            let tx = tx.clone();
            let (status, fork_filter) = (status, fork_filter.clone());
            tokio::spawn(async move {
                let _permit = permit;
                match Peer::connect(record, &key, status, fork_filter, timeout).await {
                    Ok(mut peer) => {
                        let head = peer.own_head().await.ok().flatten().map(|h| h.number);
                        let row = (record, peer.client.clone(), peer.snap_version, head);
                        peer.close().await;
                        let _ = tx.send(row).await;
                    }
                    Err(e) => debug!(addr = %record.address, error = %e, "dial failed"),
                }
            });
        }
    });
    while out.len() < count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(row)) => out.push(row),
            _ => break,
        }
    }
    out
}
