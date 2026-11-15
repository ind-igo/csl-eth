//! History acquisition (Milestone H): headers, bodies and receipts for the
//! span below a verified finalized block, from public mainnet peers over
//! `eth`, verified as they arrive, cached per block, then written as the
//! §3c tables by [`write_history`].
//!
//! Trust starts at one block hash: the finalized execution block the
//! bucket's head files prove from a checkpoint (`csl-eth head verify`).
//! Headers are asked for backwards by hash (`GetBlockHeaders`, falling,
//! up to [`AcquireConfig::header_batch`] at a time), so every header is
//! checked to be the parent of the one above it, the first to hash to the
//! trusted block. Bodies and receipts are then fetched in parallel from
//! every connected peer: a body is kept only if its transactions rebuild
//! the header's `transactionsRoot` (its ommers and withdrawals are checked
//! too), receipts only if they rebuild `receiptsRoot`. A peer that answers
//! anything that does not verify is dropped and not dialled again, and its
//! job goes back on the queue; a peer that answers nothing three times in
//! a row is dropped as not serving. Partial answers (a peer fills its
//! response and stops) keep what came and requeue the rest.
//!
//! `eth/68`, `eth/69` and `eth/70` are offered and the newest shared is
//! used; [`Peer::receipts`] turns each version's receipts into trie leaves.
//!
//! The cache (`<work>/blocks/<n>`, [`Block::encode`]) makes a run
//! resumable: a cached block is used when its hash is the verified
//! header's and it verifies again.

use crate::{
    discovery,
    peer::{self, EthBlockBody, Peer, PeerError},
};
use alloy_consensus::{
    proofs::{calculate_ommers_root, calculate_withdrawals_root},
    Header,
};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::B256;
use csl_eth_store::{
    history::{ordered_root, Block, BlockSource},
    producer::write_atomic,
};
use reth_network_peers::PeerId;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tracing::{debug, info, warn};

pub mod cli;
pub mod faults;

#[derive(Clone, Debug)]
pub struct AcquireConfig {
    /// Blocks to acquire, the anchor and those below it.
    pub blocks: u64,
    /// Connected peers to aim for.
    pub peers: usize,
    pub dial_parallel: usize,
    /// Per request.
    pub timeout: Duration,
    /// Per dial.
    pub dial_timeout: Duration,
    pub udp_port: u16,
    pub use_dns: bool,
    pub use_discv4: bool,
    /// Headers per `GetBlockHeaders` (geth and reth serve up to 1024).
    pub header_batch: u64,
    /// Hashes per `GetBlockBodies` and per `GetReceipts`; peers answer a
    /// prefix when their response fills (2 MiB soft limit).
    pub body_batch: usize,
    pub receipt_batch: usize,
    /// Give up after this long (0: never).
    pub max_wall: Duration,
    /// Give up when no header or block has arrived for this long (0:
    /// never), whatever `max_wall` says: peers that stop serving must not
    /// hold a run open forever.
    pub max_stall: Duration,
}

impl Default for AcquireConfig {
    fn default() -> Self {
        AcquireConfig {
            blocks: 7200,
            peers: 8,
            dial_parallel: 192,
            timeout: Duration::from_secs(20),
            dial_timeout: Duration::from_secs(10),
            udp_port: 30399,
            use_dns: true,
            use_discv4: true,
            header_batch: 1024,
            body_batch: 128,
            receipt_batch: 64,
            max_wall: Duration::from_secs(0),
            max_stall: Duration::from_secs(600),
        }
    }
}

/// Requests or bytes, by message.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ByKind {
    pub headers: u64,
    pub bodies: u64,
    pub receipts: u64,
}

impl ByKind {
    fn add(&mut self, k: Kind, n: u64) {
        match k {
            Kind::Headers => self.headers += n,
            Kind::Bodies => self.bodies += n,
            Kind::Receipts => self.receipts += n,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Headers,
    Bodies,
    Receipts,
}

#[derive(Clone, Debug, Serialize)]
pub struct Dropped {
    pub client: String,
    pub eth: u8,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct AcquireStats {
    pub anchor_number: u64,
    pub anchor_hash: B256,
    pub first_block: u64,
    pub blocks: u64,
    /// Blocks taken from the cache, verified again.
    pub from_cache: u64,
    pub fetched: u64,
    pub wall_secs: f64,
    pub dialed: usize,
    /// Handshakes completed.
    pub accepted: usize,
    /// Peers that served at least one verified item.
    pub peers_served: usize,
    pub requests: ByKind,
    /// Bytes received in answers to each kind of request.
    pub bytes: ByKind,
    /// Answers with nothing in them.
    pub empty: ByKind,
    /// Items that came in partial answers and were requeued.
    pub requeued_items: u64,
    pub eth_versions: BTreeMap<u8, usize>,
    pub clients: BTreeMap<String, usize>,
    /// Peers dropped for answers that did not verify.
    pub bad_peers: Vec<Dropped>,
    /// Peers dropped for answering nothing.
    pub idle_peers: usize,
    /// Of the acquired bytes: header RLP, transaction and receipt leaves.
    pub header_bytes: u64,
    pub tx_bytes: u64,
    pub receipt_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AcquireError {
    #[error("gave up after {wall:?} with {done} of {total} blocks")]
    Timeout { wall: Duration, done: u64, total: u64 },
    #[error("nothing arrived for {stall:?}, with {done} of {total} blocks")]
    Stalled { stall: Duration, done: u64, total: u64 },
    #[error("{0}")]
    Other(String),
}

#[derive(Clone, Debug)]
enum Job {
    /// Headers from `hash` (block `number`) down.
    Headers { hash: B256, number: u64 },
    Bodies(Vec<(u64, B256)>),
    Receipts(Vec<(u64, B256)>),
}

impl Job {
    fn kind(&self) -> Kind {
        match self {
            Job::Headers { .. } => Kind::Headers,
            Job::Bodies(_) => Kind::Bodies,
            Job::Receipts(_) => Kind::Receipts,
        }
    }
}

#[derive(Default)]
struct Partial {
    txs: Option<Vec<Vec<u8>>>,
    receipts: Option<Vec<Vec<u8>>>,
}

struct Shared {
    cfg: AcquireConfig,
    work: PathBuf,
    first: u64,
    total: u64,
    queue: Mutex<VecDeque<Job>>,
    notify: Notify,
    headers: Mutex<BTreeMap<u64, Header>>,
    partial: Mutex<HashMap<u64, Partial>>,
    done: AtomicU64,
    /// Blocks counted in `done`, so a block that arrives twice (a job
    /// requeued after a worker failed partway) counts once.
    completed: Mutex<HashSet<u64>>,
    finished: AtomicBool,
    connected: AtomicUsize,
    banned: Mutex<HashSet<PeerId>>,
    stats: Mutex<AcquireStats>,
    fatal: Mutex<Option<String>>,
}

impl Shared {
    fn new(cfg: AcquireConfig, work: &Path, (number, hash): (u64, B256), first: u64, blocks: u64) -> Shared {
        Shared {
            cfg,
            work: work.to_path_buf(),
            first,
            total: blocks,
            queue: Mutex::new(VecDeque::new()),
            notify: Notify::new(),
            headers: Mutex::new(BTreeMap::new()),
            partial: Mutex::new(HashMap::new()),
            done: AtomicU64::new(0),
            completed: Mutex::new(HashSet::new()),
            finished: AtomicBool::new(false),
            connected: AtomicUsize::new(0),
            banned: Mutex::new(HashSet::new()),
            stats: Mutex::new(AcquireStats { anchor_number: number, anchor_hash: hash, first_block: first, blocks, ..Default::default() }),
            fatal: Mutex::new(None),
        }
    }

    fn push(&self, job: Job, front: bool) {
        let mut q = self.queue.lock().unwrap();
        if front {
            q.push_front(job);
        } else {
            q.push_back(job);
        }
        drop(q);
        self.notify.notify_one();
    }

    fn pop(&self) -> Option<Job> {
        self.queue.lock().unwrap().pop_front()
    }

    fn header(&self, n: u64) -> Option<Header> {
        self.headers.lock().unwrap().get(&n).cloned()
    }

    fn fail(&self, e: String) {
        self.fatal.lock().unwrap().get_or_insert(e);
        self.finished.store(true, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    /// A block's body or receipts verified: write the block once both are in.
    fn arrive(&self, n: u64, txs: Option<Vec<Vec<u8>>>, receipts: Option<Vec<Vec<u8>>>) {
        if self.completed.lock().unwrap().contains(&n) {
            return;
        }
        let ready = {
            let mut p = self.partial.lock().unwrap();
            let e = p.entry(n).or_default();
            if txs.is_some() {
                e.txs = txs;
            }
            if receipts.is_some() {
                e.receipts = receipts;
            }
            if e.txs.is_some() && e.receipts.is_some() {
                p.remove(&n)
            } else {
                None
            }
        };
        let Some(Partial { txs: Some(txs), receipts: Some(receipts) }) = ready else {
            return;
        };
        let Some(h) = self.header(n) else {
            return self.fail(format!("block {n} arrived without its header"));
        };
        let b = Block { number: n, hash: h.hash_slow(), header: alloy_rlp::encode(&h), txs, receipts };
        // Both roots were checked as each half arrived; this checks the
        // counts agree and every receipt decodes as the profile says.
        if let Err(e) = b.verify() {
            return self.fail(format!("block {n}: {e}"));
        }
        if let Err(e) = write_atomic(&block_path(&self.work, n), &b.encode()) {
            return self.fail(format!("block cache: {e}"));
        }
        {
            let mut s = self.stats.lock().unwrap();
            s.fetched += 1;
            count_block(&mut s, &b);
        }
        self.block_done(n);
    }

    fn block_done(&self, n: u64) {
        if !self.completed.lock().unwrap().insert(n) {
            return;
        }
        if self.done.fetch_add(1, Ordering::Relaxed) + 1 >= self.total {
            self.finished.store(true, Ordering::Relaxed);
            self.notify.notify_waiters();
        }
    }
}

fn count_block(s: &mut AcquireStats, b: &Block) {
    s.header_bytes += b.header.len() as u64;
    s.tx_bytes += b.txs.iter().map(|t| t.len() as u64).sum::<u64>();
    s.receipt_bytes += b.receipts.iter().map(|r| r.len() as u64).sum::<u64>();
}

pub fn block_path(work: &Path, n: u64) -> PathBuf {
    work.join("blocks").join(n.to_string())
}

/// The producer's verified block cache as a [`BlockSource`].
pub struct BlockCache(pub PathBuf);

impl BlockSource for BlockCache {
    fn block(&self, n: u64) -> Result<Block, String> {
        let p = block_path(&self.0, n);
        let bytes = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        Block::decode(&bytes).ok_or_else(|| format!("{}: not a cached block", p.display()))
    }
}

/// A cached block that is the verified header's block, or `None`.
fn cached(work: &Path, h: &Header) -> Option<Block> {
    let b = BlockCache(work.to_path_buf()).block(h.number).ok()?;
    if b.hash != h.hash_slow() || b.verify().is_err() {
        return None;
    }
    Some(b)
}

/// The transaction leaves of `body` if it is the body of `h`.
fn check_body(h: &Header, body: &EthBlockBody) -> Result<Vec<Vec<u8>>, &'static str> {
    let txs: Vec<Vec<u8>> = body.transactions.iter().map(|t| t.encoded_2718()).collect();
    if ordered_root(&txs) != h.transactions_root {
        return Err("transactions do not rebuild transactionsRoot");
    }
    if calculate_ommers_root(&body.ommers) != h.ommers_hash {
        return Err("ommers do not hash to ommersHash");
    }
    match (&body.withdrawals, h.withdrawals_root) {
        (Some(w), Some(r)) if calculate_withdrawals_root(w) == r => {}
        (None, None) => {}
        _ => return Err("withdrawals do not rebuild withdrawalsRoot"),
    }
    Ok(txs)
}

/// What a peer's answer to one job came to.
enum Outcome {
    /// Verified items, and the job's rest to requeue (if any).
    Served { items: usize, rest: Option<Job> },
    Empty,
    /// Something did not verify: drop and ban the peer.
    Bad(String),
}

async fn run_job(peer: &mut Peer, sh: &Shared, job: &Job) -> Result<Outcome, PeerError> {
    match job {
        Job::Headers { hash, number } => {
            let limit = sh.cfg.header_batch.min(number - sh.first + 1);
            let hs = match peer.headers_back(*hash, limit).await {
                Ok(hs) => hs,
                Err(PeerError::Protocol(w)) => return Ok(Outcome::Bad(w.into())),
                Err(e) => return Err(e),
            };
            if hs.is_empty() {
                return Ok(Outcome::Empty);
            }
            for (i, h) in hs.iter().enumerate() {
                if h.number != number - i as u64 {
                    return Ok(Outcome::Bad(format!("header {} carries number {}", number - i as u64, h.number)));
                }
            }
            let lowest = hs.last().expect("non-empty").clone();
            let mut new = Vec::new();
            {
                let mut m = sh.headers.lock().unwrap();
                for h in &hs {
                    new.push((h.number, h.hash_slow()));
                    m.insert(h.number, h.clone());
                }
            }
            let n = hs.len();
            // The rest of the chain first, so headers stay ahead of bodies.
            let rest = (lowest.number > sh.first).then(|| Job::Headers { hash: lowest.parent_hash, number: lowest.number - 1 });
            let mut want = Vec::new();
            for h in &hs {
                match cached(&sh.work, h) {
                    Some(b) => {
                        if !sh.completed.lock().unwrap().contains(&h.number) {
                            let mut s = sh.stats.lock().unwrap();
                            count_block(&mut s, &b);
                            s.from_cache += 1;
                        }
                        sh.block_done(h.number);
                    }
                    None => want.push((h.number, h.hash_slow())),
                }
            }
            // Bodies and receipts for the same blocks side by side, so a
            // block's halves meet soon and few wait in memory.
            let per = sh.cfg.body_batch.max(sh.cfg.receipt_batch);
            for c in want.chunks(per) {
                for b in c.chunks(sh.cfg.body_batch) {
                    sh.push(Job::Bodies(b.to_vec()), false);
                }
                for r in c.chunks(sh.cfg.receipt_batch) {
                    sh.push(Job::Receipts(r.to_vec()), false);
                }
            }
            Ok(Outcome::Served { items: n, rest })
        }
        Job::Bodies(list) => {
            let bodies = match peer.bodies(list.iter().map(|x| x.1).collect()).await {
                Ok(b) => b,
                Err(PeerError::Protocol(w)) => return Ok(Outcome::Bad(w.into())),
                Err(e) => return Err(e),
            };
            if bodies.is_empty() {
                return Ok(Outcome::Empty);
            }
            if bodies.len() > list.len() {
                return Ok(Outcome::Bad("more bodies than asked".into()));
            }
            let mut ok = Vec::with_capacity(bodies.len());
            for ((n, _), body) in list.iter().zip(&bodies) {
                let h = sh.header(*n).expect("jobs follow headers");
                match check_body(&h, body) {
                    Ok(txs) => ok.push((*n, txs)),
                    Err(w) => return Ok(Outcome::Bad(format!("block {n}: {w}"))),
                }
            }
            let items = ok.len();
            for (n, txs) in ok {
                sh.arrive(n, Some(txs), None);
            }
            let rest = (items < list.len()).then(|| Job::Bodies(list[items..].to_vec()));
            Ok(Outcome::Served { items, rest })
        }
        Job::Receipts(list) => {
            let blocks = match peer.receipts(list.iter().map(|x| x.1).collect()).await {
                Ok(b) => b,
                Err(PeerError::Protocol(w)) => return Ok(Outcome::Bad(w.into())),
                Err(e) => return Err(e),
            };
            if blocks.is_empty() {
                return Ok(Outcome::Empty);
            }
            if blocks.len() > list.len() {
                return Ok(Outcome::Bad("more receipt lists than asked".into()));
            }
            for ((n, _), rs) in list.iter().zip(&blocks) {
                let h = sh.header(*n).expect("jobs follow headers");
                if ordered_root(rs) != h.receipts_root {
                    return Ok(Outcome::Bad(format!("block {n}: receipts do not rebuild receiptsRoot")));
                }
            }
            let items = blocks.len();
            for ((n, _), rs) in list.iter().zip(blocks) {
                sh.arrive(*n, None, Some(rs));
            }
            let rest = (items < list.len()).then(|| Job::Receipts(list[items..].to_vec()));
            Ok(Outcome::Served { items, rest })
        }
    }
}

/// A connected peer's place in `Shared::connected`, given back when its
/// task ends however it ends (a panic included), so the dialer can fill it.
struct Slot(Arc<Shared>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.connected.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A job a peer is working on: back on the queue's front when dropped,
/// unless it was served. A worker that fails or panics partway loses no
/// job.
struct Held<'a> {
    sh: &'a Shared,
    job: Option<Job>,
}

impl Held<'_> {
    fn job(&self) -> &Job {
        self.job.as_ref().expect("held until served or dropped")
    }

    fn served(mut self) {
        self.job = None;
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if let Some(job) = self.job.take() {
            self.sh.push(job, true);
        }
    }
}

async fn peer_task(mut peer: Peer, sh: Arc<Shared>) {
    let _slot = Slot(sh.clone());
    let client = peer.client.clone();
    let eth = peer.eth_version();
    let mut empties = 0;
    let mut served = false;
    let why: Option<String> = loop {
        if sh.finished.load(Ordering::Relaxed) {
            break None;
        }
        let Some(job) = sh.pop() else {
            // Nothing queued: keep the connection answered while waiting.
            if let Err(e) = peer.idle(Duration::from_millis(500)).await {
                break Some(format!("idle: {e}"));
            }
            continue;
        };
        let kind = job.kind();
        let before = peer.bytes_in;
        let held = Held { sh: &sh, job: Some(job) };
        let r = run_job(&mut peer, &sh, held.job()).await;
        {
            let mut s = sh.stats.lock().unwrap();
            s.requests.add(kind, 1);
            s.bytes.add(kind, peer.bytes_in - before);
        }
        match r {
            Ok(Outcome::Served { items, rest }) => {
                held.served();
                empties = 0;
                if !served {
                    served = true;
                    sh.stats.lock().unwrap().peers_served += 1;
                }
                if let Some(rest) = rest {
                    if !matches!(rest, Job::Headers { .. }) {
                        sh.stats.lock().unwrap().requeued_items += match &rest {
                            Job::Bodies(l) | Job::Receipts(l) => l.len() as u64,
                            Job::Headers { .. } => 0,
                        };
                    }
                    sh.push(rest, true);
                }
                debug!(client = %client, ?kind, items, "served");
            }
            Ok(Outcome::Empty) => {
                sh.stats.lock().unwrap().empty.add(kind, 1);
                drop(held);
                empties += 1;
                if empties >= 3 {
                    sh.stats.lock().unwrap().idle_peers += 1;
                    break Some("answered nothing three times".into());
                }
                let _ = peer.idle(Duration::from_secs(1)).await;
            }
            Ok(Outcome::Bad(w)) => {
                drop(held);
                sh.banned.lock().unwrap().insert(peer.id());
                warn!(client = %client, eth, reason = %w, "dropping peer: answer does not verify");
                sh.stats.lock().unwrap().bad_peers.push(Dropped { client: client.clone(), eth, reason: w.clone() });
                break Some(w);
            }
            Err(e) => {
                drop(held);
                break Some(e.to_string());
            }
        }
    };
    if let Some(w) = why {
        debug!(client = %client, reason = %w, "peer gone");
    }
    peer.close().await;
}

/// Acquire `cfg.blocks` blocks ending at the trusted `anchor` into
/// `<work>/blocks/`, verified.
pub async fn acquire(anchor: (u64, B256), work: &Path, cfg: AcquireConfig) -> Result<AcquireStats, AcquireError> {
    let started = Instant::now();
    let (number, hash) = anchor;
    let blocks = cfg.blocks.clamp(1, number + 1);
    let first = number + 1 - blocks;
    std::fs::create_dir_all(work.join("blocks")).map_err(|e| AcquireError::Other(e.to_string()))?;
    let sh = Arc::new(Shared::new(cfg.clone(), work, (number, hash), first, blocks));
    sh.push(Job::Headers { hash, number }, false);

    let key = peer::random_key();
    let (status, fork_filter) = peer::mainnet_status(None);
    let mut candidates = discovery::start(key, cfg.udp_port, fork_filter.clone(), cfg.use_dns, cfg.use_discv4).await;
    let dialed = Arc::new(AtomicUsize::new(0));
    {
        let sh = sh.clone();
        let dialed = dialed.clone();
        tokio::spawn(async move {
            let dials = Arc::new(tokio::sync::Semaphore::new(sh.cfg.dial_parallel));
            while let Some(record) = candidates.recv().await {
                if sh.finished.load(Ordering::Relaxed) {
                    break;
                }
                if sh.banned.lock().unwrap().contains(&record.id) {
                    continue;
                }
                while sh.connected.load(Ordering::Relaxed) >= sh.cfg.peers {
                    if sh.finished.load(Ordering::Relaxed) {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                let permit = dials.clone().acquire_owned().await.expect("semaphore open");
                let sh = sh.clone();
                let fork_filter = fork_filter.clone();
                dialed.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let _permit = permit;
                    match Peer::connect_history(record, &key, status, fork_filter, sh.cfg.dial_timeout).await {
                        Ok(mut peer) => {
                            peer.timeout = sh.cfg.timeout;
                            {
                                let mut s = sh.stats.lock().unwrap();
                                s.accepted += 1;
                                *s.eth_versions.entry(peer.eth_version()).or_default() += 1;
                                let name = peer.client.split('/').next().unwrap_or("").to_string();
                                *s.clients.entry(name).or_default() += 1;
                            }
                            if sh.connected.fetch_add(1, Ordering::Relaxed) >= sh.cfg.peers || sh.finished.load(Ordering::Relaxed) {
                                sh.connected.fetch_sub(1, Ordering::Relaxed);
                                peer.close().await;
                                return;
                            }
                            info!(client = %peer.client, eth = peer.eth_version(), "peer up");
                            peer_task(peer, sh).await;
                        }
                        Err(e) => debug!(error = %e, "dial failed"),
                    }
                });
            }
        });
    }

    let mut last_log = Instant::now();
    let (mut seen, mut last_arrival) = (0, Instant::now());
    let result = loop {
        if let Some(e) = sh.fatal.lock().unwrap().clone() {
            break Err(AcquireError::Other(e));
        }
        let done = sh.done.load(Ordering::Relaxed);
        if done >= blocks {
            break Ok(());
        }
        if !cfg.max_wall.is_zero() && started.elapsed() > cfg.max_wall {
            break Err(AcquireError::Timeout { wall: cfg.max_wall, done, total: blocks });
        }
        let arrived = done + sh.headers.lock().unwrap().len() as u64;
        if arrived != seen {
            (seen, last_arrival) = (arrived, Instant::now());
        } else if !cfg.max_stall.is_zero() && last_arrival.elapsed() > cfg.max_stall {
            break Err(AcquireError::Stalled { stall: cfg.max_stall, done, total: blocks });
        }
        if last_log.elapsed() > Duration::from_secs(10) {
            last_log = Instant::now();
            let s = sh.stats.lock().unwrap();
            info!(
                done,
                of = blocks,
                peers = sh.connected.load(Ordering::Relaxed),
                headers = sh.headers.lock().unwrap().len(),
                queued = sh.queue.lock().unwrap().len(),
                mib_in = (s.bytes.headers + s.bytes.bodies + s.bytes.receipts) / (1 << 20),
                elapsed_s = started.elapsed().as_secs(),
                "history progress"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    sh.finished.store(true, Ordering::Relaxed);
    sh.notify.notify_waiters();
    let mut s = sh.stats.lock().unwrap().clone();
    s.dialed = dialed.load(Ordering::Relaxed);
    s.wall_secs = started.elapsed().as_secs_f64();
    result.map(|()| s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(blocks: u64) -> Arc<Shared> {
        let work = std::env::temp_dir().join(format!("csl-history-acquire-{}", std::process::id()));
        Arc::new(Shared::new(AcquireConfig::default(), &work, (100, B256::ZERO), 101 - blocks, blocks))
    }

    #[tokio::test]
    async fn a_worker_that_panics_gives_back_its_job_and_its_slot() {
        let sh = shared(4);
        sh.connected.fetch_add(1, Ordering::Relaxed);
        let job = Job::Receipts(vec![(98, B256::repeat_byte(1)), (99, B256::repeat_byte(2))]);
        let t = {
            let sh = sh.clone();
            tokio::spawn(async move {
                let _slot = Slot(sh.clone());
                let held = Held { sh: &sh, job: Some(job) };
                let _ = held.job();
                panic!("a worker fails partway");
            })
        };
        assert!(t.await.unwrap_err().is_panic());
        assert_eq!(sh.connected.load(Ordering::Relaxed), 0);
        match sh.pop() {
            Some(Job::Receipts(l)) => assert_eq!(l.iter().map(|x| x.0).collect::<Vec<_>>(), [98, 99]),
            other => panic!("the job was not requeued: {other:?}"),
        }
        assert!(sh.pop().is_none());
    }

    #[test]
    fn a_served_job_is_not_requeued_and_a_block_counts_once() {
        let sh = shared(4);
        Held { sh: &sh, job: Some(Job::Headers { hash: B256::ZERO, number: 100 }) }.served();
        assert!(sh.pop().is_none());
        drop(Held { sh: &sh, job: Some(Job::Headers { hash: B256::ZERO, number: 100 }) });
        assert!(sh.pop().is_some());
        sh.block_done(99);
        sh.block_done(99);
        assert_eq!(sh.done.load(Ordering::Relaxed), 1);
    }
}
