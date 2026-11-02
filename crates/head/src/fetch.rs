//! The producer's side: pull the light-client objects from a beacon node's
//! API and lay them out as the bucket's head files. The node is a source
//! of bytes, not of trust; whatever it returns is verified by `verify`
//! before any client acts on it, and the fetch verifies the set it wrote
//! before returning so a bad node is caught here rather than downstream.

use crate::{paths, verify, Chain, DirSource, HeadError, VerifiedHead};
use alloy_primitives::B256;
use serde::Deserialize;
use std::{path::Path, time::Duration};

#[derive(Debug)]
pub struct Fetched {
    pub checkpoint: B256,
    pub updates: Vec<u64>,
    pub head: VerifiedHead,
}

#[derive(Deserialize)]
struct FinalityCheckpoints {
    data: FinalityCheckpointsData,
}

#[derive(Deserialize)]
struct FinalityCheckpointsData {
    finalized: Checkpoint,
}

#[derive(Deserialize)]
struct Checkpoint {
    root: B256,
}

fn get(agent: &ureq::Agent, url: &str) -> Result<Vec<u8>, String> {
    let mut resp = agent
        .get(url)
        .header("Accept", "application/json")
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("GET {url}: status {}", resp.status()));
    }
    resp.body_mut()
        .with_config()
        .limit(64 << 20)
        .read_to_vec()
        .map_err(|e| format!("GET {url} body: {e}"))
}

/// Write `head/` under `bucket` from the node at `beacon`: the bootstrap
/// for `checkpoint` (the node's current finalized checkpoint when `None`),
/// every period update from that checkpoint's period to now, and the
/// finality update. Returns what was written and the head it verifies to.
pub fn fetch_into(
    beacon: &str,
    bucket: &Path,
    checkpoint: Option<B256>,
) -> Result<Fetched, String> {
    let beacon = beacon.trim_end_matches('/');
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .build()
        .into();
    let chain = Chain::mainnet();

    let checkpoint = match checkpoint {
        Some(c) => c,
        None => {
            let v = get(
                &agent,
                &format!("{beacon}/eth/v1/beacon/states/finalized/finality_checkpoints"),
            )?;
            serde_json::from_slice::<FinalityCheckpoints>(&v)
                .map_err(|e| e.to_string())?
                .data
                .finalized
                .root
        }
    };

    let write = |rel: &str, bytes: &[u8]| -> Result<(), String> {
        let p = bucket.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        std::fs::write(&p, bytes).map_err(|e| format!("{}: {e}", p.display()))
    };

    let bootstrap = get(
        &agent,
        &format!("{beacon}/eth/v1/beacon/light_client/bootstrap/{checkpoint}"),
    )?;
    let slot: u64 = serde_json::from_slice::<serde_json::Value>(&bootstrap)
        .ok()
        .and_then(|v| {
            v["data"]["header"]["beacon"]["slot"]
                .as_str()
                .and_then(|s| s.parse().ok())
        })
        .ok_or("bootstrap without a slot")?;
    write(&paths::bootstrap(&checkpoint), &bootstrap)?;

    let now = std::time::SystemTime::now();
    let first = crate::period_of(slot);
    let last = crate::period_of(crate::current_slot(&chain, now));
    let mut updates = Vec::new();
    let mut period = first;
    while period <= last {
        let count = (last - period + 1).min(128);
        let v = get(
            &agent,
            &format!(
                "{beacon}/eth/v1/beacon/light_client/updates?start_period={period}&count={count}"
            ),
        )?;
        let items: Vec<serde_json::Value> =
            serde_json::from_slice(&v).map_err(|e| e.to_string())?;
        if items.is_empty() {
            break;
        }
        for item in &items {
            let s: u64 = item["data"]["attested_header"]["beacon"]["slot"]
                .as_str()
                .and_then(|s| s.parse().ok())
                .ok_or("update without a slot")?;
            let p = crate::period_of(s);
            write(
                &paths::update(p),
                &serde_json::to_vec(item).map_err(|e| e.to_string())?,
            )?;
            updates.push(p);
        }
        period += count;
    }

    let finality = get(
        &agent,
        &format!("{beacon}/eth/v1/beacon/light_client/finality_update"),
    )?;
    write(paths::FINALITY, &finality)?;

    let head = verify(&DirSource(bucket.to_path_buf()), &chain, checkpoint, now)
        .map_err(|e: HeadError| e.to_string())?;
    Ok(Fetched {
        checkpoint,
        updates,
        head,
    })
}

/// A client for one beacon node's light-client API, for a producer that
/// keeps a bucket's head files current rather than writing them once.
pub struct Beacon {
    base: String,
    agent: ureq::Agent,
}

/// A period update as the producer stores it: the period its attested
/// header is in, and the object with its version envelope.
pub struct PeriodUpdate {
    pub period: u64,
    pub bytes: Vec<u8>,
}

/// What a finality update names: the finalized execution block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finalized {
    pub slot: u64,
    pub block_number: u64,
    pub block_hash: B256,
}

fn json_u64(v: &serde_json::Value) -> Option<u64> {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| v.as_u64())
}

/// The finalized header a finality update's bytes name, read from the
/// JSON without verifying anything (`verify` does that over the files).
pub fn finalized_of(bytes: &[u8]) -> Result<Finalized, String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let h = &v["data"]["finalized_header"];
    let slot = json_u64(&h["beacon"]["slot"]).ok_or("finality update without a slot")?;
    let block_number = json_u64(&h["execution"]["block_number"])
        .ok_or("finality update without an execution block number")?;
    let block_hash = h["execution"]["block_hash"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or("finality update without an execution block hash")?;
    Ok(Finalized {
        slot,
        block_number,
        block_hash,
    })
}

impl Beacon {
    pub fn new(base: &str) -> Beacon {
        Beacon {
            base: base.trim_end_matches('/').to_string(),
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(Duration::from_secs(60)))
                .build()
                .into(),
        }
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, String> {
        get(&self.agent, &format!("{}{path}", self.base))
    }

    /// The bootstrap for `checkpoint` and the slot of its header.
    pub fn bootstrap(&self, checkpoint: B256) -> Result<(Vec<u8>, u64), String> {
        let b = self.get(&format!(
            "/eth/v1/beacon/light_client/bootstrap/{checkpoint}"
        ))?;
        let slot = serde_json::from_slice::<serde_json::Value>(&b)
            .ok()
            .and_then(|v| json_u64(&v["data"]["header"]["beacon"]["slot"]))
            .ok_or("bootstrap without a slot")?;
        Ok((b, slot))
    }

    /// The node's best update for each period in `first..=last` that it
    /// has, in order; a period with none yet (the current one, early on)
    /// is simply absent. Each is re-serialized from the response array
    /// with its envelope, as `fetch_into` writes it.
    pub fn updates(&self, first: u64, last: u64) -> Result<Vec<PeriodUpdate>, String> {
        let mut out = Vec::new();
        let mut period = first;
        while period <= last {
            let count = (last - period + 1).min(128);
            let v = self.get(&format!(
                "/eth/v1/beacon/light_client/updates?start_period={period}&count={count}"
            ))?;
            let items: Vec<serde_json::Value> =
                serde_json::from_slice(&v).map_err(|e| e.to_string())?;
            if items.is_empty() {
                break;
            }
            for item in &items {
                let s = json_u64(&item["data"]["attested_header"]["beacon"]["slot"])
                    .ok_or("update without a slot")?;
                out.push(PeriodUpdate {
                    period: crate::period_of(s),
                    bytes: serde_json::to_vec(item).map_err(|e| e.to_string())?,
                });
            }
            period += count;
        }
        Ok(out)
    }

    /// The node's current finality update, its exact response bytes.
    pub fn finality_update(&self) -> Result<Vec<u8>, String> {
        self.get("/eth/v1/beacon/light_client/finality_update")
    }
}

/// The finality updates a beacon node serves, polled in the background
/// and kept by the block they name. A node serves only its newest finality
/// update, so the one naming a given block exists for one epoch (6.4
/// minutes) about 13 to 19 minutes after that block; a producer that is
/// still fetching then must already be watching, or the bytes are gone.
pub struct FinalityWatch {
    inner: std::sync::Arc<WatchInner>,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct WatchInner {
    stop: std::sync::atomic::AtomicBool,
    seen: std::sync::Mutex<WatchSeen>,
    changed: std::sync::Condvar,
}

#[derive(Default)]
struct WatchSeen {
    /// By finalized execution block hash: what it names and the bytes.
    by_hash: std::collections::HashMap<B256, (Finalized, Vec<u8>)>,
    /// The highest finalized block number seen.
    newest: Option<Finalized>,
    polls: u64,
    last_error: Option<String>,
}

impl FinalityWatch {
    /// Start polling `beacon`'s finality update every `every`.
    pub fn start(beacon: &str, every: Duration) -> FinalityWatch {
        let inner = std::sync::Arc::new(WatchInner {
            stop: std::sync::atomic::AtomicBool::new(false),
            seen: std::sync::Mutex::new(WatchSeen::default()),
            changed: std::sync::Condvar::new(),
        });
        let node = Beacon::new(beacon);
        let w = inner.clone();
        let thread = std::thread::spawn(move || {
            use std::sync::atomic::Ordering;
            while !w.stop.load(Ordering::Relaxed) {
                let got = node
                    .finality_update()
                    .and_then(|b| finalized_of(&b).map(|f| (f, b)));
                {
                    let mut s = w.seen.lock().unwrap();
                    s.polls += 1;
                    match got {
                        Ok((f, b)) => {
                            if s.newest.is_none_or(|n| f.block_number > n.block_number) {
                                s.newest = Some(f);
                            }
                            s.by_hash.entry(f.block_hash).or_insert((f, b));
                            s.last_error = None;
                        }
                        Err(e) => s.last_error = Some(e),
                    }
                }
                w.changed.notify_all();
                // Sleep in short steps so a stop is prompt.
                let until = std::time::Instant::now() + every;
                while std::time::Instant::now() < until && !w.stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        });
        FinalityWatch {
            inner,
            thread: Some(thread),
        }
    }

    /// The newest finalized block seen so far.
    pub fn newest(&self) -> Option<Finalized> {
        self.inner.seen.lock().unwrap().newest
    }

    /// Wait until a finality update names `block_hash` and return its
    /// exact bytes. Fails when one names a later block number than
    /// `block_number` without this hash having been seen (finality moved
    /// past us, or finalized another block at our height), or at
    /// `deadline`.
    pub fn wait_for(
        &self,
        block_hash: B256,
        block_number: u64,
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, String> {
        let mut s = self.inner.seen.lock().unwrap();
        loop {
            if let Some((_, b)) = s.by_hash.get(&block_hash) {
                return Ok(b.clone());
            }
            if let Some(n) = s.newest {
                if n.block_number >= block_number {
                    return Err(format!(
                        "finality named block {} ({}) without naming ours, block {block_number} ({block_hash})",
                        n.block_number, n.block_hash
                    ));
                }
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(format!(
                    "no finality update named block {block_number} within the wait; newest finalized {}, {} polls{}",
                    s.newest
                        .map(|n| n.block_number.to_string())
                        .unwrap_or_else(|| "none".into()),
                    s.polls,
                    s.last_error
                        .as_ref()
                        .map(|e| format!(", last error: {e}"))
                        .unwrap_or_default()
                ));
            }
            s = self
                .inner
                .changed
                .wait_timeout(s, deadline - now)
                .unwrap()
                .0;
        }
    }
}

impl Drop for FinalityWatch {
    fn drop(&mut self) {
        self.inner
            .stop
            .store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Wait for the beacon node at `beacon` to serve a finality update naming
/// `block_hash` (polling every `every`, for at most `timeout`) and return
/// its exact bytes; see [`FinalityWatch::wait_for`] for when it fails.
pub fn wait_for_finality(
    beacon: &str,
    block_hash: B256,
    block_number: u64,
    timeout: Duration,
    every: Duration,
) -> Result<Vec<u8>, String> {
    let w = FinalityWatch::start(beacon, every);
    w.wait_for(
        block_hash,
        block_number,
        std::time::Instant::now() + timeout,
    )
}
