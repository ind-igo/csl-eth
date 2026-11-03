//! The producer's side: pull the light-client objects from a beacon node's
//! API and lay them out as the bucket's head files. The node is a source
//! of bytes, not of trust; whatever it returns is verified by `verify`
//! before any client acts on it, and the fetch verifies the set it wrote
//! before returning so a bad node is caught here rather than downstream.

use crate::{paths, verify, Chain, DirSource, HeadError, Tier, VerifiedHead};
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

/// What a finality update names: the finalized execution block. Also what
/// an optimistic update names, its attested block (see [`named_of`]).
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
    named_of(Tier::Finalized, bytes).map(|n| n.head)
}

/// What a tier's update names, read from its JSON without verifying.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Named {
    /// The head header: finalized for a finality update, attested for an
    /// optimistic one.
    pub head: Finalized,
    pub signature_slot: u64,
    /// Sync committee members whose bits are set.
    pub participants: u32,
}

/// The head a finality update (`Tier::Finalized`) or an optimistic update
/// (`Tier::Attested`) names, with its signature slot and participation.
pub fn named_of(tier: Tier, bytes: &[u8]) -> Result<Named, String> {
    let v: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let what = match tier {
        Tier::Finalized => "finality update",
        Tier::Attested => "optimistic update",
    };
    let h = &v["data"][match tier {
        Tier::Finalized => "finalized_header",
        Tier::Attested => "attested_header",
    }];
    let slot = json_u64(&h["beacon"]["slot"]).ok_or(format!("{what} without a slot"))?;
    let block_number = json_u64(&h["execution"]["block_number"])
        .ok_or(format!("{what} without an execution block number"))?;
    let block_hash = h["execution"]["block_hash"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(format!("{what} without an execution block hash"))?;
    let signature_slot =
        json_u64(&v["data"]["signature_slot"]).ok_or(format!("{what} without a signature slot"))?;
    let bits = v["data"]["sync_aggregate"]["sync_committee_bits"]
        .as_str()
        .and_then(|b| hex::decode(b.trim_start_matches("0x")).ok())
        .ok_or(format!("{what} without sync committee bits"))?;
    Ok(Named {
        head: Finalized {
            slot,
            block_number,
            block_hash,
        },
        signature_slot,
        participants: bits.iter().map(|b| b.count_ones()).sum(),
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

    /// The node's current optimistic update, its exact response bytes.
    pub fn optimistic_update(&self) -> Result<Vec<u8>, String> {
        self.get("/eth/v1/beacon/light_client/optimistic_update")
    }

    /// The node's current update for `tier`.
    pub fn head_update(&self, tier: Tier) -> Result<Vec<u8>, String> {
        match tier {
            Tier::Finalized => self.finality_update(),
            Tier::Attested => self.optimistic_update(),
        }
    }
}

/// One tier's updates as a beacon node serves them, polled in the
/// background and kept by the block they name.
///
/// A node serves only its newest update. The finality update naming a
/// given block exists for one epoch (6.4 minutes) about 13 to 19 minutes
/// after that block; the optimistic update attesting a block, for about
/// one slot, from the slot after it (the next block carries the sync
/// aggregate that signs it). A producer must already be watching, or the
/// bytes are gone. For each block the watch keeps the bytes with the most
/// participants and the time it first saw any.
pub struct UpdateWatch {
    tier: Tier,
    inner: std::sync::Arc<WatchInner>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// The finality watch: an [`UpdateWatch`] over `Tier::Finalized`.
pub type FinalityWatch = UpdateWatch;

struct WatchInner {
    stop: std::sync::atomic::AtomicBool,
    seen: std::sync::Mutex<WatchSeen>,
    changed: std::sync::Condvar,
}

/// One block a watch has seen named.
#[derive(Clone, Debug)]
pub struct Seen {
    pub named: Named,
    pub bytes: Vec<u8>,
    /// When the watch first saw an update naming this block.
    pub first_seen: std::time::SystemTime,
}

#[derive(Default)]
struct WatchSeen {
    by_hash: std::collections::HashMap<B256, Seen>,
    /// The highest block number seen named.
    newest: Option<Finalized>,
    polls: u64,
    last_error: Option<String>,
}

/// How long a watch keeps a block it saw: long enough for a producer to
/// come back to it after a slow cycle.
const WATCH_KEEP: Duration = Duration::from_secs(2 * 3600);

impl UpdateWatch {
    /// Start polling `beacon`'s finality update every `every`.
    pub fn start(beacon: &str, every: Duration) -> UpdateWatch {
        UpdateWatch::start_tier(beacon, Tier::Finalized, every)
    }

    /// Start polling `beacon`'s update for `tier` every `every`.
    pub fn start_tier(beacon: &str, tier: Tier, every: Duration) -> UpdateWatch {
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
                    .head_update(tier)
                    .and_then(|b| named_of(tier, &b).map(|n| (n, b)));
                {
                    let mut s = w.seen.lock().unwrap();
                    s.polls += 1;
                    match got {
                        Ok((n, b)) => s.record(n, b, std::time::SystemTime::now()),
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
        UpdateWatch {
            tier,
            inner,
            thread: Some(thread),
        }
    }

    /// The tier this watch polls.
    pub fn tier(&self) -> Tier {
        self.tier
    }

    /// The newest block seen named so far.
    pub fn newest(&self) -> Option<Finalized> {
        self.inner.seen.lock().unwrap().newest
    }

    /// What the watch kept for `block_hash`, if an update named it.
    pub fn get(&self, block_hash: &B256) -> Option<Seen> {
        self.inner
            .seen
            .lock()
            .unwrap()
            .by_hash
            .get(block_hash)
            .cloned()
    }

    /// Polls so far and the last poll's error, if it failed.
    pub fn health(&self) -> (u64, Option<String>) {
        let s = self.inner.seen.lock().unwrap();
        (s.polls, s.last_error.clone())
    }

    /// Wait until an update names `block_hash` and return its exact bytes.
    /// Fails when one names a block number at or past `block_number`
    /// without this hash having been seen (the chain moved past us, or
    /// settled another block at our height), or at `deadline`.
    pub fn wait_for(
        &self,
        block_hash: B256,
        block_number: u64,
        deadline: std::time::Instant,
    ) -> Result<Vec<u8>, String> {
        self.wait_seen(block_hash, block_number, deadline)
            .map(|s| s.bytes)
    }

    /// [`UpdateWatch::wait_for`], returning what the watch kept: the bytes,
    /// what they name and when the block was first seen. The bytes are the
    /// best-signed seen so far; [`UpdateWatch::get`] later may hold better.
    pub fn wait_seen(
        &self,
        block_hash: B256,
        block_number: u64,
        deadline: std::time::Instant,
    ) -> Result<Seen, String> {
        let what = match self.tier {
            Tier::Finalized => "finality",
            Tier::Attested => "an optimistic update",
        };
        let mut s = self.inner.seen.lock().unwrap();
        loop {
            if let Some(seen) = s.by_hash.get(&block_hash) {
                return Ok(seen.clone());
            }
            if let Some(n) = s.newest {
                if n.block_number >= block_number {
                    return Err(format!(
                        "{what} named block {} ({}) without naming ours, block {block_number} ({block_hash})",
                        n.block_number, n.block_hash
                    ));
                }
            }
            let now = std::time::Instant::now();
            if now >= deadline {
                return Err(format!(
                    "no {} named block {block_number} within the wait; newest {}, {} polls{}",
                    match self.tier {
                        Tier::Finalized => "finality update",
                        Tier::Attested => "optimistic update",
                    },
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

impl WatchSeen {
    fn record(&mut self, n: Named, bytes: Vec<u8>, at: std::time::SystemTime) {
        if self
            .newest
            .is_none_or(|x| n.head.block_number > x.block_number)
        {
            self.newest = Some(n.head);
        }
        match self.by_hash.entry(n.head.block_hash) {
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(Seen {
                    named: n,
                    bytes,
                    first_seen: at,
                });
            }
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let kept = e.get_mut();
                if n.participants > kept.named.participants {
                    kept.named = n;
                    kept.bytes = bytes;
                }
            }
        }
        self.by_hash.retain(|_, s| {
            at.duration_since(s.first_seen)
                .is_ok_and(|d| d < WATCH_KEEP)
        });
        self.last_error = None;
    }
}

impl Drop for UpdateWatch {
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
/// its exact bytes; see [`UpdateWatch::wait_for`] for when it fails.
pub fn wait_for_finality(
    beacon: &str,
    block_hash: B256,
    block_number: u64,
    timeout: Duration,
    every: Duration,
) -> Result<Vec<u8>, String> {
    let w = UpdateWatch::start(beacon, every);
    w.wait_for(
        block_hash,
        block_number,
        std::time::Instant::now() + timeout,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

    #[test]
    fn named_of_reads_each_tier_header() {
        let o = std::fs::read(format!("{FIX}/attested/optimistic.json")).unwrap();
        let n = named_of(Tier::Attested, &o).unwrap();
        assert_eq!(n.head.slot, 15_574_038);
        assert_eq!(n.head.block_number, 26_334_572);
        assert_eq!(n.signature_slot, 15_574_039);
        assert_eq!(n.participants, 510);
        let f = std::fs::read(format!("{FIX}/attested/finality.json")).unwrap();
        assert_eq!(finalized_of(&f).unwrap().block_number, 26_334_487);
        assert!(
            named_of(Tier::Finalized, &o).is_err(),
            "no finalized header"
        );
    }

    #[test]
    fn a_watch_keeps_the_best_signed_bytes_and_the_first_sighting() {
        let o = std::fs::read(format!("{FIX}/attested/optimistic.json")).unwrap();
        let n = named_of(Tier::Attested, &o).unwrap();
        let t0 = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let mut s = WatchSeen::default();
        let weaker = Named {
            participants: 400,
            ..n
        };
        s.record(weaker, b"weak".to_vec(), t0);
        s.record(n, o.clone(), t0 + Duration::from_secs(4));
        s.record(weaker, b"weak".to_vec(), t0 + Duration::from_secs(8));
        let kept = &s.by_hash[&n.head.block_hash];
        assert_eq!(kept.bytes, o);
        assert_eq!(kept.named.participants, 510);
        assert_eq!(kept.first_seen, t0);
        // Gone once older than the keep window.
        let other = Named {
            head: Finalized {
                block_hash: B256::repeat_byte(7),
                block_number: n.head.block_number + 1,
                ..n.head
            },
            ..n
        };
        s.record(other, vec![], t0 + WATCH_KEEP + Duration::from_secs(1));
        assert!(!s.by_hash.contains_key(&n.head.block_hash));
        assert_eq!(s.newest, Some(other.head));
    }
}
