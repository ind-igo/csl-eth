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
    let mut resp = agent.get(url).header("Accept", "application/json").call().map_err(|e| format!("GET {url}: {e}"))?;
    if resp.status() != 200 {
        return Err(format!("GET {url}: status {}", resp.status()));
    }
    resp.body_mut().with_config().limit(64 << 20).read_to_vec().map_err(|e| format!("GET {url} body: {e}"))
}

/// Write `head/` under `bucket` from the node at `beacon`: the bootstrap
/// for `checkpoint` (the node's current finalized checkpoint when `None`),
/// every period update from that checkpoint's period to now, and the
/// finality update. Returns what was written and the head it verifies to.
pub fn fetch_into(beacon: &str, bucket: &Path, checkpoint: Option<B256>) -> Result<Fetched, String> {
    let beacon = beacon.trim_end_matches('/');
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(60))).build().into();
    let chain = Chain::mainnet();

    let checkpoint = match checkpoint {
        Some(c) => c,
        None => {
            let v = get(&agent, &format!("{beacon}/eth/v1/beacon/states/finalized/finality_checkpoints"))?;
            serde_json::from_slice::<FinalityCheckpoints>(&v).map_err(|e| e.to_string())?.data.finalized.root
        }
    };

    let write = |rel: &str, bytes: &[u8]| -> Result<(), String> {
        let p = bucket.join(rel);
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
        }
        std::fs::write(&p, bytes).map_err(|e| format!("{}: {e}", p.display()))
    };

    let bootstrap = get(&agent, &format!("{beacon}/eth/v1/beacon/light_client/bootstrap/{checkpoint}"))?;
    let slot: u64 = serde_json::from_slice::<serde_json::Value>(&bootstrap)
        .ok()
        .and_then(|v| v["data"]["header"]["beacon"]["slot"].as_str().and_then(|s| s.parse().ok()))
        .ok_or("bootstrap without a slot")?;
    write(&paths::bootstrap(&checkpoint), &bootstrap)?;

    let now = std::time::SystemTime::now();
    let first = crate::period_of(slot);
    let last = crate::period_of(crate::current_slot(&chain, now));
    let mut updates = Vec::new();
    let mut period = first;
    while period <= last {
        let count = (last - period + 1).min(128);
        let v = get(&agent, &format!("{beacon}/eth/v1/beacon/light_client/updates?start_period={period}&count={count}"))?;
        let items: Vec<serde_json::Value> = serde_json::from_slice(&v).map_err(|e| e.to_string())?;
        if items.is_empty() {
            break;
        }
        for item in &items {
            let s: u64 = item["data"]["attested_header"]["beacon"]["slot"].as_str().and_then(|s| s.parse().ok()).ok_or("update without a slot")?;
            let p = crate::period_of(s);
            write(&paths::update(p), &serde_json::to_vec(item).map_err(|e| e.to_string())?)?;
            updates.push(p);
        }
        period += count;
    }

    let finality = get(&agent, &format!("{beacon}/eth/v1/beacon/light_client/finality_update"))?;
    write(paths::FINALITY, &finality)?;

    let head = verify(&DirSource(bucket.to_path_buf()), &chain, checkpoint, now).map_err(|e: HeadError| e.to_string())?;
    Ok(Fetched { checkpoint, updates, head })
}
