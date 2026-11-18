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
        let n = named_of(Tier::Finalized, &f).unwrap();
        assert_eq!(n.head.block_number, 26_334_487);
        assert!(
            named_of(Tier::Finalized, &o).is_err(),
            "no finalized header"
        );
    }
}
