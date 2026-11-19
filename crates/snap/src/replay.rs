//! `csl-eth bal-replay`: reproduce recent blocks' state roots on a testnet
//! from their block access lists alone (EIP-7928), with no execution and
//! no RPC: the test of the access-list path the tracker uses
//! ([`crate::track`], `--bal`) against a real chain.
//!
//! From a block a little behind the head it goes forward one block at a
//! time, following the head as it moves. For each block it takes the
//! header by number from peers and requires it to be the child of the one
//! before (hash-linked; the first block's parent is the anchor, taken from
//! peers unchecked), fetches the block's list over `eth/71` and checks it
//! against the header's `block_access_list_hash`, applies it to the state
//! at the parent's root, and requires the header's `state_root`.
//!
//! The state is not held locally: the nodes an update reads are witness
//! nodes at the parent root, fetched from the same peers with snap/1
//! `GetTrieNodes` (each checked by hash) as the update asks for them, in
//! rounds. Nodes the updates wrote serve the next block, so a block only
//! fetches what is new to it. A block whose witness cannot be had, or whose
//! root does not match, ends a run of consecutive blocks; the replay
//! starts again from that block's header (trusting its `state_root`, which
//! later blocks then check).

use crate::{
    bal::{block_changes, checked_list, force_block, try_block, BlockChanges, Witness},
    heal::{self, Need, Pool},
    peer::Net,
    track::Source,
};
use alloy_consensus::Header;
use alloy_primitives::{keccak256, Bytes, B256};
use csl_eth_trie::{
    update::{Load, World},
    Nibbles,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

pub struct Config {
    pub net: Net,
    /// Blocks to replay.
    pub blocks: u64,
    /// Start this many blocks behind the head.
    pub back: u64,
    pub peers: usize,
    pub udp_port: u16,
    /// JSON lines: one per block, then a summary. The peer log goes next
    /// to it (`.peers.jsonl`).
    pub out: PathBuf,
    /// Give up after this long.
    pub max_wall: Duration,
    /// Peers that served, kept for the next run (Sepolia's are few).
    pub known: Option<PathBuf>,
}

/// Witness nodes by hash: fetched from peers, or written by an update.
struct Wit {
    map: HashMap<B256, Bytes>,
    missing: Vec<Need>,
}

impl Load for Wit {
    fn load(&mut self, owner: Option<B256>, path: &Nibbles, hash: &B256) -> Option<Vec<u8>> {
        match self.map.get(hash) {
            Some(b) => Some(b.to_vec()),
            None => {
                self.missing.push(Need {
                    owner,
                    path: *path,
                    hash: *hash,
                });
                None
            }
        }
    }
}

impl Witness for Wit {
    fn take_missing(&mut self) -> Vec<Need> {
        std::mem::take(&mut self.missing)
    }
}

/// Witness nodes kept across blocks at most; past this the map is
/// emptied and refilled from peers.
const WITNESS_CAP: usize = 4_000_000;
/// Fetch rounds per block before its witness counts as unavailable.
const MAX_ROUNDS: usize = 32;

/// The header at `number`, waiting for it up to `wait`.
async fn header_at(pool: &mut Pool, number: u64, wait: Duration) -> Option<Header> {
    let until = Instant::now() + wait;
    loop {
        if let Some(h) = pool.header(number).await {
            return Some(h);
        }
        if Instant::now() > until {
            return None;
        }
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// Apply `b` over the state at `parent`, fetching witness nodes at that
/// root as the update asks for them. Ok(rounds, nodes, bytes) once every
/// node it needed was had.
async fn apply(
    pool: &mut Pool,
    world: &mut World,
    wit: &mut Wit,
    b: &BlockChanges,
    parent: B256,
) -> Result<(usize, u64, u64), String> {
    let (mut nodes, mut bytes) = (0u64, 0u64);
    for round in 0..MAX_ROUNDS {
        match try_block(world, b, wit) {
            Ok(()) => return Ok((round, nodes, bytes)),
            Err(needs) => {
                let deadline = Instant::now() + Duration::from_secs(60);
                let got = Source::nodes(pool, parent, &needs, deadline).await;
                if got.is_empty() {
                    force_block(world, b, wit);
                    return Err(format!(
                        "witness unavailable: none of {} nodes served at the parent root (round {round})",
                        needs.len()
                    ));
                }
                for (i, n) in got {
                    if keccak256(&n) == needs[i].hash {
                        nodes += 1;
                        bytes += n.len() as u64;
                        wit.map.insert(needs[i].hash, n);
                    }
                }
            }
        }
    }
    force_block(world, b, wit);
    Err(format!("witness incomplete after {MAX_ROUNDS} rounds"))
}

fn dist(mut v: Vec<u64>) -> Value {
    if v.is_empty() {
        return Value::Null;
    }
    v.sort_unstable();
    let q = |p: usize| v[(v.len() - 1) * p / 100];
    let sum: u64 = v.iter().sum();
    json!({"min": v[0], "p50": q(50), "p90": q(90), "max": v[v.len() - 1], "mean": sum as f64 / v.len() as f64})
}

pub async fn run(cfg: Config) -> Result<Value, String> {
    let started = Instant::now();
    let mut out = File::create(&cfg.out).map_err(|e| format!("{}: {e}", cfg.out.display()))?;
    let mut emit = |v: &Value| {
        let _ = writeln!(out, "{v}");
        println!("{v}");
    };
    let mut pool = Pool::start(&heal::Config {
        peers: cfg.peers,
        udp_port: cfg.udp_port,
        out: cfg.out.with_extension("peers.jsonl"),
        known: cfg.known.clone(),
        net: cfg.net,
        eth71: true,
        ..heal::Config::default()
    })
    .map_err(|e| e.to_string())?;
    // A peer to start from.
    let t = Instant::now();
    let head = loop {
        if pool.connected() > 0 {
            if let Some(h) = pool.head_header().await {
                break h;
            }
        }
        if t.elapsed() > cfg.max_wall {
            return Err("no peer with a recent head".into());
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let first = head.number.saturating_sub(cfg.back);
    let mut prev = header_at(&mut pool, first - 1, Duration::from_secs(60))
        .await
        .ok_or("no anchor header")?;
    emit(&json!({"ev": "start", "chain": cfg.net.name(), "head": head.number, "first": first, "anchor_root": prev.state_root, "peers": pool.connected(), "secs": t.elapsed().as_secs_f64()}));
    let mut world = World::new(prev.state_root);
    let mut wit = Wit {
        map: HashMap::new(),
        missing: Vec::new(),
    };
    let mut rows: Vec<Value> = Vec::new();
    let (mut run, mut best, mut runs) = (0u64, 0u64, Vec::new());
    for n in first..first + cfg.blocks {
        if started.elapsed() > cfg.max_wall {
            emit(&json!({"ev": "stop", "reason": "max wall time", "at": n}));
            break;
        }
        let t0 = Instant::now();
        let Some(h) = header_at(&mut pool, n, Duration::from_secs(120)).await else {
            emit(&json!({"ev": "stop", "reason": "no header", "at": n}));
            break;
        };
        let hash = h.hash_slow();
        let mut row = json!({"ev": "block", "number": n, "hash": hash, "txs_root": h.transactions_root});
        if h.parent_hash != prev.hash_slow() {
            row["ok"] = json!(false);
            row["error"] = json!("not the child of the block before (a reorg); starting again here");
        }
        let Some(bh) = h.block_access_list_hash else {
            emit(&json!({"ev": "stop", "reason": "header has no block_access_list_hash", "at": n}));
            break;
        };
        let mut raw = None;
        for _ in 0..5 {
            match pool.access_lists(&[(hash, bh)], Duration::from_secs(60)).await {
                Some(v) if v[0].is_some() => {
                    raw = v.into_iter().next().flatten();
                    break;
                }
                _ => tokio::time::sleep(Duration::from_secs(2)).await,
            }
        }
        let list = match raw.as_deref().map(|r| checked_list(&h, r)) {
            Some(Ok(l)) => l,
            Some(Err(e)) => {
                emit(&json!({"ev": "stop", "reason": e, "at": n}));
                break;
            }
            None => {
                emit(&json!({"ev": "stop", "reason": "no peer served the list", "at": n}));
                break;
            }
        };
        let b = block_changes(&list);
        row["list_bytes"] = json!(raw.as_ref().map_or(0, |r| r.len()));
        row["list_accounts"] = json!(list.len());
        row["accounts_changed"] = json!(b.accounts.len());
        row["slots_written"] = json!(b.slots());
        row["slot_reads"] = json!(list.total_storage_reads());
        row["codes"] = json!(b.codes.len());
        if row["ok"] == json!(false) {
            // Not linked: start again from this block's header.
            world = World::new(h.state_root);
            run = 0;
        } else {
            let r = apply(&mut pool, &mut world, &mut wit, &b, prev.state_root).await;
            match r {
                Ok((rounds, nodes, bytes)) => {
                    row["rounds"] = json!(rounds);
                    row["witness_nodes"] = json!(nodes);
                    row["witness_bytes"] = json!(bytes);
                    let got = world.root();
                    row["computed_root"] = json!(got);
                    row["state_root"] = json!(h.state_root);
                    row["ok"] = json!(got == Some(h.state_root));
                    if got != Some(h.state_root) {
                        row["error"] = json!("state root mismatch");
                    }
                }
                Err(e) => {
                    row["ok"] = json!(false);
                    row["error"] = json!(e);
                }
            }
            if row["ok"] == json!(true) {
                run += 1;
                best = best.max(run);
                // Keep what the update wrote as witness for the next block,
                // and start the next from the root alone.
                if wit.map.len() > WITNESS_CAP {
                    wit.map.clear();
                }
                wit.map.extend(world.written());
                world = World::new(h.state_root);
            } else {
                if run > 0 {
                    runs.push(run);
                }
                run = 0;
                world = World::new(h.state_root);
            }
        }
        row["ms"] = json!(t0.elapsed().as_millis() as u64);
        row["peers"] = json!(pool.connected());
        emit(&row);
        rows.push(row);
        prev = h;
    }
    if run > 0 {
        runs.push(run);
    }
    let ok: Vec<&Value> = rows.iter().filter(|r| r["ok"] == json!(true)).collect();
    let g = |k: &str| -> Vec<u64> { rows.iter().filter_map(|r| r[k].as_u64()).collect() };
    let summary = json!({
        "ev": "summary",
        "chain": cfg.net.name(),
        "blocks": rows.len(),
        "reproduced": ok.len(),
        "longest_consecutive": best,
        "runs": runs,
        "first": rows.first().map(|r| r["number"].clone()),
        "last": rows.last().map(|r| r["number"].clone()),
        "failures": rows.iter().filter(|r| r["ok"] != json!(true)).map(|r| json!({"number": r["number"], "error": r["error"]})).collect::<Vec<_>>(),
        "list_bytes": dist(g("list_bytes")),
        "list_accounts": dist(g("list_accounts")),
        "accounts_changed": dist(g("accounts_changed")),
        "slots_written": dist(g("slots_written")),
        "slot_reads": dist(g("slot_reads")),
        "witness_nodes": dist(g("witness_nodes")),
        "witness_bytes": dist(g("witness_bytes")),
        "rounds": dist(g("rounds")),
        "ms": dist(g("ms")),
        "elapsed_s": started.elapsed().as_secs(),
    });
    emit(&summary);
    Ok(summary)
}
