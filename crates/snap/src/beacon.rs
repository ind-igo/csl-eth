//! `csl-eth beacon`: the producer of the accumulator route's files
//! (`csl_eth_store::beacon`), and its measurement against the walk.
//!
//! Inputs, none trusted:
//! - the head: the bucket's head files, verified from the checkpoint like
//!   a client would; its beacon header comes from the finality update and
//!   must hash to the verified root;
//! - the head state's `block_roots` and `historical_summaries`: Lodestar's
//!   state proof API (`/eth/v0/beacon/proof/state/{state_root}`, compact
//!   multiproofs), each verified against the head's state root. Lodestar
//!   serves it for the newest states only, so the producer captures at the
//!   head, while it is the head (`--capture` saves the answers to reuse);
//! - blocks, as SSZ from any beacon API (`/eth/v2/beacon/blocks/{root}`):
//!   each block's body proof must hash to the root the vector holds.
//!
//! Block roots proven by a head's ring are kept per period in the work
//! directory, so a period's vector is whole once heads over its span have
//! been seen; it is written when it hashes to the period's summary.

pub mod ssz;

use alloy_primitives::B256;
use clap::{Args as ClapArgs, Subcommand};
use csl_eth_client::{
    beacon::{slot_of_timestamp, AccumError, Accumulator, BeaconAnchor},
    head::verify_head,
    history::{Anchor, HeaderRoute, History, HistoryCost},
    DirDriver, Driver, Got, Store, VerifiedHead, Want,
};
use csl_eth_head::{Chain, DirSource};
use csl_eth_store::{
    beacon::{
        chunk_blocks, chunk_file, chunk_path, chunk_record_range, chunk_root, head_path,
        period_path, route, route_ranges, state_depth, summaries_file, summaries_path, top_records,
        vector_root, verify_block_hash, BeaconHeader, BodyProof, HeadPreamble, CAPELLA_PERIOD,
        CHUNKS_PER_PERIOD, CHUNK_SLOTS, HEAD_PREAMBLE, SLOTS_PER_HISTORICAL_ROOT,
        STATE_BLOCK_ROOTS, STATE_HISTORICAL_SUMMARIES,
    },
    history::{decode_header, tx_hash, Block},
    producer::write_atomic,
};
use rand::{seq::SliceRandom, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const DEFAULT_PROOF_BEACON: &str = "https://lodestar-mainnet.chainsafe.io";
pub const DEFAULT_BLOCK_BEACON: &str = "https://ethereum-beacon-api.publicnode.com";

#[derive(Subcommand, Debug)]
pub enum BeaconCmd {
    /// Write the accumulator files for the bucket's verified head: its
    /// head file, the summaries file, every closed period whose roots are
    /// all known, and the chunks asked for.
    Build(BuildArgs),
    /// Header and transaction reads by the walk and by the accumulator,
    /// over a history span, each checked against the block cache.
    Measure(MeasureArgs),
    /// The accumulator's fault table on real files: each lie, per target,
    /// must end `Insufficient` (forced) and correct (auto).
    Faults(MeasureArgs),
}

#[derive(ClapArgs, Debug)]
pub struct BuildArgs {
    /// The bucket: its head files name the head; the files go here.
    #[arg(long)]
    pub bucket: PathBuf,
    #[arg(long)]
    pub checkpoint: B256,
    /// Work directory: captures, proven roots, body proofs.
    #[arg(long)]
    pub work: PathBuf,
    /// The node with Lodestar's state proof API.
    #[arg(long, default_value = DEFAULT_PROOF_BEACON)]
    pub proof_beacon: String,
    /// Any beacon API serving SSZ blocks by root.
    #[arg(long, default_value = DEFAULT_BLOCK_BEACON)]
    pub block_beacon: String,
    /// Chunks to write, by slot: `a-b` ranges and single slots, commas.
    #[arg(long)]
    pub slots: Option<String>,
    /// Or the chunks of sampled blocks of a history producer's cache (and
    /// its anchor), as `measure` samples them.
    #[arg(long)]
    pub targets_from: Option<PathBuf>,
    #[arg(long, default_value_t = 40)]
    pub samples: usize,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// Parallel block fetches.
    #[arg(long, default_value_t = 8)]
    pub threads: usize,
    /// Verify the head as of this unix time instead of now.
    #[arg(long)]
    pub now: Option<u64>,
}

#[derive(ClapArgs, Debug)]
pub struct MeasureArgs {
    /// A bucket with the history span, the head files and `beacon/`.
    #[arg(long)]
    pub bucket: PathBuf,
    #[arg(long)]
    pub checkpoint: B256,
    /// The history producer's work directory: `anchor.json` and the
    /// verified block cache, for the expected answers.
    #[arg(long)]
    pub work: PathBuf,
    #[arg(long, default_value_t = 40)]
    pub samples: usize,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    #[arg(long)]
    pub now: Option<u64>,
    /// The auto router's threshold: the accumulator for headers at least
    /// this many blocks below what the walk holds.
    #[arg(long)]
    pub min_depth: Option<u64>,
}

pub fn run(cmd: BeaconCmd) -> Result<Value, String> {
    match cmd {
        BeaconCmd::Build(a) => build(&a),
        BeaconCmd::Measure(a) => measure(&a),
        BeaconCmd::Faults(a) => faults(&a),
    }
}

// ---------------------------------------------------------------------------
// Compact multiproofs (Lodestar's proof API)

fn bitlen(g: u64) -> u32 {
    64 - g.leading_zeros()
}

/// The nodes a multiproof of `gindices` carries, left to right.
pub fn proof_set(gindices: &[u64]) -> Vec<u64> {
    let mut proof = BTreeSet::new();
    let mut path = BTreeSet::new();
    for &g in gindices {
        proof.insert(g);
        let mut x = g;
        while x > 1 {
            proof.insert(x ^ 1);
            path.insert(x >> 1);
            x >>= 1;
        }
    }
    for g in gindices {
        path.remove(g);
    }
    let mut v: Vec<u64> = proof.difference(&path).copied().collect();
    let d = v.iter().map(|&g| bitlen(g)).max().unwrap_or(1);
    v.sort_by_key(|&g| g << (d - bitlen(g)));
    v
}

/// The descriptor naming that set: per node, its trailing zeros as `0`s
/// then a `1`, padded to bytes.
pub fn descriptor(gindices: &[u64]) -> Vec<u8> {
    let mut bits = Vec::new();
    for g in proof_set(gindices) {
        bits.extend(std::iter::repeat_n(false, g.trailing_zeros() as usize));
        bits.push(true);
    }
    bits.chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |a, (i, &b)| a | ((b as u8) << (7 - i)))
        })
        .collect()
}

/// Every node the proof gives or implies, checked to hash to `root`.
pub fn verify_multiproof(
    gindices: &[u64],
    leaves: &[B256],
    root: &B256,
) -> Result<HashMap<u64, B256>, String> {
    let set = proof_set(gindices);
    if set.len() != leaves.len() {
        return Err(format!(
            "{} leaves for {} proof nodes",
            leaves.len(),
            set.len()
        ));
    }
    let mut nodes: HashMap<u64, B256> = set.iter().copied().zip(leaves.iter().copied()).collect();
    let mut by_depth: BTreeMap<u32, Vec<u64>> = BTreeMap::new();
    for &g in &set {
        by_depth.entry(bitlen(g)).or_default().push(g);
    }
    while let Some((&d, _)) = by_depth.iter().next_back() {
        let gs = by_depth.remove(&d).expect("present");
        if d == 1 {
            break;
        }
        for g in gs {
            let p = g >> 1;
            if nodes.contains_key(&p) {
                continue;
            }
            let (Some(l), Some(r)) = (nodes.get(&(p << 1)), nodes.get(&((p << 1) | 1))) else {
                return Err(format!("node {g} has no sibling in the proof"));
            };
            let h = csl_eth_store::beacon::sha(l, r);
            nodes.insert(p, h);
            by_depth.entry(d - 1).or_default().push(p);
        }
    }
    match nodes.get(&1) {
        Some(r) if r == root => Ok(nodes),
        Some(r) => Err(format!("multiproof hashes to {r}, not {root}")),
        None => Err("multiproof reaches no root".into()),
    }
}

// ---------------------------------------------------------------------------
// HTTP

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(120)))
        .http_status_as_error(false)
        .build()
        .into()
}

/// GET with retries on 429 and 5xx. `Ok(None)` on 404.
fn get(agent: &ureq::Agent, url: &str, accept: &str) -> Result<Option<Vec<u8>>, String> {
    let mut last = String::new();
    for attempt in 0..8u32 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(500 * (1 << attempt.min(5))));
        }
        let mut resp = match agent.get(url).header("Accept", accept).call() {
            Ok(r) => r,
            Err(e) => {
                last = e.to_string();
                continue;
            }
        };
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .with_config()
            .limit(256 << 20)
            .read_to_vec()
            .map_err(|e| e.to_string());
        match status {
            200 => return body.map(Some),
            404 => return Ok(None),
            429 | 500..=599 => last = format!("status {status}"),
            s => return Err(format!("status {s}")),
        }
    }
    Err(last)
}

fn host(url: &str) -> &str {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
}

// ---------------------------------------------------------------------------
// The head state: captured proofs

fn b256(v: &Value) -> Result<B256, String> {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("not a root: {v}"))
}

/// A captured state proof: what was asked and what was answered.
fn load_capture(path: &Path, state_root: &B256) -> Result<HashMap<u64, B256>, String> {
    let v: Value = serde_json::from_slice(
        &std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?,
    )
    .map_err(|e| e.to_string())?;
    let gis: Vec<u64> = v["gindices"]
        .as_array()
        .ok_or("capture without gindices")?
        .iter()
        .map(|g| g.as_u64().ok_or("gindex"))
        .collect::<Result<_, _>>()?;
    let leaves: Vec<B256> = v["response"]["data"]["leaves"]
        .as_array()
        .ok_or("capture without leaves")?
        .iter()
        .map(b256)
        .collect::<Result<_, _>>()?;
    verify_multiproof(&gis, &leaves, state_root).map_err(|e| format!("{}: {e}", path.display()))
}

/// The proofs `build` needs from the head state, as named files under
/// `dir`: the ring's chunk nodes and the summaries list's length
/// (`top`), every ring leaf (`ring0..3`), every summary (`summaries*`).
fn capture_requests(head_slot: u64) -> Vec<(String, Vec<u64>)> {
    let fd = state_depth(head_slot) as u32;
    let field = |f: u64| (1u64 << fd) + f;
    let br = field(STATE_BLOCK_ROOTS);
    let hs = field(STATE_HISTORICAL_SUMMARIES);
    let len = (head_slot / SLOTS_PER_HISTORICAL_ROOT).saturating_sub(CAPELLA_PERIOD);
    let mut out = vec![(
        "top".to_string(),
        (0..CHUNKS_PER_PERIOD)
            .map(|c| br * CHUNKS_PER_PERIOD + c)
            .chain([hs * 2 + 1])
            .collect(),
    )];
    for k in 0..4u64 {
        out.push((
            format!("ring{k}"),
            (2048 * k..2048 * (k + 1)).map(|j| br * 8192 + j).collect(),
        ));
    }
    let items: Vec<u64> = (0..len).collect();
    for (k, part) in items.chunks(600).enumerate() {
        let mut gis = Vec::new();
        for &i in part {
            let g = hs * 2 * (1 << 24) + i;
            gis.extend([2 * g, 2 * g + 1]);
        }
        out.push((format!("summaries{k}"), gis));
    }
    out
}

fn capture(beacon: &str, state_root: &B256, head_slot: u64, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let a = agent();
    for (name, gis) in capture_requests(head_slot) {
        let p = dir.join(format!("{name}.json"));
        if p.exists() {
            continue;
        }
        let url = format!(
            "{}/eth/v0/beacon/proof/state/{state_root}?format=0x{}",
            beacon.trim_end_matches('/'),
            hex::encode(descriptor(&gis))
        );
        let body = get(&a, &url, "application/json")
            .map_err(|e| format!("{} state proof {name}: {e}", host(beacon)))?
            .ok_or_else(|| format!("{} has no state {state_root}", host(beacon)))?;
        let response: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
        let v =
            json!({"state_root": state_root.to_string(), "gindices": gis, "response": response});
        write_atomic(&p, v.to_string().as_bytes()).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// What the head state proves, from its captures.
struct HeadState {
    pre: HeadPreamble,
    /// The ring's 128 chunk roots, by ring position.
    ring_chunks: Vec<B256>,
    /// Block roots by slot, `head_slot - 8192 .. head_slot`.
    ring_roots: BTreeMap<u64, B256>,
    summaries: Vec<(B256, B256)>,
}

fn head_state(header: &BeaconHeader, dir: &Path) -> Result<HeadState, String> {
    let sr = header.state_root;
    let slot = header.slot;
    let mut nodes = HashMap::new();
    for (name, _) in capture_requests(slot) {
        nodes.extend(load_capture(&dir.join(format!("{name}.json")), &sr)?);
    }
    let fd = state_depth(slot) as u32;
    let field = |f: u64| (1u64 << fd) + f;
    let node = |g: u64| nodes.get(&g).copied().ok_or(format!("no node {g}"));
    let branch = |mut g: u64| -> Result<Vec<B256>, String> {
        let mut out = Vec::new();
        while g > 1 {
            out.push(node(g ^ 1)?);
            g >>= 1;
        }
        Ok(out)
    };
    let br = field(STATE_BLOCK_ROOTS);
    let hs = field(STATE_HISTORICAL_SUMMARIES);
    let len_leaf = node(hs * 2 + 1)?;
    let len = u64::from_le_bytes(len_leaf[..8].try_into().expect("8"));
    let pre = HeadPreamble {
        header: *header,
        block_roots_root: node(br)?,
        block_roots_branch: branch(br)?,
        summaries_data_root: node(hs * 2)?,
        summaries_len: len,
        summaries_branch: branch(hs)?,
    };
    let ring_chunks: Vec<B256> = (0..CHUNKS_PER_PERIOD)
        .map(|c| node(br * CHUNKS_PER_PERIOD + c))
        .collect::<Result<_, _>>()?;
    let mut ring_roots = BTreeMap::new();
    for s in slot.saturating_sub(SLOTS_PER_HISTORICAL_ROOT)..slot {
        ring_roots.insert(s, node(br * 8192 + s % 8192)?);
    }
    let summaries = (0..len)
        .map(|i| {
            let g = hs * 2 * (1 << 24) + i;
            Ok((node(2 * g)?, node(2 * g + 1)?))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let (_, list_root) = summaries_file(&summaries);
    if list_root != pre.summaries_root() {
        return Err("historical_summaries do not rebuild the list's root".into());
    }
    pre.verify(slot, &header.root())?;
    Ok(HeadState {
        pre,
        ring_chunks,
        ring_roots,
        summaries,
    })
}

/// The head's beacon header, from the finality update the head verified
/// from; it must hash to the verified root.
fn head_header(bucket: &Path, head: &VerifiedHead) -> Result<BeaconHeader, String> {
    let v: Value = serde_json::from_slice(
        &std::fs::read(bucket.join(csl_eth_head::paths::FINALITY)).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let b = &v["data"]["finalized_header"]["beacon"];
    let u = |k: &str| -> Result<u64, String> {
        b[k].as_str()
            .and_then(|s| s.parse().ok())
            .ok_or(format!("beacon header {k}"))
    };
    let h = BeaconHeader {
        slot: u("slot")?,
        proposer_index: u("proposer_index")?,
        parent_root: b256(&b["parent_root"])?,
        state_root: b256(&b["state_root"])?,
        body_root: b256(&b["body_root"])?,
    };
    if h.root() != head.beacon_root || h.slot != head.slot {
        return Err("the finality update's header is not the verified head".into());
    }
    Ok(h)
}

// ---------------------------------------------------------------------------
// Proven roots, kept per period

fn roots_path(work: &Path, period: u64) -> PathBuf {
    work.join("roots").join(period.to_string())
}

fn load_roots(work: &Path, period: u64) -> Vec<B256> {
    match std::fs::read(roots_path(work, period)) {
        Ok(b) if b.len() == 8192 * 32 => b.chunks(32).map(B256::from_slice).collect(),
        _ => vec![B256::ZERO; 8192],
    }
}

/// Merge roots proven to a head into the work directory; a root that
/// disagrees with one kept is an error (two verified heads cannot).
fn keep_roots(work: &Path, roots: &BTreeMap<u64, B256>) -> Result<(), String> {
    let mut by_period: BTreeMap<u64, Vec<(u64, B256)>> = BTreeMap::new();
    for (&s, &r) in roots {
        by_period
            .entry(s / SLOTS_PER_HISTORICAL_ROOT)
            .or_default()
            .push((s, r));
    }
    for (p, rs) in by_period {
        let mut v = load_roots(work, p);
        for (s, r) in rs {
            let i = (s % SLOTS_PER_HISTORICAL_ROOT) as usize;
            if v[i] != B256::ZERO && v[i] != r {
                return Err(format!(
                    "slot {s}: kept root {} but the head proves {r}",
                    v[i]
                ));
            }
            v[i] = r;
        }
        let bytes: Vec<u8> = v.iter().flat_map(|r| r.0).collect();
        std::fs::create_dir_all(work.join("roots")).map_err(|e| e.to_string())?;
        write_atomic(&roots_path(work, p), &bytes).map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Body proofs, from SSZ blocks

fn body_cache(work: &Path, root: &B256) -> PathBuf {
    work.join("bodies").join(root.to_string())
}

fn encode_body(b: &BodyProof) -> Value {
    let s = |v: &[B256]| v.iter().map(|r| r.to_string()).collect::<Vec<_>>();
    json!({"slot": b.slot, "block_root": b.block_root.to_string(),
        "block_hash": b.block_hash.to_string(), "payload": s(&b.payload),
        "body": s(&b.body), "header": s(&b.header)})
}

fn decode_body(v: &Value) -> Option<BodyProof> {
    let rs =
        |k: &str| -> Option<Vec<B256>> { v[k].as_array()?.iter().map(|x| b256(x).ok()).collect() };
    Some(BodyProof {
        slot: v["slot"].as_u64()?,
        block_root: b256(&v["block_root"]).ok()?,
        block_hash: b256(&v["block_hash"]).ok()?,
        payload: rs("payload")?,
        body: rs("body")?.try_into().ok()?,
        header: rs("header")?.try_into().ok()?,
    })
}

/// Body proofs for `roots`, from the cache or fetched (in parallel), each
/// hashing to its root.
fn bodies(
    work: &Path,
    beacon: &str,
    roots: &BTreeSet<B256>,
    threads: usize,
) -> Result<(HashMap<B256, BodyProof>, u64, u64), String> {
    std::fs::create_dir_all(work.join("bodies")).map_err(|e| e.to_string())?;
    let mut out = HashMap::new();
    let mut todo = Vec::new();
    for r in roots {
        let cached = std::fs::read(body_cache(work, r))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| decode_body(&v))
            .filter(|b| b.block_root == *r && b.root() == *r);
        match cached {
            Some(b) => {
                out.insert(*r, b);
            }
            None => todo.push(*r),
        }
    }
    let fetched = todo.len() as u64;
    let queue = Mutex::new(todo);
    let done = Mutex::new((Vec::new(), 0u64));
    let failed: Mutex<Option<String>> = Mutex::new(None);
    let a = agent();
    let base = beacon.trim_end_matches('/');
    std::thread::scope(|sc| {
        for _ in 0..threads.max(1) {
            sc.spawn(|| loop {
                if failed.lock().unwrap().is_some() {
                    return;
                }
                let Some(r) = queue.lock().unwrap().pop() else {
                    return;
                };
                let url = format!("{base}/eth/v2/beacon/blocks/{r}");
                let res = get(
                    &a,
                    &url,
                    "application/octet-stream;q=1, application/json;q=0.9",
                )
                .and_then(|b| b.ok_or_else(|| "not found".to_string()))
                .and_then(|b| {
                    let n = b.len() as u64;
                    ssz::body_proof_any(&b).map(|p| (p, n))
                });
                match res {
                    Ok((p, _)) if p.block_root != r => {
                        *failed.lock().unwrap() = Some(format!(
                            "{} served block {} for root {r}",
                            host(beacon),
                            p.block_root
                        ));
                    }
                    Ok((p, n)) => {
                        let _ = write_atomic(
                            &body_cache(work, &r),
                            encode_body(&p).to_string().as_bytes(),
                        );
                        let mut d = done.lock().unwrap();
                        d.0.push(p);
                        d.1 += n;
                    }
                    Err(e) => {
                        *failed.lock().unwrap() = Some(format!("{} block {r}: {e}", host(beacon)));
                    }
                }
            });
        }
    });
    if let Some(e) = failed.into_inner().unwrap() {
        return Err(e);
    }
    let (ps, bytes) = done.into_inner().unwrap();
    for p in ps {
        out.insert(p.block_root, p);
    }
    Ok((out, fetched, bytes))
}

// ---------------------------------------------------------------------------
// Build

fn parse_slots(s: &str) -> Result<BTreeSet<u64>, String> {
    let mut out = BTreeSet::new();
    for part in s.split(',').filter(|p| !p.is_empty()) {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a, b),
            None => (part, part),
        };
        let a: u64 = a.trim().parse().map_err(|_| format!("slot {a}"))?;
        let b: u64 = b.trim().parse().map_err(|_| format!("slot {b}"))?;
        for c in a / CHUNK_SLOTS..=b / CHUNK_SLOTS {
            out.insert(c);
        }
    }
    Ok(out)
}

fn now_of(n: Option<u64>) -> SystemTime {
    n.map_or_else(SystemTime::now, |s| UNIX_EPOCH + Duration::from_secs(s))
}

fn write(bucket: &Path, rel: &str, b: &[u8]) -> Result<(), String> {
    let p = bucket.join(rel);
    std::fs::create_dir_all(p.parent().expect("parent")).map_err(|e| e.to_string())?;
    write_atomic(&p, b).map_err(|e| format!("{}: {e}", p.display()))
}

fn build(a: &BuildArgs) -> Result<Value, String> {
    let t0 = Instant::now();
    let head = csl_eth_head::verify(
        &DirSource(a.bucket.clone()),
        &Chain::mainnet(),
        a.checkpoint,
        now_of(a.now),
    )
    .map_err(|e| format!("head: {e}"))?;
    let header = head_header(&a.bucket, &head)?;
    let cap = a.work.join("state").join(head.slot.to_string());
    capture(&a.proof_beacon, &header.state_root, head.slot, &cap)?;
    let hs = head_state(&header, &cap)?;
    keep_roots(&a.work, &hs.ring_roots)?;
    let head_period = head.slot / SLOTS_PER_HISTORICAL_ROOT;
    let mut written: Vec<String> = Vec::new();

    // The summaries file, for this list length.
    let sp = summaries_path(hs.pre.summaries_len);
    if !a.bucket.join(&sp).exists() {
        write(&a.bucket, &sp, &summaries_file(&hs.summaries).0)?;
        written.push(sp);
    }

    // Closed periods whose roots are all proven: their vector must be the
    // summary's.
    let mut periods = Vec::new();
    for p in CAPELLA_PERIOD..head_period {
        let path = roots_path(&a.work, p);
        if !path.exists() {
            continue;
        }
        let v = load_roots(&a.work, p);
        if v.contains(&B256::ZERO) {
            continue;
        }
        let chunks: Vec<B256> = v.chunks(CHUNK_SLOTS as usize).map(chunk_root).collect();
        let want = hs.summaries[(p - CAPELLA_PERIOD) as usize].0;
        if vector_root(&chunks) != want {
            return Err(format!("period {p}: kept roots do not hash to its summary"));
        }
        let pp = period_path(p);
        if !a.bucket.join(&pp).exists() {
            write(&a.bucket, &pp, &top_records(&chunks))?;
            written.push(pp);
        }
        periods.push(p);
    }

    // The chunks asked for: whole, below the head, roots all proven.
    let mut chunks = match (&a.slots, &a.targets_from) {
        (Some(s), _) => parse_slots(s)?,
        (None, Some(w)) => targets(w, a.samples, a.seed)?
            .iter()
            .map(|t| t.slot / CHUNK_SLOTS)
            .collect(),
        (None, None) => BTreeSet::new(),
    };
    let mut skipped = Vec::new();
    let mut plan: BTreeMap<u64, Vec<B256>> = BTreeMap::new();
    for &c in &chunks {
        let s0 = c * CHUNK_SLOTS;
        let p = s0 / SLOTS_PER_HISTORICAL_ROOT;
        let v = load_roots(&a.work, p);
        let rs: Vec<B256> = (s0..s0 + CHUNK_SLOTS)
            .map(|s| v[(s % SLOTS_PER_HISTORICAL_ROOT) as usize])
            .collect();
        if s0 + CHUNK_SLOTS > head.slot || rs.contains(&B256::ZERO) {
            skipped.push(c);
            continue;
        }
        plan.insert(c, rs);
    }
    chunks.retain(|c| plan.contains_key(c));
    // One body per block: a root repeated at an empty slot has no block of
    // its own, and the root a chunk opens on may be an earlier block's (a
    // predecessor, before Capella at Capella's first chunk), which
    // `chunk_file` verifies and gives no proof to.
    let need: BTreeSet<B256> = plan
        .iter()
        .filter(|(c, _)| !a.bucket.join(chunk_path(**c)).exists())
        .flat_map(|(_, rs)| chunk_blocks(rs))
        .collect();
    let (bodies, fetched, fetched_bytes) = bodies(&a.work, &a.block_beacon, &need, a.threads)?;
    for (&c, rs) in &plan {
        let cp = chunk_path(c);
        if a.bucket.join(&cp).exists() {
            continue;
        }
        write(&a.bucket, &cp, &chunk_file(c, rs, &bodies)?)?;
        written.push(cp);
    }

    // Every block of every chunk, through the files as written, to this
    // head, before the head file names them.
    let mut head_file = hs.pre.encode();
    head_file.extend_from_slice(&top_records(&hs.ring_chunks));
    let read = |rel: &str, off: u64, len: usize| -> Result<Vec<u8>, String> {
        if rel == head_path(&head.beacon_root) {
            return Ok(head_file[off as usize..off as usize + len].to_vec());
        }
        let b = std::fs::read(a.bucket.join(rel)).map_err(|e| format!("{rel}: {e}"))?;
        b.get(off as usize..off as usize + len)
            .map(<[u8]>::to_vec)
            .ok_or(format!("{rel}: short"))
    };
    let mut checked = 0u64;
    let mut unreachable = 0u64;
    for (&c, rs) in &plan {
        for (k, r) in rs.iter().enumerate() {
            let s = c * CHUNK_SLOTS + k as u64;
            if k > 0 && rs[k - 1] == *r {
                continue; // an empty slot
            }
            let b = &bodies.get(r).cloned().or_else(|| {
                std::fs::read(body_cache(&a.work, r))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .and_then(|v| decode_body(&v))
            });
            let Some(b) = b else {
                return Err(format!("no body proof for {r}"));
            };
            if b.slot != s {
                continue; // a predecessor: the root is an earlier block's
            }
            let Ok(rt) = route(head.slot, s) else {
                unreachable += 1;
                continue;
            };
            if let csl_eth_store::beacon::Route::Closed { period, .. } = rt {
                if !periods.contains(&period) {
                    unreachable += 1;
                    continue;
                }
            }
            let (cp, co, cl) = chunk_record_range(s);
            let tops: Vec<Vec<u8>> = route_ranges(hs.pre.summaries_len, &head.beacon_root, &rt)
                .iter()
                .map(|(p, o, l)| read(p, *o, *l))
                .collect::<Result<_, _>>()?;
            verify_block_hash(
                &hs.pre,
                s,
                &b.block_hash,
                &read(&cp, co, cl)?,
                &tops[0],
                tops.get(1).map(Vec::as_slice),
            )
            .map_err(|e| format!("self-check, slot {s}: {e}"))?;
            checked += 1;
        }
    }
    let hp = head_path(&head.beacon_root);
    write(&a.bucket, &hp, &head_file)?;
    written.push(hp);
    let ring_known = hs.ring_roots.len();
    Ok(json!({
        "head": {"slot": head.slot, "beacon_root": head.beacon_root.to_string(),
            "block_number": head.execution.block_number, "state_root": header.state_root.to_string()},
        "summaries_len": hs.pre.summaries_len,
        "ring_roots_proven": ring_known,
        "periods_written_or_present": periods,
        "chunks": chunks.len(),
        "chunks_skipped": skipped,
        "blocks_fetched": fetched,
        "block_bytes_fetched": fetched_bytes,
        "block_source": host(&a.block_beacon),
        "proof_source": host(&a.proof_beacon),
        "blocks_self_checked": checked,
        "blocks_unreachable_from_head": unreachable,
        "files_written": written.len(),
        "bytes": {
            "head_file": head_file.len(),
            "summaries_file": std::fs::metadata(a.bucket.join(summaries_path(hs.pre.summaries_len))).map(|m| m.len()).unwrap_or(0),
        },
        "secs": t0.elapsed().as_secs_f64(),
    }))
}

// ---------------------------------------------------------------------------
// Targets from a history producer's cache

#[derive(Clone, Debug)]
pub struct Target {
    pub number: u64,
    pub slot: u64,
    pub hash: B256,
    pub tx: Option<B256>,
}

fn cache_block(work: &Path, n: u64) -> Result<Block, String> {
    let p = work.join("blocks").join(n.to_string());
    let b = std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    let b = Block::decode(&b).ok_or(format!("block {n}: bad cache file"))?;
    b.verify().map_err(|e| e.to_string())?;
    Ok(b)
}

fn anchor_of(work: &Path) -> Result<Anchor, String> {
    let v: Value = serde_json::from_slice(
        &std::fs::read(work.join("anchor.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(Anchor {
        number: v["number"].as_u64().ok_or("anchor number")?,
        hash: b256(&v["hash"])?,
    })
}

/// Blocks at fixed depths below the anchor, then a sample of the span,
/// then the anchor itself.
fn targets(work: &Path, samples: usize, seed: u64) -> Result<Vec<Target>, String> {
    let anchor = anchor_of(work)?;
    let mut first = anchor.number;
    while work.join("blocks").join((first - 1).to_string()).exists() {
        first -= 1;
    }
    let mut ns: Vec<u64> = [64u64, 128, 256, 1024, 2048, 4096, 4, 8, 16, 32]
        .iter()
        .map(|d| anchor.number - d)
        .chain([first])
        .filter(|n| *n >= first)
        .collect();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut all: Vec<u64> = (first..anchor.number).collect();
    all.shuffle(&mut rng);
    ns.extend(all.into_iter().take(samples));
    ns.push(anchor.number);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for n in ns {
        if !seen.insert(n) {
            continue;
        }
        let b = cache_block(work, n)?;
        let h = decode_header(&b.header).map_err(|e| e.to_string())?;
        out.push(Target {
            number: n,
            slot: slot_of_timestamp(h.timestamp).ok_or("timestamp off the slot clock")?,
            hash: b.hash,
            tx: b.txs.first().map(|t| tx_hash(t)),
        });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Measure

fn cost_json(c: &HistoryCost) -> Value {
    json!({"requests": c.requests, "bytes": c.bytes, "rounds": c.rounds,
        "headers_verified": c.headers_verified, "by_accumulator": c.headers_by_accumulator,
        "accumulator_failures": c.accumulator_failures, "table_bytes": c.table_bytes})
}

fn open_at(
    bucket: &Path,
    checkpoint: B256,
    work: &Path,
    now: SystemTime,
) -> Result<(History<DirDriver>, VerifiedHead), String> {
    let d = DirDriver::new(bucket);
    let head = verify_head(&d, checkpoint, now).map_err(|e| format!("head: {e}"))?;
    let anchor = anchor_of(work)?;
    let mut h = History::open(d, anchor)?;
    h.set_beacon(BeaconAnchor::from(&head));
    Ok((h, head))
}

/// Prove the history span's anchor itself to the head: a span written
/// at a block the head is past is verified this way, not by a manifest
/// at the head's own block.
fn prove_anchor(
    bucket: &Path,
    beacon: BeaconAnchor,
    slot: u64,
    hash: &B256,
) -> (Result<(), AccumError>, (u64, u64, u32)) {
    let store = Store::new();
    let d = DirDriver::new(bucket);
    let mut a = Accumulator::new(beacon);
    store.begin_read();
    loop {
        match a.try_prove(&store, slot, hash) {
            Ok(r) => return (r, store.cost()),
            Err(_) => csl_eth_client::drive(&d, &store, true),
        }
    }
}

fn mean(v: &[f64]) -> f64 {
    if v.is_empty() {
        0.0
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

fn measure(a: &MeasureArgs) -> Result<Value, String> {
    let now = now_of(a.now);
    let (mut h, head) = open_at(&a.bucket, a.checkpoint, &a.work, now)?;
    if let Some(d) = a.min_depth {
        h.accum_min_depth = d;
    }
    let anchor = h.anchor();
    let ts = targets(&a.work, a.samples, a.seed)?;
    let beacon = BeaconAnchor::from(&head);
    let tgt_anchor = ts.last().expect("the anchor").clone();
    let (ar, ac) = prove_anchor(&a.bucket, beacon, tgt_anchor.slot, &tgt_anchor.hash);
    let mut rows = Vec::new();
    let mut agg: BTreeMap<&str, Vec<(f64, f64, f64)>> = BTreeMap::new();
    for t in &ts[..ts.len() - 1] {
        let depth = anchor.number - t.number;
        let slots_back = head.slot - t.slot;
        let mut row = json!({"block": t.number, "slot": t.slot, "depth": depth,
            "slots_below_head": slots_back,
            "route": route(head.slot, t.slot).map(|r| format!("{r:?}")).unwrap_or_else(|e| e)});
        for (name, r) in [
            ("walk", HeaderRoute::Walk),
            ("accumulator", HeaderRoute::Accumulator),
            ("auto", HeaderRoute::Auto),
        ] {
            h.route = r;
            h.forget();
            let (got, c) = h.header(t.number);
            let ok = matches!(&got, Ok(x) if x.hash == t.hash);
            if let Err(e) = &got {
                row[name] = json!({"error": e.to_string()});
                continue;
            }
            if !ok {
                return Err(format!(
                    "block {}: {name} returned a wrong header",
                    t.number
                ));
            }
            row[name] = cost_json(&c);
            agg.entry(name)
                .or_default()
                .push((c.bytes as f64, c.requests as f64, c.rounds as f64));
            if let Some(tx) = &t.tx {
                if r != HeaderRoute::Accumulator {
                    h.forget();
                    let (got, c) = h.tx(tx);
                    match got {
                        Ok(x) if x.block_hash == t.hash => {
                            row[format!("tx_{name}")] = cost_json(&c);
                            agg.entry(if r == HeaderRoute::Walk {
                                "tx_walk"
                            } else {
                                "tx_auto"
                            })
                            .or_default()
                            .push((
                                c.bytes as f64,
                                c.requests as f64,
                                c.rounds as f64,
                            ));
                        }
                        Ok(_) => return Err(format!("tx in block {}: wrong block", t.number)),
                        Err(e) => row[format!("tx_{name}")] = json!({"error": e.to_string()}),
                    }
                }
            }
        }
        rows.push(row);
    }
    let summary: BTreeMap<&str, Value> = agg
        .iter()
        .map(|(k, v)| {
            let b: Vec<f64> = v.iter().map(|x| x.0).collect();
            let q: Vec<f64> = v.iter().map(|x| x.1).collect();
            let r: Vec<f64> = v.iter().map(|x| x.2).collect();
            (
                *k,
                json!({"reads": v.len(), "mean_bytes": mean(&b), "mean_requests": mean(&q),
                "mean_rounds": mean(&r), "max_bytes": b.iter().cloned().fold(0.0, f64::max)}),
            )
        })
        .collect();
    Ok(json!({
        "head": {"slot": head.slot, "beacon_root": head.beacon_root.to_string(),
            "block_number": head.execution.block_number},
        "anchor": {"number": anchor.number, "hash": anchor.hash.to_string(), "slot": tgt_anchor.slot,
            "proven_to_head": ar.as_ref().map(|_| true).map_err(|e| e.to_string()),
            "proof_cost": {"requests": ac.0, "bytes": ac.1, "rounds": ac.2}},
        "summary": summary,
        "reads": rows,
    }))
}

// ---------------------------------------------------------------------------
// Faults on real files

/// The bucket with one file's bytes changed or removed.
struct Lying {
    base: DirDriver,
    rel: String,
    bytes: Option<Vec<u8>>,
}

impl Driver for Lying {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        wants
            .iter()
            .map(|w| {
                if w.rel() != self.rel {
                    return self.base.fetch(std::slice::from_ref(w)).remove(0);
                }
                match (&self.bytes, w) {
                    (None, Want::File { .. }) => Ok(None),
                    (None, Want::Range { .. }) => Err(format!("{}: not found", self.rel)),
                    (Some(b), Want::File { .. }) => Ok(Some(b.clone())),
                    (Some(b), Want::Range { off, len, .. }) => b
                        .get(*off as usize..*off as usize + len)
                        .map(|v| Some(v.to_vec()))
                        .ok_or("short".into()),
                }
            })
            .collect()
    }
}

fn faults(a: &MeasureArgs) -> Result<Value, String> {
    let now = now_of(a.now);
    let (h0, head) = open_at(&a.bucket, a.checkpoint, &a.work, now)?;
    let anchor = h0.anchor();
    drop(h0);
    let ts = targets(&a.work, a.samples, a.seed)?;
    // One target per route the head reaches.
    let mut picked: Vec<Target> = Vec::new();
    for t in &ts {
        let Ok(r) = route(head.slot, t.slot) else {
            continue;
        };
        let kind = matches!(r, csl_eth_store::beacon::Route::Ring { .. });
        if t.number + 64 <= anchor.number
            && !picked.iter().any(|p| {
                matches!(
                    route(head.slot, p.slot),
                    Ok(csl_eth_store::beacon::Route::Ring { .. })
                ) == kind
            })
        {
            picked.push(t.clone());
        }
    }
    let read = |rel: &str| std::fs::read(a.bucket.join(rel)).map_err(|e| format!("{rel}: {e}"));
    let flip = |mut b: Vec<u8>, at: usize| {
        b[at] ^= 0x40;
        b
    };
    let mut table = Vec::new();
    let (mut wrong, mut fired) = (0, 0);
    for t in &picked {
        let rt = route(head.slot, t.slot)?;
        let (cp, co, _) = chunk_record_range(t.slot);
        let co = co as usize;
        let hp = head_path(&head.beacon_root);
        let pos = (rt.chunk() % CHUNKS_PER_PERIOD) as usize;
        let mut lies: Vec<(&str, String, Option<Vec<u8>>)> = vec![
            (
                "wrong root in the chunk's vector",
                cp.clone(),
                Some(flip(read(&cp)?, co + 7)),
            ),
            (
                "wrong payload proof",
                cp.clone(),
                Some(flip(read(&cp)?, co + 6 * 32 + 3)),
            ),
            (
                "wrong body proof",
                cp.clone(),
                Some(flip(read(&cp)?, co + 11 * 32 + 3)),
            ),
            (
                "wrong header proof",
                cp.clone(),
                Some(flip(read(&cp)?, co + 17 * 32 + 3)),
            ),
            ("another slot's record", cp.clone(), {
                let mut b = read(&cp)?;
                let other = if co >= 576 { co - 576 } else { co + 576 };
                let r = b[other..other + 576].to_vec();
                b[co..co + 576].copy_from_slice(&r);
                Some(b)
            }),
            ("missing chunk", cp.clone(), None),
            (
                "wrong state branch",
                hp.clone(),
                Some(flip(read(&hp)?, 152 + 3 * 32)),
            ),
            ("summaries length off by one", hp.clone(), {
                let mut b = read(&hp)?;
                let v = u64::from_le_bytes(b[376..384].try_into().unwrap()) + 1;
                b[376..384].copy_from_slice(&v.to_le_bytes());
                Some(b)
            }),
            ("missing head file", hp.clone(), None),
        ];
        match rt {
            csl_eth_store::beacon::Route::Ring { .. } => lies.push((
                "wrong root in the ring",
                hp.clone(),
                Some(flip(read(&hp)?, HEAD_PREAMBLE + pos * 224 + 9)),
            )),
            csl_eth_store::beacon::Route::Closed { period, index, .. } => {
                let pp = period_path(period);
                lies.push((
                    "wrong root in the period",
                    pp.clone(),
                    Some(flip(read(&pp)?, pos * 224 + 33)),
                ));
                let sp = summaries_path(head.slot / SLOTS_PER_HISTORICAL_ROOT - CAPELLA_PERIOD);
                let sb = read(&sp)?;
                let rl = csl_eth_store::beacon::summary_record_len(
                    head.slot / SLOTS_PER_HISTORICAL_ROOT - CAPELLA_PERIOD,
                );
                lies.push((
                    "wrong summary",
                    sp.clone(),
                    Some(flip(sb.clone(), index as usize * rl + 1)),
                ));
                lies.push(("missing summaries", sp, None));
            }
        }
        for (name, rel, bytes) in lies {
            let mut res = json!({"block": t.number, "route": format!("{rt:?}"), "lie": name});
            for (mode, r) in [
                ("forced", HeaderRoute::Accumulator),
                ("auto", HeaderRoute::Auto),
            ] {
                let d = Lying {
                    base: DirDriver::new(&a.bucket),
                    rel: rel.clone(),
                    bytes: bytes.clone(),
                };
                let mut h = History::open(d, anchor)?;
                h.set_beacon(BeaconAnchor::from(&head));
                h.route = r;
                let (got, c) = h.header(t.number);
                let out = match got {
                    Ok(x) if x.hash == t.hash => "correct".to_string(),
                    Ok(_) => {
                        wrong += 1;
                        "WRONG".to_string()
                    }
                    Err(e) => {
                        if mode == "forced" {
                            fired += 1;
                        }
                        format!("insufficient: {e}")
                    }
                };
                res[mode] = json!({"outcome": out, "bytes": c.bytes, "accumulator_failures": c.accumulator_failures});
            }
            table.push(res);
        }
    }
    Ok(
        json!({"head_slot": head.slot, "targets": picked.iter().map(|t| t.number).collect::<Vec<_>>(),
        "lies": table.len(), "forced_insufficient": fired, "wrong": wrong, "pass": wrong == 0, "table": table}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use csl_eth_store::beacon::{levels, sha};

    #[test]
    fn descriptors_match_the_spec_encoding() {
        // Reference values from an independent implementation; the long
        // one is the `top` request at depth-6 state fields, the descriptor
        // Lodestar echoed back on mainnet.
        assert_eq!(descriptor(&[2]), vec![0x60]);
        assert_eq!(descriptor(&[5]), vec![0x38]);
        assert_eq!(descriptor(&[17, 22]), vec![0x0e, 0xb8]);
        let top = &capture_requests(15_662_720)[0].1;
        assert_eq!(top.len(), 129);
        assert_eq!(proof_set(top).len(), 139);
        assert_eq!(
            hex::encode(descriptor(top)),
            "0901b36366c366c6cd8366c6cd86cd8d9b0366c6cd86cd8d9b06cd8d9b0d9b1b37a578"
        );
    }

    #[test]
    fn multiproofs_verify_and_lies_do_not() {
        let leaves: Vec<B256> = (0..16u8).map(|i| B256::repeat_byte(i + 1)).collect();
        let tree = levels(leaves.clone());
        let root = tree.last().unwrap()[0];
        // Node g at depth d is tree[4 - d][g - 2^d].
        let node = |g: u64| {
            let d = 63 - g.leading_zeros() as usize;
            tree[4 - d][(g - (1 << d)) as usize]
        };
        for gis in [
            vec![17u64, 22],
            vec![16, 31],
            vec![5, 24],
            vec![2],
            vec![16],
        ] {
            let set = proof_set(&gis);
            let vals: Vec<B256> = set.iter().map(|&g| node(g)).collect();
            let nodes = verify_multiproof(&gis, &vals, &root).unwrap();
            for g in &gis {
                assert_eq!(nodes[g], node(*g));
            }
            for i in 0..vals.len() {
                let mut bad = vals.clone();
                bad[i].0[0] ^= 1;
                assert!(verify_multiproof(&gis, &bad, &root).is_err());
            }
            assert!(verify_multiproof(&gis, &vals[1..], &root).is_err());
        }
        assert_eq!(sha(&node(2), &node(3)), root);
    }

    const CAPELLA_CHUNK: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/beacon/testdata/capella-first-chunk"
    );

    /// Capella's first chunk (97,024, slots 6,209,536 to 599) on mainnet:
    /// 6,209,536 and 537 were missed, so the chunk opens on the root of the
    /// last Bellatrix block (6,209,535), and 11 more slots were missed
    /// inside it. The roots and body proofs are from publicnode (roots by
    /// `/eth/v1/beacon/headers`, not proven to a state here: this tests
    /// the producer's handling of the chunk, not the chain). The Bellatrix
    /// block itself is kept whole, to test its decoding.
    #[test]
    fn capella_first_chunk_opens_on_a_bellatrix_root() {
        let v: Value =
            serde_json::from_slice(&std::fs::read(format!("{CAPELLA_CHUNK}/chunk.json")).unwrap())
                .unwrap();
        let roots: Vec<B256> = v["roots"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| b256(r).unwrap())
            .collect();
        let bodies: HashMap<B256, BodyProof> = v["bodies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| {
                let b = decode_body(b).unwrap();
                (b.block_root, b)
            })
            .collect();
        let chunk = csl_eth_store::beacon::CAPELLA_SLOT / CHUNK_SLOTS;
        assert_eq!(chunk, 97_024);
        // One body per block: 51 Capella blocks and the predecessor.
        let need = chunk_blocks(&roots);
        assert_eq!(need.len(), 52);
        assert!(need.iter().all(|r| bodies.contains_key(r)));
        assert_eq!(roots[0], roots[1]);
        let pred = &bodies[&roots[0]];
        assert_eq!(pred.slot, 6_209_535);

        // The predecessor's proof comes from the whole Bellatrix block,
        // and hashes to the root the chunk opens on.
        let raw = std::fs::read(format!("{CAPELLA_CHUNK}/bellatrix-6209535.json")).unwrap();
        let b = ssz::body_proof_any(&raw).unwrap();
        assert_eq!(b, *pred);
        assert_eq!(b.root(), roots[0]);

        let file = chunk_file(chunk, &roots, &bodies).unwrap();
        let s0 = chunk * CHUNK_SLOTS;
        let mut proven = 0;
        for k in 0..64usize {
            let s = s0 + k as u64;
            let tail = &file[k * 576 + 192..(k + 1) * 576];
            let own = bodies.get(&roots[k]).filter(|b| b.slot == s);
            assert_eq!(own.is_some(), tail.iter().any(|x| *x != 0), "slot {s}");
            if let Some(b) = own {
                let r = csl_eth_store::beacon::block_root_from(s, &b.block_hash, tail);
                assert_eq!(r, roots[k]);
                proven += 1;
            }
        }
        assert_eq!(proven, 51);
        // The client still refuses the Bellatrix slot.
        assert!(route(s0 + 64, 6_209_535).is_err());
    }

    /// Writes `chunk.json` from a directory of the chunk's blocks as the
    /// beacon API's JSON (`blocks/<root>.json`) and `roots.txt`.
    #[test]
    #[ignore = "regenerates a fixture from fetched blocks"]
    fn export_capella_chunk() {
        let dir = std::env::var("CSL_CAPELLA_CHUNK_DIR").unwrap();
        let roots: Vec<B256> = std::fs::read_to_string(format!("{dir}/roots.txt"))
            .unwrap()
            .lines()
            .map(|l| l.split_whitespace().nth(1).unwrap().parse().unwrap())
            .collect();
        let bodies: Vec<Value> = chunk_blocks(&roots)
            .iter()
            .map(|r| {
                let b =
                    ssz::body_proof_any(&std::fs::read(format!("{dir}/blocks/{r}.json")).unwrap())
                        .unwrap();
                assert_eq!(b.block_root, *r);
                encode_body(&b)
            })
            .collect();
        let v = json!({"roots": roots.iter().map(|r| r.to_string()).collect::<Vec<_>>(), "bodies": bodies});
        std::fs::create_dir_all(CAPELLA_CHUNK).unwrap();
        std::fs::write(
            format!("{CAPELLA_CHUNK}/chunk.json"),
            serde_json::to_vec_pretty(&v).unwrap(),
        )
        .unwrap();
    }
}
