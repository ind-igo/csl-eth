//! `csl-eth history`: build a history bucket from peers, read it, measure
//! reads against the producer's verified block cache, and run the fault
//! table. Each prints one JSON document.

use super::{acquire, faults, AcquireConfig, BlockCache};
use alloy_primitives::{keccak256, Address, B256};
use clap::{Args as ClapArgs, Subcommand};
use csl_eth_client::{
    head::verify_head,
    history::{Anchor, History, HistoryCost, LogAt, LogTier, Term},
    DirDriver, Driver, Got, HttpDriver, VerifiedHead, Want,
};
use csl_eth_store::{
    history::{decode_header, decode_receipt, history_table_name, tx_hash, write_history, BlockSource, HistoryManifest},
    producer::write_atomic,
    EPSILON,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime},
};

#[derive(Subcommand, Debug)]
pub enum HistoryCmd {
    /// Verify the finalized head from a bucket's head files, acquire the
    /// blocks below it from mainnet peers (verified, cached in
    /// `<work>/blocks/`), and write the history tables into `--out`, with
    /// the head files the client needs copied there too.
    Build(BuildArgs),
    /// One read through the client: a transaction and its receipt, a
    /// header, or logs.
    Read(ReadArgs),
    /// Sampled reads of every kind, each checked against the block cache,
    /// with their cost; and the tables' sizes.
    Measure(MeasureArgs),
    /// The fault table over the newest blocks of the cache.
    Faults(FaultArgs),
}

#[derive(ClapArgs, Debug)]
pub struct BuildArgs {
    /// Checkpoint block root the head files are verified from.
    #[arg(long)]
    pub checkpoint: Option<B256>,
    /// The bucket whose head files name the finalized block (base URL).
    #[arg(long)]
    pub head_url: Option<String>,
    /// Or a bucket directory holding them.
    #[arg(long, conflicts_with = "head_url")]
    pub head_bucket: Option<PathBuf>,
    #[arg(long)]
    pub proxy: Option<String>,
    /// Producer work directory: the block cache and `anchor.json`.
    #[arg(long)]
    pub work: PathBuf,
    /// The bucket directory to write.
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, default_value_t = 7200)]
    pub blocks: u64,
    #[arg(long, default_value_t = 8)]
    pub peers: usize,
    #[arg(long, default_value_t = EPSILON)]
    pub epsilon: u16,
    #[arg(long, default_value_t = 20)]
    pub timeout_secs: u64,
    #[arg(long, default_value_t = 30399)]
    pub udp_port: u16,
    #[arg(long)]
    pub no_dns: bool,
    #[arg(long)]
    pub no_discv4: bool,
    /// Give up acquiring after this many seconds (0: never).
    #[arg(long, default_value_t = 0)]
    pub max_secs: u64,
    /// Give up when nothing has arrived for this many seconds (0: never).
    #[arg(long, default_value_t = 600)]
    pub stall_secs: u64,
    /// No head verification and no peers: build from the cache at the
    /// anchor `anchor.json` recorded.
    #[arg(long)]
    pub offline: bool,
}

#[derive(ClapArgs, Debug)]
pub struct Source {
    /// A bucket directory.
    #[arg(long, conflicts_with = "url")]
    pub bucket: Option<PathBuf>,
    /// A bucket behind HTTP (base URL).
    #[arg(long)]
    pub url: Option<String>,
    #[arg(long)]
    pub proxy: Option<String>,
    /// Open at the finalized head the bucket's head files prove from this
    /// checkpoint.
    #[arg(long)]
    pub checkpoint: Option<B256>,
    /// Or at the anchor a producer's `<work>/anchor.json` recorded.
    #[arg(long)]
    pub anchor_from: Option<PathBuf>,
}

#[derive(ClapArgs, Debug)]
pub struct ReadArgs {
    #[command(flatten)]
    pub source: Source,
    /// A transaction hash.
    #[arg(long)]
    pub tx: Option<B256>,
    /// A block number.
    #[arg(long)]
    pub header: Option<u64>,
    /// An address or a topic (32 bytes).
    #[arg(long)]
    pub logs: Option<String>,
    #[arg(long)]
    pub from: Option<u64>,
    #[arg(long)]
    pub to: Option<u64>,
    /// indexed, complete, or both.
    #[arg(long, default_value = "both")]
    pub tier: String,
}

#[derive(ClapArgs, Debug)]
pub struct MeasureArgs {
    #[command(flatten)]
    pub source: Source,
    /// The producer's work directory, for the expected answers.
    #[arg(long)]
    pub work: PathBuf,
    /// Transaction reads.
    #[arg(long, default_value_t = 100)]
    pub samples: usize,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// Longest log range read, in blocks (the complete tier fetches every
    /// bloom match in it).
    #[arg(long, default_value_t = 1000)]
    pub max_log_range: u64,
}

#[derive(ClapArgs, Debug)]
pub struct FaultArgs {
    /// The producer's work directory (cache and `anchor.json`).
    #[arg(long)]
    pub work: PathBuf,
    /// Where the hostile buckets go (`<work>/faults` by default).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// The newest blocks of the cache the table spans.
    #[arg(long, default_value_t = 256)]
    pub blocks: u64,
    #[arg(long, default_value_t = EPSILON)]
    pub epsilon: u16,
}

/// A bucket on disk or behind HTTP.
pub enum AnyDriver {
    Dir(DirDriver),
    Http(HttpDriver),
}

impl Driver for AnyDriver {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        match self {
            AnyDriver::Dir(d) => d.fetch(wants),
            AnyDriver::Http(d) => d.fetch(wants),
        }
    }
}

impl AnyDriver {
    fn new(bucket: Option<&Path>, url: Option<&str>, proxy: Option<&str>) -> Result<AnyDriver, String> {
        match (bucket, url) {
            (Some(b), None) => Ok(AnyDriver::Dir(DirDriver::new(b))),
            (None, Some(u)) => Ok(AnyDriver::Http(HttpDriver::new(u, proxy)?)),
            _ => Err("give one of --bucket and --url".into()),
        }
    }
}

/// A driver that copies every whole file it serves into `out`: the head
/// files a verification read, so the history bucket carries them.
struct Recording<'a, D> {
    inner: D,
    out: &'a Path,
}

impl<D: Driver> Driver for Recording<'_, D> {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        let got = self.inner.fetch(wants);
        for (w, g) in wants.iter().zip(&got) {
            if let (Want::File { rel }, Ok(Some(v))) = (w, g) {
                let _ = write_atomic(&self.out.join(rel), v);
            }
        }
        got
    }
}

fn head_json(h: &VerifiedHead) -> Value {
    json!({
        "checkpoint": h.checkpoint,
        "slot": h.slot,
        "period": h.period,
        "participants": h.participants,
        "block_number": h.execution.block_number,
        "block_hash": h.execution.block_hash,
        "timestamp": h.execution.timestamp,
        "lag_secs": h.lag_secs,
    })
}

fn read_anchor(work: &Path) -> Result<Anchor, String> {
    let p = work.join("anchor.json");
    let v: Value = serde_json::from_slice(&std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?).map_err(|e| e.to_string())?;
    let number = v["number"].as_u64().ok_or("anchor.json: no number")?;
    let hash: B256 = v["hash"].as_str().ok_or("anchor.json: no hash")?.parse().map_err(|_| "anchor.json: bad hash")?;
    Ok(Anchor { number, hash })
}

pub async fn run(cmd: HistoryCmd) -> Result<Value, String> {
    match cmd {
        HistoryCmd::Build(a) => build(a).await,
        HistoryCmd::Read(a) => read(a),
        HistoryCmd::Measure(a) => measure(a),
        HistoryCmd::Faults(a) => {
            let anchor = read_anchor(&a.work)?;
            let out = a.out.clone().unwrap_or_else(|| a.work.join("faults"));
            let r = faults::run(&a.work, &out, (anchor.number, anchor.hash), a.blocks, a.epsilon)?;
            serde_json::to_value(r).map_err(|e| e.to_string())
        }
    }
}

async fn build(a: BuildArgs) -> Result<Value, String> {
    std::fs::create_dir_all(&a.work).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&a.out).map_err(|e| e.to_string())?;
    let (anchor, head) = if a.offline {
        (read_anchor(&a.work)?, Value::Null)
    } else {
        let checkpoint = a.checkpoint.ok_or("--checkpoint is required unless --offline")?;
        let inner = AnyDriver::new(a.head_bucket.as_deref(), a.head_url.as_deref(), a.proxy.as_deref())?;
        let rec = Recording { inner, out: &a.out };
        let h = verify_head(&rec, checkpoint, SystemTime::now()).map_err(|e| format!("head: {e}"))?;
        let anchor = Anchor { number: h.execution.block_number, hash: h.execution.block_hash };
        let doc = json!({ "number": anchor.number, "hash": anchor.hash, "head": head_json(&h) });
        write_atomic(&a.work.join("anchor.json"), doc.to_string().as_bytes()).map_err(|e| e.to_string())?;
        (anchor, head_json(&h))
    };
    let blocks = a.blocks.clamp(1, anchor.number + 1);
    let first = anchor.number + 1 - blocks;
    let acquisition = if a.offline {
        Value::Null
    } else {
        let cfg = AcquireConfig {
            blocks,
            peers: a.peers,
            timeout: Duration::from_secs(a.timeout_secs),
            udp_port: a.udp_port,
            use_dns: !a.no_dns,
            use_discv4: !a.no_discv4,
            max_wall: Duration::from_secs(a.max_secs),
            max_stall: Duration::from_secs(a.stall_secs),
            ..Default::default()
        };
        let s = acquire((anchor.number, anchor.hash), &a.work, cfg).await.map_err(|e| e.to_string())?;
        serde_json::to_value(s).map_err(|e| e.to_string())?
    };
    let started = Instant::now();
    let w = write_history(&a.out, &BlockCache(a.work.clone()), first, (anchor.number, anchor.hash), a.epsilon).map_err(|e| e.to_string())?;
    let mut totals: BTreeMap<&str, (u64, u64, u64, u64, u64)> = BTreeMap::new();
    let mut periods = Vec::new();
    for p in &w.stats {
        let mut tables = Vec::new();
        for t in &p.tables {
            let name = history_table_name(t.table_id);
            let e = totals.entry(name).or_default();
            e.0 += t.entries;
            e.1 += t.pages;
            e.2 += t.file_bytes;
            e.3 += t.model_bytes;
            e.4 += t.blob_bytes;
            tables.push(json!({
                "table": name, "entries": t.entries, "pages": t.pages, "file_bytes": t.file_bytes,
                "model_bytes": t.model_bytes, "eight_per_page": 8 * t.pages, "blobs": t.blobs, "blob_bytes": t.blob_bytes,
            }));
        }
        periods.push(json!({ "period": p.period, "blocks": p.blocks, "transactions": p.transactions, "logs": p.logs, "tables": tables }));
    }
    let totals: Vec<Value> = totals
        .iter()
        .map(|(n, (e, pg, fb, mb, bb))| {
            json!({ "table": n, "entries": e, "pages": pg, "file_bytes": fb, "model_bytes": mb, "eight_per_page": 8 * pg,
                    "model_over_eight_per_page": *mb as f64 / (8 * pg).max(1) as f64, "blob_bytes": bb,
                    "bytes_per_block": (*fb + *bb) as f64 / blocks as f64 })
        })
        .collect();
    Ok(json!({
        "head": head,
        "anchor": { "number": anchor.number, "hash": anchor.hash },
        "first_block": first,
        "blocks": blocks,
        "acquisition": acquisition,
        "write_secs": started.elapsed().as_secs_f64(),
        "files": w.files.len(),
        "tables": totals,
        "periods": periods,
    }))
}

fn open(s: &Source) -> Result<(History<AnyDriver>, Value), String> {
    let d = AnyDriver::new(s.bucket.as_deref(), s.url.as_deref(), s.proxy.as_deref())?;
    match (s.checkpoint, &s.anchor_from) {
        (Some(c), None) => {
            let h = verify_head(&d, c, SystemTime::now()).map_err(|e| format!("head: {e}"))?;
            let hist = History::open(d, Anchor { number: h.execution.block_number, hash: h.execution.block_hash })?;
            Ok((hist, head_json(&h)))
        }
        (None, Some(w)) => Ok((History::open(d, read_anchor(w)?)?, Value::Null)),
        _ => Err("give one of --checkpoint and --anchor-from".into()),
    }
}

fn cost_json(c: &HistoryCost) -> Value {
    json!({
        "requests": c.requests, "bytes": c.bytes, "rounds": c.rounds, "table_bytes": c.table_bytes,
        "headers_verified": c.headers_verified, "blocks_verified": c.blocks_verified,
    })
}

fn parse_tier(s: &str) -> Result<Vec<LogTier>, String> {
    match s {
        "indexed" => Ok(vec![LogTier::Indexed]),
        "complete" => Ok(vec![LogTier::Complete]),
        "both" => Ok(vec![LogTier::Indexed, LogTier::Complete]),
        _ => Err(format!("tier: {s}")),
    }
}

fn log_json(l: &LogAt) -> Value {
    json!({ "block": l.block_number, "tx_index": l.tx_index, "log_index": l.log_index, "address": l.log.address,
            "topics": l.log.topics, "data_len": l.log.data.len() })
}

fn read(a: ReadArgs) -> Result<Value, String> {
    let (mut h, head) = open(&a.source)?;
    let m = h.manifest().clone();
    let mut out = json!({ "head": head, "span": [m.first_block, m.block_number] });
    if let Some(t) = a.tx {
        let (r, c) = h.tx(&t);
        out["tx"] = match r {
            Ok(r) => json!({ "block": r.block_number, "block_hash": r.block_hash, "index": r.index, "tx_bytes": r.tx.len(),
                              "status": r.receipt.success, "cumulative_gas_used": r.receipt.cumulative_gas_used,
                              "logs": r.receipt.logs.len(), "block_receipt_bytes": r.block_receipt_bytes, "block_tx_bytes": r.block_tx_bytes }),
            Err(e) => json!({ "insufficient": e.to_string() }),
        };
        out["tx_cost"] = cost_json(&c);
    }
    if let Some(n) = a.header {
        let (r, c) = h.header(n);
        out["header"] = match r {
            Ok(x) => json!({ "number": x.number, "hash": x.hash, "parent_hash": x.parent_hash, "timestamp": x.timestamp,
                              "transactions_root": x.transactions_root, "receipts_root": x.receipts_root }),
            Err(e) => json!({ "insufficient": e.to_string() }),
        };
        out["header_cost"] = cost_json(&c);
    }
    if let Some(term) = &a.logs {
        let term = Term::parse(term)?;
        let to = a.to.unwrap_or(m.block_number);
        let from = a.from.unwrap_or(to.saturating_sub(99).max(m.first_block));
        let mut tiers = Vec::new();
        for tier in parse_tier(&a.tier)? {
            let (r, c) = h.logs(&term, from, to, tier);
            tiers.push(match r {
                Ok(l) => json!({ "tier": tier.name(), "logs": l.logs.len(), "blocks_fetched": l.blocks_fetched,
                                  "blocks_without_match": l.blocks_without_match, "first": l.logs.iter().take(5).map(log_json).collect::<Vec<_>>(), "cost": cost_json(&c) }),
                Err(e) => json!({ "tier": tier.name(), "insufficient": e.to_string(), "cost": cost_json(&c) }),
            });
        }
        out["logs"] = json!({ "term": term.to_string(), "from": from, "to": to, "tiers": tiers });
    }
    Ok(out)
}

/// p50, p95, max and mean of `v`.
fn dist(mut v: Vec<u64>) -> Value {
    if v.is_empty() {
        return Value::Null;
    }
    v.sort_unstable();
    let at = |q: f64| v[((v.len() - 1) as f64 * q).round() as usize];
    json!({ "n": v.len(), "p50": at(0.5), "p95": at(0.95), "max": v[v.len() - 1], "mean": v.iter().sum::<u64>() as f64 / v.len() as f64 })
}

#[derive(Default)]
struct Costs {
    requests: Vec<u64>,
    bytes: Vec<u64>,
    rounds: Vec<u64>,
    headers: Vec<u64>,
    table_bytes: BTreeMap<&'static str, u64>,
}

impl Costs {
    fn add(&mut self, c: &HistoryCost) {
        self.requests.push(c.requests);
        self.bytes.push(c.bytes);
        self.rounds.push(c.rounds as u64);
        self.headers.push(c.headers_verified);
        for (k, v) in &c.table_bytes {
            *self.table_bytes.entry(k).or_default() += v;
        }
    }

    fn json(self) -> Value {
        let n = self.requests.len().max(1) as f64;
        let mean: BTreeMap<_, _> = self.table_bytes.iter().map(|(k, v)| (*k, *v as f64 / n)).collect();
        json!({ "requests": dist(self.requests), "bytes": dist(self.bytes), "rounds": dist(self.rounds),
                "headers_verified": dist(self.headers), "mean_table_bytes": mean })
    }
}

fn truth(src: &dyn BlockSource, term: &Term, from: u64, to: u64) -> Result<Vec<LogAt>, String> {
    let mut out = Vec::new();
    for n in from..=to {
        let b = src.block(n)?;
        let mut li = 0;
        for (i, r) in b.receipts.iter().enumerate() {
            for l in decode_receipt(r).map_err(String::from)?.logs {
                if term.matches(&l) {
                    out.push(LogAt { block_number: n, tx_index: i as u64, log_index: li, block_hash: b.hash, log: l });
                }
                li += 1;
            }
        }
    }
    Ok(out)
}

fn measure(a: MeasureArgs) -> Result<Value, String> {
    let (mut h, head) = open(&a.source)?;
    let m: HistoryManifest = h.manifest().clone();
    let (first, last) = (m.first_block, m.block_number);
    let src = BlockCache(a.work.clone());
    let mut rng = ChaCha8Rng::seed_from_u64(a.seed);
    let mut wrong = 0u64;
    let mut insufficient: Vec<String> = Vec::new();

    // Transactions, cold (headers walked from the anchor each read), by
    // depth below the anchor; then the same reads warm.
    let mut picks = Vec::new();
    while picks.len() < a.samples {
        let n = rng.random_range(first..=last);
        let b = src.block(n)?;
        if b.txs.is_empty() {
            continue;
        }
        let i = rng.random_range(0..b.txs.len());
        picks.push((n, i, tx_hash(&b.txs[i]), b.receipts[i].clone()));
    }
    let bands: [(&str, u64, u64); 3] = [("depth_lt_64", 0, 64), ("depth_64_1024", 64, 1024), ("depth_ge_1024", 1024, u64::MAX)];
    let mut cold: Vec<Costs> = bands.iter().map(|_| Costs::default()).collect();
    let mut all_cold = Costs::default();
    let mut receipt_share = Vec::new();
    for (n, i, hash, leaf) in &picks {
        h.forget();
        let (r, c) = h.tx(hash);
        match r {
            Ok(r) if r.block_number == *n && r.index == *i as u64 && &r.receipt_leaf == leaf => {
                receipt_share.push(r.receipt_leaf.len() as u64);
            }
            Ok(_) => wrong += 1,
            Err(e) => insufficient.push(format!("tx {hash}: {e}")),
        }
        let d = last - n;
        let bi = bands.iter().position(|b| d >= b.1 && d < b.2).expect("bands cover");
        cold[bi].add(&c);
        all_cold.add(&c);
    }
    let mut warm = Costs::default();
    h.forget();
    let _ = h.header(first);
    for (n, i, hash, _) in &picks {
        let (r, c) = h.tx(hash);
        if !matches!(&r, Ok(r) if r.block_number == *n && r.index == *i as u64) {
            wrong += r.is_ok() as u64;
        }
        warm.add(&c);
    }

    // Headers by depth, cold.
    let mut headers = Vec::new();
    for d in [0u64, 1, 32, 256, 1024, 4096, last - first] {
        if d > last - first {
            continue;
        }
        let n = last - d;
        h.forget();
        let (r, c) = h.header(n);
        let want = decode_header(&src.block(n)?.header).map_err(String::from)?;
        match r {
            Ok(x) if x == want => {}
            Ok(_) => wrong += 1,
            Err(e) => insufficient.push(format!("header {n}: {e}")),
        }
        headers.push(json!({ "depth": d, "cost": cost_json(&c) }));
    }

    // Log terms: the busiest address in the span, one near 1% of blocks,
    // one in a single block, and ERC-20 Transfer's topic.
    let mut blocks_with: HashMap<Address, u64> = HashMap::new();
    for n in first..=last {
        let b = src.block(n)?;
        let mut seen = std::collections::HashSet::new();
        for r in &b.receipts {
            for l in decode_receipt(r).map_err(String::from)?.logs {
                seen.insert(l.address);
            }
        }
        for x in seen {
            *blocks_with.entry(x).or_default() += 1;
        }
    }
    let mut by_count: Vec<(u64, Address)> = blocks_with.iter().map(|(a, c)| (*c, *a)).collect();
    by_count.sort();
    let span = last - first + 1;
    let busy = by_count.last().map(|x| x.1).ok_or("no logs in the span")?;
    let one_pct = by_count.iter().min_by_key(|(c, _)| c.abs_diff(span / 100)).map(|x| x.1).expect("non-empty");
    let rare = by_count.iter().find(|(c, _)| *c == 1).map(|x| x.1).unwrap_or(busy);
    let transfer = keccak256("Transfer(address,address,uint256)");
    let terms = [
        ("busy_address", Term::Address(busy)),
        ("one_percent_address", Term::Address(one_pct)),
        ("rare_address", Term::Address(rare)),
        ("transfer_topic", Term::Topic(transfer)),
    ];
    let mut logs = Vec::new();
    for (label, term) in &terms {
        for range in [1u64, 100, a.max_log_range] {
            if range > span {
                continue;
            }
            let (from, to) = (last + 1 - range, last);
            let want = truth(&src, term, from, to)?;
            for tier in [LogTier::Indexed, LogTier::Complete] {
                h.forget();
                let (r, c) = h.logs(term, from, to, tier);
                let (n, fetched, without) = match r {
                    Ok(l) if l.logs == want => (l.logs.len(), l.blocks_fetched, l.blocks_without_match),
                    Ok(l) => {
                        wrong += 1;
                        (l.logs.len(), l.blocks_fetched, l.blocks_without_match)
                    }
                    Err(e) => {
                        insufficient.push(format!("logs {label} {range} {}: {e}", tier.name()));
                        (0, 0, 0)
                    }
                };
                logs.push(json!({ "term": label, "address_or_topic": term.to_string(), "blocks": range, "tier": tier.name(),
                                  "logs": n, "blocks_fetched": fetched, "blocks_without_match": without, "cost": cost_json(&c) }));
            }
        }
    }

    // Table sizes, from the manifest.
    let mut tables: BTreeMap<&str, (u64, u64, u64)> = BTreeMap::new();
    for p in &m.periods {
        for t in &p.tables {
            let e = tables.entry(history_table_name(t.table_id)).or_default();
            e.0 += t.page_count;
            e.1 += u64::from(t.model_bytes);
            e.2 += t.entry_count;
        }
    }
    let tables: Vec<Value> = tables
        .iter()
        .map(|(n, (pages, model, entries))| {
            json!({ "table": n, "entries": entries, "pages": pages, "page_bytes": pages * 4096, "model_bytes": model,
                    "eight_per_page": 8 * pages, "bytes_per_block": (pages * 4096 + model) as f64 / span as f64 })
        })
        .collect();

    let mut bands_json = serde_json::Map::new();
    for ((name, _, _), c) in bands.iter().zip(cold) {
        bands_json.insert((*name).into(), c.json());
    }
    Ok(json!({
        "head": head,
        "span": [first, last],
        "periods": m.periods.len(),
        "tx_cold": all_cold.json(),
        "tx_cold_by_depth": bands_json,
        "tx_warm": warm.json(),
        "receipt_leaf_bytes": dist(receipt_share),
        "headers": headers,
        "logs": logs,
        "tables": tables,
        "wrong": wrong,
        "insufficient": insufficient,
        "pass": wrong == 0 && insufficient.is_empty(),
    }))
}
