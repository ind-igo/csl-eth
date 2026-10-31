//! `csl-eth`: fetch a mainnet slice over snap, build a bucket from it,
//! probe peers.

use alloy_primitives::B256;
use clap::{Parser, Subcommand};
use csl_eth_client::{DirBucket, Hint, Read, Reason, Snapshot};
use csl_eth_snap::{fetch, probe, FetchConfig, Slice};
use csl_eth_store::{produce_with, ProduceOptions};
use csl_eth_trie::Nibbles;
use csl_eth_trie::KECCAK_EMPTY;
use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Parser)]
#[command(name = "csl-eth", about = "Ethereum state as static files: acquisition and build")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Fetch every account under a hashed-path prefix at one recent root,
    /// with storage and code, from mainnet peers; write the slice.
    Fetch {
        /// Hex nibbles, e.g. `1a` for 1/256 of state, `1a7` for 1/4096.
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value_t = 8)]
        peers: usize,
        /// Soft response size in bytes.
        #[arg(long, default_value_t = 2 * 1024 * 1024)]
        bytes: u64,
        #[arg(long, default_value_t = 20)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 30399)]
        udp_port: u16,
        #[arg(long)]
        no_dns: bool,
        #[arg(long)]
        no_discv4: bool,
        /// Pivot on this block hash instead of the first peer's head.
        #[arg(long)]
        pivot: Option<B256>,
        /// Give up after this many seconds (0: never).
        #[arg(long, default_value_t = 0)]
        max_secs: u64,
    },
    /// Build a bucket (snapshot runs, blobs, manifest) from a slice.
    Build {
        #[arg(long)]
        slice: PathBuf,
        #[arg(long)]
        out: PathBuf,
        /// Learned-index error bound in pages; 1 measured best on mainnet.
        #[arg(long, default_value_t = 1)]
        epsilon: u16,
    },
    /// Read a bucket built from a slice with the client: sampled accounts,
    /// slots and code verify, absent keys inside the prefix are proven,
    /// keys outside end Insufficient; cost per read.
    Check {
        #[arg(long)]
        slice: PathBuf,
        /// A bucket directory on disk.
        #[arg(long, conflicts_with = "url")]
        bucket: Option<PathBuf>,
        /// A bucket behind HTTP (the directory's base URL).
        #[arg(long)]
        url: Option<String>,
        /// Proxy for the URL, e.g. socks5h://localhost:1055.
        #[arg(long)]
        proxy: Option<String>,
        #[arg(long, default_value_t = 500)]
        samples: usize,
        /// Speculated account depth (profile: 9) and storage depth (7).
        #[arg(long)]
        d_account: Option<usize>,
        #[arg(long)]
        d_storage: Option<usize>,
        /// Fetch the speculative round in parallel: the predicted page per
        /// depth plus this many pages each side. Off when absent.
        #[arg(long)]
        prefetch: Option<u64>,
        /// Pages below / above the prediction, overriding --prefetch's span
        /// on that side.
        #[arg(long)]
        prefetch_below: Option<u64>,
        #[arg(long)]
        prefetch_above: Option<u64>,
        /// Ask for touching pages one request each instead of one range.
        #[arg(long)]
        no_merge: bool,
        /// Keep verified account-trie nodes at depths below this across
        /// reads (0: off).
        #[arg(long, default_value_t = 0)]
        top_levels: usize,
    },
    /// Dial peers and report client, snap version and head.
    Peers {
        #[arg(long, default_value_t = 5)]
        count: usize,
        #[arg(long, default_value_t = 15)]
        timeout_secs: u64,
        #[arg(long, default_value_t = 30399)]
        udp_port: u16,
    },
}

fn parse_prefix(s: &str) -> Result<Nibbles, String> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() || s.len() > 62 {
        return Err("prefix must be 1 to 62 hex nibbles".into());
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        out.push(c.to_digit(16).ok_or_else(|| format!("not a hex nibble: {c}"))? as u8);
    }
    Ok(Nibbles::from_nibbles(out))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,discv4=warn,reth_dns_discovery=warn,hickory=warn".into()),
        )
        .init();
    match Cli::parse().cmd {
        Cmd::Fetch { prefix, out, peers, bytes, timeout_secs, udp_port, no_dns, no_discv4, pivot, max_secs } => {
            let cfg = FetchConfig {
                prefix: parse_prefix(&prefix)?,
                peers,
                response_bytes: bytes,
                timeout: Duration::from_secs(timeout_secs),
                udp_port,
                use_dns: !no_dns,
                use_discv4: !no_discv4,
                pivot,
                max_wall: Duration::from_secs(max_secs),
                ..Default::default()
            };
            let slice = fetch(cfg).await?;
            slice.write(&out)?;
            println!("{}", serde_json::to_string_pretty(&slice.head)?);
        }
        Cmd::Build { slice, out, epsilon } => {
            let t = std::time::Instant::now();
            let s = Slice::read(&slice)?;
            let head = s.produce_head();
            let produced = produce_with(&out, &head, &s.head.prefix, s.leaves(), &s.code, ProduceOptions { epsilon, boundary: s.boundary.clone() })?;
            println!(
                "{}",
                serde_json::json!({
                    "dir": produced.dir,
                    "block_number": head.block_number,
                    "state_root": head.state_root,
                    "stats": format!("{:?}", produced.stats),
                    "wall_ms": t.elapsed().as_millis() as u64,
                })
            );
        }
        Cmd::Check { slice, bucket, url, proxy, samples, d_account, d_storage, prefetch, prefetch_below, prefetch_above, no_merge, top_levels } => {
            let s = Slice::read(&slice)?;
            let prefetch = match (prefetch, prefetch_below, prefetch_above) {
                (None, None, None) => None,
                (span, below, above) => Some(Hint {
                    below: below.or(span).unwrap_or(0),
                    above: above.or(span).unwrap_or(0),
                    merge: !no_merge,
                }),
            };
            let mut opts = CheckOpts { samples, d_account, d_storage, prefetch, top_levels, http: None };
            let out = match (bucket, url) {
                (Some(dir), None) => check(&s, Snapshot::open(DirBucket::new(&dir), None, s.head.state_root)?, &opts),
                (None, Some(base)) => {
                    let b = csl_eth_client::HttpBucket::new(&base, proxy.as_deref())?;
                    let (req, bytes, hinted) = (b.requests.clone(), b.bytes.clone(), b.hinted.clone());
                    opts.http = Some([req.clone(), bytes.clone(), hinted.clone()]);
                    let mut out = check(&s, Snapshot::open(b, None, s.head.state_root)?, &opts);
                    out["http"] = serde_json::json!({
                        "requests": req.load(std::sync::atomic::Ordering::Relaxed),
                        "bytes": bytes.load(std::sync::atomic::Ordering::Relaxed),
                        "hinted_pages": hinted.load(std::sync::atomic::Ordering::Relaxed),
                    });
                    out
                }
                _ => return Err("give --bucket <dir> or --url <base>".into()),
            };
            println!("{}", out);
        }
        Cmd::Peers { count, timeout_secs, udp_port } => {
            let rows = probe(count, Duration::from_secs(timeout_secs), udp_port).await;
            for (record, client, snap, head) in &rows {
                println!("{:<45} snap/{} head={} {}", client, snap, head.map(|n| n.to_string()).unwrap_or_else(|| "?".into()), record.address);
            }
            println!("{} peers", rows.len());
        }
    }
    Ok(())
}

/// Costs of one kind of read.
#[derive(Default)]
struct Series {
    requests: Vec<u64>,
    bytes: Vec<u64>,
    rounds: Vec<u64>,
    nodes: Vec<u64>,
    micros: Vec<u64>,
    http_requests: Vec<u64>,
    http_bytes: Vec<u64>,
    http_dependent: Vec<u64>,
}

impl Series {
    fn push(&mut self, c: &csl_eth_client::Cost, wall: Duration, http: Option<(u64, u64, u64)>) {
        self.requests.push(c.requests);
        self.bytes.push(c.bytes);
        self.rounds.push(c.rounds as u64);
        self.nodes.push(c.nodes as u64);
        self.micros.push(wall.as_micros() as u64);
        if let Some((r, b, d)) = http {
            self.http_requests.push(r);
            self.http_bytes.push(b);
            self.http_dependent.push(d);
        }
    }

    fn summary(&self) -> serde_json::Value {
        fn stats(v: &[u64]) -> serde_json::Value {
            if v.is_empty() {
                return serde_json::Value::Null;
            }
            let mut s = v.to_vec();
            s.sort_unstable();
            let mean = s.iter().sum::<u64>() as f64 / s.len() as f64;
            serde_json::json!({
                "mean": (mean * 10.0).round() / 10.0,
                "p50": s[s.len() / 2],
                "p95": s[(s.len() * 95 / 100).min(s.len() - 1)],
                "max": s[s.len() - 1],
            })
        }
        serde_json::json!({
            "n": self.requests.len(),
            "requests": stats(&self.requests),
            "bytes": stats(&self.bytes),
            "rounds": stats(&self.rounds),
            "nodes_walked": stats(&self.nodes),
            "ms": stats(&self.micros.iter().map(|u| u / 1000).collect::<Vec<_>>()),
            "http_requests": stats(&self.http_requests),
            "http_bytes": stats(&self.http_bytes),
            "http_dependent_requests": stats(&self.http_dependent),
        })
    }
}

struct CheckOpts {
    samples: usize,
    d_account: Option<usize>,
    d_storage: Option<usize>,
    prefetch: Option<Hint>,
    top_levels: usize,
    /// HTTP requests, bytes and hinted pages, when the bucket is remote.
    http: Option<[Arc<AtomicU64>; 3]>,
}

/// A read's HTTP cost: requests and bytes actually on the wire, and how
/// many of the requests were dependent (not in the prefetch hint).
fn http_delta(o: &CheckOpts, before: [u64; 3]) -> Option<(u64, u64, u64)> {
    let c = o.http.as_ref()?;
    let now = [c[0].load(Ordering::Relaxed), c[1].load(Ordering::Relaxed), c[2].load(Ordering::Relaxed)];
    let (req, bytes, hinted) = (now[0] - before[0], now[1] - before[1], now[2] - before[2]);
    Some((req, bytes, req.saturating_sub(hinted)))
}

fn http_now(o: &CheckOpts) -> [u64; 3] {
    match &o.http {
        Some(c) => [c[0].load(Ordering::Relaxed), c[1].load(Ordering::Relaxed), c[2].load(Ordering::Relaxed)],
        None => [0; 3],
    }
}

/// Sampled accounts, their slots and code, absent keys inside the prefix
/// and keys outside it, through the client; cost and wall time per read.
fn check<B: csl_eth_client::Bucket>(s: &Slice, mut snap: Snapshot<B>, o: &CheckOpts) -> serde_json::Value {
    if let Some(d) = o.d_account {
        snap.d_account = d;
    }
    if let Some(d) = o.d_storage {
        snap.d_storage = d;
    }
    snap.prefetch = o.prefetch;
    snap.top_levels = o.top_levels;
    let prefix_nibbles = parse_prefix(&s.head.prefix).expect("slice prefix");
    let in_prefix = |h: &B256| csl_eth_trie::path_of(h).starts_with(&prefix_nibbles);
    let stride = (s.accounts.len() / o.samples.max(1)).max(1);
    let mut acc = Series::default();
    let mut slot = Series::default();
    let mut code = Series::default();
    let mut absent = Series::default();
    let mut outside = Series::default();
    let (mut wrong, mut unexpected) = (0usize, 0usize);
    let t_all = std::time::Instant::now();
    for (i, (h, a)) in s.accounts.iter().enumerate().step_by(stride) {
        let (t, h0) = (std::time::Instant::now(), http_now(o));
        let (r, c) = snap.account(h);
        match r {
            Read::Verified(got) if got == *a => acc.push(&c, t.elapsed(), http_delta(o, h0)),
            Read::Verified(_) => wrong += 1,
            other => {
                unexpected += 1;
                eprintln!("account {h}: {other:?}");
            }
        }
        if let Some(slots) = s.storage.get(&a.storage_root) {
            if let Some((k, v)) = slots.get(i % slots.len()) {
                let (t, h0) = (std::time::Instant::now(), http_now(o));
                let (r, c) = snap.storage(h, k);
                match r {
                    Read::Verified(got) if got == *v => slot.push(&c, t.elapsed(), http_delta(o, h0)),
                    Read::Verified(_) => wrong += 1,
                    other => {
                        unexpected += 1;
                        eprintln!("slot {h}/{k}: {other:?}");
                    }
                }
            }
        }
        if a.code_hash != KECCAK_EMPTY {
            let (t, h0) = (std::time::Instant::now(), http_now(o));
            let (r, c) = snap.code(&a.code_hash);
            match r {
                Read::Verified(bytes) if alloy_primitives::keccak256(&bytes) == a.code_hash => code.push(&c, t.elapsed(), http_delta(o, h0)),
                Read::Verified(_) => wrong += 1,
                other => {
                    unexpected += 1;
                    eprintln!("code {}: {other:?}", a.code_hash);
                }
            }
        }
        // An absent key inside the prefix: this account's hash with the
        // last byte changed (same prefix, almost surely no leaf).
        let mut k = *h;
        k.0[31] ^= 0x5a;
        if s.accounts.binary_search_by(|(x, _)| x.cmp(&k)).is_err() {
            let (t, h0) = (std::time::Instant::now(), http_now(o));
            let (r, c) = snap.account(&k);
            match r {
                Read::VerifiedAbsent(_) => absent.push(&c, t.elapsed(), http_delta(o, h0)),
                other => {
                    unexpected += 1;
                    eprintln!("absent {k}: {other:?}");
                }
            }
        }
        // Outside the prefix: first nibble flipped.
        let mut k = *h;
        k.0[0] ^= 0x10;
        if !in_prefix(&k) {
            let (t, h0) = (std::time::Instant::now(), http_now(o));
            let (r, c) = snap.account(&k);
            match r {
                Read::Insufficient(Reason::Missing { .. }) => outside.push(&c, t.elapsed(), http_delta(o, h0)),
                other => {
                    unexpected += 1;
                    eprintln!("outside {k}: {other:?}");
                }
            }
        }
    }
    serde_json::json!({
        "block_number": s.head.block_number,
        "prefix": s.head.prefix,
        "d_account": snap.d_account,
        "d_storage": snap.d_storage,
        "prefetch": o.prefetch.map(|h| serde_json::json!({"below": h.below, "above": h.above, "merge": h.merge})),
        "top_levels": o.top_levels,
        "wrong_values": wrong,
        "unexpected_reads": unexpected,
        "wall_ms": t_all.elapsed().as_millis() as u64,
        "reads": acc.requests.len() + slot.requests.len() + code.requests.len() + absent.requests.len() + outside.requests.len(),
        "account": acc.summary(),
        "storage_slot": slot.summary(),
        "code": code.summary(),
        "absent_inside": absent.summary(),
        "outside_prefix": outside.summary(),
    })
}
