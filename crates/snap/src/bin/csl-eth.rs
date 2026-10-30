//! `csl-eth`: fetch a mainnet slice over snap, build a bucket from it,
//! probe peers.

use alloy_primitives::B256;
use clap::{Parser, Subcommand};
use csl_eth_client::{DirBucket, Read, Reason, Snapshot};
use csl_eth_snap::{fetch, probe, FetchConfig, Slice};
use csl_eth_store::{produce_with, ProduceOptions};
use csl_eth_trie::Nibbles;
use csl_eth_trie::KECCAK_EMPTY;
use std::{path::PathBuf, time::Duration};

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
        #[arg(long)]
        bucket: PathBuf,
        #[arg(long, default_value_t = 500)]
        samples: usize,
        /// Speculated account depth (profile: 9) and storage depth (7).
        #[arg(long)]
        d_account: Option<usize>,
        #[arg(long)]
        d_storage: Option<usize>,
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
        Cmd::Check { slice, bucket, samples, d_account, d_storage } => {
            let s = Slice::read(&slice)?;
            let mut snap = Snapshot::open(DirBucket::new(&bucket), None, s.head.state_root)?;
            if let Some(d) = d_account {
                snap.d_account = d;
            }
            if let Some(d) = d_storage {
                snap.d_storage = d;
            }
            let prefix_nibbles = parse_prefix(&s.head.prefix)?;
            let in_prefix = |h: &B256| csl_eth_trie::path_of(h).starts_with(&prefix_nibbles);
            let stride = (s.accounts.len() / samples.max(1)).max(1);
            let mut acc = Series::default();
            let mut slot = Series::default();
            let mut code = Series::default();
            let mut absent = Series::default();
            let mut outside = Series::default();
            let (mut wrong, mut unexpected) = (0usize, 0usize);
            for (i, (h, a)) in s.accounts.iter().enumerate().step_by(stride) {
                let (r, c) = snap.account(h);
                match r {
                    Read::Verified(got) if got == *a => acc.push(&c),
                    Read::Verified(_) => wrong += 1,
                    other => {
                        unexpected += 1;
                        eprintln!("account {h}: {other:?}");
                    }
                }
                if let Some(slots) = s.storage.get(&a.storage_root) {
                    if let Some((k, v)) = slots.get(i % slots.len()) {
                        let (r, c) = snap.storage(h, k);
                        match r {
                            Read::Verified(got) if got == *v => slot.push(&c),
                            Read::Verified(_) => wrong += 1,
                            other => {
                                unexpected += 1;
                                eprintln!("slot {h}/{k}: {other:?}");
                            }
                        }
                    }
                }
                if a.code_hash != KECCAK_EMPTY {
                    let (r, c) = snap.code(&a.code_hash);
                    match r {
                        Read::Verified(bytes) if alloy_primitives::keccak256(&bytes) == a.code_hash => code.push(&c),
                        Read::Verified(_) => wrong += 1,
                        other => {
                            unexpected += 1;
                            eprintln!("code {}: {other:?}", a.code_hash);
                        }
                    }
                }
                // An absent key inside the prefix: this account's hash with
                // the last byte changed (same prefix, almost surely no leaf).
                let mut k = *h;
                k.0[31] ^= 0x5a;
                if s.accounts.binary_search_by(|(x, _)| x.cmp(&k)).is_err() {
                    let (r, c) = snap.account(&k);
                    match r {
                        Read::VerifiedAbsent(_) => absent.push(&c),
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
                    let (r, c) = snap.account(&k);
                    match r {
                        Read::Insufficient(Reason::Missing { .. }) => outside.push(&c),
                        other => {
                            unexpected += 1;
                            eprintln!("outside {k}: {other:?}");
                        }
                    }
                }
            }
            println!(
                "{}",
                serde_json::json!({
                    "block_number": s.head.block_number,
                    "prefix": s.head.prefix,
                    "d_account": snap.d_account,
                    "d_storage": snap.d_storage,
                    "wrong_values": wrong,
                    "unexpected_reads": unexpected,
                    "account": acc.summary(),
                    "storage_slot": slot.summary(),
                    "code": code.summary(),
                    "absent_inside": absent.summary(),
                    "outside_prefix": outside.summary(),
                })
            );
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
}

impl Series {
    fn push(&mut self, c: &csl_eth_client::Cost) {
        self.requests.push(c.requests);
        self.bytes.push(c.bytes);
        self.rounds.push(c.rounds as u64);
        self.nodes.push(c.nodes as u64);
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
        })
    }
}
