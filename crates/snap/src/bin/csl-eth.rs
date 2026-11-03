//! `csl-eth`: fetch a mainnet slice over snap, build a bucket from it,
//! probe peers.

use alloy_primitives::{B256, U256};
use clap::{Parser, Subcommand};
use csl_eth_client::{open_at_head, DirDriver, Hint, Read, Reason, Snapshot, VerifiedHead};
use csl_eth_snap::{bal, fetch, peer::Net, probe, FetchConfig, Slice};
use csl_eth_store::{produce_with, ProduceOptions};
use csl_eth_trie::{Account, Nibbles};
use csl_eth_trie::KECCAK_EMPTY;
use std::{path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    name = "csl-eth",
    about = "Ethereum state as static files: acquisition and build"
)]
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
        /// Connect to peers first and pivot on the block hash this file
        /// holds once it appears (for a fetch at a finalized root).
        #[arg(long, conflicts_with = "pivot")]
        pivot_file: Option<PathBuf>,
        /// Connect to peers first and pivot on the block whose timestamp is
        /// this (the first block of an epoch, so finality will name it), or
        /// `next` for the next epoch boundary.
        #[arg(long, conflicts_with_all = ["pivot", "pivot_file"])]
        pivot_at: Option<String>,
        /// Give up after this many seconds (0: never).
        #[arg(long, default_value_t = 0)]
        max_secs: u64,
    },
    /// The milestone 1 workload: fixed reads of every shape through both
    /// clients, scored, one JSON report.
    Workload(csl_eth_snap::workload::Args),
    /// The milestone 1 fault table: every named corruption applied to a
    /// bucket's responses by a lying host, read through, tabulated; passes
    /// when safe (no false answer) and exercised (every fault fired).
    Faults(csl_eth_snap::faults::Args),
    /// The producer loop: at each chosen epoch boundary fetch the slice,
    /// build it, wait for finality to name the block, lay out the head
    /// files, verify, publish in order, collect old snapshots. One JSON
    /// line per cycle on stdout and in `<work>/produce.log`.
    Produce(csl_eth_snap::produce::Args),
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
        /// Widen the speculative round: the predicted page per depth plus
        /// this many pages each side (0: the predicted pages only).
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
        /// Read the content-addressed baseline instead (profile §9): every
        /// node fetched by hash from `nodes_by_hash`, one round each.
        #[arg(long)]
        baseline: bool,
        /// Verify the head from the bucket's `head/` files starting at this
        /// weak-subjectivity checkpoint root, and read at the finalized
        /// block's `state_root` instead of the slice's pinned header.
        #[arg(long)]
        checkpoint: Option<B256>,
    },
    /// The head files: pull them from a beacon node into a bucket, or
    /// verify a bucket's from a checkpoint.
    Head {
        #[command(subcommand)]
        cmd: HeadCmd,
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
    /// Ask testnet peers for EIP-7928 block access lists (eth/71, snap/2)
    /// and verify each against its header. One JSON line per peer, then a
    /// summary.
    BalProbe {
        /// sepolia or hoodi.
        #[arg(long)]
        chain: String,
        /// Stop after this many connected peers.
        #[arg(long, default_value_t = 30)]
        peers: usize,
        /// Or after this many seconds.
        #[arg(long, default_value_t = 180)]
        secs: u64,
        #[arg(long, default_value_t = 30411)]
        udp_port: u16,
        #[arg(long, default_value_t = 10)]
        timeout_secs: u64,
    },
}

#[derive(Subcommand)]
enum HeadCmd {
    /// Fetch bootstrap, period updates and the finality update from a
    /// beacon node's light-client API into `<bucket>/head/`, and verify
    /// the set written.
    Fetch {
        /// Beacon node base URL with the light-client endpoints enabled.
        #[arg(long, default_value = "https://lodestar-mainnet.chainsafe.io")]
        beacon: String,
        #[arg(long)]
        bucket: PathBuf,
        /// Checkpoint block root; the node's current finalized checkpoint
        /// when absent (then printed, to be pinned from here on).
        #[arg(long)]
        checkpoint: Option<B256>,
    },
    /// Verify a bucket's head files from a checkpoint and print the
    /// finalized execution block.
    Verify {
        #[arg(long)]
        checkpoint: B256,
        #[arg(long, conflicts_with = "url")]
        bucket: Option<PathBuf>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long)]
        proxy: Option<String>,
    },
}

fn head_json(h: &VerifiedHead) -> serde_json::Value {
    serde_json::json!({
        "checkpoint": h.checkpoint,
        "slot": h.slot,
        "beacon_root": h.beacon_root,
        "period": h.period,
        "participants": h.participants,
        "updates_applied": h.updates_applied,
        "block_number": h.execution.block_number,
        "block_hash": h.execution.block_hash,
        "state_root": h.execution.state_root,
        "timestamp": h.execution.timestamp,
        "tier": h.tier.name(),
        "lag_secs": h.lag_secs,
    })
}

/// The snapshot `check` reads: at the slice's pinned header, or at the head
/// the bucket proves when a checkpoint is given.
fn open_for_check<D: csl_eth_client::Driver>(
    b: D,
    s: &Slice,
    checkpoint: Option<B256>,
) -> Result<(Snapshot<D>, Option<serde_json::Value>), String> {
    match checkpoint {
        None => Ok((Snapshot::open(b, None, s.head.state_root)?, None)),
        Some(c) => {
            let (snap, head) =
                open_at_head(b, c, std::time::SystemTime::now()).map_err(|e| e.to_string())?;
            if head.execution.state_root != s.head.state_root {
                return Err(format!(
                    "the slice is at block {} ({}), the finalized head at block {} ({}); fetch a slice at the finalized block",
                    s.head.block_number, s.head.state_root, head.execution.block_number, head.execution.state_root
                ));
            }
            Ok((snap, Some(head_json(&head))))
        }
    }
}

fn parse_prefix(s: &str) -> Result<Nibbles, String> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() || s.len() > 62 {
        return Err("prefix must be 1 to 62 hex nibbles".into());
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        out.push(
            c.to_digit(16)
                .ok_or_else(|| format!("not a hex nibble: {c}"))? as u8,
        );
    }
    Ok(Nibbles::from_nibbles(out))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,discv4=warn,reth_dns_discovery=warn,hickory=warn".into());
    if matches!(cli.cmd, Cmd::Produce(_)) {
        // stdout carries the cycle lines only.
        tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    match cli.cmd {
        Cmd::Produce(args) => {
            tokio::task::spawn_blocking(move || csl_eth_snap::produce::run(args)).await??;
        }
        Cmd::Workload(args) => {
            let out = csl_eth_snap::workload::run(args)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Cmd::Faults(args) => {
            let out = csl_eth_snap::faults::run(args)?;
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Cmd::Fetch {
            prefix,
            out,
            peers,
            bytes,
            timeout_secs,
            udp_port,
            no_dns,
            no_discv4,
            pivot,
            pivot_file,
            pivot_at,
            max_secs,
        } => {
            let pivot_at = match pivot_at.as_deref() {
                None => None,
                Some("next") => {
                    let chain = csl_eth_head::Chain::mainnet();
                    let slot = csl_eth_head::current_slot(&chain, std::time::SystemTime::now());
                    let boundary = (slot / 32 + 1) * 32;
                    Some(chain.genesis_time + boundary * 12)
                }
                Some(s) => Some(s.parse::<u64>().map_err(|e| format!("--pivot-at: {e}"))?),
            };
            let cfg = FetchConfig {
                prefix: parse_prefix(&prefix)?,
                peers,
                response_bytes: bytes,
                timeout: Duration::from_secs(timeout_secs),
                udp_port,
                use_dns: !no_dns,
                use_discv4: !no_discv4,
                pivot,
                pivot_file,
                pivot_at,
                max_wall: Duration::from_secs(max_secs),
                ..Default::default()
            };
            let slice = fetch(cfg).await?;
            slice.write(&out)?;
            println!("{}", serde_json::to_string_pretty(&slice.head)?);
        }
        Cmd::Build {
            slice,
            out,
            epsilon,
        } => {
            let t = std::time::Instant::now();
            let s = Slice::read(&slice)?;
            let head = s.produce_head();
            let produced = produce_with(
                &out,
                &head,
                &s.head.prefix,
                s.leaves(),
                &s.code,
                ProduceOptions {
                    epsilon,
                    boundary: s.boundary.clone(),
                },
            )?;
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
        Cmd::Check {
            slice,
            bucket,
            url,
            proxy,
            samples,
            d_account,
            d_storage,
            prefetch,
            prefetch_below,
            prefetch_above,
            no_merge,
            top_levels,
            baseline,
            checkpoint,
        } => {
            let s = Slice::read(&slice)?;
            let hint = Hint {
                below: prefetch_below.or(prefetch).unwrap_or(0),
                above: prefetch_above.or(prefetch).unwrap_or(0),
                merge: !no_merge,
            };
            let opts = CheckOpts {
                samples,
                d_account,
                d_storage,
                hint,
                top_levels,
                baseline,
            };
            let out = match (bucket, url) {
                (Some(dir), None) => {
                    let (snap, head) = open_for_check(DirDriver::new(&dir), &s, checkpoint)?;
                    let mut out = check(&s, snap, &opts);
                    if let Some(h) = head {
                        out["head"] = h;
                    }
                    out
                }
                (None, Some(base)) => {
                    let b = csl_eth_client::HttpDriver::new(&base, proxy.as_deref())?;
                    let (req, bytes) = (b.requests.clone(), b.bytes.clone());
                    let (snap, head) = open_for_check(b, &s, checkpoint)?;
                    let head_requests = req.load(std::sync::atomic::Ordering::Relaxed);
                    let head_bytes = bytes.load(std::sync::atomic::Ordering::Relaxed);
                    let mut out = check(&s, snap, &opts);
                    if let Some(mut h) = head {
                        h["http_requests"] = head_requests.into();
                        h["http_bytes"] = head_bytes.into();
                        out["head"] = h;
                    }
                    out["http"] = serde_json::json!({
                        "requests": req.load(std::sync::atomic::Ordering::Relaxed),
                        "bytes": bytes.load(std::sync::atomic::Ordering::Relaxed),
                    });
                    out
                }
                _ => return Err("give --bucket <dir> or --url <base>".into()),
            };
            println!("{}", out);
        }
        Cmd::Head {
            cmd:
                HeadCmd::Fetch {
                    beacon,
                    bucket,
                    checkpoint,
                },
        } => {
            let f = csl_eth_head::fetch::fetch_into(&beacon, &bucket, checkpoint)?;
            let mut out = head_json(&f.head);
            out["updates_written"] = serde_json::json!(f.updates);
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Cmd::Head {
            cmd:
                HeadCmd::Verify {
                    checkpoint,
                    bucket,
                    url,
                    proxy,
                },
        } => {
            let now = std::time::SystemTime::now();
            let (h, http) = match (bucket, url) {
                (Some(dir), None) => (
                    csl_eth_client::head::verify_head(&DirDriver::new(dir), checkpoint, now)?,
                    None,
                ),
                (None, Some(base)) => {
                    let b = csl_eth_client::HttpDriver::new(&base, proxy.as_deref())?;
                    let h = csl_eth_client::head::verify_head(&b, checkpoint, now)?;
                    let http = serde_json::json!({
                        "requests": b.requests.load(std::sync::atomic::Ordering::Relaxed),
                        "bytes": b.bytes.load(std::sync::atomic::Ordering::Relaxed),
                    });
                    (h, Some(http))
                }
                _ => return Err("give --bucket <dir> or --url <base>".into()),
            };
            let mut out = head_json(&h);
            if let Some(http) = http {
                out["http"] = http;
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Cmd::Peers {
            count,
            timeout_secs,
            udp_port,
        } => {
            let rows = probe(count, Duration::from_secs(timeout_secs), udp_port).await;
            for (record, client, snap, head) in &rows {
                println!(
                    "{:<45} snap/{} head={} {}",
                    client,
                    snap,
                    head.map(|n| n.to_string()).unwrap_or_else(|| "?".into()),
                    record.address
                );
            }
            println!("{} peers", rows.len());
        }
        Cmd::BalProbe {
            chain,
            peers,
            secs,
            udp_port,
            timeout_secs,
        } => {
            let net = Net::parse(&chain)?;
            let cfg = bal::ProbeConfig {
                net,
                peers,
                secs,
                udp_port,
                timeout: Duration::from_secs(timeout_secs),
            };
            let (tx, mut rx) = tokio::sync::mpsc::channel(64);
            let printer = tokio::spawn(async move {
                while let Some(r) = rx.recv().await {
                    println!("{r}");
                }
            });
            let probed = bal::probe(&cfg, tx).await;
            printer.await?;
            let mut summary = bal::summarize(&probed.reports);
            summary["chain"] = serde_json::json!(net.name());
            summary["dial_errors"] = serde_json::json!(probed.dial_errors);
            println!("{}", serde_json::to_string_pretty(&summary)?);
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
    model_pages: Vec<u64>,
    micros: Vec<u64>,
}

impl Series {
    fn push(&mut self, c: &csl_eth_client::Cost, wall: Duration) {
        self.requests.push(c.requests);
        self.bytes.push(c.bytes);
        self.rounds.push(c.rounds as u64);
        self.nodes.push(c.nodes as u64);
        self.model_pages.push(c.model_pages);
        self.micros.push(wall.as_micros() as u64);
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
            "model_pages": stats(&self.model_pages),
            "ms": stats(&self.micros.iter().map(|u| u / 1000).collect::<Vec<_>>()),
        })
    }
}

struct CheckOpts {
    samples: usize,
    d_account: Option<usize>,
    d_storage: Option<usize>,
    hint: Hint,
    top_levels: usize,
    baseline: bool,
}

fn read_account<D: csl_eth_client::Driver>(snap: &mut Snapshot<D>, baseline: bool, h: &B256) -> (Read<Account>, csl_eth_client::Cost) {
    if baseline {
        snap.account_by_hash(h)
    } else {
        snap.account(h)
    }
}

fn read_slot<D: csl_eth_client::Driver>(snap: &mut Snapshot<D>, baseline: bool, h: &B256, k: &B256) -> (Read<U256>, csl_eth_client::Cost) {
    if baseline {
        snap.storage_by_hash(h, k)
    } else {
        snap.storage(h, k)
    }
}

/// Sampled accounts, their slots and code, absent keys inside the prefix
/// and keys outside it, through the client; cost and wall time per read.
fn check<D: csl_eth_client::Driver>(
    s: &Slice,
    mut snap: Snapshot<D>,
    o: &CheckOpts,
) -> serde_json::Value {
    if let Some(d) = o.d_account {
        snap.d_account = d;
    }
    if let Some(d) = o.d_storage {
        snap.d_storage = d;
    }
    snap.hint = o.hint;
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
        let t = std::time::Instant::now();
        let (r, c) = read_account(&mut snap, o.baseline, h);
        match r {
            Read::Verified(got) if got == *a => acc.push(&c, t.elapsed()),
            Read::Verified(_) => wrong += 1,
            other => {
                unexpected += 1;
                eprintln!("account {h}: {other:?}");
            }
        }
        if let Some(slots) = s.storage.get(&a.storage_root) {
            if let Some((k, v)) = slots.get(i % slots.len()) {
                let t = std::time::Instant::now();
                let (r, c) = read_slot(&mut snap, o.baseline, h, k);
                match r {
                    Read::Verified(got) if got == *v => slot.push(&c, t.elapsed()),
                    Read::Verified(_) => wrong += 1,
                    other => {
                        unexpected += 1;
                        eprintln!("slot {h}/{k}: {other:?}");
                    }
                }
            }
        }
        if a.code_hash != KECCAK_EMPTY {
            let t = std::time::Instant::now();
            let (r, c) = snap.code(&a.code_hash);
            match r {
                Read::Verified(bytes) if alloy_primitives::keccak256(&bytes) == a.code_hash => {
                    code.push(&c, t.elapsed())
                }
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
            let t = std::time::Instant::now();
            let (r, c) = read_account(&mut snap, o.baseline, &k);
            match r {
                Read::VerifiedAbsent(_) => absent.push(&c, t.elapsed()),
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
            let t = std::time::Instant::now();
            let (r, c) = read_account(&mut snap, o.baseline, &k);
            match r {
                Read::Insufficient(Reason::Missing { .. }) => outside.push(&c, t.elapsed()),
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
        "hint": {"below": o.hint.below, "above": o.hint.above, "merge": o.hint.merge},
        "top_levels": o.top_levels,
        "mode": if o.baseline { "baseline" } else { "path" },
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
