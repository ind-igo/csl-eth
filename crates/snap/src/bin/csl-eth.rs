//! `csl-eth`: fetch a mainnet slice over snap, build a bucket from it,
//! probe peers.

use alloy_primitives::B256;
use clap::{Parser, Subcommand};
use csl_eth_snap::{fetch, probe, FetchConfig, Slice};
use csl_eth_store::{produce_with, ProduceOptions};
use csl_eth_trie::Nibbles;
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
        #[arg(long, default_value_t = 4)]
        epsilon: u16,
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
