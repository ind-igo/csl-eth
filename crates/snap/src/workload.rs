//! The milestone 1 workload (PoC spec, "Workload" and the exit table):
//! a fixed, deterministic set of reads drawn from a slice, classified by
//! the shape of the trie's answer, run through the path-keyed client and
//! the content-addressed baseline, scored, and written as one JSON report.
//!
//! Scaffold: the build agent fills this in.

use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The slice the bucket was built from (keys and expected values).
    #[arg(long)]
    pub slice: PathBuf,
    /// A bucket directory on disk.
    #[arg(long, conflicts_with = "url")]
    pub bucket: Option<PathBuf>,
    /// A bucket behind HTTP (the directory's base URL).
    #[arg(long)]
    pub url: Option<String>,
    /// Proxy for the URL, e.g. socks5h://localhost:1055.
    #[arg(long)]
    pub proxy: Option<String>,
    /// Where to write the JSON report.
    #[arg(long)]
    pub out: PathBuf,
}

pub fn run(args: Args) -> Result<serde_json::Value, String> {
    let _ = args;
    Err("workload: not built yet".into())
}
