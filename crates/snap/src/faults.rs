//! The milestone 1 fault table (PoC spec, "Fault injection"): each named
//! corruption of a bucket or of the host's responses, applied to a copy,
//! read through with the workload's shapes, and tabulated: every row must
//! end in `Insufficient` or a correct answer, never a wrong value and
//! never a false absence.
//!
//! Scaffold: the build agent fills this in.

use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The slice the bucket was built from (keys and expected values).
    #[arg(long)]
    pub slice: PathBuf,
    /// A bucket directory on disk; faults are applied to a copy.
    #[arg(long)]
    pub bucket: PathBuf,
    /// Where to write the JSON table.
    #[arg(long)]
    pub out: PathBuf,
}

pub fn run(args: Args) -> Result<serde_json::Value, String> {
    let _ = args;
    Err("faults: not built yet".into())
}
