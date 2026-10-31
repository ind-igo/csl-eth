//! A snapshot at the head the bucket itself proves (profile §3). The head
//! files are read through the same `Bucket` as the state, verified from the
//! client's one trust input, and the snapshot opened is the one at the
//! finalized execution block, with that header's `state_root`. A bucket
//! whose newest snapshot is at some other block is not opened: for the
//! slice milestone the published snapshot must be the finalized one, and a
//! lagging snapshot is an error that says which block it is at.

use crate::{manifest_path, Bucket, Snapshot};
use alloy_primitives::B256;
pub use csl_eth_head::{Chain, ExecutionHead, HeadError, VerifiedHead};
use csl_eth_head::{verify, HeadSource};
use csl_eth_store::Manifest;
use std::{fmt, time::SystemTime};

/// Head files through a bucket.
pub struct HeadFiles<'a, B: Bucket>(pub &'a B);

impl<B: Bucket> HeadSource for HeadFiles<'_, B> {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        self.0.read_file_opt(rel)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadOpenError {
    Head(HeadError),
    /// The bucket has no snapshot at the finalized block. `newest` is the
    /// block its `latest` names, when that could be read.
    NotAtHead { finalized: ExecutionHead, newest: Option<(u64, B256)> },
    Open(String),
}

impl fmt::Display for HeadOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeadOpenError::Head(e) => write!(f, "head: {e}"),
            HeadOpenError::NotAtHead { finalized, newest: Some((n, h)) } => {
                write!(f, "no snapshot at finalized block {} ({}); the bucket's newest is block {n} ({h})", finalized.block_number, finalized.block_hash)
            }
            HeadOpenError::NotAtHead { finalized, newest: None } => {
                write!(f, "no snapshot at finalized block {} ({})", finalized.block_number, finalized.block_hash)
            }
            HeadOpenError::Open(e) => write!(f, "snapshot: {e}"),
        }
    }
}

impl std::error::Error for HeadOpenError {}

/// Verify the head from `checkpoint` as of `now`, then open the snapshot
/// at the finalized execution block with its verified `state_root`.
#[allow(clippy::result_large_err)]
pub fn open_at_head<B: Bucket>(bucket: B, checkpoint: B256, now: SystemTime) -> Result<(Snapshot<B>, VerifiedHead), HeadOpenError> {
    let head = verify(&HeadFiles(&bucket), &Chain::mainnet(), checkpoint, now).map_err(HeadOpenError::Head)?;
    let at = head.execution.block_hash;
    let present = bucket.read_file_opt(&manifest_path(&at)).map_err(HeadOpenError::Open)?.is_some();
    if !present {
        let newest = bucket
            .read_file_opt(csl_eth_store::LATEST_FILE)
            .ok()
            .flatten()
            .and_then(|s| String::from_utf8(s).ok())
            .and_then(|s| hex::decode(s.trim()).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .map(B256::from)
            .and_then(|h| {
                let m = bucket.read_file(&manifest_path(&h)).ok()?;
                let m = Manifest::from_json(&m).ok()?;
                Some((m.block_number, h))
            });
        return Err(HeadOpenError::NotAtHead { finalized: head.execution, newest });
    }
    let snap = Snapshot::open(bucket, Some(at), head.execution.state_root).map_err(HeadOpenError::Open)?;
    Ok((snap, head))
}
