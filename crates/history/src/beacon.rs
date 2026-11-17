//! The accumulator route (profile §3c, "Old headers"): an execution block
//! hash proven to the verified beacon head through `block_roots` or
//! `historical_summaries` and the block's body, from the files
//! [`csl_eth_store::beacon`] lays out. No I/O, like the rest of the
//! client: every record a proof needs is wanted at once, so a proof is one
//! round once the slot is known (two the first time, for the head's
//! preamble, which the session then keeps).

use alloy_primitives::B256;
use csl_eth_client::{Pending, Store, VerifiedHead};
use csl_eth_store::beacon::{
    chunk_record_range, head_path, route, route_ranges, verify_block_hash, HeadPreamble,
    CAPELLA_PERIOD, HEAD_PREAMBLE, SLOTS_PER_HISTORICAL_ROOT,
};
pub use csl_eth_store::beacon::{Route, CAPELLA_SLOT};
use csl_eth_store::history::{MAINNET_GENESIS_TIME, SECONDS_PER_SLOT};

/// The beacon block the accumulator proves against: a head the client
/// verified from its checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconAnchor {
    pub slot: u64,
    pub root: B256,
}

impl From<&VerifiedHead> for BeaconAnchor {
    fn from(h: &VerifiedHead) -> BeaconAnchor {
        BeaconAnchor {
            slot: h.slot,
            root: h.beacon_root,
        }
    }
}

/// The slot an execution block's timestamp names (post-merge, one block
/// per slot at most), or `None` for a timestamp off the slot clock.
pub fn slot_of_timestamp(ts: u64) -> Option<u64> {
    let d = ts.checked_sub(MAINNET_GENESIS_TIME)?;
    (d % SECONDS_PER_SLOT == 0).then_some(d / SECONDS_PER_SLOT)
}

/// Why a proof failed: the files are absent (the bucket does not serve
/// the route, which is not evidence of anything), or they are there and
/// do not verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AccumError {
    /// The head's file could not be read (absent, or the range failed).
    NotServed(String),
    /// The slot is out of the route's reach: before Capella, at or past
    /// the head, in the head's last partial chunk.
    Unreachable(String),
    /// A file is missing, short, or does not hash to the head.
    Proof(String),
}

impl std::fmt::Display for AccumError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccumError::NotServed(e) => write!(f, "no accumulator for this head: {e}"),
            AccumError::Unreachable(w) => write!(f, "unreachable: {w}"),
            AccumError::Proof(w) => write!(f, "accumulator: {w}"),
        }
    }
}

/// The session's view of one head's accumulator.
#[derive(Clone, Debug)]
pub struct Accumulator {
    pub anchor: BeaconAnchor,
    /// The head's preamble once verified.
    head: Option<HeadPreamble>,
    /// Set when the head file turned out absent: the route is off for the
    /// session.
    absent: bool,
}

impl Accumulator {
    pub fn new(anchor: BeaconAnchor) -> Accumulator {
        Accumulator {
            anchor,
            head: None,
            absent: false,
        }
    }

    /// Whether the route may still be tried (its head file was not found
    /// absent).
    pub fn available(&self) -> bool {
        !self.absent
    }

    /// Whether the route reaches `slot` from this head at all.
    pub fn reaches(&self, slot: u64) -> bool {
        route(self.anchor.slot, slot).is_ok()
    }

    /// The `historical_summaries` length the head's state has: one per
    /// closed period since Capella.
    fn expected_len(&self) -> u64 {
        (self.anchor.slot / SLOTS_PER_HISTORICAL_ROOT).saturating_sub(CAPELLA_PERIOD)
    }

    /// Prove that `block_hash` is the execution payload of the canonical
    /// beacon block at `slot`. Every range the proof needs is wanted
    /// before `Pending`: the preamble (first time only) with the records,
    /// whose places follow from the slot and the head alone.
    pub fn try_prove(
        &mut self,
        store: &Store,
        slot: u64,
        block_hash: &B256,
    ) -> Result<Result<(), AccumError>, Pending> {
        if self.absent {
            return Ok(Err(AccumError::NotServed(
                "refused earlier in the session".into(),
            )));
        }
        let r = match route(self.anchor.slot, slot) {
            Ok(r) => r,
            Err(e) => return Ok(Err(AccumError::Unreachable(e))),
        };
        let len = self
            .head
            .as_ref()
            .map_or(self.expected_len(), |h| h.summaries_len);
        let (cp, co, cl) = chunk_record_range(slot);
        let hp = head_path(&self.anchor.root);
        let mut pending = false;
        let mut get = |rel: &str, off: u64, n: usize| match store.range(rel, off, n) {
            Err(Pending) => {
                pending = true;
                None
            }
            Ok(r) => Some(r),
        };
        let pre = if self.head.is_none() {
            get(&hp, 0, HEAD_PREAMBLE)
        } else {
            None
        };
        let chunk = get(&cp, co, cl);
        let tops: Vec<_> = route_ranges(len, &self.anchor.root, &r)
            .into_iter()
            .map(|(p, o, n)| get(&p, o, n))
            .collect();
        if pending {
            return Err(Pending);
        }
        if let Some(pre) = pre {
            let pre = match pre {
                Ok(b) => b,
                Err(e) => {
                    // Absent or unreadable: either way the route is off
                    // for the session, and reads walk.
                    self.absent = true;
                    return Ok(Err(AccumError::NotServed(e)));
                }
            };
            // A preamble that does not verify will not verify later
            // either: the route is off for the session.
            let pre = match HeadPreamble::decode(&pre)
                .and_then(|p| p.verify(self.anchor.slot, &self.anchor.root).map(|()| p))
            {
                Ok(p) => p,
                Err(e) => {
                    self.absent = true;
                    return Ok(Err(AccumError::Proof(e)));
                }
            };
            let again = pre.summaries_len != len && matches!(r, Route::Closed { .. });
            self.head = Some(pre);
            if again {
                // The list is not the length the clock implies: the
                // records were asked of the wrong file. Ask again.
                return self.try_prove(store, slot, block_hash);
            }
        }
        let pre = self.head.as_ref().expect("verified above");
        let bytes = |g: Option<Result<Vec<u8>, String>>| -> Result<Vec<u8>, AccumError> {
            g.expect("fetched").map_err(AccumError::Proof)
        };
        let chunk = match bytes(chunk) {
            Ok(b) => b,
            Err(e) => return Ok(Err(e)),
        };
        let mut recs = Vec::new();
        for t in tops {
            match bytes(t) {
                Ok(b) => recs.push(b),
                Err(e) => return Ok(Err(e)),
            }
        }
        Ok(verify_block_hash(
            pre,
            slot,
            block_hash,
            &chunk,
            &recs[0],
            recs.get(1).map(Vec::as_slice),
        )
        .map_err(AccumError::Proof))
    }
}
