//! The head from the bucket (profile §3). The beacon light-client protocol
//! is a small set of signed objects; the producer publishes them as files
//! beside the state and the client verifies them offline with one trust
//! input, a weak-subjectivity checkpoint root:
//!
//! - `head/bootstrap/<block_root>`: the checkpoint's header and current
//!   sync committee, proven against the root the client was given.
//! - `head/updates/<period>`: one per sync-committee period (about 27
//!   hours), each carrying the next committee, signed by the current one.
//! - `head/finality`: the newest finality update, rewritten every epoch.
//!
//! Each file is the beacon API's JSON response for that object, version
//! envelope included, so a producer can mirror a node's endpoint byte for
//! byte and a reader can tell which fork's SSZ layout it holds.
//!
//! The verifier is `helios-consensus-core` behind this module's own
//! functions, so a finality-proof verifier (EIP-8390) can replace it
//! without the client noticing. A producer can withhold newer files, which
//! shows up as lag; it cannot forge one. For the slice milestone the head
//! files come from a public beacon node; nothing here trusts that node.

use alloy_primitives::{fixed_bytes, B256};
use helios_consensus_core::{
    apply_bootstrap, apply_finality_update, apply_update, calc_sync_period,
    consensus_spec::MainnetConsensusSpec, expected_current_slot, get_bits,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, LightClientStore, Update},
    verify_bootstrap, verify_finality_update, verify_update,
};
use serde::Deserialize;
use std::{fmt, path::PathBuf, time::SystemTime};
use tree_hash::TreeHash;

#[cfg(feature = "fetch")]
pub mod fetch;

type Spec = MainnetConsensusSpec;

/// Where the head files live in a bucket.
pub mod paths {
    use alloy_primitives::B256;

    pub const FINALITY: &str = "head/finality";

    pub fn bootstrap(block_root: &B256) -> String {
        format!("head/bootstrap/{block_root}")
    }

    pub fn update(period: u64) -> String {
        format!("head/updates/{period}")
    }
}

/// Mainnet's beacon chain constants: genesis and the fork schedule, which
/// pick the SSZ layout and the signing domain of each object.
pub struct Chain {
    pub genesis_time: u64,
    pub genesis_root: B256,
    pub forks: Forks,
}

impl Chain {
    pub fn mainnet() -> Chain {
        let fork = |epoch: u64, v: [u8; 4]| Fork {
            epoch,
            fork_version: v.into(),
        };
        Chain {
            genesis_time: 1_606_824_023,
            genesis_root: fixed_bytes!("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"),
            forks: Forks {
                genesis: fork(0, [0, 0, 0, 0]),
                altair: fork(74_240, [1, 0, 0, 0]),
                bellatrix: fork(144_896, [2, 0, 0, 0]),
                capella: fork(194_048, [3, 0, 0, 0]),
                deneb: fork(269_568, [4, 0, 0, 0]),
                electra: fork(364_032, [5, 0, 0, 0]),
                fulu: fork(411_392, [6, 0, 0, 0]),
                gloas: fork(u64::MAX, [7, 0, 0, 0]),
            },
        }
    }
}

/// Files by path, `Ok(None)` when absent. A bucket directory, an HTTP
/// bucket, anything.
pub trait HeadSource {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String>;
}

/// A bucket directory on disk.
pub struct DirSource(pub PathBuf);

impl HeadSource for DirSource {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        match std::fs::read(self.0.join(rel)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{rel}: {e}")),
        }
    }
}

/// The beacon API's envelope around every light-client object.
#[derive(Deserialize)]
struct Envelope<T> {
    #[allow(dead_code)]
    version: String,
    data: T,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadError {
    /// A file the verification needs is not in the bucket.
    Missing(String),
    /// The source failed to read a file.
    Read(String),
    /// A file is not the object its path claims.
    Decode { path: String, error: String },
    /// The bootstrap does not prove the checkpoint root given, or its
    /// committee proof is wrong.
    Bootstrap(String),
    /// A period update failed verification.
    Update { period: u64, error: String },
    /// The finality update failed verification: bad signature, too few
    /// participants, wrong branch, from the future.
    Finality(String),
    /// The finalized header carries no execution payload header (before
    /// Capella); nothing to read state against.
    NoExecution,
}

impl fmt::Display for HeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeadError::Missing(p) => write!(f, "head file missing: {p}"),
            HeadError::Read(e) => write!(f, "head file unreadable: {e}"),
            HeadError::Decode { path, error } => write!(f, "{path}: {error}"),
            HeadError::Bootstrap(e) => write!(f, "bootstrap rejected: {e}"),
            HeadError::Update { period, error } => write!(f, "update for period {period} rejected: {error}"),
            HeadError::Finality(e) => write!(f, "finality update rejected: {e}"),
            HeadError::NoExecution => write!(f, "finalized header has no execution payload"),
        }
    }
}

impl std::error::Error for HeadError {}

/// The execution block the finalized beacon header commits to. Its
/// `state_root` is the root every state read verifies against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionHead {
    pub block_number: u64,
    pub block_hash: B256,
    pub state_root: B256,
    pub timestamp: u64,
}

/// What the files proved, and how fresh it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHead {
    /// The trust input.
    pub checkpoint: B256,
    pub slot: u64,
    pub beacon_root: B256,
    pub period: u64,
    /// Sync committee members that signed the finality update, of 512.
    pub participants: u64,
    /// Period updates applied on the way from the checkpoint.
    pub updates_applied: u64,
    pub execution: ExecutionHead,
    /// Now minus the finalized block's timestamp. Normally 13 to 19
    /// minutes; unbounded in a finality stall, and growing when the
    /// producer stops rewriting `head/finality`.
    pub finality_lag_secs: u64,
}

fn read<T: for<'de> Deserialize<'de>>(src: &dyn HeadSource, path: &str) -> Result<T, HeadError> {
    let bytes = src.read_head(path).map_err(HeadError::Read)?.ok_or_else(|| HeadError::Missing(path.to_string()))?;
    let env: Envelope<T> = serde_json::from_slice(&bytes).map_err(|e| HeadError::Decode { path: path.to_string(), error: e.to_string() })?;
    Ok(env.data)
}

/// Verify the head from `src` starting at `checkpoint`, as of `now`:
/// bootstrap, every period update from the checkpoint's period to the
/// current one, then the finality update. Each step is checked against
/// what the previous one established; nothing is taken from the files on
/// faith. `now` is a parameter so that a test can fix it.
pub fn verify(src: &dyn HeadSource, chain: &Chain, checkpoint: B256, now: SystemTime) -> Result<VerifiedHead, HeadError> {
    let bootstrap: Bootstrap<Spec> = read(src, &paths::bootstrap(&checkpoint))?;
    verify_bootstrap::<Spec>(&bootstrap, checkpoint, &chain.forks).map_err(|e| HeadError::Bootstrap(e.to_string()))?;
    let mut store = LightClientStore::<Spec>::default();
    apply_bootstrap::<Spec>(&mut store, &bootstrap);

    let current_slot = expected_current_slot(now, chain.genesis_time);
    let current_period = calc_sync_period::<Spec>(current_slot);
    let mut period = calc_sync_period::<Spec>(store.finalized_header.beacon().slot);
    let mut updates_applied = 0;
    while period <= current_period {
        let path = paths::update(period);
        match src.read_head(&path).map_err(HeadError::Read)? {
            Some(bytes) => {
                let env: Envelope<Update<Spec>> = serde_json::from_slice(&bytes).map_err(|e| HeadError::Decode { path: path.clone(), error: e.to_string() })?;
                verify_update::<Spec>(&env.data, current_slot, &store, chain.genesis_root, &chain.forks)
                    .map_err(|e| HeadError::Update { period, error: e.to_string() })?;
                apply_update::<Spec>(&mut store, &env.data);
                updates_applied += 1;
            }
            // The current period's update exists only once a block of the
            // period has been attested with the next committee in it; the
            // finality update below is signed by the committee already
            // known. An earlier period's update is required.
            None if period == current_period => {}
            None => return Err(HeadError::Missing(path)),
        }
        period += 1;
    }

    let finality: FinalityUpdate<Spec> = read(src, paths::FINALITY)?;
    verify_finality_update::<Spec>(&finality, current_slot, &store, chain.genesis_root, &chain.forks).map_err(|e| HeadError::Finality(e.to_string()))?;
    let participants = get_bits::<Spec>(&finality.sync_aggregate().sync_committee_bits);
    apply_finality_update::<Spec>(&mut store, &finality);

    let header = &store.finalized_header;
    let beacon = header.beacon();
    let exec = header.execution().map_err(|_| HeadError::NoExecution)?;
    let execution = ExecutionHead {
        block_number: *exec.block_number(),
        block_hash: *exec.block_hash(),
        state_root: *exec.state_root(),
        timestamp: *exec.timestamp(),
    };
    let now_secs = now.duration_since(SystemTime::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    Ok(VerifiedHead {
        checkpoint,
        slot: beacon.slot,
        beacon_root: beacon.tree_hash_root(),
        period: calc_sync_period::<Spec>(beacon.slot),
        participants,
        updates_applied,
        execution,
        finality_lag_secs: now_secs.saturating_sub(execution.timestamp),
    })
}

/// The sync-committee period of a slot (8,192 slots, about 27 hours).
pub fn period_of(slot: u64) -> u64 {
    calc_sync_period::<Spec>(slot)
}

/// The slot the wall clock says it is.
pub fn current_slot(chain: &Chain, now: SystemTime) -> u64 {
    expected_current_slot(now, chain.genesis_time)
}
