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
    apply_bootstrap, apply_update, calc_sync_period,
    consensus_spec::MainnetConsensusSpec,
    get_bits,
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
            genesis_root: fixed_bytes!(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
            ),
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
    /// The newest finality update in the bucket was signed in period
    /// `signed` and the clock is already in `current`, two or more periods
    /// later: the producer has not published since. A head is good through
    /// the period after the one it was signed in (its committee handed over
    /// once, at most); past that it is refused however well it verifies,
    /// so a producer that stops, or a bucket that replays old files, cannot
    /// keep an old head alive. Not a broken bucket, an abandoned one.
    Stale { signed: u64, current: u64 },
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
            HeadError::Stale { signed, current } => write!(
                f,
                "stale head: the newest finality update was signed in period {signed} \
                 and the clock is in period {current}: the producer has not published since"
            ),
            HeadError::Read(e) => write!(f, "head file unreadable: {e}"),
            HeadError::Decode { path, error } => write!(f, "{path}: {error}"),
            HeadError::Bootstrap(e) => write!(f, "bootstrap rejected: {e}"),
            HeadError::Update { period, error } => {
                write!(f, "update for period {period} rejected: {error}")
            }
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
    let bytes = src
        .read_head(path)
        .map_err(HeadError::Read)?
        .ok_or_else(|| HeadError::Missing(path.to_string()))?;
    decode(path, &bytes)
}

fn decode<T: for<'de> Deserialize<'de>>(path: &str, bytes: &[u8]) -> Result<T, HeadError> {
    let env: Envelope<T> = serde_json::from_slice(bytes).map_err(|e| HeadError::Decode {
        path: path.to_string(),
        error: e.to_string(),
    })?;
    Ok(env.data)
}

/// The bootstrap checked against `checkpoint`.
fn checked_bootstrap(
    bytes: &[u8],
    checkpoint: B256,
    chain: &Chain,
) -> Result<Bootstrap<Spec>, HeadError> {
    let bootstrap: Bootstrap<Spec> = decode(&paths::bootstrap(&checkpoint), bytes)?;
    verify_bootstrap::<Spec>(&bootstrap, checkpoint, &chain.forks)
        .map_err(|e| HeadError::Bootstrap(e.to_string()))?;
    Ok(bootstrap)
}

/// The period updates between a proven bootstrap and a finality update not
/// yet verified, as of `current_period`: periods `b..s`, `b` the
/// bootstrap's and `s` the one the finality update was signed in. Each
/// update hands over to the next committee, so after `b..s` the store
/// holds the committee that signs in `s`. A finality update signed two or
/// more periods before the clock's is stale; one signed after it is from
/// the future and is refused here, before any update is asked for, so the
/// range is bounded by the clock.
fn periods_between(
    bootstrap: &Bootstrap<Spec>,
    finality: &FinalityUpdate<Spec>,
    current_period: u64,
) -> Result<std::ops::Range<u64>, HeadError> {
    let first = calc_sync_period::<Spec>(bootstrap.header().beacon().slot);
    let signed = calc_sync_period::<Spec>(*finality.signature_slot());
    if signed > current_period {
        return Err(HeadError::Finality(format!(
            "signed in period {signed}, after the clock's period {current_period}"
        )));
    }
    if signed + 1 < current_period {
        return Err(HeadError::Stale {
            signed,
            current: current_period,
        });
    }
    Ok(first..signed.max(first))
}

/// Verify the head from `src` starting at `checkpoint`, as of `now`:
/// the bootstrap, then the finality update's signing period (a head signed
/// two or more periods ago is stale), then the period updates from the
/// bootstrap's period up to the one the finality update was signed in, in
/// order, then the finality update itself. Each step is checked against
/// what the previous one established; nothing is taken from the files on
/// faith, not even which period a file holds: `head/updates/<p>` must
/// attest a header of period `p`. The head is the finality update's own
/// finalized header. `now` is a parameter so that a test can fix it.
pub fn verify(
    src: &dyn HeadSource,
    chain: &Chain,
    checkpoint: B256,
    now: SystemTime,
) -> Result<VerifiedHead, HeadError> {
    let bootstrap_path = paths::bootstrap(&checkpoint);
    let bytes = src
        .read_head(&bootstrap_path)
        .map_err(HeadError::Read)?
        .ok_or(HeadError::Missing(bootstrap_path))?;
    let bootstrap = checked_bootstrap(&bytes, checkpoint, chain)?;
    let mut store = LightClientStore::<Spec>::default();
    apply_bootstrap::<Spec>(&mut store, &bootstrap);

    let finality: FinalityUpdate<Spec> = read(src, paths::FINALITY)?;
    let current_slot = current_slot(chain, now);
    let current_period = calc_sync_period::<Spec>(current_slot);
    let periods = periods_between(&bootstrap, &finality, current_period)?;

    let mut updates_applied = 0;
    for period in periods {
        let update: Update<Spec> = read(src, &paths::update(period))?;
        let attested = calc_sync_period::<Spec>(update.attested_header().beacon().slot);
        if attested != period {
            return Err(HeadError::Update {
                period,
                error: format!("attests a header of period {attested}, not {period}"),
            });
        }
        verify_update::<Spec>(
            &update,
            current_slot,
            &store,
            chain.genesis_root,
            &chain.forks,
        )
        .map_err(|e| HeadError::Update {
            period,
            error: e.to_string(),
        })?;
        apply_update::<Spec>(&mut store, &update);
        updates_applied += 1;
    }

    verify_finality_update::<Spec>(
        &finality,
        current_slot,
        &store,
        chain.genesis_root,
        &chain.forks,
    )
    .map_err(|e| HeadError::Finality(e.to_string()))?;
    let participants = get_bits::<Spec>(&finality.sync_aggregate().sync_committee_bits);

    // The finality update's own header, not the store's: a period update
    // can carry a finalized header of its own, newer or older, and the
    // head is what `head/finality` proves.
    let header = finality.finalized_header();
    let beacon = header.beacon();
    let exec = header.execution().map_err(|_| HeadError::NoExecution)?;
    let execution = ExecutionHead {
        block_number: *exec.block_number(),
        block_hash: *exec.block_hash(),
        state_root: *exec.state_root(),
        timestamp: *exec.timestamp(),
    };
    let now_secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
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

/// The period updates [`verify`] will read, given the bootstrap's and the
/// finality update's bytes: periods `b..s`, from the bootstrap's to the
/// one before the finality update was signed in (empty when it was signed
/// in the bootstrap's period). The bootstrap is checked against
/// `checkpoint` first, and a stale or future finality update is refused
/// here, so an error is the one `verify` returns at the same step. This
/// lets a host ask for the bootstrap and the finality update in one round
/// and the period updates in the next, while `verify` still checks them in
/// order. The finality update is not verified here; its signing period
/// only bounds what the next round asks for.
pub fn update_periods(
    bootstrap: &[u8],
    finality: &[u8],
    checkpoint: B256,
    chain: &Chain,
    now: SystemTime,
) -> Result<std::ops::Range<u64>, HeadError> {
    let bootstrap = checked_bootstrap(bootstrap, checkpoint, chain)?;
    let finality: FinalityUpdate<Spec> = decode(paths::FINALITY, finality)?;
    let current = calc_sync_period::<Spec>(current_slot(chain, now));
    periods_between(&bootstrap, &finality, current)
}

/// The sync-committee period of a slot (8,192 slots, about 27 hours).
pub fn period_of(slot: u64) -> u64 {
    calc_sync_period::<Spec>(slot)
}

/// The slot the wall clock says it is: 12-second slots from genesis. Our
/// own arithmetic rather than helios's, whose clock type differs on wasm.
pub fn current_slot(chain: &Chain, now: SystemTime) -> u64 {
    let secs = now
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs.saturating_sub(chain.genesis_time) / 12
}
