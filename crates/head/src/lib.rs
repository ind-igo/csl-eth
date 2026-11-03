//! The head from the bucket (profile §3). The beacon light-client protocol
//! is a small set of signed objects; the producer publishes them as files
//! beside the state and the client verifies them offline with one trust
//! input, a weak-subjectivity checkpoint root:
//!
//! - `head/bootstrap/<block_root>`: the checkpoint's header and current
//!   sync committee, proven against the root the client was given.
//! - `head/updates/<period>`: one per sync-committee period (about 27
//!   hours), each carrying the next committee, signed by the current one.
//! - `head/finality`: the newest finality update naming a published
//!   snapshot: the finalized tier.
//! - `head/optimistic`: the optimistic update attesting the newest
//!   snapshot's block, signed by the sync committee one slot after it: the
//!   attested tier ([`Tier::Attested`]), minutes behind the chain instead
//!   of the finalized tier's 13 to 19. Its block is not final: the
//!   committee attests it was the head, and a reorg can still drop it.
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
    types::{
        Bootstrap, FinalityUpdate, Fork, Forks, LightClientHeader, LightClientStore,
        OptimisticUpdate, SyncAggregate, Update,
    },
    verify_bootstrap, verify_finality_update, verify_optimistic_update, verify_update,
};
use serde::{Deserialize, Serialize};
use std::{fmt, path::PathBuf, time::SystemTime};
use tree_hash::TreeHash;

#[cfg(feature = "fetch")]
pub mod fetch;

type Spec = MainnetConsensusSpec;

/// Members of a sync committee.
pub const COMMITTEE_SIZE: u64 = 512;

/// Whether `participants` of the committee are the two thirds that
/// finalization needs (342 of 512): the rule helios applies when it moves
/// a store forward.
pub fn has_quorum(participants: u64) -> bool {
    participants * 3 >= COMMITTEE_SIZE * 2
}

/// Where the head files live in a bucket.
pub mod paths {
    use alloy_primitives::B256;

    pub const FINALITY: &str = "head/finality";
    pub const OPTIMISTIC: &str = "head/optimistic";
    /// The producer's unverified fast-confirmation report; see [`crate::FcrReport`].
    pub const FCR: &str = "head/fcr";

    pub fn bootstrap(block_root: &B256) -> String {
        format!("head/bootstrap/{block_root}")
    }

    pub fn update(period: u64) -> String {
        format!("head/updates/{period}")
    }
}

/// Which signed object a head comes from, and so what it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Tier {
    /// `head/finality`: a finalized checkpoint block, proven final by the
    /// finality branch of an update two thirds of the committee signed.
    /// Final: no reorg undoes it short of a third of all stake being
    /// slashed.
    Finalized,
    /// `head/optimistic`: the block two thirds of the committee signed as
    /// the head one slot after it. Not final: the committee attests what it
    /// saw, and a reorg can still drop the block (rare past one slot, and
    /// it would be the chain's reorg, not this bucket's).
    Attested,
}

impl Tier {
    pub fn name(self) -> &'static str {
        match self {
            Tier::Finalized => "finalized",
            Tier::Attested => "attested",
        }
    }

    /// The head file this tier is verified from.
    pub fn path(self) -> &'static str {
        match self {
            Tier::Finalized => paths::FINALITY,
            Tier::Attested => paths::OPTIMISTIC,
        }
    }

    fn reject(self, e: String) -> HeadError {
        match self {
            Tier::Finalized => HeadError::Finality(e),
            Tier::Attested => HeadError::Attested(e),
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
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
    /// The head's update (`head/finality`, or `head/optimistic` for the
    /// attested tier) was signed in period `signed` and the clock is
    /// already in `current`, two or more periods later: the producer has
    /// not published since. A head is good through
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
    /// The finality update failed verification: bad signature, under two
    /// thirds of the committee signing, wrong branch, a finalized header
    /// before the checkpoint, from the future.
    Finality(String),
    /// The optimistic update (`head/optimistic`) failed verification, for
    /// the same reasons: an attested header at slot 0 or before the
    /// checkpoint among them.
    Attested(String),
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
                "stale head: its update was signed in period {signed} \
                 and the clock is in period {current}: the producer has not published since"
            ),
            HeadError::Read(e) => write!(f, "head file unreadable: {e}"),
            HeadError::Decode { path, error } => write!(f, "{path}: {error}"),
            HeadError::Bootstrap(e) => write!(f, "bootstrap rejected: {e}"),
            HeadError::Update { period, error } => {
                write!(f, "update for period {period} rejected: {error}")
            }
            HeadError::Finality(e) => write!(f, "finality update rejected: {e}"),
            HeadError::Attested(e) => write!(f, "attested update rejected: {e}"),
            HeadError::NoExecution => write!(f, "head header has no execution payload"),
        }
    }
}

impl std::error::Error for HeadError {}

/// The execution block the head's beacon header commits to (finalized or
/// attested, as the head's [`Tier`] says). Its `state_root` is the root
/// every state read verifies against.
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
    /// Finalized or only attested: what the head promises.
    pub tier: Tier,
    /// The trust input.
    pub checkpoint: B256,
    pub slot: u64,
    pub beacon_root: B256,
    pub period: u64,
    /// Sync committee members that signed the head's update, of 512.
    pub participants: u64,
    /// Period updates applied on the way from the checkpoint.
    pub updates_applied: u64,
    pub execution: ExecutionHead,
    /// Now minus the head block's timestamp. For the finalized tier
    /// normally 13 to 19 minutes, unbounded in a finality stall; for the
    /// attested tier the producer's cadence and pipeline, minutes; for
    /// either, growing when the producer stops rewriting the file.
    pub lag_secs: u64,
}

/// A head update of either tier.
enum HeadUpdate {
    Finality(Box<FinalityUpdate<Spec>>),
    Optimistic(Box<OptimisticUpdate<Spec>>),
}

impl HeadUpdate {
    fn decode(tier: Tier, bytes: &[u8]) -> Result<HeadUpdate, HeadError> {
        Ok(match tier {
            Tier::Finalized => HeadUpdate::Finality(Box::new(decode(tier.path(), bytes)?)),
            Tier::Attested => HeadUpdate::Optimistic(Box::new(decode(tier.path(), bytes)?)),
        })
    }

    fn signature_slot(&self) -> u64 {
        match self {
            HeadUpdate::Finality(u) => *u.signature_slot(),
            HeadUpdate::Optimistic(u) => *u.signature_slot(),
        }
    }

    fn sync_aggregate(&self) -> &SyncAggregate<Spec> {
        match self {
            HeadUpdate::Finality(u) => u.sync_aggregate(),
            HeadUpdate::Optimistic(u) => u.sync_aggregate(),
        }
    }

    /// The header the head is: the finalized one, or the attested one.
    fn head_header(&self) -> LightClientHeader {
        match self {
            HeadUpdate::Finality(u) => u.finalized_header(),
            HeadUpdate::Optimistic(u) => u.attested_header(),
        }
    }

    fn verify(
        &self,
        current_slot: u64,
        store: &LightClientStore<Spec>,
        chain: &Chain,
    ) -> Result<(), String> {
        match self {
            HeadUpdate::Finality(u) => verify_finality_update::<Spec>(
                u,
                current_slot,
                store,
                chain.genesis_root,
                &chain.forks,
            ),
            HeadUpdate::Optimistic(u) => verify_optimistic_update::<Spec>(
                u,
                current_slot,
                store,
                chain.genesis_root,
                &chain.forks,
            ),
        }
        .map_err(|e| e.to_string())
    }
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

/// The period updates between a proven bootstrap and a head update (of
/// either tier) not yet verified, as of `current_period`: periods `b..s`,
/// `b` the bootstrap's and `s` the one the head update was signed in. An
/// update applied with a quorum and a finalized header in its own period
/// hands over to the next committee, so after `b..s` the store knows the
/// committee that signs in `s`; an update short of that leaves the store
/// where it was, and the head update then fails its period check. A head
/// update signed two or more periods before the clock's is stale; one
/// signed after it is from the future and is refused here, before any
/// update is asked for, so the range is bounded by the clock.
fn periods_between(
    bootstrap: &Bootstrap<Spec>,
    head: &HeadUpdate,
    tier: Tier,
    current_period: u64,
) -> Result<std::ops::Range<u64>, HeadError> {
    let first = calc_sync_period::<Spec>(bootstrap.header().beacon().slot);
    let signed = calc_sync_period::<Spec>(head.signature_slot());
    if signed > current_period {
        return Err(tier.reject(format!(
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

/// Verify the finalized head from `src` starting at `checkpoint`, as of
/// `now`: [`verify_tier`] with [`Tier::Finalized`], from `head/finality`.
pub fn verify(
    src: &dyn HeadSource,
    chain: &Chain,
    checkpoint: B256,
    now: SystemTime,
) -> Result<VerifiedHead, HeadError> {
    verify_tier(src, chain, checkpoint, now, Tier::Finalized)
}

/// Verify the attested head, from `head/optimistic`: [`verify_tier`] with
/// [`Tier::Attested`].
pub fn verify_attested(
    src: &dyn HeadSource,
    chain: &Chain,
    checkpoint: B256,
    now: SystemTime,
) -> Result<VerifiedHead, HeadError> {
    verify_tier(src, chain, checkpoint, now, Tier::Attested)
}

/// Verify the head of `tier` from `src` starting at `checkpoint`, as of
/// `now`: the bootstrap, then the head update's signing period (a head
/// signed two or more periods ago is stale), then the period updates from
/// the bootstrap's period up to the one the head update was signed in, in
/// order, then the head update itself (`head/finality` or
/// `head/optimistic`). Each step is checked against what the previous one
/// established; nothing is taken from the files on faith, not even which
/// period a file holds: `head/updates/<p>` must attest a header of period
/// `p`. The two tiers share every step but the last; the head is the
/// finality update's finalized header, or the optimistic update's attested
/// one, its execution fields proven by that header's execution branch.
/// `now` is a parameter so that a test can fix it.
pub fn verify_tier(
    src: &dyn HeadSource,
    chain: &Chain,
    checkpoint: B256,
    now: SystemTime,
    tier: Tier,
) -> Result<VerifiedHead, HeadError> {
    let bootstrap_path = paths::bootstrap(&checkpoint);
    let bytes = src
        .read_head(&bootstrap_path)
        .map_err(HeadError::Read)?
        .ok_or(HeadError::Missing(bootstrap_path))?;
    let bootstrap = checked_bootstrap(&bytes, checkpoint, chain)?;
    let mut store = LightClientStore::<Spec>::default();
    apply_bootstrap::<Spec>(&mut store, &bootstrap);

    let head_bytes = src
        .read_head(tier.path())
        .map_err(HeadError::Read)?
        .ok_or_else(|| HeadError::Missing(tier.path().to_string()))?;
    let head = HeadUpdate::decode(tier, &head_bytes)?;
    let current_slot = current_slot(chain, now);
    let current_period = calc_sync_period::<Spec>(current_slot);
    let periods = periods_between(&bootstrap, &head, tier, current_period)?;

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

    head.verify(current_slot, &store, chain)
        .map_err(|e| tier.reject(e))?;
    // Helios checks a head update's signature and proofs, but leaves the
    // two-thirds quorum to the step that applies it to a store, which this
    // path skips (and for an optimistic update asks only for more than its
    // safety threshold, a fraction of the participation seen). Without it
    // one committee member could sign a head of its own.
    let participants = get_bits::<Spec>(&head.sync_aggregate().sync_committee_bits);
    if !has_quorum(participants) {
        return Err(tier.reject(format!(
            "{participants} of {COMMITTEE_SIZE} signed, under two thirds"
        )));
    }

    // The head update's own header, not the store's: a period update can
    // carry a finalized header of its own, newer or older, and the head is
    // what the head file proves.
    let header = head.head_header();
    let beacon = header.beacon();
    // Helios reads a finalized header at slot 0 as "no finality yet" and
    // checks neither its finality branch nor its execution proof, so its
    // execution fields are whatever the file says. Nothing after genesis
    // finalizes or attests slot 0, and nothing before the checkpoint is a
    // head.
    if beacon.slot == 0 || beacon.slot < bootstrap.header().beacon().slot {
        return Err(tier.reject(format!(
            "{tier} slot {} is before the checkpoint's slot {}",
            beacon.slot,
            bootstrap.header().beacon().slot
        )));
    }
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
        tier,
        checkpoint,
        slot: beacon.slot,
        beacon_root: beacon.tree_hash_root(),
        period: calc_sync_period::<Spec>(beacon.slot),
        participants,
        updates_applied,
        execution,
        lag_secs: now_secs.saturating_sub(execution.timestamp),
    })
}

/// The period updates [`verify`] will read, given the bootstrap's and the
/// finality update's bytes: [`update_periods_for`] the finalized tier.
pub fn update_periods(
    bootstrap: &[u8],
    finality: &[u8],
    checkpoint: B256,
    chain: &Chain,
    now: SystemTime,
) -> Result<std::ops::Range<u64>, HeadError> {
    update_periods_for(Tier::Finalized, bootstrap, finality, checkpoint, chain, now)
}

/// The period updates [`verify_tier`] will read for `tier`, given the
/// bootstrap's and the head update's bytes: periods `b..s`, from the
/// bootstrap's to the one before the head update was signed in (empty when
/// it was signed in the bootstrap's period). The bootstrap is checked
/// against `checkpoint` first, and a stale or future head update is
/// refused here, so an error is the one `verify_tier` returns at the same
/// step. This lets a host ask for the bootstrap and the head updates in
/// one round and the period updates in the next, while `verify_tier` still
/// checks them in order. The head update is not verified here; its signing
/// period only bounds what the next round asks for.
pub fn update_periods_for(
    tier: Tier,
    bootstrap: &[u8],
    head: &[u8],
    checkpoint: B256,
    chain: &Chain,
    now: SystemTime,
) -> Result<std::ops::Range<u64>, HeadError> {
    let bootstrap = checked_bootstrap(bootstrap, checkpoint, chain)?;
    let head = HeadUpdate::decode(tier, head)?;
    let current = calc_sync_period::<Spec>(current_slot(chain, now));
    periods_between(&bootstrap, &head, tier, current)
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

/// `head/fcr`: what one named RPC's `safe` tag said about a block the
/// producer published, as the producer saw it. Nothing here is verified,
/// and nothing a light client holds could verify it: fast confirmation is
/// a full node's judgement over all the attestations it has seen. A client
/// shows it as the producer's report from a named source, and only next
/// to a head it verified at the same block hash.
#[derive(Debug, Clone, PartialEq)]
pub struct FcrReport {
    pub block_hash: B256,
    pub block_number: u64,
    /// Seconds from the block's timestamp to the first poll that saw the
    /// source's `safe` at or past it, on the same chain.
    pub confirmed_after_secs: u64,
    /// How many blocks the source's `safe` trailed its `latest` then.
    pub trail_blocks: u64,
    pub classification: FcrClass,
    /// The host of the RPC, never its full URL (which may carry a key).
    pub source: String,
    /// Unix seconds of that poll.
    pub checked_at: u64,
}

/// What a source's `safe` tag behaves like, from how far it trails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FcrClass {
    /// Within [`FCR_LIKE_TRAIL`] blocks of `latest`: a fast-confirmation rule.
    FcrLike,
    /// Further behind: the justified checkpoint, which is what most public
    /// endpoints serve as `safe`.
    JustifiedLike,
}

/// The most blocks `safe` may trail `latest` and still look like a
/// fast-confirmation rule rather than justification (which trails by
/// roughly one to two epochs, 30 to 60 blocks).
pub const FCR_LIKE_TRAIL: u64 = 4;

impl FcrClass {
    pub fn of_trail(trail_blocks: u64) -> FcrClass {
        if trail_blocks <= FCR_LIKE_TRAIL {
            FcrClass::FcrLike
        } else {
            FcrClass::JustifiedLike
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            FcrClass::FcrLike => "fcr_like",
            FcrClass::JustifiedLike => "justified_like",
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FcrWire {
    block_hash: String,
    block_number: u64,
    confirmed_after_secs: u64,
    trail_blocks: u64,
    classification: FcrClass,
    source: String,
    checked_at: u64,
}

impl FcrReport {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(&FcrWire {
            block_hash: self.block_hash.to_string(),
            block_number: self.block_number,
            confirmed_after_secs: self.confirmed_after_secs,
            trail_blocks: self.trail_blocks,
            classification: self.classification,
            source: self.source.clone(),
            checked_at: self.checked_at,
        })
        .expect("serializes")
    }

    /// The report, or `None` for bytes that are not one.
    pub fn from_json(bytes: &[u8]) -> Option<FcrReport> {
        let w: FcrWire = serde_json::from_slice(bytes).ok()?;
        Some(FcrReport {
            block_hash: w.block_hash.parse().ok()?,
            block_number: w.block_number,
            confirmed_after_secs: w.confirmed_after_secs,
            trail_blocks: w.trail_blocks,
            classification: w.classification,
            source: w.source,
            checked_at: w.checked_at,
        })
    }

    /// The report if it is about `head`'s block, else `None`: a report for
    /// another block (an older snapshot, or another chain) says nothing.
    pub fn about(self, head: &ExecutionHead) -> Option<FcrReport> {
        (self.block_hash == head.block_hash && self.block_number == head.block_number)
            .then_some(self)
    }
}
