//! A snapshot at the head the bucket itself proves (profile §3). The head
//! files are read through the same [`Store`] as the state, verified from
//! the client's one trust input, and the snapshot opened is the one at the
//! head's execution block, with that header's `state_root`.
//!
//! There are two heads, one per [`Tier`]. `head/optimistic` names the
//! block most of the sync committee attested a few minutes ago; it is
//! fresh but can still be reorged out. `head/finality` names a finalized
//! checkpoint, 13 to 19 minutes old or more, that cannot. Both verify
//! through the same walk from the checkpoint. [`TierChoice::Best`] takes
//! the attested head when it verifies, is newer than the finalized one and
//! its snapshot is in the bucket, and the finalized head otherwise; the
//! result always says which it is.
//!
//! Opening is rounds like everything else, and the head is at most two of
//! them however old the checkpoint: the bootstrap and the head updates
//! together (and `head/fcr`, an unverified note, when the attested tier is
//! wanted), then at once every period update from the bootstrap's period
//! up to the one the newest head update was signed in (none when they
//! share a period, and then there is no second round); then the manifests
//! of the heads that verified, then the models. The verifier still reads
//! and checks them in its order, each against what the last established;
//! only when the bytes are asked for changed.

use crate::{manifest_path, At, Driver, Opener, Pending, Snapshot, Store, PENDING};
use alloy_primitives::B256;
use csl_eth_head::{paths, update_periods_for, verify_tier, HeadSource};
pub use csl_eth_head::{Chain, ExecutionHead, FcrClass, FcrReport, HeadError, Tier, VerifiedHead};
use csl_eth_store::Manifest;
use std::{fmt, sync::Arc, time::SystemTime};

/// Head files through the store; a file not yet fetched is a pending read.
struct StoreHead<'a>(&'a Store);

impl HeadSource for StoreHead<'_> {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        match self.0.file(rel) {
            Ok(got) => got,
            Err(Pending) => Err(PENDING.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeadOpenError {
    Head(HeadError),
    /// The bucket has no snapshot at the head's block. `newest` is the
    /// block its `latest` names, when that could be read.
    NotAtHead {
        head: ExecutionHead,
        tier: Tier,
        newest: Option<(u64, B256)>,
    },
    Open(String),
}

impl fmt::Display for HeadOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeadOpenError::Head(e) => write!(f, "head: {e}"),
            HeadOpenError::NotAtHead { head, tier, newest } => {
                write!(
                    f,
                    "no snapshot at {tier} block {} ({})",
                    head.block_number, head.block_hash
                )?;
                if let Some((n, h)) = newest {
                    write!(f, "; the bucket's newest is block {n} ({h})")?;
                }
                Ok(())
            }
            HeadOpenError::Open(e) => write!(f, "snapshot: {e}"),
        }
    }
}

impl std::error::Error for HeadOpenError {}

/// Which head an opener uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TierChoice {
    /// The attested head when it verifies, is newer than the finalized one
    /// and its snapshot is present; the finalized head otherwise.
    #[default]
    Best,
    /// Only `head/finality`; `head/optimistic` is never read.
    Finalized,
    /// Only `head/optimistic`.
    Attested,
}

impl TierChoice {
    fn tiers(self) -> &'static [Tier] {
        match self {
            TierChoice::Best => &[Tier::Attested, Tier::Finalized],
            TierChoice::Finalized => &[Tier::Finalized],
            TierChoice::Attested => &[Tier::Attested],
        }
    }

    /// `best`, `finalized` or `attested`.
    pub fn parse(s: &str) -> Option<TierChoice> {
        match s {
            "best" | "" => Some(TierChoice::Best),
            "finalized" => Some(TierChoice::Finalized),
            "attested" => Some(TierChoice::Attested),
            _ => None,
        }
    }
}

/// Verify each of `tiers`' heads from the store, or `Pending` with the next
/// round's files. Round 1 is the bootstrap, each tier's update file and
/// `extra`; round 2 the period updates every head update needs, which its
/// signing period bounds before it is verified. A file that is absent,
/// does not prove the checkpoint or is stale asks for no updates: the
/// verifier then refuses it with the same error it always did.
#[allow(clippy::type_complexity)]
fn try_verify(
    store: &Store,
    checkpoint: B256,
    now: SystemTime,
    tiers: &[Tier],
    extra: &[&str],
) -> Result<Vec<Result<VerifiedHead, HeadError>>, Pending> {
    let chain = Chain::mainnet();
    let bootstrap = store.file(&paths::bootstrap(&checkpoint));
    let heads: Vec<_> = tiers.iter().map(|t| store.file(t.path())).collect();
    let extra_pending = extra.iter().any(|p| store.file(p).is_err());
    let Ok(bootstrap) = bootstrap else {
        return Err(Pending);
    };
    if extra_pending || heads.iter().any(Result::is_err) {
        return Err(Pending);
    }
    if let Ok(Some(b)) = &bootstrap {
        let mut want = std::collections::BTreeSet::new();
        for (t, h) in tiers.iter().zip(&heads) {
            if let Ok(Ok(Some(h))) = h {
                if let Ok(ps) = update_periods_for(*t, b, h, checkpoint, &chain, now) {
                    want.extend(ps);
                }
            }
        }
        let mut pending = false;
        for p in want {
            pending |= store.file(&paths::update(p)).is_err();
        }
        if pending {
            return Err(Pending);
        }
    }
    let mut out = Vec::new();
    for t in tiers {
        match verify_tier(&StoreHead(store), &chain, checkpoint, now, *t) {
            Err(HeadError::Read(s)) if s == PENDING => return Err(Pending),
            r => out.push(r),
        }
    }
    Ok(out)
}

/// The finalized head verified from `checkpoint` as of `now`,
/// synchronously through `driver`.
pub fn verify_head<D: Driver>(
    driver: &D,
    checkpoint: B256,
    now: SystemTime,
) -> Result<VerifiedHead, HeadError> {
    let store = Store::new();
    loop {
        match try_verify(&store, checkpoint, now, &[Tier::Finalized], &[]) {
            Ok(mut r) => return r.remove(0),
            Err(Pending) => crate::drive(driver, &store, true),
        }
    }
}

/// A snapshot being opened through the head.
pub struct HeadOpener<D> {
    driver: Option<D>,
    store: Arc<Store>,
    checkpoint: B256,
    now: SystemTime,
    choice: TierChoice,
    /// The heads that verified, preferred first, so later rounds do not
    /// verify them again.
    candidates: Option<Vec<VerifiedHead>>,
    /// The one whose snapshot is being opened.
    head: Option<VerifiedHead>,
    fcr: Option<FcrReport>,
    inner: Option<Opener<D>>,
}

impl<D: Driver> HeadOpener<D> {
    /// An opener over [`TierChoice::Best`].
    pub fn new(driver: D, checkpoint: B256, now: SystemTime) -> HeadOpener<D> {
        HeadOpener::with_tier(driver, checkpoint, now, TierChoice::Best)
    }

    pub fn with_tier(
        driver: D,
        checkpoint: B256,
        now: SystemTime,
        choice: TierChoice,
    ) -> HeadOpener<D> {
        HeadOpener {
            driver: Some(driver),
            store: Store::new(),
            checkpoint,
            now,
            choice,
            candidates: None,
            head: None,
            fcr: None,
            inner: None,
        }
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The head being opened once chosen, else the preferred one that
    /// verified, once a `try_open` has verified it.
    pub fn head(&self) -> Option<&VerifiedHead> {
        self.head
            .as_ref()
            .or_else(|| self.candidates.as_ref().and_then(|c| c.first()))
    }

    /// The producer's `head/fcr` report, when the head chosen is attested
    /// and the report is about its block. Unverified: see [`FcrReport`].
    pub fn fcr(&self) -> Option<&FcrReport> {
        self.fcr.as_ref()
    }

    /// One synchronous round through the driver.
    pub fn round(&self) {
        match (&self.driver, &self.inner) {
            (Some(d), _) => crate::drive(d, &self.store, true),
            (None, Some(o)) => o.round(),
            (None, None) => {}
        }
    }

    /// The heads that verified, preferred first, or the error to report
    /// when none did.
    fn choose(
        &self,
        verified: Vec<Result<VerifiedHead, HeadError>>,
    ) -> Result<Vec<VerifiedHead>, HeadError> {
        let mut ok = Vec::new();
        let mut errs = Vec::new();
        for (t, r) in self.choice.tiers().iter().zip(verified) {
            match r {
                Ok(h) => ok.push(h),
                Err(e) => errs.push((*t, e)),
            }
        }
        // An attested head no newer than the finalized one adds nothing:
        // the producer stopped writing it, or finality caught up.
        if let [a, f] = &ok[..] {
            if a.slot <= f.slot {
                ok.remove(0);
            }
        }
        if !ok.is_empty() {
            return Ok(ok);
        }
        // Neither: the finalized tier's error, unless that is only that
        // the bucket has no finality update yet (a producer's first
        // minutes) and the attested tier failed for a real reason.
        let missing = |e: &HeadError| matches!(e, HeadError::Missing(_));
        let fin = errs.iter().position(|(t, _)| *t == Tier::Finalized);
        let pick = match fin {
            Some(i) if missing(&errs[i].1) => errs
                .iter()
                .position(|(t, e)| *t == Tier::Attested && !missing(e))
                .unwrap_or(i),
            Some(i) => i,
            None => 0,
        };
        Err(errs.swap_remove(pick).1)
    }

    /// Verify the head and open the snapshot it names from what the store
    /// holds, or `Pending` with the next round wanted.
    #[allow(clippy::type_complexity)]
    pub fn try_open(
        &mut self,
    ) -> Result<Result<(Snapshot<D>, VerifiedHead), HeadOpenError>, Pending> {
        if self.candidates.is_none() {
            let extra: &[&str] = match self.choice {
                TierChoice::Finalized => &[],
                _ => &[paths::FCR],
            };
            let r = try_verify(
                &self.store,
                self.checkpoint,
                self.now,
                self.choice.tiers(),
                extra,
            )?;
            match self.choose(r) {
                Ok(c) => self.candidates = Some(c),
                Err(e) => return Ok(Err(HeadOpenError::Head(e))),
            }
        }
        if self.inner.is_none() {
            let candidates = self.candidates.clone().expect("set above");
            // Every candidate's manifest in one round, so falling back
            // costs no round of its own. A candidate is chosen only if its
            // manifest passes every check the open makes before reading a
            // table (its block, its format, the head's state root), so an
            // attested snapshot that is there but unusable falls back to
            // the finalized one too.
            let present: Vec<_> = candidates
                .iter()
                .map(|h| self.store.file(&manifest_path(&h.execution.block_hash)))
                .collect();
            let mut chosen = None;
            let mut error = None;
            for (h, p) in candidates.iter().zip(present) {
                match p? {
                    Ok(Some(m)) => {
                        let ex = &h.execution;
                        match crate::check_manifest(&m, ex.block_hash, ex.state_root) {
                            Ok(_) => {
                                chosen.get_or_insert(h.clone());
                            }
                            Err(e) => {
                                error.get_or_insert(format!(
                                    "{} head's snapshot: {e}",
                                    h.tier.name()
                                ));
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => {
                        error.get_or_insert(e);
                    }
                }
            }
            let Some(head) = chosen else {
                if let Some(e) = error {
                    return Ok(Err(HeadOpenError::Open(e)));
                }
                // Name the last-resort head: finalized under `Best`.
                let head = candidates.last().expect("not empty").clone();
                let newest = self.newest()?;
                return Ok(Err(HeadOpenError::NotAtHead {
                    head: head.execution,
                    tier: head.tier,
                    newest,
                }));
            };
            if head.tier == Tier::Attested {
                if let Ok(Ok(Some(b))) = self.store.file(paths::FCR) {
                    self.fcr = FcrReport::from_json(&b).and_then(|r| r.about(&head.execution));
                }
            }
            let driver = self.driver.take().expect("taken once");
            self.inner = Some(Opener::new(
                driver,
                self.store.clone(),
                At::Block(head.execution.block_hash),
                head.execution.state_root,
            ));
            self.head = Some(head);
        }
        let head = self.head.clone().expect("set above");
        let inner = self.inner.as_mut().expect("set above");
        match inner.try_open()? {
            Ok(snap) => Ok(Ok((snap, head))),
            Err(e) => Ok(Err(HeadOpenError::Open(e))),
        }
    }

    /// The block `latest` names, for the error that says the bucket lags.
    fn newest(&self) -> Result<Option<(u64, B256)>, Pending> {
        let Ok(Some(s)) = self.store.file(csl_eth_store::LATEST_FILE)? else {
            return Ok(None);
        };
        let Some(h) = String::from_utf8(s)
            .ok()
            .and_then(|s| hex::decode(s.trim()).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .map(B256::from)
        else {
            return Ok(None);
        };
        let Ok(Some(m)) = self.store.file(&manifest_path(&h))? else {
            return Ok(None);
        };
        Ok(Manifest::from_json(&m).ok().map(|m| (m.block_number, h)))
    }
}

/// Verify the head from `checkpoint` as of `now`, then open the snapshot
/// at its execution block with its verified `state_root`: the attested
/// head when it is newer and present, the finalized one otherwise
/// ([`TierChoice::Best`]). Synchronous: the driver fetches each round.
#[allow(clippy::result_large_err)]
pub fn open_at_head<D: Driver>(
    driver: D,
    checkpoint: B256,
    now: SystemTime,
) -> Result<(Snapshot<D>, VerifiedHead), HeadOpenError> {
    open_at_head_with(driver, checkpoint, now, TierChoice::Best).map(|(s, h, _)| (s, h))
}

/// [`open_at_head`] with the tier chosen, also returning the producer's
/// unverified `head/fcr` report when it is about the head opened.
#[allow(clippy::result_large_err, clippy::type_complexity)]
pub fn open_at_head_with<D: Driver>(
    driver: D,
    checkpoint: B256,
    now: SystemTime,
    choice: TierChoice,
) -> Result<(Snapshot<D>, VerifiedHead, Option<FcrReport>), HeadOpenError> {
    let mut o = HeadOpener::with_tier(driver, checkpoint, now, choice);
    loop {
        match o.try_open() {
            Ok(r) => return r.map(|(s, h)| (s, h, o.fcr().cloned())),
            Err(Pending) => o.round(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(tier: Tier, slot: u64) -> VerifiedHead {
        VerifiedHead {
            tier,
            checkpoint: B256::ZERO,
            slot,
            beacon_root: B256::ZERO,
            period: slot / 8192,
            participants: 500,
            updates_applied: 0,
            execution: ExecutionHead {
                block_number: slot,
                block_hash: B256::with_last_byte(slot as u8),
                state_root: B256::ZERO,
                timestamp: 0,
            },
            lag_secs: 0,
        }
    }

    fn choose(
        choice: TierChoice,
        r: Vec<Result<VerifiedHead, HeadError>>,
    ) -> Result<Vec<(Tier, u64)>, HeadError> {
        let o = HeadOpener::with_tier(crate::NoDriver, B256::ZERO, SystemTime::UNIX_EPOCH, choice);
        o.choose(r)
            .map(|v| v.iter().map(|h| (h.tier, h.slot)).collect())
    }

    #[test]
    fn best_prefers_a_newer_attested_head_and_keeps_the_finalized_behind_it() {
        use Tier::*;
        let best = TierChoice::Best;
        assert_eq!(
            choose(best, vec![Ok(head(Attested, 100)), Ok(head(Finalized, 36))]),
            Ok(vec![(Attested, 100), (Finalized, 36)])
        );
        // Stalled: an attested head no newer than finality adds nothing.
        for slot in [36, 10] {
            assert_eq!(
                choose(
                    best,
                    vec![Ok(head(Attested, slot)), Ok(head(Finalized, 36))]
                ),
                Ok(vec![(Finalized, 36)])
            );
        }
        let missing = |p: &str| HeadError::Missing(p.to_string());
        assert_eq!(
            choose(
                best,
                vec![Err(missing(paths::OPTIMISTIC)), Ok(head(Finalized, 36))]
            ),
            Ok(vec![(Finalized, 36)])
        );
        // Both fail: the finalized error, unless it is only "no finality
        // update yet".
        let stale = HeadError::Stale {
            signed: 1,
            current: 3,
        };
        assert_eq!(
            choose(
                best,
                vec![Err(stale.clone()), Err(missing(paths::FINALITY))]
            ),
            Err(stale.clone())
        );
        assert_eq!(
            choose(
                best,
                vec![Err(missing(paths::OPTIMISTIC)), Err(stale.clone())]
            ),
            Err(stale)
        );
        assert_eq!(
            choose(
                best,
                vec![
                    Err(missing(paths::OPTIMISTIC)),
                    Err(missing(paths::FINALITY))
                ]
            ),
            Err(missing(paths::FINALITY))
        );
    }
}
