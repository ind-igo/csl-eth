//! A snapshot at the head the bucket itself proves (profile §3). The head
//! files are read through the same [`Store`] as the state, verified from
//! the client's one trust input, and the snapshot opened is the one at the
//! finalized execution block, with that header's `state_root`. A bucket
//! whose newest snapshot is at some other block is not opened: for the
//! slice milestone the published snapshot must be the finalized one, and a
//! lagging snapshot is an error that says which block it is at.
//!
//! Opening is rounds like everything else, and the head is at most two of
//! them however old the checkpoint: the bootstrap and the finality update
//! together, then at once every period update from the bootstrap's period
//! up to the one the finality update was signed in (the bootstrap names the
//! first, the finality update the last; none when they share a period, and
//! then there is no second round); then the manifest, then the models. The
//! verifier still reads and checks them in its order, each against what
//! the last established; only when the bytes are asked for changed.

use crate::{manifest_path, At, Driver, Opener, Pending, Snapshot, Store, PENDING};
use alloy_primitives::B256;
use csl_eth_head::{paths, update_periods, verify, HeadSource};
pub use csl_eth_head::{Chain, ExecutionHead, HeadError, VerifiedHead};
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
    /// The bucket has no snapshot at the finalized block. `newest` is the
    /// block its `latest` names, when that could be read.
    NotAtHead {
        finalized: ExecutionHead,
        newest: Option<(u64, B256)>,
    },
    Open(String),
}

impl fmt::Display for HeadOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeadOpenError::Head(e) => write!(f, "head: {e}"),
            HeadOpenError::NotAtHead {
                finalized,
                newest: Some((n, h)),
            } => {
                write!(f, "no snapshot at finalized block {} ({}); the bucket's newest is block {n} ({h})", finalized.block_number, finalized.block_hash)
            }
            HeadOpenError::NotAtHead {
                finalized,
                newest: None,
            } => {
                write!(
                    f,
                    "no snapshot at finalized block {} ({})",
                    finalized.block_number, finalized.block_hash
                )
            }
            HeadOpenError::Open(e) => write!(f, "snapshot: {e}"),
        }
    }
}

impl std::error::Error for HeadOpenError {}

/// Verify the head from the store, or `Pending` with the next round's
/// files. Round 1 is the bootstrap and `head/finality`; round 2 the period
/// updates between them, which the finality update's signing period bounds
/// before it is verified. A bootstrap or finality update that is absent,
/// does not prove the checkpoint or is stale asks for no updates: `verify`
/// then refuses it with the same error it always did.
fn try_verify(
    store: &Store,
    checkpoint: B256,
    now: SystemTime,
) -> Result<Result<VerifiedHead, HeadError>, Pending> {
    let chain = Chain::mainnet();
    let bootstrap = store.file(&paths::bootstrap(&checkpoint));
    let finality = store.file(paths::FINALITY);
    let (Ok(bootstrap), Ok(finality)) = (bootstrap, finality) else {
        return Err(Pending);
    };
    if let (Ok(Some(b)), Ok(Some(f))) = (&bootstrap, &finality) {
        if let Ok(periods) = update_periods(b, f, checkpoint, &chain, now) {
            let mut pending = false;
            for p in periods {
                pending |= store.file(&paths::update(p)).is_err();
            }
            if pending {
                return Err(Pending);
            }
        }
    }
    match verify(&StoreHead(store), &chain, checkpoint, now) {
        Err(HeadError::Read(s)) if s == PENDING => Err(Pending),
        r => Ok(r),
    }
}

/// The head verified from `checkpoint` as of `now`, synchronously through
/// `driver`.
pub fn verify_head<D: Driver>(
    driver: &D,
    checkpoint: B256,
    now: SystemTime,
) -> Result<VerifiedHead, HeadError> {
    let store = Store::new();
    loop {
        match try_verify(&store, checkpoint, now) {
            Ok(r) => return r,
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
    /// The head once verified, so later rounds do not verify it again.
    head: Option<VerifiedHead>,
    inner: Option<Opener<D>>,
}

impl<D: Driver> HeadOpener<D> {
    pub fn new(driver: D, checkpoint: B256, now: SystemTime) -> HeadOpener<D> {
        HeadOpener {
            driver: Some(driver),
            store: Store::new(),
            checkpoint,
            now,
            head: None,
            inner: None,
        }
    }

    pub fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The head, once a `try_open` has verified it.
    pub fn head(&self) -> Option<&VerifiedHead> {
        self.head.as_ref()
    }

    /// One synchronous round through the driver.
    pub fn round(&self) {
        match (&self.driver, &self.inner) {
            (Some(d), _) => crate::drive(d, &self.store, true),
            (None, Some(o)) => o.round(),
            (None, None) => {}
        }
    }

    /// Verify the head and open the snapshot it names from what the store
    /// holds, or `Pending` with the next round wanted.
    #[allow(clippy::type_complexity)]
    pub fn try_open(
        &mut self,
    ) -> Result<Result<(Snapshot<D>, VerifiedHead), HeadOpenError>, Pending> {
        if self.head.is_none() {
            match try_verify(&self.store, self.checkpoint, self.now)? {
                Ok(h) => self.head = Some(h),
                Err(e) => return Ok(Err(HeadOpenError::Head(e))),
            }
        }
        let head = self.head.clone().expect("set above");
        let at = head.execution.block_hash;
        if self.inner.is_none() {
            let present = match self.store.file(&manifest_path(&at))? {
                Ok(p) => p.is_some(),
                Err(e) => return Ok(Err(HeadOpenError::Open(e))),
            };
            if !present {
                let newest = self.newest()?;
                return Ok(Err(HeadOpenError::NotAtHead {
                    finalized: head.execution,
                    newest,
                }));
            }
            let driver = self.driver.take().expect("taken once");
            self.inner = Some(Opener::new(
                driver,
                self.store.clone(),
                At::Block(at),
                head.execution.state_root,
            ));
        }
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
/// at the finalized execution block with its verified `state_root`.
/// Synchronous: the driver fetches each round.
#[allow(clippy::result_large_err)]
pub fn open_at_head<D: Driver>(
    driver: D,
    checkpoint: B256,
    now: SystemTime,
) -> Result<(Snapshot<D>, VerifiedHead), HeadOpenError> {
    let mut o = HeadOpener::new(driver, checkpoint, now);
    loop {
        match o.try_open() {
            Ok(r) => return r,
            Err(Pending) => o.round(),
        }
    }
}
