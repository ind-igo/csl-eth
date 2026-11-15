//! Export a stopped reth node's whole state at one block into the csl-eth
//! bucket layout: `csl_eth_store::export` over reth's hashed tables.
//!
//! reth (storage v2) keeps the current state in MDBX as `HashedAccounts`
//! (keccak(address) → nonce, balance, code hash; no storage root) and
//! `HashedStorages` (keccak(address) → keccak(slot) → word, dup-sorted),
//! both in ascending key order, which is the order the exporter needs, and
//! bytecode by hash in `Bytecodes`. The node must be stopped (or at least
//! not writing) and synced to exactly the block given: this checks reth's
//! best block and its hash before reading anything, and the exporter checks
//! the root it computes against the given `state_root` before writing
//! anything. So a wrong or half-synced database cannot publish a snapshot.
//!
//!   export-reth --datadir /data/reth --block-hash 0x… --block-number N \
//!     --timestamp T --state-root 0x… --out /data/out [--workers W]
//!
//! The storage tries are built on `--workers` threads over ranges of the
//! hashed-address space, each reading through a read transaction of its own
//! from one `ProviderFactory` (MDBX read transactions belong to the thread
//! that opened them). Reading reth is mostly waiting on page faults of its
//! memory map, one at a time per thread, so more threads than cores keep
//! the disk busy; the default is twice the cores. Every transaction sees
//! the same database because the node is stopped, and each checks the best
//! block again when it opens.
//!
//! Progress goes to stderr as one JSON line per tick; the final stats go to
//! stdout.

use alloy_primitives::{B256, U256};
use clap::Parser;
use csl_eth_store::{export, AccountRange, ExportOptions, ExportStats, SourceAccount, Sources, StateSource};
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    node::EthereumNode,
    provider::{
        db::{
            cursor::{DbCursorRO, DbDupCursorRO},
            tables,
            transaction::DbTx,
            Database, DatabaseError,
        },
        providers::{ProviderNodeTypes, ReadOnlyConfig},
        BlockHashReader, BlockNumReader, ProviderError, ProviderFactory,
    },
};
use std::io::Write as _;
use std::{
    cell::{RefCell, RefMut},
    path::PathBuf,
    time::Duration,
};

#[derive(Parser)]
struct Args {
    /// reth's datadir (holding db/ and static_files/).
    #[arg(long)]
    datadir: PathBuf,
    #[arg(long)]
    block_hash: B256,
    #[arg(long)]
    block_number: u64,
    #[arg(long)]
    timestamp: u64,
    #[arg(long)]
    state_root: B256,
    /// The bucket directory to write (snapshots/, blobs/ under it).
    #[arg(long)]
    out: PathBuf,
    /// Scratch for the external sorts; about the output's size.
    #[arg(long)]
    scratch: Option<PathBuf>,
    /// Export memory, GiB: sort chunks for every worker and the main
    /// thread, and finished accounts waiting for the account trie. It need
    /// not be large (the chunks only keep each table's spills within one
    /// merge's fan-in of 1,024); what it leaves is page cache for reth's
    /// database, which the build reads at random.
    #[arg(long, default_value_t = 16)]
    memory_gib: u64,
    /// Threads building storage tries. Default: twice the cores.
    #[arg(long)]
    workers: Option<usize>,
    /// Parts the hashed-address space is cut into for the workers.
    #[arg(long, default_value_t = csl_eth_store::DEFAULT_RANGES)]
    ranges: usize,
    /// Also write nodes_by_hash (the baseline table; roughly doubles the output).
    #[arg(long)]
    by_hash: bool,
}

/// Opens one reader per thread, each on a read transaction of its own.
struct Readers<N: ProviderNodeTypes> {
    factory: ProviderFactory<N>,
    block_number: u64,
}

impl<N: ProviderNodeTypes> Sources for Readers<N> {
    type Error = ProviderError;
    type Source<'a>
        = Reth<<N::DB as Database>::TX>
    where
        Self: 'a;

    fn open(&self) -> Result<Self::Source<'_>, ProviderError> {
        let provider = self.factory.provider()?;
        // The node is stopped, so every transaction sees the block main()
        // checked; this guards against one that was not.
        let best = provider.best_block_number()?;
        if best != self.block_number {
            return Err(ProviderError::other(std::io::Error::other(format!("reth's best block moved to {best} from {}", self.block_number))));
        }
        let tx = provider.into_tx();
        let cursor = tx.cursor_dup_read::<tables::HashedStorages>()?;
        Ok(Reth { storage: RefCell::new(StorageWalk { cursor, at: None, positioned: false }), tx })
    }
}

/// One thread's read transaction; every cursor is opened from it.
///
/// Storage is read through one cursor that walks `HashedStorages` forward
/// beside the accounts (a reader is asked for each account's storage in
/// ascending order, across its ranges too, and drains or drops it before
/// the next): an account with no storage costs a comparison with the owner
/// the cursor is on, not a cursor and a seek. ~3e8 accounts, most without
/// storage.
struct Reth<Tx: DbTx> {
    tx: Tx,
    storage: RefCell<StorageWalk<Tx::DupCursor<tables::HashedStorages>>>,
}

struct StorageWalk<C> {
    cursor: C,
    /// The entry the cursor is on, as (owner, slot, word); None past the end.
    at: Option<(B256, B256, U256)>,
    /// Whether the cursor has been placed yet (by a first seek).
    positioned: bool,
}

fn entry(got: Option<(alloy_primitives::B256, reth_ethereum::primitives::StorageEntry)>) -> Option<(B256, B256, U256)> {
    got.map(|(owner, e)| (B256::from(owner.0), B256::from(e.key.0), U256::from_limbs(*e.value.as_limbs())))
}

struct Accounts<C> {
    cursor: C,
    range: AccountRange,
    started: bool,
    done: bool,
}

impl<C: DbCursorRO<tables::HashedAccounts>> Iterator for Accounts<C> {
    type Item = Result<SourceAccount, DatabaseError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let got = if self.started {
            self.cursor.next()
        } else {
            self.started = true;
            self.cursor.seek(self.range.start)
        };
        match got {
            Ok(Some((hashed, _))) if self.range.end.is_some_and(|e| B256::from(hashed.0) >= e) => {
                self.done = true;
                None
            }
            Ok(Some((hashed, a))) => Some(Ok(SourceAccount {
                hashed: B256::from(hashed.0),
                nonce: a.nonce,
                balance: U256::from_limbs(*a.balance.as_limbs()),
                code_hash: B256::from(a.get_bytecode_hash().0),
            })),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

struct Slots<'a, C> {
    walk: RefMut<'a, StorageWalk<C>>,
    owner: B256,
}

impl<C: DbDupCursorRO<tables::HashedStorages> + DbCursorRO<tables::HashedStorages>> Iterator for Slots<'_, C> {
    type Item = Result<(B256, U256), DatabaseError>;
    fn next(&mut self) -> Option<Self::Item> {
        let (owner, slot, word) = self.walk.at?;
        if owner != self.owner {
            return None;
        }
        match self.walk.cursor.next() {
            Ok(got) => self.walk.at = entry(got),
            Err(e) => {
                self.walk.at = None;
                return Some(Err(e));
            }
        }
        Some(Ok((slot, word)))
    }
}

struct Codes<C> {
    cursor: C,
    started: bool,
}

impl<C: DbCursorRO<tables::Bytecodes>> Iterator for Codes<C> {
    type Item = Result<(B256, Vec<u8>), DatabaseError>;
    fn next(&mut self) -> Option<Self::Item> {
        let got = if self.started {
            self.cursor.next()
        } else {
            self.started = true;
            self.cursor.first()
        };
        match got {
            Ok(Some((hash, code))) => Some(Ok((B256::from(hash.0), code.original_bytes().to_vec()))),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}

impl<Tx: DbTx> StateSource for Reth<Tx> {
    type Error = DatabaseError;
    type Accounts<'a>
        = Accounts<Tx::Cursor<tables::HashedAccounts>>
    where
        Self: 'a;
    type Storage<'a>
        = Slots<'a, Tx::DupCursor<tables::HashedStorages>>
    where
        Self: 'a;

    fn accounts(&self, range: &AccountRange) -> Result<Self::Accounts<'_>, DatabaseError> {
        Ok(Accounts { cursor: self.tx.cursor_read::<tables::HashedAccounts>()?, range: *range, started: false, done: false })
    }

    fn storage(&self, hashed: &B256) -> Result<Self::Storage<'_>, DatabaseError> {
        let mut walk = self.storage.borrow_mut();
        // Not yet placed, or behind the account (a new one, or one whose
        // slots were not all read): seek, which only ever moves forward
        // here, since a reader's accounts ascend.
        if !walk.positioned || matches!(walk.at, Some((owner, _, _)) if owner < *hashed) {
            walk.positioned = true;
            let got = walk.cursor.seek(*hashed)?;
            walk.at = entry(got);
        }
        Ok(Slots { walk, owner: *hashed })
    }

    fn code(&self, code_hash: &B256) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self.tx.get::<tables::Bytecodes>(*code_hash)?.map(|c| c.original_bytes().to_vec()))
    }

    fn codes(&self) -> Option<Result<csl_eth_store::CodeIter<'_, DatabaseError>, DatabaseError>> {
        Some(self.tx.cursor_read::<tables::Bytecodes>().map(|cursor| Box::new(Codes { cursor, started: false }) as csl_eth_store::CodeIter<'_, DatabaseError>))
    }
}

fn line(s: &ExportStats) -> serde_json::Value {
    serde_json::json!({
        "phase": format!("{:?}", s.phase),
        "workers": s.workers,
        "accounts": s.accounts,
        "storage_slots": s.storage_slots,
        "storage_tries": s.storage_tries,
        "largest_storage": s.largest_storage.0,
        "building": s.building.1,
        "build_wait_s": s.build_wait.as_secs(),
        "code_refs": s.code_refs,
        "account_nodes": s.account_nodes,
        "storage_nodes": s.storage_nodes,
        "spill_gb": s.spill_bytes() as f64 / 1e9,
        "peak_sort_gb": s.peak_sort_bytes as f64 / 1e9,
        "written": s.written,
        "elapsed_s": s.elapsed.as_secs(),
    })
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();
    let spec = ChainSpecBuilder::mainnet().build();
    let runtime = reth_ethereum::tasks::Runtime::test();
    let factory = EthereumNode::provider_factory_builder().open_read_only(
        spec.into(),
        ReadOnlyConfig::from_datadir(&args.datadir).no_watch().disable_long_read_transaction_safety(),
        runtime,
    )?;
    let provider = factory.provider()?;

    // The database must be at exactly the block the head files proved.
    let best = provider.best_block_number()?;
    let hash = provider.block_hash(args.block_number)?;
    eyre::ensure!(best == args.block_number, "reth's best block is {best}, not {}", args.block_number);
    eyre::ensure!(
        hash.map(|h| B256::from(h.0)) == Some(args.block_hash),
        "reth's block {} is {hash:?}, not {}",
        args.block_number,
        args.block_hash
    );
    eprintln!("{}", serde_json::json!({"reth_best": best, "block_hash": args.block_hash}));

    drop(provider);
    let readers = Readers { factory, block_number: args.block_number };
    let head = csl_eth_store::Head {
        block_hash: args.block_hash,
        block_number: args.block_number,
        timestamp: args.timestamp,
        state_root: args.state_root,
    };
    let mut opts = ExportOptions::new(args.scratch.unwrap_or_else(|| args.out.with_extension("scratch")));
    opts.by_hash = args.by_hash;
    opts.memory_bytes = args.memory_gib << 30;
    opts.progress_every = Duration::from_secs(60);
    opts.workers = args.workers.unwrap_or_else(|| 2 * std::thread::available_parallelism().map_or(1, |n| n.get()));
    opts.ranges = args.ranges;
    let done = export(&args.out, &head, &readers, &opts, &mut |s| {
        // Never panic on a closed log pipe: progress is not worth an export.
        let _ = writeln!(std::io::stderr(), "{}", line(s));
    })?;
    println!("{}", serde_json::json!({"dir": done.dir, "stats": line(&done.stats), "manifest": done.manifest}));
    Ok(())
}
