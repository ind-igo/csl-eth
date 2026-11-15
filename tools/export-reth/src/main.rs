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
//!     --timestamp T --state-root 0x… --out /data/out
//!
//! Progress goes to stderr as one JSON line per tick; the final stats go to
//! stdout.

use alloy_primitives::{B256, U256};
use clap::Parser;
use csl_eth_store::{export, ExportOptions, ExportStats, SourceAccount, StateSource};
use reth_ethereum::{
    chainspec::ChainSpecBuilder,
    node::EthereumNode,
    provider::{
        db::{
            cursor::{DbCursorRO, DbDupCursorRO},
            tables,
            transaction::DbTx,
            DatabaseError,
        },
        providers::ReadOnlyConfig,
        BlockHashReader, BlockNumReader,
    },
};
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
    /// Sort memory, GiB.
    #[arg(long, default_value_t = 32)]
    memory_gib: u64,
    /// Also write nodes_by_hash (the baseline table; roughly doubles the output).
    #[arg(long)]
    by_hash: bool,
}

/// The read transaction reth's state is read through; every cursor is opened
/// from it, so the export sees one consistent version of the database.
///
/// Storage is read through one cursor that walks `HashedStorages` forward
/// beside the accounts (the exporter asks for each account's storage in
/// ascending order and drains or drops it before the next): an account with
/// no storage costs a comparison with the owner the cursor is on, not a
/// cursor and a seek. ~3e8 accounts, most without storage.
struct Reth<Tx: DbTx> {
    tx: Tx,
    storage: RefCell<StorageWalk<Tx::DupCursor<tables::HashedStorages>>>,
}

struct StorageWalk<C> {
    cursor: C,
    /// The entry the cursor is on, as (owner, slot, word); None past the end.
    at: Option<(B256, B256, U256)>,
}

fn entry(got: Option<(alloy_primitives::B256, reth_ethereum::primitives::StorageEntry)>) -> Option<(B256, B256, U256)> {
    got.map(|(owner, e)| (B256::from(owner.0), B256::from(e.key.0), U256::from_limbs(*e.value.as_limbs())))
}

struct Accounts<C> {
    cursor: C,
    started: bool,
}

impl<C: DbCursorRO<tables::HashedAccounts>> Iterator for Accounts<C> {
    type Item = Result<SourceAccount, DatabaseError>;
    fn next(&mut self) -> Option<Self::Item> {
        let got = if self.started {
            self.cursor.next()
        } else {
            self.started = true;
            self.cursor.first()
        };
        match got {
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

    fn accounts(&self) -> Result<Self::Accounts<'_>, DatabaseError> {
        Ok(Accounts { cursor: self.tx.cursor_read::<tables::HashedAccounts>()?, started: false })
    }

    fn storage(&self, hashed: &B256) -> Result<Self::Storage<'_>, DatabaseError> {
        let mut walk = self.storage.borrow_mut();
        // Behind the account (a new one, or one whose slots were not all
        // read): seek, which only ever moves forward here.
        if matches!(walk.at, Some((owner, _, _)) if owner < *hashed) {
            let got = walk.cursor.seek((*hashed).into())?;
            walk.at = entry(got);
        }
        Ok(Slots { walk, owner: *hashed })
    }

    fn code(&self, code_hash: &B256) -> Result<Option<Vec<u8>>, DatabaseError> {
        Ok(self.tx.get::<tables::Bytecodes>((*code_hash).into())?.map(|c| c.original_bytes().to_vec()))
    }

    fn codes(&self) -> Option<Result<csl_eth_store::CodeIter<'_, DatabaseError>, DatabaseError>> {
        Some(self.tx.cursor_read::<tables::Bytecodes>().map(|cursor| Box::new(Codes { cursor, started: false }) as csl_eth_store::CodeIter<'_, DatabaseError>))
    }
}

fn line(s: &ExportStats) -> serde_json::Value {
    serde_json::json!({
        "phase": format!("{:?}", s.phase),
        "accounts": s.accounts,
        "storage_slots": s.storage_slots,
        "storage_tries": s.storage_tries,
        "largest_storage": s.largest_storage.0,
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

    let tx = provider.into_tx();
    let mut cursor = tx.cursor_dup_read::<tables::HashedStorages>()?;
    let at = entry(cursor.first()?);
    let src = Reth { storage: RefCell::new(StorageWalk { cursor, at }), tx };
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
    let done = export(&args.out, &head, &src, &opts, &mut |s| eprintln!("{}", line(s)))?;
    println!("{}", serde_json::json!({"dir": done.dir, "stats": line(&done.stats), "manifest": done.manifest}));
    Ok(())
}
