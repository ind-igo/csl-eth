//! `export-reth history`: the §3c history tables (headers, transactions,
//! receipts, `tx_lookup`, `log_lookup`) from a stopped reth node's static
//! files instead of from peers, through `csl_eth_store::history`'s writer.
//!
//!   export-reth history export --datadir /data/reth --block-number B \
//!     --block-hash 0x… --out /data/out [--first 0] [--era1-dir /data/era1]
//!   export-reth history compare --datadir /data/reth --cache <work> --out /data/cmp
//!   export-reth history probe --datadir /data/reth [--cache <work>]
//!   export-reth history era1-check --era1-dir /data/era1 [--from N --to M]
//!
//! Trust is the writer's: every block is decoded from reth, re-encoded
//! (header RLP, EIP-2718 transactions, receipts with their blooms), and
//! must rebuild the roots of a header whose `keccak` chains by `parentHash`
//! to the block hash the caller passes (from head files it verified), or
//! nothing is published. Reth's database is not believed for anything.
//!
//! Before Byzantium (block 4,370,000) a receipt carries the state root
//! after its transaction instead of a status. Reth does not keep it (its
//! receipts have a success flag only, and it skips the receipts-root check
//! for those blocks), so their receipts come from era1 files
//! (`--era1-dir`, `mainnet-NNNNN-xxxxxxxx.era1`, 8,192 blocks each),
//! checked against the header from reth like any other leaf. Nothing else
//! is read from them.
//!
//! Progress goes to stderr as one JSON line per tick; the summary to stdout.

use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{B256, keccak256};
use alloy_rlp::Header as RlpHeader;
use clap::{Args, Parser, Subcommand};
use csl_eth_store::history::{
    Block, BlockCache, BlockSource, BlockSources, HistoryOptions, HistoryWritten,
    MAINNET_BYZANTIUM_BLOCK, history_table_name, write_history_with,
};
use reth_era::{
    common::file_ops::StreamReader,
    era1::file::{Era1File, Era1Reader},
};
use reth_ethereum::{
    EthPrimitives,
    chainspec::ChainSpecBuilder,
    node::EthereumNode,
    provider::{
        BlockBodyIndicesProvider, BlockHashReader, BlockNumReader, HeaderProvider, ProviderFactory,
        ReceiptProvider, StaticFileProviderFactory, StaticFileSegment, TransactionsProvider,
        providers::{ProviderNodeTypes, ReadOnlyConfig},
    },
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

/// Blocks per era1 file.
const ERA1_BLOCKS: u64 = 8192;

#[derive(Parser)]
#[command(
    name = "export-reth history",
    about = "History tables from a stopped reth node"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write the history tables for `--first ..= --block-number` into a
    /// bucket directory: runs and blobs, then the manifest, then
    /// history/latest, only if every block verifies and chains to the hash.
    Export(ExportArgs),
    /// Validation: build a span from reth and from a peer-built block cache
    /// (`csl-eth history build`'s work directory), compare every block's
    /// header, transactions and receipts, then both buckets file by file.
    Compare(CompareArgs),
    /// What the datadir holds: its best block and the lowest blocks whose
    /// transactions and receipts it still has.
    Probe(ProbeArgs),
    /// Verify era1 files on their own: every block's transactions and
    /// receipts against its header, and the headers' chain.
    Era1Check(Era1CheckArgs),
    /// Without a node: decode every header, transaction and receipt of a
    /// block cache into reth's types and re-encode them the way `export`
    /// does, which must give back the cache's bytes (the leaves the roots
    /// commit to). Checks the encoding path on real blocks of every kind.
    Roundtrip(RoundtripArgs),
}

#[derive(Args)]
struct RoundtripArgs {
    /// A `csl-eth history build` work directory (blocks/<n>).
    #[arg(long)]
    cache: PathBuf,
}

#[derive(Args)]
struct Datadir {
    /// reth's datadir (holding db/ and static_files/). The node must be
    /// stopped.
    #[arg(long)]
    datadir: PathBuf,
    /// Era1 files for the receipts below block 4,370,000.
    #[arg(long)]
    era1_dir: Option<PathBuf>,
}

#[derive(Args)]
struct Run {
    /// Worker threads. Default: the cores. Each holds a read transaction
    /// and one period's hint rows.
    #[arg(long)]
    workers: Option<usize>,
    /// Blocks per verification job.
    #[arg(long, default_value_t = 8192)]
    chunk_blocks: u64,
    #[arg(long, default_value_t = csl_eth_store::EPSILON)]
    epsilon: u16,
    #[arg(long, default_value_t = 60)]
    progress_secs: u64,
}

#[derive(Args)]
struct ExportArgs {
    #[command(flatten)]
    db: Datadir,
    #[command(flatten)]
    run: Run,
    /// The anchor: the newest block of the span, and its hash as head
    /// files proved it.
    #[arg(long)]
    block_number: u64,
    #[arg(long)]
    block_hash: B256,
    /// The oldest block of the span.
    #[arg(long, default_value_t = 0)]
    first: u64,
    /// The bucket directory to write (history/ and blobs/ under it).
    #[arg(long)]
    out: PathBuf,
}

#[derive(Args)]
struct CompareArgs {
    #[command(flatten)]
    db: Datadir,
    #[command(flatten)]
    run: Run,
    /// A `csl-eth history build` work directory (blocks/<n>).
    #[arg(long)]
    cache: PathBuf,
    /// The span to compare in full (default: every block both hold).
    #[arg(long)]
    from: Option<u64>,
    #[arg(long)]
    to: Option<u64>,
    /// Scratch for the two buckets (reth/, cache/), removed when they match.
    #[arg(long)]
    out: PathBuf,
    /// Keep the two buckets even when they match.
    #[arg(long)]
    keep: bool,
}

#[derive(Args)]
struct ProbeArgs {
    #[command(flatten)]
    db: Datadir,
    /// A block cache to report the overlap with.
    #[arg(long)]
    cache: Option<PathBuf>,
}

#[derive(Args)]
struct Era1CheckArgs {
    #[arg(long)]
    era1_dir: PathBuf,
    #[arg(long)]
    from: Option<u64>,
    #[arg(long)]
    to: Option<u64>,
    /// Also write the span's history tables from the era1 files alone
    /// (anchored at the last block's hash as the files give it: a test of
    /// the writer on old blocks, not a publishable bucket).
    #[arg(long)]
    out: Option<PathBuf>,
    #[command(flatten)]
    run: Run,
}

pub fn main(args: impl IntoIterator<Item = std::ffi::OsString>) -> eyre::Result<()> {
    let cli = Cli::parse_from(args);
    let out = match cli.cmd {
        Cmd::Export(a) => export(a)?,
        Cmd::Compare(a) => compare(a)?,
        Cmd::Probe(a) => probe(a)?,
        Cmd::Era1Check(a) => era1_check(a)?,
        Cmd::Roundtrip(a) => roundtrip(a)?,
    };
    println!("{out}");
    Ok(())
}

fn open_factory(
    datadir: &Path,
) -> eyre::Result<ProviderFactory<impl ProviderNodeTypes<Primitives = EthPrimitives>>> {
    let spec = ChainSpecBuilder::mainnet().build();
    let runtime = reth_ethereum::tasks::Runtime::test();
    EthereumNode::provider_factory_builder().open_read_only(
        spec.into(),
        ReadOnlyConfig::from_datadir(datadir)
            .no_watch()
            .disable_long_read_transaction_safety(),
        runtime,
    )
}

/// The era1 files in a directory, by era (block / 8,192).
struct Era1Dir {
    dir: PathBuf,
    files: BTreeMap<u64, PathBuf>,
}

impl Era1Dir {
    fn open(dir: &Path) -> eyre::Result<Era1Dir> {
        let mut files = BTreeMap::new();
        for e in fs::read_dir(dir)? {
            let p = e?.path();
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            // mainnet-00533-bb2932ed.era1
            let mut parts = name.strip_suffix(".era1").unwrap_or("").split('-');
            if let (Some("mainnet"), Some(era), Some(_), None) =
                (parts.next(), parts.next(), parts.next(), parts.next())
                && let Ok(era) = era.parse::<u64>()
            {
                files.insert(era, p);
            }
        }
        Ok(Era1Dir {
            dir: dir.to_path_buf(),
            files,
        })
    }

    /// The eras `lo ..= hi` needs that the directory lacks.
    fn missing(&self, lo: u64, hi: u64) -> Vec<u64> {
        (lo / ERA1_BLOCKS..=hi / ERA1_BLOCKS)
            .filter(|e| !self.files.contains_key(e))
            .collect()
    }
}

/// One thread's open era1 file.
struct Era1Reader1<'a> {
    dir: &'a Era1Dir,
    open: RefCell<Option<(u64, Era1File)>>,
}

/// An RLP list's items as trie leaves: a legacy transaction or receipt is
/// itself a list, a typed one is a string around `type ‖ payload` (the
/// network form), which is unwrapped.
fn leaves(mut buf: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let h = RlpHeader::decode(&mut buf).map_err(|e| format!("rlp: {e}"))?;
    if !h.list || buf.len() != h.payload_length {
        return Err("not a whole rlp list".into());
    }
    let mut out = Vec::new();
    while !buf.is_empty() {
        let start = buf;
        let ih = RlpHeader::decode(&mut buf).map_err(|e| format!("rlp item: {e}"))?;
        if ih.payload_length > buf.len() {
            return Err("rlp item runs past its list".into());
        }
        let head = start.len() - buf.len();
        out.push(if ih.list {
            start[..head + ih.payload_length].to_vec()
        } else {
            buf[..ih.payload_length].to_vec()
        });
        buf = &buf[ih.payload_length..];
    }
    Ok(out)
}

impl Era1Reader1<'_> {
    fn with_block<T>(
        &self,
        n: u64,
        f: impl FnOnce(&Era1File, &Path) -> Result<T, String>,
    ) -> Result<T, String> {
        let era = n / ERA1_BLOCKS;
        let mut open = self.open.borrow_mut();
        if open.as_ref().is_none_or(|(e, _)| *e != era) {
            *open = None;
            let path = self.dir.files.get(&era).ok_or_else(|| {
                format!(
                    "no era1 file for block {n} (mainnet-{era:05}-*.era1) in {}",
                    self.dir.dir.display()
                )
            })?;
            let file = fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let era1 = Era1Reader::new(file)
                .read_and_assemble("mainnet".into())
                .map_err(|e| format!("{}: {e}", path.display()))?;
            *open = Some((era, era1));
        }
        let (_, file) = open.as_ref().expect("opened");
        f(file, &self.dir.files[&era])
    }

    /// Block `n` as its era1 file holds it: header, transactions and
    /// receipts, all as trie leaves. Not verified here.
    fn block(&self, n: u64) -> Result<Block, String> {
        self.with_block(n, |file, path| {
            if !file.contains_block(n) {
                return Err(format!("{} does not hold block {n}", path.display()));
            }
            let t = file.get_block_by_number(n).expect("contains the block");
            let header = t
                .header
                .decompress()
                .map_err(|e| format!("{}: block {n} header: {e}", path.display()))?;
            let body = t
                .body
                .decompress()
                .map_err(|e| format!("{}: block {n} body: {e}", path.display()))?;
            let receipts = t
                .receipts
                .decompress()
                .map_err(|e| format!("{}: block {n} receipts: {e}", path.display()))?;
            // body = rlp([transactions, ommers, withdrawals?])
            let parts = list_items(&body)
                .map_err(|e| format!("{}: block {n} body: {e}", path.display()))?;
            let txs = leaves(parts.first().ok_or("empty body")?)
                .map_err(|e| format!("{}: block {n} transactions: {e}", path.display()))?;
            let receipts = leaves(&receipts)
                .map_err(|e| format!("{}: block {n} receipts: {e}", path.display()))?;
            Ok(Block {
                number: n,
                hash: keccak256(&header),
                header,
                txs,
                receipts,
            })
        })
    }

    /// Block `n`'s receipt leaves, if the file's block `n` is the block
    /// `hash`.
    fn receipts(&self, n: u64, hash: B256) -> Result<Vec<Vec<u8>>, String> {
        let b = self.block(n)?;
        if b.hash != hash {
            return Err(format!(
                "era1 holds block {n} as {}, reth as {hash}",
                b.hash
            ));
        }
        Ok(b.receipts)
    }
}

/// An RLP list's items, each as its whole encoding.
fn list_items(mut buf: &[u8]) -> Result<Vec<&[u8]>, String> {
    let h = RlpHeader::decode(&mut buf).map_err(|e| format!("rlp: {e}"))?;
    if !h.list || buf.len() != h.payload_length {
        return Err("not a whole rlp list".into());
    }
    let mut out = Vec::new();
    while !buf.is_empty() {
        let start = buf;
        let ih = RlpHeader::decode(&mut buf).map_err(|e| format!("rlp item: {e}"))?;
        let total = start.len() - buf.len() + ih.payload_length;
        if total > start.len() {
            return Err("rlp item runs past its list".into());
        }
        out.push(&start[..total]);
        buf = &start[total..];
    }
    Ok(out)
}

/// Opens a [`RethBlocks`] per worker thread, each on a read transaction of
/// its own (MDBX's belong to the thread that opened them).
struct RethSources<N: ProviderNodeTypes> {
    factory: ProviderFactory<N>,
    era1: Option<Era1Dir>,
}

impl<N: ProviderNodeTypes<Primitives = EthPrimitives>> BlockSources for RethSources<N> {
    fn open(&self) -> Result<Box<dyn BlockSource + '_>, String> {
        let provider = self.factory.provider().map_err(|e| e.to_string())?;
        Ok(Box::new(RethBlocks {
            provider,
            era1: self.era1.as_ref().map(|dir| Era1Reader1 {
                dir,
                open: RefCell::new(None),
            }),
        }))
    }
}

/// One thread's view of reth: blocks as the writer wants them.
struct RethBlocks<'a, P> {
    provider: P,
    era1: Option<Era1Reader1<'a>>,
}

/// What reth holds for a block, re-encoded as trie leaves. Below
/// Byzantium `receipts` stays empty: reth cannot rebuild those leaves.
struct RethBlock {
    block: Block,
    pre_byzantium: bool,
}

/// Which parts of a block to read: the header always, transactions and
/// receipts when asked (a pruned node has neither for old blocks).
#[derive(Clone, Copy)]
struct Parts {
    txs: bool,
    receipts: bool,
}

const ALL: Parts = Parts {
    txs: true,
    receipts: true,
};

fn reth_block<P>(p: &P, n: u64, parts: Parts) -> Result<RethBlock, String>
where
    P: HeaderProvider<Header = reth_ethereum::primitives::Header>
        + BlockBodyIndicesProvider
        + TransactionsProvider<Transaction = reth_ethereum::TransactionSigned>
        + ReceiptProvider<Receipt = reth_ethereum::Receipt>,
{
    let e = |what: &str, err: reth_ethereum::provider::ProviderError| {
        format!("reth block {n} {what}: {err}")
    };
    let sealed = p
        .sealed_header(n)
        .map_err(|err| e("header", err))?
        .ok_or_else(|| format!("reth has no header for block {n}"))?;
    let header = alloy_rlp::encode(sealed.header());
    let hash = sealed.hash();
    let mut block = Block {
        number: n,
        hash,
        header,
        txs: Vec::new(),
        receipts: Vec::new(),
    };
    if !parts.txs && !parts.receipts {
        return Ok(RethBlock {
            block,
            pre_byzantium: false,
        });
    }
    let idx = p
        .block_body_indices(n)
        .map_err(|err| e("body indices", err))?
        .ok_or_else(|| format!("reth has no body indices for block {n}"))?;
    let count = idx.tx_count as usize;
    let range = idx.first_tx_num..idx.first_tx_num + idx.tx_count;
    if count > 0 && parts.txs {
        let got = p
            .transactions_by_tx_range(range.clone())
            .map_err(|err| e("transactions", err))?;
        if got.len() != count {
            return Err(format!(
                "reth holds {} of block {n}'s {count} transactions (pruned?)",
                got.len()
            ));
        }
        block.txs = got.iter().map(|t| t.encoded_2718()).collect();
    }
    let pre_byzantium = n < MAINNET_BYZANTIUM_BLOCK && count > 0;
    if count > 0 && parts.receipts && !pre_byzantium {
        let got = p
            .receipts_by_tx_range(range)
            .map_err(|err| e("receipts", err))?;
        if got.len() != count {
            return Err(format!(
                "reth holds {} of block {n}'s {count} receipts (pruned?)",
                got.len()
            ));
        }
        use alloy_consensus::TxReceipt as _;
        block.receipts = got
            .iter()
            .map(|r| r.with_bloom_ref().encoded_2718())
            .collect();
    }
    Ok(RethBlock {
        block,
        pre_byzantium,
    })
}

impl<P> BlockSource for RethBlocks<'_, P>
where
    P: HeaderProvider<Header = reth_ethereum::primitives::Header>
        + BlockBodyIndicesProvider
        + TransactionsProvider<Transaction = reth_ethereum::TransactionSigned>
        + ReceiptProvider<Receipt = reth_ethereum::Receipt>,
{
    fn block(&self, n: u64) -> Result<Block, String> {
        let RethBlock {
            mut block,
            pre_byzantium,
        } = reth_block(&self.provider, n, ALL)?;
        if pre_byzantium {
            let era1 = self.era1.as_ref().ok_or_else(|| {
                format!("block {n} is before Byzantium: its receipts need --era1-dir")
            })?;
            block.receipts = era1.receipts(n, block.hash)?;
        }
        Ok(block)
    }
}

/// Every block of the era1 files as a source (for `era1-check`).
struct Era1Blocks(Era1Dir);

impl BlockSources for Era1Blocks {
    fn open(&self) -> Result<Box<dyn BlockSource + '_>, String> {
        Ok(Box::new(Era1Reader1 {
            dir: &self.0,
            open: RefCell::new(None),
        }))
    }
}

impl BlockSource for Era1Reader1<'_> {
    fn block(&self, n: u64) -> Result<Block, String> {
        Era1Reader1::block(self, n)
    }
}

fn workers(run: &Run) -> usize {
    run.workers
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(1, |n| n.get()))
}

/// Write `first ..= anchor` with progress lines on stderr.
fn write(
    out: &Path,
    sources: &dyn BlockSources,
    first: u64,
    anchor: (u64, B256),
    run: &Run,
) -> eyre::Result<HistoryWritten> {
    let mut progress = |p: &csl_eth_store::history::HistoryProgress| {
        // Never panic on a closed log pipe: progress is not worth an export.
        let _ = writeln!(
            std::io::stderr(),
            "{}",
            serde_json::to_string(p).unwrap_or_default()
        );
    };
    let mut opts = HistoryOptions {
        workers: workers(run),
        chunk_blocks: run.chunk_blocks,
        list_blobs: false,
        progress_every: Duration::from_secs(run.progress_secs.max(1)),
        progress: Some(&mut progress),
    };
    Ok(write_history_with(
        out,
        sources,
        first,
        anchor,
        run.epsilon,
        &mut opts,
    )?)
}

/// Per-table totals of a written span.
fn summary(w: &HistoryWritten) -> Value {
    let mut totals: BTreeMap<&str, (u64, u64, u64, u64)> = BTreeMap::new();
    let (mut blocks, mut txs, mut logs) = (0, 0, 0);
    for p in &w.stats {
        blocks += p.blocks;
        txs += p.transactions;
        logs += p.logs;
        for t in &p.tables {
            let e = totals.entry(history_table_name(t.table_id)).or_default();
            e.0 += t.entries;
            e.1 += t.file_bytes;
            e.2 += t.blobs;
            e.3 += t.blob_bytes;
        }
    }
    let tables: Vec<Value> = totals
        .iter()
        .map(|(n, (e, fb, b, bb))| json!({ "table": n, "entries": e, "file_bytes": fb, "blobs": b, "blob_bytes": bb, "bytes_per_block": (fb + bb) as f64 / blocks.max(1) as f64 }))
        .collect();
    json!({
        "first_block": w.manifest.first_block,
        "block_number": w.manifest.block_number,
        "block_hash": w.manifest.block_hash,
        "periods": w.manifest.periods.len(),
        "blocks": blocks,
        "transactions": txs,
        "logs": logs,
        "tables": tables,
    })
}

fn export(a: ExportArgs) -> eyre::Result<Value> {
    let started = Instant::now();
    eyre::ensure!(
        a.first <= a.block_number,
        "--first {} is above --block-number {}",
        a.first,
        a.block_number
    );
    let era1 = a.db.era1_dir.as_deref().map(Era1Dir::open).transpose()?;
    if a.first < MAINNET_BYZANTIUM_BLOCK {
        let Some(e) = &era1 else {
            eyre::bail!(
                "blocks below {MAINNET_BYZANTIUM_BLOCK} carry receipts reth cannot rebuild (a state root, not a status): give --era1-dir, or --first {MAINNET_BYZANTIUM_BLOCK} or above"
            )
        };
        let missing = e.missing(a.first, a.block_number.min(MAINNET_BYZANTIUM_BLOCK - 1));
        eyre::ensure!(
            missing.is_empty(),
            "{} lacks era1 files for eras {missing:?}",
            e.dir.display()
        );
    }
    let factory = open_factory(&a.db.datadir)?;
    let provider = factory.provider()?;
    let best = provider.best_block_number()?;
    let hash = provider.block_hash(a.block_number)?;
    eyre::ensure!(
        a.block_number <= best,
        "reth's best block is {best}, below {}",
        a.block_number
    );
    eyre::ensure!(
        hash == Some(a.block_hash),
        "reth's block {} is {hash:?}, not {}",
        a.block_number,
        a.block_hash
    );
    drop(provider);
    eprintln!(
        "{}",
        json!({"reth_best": best, "anchor": a.block_number, "block_hash": a.block_hash, "first": a.first})
    );
    let sources = RethSources { factory, era1 };
    let w = write(
        &a.out,
        &sources,
        a.first,
        (a.block_number, a.block_hash),
        &a.run,
    )?;
    let mut s = summary(&w);
    s["elapsed_s"] = json!(started.elapsed().as_secs_f64());
    s["files"] = json!(w.files.len());
    Ok(s)
}

/// The cache's lowest and highest block.
fn cache_range(work: &Path) -> eyre::Result<(u64, u64)> {
    let mut lo = u64::MAX;
    let mut hi = 0;
    for e in fs::read_dir(work.join("blocks"))? {
        if let Some(n) = e?.file_name().to_str().and_then(|s| s.parse::<u64>().ok()) {
            lo = lo.min(n);
            hi = hi.max(n);
        }
    }
    eyre::ensure!(
        lo <= hi,
        "{} holds no blocks",
        work.join("blocks").display()
    );
    Ok((lo, hi))
}

/// The lowest block at or above `lo` whose transactions (or receipts) reth
/// still has: the lowest whose first transaction number it can read.
/// Pruning removes a prefix, so readability rises with the number.
fn lowest_with<P>(p: &P, lo: u64, best: u64, receipts: bool) -> eyre::Result<Option<u64>>
where
    P: BlockBodyIndicesProvider
        + TransactionsProvider<Transaction = reth_ethereum::TransactionSigned>
        + ReceiptProvider<Receipt = reth_ethereum::Receipt>,
{
    // The newest block with a transaction bounds the search.
    let mut hi = best;
    loop {
        match p.block_body_indices(hi)? {
            Some(i) if i.tx_count > 0 => break,
            _ if hi == lo => return Ok(None),
            _ => hi -= 1,
        }
    }
    let readable = |n: u64| -> bool {
        let Ok(Some(i)) = p.block_body_indices(n) else {
            return false;
        };
        if receipts {
            matches!(p.receipt(i.first_tx_num), Ok(Some(_)))
        } else {
            matches!(p.transaction_by_id_unhashed(i.first_tx_num), Ok(Some(_)))
        }
    };
    if !readable(hi) {
        return Ok(None);
    }
    let (mut a, mut b) = (lo, hi);
    while a < b {
        let m = a + (b - a) / 2;
        if readable(m) {
            b = m;
        } else {
            a = m + 1;
        }
    }
    Ok(Some(a))
}

fn segments<N: ProviderNodeTypes<Primitives = EthPrimitives>>(
    factory: &ProviderFactory<N>,
) -> Value {
    let sf = factory.static_file_provider();
    let mut v = serde_json::Map::new();
    for (name, seg) in [
        ("headers", StaticFileSegment::Headers),
        ("transactions", StaticFileSegment::Transactions),
        ("receipts", StaticFileSegment::Receipts),
    ] {
        v.insert(
            name.into(),
            json!({ "lowest_file_start": sf.get_lowest_range_start(seg), "highest_block": sf.get_highest_static_file_block(seg) }),
        );
    }
    Value::Object(v)
}

fn probe(a: ProbeArgs) -> eyre::Result<Value> {
    let factory = open_factory(&a.db.datadir)?;
    let p = factory.provider()?;
    let best = p.best_block_number()?;
    let txs = lowest_with(&p, 0, best, false)?;
    let receipts = lowest_with(&p, 0, best, true)?;
    let mut out = json!({
        "best": best,
        "best_hash": p.block_hash(best)?,
        "static_files": segments(&factory),
        "transactions_from": txs,
        "receipts_from": receipts,
    });
    if let Some(work) = &a.cache {
        let (lo, hi) = cache_range(work)?;
        let to = hi.min(best);
        out["cache"] = json!({ "from": lo, "to": hi });
        out["testable"] = json!({
            "headers": (lo <= to).then_some([lo, to]),
            "transactions": txs.map(|t| t.max(lo)).filter(|f| *f <= to).map(|f| [f, to]),
            "receipts_and_bucket": receipts.map(|r| r.max(lo)).filter(|f| *f <= to).map(|f| [f, to]),
        });
    }
    Ok(out)
}

/// Every file under `dir`, relative path to contents' blake3 and length.
fn tree(dir: &Path) -> eyre::Result<BTreeMap<String, ([u8; 32], u64)>> {
    fn walk(
        base: &Path,
        d: &Path,
        out: &mut BTreeMap<String, ([u8; 32], u64)>,
    ) -> eyre::Result<()> {
        for e in fs::read_dir(d)? {
            let p = e?.path();
            if p.is_dir() {
                walk(base, &p, out)?;
            } else {
                let bytes = fs::read(&p)?;
                out.insert(
                    p.strip_prefix(base)?.to_string_lossy().into_owned(),
                    (*blake3::hash(&bytes).as_bytes(), bytes.len() as u64),
                );
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(dir, dir, &mut out)?;
    Ok(out)
}

fn compare(a: CompareArgs) -> eyre::Result<Value> {
    let started = Instant::now();
    let factory = open_factory(&a.db.datadir)?;
    let p = factory.provider()?;
    let best = p.best_block_number()?;
    let (cache_lo, cache_hi) = cache_range(&a.cache)?;
    let cache = BlockCache(a.cache.clone());
    let to = a.to.unwrap_or(cache_hi.min(best));
    eyre::ensure!(
        to <= best && to <= cache_hi,
        "--to {to} is above reth's best {best} or the cache's {cache_hi}"
    );
    let tx_from = lowest_with(&p, cache_lo, to, false)?;
    let rcpt_from = lowest_with(&p, cache_lo, to, true)?;
    let from = match a.from {
        Some(f) => f,
        None => rcpt_from.ok_or_else(|| {
            eyre::eyre!("reth holds no receipts in the cache's span {cache_lo}..={to}")
        })?,
    };
    eyre::ensure!(
        cache_lo <= from && from <= to,
        "--from {from} is outside {cache_lo}..={to}"
    );

    // 1. Block by block, as far down as each part reaches.
    let mut mismatches: Vec<Value> = Vec::new();
    let (mut headers, mut tx_blocks, mut rcpt_blocks, mut txs, mut receipts, mut reth_errors) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let era1 = a.db.era1_dir.as_deref().map(Era1Dir::open).transpose()?;
    let era1 = era1.as_ref().map(|dir| Era1Reader1 {
        dir,
        open: RefCell::new(None),
    });
    let mut differing = 0u64;
    for n in cache_lo..=to {
        let c = cache.block(n).map_err(|e| eyre::eyre!(e))?;
        let with_tx = tx_from.is_some_and(|f| n >= f);
        let with_rcpt = rcpt_from.is_some_and(|f| n >= f);
        let r = match reth_block(
            &p,
            n,
            Parts {
                txs: with_tx,
                receipts: with_rcpt,
            },
        ) {
            Ok(r) => r.block,
            Err(e) => {
                reth_errors += 1;
                if mismatches.len() < 50 {
                    mismatches.push(json!({ "block": n, "what": "reth", "error": e }));
                }
                continue;
            }
        };
        let mut diff = |what: &str, detail: Value| {
            differing += 1;
            if mismatches.len() < 50 {
                mismatches.push(json!({ "block": n, "what": what, "detail": detail }));
            }
        };
        headers += 1;
        if c.hash != r.hash || c.header != r.header {
            diff(
                "header",
                json!({ "cache": c.hash, "reth": r.hash, "cache_len": c.header.len(), "reth_len": r.header.len() }),
            );
        }
        if with_tx {
            tx_blocks += 1;
            txs += c.txs.len() as u64;
            if c.txs.len() != r.txs.len() {
                diff("transaction count", json!([c.txs.len(), r.txs.len()]));
            } else if let Some(i) = (0..c.txs.len()).find(|&i| c.txs[i] != r.txs[i]) {
                diff(
                    "transaction",
                    json!({ "index": i, "cache": alloy_primitives::hex::encode(&c.txs[i]), "reth": alloy_primitives::hex::encode(&r.txs[i]) }),
                );
            }
        }
        if with_rcpt {
            let mut rr = r.receipts;
            if n < MAINNET_BYZANTIUM_BLOCK && !c.txs.is_empty() {
                rr = match &era1 {
                    Some(e) => e.receipts(n, r.hash).map_err(|e| eyre::eyre!(e))?,
                    None => eyre::bail!("block {n} is before Byzantium: give --era1-dir"),
                };
            }
            rcpt_blocks += 1;
            receipts += c.receipts.len() as u64;
            if c.receipts.len() != rr.len() {
                diff("receipt count", json!([c.receipts.len(), rr.len()]));
            } else if let Some(i) = (0..c.receipts.len()).find(|&i| c.receipts[i] != rr[i]) {
                diff(
                    "receipt",
                    json!({ "index": i, "cache": alloy_primitives::hex::encode(&c.receipts[i]), "reth": alloy_primitives::hex::encode(&rr[i]) }),
                );
            }
        }
    }
    drop(p);

    // 2. The same span written from each, file by file.
    let anchor = (to, cache.block(to).map_err(|e| eyre::eyre!(e))?.hash);
    let (dir_reth, dir_cache) = (a.out.join("reth"), a.out.join("cache"));
    for d in [&dir_reth, &dir_cache] {
        eyre::ensure!(!d.exists(), "{} exists: give an empty --out", d.display());
    }
    let sources = RethSources {
        factory,
        era1: a.db.era1_dir.as_deref().map(Era1Dir::open).transpose()?,
    };
    let w_reth = write(&dir_reth, &sources, from, anchor, &a.run)?;
    let w_cache = write(&dir_cache, &cache, from, anchor, &a.run)?;
    let (t_reth, t_cache) = (tree(&dir_reth)?, tree(&dir_cache)?);
    let only = |x: &BTreeMap<String, ([u8; 32], u64)>,
                y: &BTreeMap<String, ([u8; 32], u64)>|
     -> Vec<String> {
        x.keys()
            .filter(|k| !y.contains_key(*k))
            .take(20)
            .cloned()
            .collect()
    };
    let differ: Vec<&String> = t_reth
        .iter()
        .filter(|(k, v)| t_cache.get(*k).is_some_and(|w| w != *v))
        .map(|(k, _)| k)
        .take(20)
        .collect();
    let identical = t_reth == t_cache;
    let bytes: u64 = t_reth.values().map(|v| v.1).sum();
    let ok = identical && differing == 0 && reth_errors == 0;
    let out = json!({
        "ok": ok,
        "reth_best": best,
        "cache": [cache_lo, cache_hi],
        "blocks": {
            "headers": headers, "header_range": [cache_lo, to],
            "transaction_blocks": tx_blocks, "transactions": txs, "transactions_from": tx_from,
            "receipt_blocks": rcpt_blocks, "receipts": receipts, "receipts_from": rcpt_from,
            "differing": differing, "reth_errors": reth_errors, "mismatches": mismatches,
        },
        "bucket": {
            "span": [from, to],
            "anchor_hash": anchor.1,
            "files": t_reth.len(),
            "bytes": bytes,
            "identical": identical,
            "manifests_equal": w_reth.manifest == w_cache.manifest,
            "only_reth": only(&t_reth, &t_cache),
            "only_cache": only(&t_cache, &t_reth),
            "differ": differ,
            "reth": summary(&w_reth),
        },
        "elapsed_s": started.elapsed().as_secs_f64(),
    });
    if ok && !a.keep {
        let _ = fs::remove_dir_all(&dir_reth);
        let _ = fs::remove_dir_all(&dir_cache);
    }
    if !ok {
        println!("{out}");
        eyre::bail!("reth's blocks or bucket differ from the cache's");
    }
    Ok(out)
}

fn era1_check(a: Era1CheckArgs) -> eyre::Result<Value> {
    let started = Instant::now();
    let dir = Era1Dir::open(&a.era1_dir)?;
    let (Some(lo_era), Some(hi_era)) = (
        dir.files.keys().next().copied(),
        dir.files.keys().last().copied(),
    ) else {
        eyre::bail!("no mainnet-*.era1 files in {}", a.era1_dir.display())
    };
    let from = a.from.unwrap_or(lo_era * ERA1_BLOCKS);
    let to = a.to.unwrap_or(hi_era * ERA1_BLOCKS + ERA1_BLOCKS - 1);
    let missing = dir.missing(from, to);
    eyre::ensure!(missing.is_empty(), "missing eras {missing:?}");
    let src = Era1Blocks(dir);
    let r = src.open().map_err(|e| eyre::eyre!(e))?;
    let r = &*r;
    let (mut blocks, mut txs, mut receipts, mut post_state, mut status, mut typed) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    let mut prev: Option<B256> = None;
    for n in from..=to {
        let b = r.block(n).map_err(|e| eyre::eyre!(e))?;
        let h = b.verify().map_err(|e| eyre::eyre!("era1 block {n}: {e}"))?;
        if let Some(p) = prev {
            eyre::ensure!(
                h.parent_hash == p,
                "era1 block {n} is not the child of block {}",
                n - 1
            );
        }
        prev = Some(h.hash);
        // What export would get from reth for this block (its receipts too
        // from Byzantium on) must be these bytes.
        roundtrip_block(&b, n >= MAINNET_BYZANTIUM_BLOCK).map_err(|e| eyre::eyre!(e))?;
        blocks += 1;
        txs += b.txs.len() as u64;
        receipts += b.receipts.len() as u64;
        for leaf in &b.receipts {
            let f = csl_eth_store::history::decode_receipt(leaf)
                .map_err(|e| eyre::eyre!("block {n}: {e}"))?;
            if f.post_state.is_some() {
                post_state += 1;
            } else {
                status += 1;
            }
            typed += u64::from(f.tx_type != 0);
        }
    }
    let mut out = json!({
        "from": from, "to": to, "blocks": blocks, "transactions": txs, "receipts": receipts,
        "post_state_receipts": post_state, "status_receipts": status, "typed_receipts": typed,
        "last_hash": prev,
    });
    if let (Some(dir), Some(hash)) = (&a.out, prev) {
        let w = write(dir, &src, from, (to, hash), &a.run)?;
        out["written"] = summary(&w);
    }
    out["elapsed_s"] = json!(started.elapsed().as_secs_f64());
    Ok(out)
}

/// One block through reth's types and back, as [`reth_block`] encodes.
fn roundtrip_block(b: &Block, receipts: bool) -> Result<(), String> {
    use alloy_consensus::TxReceipt as _;
    use alloy_eips::eip2718::Decodable2718;
    use alloy_rlp::Decodable;
    let n = b.number;
    let header = reth_ethereum::primitives::Header::decode(&mut b.header.as_slice())
        .map_err(|e| format!("block {n} header: {e}"))?;
    if alloy_rlp::encode(&header) != b.header {
        return Err(format!(
            "block {n}: the header does not re-encode to its bytes"
        ));
    }
    for (i, leaf) in b.txs.iter().enumerate() {
        let tx = reth_ethereum::TransactionSigned::decode_2718_exact(leaf)
            .map_err(|e| format!("block {n} tx {i}: {e}"))?;
        if tx.encoded_2718() != *leaf {
            return Err(format!("block {n} tx {i}: does not re-encode to its leaf"));
        }
    }
    for (i, leaf) in b.receipts.iter().enumerate().filter(|_| receipts) {
        let r =
            alloy_consensus::ReceiptWithBloom::<reth_ethereum::Receipt>::decode_2718_exact(leaf)
                .map_err(|e| format!("block {n} receipt {i}: {e}"))?;
        // What reth stores is the receipt without its bloom; export
        // recomputes the bloom from the logs.
        if r.receipt.with_bloom_ref().encoded_2718() != *leaf {
            return Err(format!(
                "block {n} receipt {i}: does not re-encode to its leaf"
            ));
        }
    }
    Ok(())
}

fn roundtrip(a: RoundtripArgs) -> eyre::Result<Value> {
    let started = Instant::now();
    let (lo, hi) = cache_range(&a.cache)?;
    let cache = BlockCache(a.cache.clone());
    let (mut txs, mut receipts) = (0u64, 0u64);
    let mut types: BTreeMap<u8, u64> = BTreeMap::new();
    for n in lo..=hi {
        let b = cache.block(n).map_err(|e| eyre::eyre!(e))?;
        b.verify().map_err(|e| eyre::eyre!("block {n}: {e}"))?;
        roundtrip_block(&b, true).map_err(|e| eyre::eyre!(e))?;
        txs += b.txs.len() as u64;
        receipts += b.receipts.len() as u64;
        for t in &b.txs {
            *types
                .entry(if t[0] >= 0xc0 { 0 } else { t[0] })
                .or_default() += 1;
        }
    }
    Ok(
        json!({ "from": lo, "to": hi, "transactions": txs, "receipts": receipts, "tx_types": types, "elapsed_s": started.elapsed().as_secs_f64() }),
    )
}
