//! History tables, profile §3c: headers, transactions, receipts and two
//! hints, written once per finalized span and never rewritten.
//!
//! ```text
//! history/latest                        hex hash of the newest manifest's block
//! history/<block_hash>/manifest.json    HistoryManifest: the span and its runs
//! history/runs/<blake3>.run             a run per table per period, and the tx_lookup pieces
//! history/packs/<blake3>.pack           one period's values above the inline size
//! ```
//!
//! A run or pack is named by its own bytes, so a closed period's files are
//! written once and every later manifest names the same files; only the
//! open period's change.
//!
//! Values above the inline size go in the period's pack, one object, in the
//! order written (each block's header, transactions, receipts), and the run
//! entry carries their offset, length and `blake3` (tag 3): a block's large
//! values sit side by side, so one range request fetches them all, and a
//! full chain is thousands of objects rather than a hundred million.
//!
//! `tx_lookup` is not per period: a transaction hash says nothing of its
//! block, so a per-period hint costs a probe per period. It is a few runs
//! over ranges of periods ([`LookupRun`], [`tx_lookup_plan`]): a base over
//! the closed periods, pieces for the closed periods after it whose sizes
//! are the binary digits of their count, and the open period alone. A
//! piece whose periods hold no transactions has no run and only records
//! that it covers them. A
//! fresh write is the base and the open period; a span extended without
//! rewriting the base adds pieces that merge as a binary counter does. The manifest names the newest block of the span,
//! the block a client must reach from its verified head; a client reads
//! nothing in here as evidence. Headers verify by `keccak` and `parentHash`
//! down from that block, a block's transactions and receipts by rebuilding
//! their tries to the header's roots, and the two hint tables only route.
//!
//! Keys (32 bytes, big-endian):
//!
//! | table | key | value |
//! |---|---|---|
//! | `headers` | `block u40 ‖ 0 u24 ‖ zeros` | RLP header |
//! | `transactions` | `block u40 ‖ index u24 ‖ zeros` | EIP-2718 envelope (the trie's leaf) |
//! | `receipts` | `block u40 ‖ index u24 ‖ zeros` | EIP-2718 receipt with bloom (the trie's leaf) |
//! | `tx_lookup` | `keccak(tx_hash)` | `block u40 ‖ index u24` |
//! | `log_lookup` | `h[0..3] ‖ block u40 ‖ h[3..27]`, `h = keccak("csl/eth/log/v1" ‖ term)` | empty |
//!
//! `log_lookup` departs from the profile's `keccak(…) ‖ block`: with the
//! block after 32 bytes of hash, every row of one address shares its `k64`
//! and a busy contract's day is one prefix group of dozens of pages, which
//! the model cannot represent (core §4 caps a group at `2ε + 1` pages, and
//! the writer aborts). Three bytes of the term's hash, then the block, puts
//! one term's rows for a span in one contiguous key range whose `k64`s rise
//! with the block; terms sharing the three bytes interleave, and a reader
//! filters them out by the remaining 24 bytes.

use crate::{
    CODE_BLOB_THRESHOLD, TableRef,
    extsort::{Budget, Dups, ExtSort, Scratch, SortError, SortedFile},
    producer::write_atomic,
    profile_id,
};
use alloy_primitives::{Address, B256, Bloom, BloomInput, keccak256};
use alloy_rlp::{Decodable, Header as RlpHeader};
use alloy_trie::root::ordered_trie_root_encoded;
use csl_run::{Config, Entry, PackedRef, Writer};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    fs::{self, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

/// Bumped when a key, value or the manifest changes shape.
/// 2: values above the inline size in one pack per period, `tx_lookup` in
/// pieces over ranges of periods.
pub const HISTORY_FORMAT_VERSION: u32 = 2;

/// History runs keep the whole model in one section rather than paging it:
/// keys rising with the block (and uniform hashes in the hints) fit in a
/// handful of segments, so the client loads every model when it opens the
/// manifest and each read is data pages only.
pub const HISTORY_RUN_FORMAT: csl_run::Format = csl_run::Format::variable();

/// Table ids in run headers, apart from the state tables' 0 to 3.
pub const H_HEADERS: u16 = 16;
pub const H_TRANSACTIONS: u16 = 17;
pub const H_RECEIPTS: u16 = 18;
pub const H_TX_LOOKUP: u16 = 19;
pub const H_LOG_LOOKUP: u16 = 20;
pub const HISTORY_TABLES: [u16; 5] = [
    H_HEADERS,
    H_TRANSACTIONS,
    H_RECEIPTS,
    H_TX_LOOKUP,
    H_LOG_LOOKUP,
];

pub fn history_table_name(t: u16) -> &'static str {
    match t {
        H_HEADERS => "headers",
        H_TRANSACTIONS => "transactions",
        H_RECEIPTS => "receipts",
        H_TX_LOOKUP => "tx_lookup",
        H_LOG_LOOKUP => "log_lookup",
        _ => "?",
    }
}

pub const HISTORY_LATEST: &str = "history/latest";

pub fn history_manifest_path(block_hash: &B256) -> String {
    format!("history/{}/manifest.json", hex::encode(block_hash))
}

/// A run by its `blake3`.
pub fn history_pack_path(root: &[u8; 32]) -> String {
    format!("history/packs/{}.pack", hex::encode(root))
}

pub fn history_run_path(root: &[u8; 32]) -> String {
    format!("history/runs/{}.run", hex::encode(root))
}

/// The block number field is 40 bits, the index 24.
pub const MAX_BLOCK: u64 = (1 << 40) - 1;
pub const MAX_INDEX: u64 = (1 << 24) - 1;

/// Mainnet's beacon genesis time and the sync-committee period in slots:
/// a post-merge block's period is fixed by its timestamp.
pub const MAINNET_GENESIS_TIME: u64 = 1_606_824_023;
pub const SLOTS_PER_PERIOD: u64 = 8192;
pub const SECONDS_PER_SLOT: u64 = 12;

/// The first mainnet block with EIP-658 receipts (a status, not a state
/// root).
pub const MAINNET_BYZANTIUM_BLOCK: u64 = 4_370_000;

/// The sync-committee period of a block's timestamp. Blocks older than the
/// beacon chain (before 2020-12-01, about block 11.4 M) fall in negative
/// periods of the same length, the clock run backwards, so the whole
/// chain is cut into spans of about 27 hours (6,000 to 8,000 blocks) the
/// same way.
pub fn period_of_timestamp(ts: u64) -> i64 {
    let span = (SECONDS_PER_SLOT * SLOTS_PER_PERIOD) as i128;
    (ts as i128 - MAINNET_GENESIS_TIME as i128).div_euclid(span) as i64
}

/// `block u40 ‖ index u24 ‖ zeros`.
pub fn block_key(block: u64, index: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..8].copy_from_slice(&locator(block, index));
    k
}

/// `block u40 ‖ index u24`, the `tx_lookup` value and the first eight
/// bytes of a block key.
pub fn locator(block: u64, index: u64) -> [u8; 8] {
    debug_assert!(block <= MAX_BLOCK && index <= MAX_INDEX);
    ((block << 24) | (index & MAX_INDEX)).to_be_bytes()
}

pub fn parse_locator(v: &[u8]) -> Option<(u64, u64)> {
    let v: [u8; 8] = v.try_into().ok()?;
    let x = u64::from_be_bytes(v);
    Some((x >> 24, x & MAX_INDEX))
}

pub fn tx_lookup_key(tx_hash: &B256) -> [u8; 32] {
    keccak256(tx_hash).0
}

/// What a log query asks for: logs emitted by an address, or carrying a
/// topic in any position.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Term {
    Address(Address),
    Topic(B256),
}

impl Term {
    fn bytes(&self) -> &[u8] {
        match self {
            Term::Address(a) => a.as_slice(),
            Term::Topic(t) => t.as_slice(),
        }
    }

    /// `keccak("csl/eth/log/v1" ‖ term)`. Addresses and topics differ in
    /// length, so the two never share a preimage.
    pub fn hash(&self) -> [u8; 32] {
        let mut v = b"csl/eth/log/v1".to_vec();
        v.extend_from_slice(self.bytes());
        keccak256(v).0
    }

    /// Whether `log` carries this term.
    pub fn matches(&self, log: &Log) -> bool {
        match self {
            Term::Address(a) => log.address == *a,
            Term::Topic(t) => log.topics.contains(t),
        }
    }

    /// Whether a block's `logsBloom` admits this term (no false negatives).
    pub fn in_bloom(&self, bloom: &Bloom) -> bool {
        bloom.contains_input(BloomInput::Raw(self.bytes()))
    }

    /// `0x` + 40 hex is an address, `0x` + 64 hex a topic.
    pub fn parse(s: &str) -> Result<Term, String> {
        let h = s.trim_start_matches("0x");
        let v = hex::decode(h).map_err(|e| format!("{s}: {e}"))?;
        match v.len() {
            20 => Ok(Term::Address(Address::from_slice(&v))),
            32 => Ok(Term::Topic(B256::from_slice(&v))),
            n => Err(format!("{s}: {n} bytes, want 20 (address) or 32 (topic)")),
        }
    }
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Address(a) => write!(f, "{a}"),
            Term::Topic(t) => write!(f, "{t}"),
        }
    }
}

/// `h[0..3] ‖ block u40 ‖ h[3..27]` for the term hash `h` (module doc).
pub fn log_lookup_key(term_hash: &[u8; 32], block: u64) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[..3].copy_from_slice(&term_hash[..3]);
    k[3..8].copy_from_slice(&block.to_be_bytes()[3..]);
    k[8..].copy_from_slice(&term_hash[3..27]);
    k
}

/// The block of a `log_lookup` key, if it is this term's.
pub fn log_lookup_block(term_hash: &[u8; 32], key: &[u8; 32]) -> Option<u64> {
    if key[..3] != term_hash[..3] || key[8..] != term_hash[3..27] {
        return None;
    }
    let mut b = [0u8; 8];
    b[3..].copy_from_slice(&key[3..8]);
    Some(u64::from_be_bytes(b))
}

/// The header fields history reads, decoded from the RLP whose `keccak` is
/// `hash`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderFields {
    pub hash: B256,
    pub parent_hash: B256,
    pub ommers_hash: B256,
    pub state_root: B256,
    pub transactions_root: B256,
    pub receipts_root: B256,
    pub logs_bloom: Bloom,
    pub number: u64,
    pub timestamp: u64,
    pub withdrawals_root: Option<B256>,
}

/// Every item of an RLP list, each as its whole encoding. The list must
/// be the whole of `buf`.
fn list_items(mut buf: &[u8]) -> Result<Vec<&[u8]>, &'static str> {
    let h = RlpHeader::decode(&mut buf).map_err(|_| "not rlp")?;
    if !h.list {
        return Err("not an rlp list");
    }
    if buf.len() != h.payload_length {
        return Err("rlp list length disagrees with its bytes");
    }
    let mut out = Vec::new();
    while !buf.is_empty() {
        let mut probe = buf;
        let ih = RlpHeader::decode(&mut probe).map_err(|_| "bad rlp item")?;
        let head = buf.len() - probe.len();
        let total = head + ih.payload_length;
        if total > buf.len() {
            return Err("rlp item runs past its list");
        }
        out.push(&buf[..total]);
        buf = &buf[total..];
    }
    Ok(out)
}

fn item<T: Decodable>(mut b: &[u8], what: &'static str) -> Result<T, &'static str> {
    let v = T::decode(&mut b).map_err(|_| what)?;
    if !b.is_empty() {
        return Err(what);
    }
    Ok(v)
}

/// Decode a header's fields. Nothing here checks the hash against anything:
/// the caller compares `hash` with the hash it expects.
pub fn decode_header(rlp: &[u8]) -> Result<HeaderFields, &'static str> {
    let it = list_items(rlp)?;
    if it.len() < 15 {
        return Err("header has too few fields");
    }
    Ok(HeaderFields {
        hash: keccak256(rlp),
        parent_hash: item(it[0], "parentHash")?,
        ommers_hash: item(it[1], "ommersHash")?,
        state_root: item(it[3], "stateRoot")?,
        transactions_root: item(it[4], "transactionsRoot")?,
        receipts_root: item(it[5], "receiptsRoot")?,
        logs_bloom: item(it[6], "logsBloom")?,
        number: item(it[8], "number")?,
        timestamp: item(it[11], "timestamp")?,
        withdrawals_root: match it.get(16) {
            Some(b) => Some(item(b, "withdrawalsRoot")?),
            None => None,
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

/// A receipt as the receipt trie's leaf holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiptFields {
    /// 0 for legacy.
    pub tx_type: u8,
    /// Post-Byzantium: whether the transaction succeeded. False for a
    /// pre-Byzantium receipt, which does not say.
    pub success: bool,
    /// Pre-Byzantium (blocks below 4,370,000 on mainnet): the state root
    /// after the transaction, which the receipt carries in place of the
    /// status (EIP-658 replaced it).
    pub post_state: Option<B256>,
    pub cumulative_gas_used: u64,
    pub bloom: Bloom,
    pub logs: Vec<Log>,
}

/// Decode a receipt leaf: `type ‖ rlp([status, cumulativeGas, bloom,
/// logs])`, or the bare list for a legacy receipt. The first field is the
/// status (empty or `0x01`) or, before Byzantium, a 32-byte state root.
pub fn decode_receipt(leaf: &[u8]) -> Result<ReceiptFields, &'static str> {
    let (tx_type, body) = match leaf.first() {
        None => return Err("empty receipt"),
        Some(&b) if b >= 0xc0 => (0u8, leaf),
        Some(&b) if b <= 0x7f && b != 0 => (b, &leaf[1..]),
        Some(_) => return Err("receipt type byte out of range"),
    };
    let it = list_items(body)?;
    if it.len() != 4 {
        return Err("receipt is not four fields");
    }
    let status: alloy_primitives::Bytes = item(it[0], "receipt status")?;
    let (success, post_state) = match status.as_ref() {
        [] => (false, None),
        [1] => (true, None),
        root if root.len() == 32 => (false, Some(B256::from_slice(root))),
        _ => return Err("receipt status is neither a status nor a state root"),
    };
    let logs_items = list_items(it[3])?;
    let mut logs = Vec::with_capacity(logs_items.len());
    for l in logs_items {
        let f = list_items(l)?;
        if f.len() != 3 {
            return Err("log is not three fields");
        }
        let topics = list_items(f[1])?
            .into_iter()
            .map(|t| item::<B256>(t, "log topic"))
            .collect::<Result<Vec<_>, _>>()?;
        let data: alloy_primitives::Bytes = item(f[2], "log data")?;
        logs.push(Log {
            address: item(f[0], "log address")?,
            topics,
            data: data.to_vec(),
        });
    }
    Ok(ReceiptFields {
        tx_type,
        success,
        post_state,
        cumulative_gas_used: item(it[1], "cumulativeGasUsed")?,
        bloom: item(it[2], "receipt bloom")?,
        logs,
    })
}

/// The transaction hash of a transaction leaf (an EIP-2718 envelope).
pub fn tx_hash(leaf: &[u8]) -> B256 {
    keccak256(leaf)
}

/// The root of the ordered trie over `leaves` (transactions or receipts).
pub fn ordered_root(leaves: &[Vec<u8>]) -> B256 {
    ordered_trie_root_encoded(leaves)
}

/// Why a block does not match its header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    Header(&'static str),
    /// The header does not hash to the hash it was asked for.
    Hash {
        number: u64,
        expected: B256,
        got: B256,
    },
    /// Not the parent of the next block, or not consecutive.
    Chain {
        number: u64,
    },
    TransactionsRoot {
        number: u64,
    },
    ReceiptsRoot {
        number: u64,
    },
    /// As many receipts as transactions, always.
    Counts {
        number: u64,
        txs: usize,
        receipts: usize,
    },
    Receipt {
        number: u64,
        index: usize,
        what: &'static str,
    },
}

impl fmt::Display for BlockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlockError::Header(w) => write!(f, "header: {w}"),
            BlockError::Hash {
                number,
                expected,
                got,
            } => write!(
                f,
                "block {number}: header hashes to {got}, expected {expected}"
            ),
            BlockError::Chain { number } => {
                write!(f, "block {number}: not the parent of the next block")
            }
            BlockError::TransactionsRoot { number } => write!(
                f,
                "block {number}: transactions do not rebuild transactionsRoot"
            ),
            BlockError::ReceiptsRoot { number } => {
                write!(f, "block {number}: receipts do not rebuild receiptsRoot")
            }
            BlockError::Counts {
                number,
                txs,
                receipts,
            } => write!(f, "block {number}: {txs} transactions, {receipts} receipts"),
            BlockError::Receipt {
                number,
                index,
                what,
            } => write!(f, "block {number} receipt {index}: {what}"),
        }
    }
}

impl std::error::Error for BlockError {}

/// Check a block's transactions and receipts against its header's roots.
pub fn check_block(
    h: &HeaderFields,
    txs: &[Vec<u8>],
    receipts: &[Vec<u8>],
) -> Result<(), BlockError> {
    if txs.len() != receipts.len() {
        return Err(BlockError::Counts {
            number: h.number,
            txs: txs.len(),
            receipts: receipts.len(),
        });
    }
    if ordered_root(txs) != h.transactions_root {
        return Err(BlockError::TransactionsRoot { number: h.number });
    }
    if ordered_root(receipts) != h.receipts_root {
        return Err(BlockError::ReceiptsRoot { number: h.number });
    }
    Ok(())
}

/// One verified block as the producer keeps it: the header's RLP and the
/// two tries' leaves in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub number: u64,
    pub hash: B256,
    pub header: Vec<u8>,
    pub txs: Vec<Vec<u8>>,
    pub receipts: Vec<Vec<u8>>,
}

impl Block {
    /// Decode the header and check it hashes to `self.hash`, carries
    /// `self.number`, and that the leaves rebuild its roots.
    pub fn verify(&self) -> Result<HeaderFields, BlockError> {
        let h = decode_header(&self.header).map_err(BlockError::Header)?;
        if h.hash != self.hash {
            return Err(BlockError::Hash {
                number: self.number,
                expected: self.hash,
                got: h.hash,
            });
        }
        if h.number != self.number {
            return Err(BlockError::Header("number differs from the block's"));
        }
        check_block(&h, &self.txs, &self.receipts)?;
        for (i, r) in self.receipts.iter().enumerate() {
            decode_receipt(r).map_err(|what| BlockError::Receipt {
                number: self.number,
                index: i,
                what,
            })?;
        }
        Ok(h)
    }

    /// A block's on-disk form, for a producer's cache: `hash ‖ number u64 ‖
    /// header ‖ n u32 ‖ txs ‖ receipts`, each item `len u32 ‖ bytes`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.hash.as_slice());
        out.extend_from_slice(&self.number.to_be_bytes());
        let put = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend_from_slice(&(b.len() as u32).to_be_bytes());
            out.extend_from_slice(b);
        };
        put(&mut out, &self.header);
        out.extend_from_slice(&(self.txs.len() as u32).to_be_bytes());
        for t in &self.txs {
            put(&mut out, t);
        }
        out.extend_from_slice(&(self.receipts.len() as u32).to_be_bytes());
        for r in &self.receipts {
            put(&mut out, r);
        }
        out
    }

    pub fn decode(mut b: &[u8]) -> Option<Block> {
        fn take<'a>(b: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
            let (h, t) = b.split_at_checked(n)?;
            *b = t;
            Some(h)
        }
        fn u32_(b: &mut &[u8]) -> Option<usize> {
            Some(u32::from_be_bytes(take(b, 4)?.try_into().ok()?) as usize)
        }
        let hash = B256::from_slice(take(&mut b, 32)?);
        let number = u64::from_be_bytes(take(&mut b, 8)?.try_into().ok()?);
        let n = u32_(&mut b)?;
        let header = take(&mut b, n)?.to_vec();
        let list = |b: &mut &[u8]| -> Option<Vec<Vec<u8>>> {
            let k = u32_(b)?;
            let mut v = Vec::with_capacity(k.min(1 << 16));
            for _ in 0..k {
                let n = u32_(b)?;
                v.push(take(b, n)?.to_vec());
            }
            Some(v)
        };
        let txs = list(&mut b)?;
        let receipts = list(&mut b)?;
        b.is_empty().then_some(Block {
            number,
            hash,
            header,
            txs,
            receipts,
        })
    }
}

/// One period's runs, as the manifest carries them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeriodRef {
    /// Negative before the beacon chain ([`period_of_timestamp`]).
    pub period: i64,
    /// The blocks of the span in this period, inclusive.
    pub first_block: u64,
    pub last_block: u64,
    /// Tables with at least one entry; an empty one has no run.
    /// `tx_lookup` is never here ([`HistoryManifest::tx_lookup`]).
    pub tables: Vec<TableRef>,
    /// The values above the inline size, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pack: Option<PackRef>,
}

/// One period's pack: `blake3` of the file and its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackRef {
    #[serde(with = "crate::hex32")]
    pub root: [u8; 32],
    pub bytes: u64,
}

/// A `tx_lookup` run over the periods `first_period ..= last_period`.
/// `table` is `None` when those periods hold no transactions: the piece
/// still covers them, so the pieces always cover every period.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LookupRun {
    pub first_period: i64,
    pub last_period: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table: Option<TableRef>,
}

/// The `tx_lookup` pieces over `n` periods, as inclusive ranges of indexes
/// into the period list: `0 ..= base - 1` (none when `base` is 0), then
/// the closed periods after it in pieces whose sizes are the binary digits
/// of their count, largest first, then the open period (the last) alone.
/// `base` is clamped to the closed periods, `n - 1`.
pub fn tx_lookup_plan(n: usize, base: usize) -> Vec<(usize, usize)> {
    if n == 0 {
        return Vec::new();
    }
    let closed = n - 1;
    let base = base.min(closed);
    let mut out = Vec::new();
    if base > 0 {
        out.push((0, base - 1));
    }
    let tail = closed - base;
    let mut at = base;
    for bit in (0..usize::BITS).rev() {
        let size = 1usize << bit;
        if tail & size != 0 {
            out.push((at, at + size - 1));
            at += size;
        }
    }
    out.push((closed, closed));
    out
}

impl PeriodRef {
    pub fn table(&self, t: u16) -> Option<&TableRef> {
        self.tables.iter().find(|r| r.table_id == t)
    }

    pub fn holds(&self, block: u64) -> bool {
        (self.first_block..=self.last_block).contains(&block)
    }
}

/// A history span: every block from `first_block` to `block_number`, which
/// is `block_hash`, by period. Not evidence of anything: the client checks
/// that `block_hash` is a block its head reaches and verifies the rest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryManifest {
    pub format_version: u32,
    #[serde(with = "crate::hex32")]
    pub profile_id: [u8; 32],
    pub block_hash: B256,
    pub block_number: u64,
    pub first_block: u64,
    /// Ascending, contiguous.
    pub periods: Vec<PeriodRef>,
    /// Ascending, together covering every period once.
    pub tx_lookup: Vec<LookupRun>,
}

impl HistoryManifest {
    /// Compact: a full chain's manifest names about 18,000 files, 3.5 MB
    /// this way against 5 MB pretty, and a client fetches it whole on open.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("manifest serializes")
    }

    pub fn from_json(bytes: &[u8]) -> Result<HistoryManifest, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// The period holding `block`.
    pub fn period_of(&self, block: u64) -> Option<usize> {
        let i = self.periods.partition_point(|p| p.last_block < block);
        self.periods.get(i).filter(|p| p.holds(block)).map(|_| i)
    }

    /// Every run and pack file the manifest names.
    pub fn run_paths(&self) -> Vec<String> {
        let mut v: Vec<String> = self
            .periods
            .iter()
            .flat_map(|p| {
                p.tables
                    .iter()
                    .map(|t| history_run_path(&t.root))
                    .chain(p.pack.map(|k| history_pack_path(&k.root)))
            })
            .chain(
                self.tx_lookup
                    .iter()
                    .filter_map(|l| l.table.as_ref())
                    .map(|t| history_run_path(&t.root)),
            )
            .collect();
        v.sort();
        v.dedup();
        v
    }
}

/// Where the writer reads verified blocks from: a producer's cache, a
/// node's database, or memory in tests.
pub trait BlockSource {
    fn block(&self, number: u64) -> Result<Block, String>;
}

impl<S: BlockSource + ?Sized> BlockSource for &S {
    fn block(&self, number: u64) -> Result<Block, String> {
        (**self).block(number)
    }
}

impl BlockSource for BTreeMap<u64, Block> {
    fn block(&self, number: u64) -> Result<Block, String> {
        self.get(&number)
            .cloned()
            .ok_or_else(|| format!("no block {number}"))
    }
}

/// Opens a [`BlockSource`] for each worker thread of
/// [`write_history_with`]: a node's database wants a read transaction per
/// thread. A source that is `Sync` is its own.
pub trait BlockSources: Sync {
    fn open(&self) -> Result<Box<dyn BlockSource + '_>, String>;
}

impl<S: BlockSource + Sync> BlockSources for S {
    fn open(&self) -> Result<Box<dyn BlockSource + '_>, String> {
        Ok(Box::new(self))
    }
}

/// A producer's block cache, `<work>/blocks/<n>` in [`Block::encode`]'s
/// form. Nothing in it is believed: the writer verifies every block.
pub struct BlockCache(pub PathBuf);

pub fn block_path(work: &Path, n: u64) -> PathBuf {
    work.join("blocks").join(n.to_string())
}

impl BlockSource for BlockCache {
    fn block(&self, n: u64) -> Result<Block, String> {
        let p = block_path(&self.0, n);
        let bytes = fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        Block::decode(&bytes).ok_or_else(|| format!("{}: not a cached block", p.display()))
    }
}

#[derive(Debug)]
pub enum HistoryError {
    Io(std::io::Error),
    Source(String),
    Block(BlockError),
    Run(csl_run::Error),
    Span(String),
}

impl fmt::Display for HistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistoryError::Io(e) => write!(f, "io: {e}"),
            HistoryError::Source(e) => write!(f, "source: {e}"),
            HistoryError::Block(e) => write!(f, "{e}"),
            HistoryError::Run(e) => write!(f, "run: {e}"),
            HistoryError::Span(e) => write!(f, "span: {e}"),
        }
    }
}

impl std::error::Error for HistoryError {}

impl From<std::io::Error> for HistoryError {
    fn from(e: std::io::Error) -> Self {
        HistoryError::Io(e)
    }
}
impl From<BlockError> for HistoryError {
    fn from(e: BlockError) -> Self {
        HistoryError::Block(e)
    }
}
impl From<SortError> for HistoryError {
    fn from(e: SortError) -> Self {
        match e {
            SortError::Io(e) => HistoryError::Io(e),
            SortError::Duplicate { key, .. } | SortError::Conflict { key, .. } => {
                HistoryError::Span(format!(
                    "two transactions with one hash (key {})",
                    hex::encode(key)
                ))
            }
        }
    }
}

impl From<csl_run::Error> for HistoryError {
    fn from(e: csl_run::Error) -> Self {
        HistoryError::Run(e)
    }
}

/// One table of one period as written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HistoryTableStats {
    pub table_id: u16,
    pub entries: u64,
    pub pages: u64,
    pub model_bytes: u64,
    pub file_bytes: u64,
    /// Entries above the inline size, and their bytes, in the period's
    /// pack (a value repeated within a block is stored once).
    pub packed: u64,
    pub packed_bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PeriodStats {
    pub period: i64,
    pub blocks: u64,
    pub transactions: u64,
    pub logs: u64,
    /// Every table but `tx_lookup`, which is written in pieces.
    pub tables: Vec<HistoryTableStats>,
    /// The pack's length; 0 without one.
    pub pack_bytes: u64,
}

impl PeriodStats {
    /// Runs and pack bytes.
    pub fn bytes(&self) -> u64 {
        self.tables.iter().map(|t| t.file_bytes).sum::<u64>() + self.pack_bytes
    }
}

#[derive(Clone, Debug)]
pub struct HistoryWritten {
    pub manifest: HistoryManifest,
    pub stats: Vec<PeriodStats>,
    /// The `tx_lookup` pieces, in the manifest's order.
    pub lookup_stats: Vec<HistoryTableStats>,
    /// Every file written, bucket-relative, in the order a publisher must
    /// put them: runs and packs, then the manifest, then `history/latest`.
    pub files: Vec<String>,
}

/// How [`write_history_with`] runs.
pub struct HistoryOptions<'a> {
    /// Worker threads, each with a source of its own from
    /// [`BlockSources::open`]. Verification takes runs of
    /// [`chunk_blocks`](Self::chunk_blocks) blocks, writing takes whole
    /// periods, both in ascending order.
    pub workers: usize,
    pub chunk_blocks: u64,
    /// The last period of the `tx_lookup` base ([`tx_lookup_plan`]); the
    /// closed periods after it go in binary pieces. `None`: every closed
    /// period, so a read probes two runs.
    pub tx_lookup_base: Option<i64>,
    pub progress_every: Duration,
    /// Called on the calling thread every `progress_every`, and at the end
    /// of each phase.
    pub progress: Option<&'a mut dyn FnMut(&HistoryProgress)>,
}

impl Default for HistoryOptions<'_> {
    fn default() -> Self {
        HistoryOptions {
            workers: 1,
            chunk_blocks: SLOTS_PER_PERIOD,
            tx_lookup_base: None,
            progress_every: Duration::from_secs(60),
            progress: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum HistoryPhase {
    /// Pass 1: every block verified and chained to the anchor; nothing is
    /// written.
    Verify,
    /// Pass 2: each period's runs.
    Write,
    /// The `tx_lookup` pieces, merged from every period's rows.
    Lookup,
}

#[derive(Clone, Debug, Serialize)]
pub struct HistoryProgress {
    pub phase: HistoryPhase,
    pub workers: usize,
    /// Blocks done in this phase, of `of_blocks`.
    pub blocks: u64,
    pub of_blocks: u64,
    /// Transactions done in this phase (in [`HistoryPhase::Lookup`], rows
    /// merged into pieces).
    pub transactions: u64,
    /// Periods written, of `of_periods` (known once verification ends).
    pub periods: u64,
    pub of_periods: u64,
    /// Runs and pack bytes of the periods written.
    pub written_bytes: u64,
    pub elapsed_s: f64,
}

/// One period's span, from pass 1.
#[derive(Clone, Debug)]
struct PeriodPlan {
    period: i64,
    first: u64,
    last: u64,
    txs: u64,
    receipts: u64,
}

/// What pass 1 learns from a run of consecutive blocks.
struct Scan {
    first: u64,
    /// The first block's `parentHash`.
    parent: B256,
    hashes: Vec<B256>,
    periods: Vec<PeriodPlan>,
}

/// One period written.
struct PeriodOut {
    period: PeriodRef,
    stats: PeriodStats,
    files: Vec<String>,
    /// The period's `tx_lookup` rows, sorted, for the pieces.
    rows: Option<SortedFile>,
}

#[derive(Default)]
struct Counters {
    blocks: AtomicU64,
    txs: AtomicU64,
    periods: AtomicU64,
    bytes: AtomicU64,
}

/// Write the span `first ..= anchor.0` from `src`, which must end at the
/// block `anchor.1`, under `root`. Every block is checked here (its
/// header's hash, the chain to the anchor, both roots) before anything is
/// written, so a bucket never holds a block its header does not commit to,
/// whatever the source. Runs and packs first, then the manifest, then
/// `history/latest`.
pub fn write_history(
    root: &Path,
    src: &dyn BlockSource,
    first: u64,
    anchor: (u64, B256),
    epsilon: u16,
) -> Result<HistoryWritten, HistoryError> {
    write_inner(
        root,
        Src::One(src),
        first,
        anchor,
        epsilon,
        None,
        &mut HistoryOptions::default(),
    )
}

/// [`write_history`] on `opts.workers` threads, for spans too large to
/// hold: the whole chain. The output is the same file for file whatever
/// the worker count. Memory is the blocks' hashes (32 bytes a block, about
/// 0.85 GB for mainnet) and, per worker, one period's hint rows. Every
/// period's `tx_lookup` rows also go to a scratch directory under
/// `root/history` (44 bytes a transaction, about 160 GB for mainnet) until
/// the pieces are merged.
pub fn write_history_with(
    root: &Path,
    sources: &dyn BlockSources,
    first: u64,
    anchor: (u64, B256),
    epsilon: u16,
    opts: &mut HistoryOptions,
) -> Result<HistoryWritten, HistoryError> {
    write_inner(root, Src::Many(sources), first, anchor, epsilon, None, opts)
}

/// A `tx_lookup` row: the key and the locator.
pub type TxLookupRow = ([u8; 32], [u8; 8]);

/// A hostile producer's edits, for fault tables: each verified block, each
/// period's sorted hint rows, and each packed value's location (table and
/// key) pass through these before they are written. A bucket written with
/// a `Tamper` is a lying bucket by design; nothing outside a fault table
/// writes one.
#[doc(hidden)]
pub struct Tamper<'a> {
    pub block: &'a dyn Fn(&mut Block),
    pub tx_lookup: &'a dyn Fn(&mut Vec<TxLookupRow>),
    pub log_lookup: &'a dyn Fn(&mut Vec<[u8; 32]>),
    pub packed: &'a dyn Fn(u16, &[u8; 32], &mut PackedRef),
}

/// [`write_history`] with a hostile producer's edits applied after the
/// source is verified. For fault tables only.
#[doc(hidden)]
pub fn write_history_tampered(
    root: &Path,
    src: &dyn BlockSource,
    first: u64,
    anchor: (u64, B256),
    epsilon: u16,
    tamper: &Tamper,
) -> Result<HistoryWritten, HistoryError> {
    write_inner(
        root,
        Src::One(src),
        first,
        anchor,
        epsilon,
        Some(tamper),
        &mut HistoryOptions::default(),
    )
}

enum Src<'a> {
    /// Everything on the calling thread.
    One(&'a dyn BlockSource),
    /// A source per worker.
    Many(&'a dyn BlockSources),
}

fn write_inner(
    root: &Path,
    src: Src,
    first: u64,
    anchor: (u64, B256),
    epsilon: u16,
    tamper: Option<&Tamper>,
    opts: &mut HistoryOptions,
) -> Result<HistoryWritten, HistoryError> {
    let (last, anchor_hash) = anchor;
    if first > last || last > MAX_BLOCK {
        return Err(HistoryError::Span(format!("blocks {first} to {last}")));
    }
    let started = Instant::now();
    let workers = match src {
        Src::One(_) => 1,
        Src::Many(_) => opts.workers.max(1),
    };
    let total = last - first + 1;
    let counters = Counters::default();
    let stop = AtomicBool::new(false);
    let report = |opts: &mut HistoryOptions, phase, of_periods| {
        let p = HistoryProgress {
            phase,
            workers,
            blocks: counters.blocks.load(Ordering::Relaxed),
            of_blocks: total,
            transactions: counters.txs.load(Ordering::Relaxed),
            periods: counters.periods.load(Ordering::Relaxed),
            of_periods,
            written_bytes: counters.bytes.load(Ordering::Relaxed),
            elapsed_s: started.elapsed().as_secs_f64(),
        };
        if let Some(f) = opts.progress.as_mut() {
            f(&p);
        }
    };

    // Pass 1: verify the chain and every block, plan the periods.
    let scans = match src {
        Src::One(s) => vec![scan(s, first, last, tamper, &counters, &stop)?],
        Src::Many(sources) => {
            let chunk = opts.chunk_blocks.max(1);
            let jobs = total.div_ceil(chunk) as usize;
            let job = |s: &dyn BlockSource, i: usize| {
                let lo = first + i as u64 * chunk;
                scan(s, lo, (lo + chunk - 1).min(last), None, &counters, &stop)
            };
            let every = opts.progress_every;
            par_jobs(sources, workers, jobs, &job, &stop, every, &mut || {
                report(opts, HistoryPhase::Verify, 0)
            })?
        }
    };
    let (plans, verified) = join(scans, anchor)?;
    report(opts, HistoryPhase::Verify, plans.len() as u64);

    // Pass 2: write each period's runs and pack; the `tx_lookup` rows go
    // to scratch for the pieces.
    fs::create_dir_all(root.join("history/runs"))?;
    fs::create_dir_all(root.join("history/packs"))?;
    let scratch = Scratch::new(&root.join("history"))?;
    counters.blocks.store(0, Ordering::Relaxed);
    counters.txs.store(0, Ordering::Relaxed);
    let rows_dir = scratch.path();
    let outs = match src {
        Src::One(s) => {
            let mut v = Vec::with_capacity(plans.len());
            for p in &plans {
                let w = PeriodWrite {
                    root,
                    rows_dir,
                    epsilon,
                    counters: &counters,
                    stop: &stop,
                };
                v.push(w.write(s, p, period_hashes(&verified, first, p), tamper)?);
            }
            v
        }
        Src::Many(sources) => {
            let job = |s: &dyn BlockSource, i: usize| {
                let p = &plans[i];
                let w = PeriodWrite {
                    root,
                    rows_dir,
                    epsilon,
                    counters: &counters,
                    stop: &stop,
                };
                w.write(s, p, period_hashes(&verified, first, p), None)
            };
            let every = opts.progress_every;
            let n = plans.len() as u64;
            par_jobs(
                sources,
                workers,
                plans.len(),
                &job,
                &stop,
                every,
                &mut || report(opts, HistoryPhase::Write, n),
            )?
        }
    };
    report(opts, HistoryPhase::Write, plans.len() as u64);

    let mut files: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut periods = Vec::with_capacity(outs.len());
    let mut stats = Vec::with_capacity(outs.len());
    let mut rows = Vec::with_capacity(outs.len());
    for o in outs {
        for f in o.files {
            if seen.insert(f.clone()) {
                files.push(f);
            }
        }
        periods.push(o.period);
        stats.push(o.stats);
        rows.push(o.rows);
    }

    // The `tx_lookup` pieces.
    counters.txs.store(0, Ordering::Relaxed);
    let base = match opts.tx_lookup_base {
        None => periods.len(),
        Some(b) => periods.iter().take_while(|p| p.period <= b).count(),
    };
    let mut tx_lookup = Vec::new();
    let mut lookup_stats = Vec::new();
    let runs_dir = root.join("history/runs");
    let mut last_tick = Instant::now();
    for (lo, hi) in tx_lookup_plan(periods.len(), base) {
        let mut sort = ExtSort::new(rows_dir, LOOKUP_MERGE_BUDGET, &[Dups::Error]);
        for f in rows[lo..=hi].iter_mut().filter_map(Option::take) {
            sort.adopt(0, f);
        }
        sort.prepare()?;
        let entries = sort.stats(0).entries;
        let cfg = Config {
            profile_id: profile_id(),
            table_id: H_TX_LOOKUP,
            value_size: 0,
            epsilon,
        };
        let tag = format!("{}-lookup-{lo}", std::process::id());
        let mut w = RunOut::new(&runs_dir, &tag, cfg, entries)?;
        let mut none = PackOut::new(&runs_dir, &tag);
        sort.merge::<HistoryError>(0, |k, v| {
            w.push(&mut none, None, *k, v.to_vec())?;
            let n = counters.txs.fetch_add(1, Ordering::Relaxed);
            if n % (1 << 20) == 0 && last_tick.elapsed() >= opts.progress_every {
                last_tick = Instant::now();
                report(opts, HistoryPhase::Lookup, plans.len() as u64);
            }
            Ok(())
        })?;
        drop(sort);
        // A piece with no transactions still covers its periods; it has no
        // run, and zero stats keep `lookup_stats` in step with the pieces.
        let (table, st) = match w.finish(root, &mut files)? {
            Some((tr, st)) => (Some(tr), st),
            None => (
                None,
                HistoryTableStats {
                    table_id: H_TX_LOOKUP,
                    ..Default::default()
                },
            ),
        };
        tx_lookup.push(LookupRun {
            first_period: periods[lo].period,
            last_period: periods[hi].period,
            table,
        });
        lookup_stats.push(st);
    }
    drop(scratch);
    report(opts, HistoryPhase::Lookup, plans.len() as u64);

    let manifest = HistoryManifest {
        format_version: HISTORY_FORMAT_VERSION,
        profile_id: profile_id(),
        block_hash: anchor_hash,
        block_number: last,
        first_block: first,
        periods,
        tx_lookup,
    };
    let mpath = history_manifest_path(&anchor_hash);
    write_atomic(&root.join(&mpath), manifest.to_json().as_bytes())?;
    files.push(mpath);
    write_atomic(
        &root.join(HISTORY_LATEST),
        hex::encode(anchor_hash).as_bytes(),
    )?;
    files.push(HISTORY_LATEST.to_string());
    Ok(HistoryWritten {
        manifest,
        stats,
        lookup_stats,
        files,
    })
}

/// The merge of `tx_lookup` rows reads 64 KiB from each of up to 128
/// period files at once ([`Budget::fan_in`]); more periods than that merge
/// in groups first. Well under any open-file limit.
const LOOKUP_MERGE_BUDGET: Budget = Budget::new(128 * (64 << 10));

/// Pass 1 over `lo ..= hi`: each block verified on its own (header hash,
/// both roots, receipts decoding) and chained to the one before it.
fn scan(
    src: &dyn BlockSource,
    lo: u64,
    hi: u64,
    tamper: Option<&Tamper>,
    c: &Counters,
    stop: &AtomicBool,
) -> Result<Scan, HistoryError> {
    let mut out = Scan {
        first: lo,
        parent: B256::ZERO,
        hashes: Vec::with_capacity((hi - lo + 1) as usize),
        periods: Vec::new(),
    };
    let mut prev: Option<HeaderFields> = None;
    for n in lo..=hi {
        if stop.load(Ordering::Relaxed) {
            return Err(stopped());
        }
        let mut b = src.block(n).map_err(HistoryError::Source)?;
        if b.number != n {
            return Err(HistoryError::Source(format!(
                "asked for block {n}, got {}",
                b.number
            )));
        }
        let h = b.verify()?;
        out.hashes.push(h.hash);
        if let Some(t) = tamper {
            (t.block)(&mut b);
        }
        match &prev {
            Some(p) if h.parent_hash != p.hash => {
                return Err(BlockError::Chain { number: p.number }.into());
            }
            Some(_) => {}
            None => out.parent = h.parent_hash,
        }
        if b.txs.len() as u64 > MAX_INDEX {
            return Err(HistoryError::Span(format!(
                "block {n} has {} transactions",
                b.txs.len()
            )));
        }
        let period = period_of_timestamp(h.timestamp);
        let (txs, receipts) = (b.txs.len() as u64, b.receipts.len() as u64);
        match out.periods.last_mut() {
            Some(p) if p.period == period => {
                p.last = n;
                p.txs += txs;
                p.receipts += receipts;
            }
            Some(p) if p.period > period => return Err(earlier_period(n)),
            _ => out.periods.push(PeriodPlan {
                period,
                first: n,
                last: n,
                txs,
                receipts,
            }),
        }
        c.blocks.fetch_add(1, Ordering::Relaxed);
        c.txs.fetch_add(txs, Ordering::Relaxed);
        prev = Some(h);
    }
    Ok(out)
}

fn earlier_period(n: u64) -> HistoryError {
    HistoryError::Span(format!("block {n} is in an earlier period than its parent"))
}

/// The hashes pass 1 verified for a period's blocks.
fn period_hashes<'a>(verified: &'a [B256], first: u64, p: &PeriodPlan) -> &'a [B256] {
    &verified[(p.first - first) as usize..=(p.last - first) as usize]
}

/// A worker giving up because another failed; never the error returned.
fn stopped() -> HistoryError {
    HistoryError::Span("stopped: another worker failed".into())
}

/// Pass 1's runs in order, into periods and the blocks' hashes, checking
/// that each run follows the last and the span ends at the anchor.
fn join(
    scans: Vec<Scan>,
    anchor: (u64, B256),
) -> Result<(Vec<PeriodPlan>, Vec<B256>), HistoryError> {
    let (last, anchor_hash) = anchor;
    let mut hashes: Vec<B256> = Vec::with_capacity(scans.iter().map(|s| s.hashes.len()).sum());
    let mut plans: Vec<PeriodPlan> = Vec::new();
    for s in scans {
        if let Some(prev) = hashes.last() {
            if s.parent != *prev {
                return Err(BlockError::Chain {
                    number: s.first - 1,
                }
                .into());
            }
        }
        hashes.extend(s.hashes);
        for p in s.periods {
            match plans.last_mut() {
                Some(q) if q.period == p.period => {
                    q.last = p.last;
                    q.txs += p.txs;
                    q.receipts += p.receipts;
                }
                Some(q) if q.period > p.period => return Err(earlier_period(p.first)),
                _ => plans.push(p),
            }
        }
    }
    let top = *hashes.last().expect("at least one block");
    if top != anchor_hash {
        return Err(HistoryError::Span(format!(
            "block {last} is {top}, the anchor is {anchor_hash}"
        )));
    }
    Ok((plans, hashes))
}

/// Run `jobs` jobs on `workers` threads, each with its own source, in
/// ascending order of index; the results come back in index order. The
/// first job to fail stops the others (they finish the block they are on)
/// and its error is returned. A worker that panics stops the others too,
/// and the panic resumes here once they have.
fn par_jobs<T: Send>(
    sources: &dyn BlockSources,
    workers: usize,
    jobs: usize,
    job: &(dyn Fn(&dyn BlockSource, usize) -> Result<T, HistoryError> + Sync),
    stop: &AtomicBool,
    every: Duration,
    tick: &mut dyn FnMut(),
) -> Result<Vec<T>, HistoryError> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<T>>> = Mutex::new((0..jobs).map(|_| None).collect());
    let failed: Mutex<Option<HistoryError>> = Mutex::new(None);
    let threads = workers.clamp(1, jobs.max(1));
    let running = AtomicUsize::new(threads);
    let fail = |e: HistoryError| {
        let mut f = failed.lock().unwrap_or_else(|p| p.into_inner());
        if f.is_none() {
            *f = Some(e);
        }
        stop.store(true, Ordering::Relaxed);
    };
    /// Counts a worker out however it ends, and stops the others if it
    /// panicked.
    struct Out<'a>(&'a AtomicUsize, &'a AtomicBool);
    impl Drop for Out<'_> {
        fn drop(&mut self) {
            if std::thread::panicking() {
                self.1.store(true, Ordering::Relaxed);
            }
            self.0.fetch_sub(1, Ordering::Release);
        }
    }
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                let _out = Out(&running, stop);
                let src = match sources.open() {
                    Ok(src) => src,
                    Err(e) => return fail(HistoryError::Source(e)),
                };
                while !stop.load(Ordering::Relaxed) {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= jobs {
                        break;
                    }
                    match job(&*src, i) {
                        Ok(t) => results.lock().unwrap_or_else(|p| p.into_inner())[i] = Some(t),
                        Err(e) => return fail(e),
                    }
                }
            });
        }
        let mut last = Instant::now();
        while running.load(Ordering::Acquire) > 0 {
            std::thread::sleep(Duration::from_millis(50).min(every));
            if last.elapsed() >= every {
                last = Instant::now();
                tick();
            }
        }
    });
    if let Some(e) = failed.into_inner().unwrap_or_else(|p| p.into_inner()) {
        return Err(e);
    }
    results
        .into_inner()
        .unwrap_or_else(|p| p.into_inner())
        .into_iter()
        .enumerate()
        .map(|(i, r)| r.ok_or_else(|| HistoryError::Span(format!("job {i} did not finish"))))
        .collect()
}

/// Pass 2 for one period.
struct PeriodWrite<'a> {
    root: &'a Path,
    rows_dir: &'a Path,
    epsilon: u16,
    counters: &'a Counters,
    stop: &'a AtomicBool,
}

impl PeriodWrite<'_> {
    /// Read the period's blocks again, check each is the block pass 1
    /// chained to the anchor (`verified`, the period's hashes) and verifies
    /// again, and write the four runs and the pack; the hint rows come
    /// from the same bytes, `tx_lookup`'s to a sorted file in `rows_dir`.
    fn write(
        &self,
        src: &dyn BlockSource,
        plan: &PeriodPlan,
        verified: &[B256],
        tamper: Option<&Tamper>,
    ) -> Result<PeriodOut, HistoryError> {
        let root = self.root;
        let runs_dir = root.join("history/runs");
        let cfg = |table_id: u16| Config {
            profile_id: profile_id(),
            table_id,
            value_size: 0,
            epsilon: self.epsilon,
        };
        let mut files = Vec::new();
        let blocks = plan.last - plan.first + 1;
        let tag = format!("{}-{}", std::process::id(), plan.first);
        let mut pack = PackOut::new(&root.join("history/packs"), &tag);
        let mut w_headers = RunOut::new(&runs_dir, &tag, cfg(H_HEADERS), blocks)?;
        let mut w_txs = RunOut::new(&runs_dir, &tag, cfg(H_TRANSACTIONS), plan.txs)?;
        let mut w_receipts = RunOut::new(&runs_dir, &tag, cfg(H_RECEIPTS), plan.receipts)?;
        let mut tx_lookup: Vec<TxLookupRow> = Vec::with_capacity(plan.txs as usize);
        let mut log_lookup: Vec<[u8; 32]> = Vec::new();
        let mut logs = 0u64;
        for n in plan.first..=plan.last {
            if self.stop.load(Ordering::Relaxed) {
                return Err(stopped());
            }
            pack.next_block();
            let mut b = src.block(n).map_err(HistoryError::Source)?;
            // The source served this block once already. The bytes written
            // are verified again here (header hash, both roots, receipts
            // decoding) and must be the block pass 1 chained to the anchor:
            // a source that changed in between is a fault, not something
            // to write.
            let was = verified[(n - plan.first) as usize];
            let changed = || HistoryError::Source(format!("block {n} changed between passes"));
            if b.number != n || b.hash != was {
                return Err(changed());
            }
            match b.verify() {
                Ok(h) if h.hash == was => {}
                _ => return Err(changed()),
            }
            if let Some(t) = tamper {
                (t.block)(&mut b);
            }
            for (i, t) in b.txs.iter().enumerate() {
                tx_lookup.push((tx_lookup_key(&tx_hash(t)), locator(n, i as u64)));
            }
            let mut terms = std::collections::BTreeSet::new();
            for r in &b.receipts {
                // Verified above, unless a fault table's edit broke it.
                let Ok(r) = decode_receipt(r) else { continue };
                logs += r.logs.len() as u64;
                for l in &r.logs {
                    terms.insert(Term::Address(l.address));
                    for t in &l.topics {
                        terms.insert(Term::Topic(*t));
                    }
                }
            }
            for t in terms {
                log_lookup.push(log_lookup_key(&t.hash(), n));
            }
            // Header, transactions, receipts: a block's packed values are
            // adjacent in the pack.
            let txs = b.txs.len() as u64;
            w_headers.push(&mut pack, tamper, block_key(n, 0), b.header)?;
            for (i, t) in b.txs.into_iter().enumerate() {
                w_txs.push(&mut pack, tamper, block_key(n, i as u64), t)?;
            }
            for (i, r) in b.receipts.into_iter().enumerate() {
                w_receipts.push(&mut pack, tamper, block_key(n, i as u64), r)?;
            }
            self.counters.blocks.fetch_add(1, Ordering::Relaxed);
            self.counters.txs.fetch_add(txs, Ordering::Relaxed);
        }
        tx_lookup.sort_unstable();
        log_lookup.sort_unstable();
        log_lookup.dedup();
        if tx_lookup.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(HistoryError::Span("two transactions with one hash".into()));
        }
        if let Some(t) = tamper {
            (t.tx_lookup)(&mut tx_lookup);
            (t.log_lookup)(&mut log_lookup);
        }
        let rows = if tx_lookup.is_empty() {
            None
        } else {
            let path = self.rows_dir.join(format!("{tag}.rows"));
            Some(SortedFile::write(
                &path,
                1 << 20,
                tx_lookup.iter().map(|(k, v)| (k, &v[..])),
            )?)
        };
        drop(tx_lookup);
        let mut w_log_lookup =
            RunOut::new(&runs_dir, &tag, cfg(H_LOG_LOOKUP), log_lookup.len() as u64)?;
        for k in &log_lookup {
            w_log_lookup.push(&mut pack, None, *k, Vec::new())?;
        }
        let mut stats = PeriodStats {
            period: plan.period,
            blocks,
            transactions: plan.txs,
            logs,
            tables: Vec::new(),
            pack_bytes: 0,
        };
        // The pack before the runs that point into it.
        let pack = pack.finish(root, &mut files)?;
        stats.pack_bytes = pack.map_or(0, |p| p.bytes);
        let mut tables = Vec::new();
        for w in [w_headers, w_txs, w_receipts, w_log_lookup] {
            if let Some((tr, st)) = w.finish(root, &mut files)? {
                tables.push(tr);
                stats.tables.push(st);
            }
        }
        self.counters.periods.fetch_add(1, Ordering::Relaxed);
        self.counters
            .bytes
            .fetch_add(stats.bytes(), Ordering::Relaxed);
        Ok(PeriodOut {
            period: PeriodRef {
                period: plan.period,
                first_block: plan.first,
                last_block: plan.last,
                tables,
                pack,
            },
            stats,
            files,
            rows,
        })
    }
}

/// One period's pack being written under a temporary name, renamed to its
/// `blake3` when finished, removed if it never is. A value repeated within
/// a block is stored once; across blocks it is stored again, so a block's
/// values stay one range.
struct PackOut {
    tmp: PathBuf,
    out: Option<BufWriter<File>>,
    hasher: blake3::Hasher,
    len: u64,
    seen: HashMap<[u8; 32], PackedRef>,
}

impl Drop for PackOut {
    fn drop(&mut self) {
        if self.out.take().is_some() {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

impl PackOut {
    fn new(dir: &Path, tag: &str) -> PackOut {
        PackOut {
            tmp: dir.join(format!("tmp-{tag}.pack")),
            out: None,
            hasher: blake3::Hasher::new(),
            len: 0,
            seen: HashMap::new(),
        }
    }

    /// A new block: values before it are no longer shared.
    fn next_block(&mut self) {
        self.seen.clear();
    }

    fn add(&mut self, value: &[u8]) -> Result<PackedRef, HistoryError> {
        let hash = *blake3::hash(value).as_bytes();
        if let Some(r) = self.seen.get(&hash) {
            return Ok(*r);
        }
        let len = u32::try_from(value.len())
            .map_err(|_| HistoryError::Span(format!("a value of {} bytes", value.len())))?;
        if self.out.is_none() {
            self.out = Some(BufWriter::with_capacity(1 << 20, File::create(&self.tmp)?));
        }
        let out = self.out.as_mut().expect("opened above");
        out.write_all(value)?;
        self.hasher.update(value);
        let r = PackedRef {
            off: self.len,
            len,
            hash,
        };
        self.len += value.len() as u64;
        self.seen.insert(hash, r);
        Ok(r)
    }

    fn finish(
        mut self,
        root: &Path,
        files: &mut Vec<String>,
    ) -> Result<Option<PackRef>, HistoryError> {
        let Some(out) = self.out.take() else {
            return Ok(None);
        };
        let done = (|| {
            out.into_inner().map_err(|e| e.into_error())?.sync_data()?;
            let k = PackRef {
                root: *self.hasher.finalize().as_bytes(),
                bytes: self.len,
            };
            let rel = history_pack_path(&k.root);
            fs::rename(&self.tmp, root.join(&rel))?;
            Ok::<_, std::io::Error>((k, rel))
        })();
        match done {
            Ok((k, rel)) => {
                files.push(rel);
                Ok(Some(k))
            }
            Err(e) => {
                let _ = fs::remove_file(&self.tmp);
                Err(e.into())
            }
        }
    }
}

/// One run being written under a temporary name, renamed to its `blake3`
/// when finished, removed if it never is. Values above the inline size go
/// to the period's pack.
struct RunOut {
    tmp: PathBuf,
    w: Option<Writer<File>>,
    table_id: u16,
    epsilon: u16,
    packed: u64,
    packed_bytes: u64,
}

impl Drop for RunOut {
    fn drop(&mut self) {
        if self.w.take().is_some() {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

impl RunOut {
    fn new(dir: &Path, tag: &str, cfg: Config, entries: u64) -> Result<RunOut, HistoryError> {
        let tmp = dir.join(format!("tmp-{tag}-{}.run", cfg.table_id));
        let w = if entries == 0 {
            None
        } else {
            let file = File::options()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            Some(Writer::with_format(file, cfg, HISTORY_RUN_FORMAT, entries)?)
        };
        Ok(RunOut {
            tmp,
            w,
            table_id: cfg.table_id,
            epsilon: cfg.epsilon,
            packed: 0,
            packed_bytes: 0,
        })
    }

    fn push(
        &mut self,
        pack: &mut PackOut,
        tamper: Option<&Tamper>,
        key: [u8; 32],
        value: Vec<u8>,
    ) -> Result<(), HistoryError> {
        let w = self
            .w
            .as_mut()
            .ok_or_else(|| HistoryError::Span("an entry for a table counted empty".into()))?;
        if value.len() > CODE_BLOB_THRESHOLD {
            let mut r = pack.add(&value)?;
            if let Some(t) = tamper {
                (t.packed)(self.table_id, &key, &mut r);
            }
            self.packed += 1;
            self.packed_bytes += value.len() as u64;
            w.push(Entry::packed(key, r))?;
        } else {
            w.push(Entry::value(key, value))?;
        }
        Ok(())
    }

    fn finish(
        mut self,
        root: &Path,
        files: &mut Vec<String>,
    ) -> Result<Option<(TableRef, HistoryTableStats)>, HistoryError> {
        let Some(w) = self.w.take() else {
            return Ok(None);
        };
        let built = match w.finish() {
            Ok(b) => b,
            Err(e) => {
                let _ = fs::remove_file(&self.tmp);
                return Err(e.into());
            }
        };
        let rel = history_run_path(&built.root);
        if let Err(e) = fs::rename(&self.tmp, root.join(&rel)) {
            let _ = fs::remove_file(&self.tmp);
            return Err(e.into());
        }
        files.push(rel);
        let tr = TableRef {
            table_id: self.table_id,
            root: built.root,
            page_count: built.page_count,
            entry_count: built.entry_count,
            epsilon_pages: self.epsilon,
            model_bytes: built.layout.model_bytes as u32,
            model_root: built.model_root,
        };
        let st = HistoryTableStats {
            table_id: self.table_id,
            entries: built.entry_count,
            pages: built.page_count,
            model_bytes: built.layout.model_bytes,
            file_bytes: built.layout.total_len,
            packed: self.packed,
            packed_bytes: self.packed_bytes,
        };
        Ok(Some((tr, st)))
    }
}

/// Encode a receipt leaf from its fields: the inverse of
/// [`decode_receipt`].
pub fn encode_receipt(r: &ReceiptFields) -> Vec<u8> {
    use alloy_rlp::Encodable;
    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let len = items.iter().map(Vec::len).sum();
        let mut out = Vec::with_capacity(len + 9);
        RlpHeader {
            list: true,
            payload_length: len,
        }
        .encode(&mut out);
        for i in items {
            out.extend_from_slice(i);
        }
        out
    }
    fn enc<T: Encodable + ?Sized>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        v.encode(&mut out);
        out
    }
    let logs: Vec<Vec<u8>> = r
        .logs
        .iter()
        .map(|l| {
            let topics: Vec<Vec<u8>> = l.topics.iter().map(enc).collect();
            list(&[enc(&l.address), list(&topics), enc(&l.data[..])])
        })
        .collect();
    let status: &[u8] = match (&r.post_state, r.success) {
        (Some(root), _) => root.as_slice(),
        (None, true) => &[1],
        (None, false) => &[],
    };
    let body = list(&[
        enc(status),
        enc(&r.cumulative_gas_used),
        enc(&r.bloom),
        list(&logs),
    ]);
    if r.tx_type == 0 {
        body
    } else {
        let mut out = vec![r.tx_type];
        out.extend_from_slice(&body);
        out
    }
}

/// A deterministic synthetic chain for tests and fault tables: real
/// header RLP (London fields and a withdrawals root), typed transaction
/// envelopes of arbitrary content (history never decodes a transaction),
/// receipts whose logs draw from small address and topic pools, so
/// lookups have busy terms and rare ones, and a few leaves above the blob
/// threshold.
pub mod synthetic {
    use super::*;
    use alloy_rlp::Encodable;

    /// The busy address: a log in most blocks.
    pub fn busy_address() -> Address {
        Address::repeat_byte(0xb5)
    }

    /// An address with one log in the whole chain, in block
    /// `first + count / 2`, transaction 0.
    pub fn rare_address() -> Address {
        Address::repeat_byte(0x7a)
    }

    pub fn pool_address(i: u64) -> Address {
        let mut a = [0u8; 20];
        a[0] = 0xa0;
        a[12..].copy_from_slice(&i.to_be_bytes());
        Address::from(a)
    }

    pub fn pool_topic(i: u64) -> B256 {
        keccak256(format!("synthetic topic {i}"))
    }

    struct Rng(B256);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = keccak256(self.0);
            u64::from_be_bytes(self.0[..8].try_into().expect("8 bytes"))
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    fn enc<T: Encodable + ?Sized>(v: &T) -> Vec<u8> {
        let mut out = Vec::new();
        v.encode(&mut out);
        out
    }

    fn list(items: &[Vec<u8>]) -> Vec<u8> {
        let len = items.iter().map(Vec::len).sum();
        let mut out = Vec::with_capacity(len + 9);
        RlpHeader {
            list: true,
            payload_length: len,
        }
        .encode(&mut out);
        for i in items {
            out.extend_from_slice(i);
        }
        out
    }

    /// `count` blocks from `first`, the first with timestamp `ts_first`,
    /// 12 seconds apart, chained from a made-up parent. Same seed, same
    /// chain.
    pub fn chain(seed: u64, first: u64, count: u64, ts_first: u64) -> BTreeMap<u64, Block> {
        chain_with(seed, first, count, ts_first, false)
    }

    /// [`chain`], or with `pre_byzantium` a chain of legacy transactions
    /// whose receipts carry a post-state root in place of the status, as
    /// mainnet's below block 4,370,000 do.
    pub fn chain_with(
        seed: u64,
        first: u64,
        count: u64,
        ts_first: u64,
        pre_byzantium: bool,
    ) -> BTreeMap<u64, Block> {
        chain_spaced(seed, first, count, ts_first, 12, pre_byzantium)
    }

    /// [`chain_with`] with `block_secs` between blocks: a chain over many
    /// periods in a few blocks (a period is 98,304 seconds).
    pub fn chain_spaced(
        seed: u64,
        first: u64,
        count: u64,
        ts_first: u64,
        block_secs: u64,
        pre_byzantium: bool,
    ) -> BTreeMap<u64, Block> {
        let mut rng = Rng(keccak256(seed.to_be_bytes()));
        let mut parent = keccak256(format!("synthetic parent {seed}"));
        let empty_ommers = keccak256([0xc0u8]);
        let mut out = BTreeMap::new();
        for n in first..first + count {
            let txn = if rng.below(8) == 0 {
                0
            } else {
                1 + rng.below(40)
            };
            let mut txs = Vec::new();
            let mut receipts = Vec::new();
            let mut block_bloom = Bloom::ZERO;
            let mut gas = 0u64;
            for i in 0..txn {
                let big = rng.below(50) == 0;
                let size = if big {
                    5000 + rng.below(3000)
                } else {
                    40 + rng.below(300)
                };
                let mut payload = vec![0u8; size as usize];
                for (j, b) in payload.iter_mut().enumerate() {
                    *b = (rng.0[j % 32]) ^ (j as u8);
                }
                let tx_type = [0u8, 2, 2, 2, 3][rng.below(5) as usize];
                let tx_type = if pre_byzantium { 0 } else { tx_type };
                let body = list(&[enc(&n), enc(&i), enc(&rng.next()), enc(&payload[..])]);
                let tx = if tx_type == 0 {
                    body
                } else {
                    let mut t = vec![tx_type];
                    t.extend_from_slice(&body);
                    t
                };
                let mut logs = Vec::new();
                if n == first + count / 2 && i == 0 {
                    logs.push(Log {
                        address: rare_address(),
                        topics: vec![pool_topic(99)],
                        data: vec![1, 2, 3],
                    });
                }
                if i == 0 && rng.below(10) != 0 {
                    logs.push(Log {
                        address: busy_address(),
                        topics: vec![pool_topic(0), pool_topic(1 + rng.below(3))],
                        data: vec![0; 32],
                    });
                }
                for _ in 0..rng.below(4) {
                    let topics = (0..rng.below(4))
                        .map(|_| pool_topic(rng.below(12)))
                        .collect();
                    let dl = if big { 4500 } else { rng.below(96) as usize };
                    logs.push(Log {
                        address: pool_address(rng.below(24)),
                        topics,
                        data: vec![0x5a; dl],
                    });
                }
                let mut bloom = Bloom::ZERO;
                for l in &logs {
                    bloom.accrue(BloomInput::Raw(l.address.as_slice()));
                    for t in &l.topics {
                        bloom.accrue(BloomInput::Raw(t.as_slice()));
                    }
                }
                block_bloom.accrue_bloom(&bloom);
                gas += 21_000 + rng.below(200_000);
                let r = ReceiptFields {
                    tx_type,
                    success: rng.below(20) != 0 && !pre_byzantium,
                    post_state: pre_byzantium.then(|| keccak256(format!("post state {n} {i}"))),
                    cumulative_gas_used: gas,
                    bloom,
                    logs,
                };
                txs.push(tx);
                receipts.push(encode_receipt(&r));
            }
            let fields = [
                enc(&parent),
                enc(&empty_ommers),
                enc(&Address::repeat_byte(0xfe)),
                enc(&keccak256(format!("state {n}"))),
                enc(&ordered_root(&txs)),
                enc(&ordered_root(&receipts)),
                enc(&block_bloom),
                enc(&0u64),
                enc(&n),
                enc(&36_000_000u64),
                enc(&gas),
                enc(&(ts_first + (n - first) * block_secs)),
                enc(&b"synthetic"[..]),
                enc(&B256::ZERO),
                enc(&[0u8; 8][..]),
                enc(&7u64),
                enc(&keccak256(format!("withdrawals {n}"))),
            ];
            let header = list(&fields);
            let hash = keccak256(&header);
            out.insert(
                n,
                Block {
                    number: n,
                    hash,
                    header,
                    txs,
                    receipts,
                },
            );
            parent = hash;
        }
        out
    }

    /// Empty the blocks of `c` that `pred` picks (no transactions, no
    /// receipts, no gas, an empty bloom) and rebuild the headers from the
    /// first of them, so the chain still links.
    pub fn strip(c: &mut BTreeMap<u64, Block>, pred: impl Fn(u64) -> bool) {
        let mut parent: Option<B256> = None;
        for (&n, b) in c.iter_mut() {
            let hit = pred(n);
            if !hit && parent.is_none() {
                continue;
            }
            let mut it: Vec<Vec<u8>> = list_items(&b.header)
                .expect("a synthetic header")
                .iter()
                .map(|x| x.to_vec())
                .collect();
            if let Some(p) = parent {
                it[0] = enc(&p);
            }
            if hit {
                b.txs.clear();
                b.receipts.clear();
                it[4] = enc(&ordered_root(&[]));
                it[5] = enc(&ordered_root(&[]));
                it[6] = enc(&Bloom::ZERO);
                it[10] = enc(&0u64);
            }
            b.header = list(&it);
            b.hash = keccak256(&b.header);
            parent = Some(b.hash);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_sort_by_block_then_index() {
        assert!(block_key(5, 0) < block_key(5, 1));
        assert!(block_key(5, MAX_INDEX) < block_key(6, 0));
        assert_eq!(
            parse_locator(&locator(26_421_605, 377)),
            Some((26_421_605, 377))
        );
        assert_eq!(csl_run::k64(&block_key(7, 3)), (7 << 24) | 3);
    }

    #[test]
    fn a_log_key_belongs_to_its_term_and_rises_with_the_block() {
        let a = Term::Address(Address::repeat_byte(0x11)).hash();
        let b = Term::Topic(B256::repeat_byte(0x11)).hash();
        assert_ne!(a, b);
        let k1 = log_lookup_key(&a, 100);
        let k2 = log_lookup_key(&a, 101);
        assert!(k1 < k2);
        assert!(
            csl_run::k64(&k1) < csl_run::k64(&k2),
            "one term's rows do not share a k64"
        );
        assert_eq!(log_lookup_block(&a, &k2), Some(101));
        assert_eq!(log_lookup_block(&b, &k2), None);
    }

    #[test]
    fn a_block_survives_its_cache_encoding() {
        let b = Block {
            number: 9,
            hash: B256::repeat_byte(3),
            header: vec![0xc0],
            txs: vec![vec![1, 2], vec![]],
            receipts: vec![vec![3], vec![4, 5, 6]],
        };
        assert_eq!(Block::decode(&b.encode()), Some(b.clone()));
        let mut e = b.encode();
        e.push(0);
        assert_eq!(Block::decode(&e), None);
        assert_eq!(Block::decode(&b.encode()[..10]), None);
    }

    /// Serves `chain`, but `swap(block)` in place of block `at` from its
    /// second read on: a cache file replaced between the writer's passes.
    struct Changing<F: Fn(&Block) -> Block> {
        chain: BTreeMap<u64, Block>,
        at: u64,
        reads: std::cell::Cell<u32>,
        swap: F,
    }

    impl<F: Fn(&Block) -> Block> BlockSource for Changing<F> {
        fn block(&self, n: u64) -> Result<Block, String> {
            let b = self.chain.block(n)?;
            if n != self.at {
                return Ok(b);
            }
            self.reads.set(self.reads.get() + 1);
            Ok(if self.reads.get() > 1 {
                (self.swap)(&b)
            } else {
                b
            })
        }
    }

    fn scratch(what: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("csl-history-changed-{}-{what}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    type Swap<'a> = Box<dyn Fn(&Block) -> Block + 'a>;

    #[test]
    fn a_block_changed_between_passes_is_not_written() {
        let ts = MAINNET_GENESIS_TIME + 12 * 8192 * 5;
        let chain = synthetic::chain(1, 100, 20, ts);
        let other = synthetic::chain(2, 100, 20, ts);
        let anchor = (119, chain[&119].hash);
        let at = 110;
        assert!(!chain[&at].txs.is_empty());
        let swaps: [(&str, Swap); 3] = [
            // The same header, another body: the roots no longer rebuild.
            (
                "body",
                Box::new(|b: &Block| {
                    let mut b = b.clone();
                    b.txs[0].push(0);
                    b
                }),
            ),
            // The same header, its receipts reordered and altered.
            (
                "receipts",
                Box::new(|b: &Block| {
                    let mut b = b.clone();
                    let last = b.receipts.len() - 1;
                    b.receipts.swap(0, last);
                    b.receipts[0].push(0);
                    b
                }),
            ),
            // A whole block that verifies on its own but is not the one
            // chained to the anchor.
            ("block", Box::new(|_: &Block| other[&110].clone())),
        ];
        for (what, swap) in swaps {
            let dir = scratch(what);
            let src = Changing {
                chain: chain.clone(),
                at,
                reads: std::cell::Cell::new(0),
                swap,
            };
            match write_history(&dir, &src, 100, anchor, 4) {
                Err(HistoryError::Source(e)) => assert!(e.contains("changed"), "{what}: {e}"),
                Err(e) => panic!("{what}: {e}"),
                Ok(_) => panic!("{what}: a changed block was written"),
            }
            assert_eq!(src.reads.get(), 2, "{what}");
            assert!(!dir.join(HISTORY_LATEST).exists(), "{what}");
            let _ = fs::remove_dir_all(&dir);
        }
        let dir = scratch("unchanged");
        write_history(&dir, &chain, 100, anchor, 4).expect("the unchanged chain writes");
        let _ = fs::remove_dir_all(&dir);
    }

    /// Every file under `dir`, by its path relative to `dir`.
    fn tree(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fn walk(base: &Path, d: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
            for e in fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    walk(base, &p, out);
                } else {
                    let rel = p.strip_prefix(base).unwrap().to_string_lossy().into_owned();
                    out.insert(rel, fs::read(&p).unwrap());
                }
            }
        }
        let mut out = BTreeMap::new();
        walk(dir, dir, &mut out);
        out
    }

    /// A chain over the boundary between periods 1911 and 1912 and through
    /// part of the next, so a span has three periods.
    fn three_periods() -> (BTreeMap<u64, Block>, u64, u64) {
        let ts = MAINNET_GENESIS_TIME + 1912 * 8192 * 12 - 12 * 30;
        let c = synthetic::chain(3, 1_000, 90, ts);
        let mut c2 = c.clone();
        // Push the last 20 blocks a period on, keeping them chained.
        let mut parent = c[&1_069].hash;
        for n in 1_070..1_090 {
            let b = &c[&n];
            let mut it: Vec<Vec<u8>> = list_items(&b.header)
                .unwrap()
                .iter()
                .map(|x| x.to_vec())
                .collect();
            let ts: u64 = item(&it[11], "ts").unwrap();
            it[0] = alloy_rlp::encode(parent);
            it[11] = alloy_rlp::encode(ts + 8192 * 12);
            let header = synthetic_list(&it);
            let hash = keccak256(&header);
            c2.insert(
                n,
                Block {
                    header,
                    hash,
                    ..b.clone()
                },
            );
            parent = hash;
        }
        (c2, 1_000, 1_089)
    }

    fn synthetic_list(items: &[Vec<u8>]) -> Vec<u8> {
        let len = items.iter().map(Vec::len).sum();
        let mut out = Vec::new();
        RlpHeader {
            list: true,
            payload_length: len,
        }
        .encode(&mut out);
        for i in items {
            out.extend_from_slice(i);
        }
        out
    }

    fn par(
        dir: &Path,
        c: &BTreeMap<u64, Block>,
        first: u64,
        last: u64,
        workers: usize,
        chunk: u64,
    ) -> Result<HistoryWritten, HistoryError> {
        let mut seen = Vec::new();
        let mut progress = |p: &HistoryProgress| seen.push(p.phase);
        let mut opts = HistoryOptions {
            workers,
            chunk_blocks: chunk,
            progress_every: Duration::from_millis(1),
            progress: Some(&mut progress),
            ..Default::default()
        };
        let r = write_history_with(dir, c, first, (last, c[&last].hash), 4, &mut opts);
        if r.is_ok() {
            assert!(
                seen.contains(&HistoryPhase::Verify)
                    && seen.contains(&HistoryPhase::Write)
                    && seen.last() == Some(&HistoryPhase::Lookup)
            );
        }
        r
    }

    #[test]
    fn the_parallel_writer_writes_what_the_single_one_does() {
        let (c, first, last) = three_periods();
        let one = scratch("par-one");
        let w = write_history(&one, &c, first, (last, c[&last].hash), 4).unwrap();
        let ps: Vec<_> = w
            .manifest
            .periods
            .iter()
            .map(|p| (p.period, p.first_block, p.last_block))
            .collect();
        assert_eq!(ps.len(), 3, "{ps:?}");
        assert_eq!((ps[1].0, ps[2].0), (1912, 1913));
        let want = tree(&one);
        for (workers, chunk) in [(1, 8192), (2, 1), (3, 7), (8, 13), (16, 64)] {
            let dir = scratch(&format!("par-{workers}-{chunk}"));
            let got = par(&dir, &c, first, last, workers, chunk).unwrap();
            assert_eq!(
                got.manifest, w.manifest,
                "{workers} workers, chunks of {chunk}"
            );
            assert_eq!(got.files, w.files, "{workers} workers, chunks of {chunk}");
            assert!(
                tree(&dir) == want,
                "{workers} workers, chunks of {chunk}: the files differ"
            );
            let _ = fs::remove_dir_all(&dir);
        }
        // Nothing but the files listed: no scratch, no temporary names.
        let mut listed: Vec<&String> = w.files.iter().collect();
        listed.sort();
        assert_eq!(listed, want.keys().collect::<Vec<_>>());
        assert_eq!(
            w.manifest.tx_lookup.len(),
            2,
            "the base and the open period"
        );
        let _ = fs::remove_dir_all(&one);
    }

    #[test]
    fn tx_lookup_pieces_follow_the_binary_digits_of_the_tail() {
        assert_eq!(tx_lookup_plan(0, 0), vec![]);
        assert_eq!(tx_lookup_plan(1, 0), vec![(0, 0)]);
        assert_eq!(tx_lookup_plan(1, 5), vec![(0, 0)]);
        assert_eq!(tx_lookup_plan(5, usize::MAX), vec![(0, 3), (4, 4)]);
        assert_eq!(tx_lookup_plan(10, 3), vec![(0, 2), (3, 6), (7, 8), (9, 9)]);
        assert_eq!(tx_lookup_plan(8, 0), vec![(0, 3), (4, 5), (6, 6), (7, 7)]);
        for n in 1..300 {
            for base in [0, 1, n / 3, n / 2, n] {
                let p = tx_lookup_plan(n, base);
                // Contiguous, covering every period once, the open one alone.
                assert_eq!(p[0].0, 0);
                assert!(
                    p.windows(2)
                        .all(|w| w[1].0 == w[0].1 + 1 && w[0].0 <= w[0].1)
                );
                assert_eq!(*p.last().unwrap(), (n - 1, n - 1));
                // A probe per base, per binary digit, and the open period.
                let tail = (n - 1) - base.min(n - 1);
                let want = usize::from(base.min(n - 1) > 0) + tail.count_ones() as usize + 1;
                assert_eq!(p.len(), want, "{n} periods, base {base}");
            }
        }
    }

    /// Every packed value of `dir`'s runs is in its period's pack, at its
    /// offset, with its hash; every transaction is in one `tx_lookup`
    /// piece, at its place.
    fn check_packs_and_pieces(dir: &Path, w: &HistoryWritten, c: &BTreeMap<u64, Block>) -> u64 {
        let mut packed = 0;
        for p in &w.manifest.periods {
            let pack = p
                .pack
                .map(|k| fs::read(dir.join(history_pack_path(&k.root))).unwrap());
            if let (Some(k), Some(bytes)) = (p.pack, &pack) {
                assert_eq!(bytes.len() as u64, k.bytes);
                assert_eq!(*blake3::hash(bytes).as_bytes(), k.root);
            }
            assert!(p.table(H_TX_LOOKUP).is_none());
            for t in &p.tables {
                let run = fs::read(dir.join(history_run_path(&t.root))).unwrap();
                let rr = csl_run::RunRef {
                    root: t.root,
                    block_lo: 0,
                    block_hi: 0,
                    page_count: t.page_count,
                    entry_count: t.entry_count,
                    epsilon_pages: t.epsilon_pages,
                    model_bytes: t.model_bytes,
                    model_root: t.model_root,
                };
                let mut r = csl_run::Reader::with_format(run, rr, HISTORY_RUN_FORMAT);
                for n in p.first_block..=p.last_block {
                    let b = &c[&n];
                    let vals: Vec<&Vec<u8>> = match t.table_id {
                        H_HEADERS => vec![&b.header],
                        H_TRANSACTIONS => b.txs.iter().collect(),
                        H_RECEIPTS => b.receipts.iter().collect(),
                        _ => continue,
                    };
                    for (i, v) in vals.into_iter().enumerate() {
                        let (e, _) = r.get_entry(&block_key(n, i as u64)).unwrap();
                        let e = e.unwrap();
                        if v.len() > CODE_BLOB_THRESHOLD {
                            let pr = e.packed_ref().expect("a large value is packed");
                            let bytes = pack.as_ref().expect("a pack");
                            assert_eq!(&bytes[pr.off as usize..][..pr.len as usize], &v[..]);
                            assert_eq!(pr.hash, *blake3::hash(v).as_bytes());
                            packed += 1;
                        } else {
                            assert_eq!((e.tag, &e.value), (0, v));
                        }
                    }
                }
            }
        }
        let mut found = 0;
        for l in &w.manifest.tx_lookup {
            let ps = &w.manifest.periods;
            let lo = ps.iter().position(|p| p.period == l.first_period).unwrap();
            let hi = ps.iter().position(|p| p.period == l.last_period).unwrap();
            let Some(t) = &l.table else {
                let n: usize = (ps[lo].first_block..=ps[hi].last_block)
                    .map(|b| c[&b].txs.len())
                    .sum();
                assert_eq!(n, 0, "a piece without a run covers no transactions");
                continue;
            };
            let run = fs::read(dir.join(history_run_path(&t.root))).unwrap();
            let rr = csl_run::RunRef {
                root: t.root,
                block_lo: 0,
                block_hi: 0,
                page_count: t.page_count,
                entry_count: t.entry_count,
                epsilon_pages: t.epsilon_pages,
                model_bytes: t.model_bytes,
                model_root: t.model_root,
            };
            let mut r = csl_run::Reader::with_format(run, rr, HISTORY_RUN_FORMAT);
            let mut n = 0;
            for p in &ps[lo..=hi] {
                for b in p.first_block..=p.last_block {
                    for (i, tx) in c[&b].txs.iter().enumerate() {
                        let (e, _) = r.get_entry(&tx_lookup_key(&tx_hash(tx))).unwrap();
                        assert_eq!(e.unwrap().value, locator(b, i as u64));
                        n += 1;
                    }
                }
            }
            assert_eq!(
                n, t.entry_count,
                "a piece holds its periods' transactions only"
            );
            found += n;
        }
        assert_eq!(found, c.values().map(|b| b.txs.len() as u64).sum::<u64>());
        packed
    }

    #[test]
    fn large_values_go_in_one_pack_per_period_and_tx_lookup_in_pieces() {
        let c = ten_periods();
        let (first, last) = (2_000, 2_089);
        // Base 1912..=1914, then 6 closed periods in 4 and 2, then the open
        // one; no base, 9 closed in 8 and 1.
        for (base, pieces) in [(None, 2), (Some(1912 + 2), 4), (Some(0), 3)] {
            let dir = scratch("packs");
            let mut opts = HistoryOptions {
                workers: 3,
                tx_lookup_base: base,
                ..Default::default()
            };
            let w =
                write_history_with(&dir, &c, first, (last, c[&last].hash), 4, &mut opts).unwrap();
            assert_eq!(w.manifest.periods.len(), 10);
            assert_eq!(w.manifest.tx_lookup.len(), pieces, "base {base:?}");
            assert_eq!(w.lookup_stats.len(), pieces);
            let packed = check_packs_and_pieces(&dir, &w, &c);
            assert!(
                packed > 10,
                "the synthetic chain has large values: {packed}"
            );
            let objects = w.files.len();
            assert_eq!(
                objects,
                w.manifest.run_paths().len() + 2,
                "runs, packs, manifest, latest"
            );
            let _ = fs::remove_dir_all(&dir);
        }
    }

    /// Ten periods (1912..=1921) of nine blocks each, 2_000..=2_089.
    fn ten_periods() -> BTreeMap<u64, Block> {
        let ts = MAINNET_GENESIS_TIME + 1912 * 8192 * 12;
        let mut c = synthetic::chain(5, 2_000, 90, ts);
        let mut parent = c[&2_000].hash;
        for n in 2_001..2_090 {
            let b = c[&n].clone();
            let mut it: Vec<Vec<u8>> = list_items(&b.header)
                .unwrap()
                .iter()
                .map(|x| x.to_vec())
                .collect();
            let t: u64 = item(&it[11], "ts").unwrap();
            it[0] = alloy_rlp::encode(parent);
            it[11] = alloy_rlp::encode(t + (n - 2_000) / 9 * 8192 * 12);
            let header = synthetic_list(&it);
            let hash = keccak256(&header);
            c.insert(n, Block { header, hash, ..b });
            parent = hash;
        }
        c
    }

    #[test]
    fn a_piece_without_transactions_still_covers_its_periods() {
        // (strip, base, pieces, the empty piece): a middle piece (periods
        // 1919..=1920 of (0,2),(3,6),(7,8),(9,9)), and the open period
        // alone, as when the anchor opens a period.
        let cases = [(7..=8, Some(1912 + 2), 4, 2), (9..=9, None, 2, 1)];
        for (i, (strip, base, pieces, empty)) in cases.into_iter().enumerate() {
            let mut c = ten_periods();
            synthetic::strip(&mut c, |n| strip.contains(&((n - 2_000) / 9)));
            let (first, last) = (2_000, 2_089);
            let dir = scratch(&format!("empty-piece-{i}"));
            let mut opts = HistoryOptions {
                workers: 3,
                tx_lookup_base: base,
                ..Default::default()
            };
            let w =
                write_history_with(&dir, &c, first, (last, c[&last].hash), 4, &mut opts).unwrap();
            let m = &w.manifest;
            assert_eq!(m.tx_lookup.len(), pieces, "case {i}");
            for (j, l) in m.tx_lookup.iter().enumerate() {
                assert_eq!(l.table.is_none(), j == empty, "case {i} piece {j}");
            }
            assert_eq!(w.lookup_stats.len(), pieces);
            assert_eq!(
                w.lookup_stats[empty],
                HistoryTableStats {
                    table_id: H_TX_LOOKUP,
                    ..Default::default()
                }
            );
            check_packs_and_pieces(&dir, &w, &c);
            assert_eq!(w.files.len(), m.run_paths().len() + 2);
            // The piece round-trips without a table.
            let json = m.to_json();
            assert_eq!(HistoryManifest::from_json(json.as_bytes()).unwrap(), *m);
            let _ = fs::remove_dir_all(&dir);
        }

        // A span of one empty block: one period, one piece, no run.
        let mut c = synthetic::chain(6, 0, 1, MAINNET_GENESIS_TIME - 12 * 100);
        synthetic::strip(&mut c, |_| true);
        let dir = scratch("empty-span");
        let w = write_history(&dir, &c, 0, (0, c[&0].hash), 4).unwrap();
        assert_eq!(w.manifest.periods.len(), 1);
        assert_eq!(w.manifest.tx_lookup.len(), 1);
        assert_eq!(w.manifest.tx_lookup[0].table, None);
        assert!(!w.manifest.to_json().contains("\"table\""));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn one_transaction_in_two_periods_is_not_written() {
        let (mut c, first, last) = three_periods();
        // Block 1_050 (the second period) repeats a transaction of block
        // 1_010 (the first), both in the base piece; the chain is rebuilt
        // over it.
        let tx = c[&1_010].txs[0].clone();
        let mut parent = c[&1_049].hash;
        for n in 1_050..=last {
            let mut b = c[&n].clone();
            let mut it: Vec<Vec<u8>> = list_items(&b.header)
                .unwrap()
                .iter()
                .map(|x| x.to_vec())
                .collect();
            if n == 1_050 {
                b.txs[0] = tx.clone();
                it[4] = alloy_rlp::encode(ordered_root(&b.txs));
            }
            it[0] = alloy_rlp::encode(parent);
            b.header = synthetic_list(&it);
            b.hash = keccak256(&b.header);
            parent = b.hash;
            c.insert(n, b);
        }
        let dir = scratch("dup-tx");
        match write_history(&dir, &c, first, (last, c[&last].hash), 4) {
            Err(HistoryError::Span(e)) => assert!(e.contains("one hash"), "{e}"),
            r => panic!("{:?}", r.map(|w| w.manifest.block_number)),
        }
        nothing_published(&dir);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn blocks_before_the_beacon_chain_write_in_negative_periods() {
        // 40 blocks, 15 s apart, over the beacon chain's genesis time.
        let c = synthetic::chain(4, 11_000_000, 40, MAINNET_GENESIS_TIME - 12 * 20);
        let (first, last) = (11_000_000, 11_000_039);
        let one = scratch("negative-one");
        let w = write_history(&one, &c, first, (last, c[&last].hash), 4).unwrap();
        let ps: Vec<_> = w
            .manifest
            .periods
            .iter()
            .map(|p| (p.period, p.first_block, p.last_block))
            .collect();
        assert_eq!(ps, vec![(-1, first, first + 19), (0, first + 20, last)]);
        let back = HistoryManifest::from_json(w.manifest.to_json().as_bytes()).unwrap();
        assert_eq!(back, w.manifest);
        let dir = scratch("negative-par");
        par(&dir, &c, first, last, 4, 3).unwrap();
        assert!(tree(&dir) == tree(&one));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&one);
    }

    #[test]
    fn pre_byzantium_receipts_carry_a_state_root_and_write() {
        let c = synthetic::chain_with(
            5,
            4_000_000,
            30,
            MAINNET_GENESIS_TIME - 12 * 8192 * 400,
            true,
        );
        let mut roots = 0;
        for b in c.values() {
            b.verify().unwrap();
            for r in &b.receipts {
                let f = decode_receipt(r).unwrap();
                assert!(f.post_state.is_some() && !f.success && f.tx_type == 0);
                assert_eq!(&encode_receipt(&f), r);
                roots += 1;
            }
        }
        assert!(roots > 100);
        let dir = scratch("pre-byzantium");
        let w = par(&dir, &c, 4_000_000, 4_000_029, 3, 4).unwrap();
        assert_eq!(w.manifest.periods.len(), 1);
        assert!(w.manifest.periods[0].period < 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_receipt_status_is_a_status_or_a_state_root() {
        let mut f = decode_receipt(
            &synthetic::chain(1, 100, 20, MAINNET_GENESIS_TIME)
                .values()
                .find(|b| !b.receipts.is_empty())
                .unwrap()
                .receipts[0],
        )
        .unwrap();
        f.post_state = None;
        for (status, ok) in [
            (vec![], true),
            (vec![1], true),
            (vec![0], false),
            (vec![2], false),
            (vec![7; 31], false),
            (vec![7; 32], true),
            (vec![7; 33], false),
        ] {
            let body = synthetic_list(&[
                alloy_rlp::encode(&status[..]),
                alloy_rlp::encode(f.cumulative_gas_used),
                alloy_rlp::encode(f.bloom),
                synthetic_list(&[]),
            ]);
            assert_eq!(decode_receipt(&body).is_ok(), ok, "status {status:?}");
        }
    }

    /// No manifest, no `history/latest`, no temporary run left behind.
    fn nothing_published(dir: &Path) {
        assert!(!dir.join(HISTORY_LATEST).exists());
        let runs = dir.join("history/runs");
        if runs.exists() {
            for e in fs::read_dir(&runs).unwrap() {
                let name = e.unwrap().file_name().into_string().unwrap();
                assert!(!name.starts_with("tmp-"), "{name} left behind");
            }
        }
        for e in fs::read_dir(dir.join("history")).into_iter().flatten() {
            let p = e.unwrap().path();
            assert!(!p.join("manifest.json").exists(), "{} written", p.display());
        }
    }

    #[test]
    fn a_bad_block_anywhere_stops_every_worker_and_publishes_nothing() {
        let (c, first, last) = three_periods();
        // A body that does not rebuild its root, late in the span.
        let mut bad = c.clone();
        let at = bad
            .range(1_080..)
            .find(|(_, b)| !b.txs.is_empty())
            .map(|(n, _)| *n)
            .unwrap();
        bad.get_mut(&at).unwrap().txs[0].push(0);
        let dir = scratch("par-bad-body");
        match par(&dir, &bad, first, last, 4, 5) {
            Err(HistoryError::Block(BlockError::TransactionsRoot { number })) => {
                assert_eq!(number, at)
            }
            other => panic!("{:?}", other.map(|w| w.manifest.block_number)),
        }
        nothing_published(&dir);
        assert!(!dir.join("history/runs").exists(), "pass 1 wrote something");
        let _ = fs::remove_dir_all(&dir);

        // A block from another chain at a chunk boundary: each chunk
        // verifies alone, the join does not.
        let other = synthetic::chain(
            9,
            1_000,
            90,
            MAINNET_GENESIS_TIME + 1912 * 8192 * 12 - 12 * 30,
        );
        let mut forked = c.clone();
        forked.insert(1_010, other[&1_010].clone());
        let dir = scratch("par-fork");
        match par(&dir, &forked, first, last, 4, 10) {
            Err(HistoryError::Block(BlockError::Chain { number })) => {
                assert!(number == 1_009 || number == 1_010, "{number}")
            }
            other => panic!("{:?}", other.map(|w| w.manifest.block_number)),
        }
        nothing_published(&dir);
        let _ = fs::remove_dir_all(&dir);

        // An anchor the chain does not end at.
        let dir = scratch("par-anchor");
        let mut opts = HistoryOptions {
            workers: 4,
            chunk_blocks: 9,
            ..Default::default()
        };
        match write_history_with(&dir, &c, first, (last, B256::repeat_byte(1)), 4, &mut opts) {
            Err(HistoryError::Span(e)) => assert!(e.contains("anchor"), "{e}"),
            other => panic!("{:?}", other.map(|w| w.manifest.block_number)),
        }
        nothing_published(&dir);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Serves `chain`, but a block from another chain in place of `at` once
    /// it has been read `after` times: a source changing under the writer.
    struct Shifting {
        chain: BTreeMap<u64, Block>,
        other: BTreeMap<u64, Block>,
        at: u64,
        after: u32,
        reads: Mutex<u32>,
    }

    impl BlockSource for Shifting {
        fn block(&self, n: u64) -> Result<Block, String> {
            if n == self.at {
                let mut r = self.reads.lock().unwrap();
                *r += 1;
                if *r > self.after {
                    return self.other.block(n);
                }
            }
            self.chain.block(n)
        }
    }

    #[test]
    fn a_block_that_changes_while_periods_are_written_publishes_nothing() {
        let (c, first, last) = three_periods();
        let other = synthetic::chain(
            9,
            1_000,
            90,
            MAINNET_GENESIS_TIME + 1912 * 8192 * 12 - 12 * 30,
        );
        let src = Shifting {
            chain: c.clone(),
            other,
            at: 1_085,
            after: 1,
            reads: Mutex::new(0),
        };
        let dir = scratch("par-shift");
        let mut opts = HistoryOptions {
            workers: 3,
            chunk_blocks: 4,
            ..Default::default()
        };
        match write_history_with(&dir, &src, first, (last, c[&last].hash), 4, &mut opts) {
            Err(HistoryError::Source(e)) => assert!(e.contains("changed"), "{e}"),
            other => panic!("{:?}", other.map(|w| w.manifest.block_number)),
        }
        nothing_published(&dir);
        let _ = fs::remove_dir_all(&dir);
    }

    struct Panicking(BTreeMap<u64, Block>);

    impl BlockSource for Panicking {
        fn block(&self, n: u64) -> Result<Block, String> {
            assert!(n != 1_050, "a source that panics");
            self.0.block(n)
        }
    }

    #[test]
    #[should_panic(expected = "a scoped thread panicked")]
    fn a_worker_that_panics_is_not_a_hang() {
        let (c, first, last) = three_periods();
        let hash = c[&last].hash;
        let dir = scratch("par-panic");
        let mut opts = HistoryOptions {
            workers: 4,
            chunk_blocks: 3,
            ..Default::default()
        };
        let _ = write_history_with(&dir, &Panicking(c), first, (last, hash), 4, &mut opts);
    }

    #[test]
    fn a_synthetic_chain_verifies_and_round_trips_its_receipts() {
        let c = synthetic::chain(1, 100, 20, MAINNET_GENESIS_TIME + 12 * 8192 * 5);
        let mut prev: Option<HeaderFields> = None;
        for b in c.values() {
            let h = b.verify().expect("synthetic block verifies");
            if let Some(p) = &prev {
                assert_eq!(h.parent_hash, p.hash);
            }
            for r in &b.receipts {
                assert_eq!(&encode_receipt(&decode_receipt(r).unwrap()), r);
            }
            prev = Some(h);
        }
    }

    #[test]
    fn blocks_before_the_beacon_chain_fall_in_negative_periods() {
        let span = SECONDS_PER_SLOT * SLOTS_PER_PERIOD;
        assert_eq!(period_of_timestamp(MAINNET_GENESIS_TIME - 1), -1);
        assert_eq!(period_of_timestamp(MAINNET_GENESIS_TIME - span), -1);
        assert_eq!(period_of_timestamp(MAINNET_GENESIS_TIME - span - 1), -2);
        // Mainnet's genesis block (2015-07-30 15:26:13 UTC) is 1,715
        // periods back.
        assert_eq!(period_of_timestamp(1_438_269_973), -1715);
        assert_eq!(period_of_timestamp(0), -16346);
    }

    #[test]
    fn periods_follow_the_beacon_clock() {
        // Slot 15,662,336 (the demo's head on 2026-11-15) is in period 1911.
        assert_eq!(
            period_of_timestamp(MAINNET_GENESIS_TIME + 15_662_336 * 12),
            1911
        );
        assert_eq!(
            period_of_timestamp(MAINNET_GENESIS_TIME + 1912 * 8192 * 12 - 1),
            1911
        );
        assert_eq!(
            period_of_timestamp(MAINNET_GENESIS_TIME + 1912 * 8192 * 12),
            1912
        );
    }
}
