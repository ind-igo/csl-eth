//! The history fault table (Milestone H): each named lie written into a
//! bucket by a hostile producer, from verified blocks, and read through.
//! Every read must end `Insufficient` or correct; the one fault a client
//! cannot see in the indexed tier (`log_lookup` omitting a block) must
//! come back short there, every returned log verified, and whole in the
//! complete tier.
//!
//! Unlike the state fault table, which lies on the wire ([`crate::faults`]),
//! these lies are written into the files: the history client trusts no
//! file, so a consistent hostile bucket (runs whose pages, fences and
//! models all agree with the lie) is the stronger test, and the only way to
//! express a hint that routes wrongly or omits.

use crate::history::BlockCache;
use alloy_primitives::B256;
use csl_eth_client::DirDriver;
use csl_eth_history::{Anchor, History, LogAt, LogTier, Term};
use csl_eth_store::{
    history::{
        decode_header, decode_receipt, encode_receipt, locator, log_lookup_key, tx_hash,
        tx_lookup_key, write_history_tampered, Block, BlockSource, Tamper, H_TRANSACTIONS,
    },
    CODE_BLOB_THRESHOLD,
};
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    ReceiptAltered,
    LogDropped,
    ReceiptsReordered,
    ReceiptsFromAnotherBlock,
    HeaderOutOfChain,
    TxLookupWrongPlace,
    LogLookupOmitsBlock,
    PackedOffsetWrong,
}

pub const FAULTS: [Fault; 8] = [
    Fault::ReceiptAltered,
    Fault::LogDropped,
    Fault::ReceiptsReordered,
    Fault::ReceiptsFromAnotherBlock,
    Fault::HeaderOutOfChain,
    Fault::TxLookupWrongPlace,
    Fault::LogLookupOmitsBlock,
    Fault::PackedOffsetWrong,
];

impl Fault {
    pub fn name(self) -> &'static str {
        match self {
            Fault::ReceiptAltered => "receipt_altered",
            Fault::LogDropped => "log_dropped",
            Fault::ReceiptsReordered => "receipts_reordered",
            Fault::ReceiptsFromAnotherBlock => "receipts_from_another_block",
            Fault::HeaderOutOfChain => "header_out_of_chain",
            Fault::TxLookupWrongPlace => "tx_lookup_wrong_place",
            Fault::LogLookupOmitsBlock => "log_lookup_omits_block",
            Fault::PackedOffsetWrong => "packed_offset_wrong",
        }
    }

    /// May the indexed tier come back short under this fault? Only when
    /// the hint omits: by the fault itself, or because the hostile
    /// producer derived its hint from the receipts it altered (a dropped
    /// log; another block's receipts, which need not carry the term; a
    /// flipped byte, which may land in an address or topic). Whether it
    /// does depends on the target block, so these may also end every read
    /// `Insufficient`.
    fn may_shorten(self) -> bool {
        matches!(
            self,
            Fault::LogLookupOmitsBlock
                | Fault::LogDropped
                | Fault::ReceiptsFromAnotherBlock
                | Fault::ReceiptAltered
        )
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Row {
    pub fault: &'static str,
    pub reads: u64,
    pub correct: u64,
    pub insufficient: u64,
    /// Indexed-tier answers missing logs, every returned log verified.
    pub short_indexed: u64,
    /// Answers that are wrong: must be 0.
    pub wrong: u64,
    /// Some read saw the fault (`Insufficient` or short).
    pub fired: bool,
    /// The distinct reasons reads ended `Insufficient` (the first few).
    pub insufficient_reasons: Vec<String>,
    pub pass: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub first_block: u64,
    pub anchor: u64,
    pub target_block: u64,
    pub term: String,
    pub rows: Vec<Row>,
    pub pass: bool,
}

fn truth(src: &dyn BlockSource, term: &Term, from: u64, to: u64) -> Result<Vec<LogAt>, String> {
    let mut out = Vec::new();
    for n in from..=to {
        let b = src.block(n)?;
        let mut li = 0;
        for (i, r) in b.receipts.iter().enumerate() {
            for l in decode_receipt(r).map_err(String::from)?.logs {
                if term.matches(&l) {
                    out.push(LogAt {
                        block_number: n,
                        tx_index: i as u64,
                        log_index: li,
                        block_hash: b.hash,
                        log: l,
                    });
                }
                li += 1;
            }
        }
    }
    Ok(out)
}

/// A block with two or more transactions whose first receipt has a log,
/// in the upper half of the span (so the header walk to it is real), with
/// a neighbour on each side; one with a transaction above the inline size
/// among the first 24 (the reads') if there is one, so that a lie about a
/// packed value is read.
fn target(src: &dyn BlockSource, first: u64, last: u64) -> Result<(u64, Term), String> {
    let mut fallback = None;
    for n in (first + (last - first) / 2).max(first + 3)..last.saturating_sub(3) {
        let b = src.block(n)?;
        if b.txs.len() < 2 {
            continue;
        }
        if let Some(l) = decode_receipt(&b.receipts[0])
            .map_err(String::from)?
            .logs
            .first()
        {
            let t = (n, Term::Address(l.address));
            if b.txs.iter().take(24).any(|t| t.len() > CODE_BLOB_THRESHOLD) {
                return Ok(t);
            }
            fallback.get_or_insert(t);
        }
    }
    fallback.ok_or_else(|| {
        "no block in the span has two transactions and a log in its first receipt".into()
    })
}

#[allow(clippy::too_many_arguments)]
fn write_hostile(
    src: &dyn BlockSource,
    dir: &Path,
    first: u64,
    anchor: (u64, B256),
    epsilon: u16,
    fault: Fault,
    t: u64,
    term: &Term,
) -> Result<(), String> {
    let other = src.block(t + 1)?.receipts;
    let tb = src.block(t)?;
    let term = *term;
    let block = move |b: &mut Block| {
        if b.number != t {
            return;
        }
        match fault {
            Fault::ReceiptAltered => {
                let r = &mut b.receipts[1];
                let mid = r.len() / 2;
                r[mid] ^= 0x01;
            }
            Fault::LogDropped => {
                let Ok(mut r) = decode_receipt(&b.receipts[0]) else {
                    return;
                };
                if let Some(i) = r.logs.iter().position(|l| term.matches(l)) {
                    r.logs.remove(i);
                }
                b.receipts[0] = encode_receipt(&r);
            }
            Fault::ReceiptsReordered => b.receipts.swap(0, 1),
            Fault::ReceiptsFromAnotherBlock => b.receipts = other.clone(),
            Fault::HeaderOutOfChain => {
                // One byte of the last field (the newest fork's), so the
                // header still decodes and hashes elsewhere.
                let n = b.header.len();
                b.header[n - 1] ^= 0x01;
            }
            _ => {}
        }
    };
    let moved = tx_lookup_key(&tx_hash(&tb.txs[0]));
    let tx_lookup = move |rows: &mut Vec<([u8; 32], [u8; 8])>| {
        if fault == Fault::TxLookupWrongPlace {
            for r in rows.iter_mut().filter(|r| r.0 == moved) {
                r.1 = locator(t, 1);
            }
        }
    };
    let omitted = log_lookup_key(&term.hash(), t);
    let log_lookup = move |rows: &mut Vec<[u8; 32]>| {
        if fault == Fault::LogLookupOmitsBlock {
            rows.retain(|k| *k != omitted);
        }
    };
    // The target's packed transactions point one byte early: the wrong
    // bytes, under the entry's hash.
    let packed = move |table: u16, key: &[u8; 32], r: &mut csl_run::PackedRef| {
        if fault == Fault::PackedOffsetWrong
            && table == H_TRANSACTIONS
            && key[..5] == t.to_be_bytes()[3..]
        {
            r.off = r.off.checked_sub(1).unwrap_or(1);
        }
    };
    let tamper = Tamper {
        block: &block,
        tx_lookup: &tx_lookup,
        log_lookup: &log_lookup,
        packed: &packed,
    };
    let _ = std::fs::remove_dir_all(dir);
    write_history_tampered(dir, src, first, anchor, epsilon, &tamper).map_err(|e| e.to_string())?;
    Ok(())
}

/// The table over `blocks` blocks of the cache ending at `anchor`, the
/// hostile buckets written under `dir`.
pub fn run(
    work: &Path,
    dir: &Path,
    anchor: (u64, B256),
    blocks: u64,
    epsilon: u16,
) -> Result<Report, String> {
    let src = BlockCache(work.to_path_buf());
    let (last, hash) = anchor;
    let first = last + 1 - blocks.clamp(8, last + 1);
    let (t, term) = target(&src, first, last)?;
    let a = Anchor { number: last, hash };
    let topic = decode_receipt(&src.block(t)?.receipts[0])
        .map_err(String::from)?
        .logs[0]
        .topics
        .first()
        .map(|x| Term::Topic(*x));
    let terms: Vec<Term> = std::iter::once(term).chain(topic).collect();
    let mut rows = Vec::new();
    for fault in FAULTS {
        let fdir = dir.join(fault.name());
        write_hostile(&src, &fdir, first, anchor, epsilon, fault, t, &term)?;
        let mut h = History::open(DirDriver::new(&fdir), a)
            .map_err(|e| format!("{}: {e}", fault.name()))?;
        let mut row = Row {
            fault: fault.name(),
            ..Default::default()
        };
        let note = |row: &mut Row, e: String| {
            row.insufficient += 1;
            if !row.insufficient_reasons.contains(&e) && row.insufficient_reasons.len() < 6 {
                row.insufficient_reasons.push(e);
            }
        };
        for n in [t - 1, t, t + 1] {
            let b = src.block(n)?;
            for (i, tx) in b.txs.iter().enumerate().take(24) {
                row.reads += 1;
                h.forget_headers();
                match h.tx(&tx_hash(tx)).0 {
                    Ok(r)
                        if (r.block_number, r.index) == (n, i as u64)
                            && &r.tx == tx
                            && r.receipt_leaf == b.receipts[i] =>
                    {
                        row.correct += 1
                    }
                    Ok(_) => row.wrong += 1,
                    Err(e) => note(&mut row, e.to_string()),
                }
            }
        }
        for n in [t + 1, t, t - 1] {
            row.reads += 1;
            h.forget_headers();
            let want = decode_header(&src.block(n)?.header).map_err(String::from)?;
            match h.header(n).0 {
                Ok(x) if x == want => row.correct += 1,
                Ok(_) => row.wrong += 1,
                Err(e) => note(&mut row, e.to_string()),
            }
        }
        for term in &terms {
            let want = truth(&src, term, t - 3, t + 3)?;
            for tier in [LogTier::Indexed, LogTier::Complete] {
                row.reads += 1;
                h.forget_headers();
                match h.logs(term, t - 3, t + 3, tier).0 {
                    Ok(r) if r.logs == want => row.correct += 1,
                    Ok(r)
                        if tier == LogTier::Indexed
                            && fault.may_shorten()
                            && r.logs.iter().all(|l| want.contains(l)) =>
                    {
                        row.short_indexed += 1
                    }
                    Ok(_) => row.wrong += 1,
                    Err(e) => note(&mut row, e.to_string()),
                }
            }
        }
        row.fired = row.insufficient + row.short_indexed > 0;
        row.pass = row.wrong == 0
            && row.fired
            && match fault {
                Fault::LogLookupOmitsBlock => row.short_indexed > 0 && row.insufficient == 0,
                _ => true,
            };
        rows.push(row);
    }
    let pass = rows.iter().all(|r| r.pass);
    Ok(Report {
        first_block: first,
        anchor: last,
        target_block: t,
        term: term.to_string(),
        rows,
        pass,
    })
}
