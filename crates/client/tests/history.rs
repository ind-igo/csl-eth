//! History reads over a synthetic chain written by the producer's writer:
//! every answer checked against the chain itself, and the spec's history
//! fault list (Milestone H) written as hostile buckets, each of which must
//! end every read `Insufficient` or correct.

use alloy_primitives::{Address, B256};
use csl_eth_client::{
    history::{Anchor, History, HistoryCost, Insufficient, LogAt, LogTier, Logs, Term},
    DirDriver,
};
use csl_eth_store::{
    history::{
        decode_header, decode_receipt, encode_receipt, locator, synthetic, tx_hash, tx_lookup_key,
        write_history, write_history_tampered, Block, Tamper, MAINNET_GENESIS_TIME,
        SECONDS_PER_SLOT, SLOTS_PER_PERIOD,
    },
    EPSILON,
};
use std::{collections::BTreeMap, path::PathBuf};

const FIRST: u64 = 20_000;
const COUNT: u64 = 96;
const LAST: u64 = FIRST + COUNT - 1;
/// Block `FIRST + 40` opens period 1912.
const BOUNDARY: u64 = FIRST + 40;

fn chain() -> BTreeMap<u64, Block> {
    let t = MAINNET_GENESIS_TIME + 1912 * SLOTS_PER_PERIOD * SECONDS_PER_SLOT - 40 * 12;
    synthetic::chain(7, FIRST, COUNT, t)
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("csl-eth-history-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn anchor(c: &BTreeMap<u64, Block>) -> Anchor {
    Anchor {
        number: LAST,
        hash: c[&LAST].hash,
    }
}

fn open(dir: &PathBuf, c: &BTreeMap<u64, Block>) -> History<DirDriver> {
    History::open(DirDriver::new(dir), anchor(c)).expect("history opens")
}

fn truth(c: &BTreeMap<u64, Block>, term: &Term, from: u64, to: u64) -> Vec<LogAt> {
    let mut out = Vec::new();
    for n in from..=to {
        let b = &c[&n];
        let mut li = 0;
        for (i, r) in b.receipts.iter().enumerate() {
            for l in decode_receipt(r).unwrap().logs {
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
    out
}

fn busy() -> Term {
    Term::Address(synthetic::busy_address())
}

#[test]
fn the_span_spans_two_periods() {
    let c = chain();
    let dir = scratch("periods");
    let w = write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let ps: Vec<_> = w
        .manifest
        .periods
        .iter()
        .map(|p| (p.period, p.first_block, p.last_block))
        .collect();
    assert_eq!(
        ps,
        vec![(1911, FIRST, BOUNDARY - 1), (1912, BOUNDARY, LAST)]
    );
    assert_eq!(w.files.last().map(String::as_str), Some("history/latest"));
    assert!(
        w.files.iter().any(|f| f.starts_with("blobs/")),
        "the chain has blob-sized leaves"
    );
}

#[test]
fn every_transaction_and_receipt_reads_back_verified() {
    let c = chain();
    let dir = scratch("tx");
    write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let mut h = open(&dir, &c);
    let mut worst = HistoryCost::default();
    let mut blobs = 0;
    for b in c.values().step_by(3) {
        for (i, t) in b.txs.iter().enumerate().step_by(5) {
            h.forget_headers();
            let (r, cost) = h.tx(&tx_hash(t));
            let r = r.unwrap_or_else(|e| panic!("block {} tx {i}: {e}", b.number));
            assert_eq!(
                (r.block_number, r.index, r.block_hash),
                (b.number, i as u64, b.hash)
            );
            assert_eq!(&r.tx, t);
            assert_eq!(&r.receipt_leaf, &b.receipts[i]);
            if t.len() > 3968 || b.receipts[i].len() > 3968 {
                blobs += 1;
            }
            worst.rounds = worst.rounds.max(cost.rounds);
            worst.requests = worst.requests.max(cost.requests);
        }
    }
    assert!(blobs > 0, "some reads resolve blobs");
    // The hint and the block, each a round or two (two when the model's
    // page is off and the `ε` window follows), then the blobs.
    assert!(worst.rounds <= 5, "worst read took {} rounds", worst.rounds);

    let (r, _) = h.tx(&B256::repeat_byte(0x42));
    assert_eq!(r.unwrap_err(), Insufficient::NotIndexed);
}

#[test]
fn old_headers_come_by_the_parent_hash_route() {
    let c = chain();
    let dir = scratch("headers");
    write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let mut h = open(&dir, &c);
    h.keep_headers = false;
    for n in [LAST, BOUNDARY, BOUNDARY - 1, FIRST] {
        let (r, cost) = h.header(n);
        assert_eq!(r.unwrap(), decode_header(&c[&n].header).unwrap());
        assert_eq!(cost.headers_verified, LAST - n + 1);
    }
    assert_eq!(
        h.header(FIRST - 1).0.unwrap_err(),
        Insufficient::OutOfSpan { block: FIRST - 1 }
    );
}

#[test]
fn both_log_tiers_find_every_log() {
    let c = chain();
    let dir = scratch("logs");
    write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let mut h = open(&dir, &c);
    let terms = [
        busy(),
        Term::Address(synthetic::rare_address()),
        Term::Address(synthetic::pool_address(3)),
        Term::Topic(synthetic::pool_topic(0)),
        Term::Topic(synthetic::pool_topic(7)),
        Term::Address(Address::repeat_byte(0x01)),
    ];
    for term in &terms {
        for (from, to) in [
            (FIRST, LAST),
            (BOUNDARY - 5, BOUNDARY + 5),
            (LAST - 3, LAST),
        ] {
            let want = truth(&c, term, from, to);
            for tier in [LogTier::Indexed, LogTier::Complete] {
                let (r, _) = h.logs(term, from, to, tier);
                let r: Logs =
                    r.unwrap_or_else(|e| panic!("{term} {from}..={to} {}: {e}", tier.name()));
                assert_eq!(r.logs, want, "{term} {from}..={to} {}", tier.name());
                if tier == LogTier::Indexed {
                    assert_eq!(
                        r.blocks_without_match, 0,
                        "the honest hint names only blocks with a log"
                    );
                }
            }
        }
    }
}

#[test]
fn a_manifest_for_another_block_is_refused() {
    let c = chain();
    let dir = scratch("anchor");
    write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let e = History::open(
        DirDriver::new(&dir),
        Anchor {
            number: LAST,
            hash: c[&(LAST - 1)].hash,
        },
    )
    .err()
    .unwrap();
    assert!(e.contains("no history at block"), "{e}");
    // The bucket's span ends below the anchor: the anchor is not reached.
    let short = scratch("anchor-short");
    write_history(&short, &c, FIRST, (LAST - 1, c[&(LAST - 1)].hash), EPSILON).unwrap();
    let e = History::open(
        DirDriver::new(&short),
        Anchor {
            number: LAST,
            hash: c[&LAST].hash,
        },
    )
    .err()
    .unwrap();
    assert!(e.contains("no history at block"), "{e}");
}

/// The fault list. Each writes a hostile bucket from the honest chain and
/// reads through it.
#[derive(Clone, Copy, Debug)]
enum Fault {
    ReceiptAltered,
    LogDropped,
    ReceiptsReordered,
    ReceiptsFromAnotherBlock,
    HeaderOutOfChain,
    TxLookupWrongPlace,
    LogLookupOmitsBlock,
}

const FAULTS: [Fault; 7] = [
    Fault::ReceiptAltered,
    Fault::LogDropped,
    Fault::ReceiptsReordered,
    Fault::ReceiptsFromAnotherBlock,
    Fault::HeaderOutOfChain,
    Fault::TxLookupWrongPlace,
    Fault::LogLookupOmitsBlock,
];

/// A block with a busy log in its first receipt and at least two
/// transactions, near the middle of the span.
fn target(c: &BTreeMap<u64, Block>) -> u64 {
    (FIRST + 50..LAST)
        .find(|n| {
            let b = &c[n];
            b.txs.len() >= 2
                && decode_receipt(&b.receipts[0])
                    .unwrap()
                    .logs
                    .iter()
                    .any(|l| busy().matches(l))
        })
        .expect("a target block")
}

fn hostile(c: &BTreeMap<u64, Block>, fault: Fault) -> PathBuf {
    let dir = scratch(&format!("fault-{fault:?}"));
    let t = target(c);
    let other = c[&(t + 1)].receipts.clone();
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
                let mut r = decode_receipt(&b.receipts[0]).unwrap();
                let i = r.logs.iter().position(|l| busy().matches(l)).unwrap();
                r.logs.remove(i);
                b.receipts[0] = encode_receipt(&r);
            }
            Fault::ReceiptsReordered => b.receipts.swap(0, 1),
            Fault::ReceiptsFromAnotherBlock => b.receipts = other.clone(),
            Fault::HeaderOutOfChain => {
                let i = b.header.windows(9).position(|w| w == b"synthetic").unwrap();
                b.header[i] = b'S';
            }
            _ => {}
        }
    };
    let moved = tx_lookup_key(&tx_hash(&c[&t].txs[0]));
    let tx_lookup = move |rows: &mut Vec<([u8; 32], [u8; 8])>| {
        if let Fault::TxLookupWrongPlace = fault {
            for r in rows.iter_mut() {
                if r.0 == moved {
                    r.1 = locator(t, 1);
                }
            }
        }
    };
    let omitted = csl_eth_store::history::log_lookup_key(&busy().hash(), t);
    let log_lookup = move |rows: &mut Vec<[u8; 32]>| {
        if let Fault::LogLookupOmitsBlock = fault {
            rows.retain(|k| *k != omitted);
        }
    };
    let tamper = Tamper {
        block: &block,
        tx_lookup: &tx_lookup,
        log_lookup: &log_lookup,
    };
    write_history_tampered(&dir, c, FIRST, (LAST, c[&LAST].hash), EPSILON, &tamper).unwrap();
    dir
}

#[test]
fn every_fault_ends_insufficient_or_correct() {
    let c = chain();
    let t = target(&c);
    let a = anchor(&c);
    for fault in FAULTS {
        let dir = hostile(&c, fault);
        let Ok(mut h) = History::open(DirDriver::new(&dir), a) else {
            panic!("{fault:?}: the hostile bucket does not open");
        };
        let mut insufficient = 0;
        let mut short = 0;

        // Every transaction of the target block and its neighbours.
        for n in [t - 1, t, t + 1] {
            for (i, tx) in c[&n].txs.iter().enumerate() {
                h.forget_headers();
                match h.tx(&tx_hash(tx)).0 {
                    Ok(r) => {
                        assert_eq!((r.block_number, r.index), (n, i as u64), "{fault:?}");
                        assert_eq!(&r.tx, tx, "{fault:?}");
                        assert_eq!(&r.receipt_leaf, &c[&n].receipts[i], "{fault:?}");
                    }
                    Err(_) => insufficient += 1,
                }
            }
        }
        // Headers on both sides of the target.
        for n in [t + 1, t, t - 1] {
            h.forget_headers();
            match h.header(n).0 {
                Ok(hf) => assert_eq!(hf, decode_header(&c[&n].header).unwrap(), "{fault:?}"),
                Err(_) => insufficient += 1,
            }
        }
        // Logs over the target, in both tiers.
        for term in [busy(), Term::Topic(synthetic::pool_topic(0))] {
            let want = truth(&c, &term, t - 3, t + 3);
            for tier in [LogTier::Indexed, LogTier::Complete] {
                h.forget_headers();
                match h.logs(&term, t - 3, t + 3, tier).0 {
                    Ok(r) if r.logs == want => {}
                    Ok(r) => {
                        // Only the indexed tier may come back short, and
                        // only by what the hint omitted: every log it does
                        // return is in a verified receipt.
                        assert_eq!(
                            tier,
                            LogTier::Indexed,
                            "{fault:?}: the complete tier is wrong"
                        );
                        assert!(
                            r.logs.iter().all(|l| want.contains(l)),
                            "{fault:?}: a log that is not in the chain"
                        );
                        assert!(r.logs.iter().all(|l| l.block_number != t), "{fault:?}");
                        short += 1;
                    }
                    Err(_) => insufficient += 1,
                }
            }
        }
        // Each fault must fire on something.
        match fault {
            Fault::LogLookupOmitsBlock => {
                assert_eq!(insufficient, 0, "{fault:?}");
                assert!(
                    short > 0,
                    "{fault:?}: the omission went unseen by the indexed tier"
                );
            }
            // The hostile producer derived its hint from the receipts it
            // altered, so the hint omits the block too: the indexed tier
            // misses the log (unproven, as for an omitted row) and the
            // complete tier, which fetches every bloom match, refuses.
            Fault::LogDropped => assert!(insufficient > 0, "{fault:?}: no read noticed"),
            _ => {
                assert_eq!(short, 0, "{fault:?}");
                assert!(insufficient > 0, "{fault:?}: no read noticed");
            }
        }
    }
}
