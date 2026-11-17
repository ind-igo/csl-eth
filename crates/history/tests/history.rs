//! History reads over a synthetic chain written by the producer's writer:
//! every answer checked against the chain itself, and the spec's history
//! fault list (Milestone H) written as hostile buckets, each of which must
//! end every read `Insufficient` or correct.

use alloy_primitives::{Address, B256};
use csl_eth_client::DirDriver;
use csl_eth_history::{Anchor, History, HistoryCost, Insufficient, LogAt, LogTier, Logs, Term};
use csl_eth_store::{
    history::{
        decode_header, decode_receipt, encode_receipt, history_manifest_path, locator, synthetic,
        tx_hash, tx_lookup_key, write_history, write_history_tampered, Block, HistoryManifest,
        Tamper, H_TRANSACTIONS, MAINNET_GENESIS_TIME, SECONDS_PER_SLOT, SLOTS_PER_PERIOD,
    },
    CODE_BLOB_THRESHOLD, EPSILON,
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
        w.manifest.periods.iter().all(|p| p.pack.is_some()),
        "the chain has values above the inline size, packed by period"
    );
    assert!(!w.files.iter().any(|f| f.starts_with("blobs/")));
    // Runs for four tables and a pack per period, two tx_lookup pieces,
    // the manifest and the pointer.
    assert_eq!(w.manifest.tx_lookup.len(), 2);
    assert_eq!(w.files.len(), 2 * 5 + 2 + 2);
}

#[test]
fn opening_is_one_request() {
    let c = chain();
    let dir = scratch("open");
    write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let h = open(&dir, &c);
    let cost = h.cost();
    assert_eq!((cost.requests, cost.rounds), (1, 1), "the manifest only");
}

#[test]
fn every_transaction_and_receipt_reads_back_verified() {
    let c = chain();
    let dir = scratch("tx");
    write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let mut h = open(&dir, &c);
    let mut worst = HistoryCost::default();
    let mut packed = 0;
    let mut first = true;
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
            let large = b
                .txs
                .iter()
                .chain(&b.receipts)
                .filter(|v| v.len() > CODE_BLOB_THRESHOLD)
                .count();
            if large > 0 {
                packed += 1;
                // A block's packed values are one range.
                assert!(cost.table_bytes.contains_key("packs"));
            }
            if first {
                // The first read loads the models it touches: the pieces',
                // then the period's, a round each.
                assert!(cost.rounds <= 7, "first read took {} rounds", cost.rounds);
                first = false;
            } else {
                worst.rounds = worst.rounds.max(cost.rounds);
                worst.requests = worst.requests.max(cost.requests);
            }
        }
    }
    assert!(packed > 0, "some reads resolve packed values");
    // The hint and the block, each a round or two (two when the model's
    // page is off and the `ε` window follows; one more the first time a
    // read reaches a period, for its models), then the packed values.
    assert!(worst.rounds <= 6, "worst read took {} rounds", worst.rounds);

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

/// Every transaction of `blocks` of `c` reads back verified.
fn txs_read(
    h: &mut History<DirDriver>,
    c: &BTreeMap<u64, Block>,
    blocks: impl Iterator<Item = u64>,
) -> u64 {
    let mut n = 0;
    for b in blocks {
        for (i, t) in c[&b].txs.iter().enumerate() {
            let r = h
                .tx(&tx_hash(t))
                .0
                .unwrap_or_else(|e| panic!("block {b} tx {i}: {e}"));
            assert_eq!((r.block_number, r.index, &r.tx), (b, i as u64, t));
            n += 1;
        }
    }
    n
}

#[test]
fn a_span_whose_open_period_is_empty_opens_and_reads() {
    let honest = chain();
    // The open period with no transactions: a tx_lookup piece without a
    // run. Then the anchor alone in its period, empty, as when a span
    // ends on the first block of a new period.
    for (i, last) in [LAST, BOUNDARY].into_iter().enumerate() {
        let mut c = honest.clone();
        synthetic::strip(&mut c, |n| n >= BOUNDARY);
        let dir = scratch(&format!("empty-open-{i}"));
        let w = write_history(&dir, &c, FIRST, (last, c[&last].hash), EPSILON).unwrap();
        let pieces: Vec<_> = w
            .manifest
            .tx_lookup
            .iter()
            .map(|l| l.table.is_some())
            .collect();
        assert_eq!(pieces, vec![true, false]);
        let a = Anchor {
            number: last,
            hash: c[&last].hash,
        };
        let mut h = History::open(DirDriver::new(&dir), a).expect("an empty piece opens");
        assert_eq!(
            h.header(FIRST).0.unwrap(),
            decode_header(&c[&FIRST].header).unwrap()
        );
        assert!(txs_read(&mut h, &c, FIRST..BOUNDARY) > 0);
        // A transaction the stripped period no longer has is not indexed.
        let gone = honest
            .range(BOUNDARY..)
            .find_map(|(_, b)| b.txs.first())
            .unwrap();
        assert_eq!(
            h.tx(&tx_hash(gone)).0.unwrap_err(),
            Insufficient::NotIndexed
        );
        for tier in [LogTier::Indexed, LogTier::Complete] {
            let r = h.logs(&busy(), FIRST, last, tier).0.unwrap();
            assert_eq!(r.logs, truth(&c, &busy(), FIRST, last), "{}", tier.name());
        }
    }
}

#[test]
fn a_manifest_that_drops_a_piece_never_reads_wrong() {
    // A hostile manifest names no run for a piece that has transactions:
    // its transactions are not indexed, never misplaced, and the other
    // piece reads as before.
    let c = chain();
    let a = anchor(&c);
    for drop in [0usize, 1] {
        let dir = scratch(&format!("drop-piece-{drop}"));
        write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
        let path = dir.join(history_manifest_path(&c[&LAST].hash));
        let mut m = HistoryManifest::from_json(&std::fs::read(&path).unwrap()).unwrap();
        assert!(m.tx_lookup[drop].table.is_some());
        m.tx_lookup[drop].table = None;
        std::fs::write(&path, m.to_json()).unwrap();
        let mut h = History::open(DirDriver::new(&dir), a).expect("the bucket opens");
        let (dropped, kept) = if drop == 0 {
            (FIRST..BOUNDARY, BOUNDARY..LAST + 1)
        } else {
            (BOUNDARY..LAST + 1, FIRST..BOUNDARY)
        };
        let mut missing = 0;
        for b in dropped {
            for t in &c[&b].txs {
                assert_eq!(h.tx(&tx_hash(t)).0.unwrap_err(), Insufficient::NotIndexed);
                missing += 1;
            }
        }
        assert!(missing > 0);
        assert!(txs_read(&mut h, &c, kept) > 0);
    }
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
    PackedOffsetWrong,
}

const FAULTS: [Fault; 8] = [
    Fault::ReceiptAltered,
    Fault::LogDropped,
    Fault::ReceiptsReordered,
    Fault::ReceiptsFromAnotherBlock,
    Fault::HeaderOutOfChain,
    Fault::TxLookupWrongPlace,
    Fault::LogLookupOmitsBlock,
    Fault::PackedOffsetWrong,
];

/// A block with a transaction above the inline size, near the middle of
/// the span.
fn packed_target(c: &BTreeMap<u64, Block>) -> u64 {
    (FIRST + 50..LAST)
        .find(|n| c[n].txs.iter().any(|t| t.len() > CODE_BLOB_THRESHOLD))
        .expect("a block with a packed transaction")
}

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
    // The packed transactions of one block point one byte early: the
    // wrong bytes, under the entry's hash.
    let p = packed_target(c);
    let packed = move |table: u16, key: &[u8; 32], r: &mut csl_run::PackedRef| {
        if let Fault::PackedOffsetWrong = fault {
            if table == H_TRANSACTIONS && key[..5] == p.to_be_bytes()[3..] {
                r.off = r.off.checked_sub(1).unwrap_or(1);
            }
        }
    };
    let tamper = Tamper {
        block: &block,
        tx_lookup: &tx_lookup,
        log_lookup: &log_lookup,
        packed: &packed,
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

        // Every transaction of the target block and its neighbours, and of
        // the block with packed transactions.
        for n in [t - 1, t, t + 1, packed_target(&c)] {
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

/// A span of `periods` periods, `per` blocks each.
fn many_periods(periods: u64, per: u64) -> (BTreeMap<u64, Block>, Anchor) {
    let secs = SLOTS_PER_PERIOD * SECONDS_PER_SLOT / per;
    let t = MAINNET_GENESIS_TIME + 1900 * SLOTS_PER_PERIOD * SECONDS_PER_SLOT;
    let c = synthetic::chain_spaced(9, FIRST, periods * per, t, secs, false);
    let last = FIRST + periods * per - 1;
    let a = Anchor {
        number: last,
        hash: c[&last].hash,
    };
    (c, a)
}

/// Warm transaction reads (models loaded, headers kept) over every
/// `step`th block: the worst requests and rounds, and the tx_lookup bytes.
fn warm_tx_reads(
    h: &mut History<DirDriver>,
    c: &BTreeMap<u64, Block>,
    step: usize,
) -> (u64, u32, u64) {
    let (mut requests, mut rounds, mut lookup) = (0, 0, 0);
    for b in c.values().step_by(step) {
        let Some(t) = b.txs.first() else { continue };
        let (r, cost) = h.tx(&tx_hash(t));
        let r = r.unwrap_or_else(|e| panic!("block {}: {e}", b.number));
        assert_eq!((r.block_number, r.index), (b.number, 0));
        requests = requests.max(cost.requests);
        rounds = rounds.max(cost.rounds);
        lookup = lookup.max(cost.table_bytes.get("tx_lookup").copied().unwrap_or(0));
    }
    (requests, rounds, lookup)
}

#[test]
fn a_tx_read_does_not_grow_with_the_periods() {
    let mut worst = Vec::new();
    for periods in [2u64, 64] {
        let (c, a) = many_periods(periods, 2);
        let dir = scratch(&format!("many-{periods}"));
        let w = write_history(&dir, &c, FIRST, (a.number, a.hash), EPSILON).unwrap();
        assert_eq!(w.manifest.periods.len() as u64, periods);
        assert_eq!(
            w.manifest.tx_lookup.len(),
            2,
            "the base and the open period"
        );
        let mut h = History::open(DirDriver::new(&dir), a).unwrap();
        assert_eq!(h.cost().requests, 1, "opening fetches the manifest only");
        // Load what the reads touch, then measure.
        h.header(FIRST).0.unwrap();
        warm_tx_reads(&mut h, &c, 1);
        worst.push(warm_tx_reads(&mut h, &c, 1));
    }
    let (two, many) = (worst[0], worst[1]);
    // Two pieces probed whatever the periods: a request each, and when a
    // larger piece's model misses its page, the `ε + 1` window around it
    // in one more round. A probe per period would be 64 requests.
    let window = 2 * (u64::from(EPSILON) + 1) + 1;
    assert!(many.0 <= two.0 + 2, "{two:?} vs {many:?}");
    assert!(many.1 <= two.1 + 1, "{two:?} vs {many:?}");
    assert!(many.2 <= 2 * (window + 1) * 4096, "{many:?}");
}

/// The cost of a span of thousands of periods: run with
/// `cargo test -p csl-eth-history --release --test history -- --ignored --nocapture`.
#[test]
#[ignore]
fn measure_many_periods() {
    for (periods, per) in [(1u64, 64u64), (3_630, 1)] {
        let (c, a) = many_periods(periods, per);
        let dir = scratch(&format!("measure-{periods}"));
        let t0 = std::time::Instant::now();
        let w = write_history(&dir, &c, FIRST, (a.number, a.hash), EPSILON).unwrap();
        let write_s = t0.elapsed().as_secs_f64();
        let manifest =
            std::fs::read(dir.join(csl_eth_store::history::history_manifest_path(&a.hash)))
                .unwrap();
        let pretty = serde_json::to_vec_pretty(&w.manifest).unwrap();
        let t0 = std::time::Instant::now();
        let mut h = History::open(DirDriver::new(&dir), a).unwrap();
        let open_s = t0.elapsed().as_secs_f64();
        let open = h.cost();
        // A first read after opening: a fresh client.
        let mid = &c[&(FIRST + periods * per / 2)];
        let probe = mid
            .txs
            .first()
            .or_else(|| c.values().find_map(|b| b.txs.first()))
            .unwrap()
            .clone();
        let (r, first) = h.tx(&tx_hash(&probe));
        r.unwrap();
        // Cold: headers and packs forgotten, models kept.
        let mut cold = Vec::new();
        for b in c.values().step_by((c.len() / 50).max(1)) {
            let Some(t) = b.txs.first() else { continue };
            h.forget();
            let (r, cost) = h.tx(&tx_hash(t));
            r.unwrap();
            cold.push((
                cost.requests,
                cost.rounds,
                cost.bytes,
                cost.headers_verified,
            ));
        }
        // Warm: every header verified and kept, the models loaded; what a
        // transaction costs past the header walk.
        h.forget();
        h.header(FIRST).0.unwrap();
        let mut warm = Vec::new();
        for b in c.values().step_by((c.len() / 50).max(1)) {
            let Some(t) = b.txs.first() else { continue };
            h.tx(&tx_hash(t)).0.unwrap();
            let (r, cost) = h.tx(&tx_hash(t));
            r.unwrap();
            warm.push((
                cost.requests,
                cost.rounds,
                cost.bytes,
                cost.headers_verified,
            ));
        }
        let n = cold.len() as f64;
        let mean = |f: fn(&(u64, u32, u64, u64)) -> f64| cold.iter().map(f).sum::<f64>() / n;
        let wn = warm.len() as f64;
        let wmean = |f: fn(&(u64, u32, u64, u64)) -> f64| warm.iter().map(f).sum::<f64>() / wn;
        println!(
            "{}",
            serde_json::json!({
                "periods": periods, "blocks": c.len(), "write_s": write_s, "objects": w.files.len(),
                "tx_lookup_pieces": w.manifest.tx_lookup.len(),
                "manifest_bytes": manifest.len(), "manifest_bytes_pretty": pretty.len(),
                "open": { "requests": open.requests, "bytes": open.bytes, "rounds": open.rounds, "secs": open_s },
                "first_tx": { "requests": first.requests, "bytes": first.bytes, "rounds": first.rounds, "table_bytes": first.table_bytes },
                "cold_tx_mean": { "requests": mean(|x| x.0 as f64), "rounds": mean(|x| x.1 as f64), "bytes": mean(|x| x.2 as f64), "headers": mean(|x| x.3 as f64) },
                "warm_tx_mean": { "requests": wmean(|x| x.0 as f64), "rounds": wmean(|x| x.1 as f64), "bytes": wmean(|x| x.2 as f64) },
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
