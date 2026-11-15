//! The accumulator route over a synthetic chain: history tables written by
//! the producer's writer and a synthetic beacon chain over the same
//! blocks (`csl_eth_store::beacon::synthetic`), all consistent. Old headers
//! must come back verified by the accumulator, through both the ring (the
//! head's own period) and `historical_summaries` (a closed one), and every
//! lie in the beacon files must end `Insufficient` when the route is forced
//! and correct (by the walk) when it is not.

use alloy_primitives::B256;
use csl_eth_client::{
    beacon::{AccumError, Accumulator, BeaconAnchor},
    history::{Anchor, HeaderRoute, History, Insufficient},
    DirDriver, Driver, Got, Store, Want,
};
use csl_eth_store::{
    beacon::{
        chunk_record_range, head_path, period_path, summaries_path, synthetic, CHUNK_RECORD,
        HEAD_PREAMBLE, SLOTS_PER_HISTORICAL_ROOT,
    },
    history::{
        decode_header, synthetic as hsyn, tx_hash, write_history, Block, MAINNET_GENESIS_TIME,
        SECONDS_PER_SLOT,
    },
    EPSILON,
};
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
    sync::Arc,
};

const FIRST: u64 = 30_000;
const COUNT: u64 = 160;
const LAST: u64 = FIRST + COUNT - 1;
/// The first block's slot: 60 slots before period 1912 opens, so the span
/// has 60 blocks in a closed period and 100 in the head's.
const FIRST_SLOT: u64 = 1912 * SLOTS_PER_HISTORICAL_ROOT - 60;
/// The head: 70 slots past the last block, so the last block's chunk is
/// whole.
const HEAD_SLOT: u64 = FIRST_SLOT + COUNT + 70;

fn chain() -> BTreeMap<u64, Block> {
    hsyn::chain(
        11,
        FIRST,
        COUNT,
        MAINNET_GENESIS_TIME + FIRST_SLOT * SECONDS_PER_SLOT,
    )
}

fn slot_of(n: u64) -> u64 {
    FIRST_SLOT + (n - FIRST)
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("csl-eth-beacon-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

struct Fixture {
    dir: PathBuf,
    chain: BTreeMap<u64, Block>,
    world: synthetic::World,
}

fn fixture(name: &str) -> Fixture {
    let c = chain();
    let dir = scratch(name);
    write_history(&dir, &c, FIRST, (LAST, c[&LAST].hash), EPSILON).unwrap();
    let blocks: Vec<(u64, B256)> = c.values().map(|b| (slot_of(b.number), b.hash)).collect();
    let world = synthetic::world(&blocks, HEAD_SLOT);
    world.write(&dir).unwrap();
    Fixture {
        dir,
        chain: c,
        world,
    }
}

impl Fixture {
    fn beacon(&self) -> BeaconAnchor {
        BeaconAnchor {
            slot: self.world.head.slot,
            root: self.world.head_root,
        }
    }

    fn open<D: Driver>(&self, d: D, route: HeaderRoute) -> History<D> {
        let mut h = History::open(
            d,
            Anchor {
                number: LAST,
                hash: self.chain[&LAST].hash,
            },
        )
        .expect("history opens");
        h.set_beacon(self.beacon());
        h.route = route;
        h.accum_min_depth = 16;
        h
    }
}

/// The bucket on disk with some files replaced or removed: a lying host.
struct Overlay {
    base: DirDriver,
    files: HashMap<String, Option<Vec<u8>>>,
}

impl Overlay {
    fn new(f: &Fixture) -> Overlay {
        Overlay {
            base: DirDriver::new(&f.dir),
            files: HashMap::new(),
        }
    }

    fn edit(mut self, f: &Fixture, rel: &str, e: impl FnOnce(&mut Vec<u8>)) -> Overlay {
        let mut b = f.world.files[rel].clone();
        e(&mut b);
        self.files.insert(rel.to_string(), Some(b));
        self
    }

    fn remove(mut self, rel: &str) -> Overlay {
        self.files.insert(rel.to_string(), None);
        self
    }
}

impl Driver for Overlay {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        wants
            .iter()
            .map(|w| match self.files.get(w.rel()) {
                None => self.base.fetch(std::slice::from_ref(w)).remove(0),
                Some(None) => match w {
                    Want::File { .. } => Ok(None),
                    Want::Range { rel, .. } => Err(format!("{rel}: not found")),
                },
                Some(Some(b)) => match w {
                    Want::File { .. } => Ok(Some(b.clone())),
                    Want::Range { off, len, .. } => b
                        .get(*off as usize..*off as usize + len)
                        .map(|v| Some(v.to_vec()))
                        .ok_or_else(|| "short".to_string()),
                },
            })
            .collect()
    }
}

#[test]
fn old_headers_come_by_the_accumulator_through_both_vectors() {
    let f = fixture("routes");
    let mut h = f.open(DirDriver::new(&f.dir), HeaderRoute::Accumulator);
    let mut closed = 0;
    for n in (FIRST..=LAST).step_by(7) {
        h.forget();
        let (r, cost) = h.header(n);
        let got = r.unwrap_or_else(|e| panic!("block {n}: {e}"));
        assert_eq!(got.hash, f.chain[&n].hash);
        assert_eq!(cost.headers_verified, 1, "block {n}: one header, no walk");
        assert_eq!(cost.headers_by_accumulator, 1);
        assert!(cost.table_bytes.get("beacon").copied().unwrap_or(0) > 0);
        // Header row and preamble, then the records.
        assert!(cost.rounds <= 3, "block {n}: {} rounds", cost.rounds);
        if slot_of(n) < 1912 * SLOTS_PER_HISTORICAL_ROOT {
            closed += 1;
            // Row (one more when the model misses its page), preamble,
            // chunk, period, summary.
            assert!(cost.requests <= 6, "block {n}: {cost:?}");
        } else {
            assert!(cost.requests <= 5, "block {n}: {cost:?}");
        }
    }
    assert!(closed > 0);
}

#[test]
fn auto_walks_near_the_anchor_and_proves_far_from_it() {
    let f = fixture("auto");
    let mut h = f.open(DirDriver::new(&f.dir), HeaderRoute::Auto);
    let (r, c) = h.header(LAST - 3);
    r.unwrap();
    assert_eq!((c.headers_verified, c.headers_by_accumulator), (4, 0));
    let (r, c) = h.header(FIRST + 2);
    assert_eq!(r.unwrap().hash, f.chain[&(FIRST + 2)].hash);
    assert_eq!((c.headers_verified, c.headers_by_accumulator), (1, 1));
    // A transaction deep in the span: its header by the accumulator too.
    let b = f
        .chain
        .values()
        .find(|b| !b.txs.is_empty())
        .expect("a block with transactions");
    assert!(b.number < LAST - 16);
    let t = &b.txs[0];
    h.forget();
    let (r, c) = h.tx(&tx_hash(t));
    assert_eq!(r.unwrap().block_hash, b.hash);
    assert_eq!(c.headers_by_accumulator, 1);
    // The walk would have verified 155 headers.
    let mut w = f.open(DirDriver::new(&f.dir), HeaderRoute::Walk);
    let (r, cw) = w.tx(&tx_hash(t));
    r.unwrap();
    assert_eq!(cw.headers_verified, LAST - b.number + 1);
    assert!(
        cw.bytes > c.bytes,
        "walk {} vs accumulator {}",
        cw.bytes,
        c.bytes
    );
}

#[derive(Debug, Clone, Copy)]
enum Fault {
    /// A neighbour's root in the chunk's vector replaced.
    WrongRootInChunk,
    /// A chunk-root sibling in the head's ring record replaced.
    WrongRootInRing,
    /// A chunk-root sibling in a closed period's record replaced.
    WrongRootInPeriod,
    /// The block's body proof: a sibling of `block_hash` in the payload.
    WrongPayloadProof,
    /// The body proof's `body_root` siblings.
    WrongBodyProof,
    /// The record served is the next slot's (another block's proof).
    RecordOfNextSlot,
    /// `state_summary_root` of the summary.
    WrongSummary,
    /// The preamble claims a shorter `historical_summaries`.
    SummariesTooShort,
    /// The preamble's state branch.
    WrongStateBranch,
    /// The head file of another head.
    OtherHeadsFile,
    /// The chunk file is missing.
    MissingChunk,
    /// The head file is missing.
    MissingHead,
}

const FAULTS: [Fault; 12] = [
    Fault::WrongRootInChunk,
    Fault::WrongRootInRing,
    Fault::WrongRootInPeriod,
    Fault::WrongPayloadProof,
    Fault::WrongBodyProof,
    Fault::RecordOfNextSlot,
    Fault::WrongSummary,
    Fault::SummariesTooShort,
    Fault::WrongStateBranch,
    Fault::OtherHeadsFile,
    Fault::MissingChunk,
    Fault::MissingHead,
];

fn flip(b: &mut [u8], at: usize) {
    b[at] ^= 0x40;
}

/// The hostile host for `fault` against block `n`'s proof.
fn hostile(f: &Fixture, fault: Fault, n: u64) -> Overlay {
    let slot = slot_of(n);
    let (cp, co, _) = chunk_record_range(slot);
    let co = co as usize;
    let hp = head_path(&f.world.head_root);
    let chunk_pos = ((slot / 64) % 128) as usize;
    let o = Overlay::new(f);
    match fault {
        Fault::WrongRootInChunk => o.edit(f, &cp, |b| flip(b, co + 3)),
        Fault::WrongRootInRing => o.edit(f, &hp, |b| flip(b, HEAD_PREAMBLE + chunk_pos * 224 + 5)),
        Fault::WrongRootInPeriod => {
            o.edit(f, &period_path(1911), |b| flip(b, chunk_pos * 224 + 40))
        }
        Fault::WrongPayloadProof => o.edit(f, &cp, |b| flip(b, co + 6 * 32 + 1)),
        Fault::WrongBodyProof => o.edit(f, &cp, |b| flip(b, co + 11 * 32 + 2)),
        Fault::RecordOfNextSlot => o.edit(f, &cp, |b| {
            let next = if co + 2 * CHUNK_RECORD <= b.len() {
                co + CHUNK_RECORD
            } else {
                co - CHUNK_RECORD
            };
            let r = b[next..next + CHUNK_RECORD].to_vec();
            b[co..co + CHUNK_RECORD].copy_from_slice(&r);
        }),
        Fault::WrongSummary => {
            let len = 1912 - 758;
            o.edit(f, &summaries_path(len), |b| {
                let rl = b.len() / len as usize;
                flip(b, (1911 - 758) * rl + 4)
            })
        }
        Fault::SummariesTooShort => o.edit(f, &hp, |b| {
            let v = u64::from_le_bytes(b[376..384].try_into().unwrap()) - 1;
            b[376..384].copy_from_slice(&v.to_le_bytes());
        }),
        Fault::WrongStateBranch => o.edit(f, &hp, |b| flip(b, 152 + 32 * 2)),
        Fault::OtherHeadsFile => {
            let other = synthetic::world(&[(slot, B256::repeat_byte(9))], HEAD_SLOT + 64);
            let mut o = o;
            o.files.insert(
                hp.clone(),
                Some(other.files[&head_path(&other.head_root)].clone()),
            );
            o
        }
        Fault::MissingChunk => o.remove(&cp),
        Fault::MissingHead => o.remove(&hp),
    }
}

/// Whether `fault` touches the proof of a block at `slot` at all (a ring
/// record cannot lie about a closed period's block, and so on).
fn applies(fault: Fault, slot: u64) -> bool {
    let closed = slot < 1912 * SLOTS_PER_HISTORICAL_ROOT;
    match fault {
        Fault::WrongRootInRing => !closed,
        Fault::WrongRootInPeriod | Fault::WrongSummary => closed,
        _ => true,
    }
}

#[test]
fn every_beacon_fault_ends_insufficient_or_correct() {
    let f = fixture("faults");
    // One block in the closed period, one in the head's.
    let targets = [FIRST + 10, LAST - 20];
    let mut fired = 0;
    for &n in &targets {
        for fault in FAULTS {
            let slot = slot_of(n);
            // Forced: the lie is caught.
            let mut h = f.open(hostile(&f, fault, n), HeaderRoute::Accumulator);
            let (r, _) = h.header(n);
            match r {
                Err(Insufficient::Accumulator { block, .. }) => {
                    assert_eq!(block, n);
                    assert!(
                        applies(fault, slot),
                        "{fault:?} at block {n}: fired, but should not touch it"
                    );
                    fired += 1;
                }
                Ok(got) => {
                    assert!(
                        !applies(fault, slot),
                        "{fault:?} at block {n}: a lie was believed"
                    );
                    assert_eq!(got.hash, f.chain[&n].hash, "{fault:?}: a wrong header");
                }
                Err(e) => panic!("{fault:?} at block {n}: unexpected {e}"),
            }
            // Auto: the read walks instead, and is right.
            let mut h = f.open(hostile(&f, fault, n), HeaderRoute::Auto);
            let (r, c) = h.header(n);
            assert_eq!(
                r.unwrap_or_else(|e| panic!("{fault:?} at {n}, auto: {e}"))
                    .hash,
                f.chain[&n].hash
            );
            if applies(fault, slot) {
                assert_eq!(c.accumulator_failures, 1, "{fault:?} at {n}");
                assert_eq!(c.headers_by_accumulator, 0);
            }
        }
    }
    assert!(fired >= 18, "{fired} faults fired");
}

/// A lying header row: block `n`'s key serves block `n + 1`'s header, a
/// real block the accumulator proves, at another number.
#[test]
fn a_header_row_of_another_block_is_refused() {
    let f = fixture("row");
    let n = FIRST + 30;
    let c = f.chain.clone();
    // Build the history again with the swap after verification.
    let dir = scratch("row-hostile");
    let next = c[&(n + 1)].header.clone();
    let tamper = csl_eth_store::history::Tamper {
        block: &|b: &mut Block| {
            if b.number == n {
                b.header = next.clone();
            }
        },
        tx_lookup: &|_| {},
        log_lookup: &|_| {},
        packed: &|_, _, _| {},
    };
    csl_eth_store::history::write_history_tampered(
        &dir,
        &c,
        FIRST,
        (LAST, c[&LAST].hash),
        EPSILON,
        &tamper,
    )
    .unwrap();
    f.world.write(&dir).unwrap();
    let mut h = f.open(DirDriver::new(&dir), HeaderRoute::Accumulator);
    let (r, _) = h.header(n);
    assert!(
        matches!(r, Err(Insufficient::Accumulator { block, .. }) if block == n),
        "{r:?}"
    );
    // The neighbour itself is fine.
    let (r, _) = h.header(n + 1);
    assert_eq!(r.unwrap().hash, f.chain[&(n + 1)].hash);
}

fn prove(f: &Fixture, slot: u64, hash: &B256) -> Result<(), AccumError> {
    let store = Arc::new(Store::default());
    let d = DirDriver::new(&f.dir);
    let mut a = Accumulator::new(f.beacon());
    loop {
        match a.try_prove(&store, slot, hash) {
            Ok(r) => return r,
            Err(_) => csl_eth_client::drive(&d, &store, true),
        }
    }
}

/// The slot is the hint: asked at another slot, a real block hash fails;
/// asked before Capella, at or past the head, or in the head's partial
/// chunk, the route says it cannot reach.
#[test]
fn a_slot_pointing_at_another_block_fails() {
    let f = fixture("slot");
    let n = FIRST + 50;
    let h = decode_header(&f.chain[&n].header).unwrap();
    let s = slot_of(n);
    assert_eq!(prove(&f, s, &h.hash), Ok(()));
    for wrong in [s - 1, s + 1, s + 64, s - 8192] {
        assert!(
            matches!(
                prove(&f, wrong, &h.hash),
                Err(AccumError::Proof(_)) | Err(AccumError::Unreachable(_))
            ),
            "slot {wrong}"
        );
    }
    for far in [100, HEAD_SLOT, HEAD_SLOT + 5, HEAD_SLOT - 1] {
        assert!(
            matches!(prove(&f, far, &h.hash), Err(AccumError::Unreachable(_))),
            "slot {far}"
        );
    }
}
