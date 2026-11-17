//! The accumulator route on real mainnet files: the head verified from
//! the checkpoint by the head files the producer published, then
//! execution block hashes proven to it from the records `csl-eth beacon
//! build` wrote (kept sparse: only the ranges these reads touch). Each
//! fixture is one head: `h1` (slot 15,662,720, period 1911) reaches its
//! targets through its own `block_roots`; `h2` (slot 15,663,104, the
//! first of 1912) reaches the same blocks through period 1911's file and
//! `historical_summaries[1153]`.
//! The anchor block of the day's history span is among the targets, with
//! its hash from the history producer, not the beacon files. `now` is
//! pinned near each head.
//!
//! Every lie must fail: a byte changed in any record, a record missing,
//! another block's hash, a neighbour slot.

use alloy_primitives::B256;
use csl_eth_client::{head::verify_head, Driver, Got, Store, Want};
use csl_eth_history::beacon::{AccumError, Accumulator, BeaconAnchor};
use std::{
    collections::{BTreeMap, HashMap},
    time::{Duration, SystemTime},
};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/accum");

struct Target {
    slot: u64,
    hash: B256,
    route: String,
}

/// Whole head files, and sparse ranges of the beacon files.
#[derive(Clone)]
struct Sparse {
    files: HashMap<String, Vec<u8>>,
    ranges: BTreeMap<String, BTreeMap<u64, Vec<u8>>>,
}

impl Driver for Sparse {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        wants
            .iter()
            .map(|w| match w {
                Want::File { rel } => Ok(self.files.get(rel).cloned()),
                Want::Range { rel, off, len } => {
                    let Some(m) = self.ranges.get(rel) else {
                        return Err(format!("{rel}: not found"));
                    };
                    let Some((o, b)) = m.range(..=*off).next_back() else {
                        return Err(format!("{rel}: {off} not held"));
                    };
                    let s = (*off - *o) as usize;
                    b.get(s..s + len)
                        .map(|v| Some(v.to_vec()))
                        .ok_or(format!("{rel}: {off}+{len} not held"))
                }
            })
            .collect()
    }
}

struct Fixture {
    anchor: BeaconAnchor,
    targets: Vec<Target>,
    files: Sparse,
}

fn load(name: &str) -> Option<Fixture> {
    let dir = format!("{FIX}/{name}");
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{dir}/meta.json")).ok()?).unwrap();
    let mut files = HashMap::new();
    for e in walk(&format!("{dir}/head")) {
        let rel = e.strip_prefix(&format!("{dir}/")).unwrap().to_string();
        files.insert(rel, std::fs::read(&e).unwrap());
    }
    let r: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{dir}/ranges.json")).unwrap()).unwrap();
    let mut ranges: BTreeMap<String, BTreeMap<u64, Vec<u8>>> = BTreeMap::new();
    for (path, rs) in r.as_object().unwrap() {
        for x in rs.as_array().unwrap() {
            ranges.entry(path.clone()).or_default().insert(
                x[0].as_u64().unwrap(),
                hex::decode(x[1].as_str().unwrap()).unwrap(),
            );
        }
    }
    let files = Sparse { files, ranges };
    let checkpoint: B256 = meta["checkpoint"].as_str().unwrap().parse().unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(meta["now"].as_u64().unwrap());
    let head = verify_head(&files, checkpoint, now).expect("the head verifies");
    assert_eq!(head.slot, meta["slot"].as_u64().unwrap());
    assert_eq!(
        head.beacon_root.to_string(),
        meta["beacon_root"].as_str().unwrap()
    );
    let targets = meta["targets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| Target {
            slot: t["slot"].as_u64().unwrap(),
            hash: t["block_hash"].as_str().unwrap().parse().unwrap(),
            route: t["route"].as_str().unwrap().to_string(),
        })
        .collect();
    Some(Fixture {
        anchor: BeaconAnchor::from(&head),
        targets,
        files,
    })
}

fn walk(dir: &str) -> Vec<String> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(p.to_str().unwrap()));
        } else {
            out.push(p.to_str().unwrap().to_string());
        }
    }
    out
}

/// One proof, driven to the end: the result and (requests, bytes, rounds).
fn prove<D: Driver>(
    d: &D,
    anchor: BeaconAnchor,
    slot: u64,
    hash: &B256,
) -> (Result<(), AccumError>, (u64, u64, u32)) {
    let store = Store::new();
    let mut a = Accumulator::new(anchor);
    store.begin_read();
    for _ in 0..8 {
        match a.try_prove(&store, slot, hash) {
            Ok(r) => return (r, store.cost()),
            Err(_) => csl_eth_client::drive(d, &store, false),
        }
    }
    panic!("no answer in 8 rounds");
}

fn check(name: &str) {
    let f = load(name).expect("fixture");
    let mut lies = 0;
    for t in &f.targets {
        let (r, (req, bytes, rounds)) = prove(&f.files, f.anchor, t.slot, &t.hash);
        assert_eq!(r, Ok(()), "{name}: slot {} ({})", t.slot, t.route);
        let want = if t.route == "ring" { 3 } else { 4 };
        assert_eq!((req, rounds), (want, 1), "{name}: slot {}", t.slot);
        assert!(bytes <= 576 + 576 + 224 + 32 * 13, "{bytes}");

        // Another block's hash, and this hash at a neighbour slot.
        let other = f.targets.iter().find(|o| o.hash != t.hash).unwrap();
        assert!(matches!(
            prove(&f.files, f.anchor, t.slot, &other.hash).0,
            Err(AccumError::Proof(_))
        ));
        assert!(prove(&f.files, f.anchor, t.slot + 1, &t.hash).0.is_err());

        // Every byte range this read touches: a flip anywhere in it fails,
        // and so does its absence.
        let touched: Vec<(String, u64)> = f
            .files
            .ranges
            .iter()
            .flat_map(|(p, m)| m.keys().map(move |o| (p.clone(), *o)))
            .filter(|(p, o)| touches(t, &f, p, *o))
            .collect();
        assert_eq!(touched.len(), if t.route == "ring" { 3 } else { 4 });
        for (p, o) in &touched {
            let len = f.files.ranges[p][o].len();
            for at in (0..len).step_by(32).map(|w| w + 7) {
                let mut bad = f.files.clone();
                bad.ranges.get_mut(p).unwrap().get_mut(o).unwrap()[at] ^= 0x10;
                let r = prove(&bad, f.anchor, t.slot, &t.hash).0;
                assert!(
                    matches!(r, Err(AccumError::Proof(_))),
                    "{name}: slot {}: {p}@{o}+{at} flipped gave {r:?}",
                    t.slot
                );
                lies += 1;
            }
            let mut gone = f.files.clone();
            gone.ranges.get_mut(p).unwrap().remove(o);
            let r = prove(&gone, f.anchor, t.slot, &t.hash).0;
            assert!(r.is_err(), "{name}: {p} absent gave {r:?}");
            lies += 1;
        }
    }
    eprintln!("{name}: {} targets, {lies} lies refused", f.targets.len());
}

/// Whether the record at `p@o` is one the read of `t` uses.
fn touches(t: &Target, f: &Fixture, p: &str, o: u64) -> bool {
    use csl_eth_store::beacon::{chunk_record_range, head_path, route, route_ranges};
    let (cp, co, _) = chunk_record_range(t.slot);
    let len_l = (f.anchor.slot / 8192) - csl_eth_store::beacon::CAPELLA_PERIOD;
    let r = route(f.anchor.slot, t.slot).unwrap();
    let mut mine: Vec<(String, u64)> = route_ranges(len_l, &f.anchor.root, &r)
        .into_iter()
        .map(|(p, o, _)| (p, o))
        .collect();
    mine.push((cp, co));
    mine.push((head_path(&f.anchor.root), 0));
    mine.iter().any(|(mp, mo)| mp == p && *mo == o)
}

#[test]
fn ring_route_on_mainnet() {
    check("h1");
}

#[test]
fn summaries_route_on_mainnet() {
    check("h2");
}
