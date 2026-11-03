//! The head through the sans-I/O opener: at most two rounds however many
//! period updates the bucket holds, exactly the files the verifier reads,
//! and every rejection the verifier makes on files read one by one it
//! makes the same way on files fetched in rounds. Real mainnet objects, the
//! head crate's fixtures: 2026-10-31's (bootstrap and finality update both
//! in period 1898) and the producer's of 2026-11-02 (bootstrap in 1898,
//! finality update signed in 1900), with `now` pinned; and 2026-11-03's
//! optimistic and finality updates fetched together (both signed in 1901)
//! for the choice between the attested and the finalized head.

use alloy_primitives::B256;
use csl_eth_client::{
    head::{verify_head, HeadError, Tier},
    open_at_head, open_at_head_with, Driver, FcrReport, Got, HeadOpenError, HeadOpener, Pending,
    TierChoice, Want,
};
use csl_eth_head::{paths, verify, Chain, FcrClass, HeadSource};
use csl_eth_store::manifest_path;
use std::{
    collections::{BTreeSet, HashMap},
    sync::Mutex,
    time::{Duration, SystemTime},
};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../head/tests/fixtures");

/// A bucket in memory that records each round's wants.
struct Files {
    files: HashMap<String, Vec<u8>>,
    rounds: Mutex<Vec<BTreeSet<String>>>,
}

impl Files {
    fn rounds(&self) -> Vec<BTreeSet<String>> {
        self.rounds.lock().unwrap().clone()
    }
}

impl Driver for &Files {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        self.rounds
            .lock()
            .unwrap()
            .push(wants.iter().map(|w| w.rel().to_string()).collect());
        wants
            .iter()
            .map(|w| match w {
                Want::File { rel } => Ok(self.files.get(rel).cloned()),
                Want::Range { rel, .. } => Err(format!("{rel}: no ranges here")),
            })
            .collect()
    }
}

impl HeadSource for Files {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.files.get(rel).cloned())
    }
}

struct Fixture {
    checkpoint: B256,
    now: SystemTime,
    files: Files,
}

/// Bootstrap and finality update both in 1898.
fn fixture() -> Fixture {
    load(FIX, &[1897, 1898])
}

/// Bootstrap in 1898, finality update signed in 1900.
fn fixture_1900() -> Fixture {
    load(&format!("{FIX}/p1900"), &[1898, 1899, 1900])
}

fn load(dir: &str, updates: &[u64]) -> Fixture {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{dir}/meta.json")).unwrap()).unwrap();
    let checkpoint: B256 = meta["checkpoint"].as_str().unwrap().parse().unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(meta["now"].as_u64().unwrap());
    let mut files = HashMap::new();
    files.insert(
        paths::bootstrap(&checkpoint),
        std::fs::read(format!("{dir}/bootstrap.json")).unwrap(),
    );
    for p in updates {
        files.insert(
            paths::update(*p),
            std::fs::read(format!("{dir}/update-{p}.json")).unwrap(),
        );
    }
    files.insert(
        paths::FINALITY.to_string(),
        std::fs::read(format!("{dir}/finality.json")).unwrap(),
    );
    Fixture {
        checkpoint,
        now,
        files: Files {
            files,
            rounds: Mutex::new(Vec::new()),
        },
    }
}

fn period_start(p: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(Chain::mainnet().genesis_time + p * 8192 * 12)
}

fn set(v: &[String]) -> BTreeSet<String> {
    v.iter().cloned().collect()
}

fn edit_json(bytes: &[u8], f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    f(&mut v);
    serde_json::to_vec(&v).unwrap()
}

/// What the finalized tier alone reads first.
fn head_round(fx: &Fixture) -> BTreeSet<String> {
    set(&[
        paths::bootstrap(&fx.checkpoint),
        paths::FINALITY.to_string(),
    ])
}

/// What the default opener reads first: both tiers' head updates and the
/// FCR note beside the bootstrap.
fn best_round(fx: &Fixture) -> BTreeSet<String> {
    let mut r = head_round(fx);
    r.insert(paths::OPTIMISTIC.to_string());
    r.insert(paths::FCR.to_string());
    r
}

#[test]
fn signed_in_the_bootstraps_period_the_head_is_one_round() {
    let fx = fixture();
    let r = open_at_head(&fx.files, fx.checkpoint, fx.now);
    // No snapshot in this bucket: the open verifies the head and stops at
    // the finalized block's manifest.
    let Err(HeadOpenError::NotAtHead { head, tier, .. }) = r else {
        panic!("{:?}", r.err());
    };
    assert_eq!(head.block_number, 26_310_853);
    // No `head/optimistic` in this bucket: the finalized head.
    assert_eq!(tier, Tier::Finalized);
    let rounds = fx.files.rounds();
    assert_eq!(rounds[0], best_round(&fx));
    // Bootstrap and finality update in 1898: no update between, and the
    // 1897 and 1898 files beside them are never asked for.
    assert!(
        rounds[1].iter().all(|f| f.starts_with("snapshots/")),
        "{:?}",
        rounds[1]
    );
}

#[test]
fn two_periods_on_the_updates_between_are_the_second_round() {
    let fx = fixture_1900();
    let r = open_at_head(&fx.files, fx.checkpoint, fx.now);
    let Err(HeadOpenError::NotAtHead { head, .. }) = r else {
        panic!("{:?}", r.err());
    };
    assert_eq!(head.block_number, 26_327_404);
    let rounds = fx.files.rounds();
    assert_eq!(rounds[0], best_round(&fx));
    // 1898 and 1899; 1900's update is in the bucket and not asked for.
    assert_eq!(rounds[1], set(&[paths::update(1898), paths::update(1899)]));
    assert!(
        rounds[2].iter().all(|f| f.starts_with("snapshots/")),
        "{:?}",
        rounds[2]
    );
}

#[test]
fn a_stale_bucket_is_refused_in_one_round() {
    let fx = fixture();
    let now = period_start(1900) + Duration::from_secs(3600);
    let r = open_at_head(&fx.files, fx.checkpoint, now);
    assert_eq!(
        r.err(),
        Some(HeadOpenError::Head(HeadError::Stale {
            signed: 1898,
            current: 1900
        }))
    );
    assert_eq!(fx.files.rounds(), vec![best_round(&fx)]);
}

#[test]
fn a_missing_update_between_is_refused_after_the_second_round() {
    let mut fx = fixture_1900();
    fx.files.files.remove(&paths::update(1898));
    let r = verify_head(&&fx.files, fx.checkpoint, fx.now);
    assert_eq!(r, Err(HeadError::Missing(paths::update(1898))));
    let rounds = fx.files.rounds();
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[1], set(&[paths::update(1898), paths::update(1899)]));
}

/// Each of the head crate's rejections, through the two-round opener:
/// the same error as the verifier reading file by file, and never more
/// than two rounds.
#[test]
fn every_rejection_is_the_same_through_the_opener() {
    type Tamper = Box<dyn Fn(&mut Fixture)>;
    let on_1900 = |t: Tamper| -> Tamper {
        Box::new(move |fx: &mut Fixture| {
            *fx = fixture_1900();
            t(fx)
        })
    };
    let finality = |f: fn(&mut serde_json::Value)| -> Tamper {
        Box::new(move |fx: &mut Fixture| {
            let b = fx.files.files.get_mut(paths::FINALITY).unwrap();
            *b = edit_json(b, f);
        })
    };
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "different checkpoint",
            Box::new(|fx| {
                let other = B256::repeat_byte(0x11);
                let b = fx
                    .files
                    .files
                    .remove(&paths::bootstrap(&fx.checkpoint))
                    .unwrap();
                fx.files.files.insert(paths::bootstrap(&other), b);
                fx.checkpoint = other;
            }),
        ),
        (
            "missing bootstrap",
            Box::new(|fx| {
                fx.files.files.remove(&paths::bootstrap(&fx.checkpoint));
            }),
        ),
        (
            "missing finality",
            Box::new(|fx| {
                fx.files.files.remove(paths::FINALITY);
            }),
        ),
        (
            "forged state root",
            finality(|v| {
                v["data"]["finalized_header"]["execution"]["state_root"] =
                    serde_json::Value::String(format!("{}", B256::repeat_byte(0x42)));
            }),
        ),
        (
            "forged block hash",
            finality(|v| {
                v["data"]["finalized_header"]["execution"]["block_hash"] =
                    serde_json::Value::String(format!("{}", B256::repeat_byte(0x43)));
            }),
        ),
        (
            "too few signers",
            finality(|v| {
                let bits = v["data"]["sync_aggregate"]["sync_committee_bits"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x")
                    .to_string();
                v["data"]["sync_aggregate"]["sync_committee_bits"] =
                    serde_json::Value::String(format!("0xff{}", "00".repeat(bits.len() / 2 - 1)));
            }),
        ),
        (
            "one signer bit flipped",
            finality(|v| {
                let bits = v["data"]["sync_aggregate"]["sync_committee_bits"]
                    .as_str()
                    .unwrap()
                    .to_string();
                let mut raw = hex::decode(bits.trim_start_matches("0x")).unwrap();
                raw[3] ^= 0x01;
                v["data"]["sync_aggregate"]["sync_committee_bits"] =
                    serde_json::Value::String(format!("0x{}", hex::encode(raw)));
            }),
        ),
        (
            "a day early",
            Box::new(|fx| fx.now -= Duration::from_secs(24 * 3600)),
        ),
        (
            "update in the wrong period's slot",
            on_1900(Box::new(|fx| {
                let wrong = std::fs::read(format!("{FIX}/update-1897.json")).unwrap();
                fx.files.files.insert(paths::update(1898), wrong);
            })),
        ),
        (
            "1900's update replayed as 1899's",
            on_1900(Box::new(|fx| {
                let u = fx.files.files[&paths::update(1900)].clone();
                fx.files.files.insert(paths::update(1899), u);
            })),
        ),
        (
            "an update between missing",
            on_1900(Box::new(|fx| {
                fx.files.files.remove(&paths::update(1899));
            })),
        ),
        (
            "an update between not the object",
            on_1900(Box::new(|fx| {
                fx.files
                    .files
                    .insert(paths::update(1898), b"{\"version\":\"fulu\"}".to_vec());
            })),
        ),
        (
            "an update between with a flipped signer bit",
            on_1900(Box::new(|fx| {
                let b = fx.files.files.get_mut(&paths::update(1899)).unwrap();
                *b = edit_json(b, |v| {
                    let bits = v["data"]["sync_aggregate"]["sync_committee_bits"]
                        .as_str()
                        .unwrap()
                        .to_string();
                    let mut raw = hex::decode(bits.trim_start_matches("0x")).unwrap();
                    raw[3] ^= 0x01;
                    v["data"]["sync_aggregate"]["sync_committee_bits"] =
                        serde_json::Value::String(format!("0x{}", hex::encode(raw)));
                });
            })),
        ),
        (
            "two periods on, stale",
            on_1900(Box::new(|fx| {
                fx.now = period_start(1902) + Duration::from_secs(60)
            })),
        ),
        (
            "two periods on, from the future",
            on_1900(Box::new(|fx| {
                fx.now = period_start(1899) + Duration::from_secs(60)
            })),
        ),
        (
            "not the object",
            Box::new(|fx| {
                fx.files.files.insert(
                    paths::FINALITY.to_string(),
                    b"{\"version\":\"fulu\",\"data\":{}}".to_vec(),
                );
            }),
        ),
        (
            "bootstrap not the object",
            Box::new(|fx| {
                fx.files
                    .files
                    .insert(paths::bootstrap(&fx.checkpoint), b"{}".to_vec());
            }),
        ),
        (
            "stale",
            Box::new(|fx| fx.now = period_start(1900) + Duration::from_secs(60)),
        ),
    ];
    for (name, tamper) in cases {
        let mut fx = fixture();
        tamper(&mut fx);
        let direct = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
        assert!(direct.is_err(), "{name}: the verifier accepted it");
        let through = verify_head(&&fx.files, fx.checkpoint, fx.now);
        assert_eq!(through, direct, "{name}");
        let rounds = fx.files.rounds().len();
        assert!(rounds <= 2, "{name}: {rounds} rounds");
    }
}

// The attested tier.

const ATTESTED_BLOCK: u64 = 26_334_572;
const FINALIZED_BLOCK: u64 = 26_334_487;

/// p1900's bootstrap and updates with 2026-11-03's optimistic and finality
/// updates, both signed in 1901.
fn fixture_attested() -> Fixture {
    let mut fx = load(&format!("{FIX}/p1900"), &[1898, 1899, 1900]);
    let dir = format!("{FIX}/attested");
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{dir}/meta.json")).unwrap()).unwrap();
    fx.now = SystemTime::UNIX_EPOCH + Duration::from_secs(meta["now"].as_u64().unwrap());
    for (rel, file) in [
        (paths::OPTIMISTIC, "optimistic.json"),
        (paths::FINALITY, "finality.json"),
    ] {
        fx.files.files.insert(
            rel.to_string(),
            std::fs::read(format!("{dir}/{file}")).unwrap(),
        );
    }
    fx
}

fn hash_of(fx: &Fixture, rel: &str, header: &str) -> B256 {
    let v: serde_json::Value = serde_json::from_slice(&fx.files.files[rel]).unwrap();
    v["data"][header]["execution"]["block_hash"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn attested_hash(fx: &Fixture) -> B256 {
    hash_of(fx, paths::OPTIMISTIC, "attested_header")
}

fn finalized_hash(fx: &Fixture) -> B256 {
    hash_of(fx, paths::FINALITY, "finalized_header")
}

/// A manifest file at `hash`: enough for the opener to choose that head;
/// the open itself then fails on the bytes, which is past what these
/// tests are about.
fn snapshot_at(fx: &mut Fixture, hash: B256) {
    fx.files
        .files
        .insert(manifest_path(&hash), b"not a manifest".to_vec());
}

/// What an opener ended with: the head it chose, the FCR note it kept and
/// its result.
type Ended = (
    Option<(Tier, u64)>,
    Option<FcrReport>,
    Result<(), HeadOpenError>,
);

/// Run an opener to its end.
fn open_with(fx: &Fixture, choice: TierChoice) -> Ended {
    let mut o = HeadOpener::with_tier(&fx.files, fx.checkpoint, fx.now, choice);
    let r = loop {
        match o.try_open() {
            Ok(r) => break r.map(|_| ()),
            Err(Pending) => o.round(),
        }
    };
    (
        o.head().map(|h| (h.tier, h.execution.block_number)),
        o.fcr().cloned(),
        r,
    )
}

#[test]
fn the_attested_head_is_preferred_when_its_snapshot_is_there() {
    let mut fx = fixture_attested();
    let (a, f) = (attested_hash(&fx), finalized_hash(&fx));
    snapshot_at(&mut fx, a);
    snapshot_at(&mut fx, f);
    let (head, _, r) = open_with(&fx, TierChoice::Best);
    assert_eq!(head, Some((Tier::Attested, ATTESTED_BLOCK)));
    assert!(matches!(r, Err(HeadOpenError::Open(_))), "{r:?}");
    let rounds = fx.files.rounds();
    assert_eq!(rounds[0], best_round(&fx));
    // One round of updates for both heads: they share 1898..=1900.
    assert_eq!(
        rounds[1],
        set(&[
            paths::update(1898),
            paths::update(1899),
            paths::update(1900)
        ])
    );
    // Both manifests in one round: falling back would have cost nothing.
    assert_eq!(rounds[2], set(&[manifest_path(&a), manifest_path(&f)]));
}

#[test]
fn the_finalized_head_is_the_fallback() {
    type Tamper = Box<dyn Fn(&mut Fixture)>;
    let cases: Vec<(&str, Tamper)> = vec![
        (
            "attested snapshot gone",
            Box::new(|fx| {
                let f = finalized_hash(fx);
                snapshot_at(fx, f);
            }),
        ),
        (
            "no head/optimistic",
            Box::new(|fx| {
                let f = finalized_hash(fx);
                snapshot_at(fx, f);
                fx.files.files.remove(paths::OPTIMISTIC);
            }),
        ),
        (
            "attested state root forged",
            Box::new(|fx| {
                let (a, f) = (attested_hash(fx), finalized_hash(fx));
                snapshot_at(fx, a);
                snapshot_at(fx, f);
                let b = fx.files.files.get_mut(paths::OPTIMISTIC).unwrap();
                *b = edit_json(b, |v| {
                    v["data"]["attested_header"]["execution"]["state_root"] =
                        format!("{}", B256::repeat_byte(0x42)).into();
                });
            }),
        ),
        (
            "head/optimistic not an optimistic update",
            Box::new(|fx| {
                let (a, f) = (attested_hash(fx), finalized_hash(fx));
                snapshot_at(fx, a);
                snapshot_at(fx, f);
                let other = std::fs::read(format!("{FIX}/p1900/finality.json")).unwrap();
                fx.files.files.insert(paths::OPTIMISTIC.to_string(), other);
            }),
        ),
    ];
    for (name, tamper) in cases {
        let mut fx = fixture_attested();
        tamper(&mut fx);
        let (head, fcr, r) = open_with(&fx, TierChoice::Best);
        assert_eq!(head, Some((Tier::Finalized, FINALIZED_BLOCK)), "{name}");
        assert!(matches!(r, Err(HeadOpenError::Open(_))), "{name}: {r:?}");
        assert_eq!(fcr, None, "{name}");
        assert!(
            fx.files.rounds().len() <= 4,
            "{name}: {:?}",
            fx.files.rounds()
        );
    }
}

#[test]
fn neither_snapshot_present_names_the_finalized_head() {
    let fx = fixture_attested();
    let r = open_at_head(&fx.files, fx.checkpoint, fx.now);
    let Err(HeadOpenError::NotAtHead { head, tier, .. }) = r else {
        panic!("{:?}", r.err());
    };
    assert_eq!(
        (tier, head.block_number),
        (Tier::Finalized, FINALIZED_BLOCK)
    );
    // Forced to the attested tier, the attested head.
    let r = open_at_head_with(&fx.files, fx.checkpoint, fx.now, TierChoice::Attested);
    let Err(HeadOpenError::NotAtHead { head, tier, .. }) = r else {
        panic!("{:?}", r.err().map(|e| e.to_string()));
    };
    assert_eq!((tier, head.block_number), (Tier::Attested, ATTESTED_BLOCK));
}

#[test]
fn forced_finalized_never_reads_the_attested_files() {
    let mut fx = fixture_attested();
    let (a, f) = (attested_hash(&fx), finalized_hash(&fx));
    snapshot_at(&mut fx, a);
    snapshot_at(&mut fx, f);
    let (head, _, _) = open_with(&fx, TierChoice::Finalized);
    assert_eq!(head, Some((Tier::Finalized, FINALIZED_BLOCK)));
    let rounds = fx.files.rounds();
    assert_eq!(rounds[0], head_round(&fx));
    assert!(rounds
        .iter()
        .flatten()
        .all(|f| f != paths::OPTIMISTIC && f != paths::FCR));
    assert_eq!(rounds[2], set(&[manifest_path(&f)]));
}

#[test]
fn before_any_finality_update_the_attested_head_opens_alone() {
    // A producer's first minutes: optimistic published, finality not yet.
    let mut fx = fixture_attested();
    let a = attested_hash(&fx);
    snapshot_at(&mut fx, a);
    fx.files.files.remove(paths::FINALITY);
    let (head, _, _) = open_with(&fx, TierChoice::Best);
    assert_eq!(head, Some((Tier::Attested, ATTESTED_BLOCK)));
    // And when the attested head fails too, its error, not "no finality".
    let mut fx = fixture_attested();
    fx.files.files.remove(paths::FINALITY);
    fx.now = period_start(1903) + Duration::from_secs(60);
    let r = open_at_head(&fx.files, fx.checkpoint, fx.now);
    assert_eq!(
        r.err(),
        Some(HeadOpenError::Head(HeadError::Stale {
            signed: 1901,
            current: 1903
        }))
    );
}

fn fcr_note(fx: &Fixture, hash: B256, number: u64) -> Vec<u8> {
    let _ = fx;
    FcrReport {
        block_hash: hash,
        block_number: number,
        confirmed_after_secs: 13,
        trail_blocks: 2,
        classification: FcrClass::of_trail(2),
        source: "rpc.example".into(),
        checked_at: 1_793_712_520,
    }
    .to_json()
}

#[test]
fn the_fcr_note_rides_only_on_the_attested_head_it_names() {
    let mut fx = fixture_attested();
    let (a, f) = (attested_hash(&fx), finalized_hash(&fx));
    snapshot_at(&mut fx, a);
    snapshot_at(&mut fx, f);
    let note = fcr_note(&fx, a, ATTESTED_BLOCK);
    fx.files.files.insert(paths::FCR.to_string(), note);
    let (_, fcr, _) = open_with(&fx, TierChoice::Best);
    let fcr = fcr.expect("attached");
    assert_eq!(fcr.classification, FcrClass::FcrLike);
    assert_eq!(fcr.source, "rpc.example");
    // About another block (an older snapshot's report): ignored.
    for (hash, number) in [(f, FINALIZED_BLOCK), (a, ATTESTED_BLOCK + 1)] {
        let note = fcr_note(&fx, hash, number);
        fx.files.files.insert(paths::FCR.to_string(), note);
        let (head, fcr, _) = open_with(&fx, TierChoice::Best);
        assert_eq!(head, Some((Tier::Attested, ATTESTED_BLOCK)));
        assert_eq!(fcr, None, "{hash} {number}");
    }
    // Not a report: ignored, and the head opens as before.
    fx.files
        .files
        .insert(paths::FCR.to_string(), b"{\"block_hash\":1}".to_vec());
    let (head, fcr, _) = open_with(&fx, TierChoice::Best);
    assert_eq!((head, fcr), (Some((Tier::Attested, ATTESTED_BLOCK)), None));
    // A finalized head never carries it, even at the named block.
    let note = fcr_note(&fx, f, FINALIZED_BLOCK);
    fx.files.files.insert(paths::FCR.to_string(), note);
    fx.files.files.remove(&manifest_path(&a));
    let (head, fcr, _) = open_with(&fx, TierChoice::Best);
    assert_eq!(
        (head, fcr),
        (Some((Tier::Finalized, FINALIZED_BLOCK)), None)
    );
}

#[test]
fn fcr_classification_is_by_trail() {
    assert_eq!(FcrClass::of_trail(0), FcrClass::FcrLike);
    assert_eq!(FcrClass::of_trail(4), FcrClass::FcrLike);
    assert_eq!(FcrClass::of_trail(5), FcrClass::JustifiedLike);
    assert_eq!(FcrClass::of_trail(40), FcrClass::JustifiedLike);
    let r = FcrReport::from_json(&fcr_note(&fixture(), B256::repeat_byte(9), 7)).unwrap();
    assert_eq!(r.block_hash, B256::repeat_byte(9));
    let v: serde_json::Value = serde_json::from_slice(&r.to_json()).unwrap();
    assert_eq!(v["classification"], "fcr_like");
}
