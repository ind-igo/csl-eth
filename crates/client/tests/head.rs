//! The head through the sans-I/O opener: at most two rounds however many
//! period updates the bucket holds, exactly the files the verifier reads,
//! and every rejection the verifier makes on files read one by one it
//! makes the same way on files fetched in rounds. Real mainnet objects, the
//! head crate's fixtures: 2026-10-31's (bootstrap and finality update both
//! in period 1898) and the producer's of 2026-11-02 (bootstrap in 1898,
//! finality update signed in 1900), with `now` pinned.

use alloy_primitives::B256;
use csl_eth_client::{
    head::{verify_head, HeadError},
    open_at_head, Driver, Got, HeadOpenError, Want,
};
use csl_eth_head::{paths, verify, Chain, HeadSource};
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

fn head_round(fx: &Fixture) -> BTreeSet<String> {
    set(&[
        paths::bootstrap(&fx.checkpoint),
        paths::FINALITY.to_string(),
    ])
}

#[test]
fn signed_in_the_bootstraps_period_the_head_is_one_round() {
    let fx = fixture();
    let r = open_at_head(&fx.files, fx.checkpoint, fx.now);
    // No snapshot in this bucket: the open verifies the head and stops at
    // the finalized block's manifest.
    let Err(HeadOpenError::NotAtHead { finalized, .. }) = r else {
        panic!("{:?}", r.err());
    };
    assert_eq!(finalized.block_number, 26_310_853);
    let rounds = fx.files.rounds();
    assert_eq!(rounds[0], head_round(&fx));
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
    let Err(HeadOpenError::NotAtHead { finalized, .. }) = r else {
        panic!("{:?}", r.err());
    };
    assert_eq!(finalized.block_number, 26_327_404);
    let rounds = fx.files.rounds();
    assert_eq!(rounds[0], head_round(&fx));
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
    assert_eq!(fx.files.rounds(), vec![head_round(&fx)]);
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
