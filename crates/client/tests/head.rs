//! The head through the sans-I/O opener: two rounds however many period
//! updates the bucket holds, and every rejection the verifier makes on
//! files read one by one it makes the same way on files fetched in two
//! rounds. Real mainnet objects of 2026-10-31 (period 1898), the head
//! crate's fixtures, with `now` pinned.

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

fn fixture() -> Fixture {
    let meta: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{FIX}/meta.json")).unwrap()).unwrap();
    let checkpoint: B256 = meta["checkpoint"].as_str().unwrap().parse().unwrap();
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(meta["now"].as_u64().unwrap());
    let mut files = HashMap::new();
    files.insert(
        paths::bootstrap(&checkpoint),
        std::fs::read(format!("{FIX}/bootstrap.json")).unwrap(),
    );
    for p in [1897u64, 1898] {
        files.insert(
            paths::update(p),
            std::fs::read(format!("{FIX}/update-{p}.json")).unwrap(),
        );
    }
    files.insert(
        paths::FINALITY.to_string(),
        std::fs::read(format!("{FIX}/finality.json")).unwrap(),
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

#[test]
fn the_head_is_two_rounds_then_the_manifest() {
    let fx = fixture();
    let r = open_at_head(&fx.files, fx.checkpoint, fx.now);
    // No snapshot in this bucket: the open verifies the head and stops at
    // the finalized block's manifest.
    let Err(HeadOpenError::NotAtHead { finalized, .. }) = r else {
        panic!("{:?}", r.err());
    };
    assert_eq!(finalized.block_number, 26_310_853);
    let rounds = fx.files.rounds();
    assert_eq!(
        rounds[0],
        set(&[
            paths::bootstrap(&fx.checkpoint),
            paths::FINALITY.to_string()
        ])
    );
    // The bootstrap is in 1898 and so is the clock: one update, and the
    // 1897 file beside it is never asked for.
    assert_eq!(rounds[1], set(&[paths::update(1898)]));
    assert!(
        rounds[2].iter().all(|f| f.starts_with("snapshots/")),
        "{:?}",
        rounds[2]
    );
}

#[test]
fn every_period_update_comes_in_the_second_round() {
    // Two periods on, with the 1899 and 1900 updates present: still two
    // rounds, all three updates in the second.
    let mut fx = fixture();
    let u = fx.files.files[&paths::update(1898)].clone();
    // The bytes do not matter for the round count up to the refusal: 1898
    // verifies, the copy in 1899's slot is refused by its period.
    fx.files.files.insert(paths::update(1899), u.clone());
    fx.files.files.insert(paths::update(1900), u);
    let now = period_start(1900) + Duration::from_secs(600);
    let r = verify_head(&&fx.files, fx.checkpoint, now);
    assert!(
        matches!(r, Err(HeadError::Update { period: 1899, .. })),
        "{r:?}"
    );
    assert_eq!(r, verify(&fx.files, &Chain::mainnet(), fx.checkpoint, now));
    let rounds = fx.files.rounds();
    assert_eq!(rounds.len(), 2, "{rounds:?}");
    assert_eq!(
        rounds[1],
        set(&[
            paths::update(1898),
            paths::update(1899),
            paths::update(1900)
        ])
    );
}

#[test]
fn a_missing_current_period_update_is_fine_in_the_second_round() {
    let fx = fixture();
    let now = period_start(1899) + Duration::from_secs(600);
    let h = verify_head(&&fx.files, fx.checkpoint, now).unwrap();
    assert_eq!(h.execution.block_number, 26_310_853);
    let rounds = fx.files.rounds();
    assert_eq!(rounds.len(), 2);
    assert_eq!(rounds[1], set(&[paths::update(1898), paths::update(1899)]));
}

#[test]
fn a_stale_bucket_is_refused_as_stale_in_two_rounds() {
    let fx = fixture();
    let now = period_start(1900) + Duration::from_secs(3600);
    let r = open_at_head(&fx.files, fx.checkpoint, now);
    assert_eq!(
        r.err(),
        Some(HeadOpenError::Head(HeadError::Stale {
            missing: 1899,
            current: 1900
        }))
    );
    assert_eq!(fx.files.rounds().len(), 2);
}

/// Each of the head crate's rejections, through the two-round opener:
/// the same error as the verifier reading file by file, and never more
/// than two rounds.
#[test]
fn every_rejection_is_the_same_through_the_opener() {
    type Tamper = Box<dyn Fn(&mut Fixture)>;
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
            Box::new(|fx| {
                let wrong = fx.files.files[&paths::update(1897)].clone();
                fx.files.files.insert(paths::update(1898), wrong);
            }),
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
