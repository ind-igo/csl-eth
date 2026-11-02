//! Real mainnet objects fetched from a beacon node on 2026-10-31 (period
//! 1898, Fulu): the head verifies from the checkpoint root alone, and
//! every tampered or misplaced file is rejected. `now` is pinned to the
//! fetch time so the slot arithmetic is stable.

use alloy_primitives::B256;
use csl_eth_head::{paths, verify, Chain, HeadError, HeadSource};
use std::{
    collections::HashMap,
    time::{Duration, SystemTime},
};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

struct Files(HashMap<String, Vec<u8>>);

impl HeadSource for Files {
    fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        Ok(self.0.get(rel).cloned())
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
        files: Files(files),
    }
}

fn edit_json(bytes: &[u8], f: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let mut v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
    f(&mut v);
    serde_json::to_vec(&v).unwrap()
}

#[test]
fn the_head_verifies_from_the_checkpoint_alone() {
    let fx = fixture();
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now).unwrap();
    assert_eq!(h.checkpoint, fx.checkpoint);
    assert_eq!(h.period, 1898);
    assert_eq!(h.updates_applied, 1, "the checkpoint's own period update");
    assert!(
        h.participants > 341,
        "two thirds of 512: {}",
        h.participants
    );
    assert_eq!(h.execution.block_number, 26_310_853);
    assert_eq!(
        h.execution.block_hash,
        "0x4f081166c6721bf4adbc941c2dd72ebd621c4e7fc9ebf462c7921b79cc3858b4"
            .parse::<B256>()
            .unwrap()
    );
    assert_ne!(h.execution.state_root, B256::ZERO);
    assert!(
        h.finality_lag_secs > 12 * 60 && h.finality_lag_secs < 40 * 60,
        "lag {}",
        h.finality_lag_secs
    );
}

#[test]
fn a_different_checkpoint_root_rejects_the_bootstrap() {
    let mut fx = fixture();
    let other = B256::repeat_byte(0x11);
    let b = fx
        .files
        .0
        .remove(&paths::bootstrap(&fx.checkpoint))
        .unwrap();
    fx.files.0.insert(paths::bootstrap(&other), b);
    let r = verify(&fx.files, &Chain::mainnet(), other, fx.now);
    assert!(matches!(r, Err(HeadError::Bootstrap(_))), "{r:?}");
}

#[test]
fn a_missing_bootstrap_is_missing_not_trusted() {
    let mut fx = fixture();
    fx.files.0.remove(&paths::bootstrap(&fx.checkpoint));
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(matches!(r, Err(HeadError::Missing(_))), "{r:?}");
}

#[test]
fn a_forged_execution_state_root_fails_the_header_proof() {
    let mut fx = fixture();
    let f = fx.files.0.get_mut(paths::FINALITY).unwrap();
    *f = edit_json(f, |v| {
        v["data"]["finalized_header"]["execution"]["state_root"] =
            serde_json::Value::String(format!("{}", B256::repeat_byte(0x42)));
    });
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(matches!(r, Err(HeadError::Finality(_))), "{r:?}");
}

#[test]
fn a_forged_finalized_block_hash_fails_the_header_proof() {
    let mut fx = fixture();
    let f = fx.files.0.get_mut(paths::FINALITY).unwrap();
    *f = edit_json(f, |v| {
        v["data"]["finalized_header"]["execution"]["block_hash"] =
            serde_json::Value::String(format!("{}", B256::repeat_byte(0x43)));
    });
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(matches!(r, Err(HeadError::Finality(_))), "{r:?}");
}

#[test]
fn too_few_signers_are_rejected() {
    let mut fx = fixture();
    let f = fx.files.0.get_mut(paths::FINALITY).unwrap();
    *f = edit_json(f, |v| {
        // Keep one byte of participation: 8 of 512, far under two thirds.
        let bits = v["data"]["sync_aggregate"]["sync_committee_bits"]
            .as_str()
            .unwrap();
        let mut hexs = bits.trim_start_matches("0x").to_string();
        hexs = format!("ff{}", "00".repeat(hexs.len() / 2 - 1));
        v["data"]["sync_aggregate"]["sync_committee_bits"] =
            serde_json::Value::String(format!("0x{hexs}"));
    });
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(matches!(r, Err(HeadError::Finality(_))), "{r:?}");
}

#[test]
fn a_changed_signer_set_breaks_the_aggregate_signature() {
    let mut fx = fixture();
    let f = fx.files.0.get_mut(paths::FINALITY).unwrap();
    *f = edit_json(f, |v| {
        // Flip one bit: still a supermajority, but the aggregate public key
        // no longer matches the signature.
        let bits = v["data"]["sync_aggregate"]["sync_committee_bits"]
            .as_str()
            .unwrap()
            .to_string();
        let mut raw = hex::decode(bits.trim_start_matches("0x")).unwrap();
        raw[3] ^= 0x01;
        v["data"]["sync_aggregate"]["sync_committee_bits"] =
            serde_json::Value::String(format!("0x{}", hex::encode(raw)));
    });
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(matches!(r, Err(HeadError::Finality(_))), "{r:?}");
}

#[test]
fn a_finality_update_from_the_future_is_rejected() {
    let fx = fixture();
    // A clock a day behind the objects: their signature slot is in the future.
    let early = fx.now - Duration::from_secs(24 * 3600);
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, early);
    assert!(
        matches!(
            r,
            Err(HeadError::Finality(_)) | Err(HeadError::Update { .. })
        ),
        "{r:?}"
    );
}

#[test]
fn a_frozen_finality_file_shows_as_lag_not_as_fresh_state() {
    let fx = fixture();
    let later = fx.now + Duration::from_secs(6 * 3600);
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, later).unwrap();
    assert!(
        h.finality_lag_secs > 6 * 3600,
        "lag {}",
        h.finality_lag_secs
    );
    assert_eq!(h.execution.block_number, 26_310_853);
}

#[test]
fn an_update_from_the_wrong_period_is_rejected() {
    let mut fx = fixture();
    // The 1897 update in 1898's slot: its committee proof is for another period.
    let wrong = fx.files.0.get(&paths::update(1897)).unwrap().clone();
    fx.files.0.insert(paths::update(1898), wrong);
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(
        matches!(r, Err(HeadError::Update { period: 1898, .. })),
        "{r:?}"
    );
}

#[test]
fn a_file_that_is_not_the_object_is_a_decode_error() {
    let mut fx = fixture();
    fx.files.0.insert(
        paths::FINALITY.to_string(),
        b"{\"version\":\"fulu\",\"data\":{}}".to_vec(),
    );
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(matches!(r, Err(HeadError::Decode { .. })), "{r:?}");
}

/// Period boundaries for the fixture: period 1898 began at this time, and
/// each period is 8,192 slots of 12 seconds.
fn period_start(p: u64) -> SystemTime {
    let chain = Chain::mainnet();
    SystemTime::UNIX_EPOCH + Duration::from_secs(chain.genesis_time + p * 8192 * 12)
}

#[test]
fn a_bucket_not_updated_since_is_stale_not_missing() {
    let fx = fixture();
    // An hour into period 1900 with updates through 1898: the head stops
    // at 1899, which the clock has left. The frozen snapshot's case.
    let now = period_start(1900) + Duration::from_secs(3600);
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, now);
    assert_eq!(
        r,
        Err(HeadError::Stale {
            missing: 1899,
            current: 1900
        })
    );
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("stops at period 1899") && msg.contains("clock is in period 1900"),
        "{msg}"
    );
    assert!(msg.contains("has not published since"), "{msg}");
}

#[test]
fn the_period_after_the_last_update_still_verifies() {
    let fx = fixture();
    // In period 1899 with no 1899 update: the current period's update may
    // not exist yet, and the 1899 committee (from 1898's update) signs.
    // The fixture's finality update is from 1898 and still verifies; it is
    // lag, not staleness.
    let now = period_start(1899) + Duration::from_secs(3600);
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, now).unwrap();
    assert_eq!(h.execution.block_number, 26_310_853);
}

#[test]
fn a_missing_checkpoint_period_update_is_stale() {
    let mut fx = fixture();
    fx.files.0.remove(&paths::update(1898));
    let now = period_start(1899) + Duration::from_secs(60);
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, now);
    assert_eq!(
        r,
        Err(HeadError::Stale {
            missing: 1898,
            current: 1899
        })
    );
}

#[test]
fn a_gap_before_a_later_update_is_missing_not_stale() {
    let mut fx = fixture();
    // 1898 gone but a (here bogus) 1899 present: the producer did publish
    // later, so the hole is a broken bucket, named by its path.
    let later = fx.files.0.remove(&paths::update(1898)).unwrap();
    fx.files.0.insert(paths::update(1899), later);
    let now = period_start(1899) + Duration::from_secs(60);
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, now);
    assert_eq!(r, Err(HeadError::Missing(paths::update(1898))));
}
