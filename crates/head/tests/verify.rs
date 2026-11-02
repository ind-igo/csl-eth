//! Real mainnet objects (Fulu): the head verifies from the checkpoint root
//! alone, and every tampered, misplaced or stale file is rejected. Two sets:
//! `fixtures/` fetched from a beacon node on 2026-10-31, a finality update
//! signed in the bootstrap's own period 1898 (no update between them); and
//! `fixtures/p1900/`, the producer's first published head of 2026-11-02, a
//! bootstrap in 1898 and a finality update signed in 1900, with the period
//! updates for 1898, 1899 and 1900. `now` is pinned to each fetch time so
//! the slot arithmetic is stable.

use alloy_primitives::B256;
use csl_eth_head::{has_quorum, paths, verify, Chain, HeadError, HeadSource, COMMITTEE_SIZE};
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

/// The 2026-10-31 set: bootstrap and finality update both in 1898.
fn fixture() -> Fixture {
    load(FIX, &[1897, 1898])
}

/// The producer's set: bootstrap in 1898, finality update signed in 1900.
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
    assert_eq!(
        h.updates_applied, 0,
        "signed in the checkpoint's own period: no committee handover between"
    );
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
    assert!(matches!(r, Err(HeadError::Finality(_))), "{r:?}");
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

fn reads(fx: &Fixture, now: SystemTime) -> Vec<String> {
    struct Log<'a>(&'a Files, std::cell::RefCell<Vec<String>>);
    impl HeadSource for Log<'_> {
        fn read_head(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
            self.1.borrow_mut().push(rel.to_string());
            self.0.read_head(rel)
        }
    }
    let log = Log(&fx.files, Default::default());
    let _ = verify(&log, &Chain::mainnet(), fx.checkpoint, now);
    log.1.into_inner()
}

#[test]
fn a_head_signed_two_periods_ago_is_stale() {
    let mut fx = fixture();
    // An hour into period 1900 with the finality update signed in 1898:
    // the producer has not published since. Refused before any period
    // update is read, so later files in the bucket change nothing.
    let now = period_start(1900) + Duration::from_secs(3600);
    for p in [1899, 1900] {
        fx.files.0.insert(paths::update(p), b"not read".to_vec());
    }
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, now);
    assert_eq!(
        r,
        Err(HeadError::Stale {
            signed: 1898,
            current: 1900
        })
    );
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("signed in period 1898") && msg.contains("clock is in period 1900"),
        "{msg}"
    );
    assert!(msg.contains("has not published since"), "{msg}");
    assert!(
        reads(&fx, now)
            .iter()
            .all(|f| !f.starts_with("head/updates/")),
        "{:?}",
        reads(&fx, now)
    );
}

#[test]
fn the_period_after_the_signing_period_still_verifies() {
    let mut fx = fixture();
    // In period 1899 with the finality update signed in 1898: lag, not
    // staleness. No period update is needed, so none is read.
    fx.files.0.retain(|k, _| !k.starts_with("head/updates/"));
    let now = period_start(1899) + Duration::from_secs(3600);
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, now).unwrap();
    assert_eq!(h.execution.block_number, 26_310_853);
    assert_eq!(h.updates_applied, 0);
}

#[test]
fn a_head_two_periods_on_applies_the_updates_between() {
    let fx = fixture_1900();
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now).unwrap();
    assert_eq!(h.updates_applied, 2, "1898 and 1899, not 1900");
    assert_eq!(h.execution.block_number, 26_327_404);
    assert_eq!(
        h.execution.block_hash,
        "0x4fc8b6c654c2a14171aee6474d12312088fa4f2a21f5df74eb97edb5f99ba8db"
            .parse::<B256>()
            .unwrap()
    );
    // The finality update's own finalized header.
    assert_eq!(h.slot, 15_566_847);
    assert_eq!(h.period, 1900);
    assert!(h.participants > 341, "{}", h.participants);
    assert_eq!(
        reads(&fx, fx.now),
        vec![
            paths::bootstrap(&fx.checkpoint),
            paths::FINALITY.to_string(),
            paths::update(1898),
            paths::update(1899),
        ]
    );
}

#[test]
fn the_signing_periods_own_update_is_not_read() {
    let mut fx = fixture_1900();
    // The producer publishes 1900's update for other light clients; this
    // verifier has the 1900 committee from 1899's update and never reads it.
    fx.files
        .0
        .insert(paths::update(1900), b"not an update".to_vec());
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now).unwrap();
    assert_eq!(h.execution.block_number, 26_327_404);
    fx.files.0.remove(&paths::update(1900));
    assert!(verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now).is_ok());
}

#[test]
fn a_missing_update_between_is_a_broken_bucket() {
    for p in [1898, 1899] {
        let mut fx = fixture_1900();
        fx.files.0.remove(&paths::update(p));
        let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
        assert_eq!(r, Err(HeadError::Missing(paths::update(p))));
    }
}

#[test]
fn an_update_from_the_wrong_period_is_rejected() {
    let mut fx = fixture_1900();
    // The 2026-10-31 set's 1897 update in 1898's slot: it attests a 1897
    // header, so it is not 1898's update whatever it proves.
    let wrong = std::fs::read(format!("{FIX}/update-1897.json")).unwrap();
    fx.files.0.insert(paths::update(1898), wrong);
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    let Err(HeadError::Update {
        period: 1898,
        error,
    }) = &r
    else {
        panic!("{r:?}");
    };
    assert!(error.contains("period 1897"), "{error}");
}

#[test]
fn an_update_replayed_under_a_later_period_is_refused() {
    // Update 1900 attests slot 15,564,866, above its finalized 15,564,800
    // and above anything the store has finalized: a relevance check that
    // compares slots alone does not refuse a copy of it. Its file name
    // does: 1900's bytes in 1899's slot attest period 1900.
    let mut fx = fixture_1900();
    let u = fx.files.0[&paths::update(1900)].clone();
    fx.files.0.insert(paths::update(1899), u.clone());
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    let Err(HeadError::Update {
        period: 1899,
        error,
    }) = &r
    else {
        panic!("{r:?}");
    };
    assert!(error.contains("period 1900"), "{error}");

    // The replay as a way to keep the head alive: 1900's update copied
    // into every later period while the clock runs on. The finality update
    // is still the one signed in 1900, so the head is stale from 1902
    // whatever the update files say.
    let mut fx = fixture_1900();
    for p in [1901, 1902] {
        fx.files.0.insert(paths::update(p), u.clone());
    }
    let ok = period_start(1901) + Duration::from_secs(3600);
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, ok).unwrap();
    assert_eq!(h.execution.block_number, 26_327_404);
    let later = period_start(1902) + Duration::from_secs(60);
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, later);
    assert_eq!(
        r,
        Err(HeadError::Stale {
            signed: 1900,
            current: 1902
        })
    );
}

#[test]
fn a_slot_zero_finalized_header_is_not_a_head() {
    // Helios takes a finalized header at slot 0 for "nothing finalized yet"
    // and checks none of its proofs; the genuine signature covers only the
    // attested header. So these execution fields are unauthenticated and
    // must not come back as the head.
    let mut fx = fixture();
    let f = fx.files.0.get_mut(paths::FINALITY).unwrap();
    *f = edit_json(f, |v| {
        let h = &mut v["data"]["finalized_header"];
        h["beacon"]["slot"] = "0".into();
        h["execution"]["state_root"] = format!("0x{}", "11".repeat(32)).into();
        h["execution"]["block_hash"] = format!("0x{}", "22".repeat(32)).into();
        h["execution"]["block_number"] = "1".into();
    });
    let r = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now);
    assert!(matches!(r, Err(HeadError::Finality(_))), "{r:?}");
}

#[test]
fn finality_needs_two_thirds_of_the_committee() {
    // A genuinely signed subquorum update cannot be built without keys;
    // the rule itself is checked here, and every fixture is a supermajority.
    assert!(!has_quorum(341));
    assert!(has_quorum(342));
    assert_eq!(COMMITTEE_SIZE, 512);
    let fx = fixture();
    let h = verify(&fx.files, &Chain::mainnet(), fx.checkpoint, fx.now).unwrap();
    assert!(has_quorum(h.participants));
}
