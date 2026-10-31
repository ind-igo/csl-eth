//! The fault table over a synthetic bucket: every named fault applied to
//! the responses, every shape read under it through both clients, and the
//! table passes (no wrong value, no false absence) with each fault caught
//! the way its row says.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{HashBuilder, KECCAK_EMPTY};
use csl_eth_snap::faults::{run_table, Fault, Mode, Options};
use csl_eth_snap::{Slice, SliceHead};
use csl_eth_store::{produce, AccountLeaf, Head};
use csl_eth_trie::{encode_word, path_of, Account};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};

fn storage_root(slots: &[(B256, U256)]) -> B256 {
    let mut hb = HashBuilder::default();
    for (k, v) in slots {
        hb.add_leaf(path_of(k), &encode_word(v));
    }
    hb.root()
}

fn state_root(accounts: &[AccountLeaf]) -> B256 {
    let mut hb = HashBuilder::default();
    for a in accounts {
        hb.add_leaf(path_of(&a.hashed), &a.account.encode());
    }
    hb.root()
}

/// The e2e world, as a slice: `n` accounts, a third with storage (two of
/// them deep), a quarter with code (some above the blob threshold), and a
/// pair under a long extension.
fn world(n: usize, seed: u64) -> (Slice, Vec<AccountLeaf>, Head) {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut by_key: BTreeMap<B256, AccountLeaf> = BTreeMap::new();
    let mut code = HashMap::new();
    let mut i = 0usize;
    while by_key.len() < n {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        if i == 0 || i == 1 {
            h = [0x33; 32];
            h[30] = if i == 0 { 0x10 } else { 0x70 };
        }
        let hashed = B256::from(h);
        let mut storage: Vec<(B256, U256)> = Vec::new();
        if i.is_multiple_of(3) {
            let slots = if i == 3 || i == 6 {
                2000
            } else {
                rng.random_range(1..=40)
            };
            let mut m = BTreeMap::new();
            while m.len() < slots {
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut s);
                let w = U256::from(rng.random::<u64>() | 1);
                m.insert(B256::from(s), w);
            }
            storage = m.into_iter().collect();
        }
        let code_hash = if i % 4 == 1 {
            let len = if i % 8 == 1 {
                rng.random_range(1..=3000)
            } else {
                rng.random_range(3969..=24576)
            };
            let mut c = vec![0u8; len];
            rng.fill_bytes(&mut c);
            let h = keccak256(&c);
            code.insert(h, c);
            h
        } else {
            KECCAK_EMPTY
        };
        let account = Account {
            nonce: rng.random_range(0..1000),
            balance: U256::from(rng.random::<u128>()),
            storage_root: storage_root(&storage),
            code_hash,
        };
        by_key.insert(
            hashed,
            AccountLeaf {
                hashed,
                account,
                storage,
            },
        );
        i += 1;
    }
    let leaves: Vec<AccountLeaf> = by_key.into_values().collect();
    let head = Head {
        block_hash: B256::repeat_byte(0xAB),
        block_number: 24_400_000,
        timestamp: 1_761_800_000,
        state_root: state_root(&leaves),
    };
    let mut storage: HashMap<B256, Vec<(B256, U256)>> = HashMap::new();
    for a in &leaves {
        if !a.storage.is_empty() {
            storage.insert(a.account.storage_root, a.storage.clone());
        }
    }
    let slice = Slice {
        head: SliceHead {
            block_hash: head.block_hash,
            block_number: head.block_number,
            timestamp: head.timestamp,
            state_root: head.state_root,
            prefix: String::new(),
            fetched_at: 0,
            accounts: leaves.len() as u64,
            storage_tries: storage.len() as u64,
            storage_slots: leaves.iter().map(|a| a.storage.len() as u64).sum(),
            codes: code.len() as u64,
            peers_used: 0,
            bytes_in: 0,
            requests: 0,
            wall_ms: 0,
            repivots: 0,
        },
        accounts: leaves.iter().map(|a| (a.hashed, a.account)).collect(),
        storage,
        code,
        boundary: Vec::new(),
    };
    (slice, leaves, head)
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "csl-eth-faults-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn every_fault_is_caught_and_none_becomes_a_false_answer() {
    let (slice, leaves, head) = world(900, 2);
    let dir = scratch("table");
    produce(&dir, &head, "", leaves.iter().cloned(), &slice.code).unwrap();

    let o = Options {
        keys: 40,
        rate: 1.0,
        seed: 1,
        mode: Mode::Both,
        top_levels: 0,
        faults: Fault::ALL.to_vec(),
    };
    let t = run_table(&slice, &dir, &o).unwrap();
    for r in &t.faults {
        eprintln!(
            "{:<22} open_error={:?} faulted={} reads={} correct={} insufficient={} failures={} reasons={:?}",
            r.name,
            r.open_error,
            r.faulted,
            r.total.reads,
            r.total.correct,
            r.total.insufficient,
            r.total.failures(),
            r.reasons
        );
    }
    for f in &t.failures {
        eprintln!("failure: {f:?}");
    }
    assert!(t.pass, "a fault produced a wrong value or a false absence");
    assert!(t.failures.is_empty(), "{:?}", t.failures);
    assert_eq!(t.faults.len(), Fault::ALL.len());
    assert!(t.shapes["account_present"] == 40 && t.shapes["slot_present"] == 40);
    assert!(t.shapes["code"] > 0 && t.shapes["slot_empty_storage"] > 0);
    assert!(
        !t.shapes.contains_key("account_outside"),
        "a whole-trie slice has no outside"
    );

    // The control row: every read right, through both clients.
    let none = t.row("none").unwrap();
    assert_eq!(none.total.insufficient, 0);
    assert_eq!(none.total.correct, none.total.reads);
    assert_eq!(none.faulted, 0);
    assert!(none.counts("baseline", "account_present").unwrap().correct == 40);

    // Every row that opened made the same reads, and every fault fired.
    for r in &t.faults {
        if r.open_error.is_none() {
            assert_eq!(r.total.reads, none.total.reads, "{}", r.name);
            if r.name != "none" {
                assert!(r.faulted > 0, "{} never fired", r.name);
            }
        }
    }

    // How each was caught.
    let caught = |name: &str, needle: &str| {
        let r = t.row(name).unwrap();
        assert!(r.total.insufficient > 0, "{name}: nothing insufficient");
        assert!(
            r.reasons.keys().any(|k| k.contains(needle)),
            "{name}: expected a {needle} reason, saw {:?}",
            r.reasons
        );
    };
    caught("node_omitted", "Missing");
    caught("page_malformed", "malformed: offsets");
    caught("forged_fence", "Missing");
    caught("fence_excludes", "malformed: key outside fences");
    // Narrowed fences still cover every entry, and every node a walk
    // needs is an entry: the row is all correct and that is the point.
    let gap = t.row("fence_gap").unwrap();
    assert_eq!(gap.total.correct, gap.total.reads);
    caught("truncated_page", "short range");
    caught("wrong_run_page", "Run(");
    caught("wrong_range", "Run(");
    caught("bit_flip", "Run(");
    caught("model_page_tamper", "ModelMismatch");
    caught("page0_tamper", "ModelMismatch");
    caught("stale_value", "HashMismatch");
    caught("stale_value", "Code(bytecode does not hash");
    caught("stale_page", "HashMismatch");
    caught("missing_range", "io: not found");
    caught("http_error", "500");
    caught("truncated_blob", "Blob(does not hash to its name");

    // The manifest: a forged state_root refuses the open; forged model
    // roots open but every read is Insufficient; a forged file root is
    // not checked by anything (the trie proves values) so every read is
    // still right.
    let sr = t.row("manifest_state_root").unwrap();
    assert!(
        sr.open_error
            .as_deref()
            .is_some_and(|e| e.contains("state_root")),
        "{:?}",
        sr.open_error
    );
    assert_eq!(sr.total.reads, 0);
    let mr = t.row("manifest_model_root").unwrap();
    assert!(mr.open_error.is_none());
    assert_eq!(mr.total.insufficient, mr.total.reads);
    assert!(
        mr.reasons.keys().all(|k| k.contains("ModelMismatch")),
        "{:?}",
        mr.reasons
    );
    let tr = t.row("manifest_table_root").unwrap();
    assert_eq!(tr.total.correct, tr.total.reads);
    // Whole files cut in half: `latest` is no longer a block hash.
    assert!(t.row("truncated_file").unwrap().open_error.is_some());
    // Page 0 tampered on every table: nothing can route.
    let p0 = t.row("page0_tamper").unwrap();
    assert_eq!(p0.total.insufficient, p0.total.reads);

    std::fs::remove_dir_all(&dir).ok();
}

/// At a partial rate the host is flaky rather than hostile: reads split
/// between right and Insufficient, still never wrong.
#[test]
fn a_flaky_host_splits_reads_between_right_and_insufficient() {
    let (slice, leaves, head) = world(300, 5);
    let dir = scratch("flaky");
    produce(&dir, &head, "", leaves.iter().cloned(), &slice.code).unwrap();
    let o = Options {
        keys: 30,
        rate: 0.3,
        seed: 9,
        mode: Mode::Path,
        top_levels: 0,
        faults: vec![
            Fault::MissingRange,
            Fault::HttpError,
            Fault::BitFlip,
            Fault::StalePage,
        ],
    };
    let t = run_table(&slice, &dir, &o).unwrap();
    assert!(t.pass, "{:?}", t.failures);
    for r in &t.faults {
        eprintln!("{} at 0.3: {:?} {:?}", r.name, r.total, r.reasons);
        assert!(
            r.total.correct > 0 && r.total.insufficient > 0,
            "{}: {:?}",
            r.name,
            r.total
        );
    }
    std::fs::remove_dir_all(&dir).ok();
}
