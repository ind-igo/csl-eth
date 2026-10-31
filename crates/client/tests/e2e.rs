//! Producer to client over a directory: synthetic state with every shape
//! the workload names (profile §2, PoC §M1), every present key verified,
//! every absent key proven absent by the trie, every injected fault ending
//! in `Insufficient` or a correct answer, never a false absence.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{HashBuilder, Nibbles, KECCAK_EMPTY};
use csl_eth_client::{Cost, DirDriver, Driver, Got, Read, Reason, Snapshot, Want};
use csl_eth_store::{
    produce, table_path, trie::AbsentBy, AccountLeaf, Head, TABLE_ACCOUNT_NODES,
    TABLE_STORAGE_NODES,
};
use csl_eth_trie::{encode_word, path_of, Account, Invalid};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{
    collections::{BTreeMap, HashMap},
    path::PathBuf,
};

struct World {
    accounts: Vec<AccountLeaf>,
    code: HashMap<B256, Vec<u8>>,
    head: Head,
}

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

/// `n` accounts: a third with storage (two of them deep), a quarter with
/// code (some above the blob threshold), plus a pair sharing a long path
/// prefix so the account trie has an extension to miss through.
fn world(n: usize, seed: u64) -> World {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut by_key: BTreeMap<B256, AccountLeaf> = BTreeMap::new();
    let mut code = HashMap::new();
    let mut i = 0usize;
    while by_key.len() < n {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        if i == 0 || i == 1 {
            // Two keys sharing 60 nibbles: the trie puts an extension of
            // 60 nibbles above their branch, with the leaves at depth 61
            // (the deepest position the profile's key can hold is 62).
            h = [0x33; 32];
            h[30] = if i == 0 { 0x10 } else { 0x70 };
        }
        let hashed = B256::from(h);
        let mut storage: Vec<(B256, U256)> = Vec::new();
        if i.is_multiple_of(3) {
            let slots = if i == 3 || i == 6 {
                3000
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
    let accounts: Vec<AccountLeaf> = by_key.into_values().collect();
    let head = Head {
        block_hash: B256::repeat_byte(0xAB),
        block_number: 24_400_000,
        timestamp: 1_761_800_000,
        state_root: state_root(&accounts),
    };
    World {
        accounts,
        code,
        head,
    }
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "csl-eth-e2e-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn random_absent(rng: &mut ChaCha8Rng, present: &BTreeMap<B256, ()>) -> B256 {
    loop {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        let h = B256::from(h);
        if !present.contains_key(&h) {
            return h;
        }
    }
}

#[test]
fn every_shape_reads_correctly_and_within_budget() {
    let w = world(3000, 1);
    let dir = scratch("shapes");
    let produced = produce(&dir, &w.head, "", w.accounts.iter().cloned(), &w.code).unwrap();
    let st = &produced.stats;
    assert_eq!(st.accounts, 3000);
    assert!(st.code_blobs > 0 && st.code_entries > st.code_blobs);
    assert!(st.storage_tries > 0 && st.storage_nodes > 0);
    eprintln!("produced: {st:?}");

    let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
    assert_eq!(snap.manifest().block_number, 24_400_000);
    // The model puts a stored key within ε pages of its prediction and an
    // absent key within ε + 1: a round that asks for that span around every
    // predicted page is the one round the claims below count.
    let eps = snap
        .manifest()
        .table(TABLE_ACCOUNT_NODES)
        .unwrap()
        .epsilon_pages as u64;
    snap.hint = csl_eth_client::Hint::symmetric(eps + 1);

    // Present accounts: verified, one round each on a random path. The
    // crafted pair sits under a 60-nibble extension that speculation to
    // depth 9 cannot reach, so it alone costs two repairs; a repair whose
    // page a neighbouring depth's span already fetched costs no round.
    let mut max_cost = Cost::default();
    let mut repaired = 0;
    for a in &w.accounts {
        let (r, c) = snap.account(&a.hashed);
        assert_eq!(r, Read::Verified(a.account), "{}", a.hashed);
        if a.hashed[0] == 0x33 && a.hashed[1] == 0x33 {
            assert_eq!(c.repairs, 2, "crafted pair: {c:?}");
            assert!((1..=3).contains(&c.rounds), "crafted pair: {c:?}");
            repaired += 1;
            continue;
        }
        assert_eq!((c.repairs, c.rounds), (0, 1), "{}: {c:?}", a.hashed);
        max_cost.requests = max_cost.requests.max(c.requests);
        max_cost.bytes = max_cost.bytes.max(c.bytes);
    }
    assert_eq!(repaired, 2);
    eprintln!("account present: max {max_cost:?}");

    // Absent accounts: every one proven by the trie, with the shapes counted.
    let present: BTreeMap<B256, ()> = w.accounts.iter().map(|a| (a.hashed, ())).collect();
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    let mut shapes: HashMap<AbsentBy, usize> = HashMap::new();
    for _ in 0..1000 {
        let k = random_absent(&mut rng, &present);
        let (r, c) = snap.account(&k);
        let Read::VerifiedAbsent(by) = r else {
            panic!("absent {k} gave {r:?}")
        };
        *shapes.entry(by).or_default() += 1;
        assert_eq!(c.rounds, 1, "{k}: {c:?}");
    }
    // Through the extension: a key sharing the pair's first byte but not
    // the next 61 nibbles.
    let mut k = [0x33u8; 32];
    k[5] = 0x44;
    let (r, _) = snap.account(&B256::from(k));
    assert_eq!(r, Read::VerifiedAbsent(AbsentBy::ExtensionMismatch));
    // Under the pair's branch, a slot neither 1 nor 7.
    let mut k = [0x33u8; 32];
    k[30] = 0x50;
    let (r, _) = snap.account(&B256::from(k));
    assert_eq!(r, Read::VerifiedAbsent(AbsentBy::EmptySlot));
    // Reaching the first of the pair with a different tail.
    let mut k = [0x33u8; 32];
    k[30] = 0x10;
    k[31] = 0x1F;
    let (r, _) = snap.account(&B256::from(k));
    assert_eq!(r, Read::VerifiedAbsent(AbsentBy::LeafMismatch));
    *shapes.entry(AbsentBy::ExtensionMismatch).or_default() += 1;
    eprintln!("absent shapes: {shapes:?}");
    assert!(shapes.contains_key(&AbsentBy::EmptySlot));
    assert!(shapes.contains_key(&AbsentBy::LeafMismatch));

    // Storage: every present slot, absent slots in accounts with storage,
    // slots of accounts with empty storage (no storage fetch), slots of
    // absent accounts.
    let mut storage_max = Cost::default();
    let mut slots_read = 0;
    for a in w
        .accounts
        .iter()
        .filter(|a| !a.storage.is_empty() && a.hashed[0] != 0x33)
    {
        let sample: Vec<_> = a
            .storage
            .iter()
            .step_by((a.storage.len() / 20).max(1))
            .collect();
        for (s, v) in sample {
            let (r, c) = snap.storage(&a.hashed, s);
            assert_eq!(r, Read::Verified(*v));
            storage_max.requests = storage_max.requests.max(c.requests);
            storage_max.bytes = storage_max.bytes.max(c.bytes);
            storage_max.rounds = storage_max.rounds.max(c.rounds);
            slots_read += 1;
        }
        let absent_slot =
            random_absent(&mut rng, &a.storage.iter().map(|(k, _)| (*k, ())).collect());
        let (r, _) = snap.storage(&a.hashed, &absent_slot);
        assert!(
            matches!(r, Read::VerifiedAbsent(by) if by != AbsentBy::EmptyTrie),
            "{r:?}"
        );
    }
    eprintln!("storage present: {slots_read} reads, max {storage_max:?}");
    assert_eq!(
        storage_max.rounds, 1,
        "storage speculation to depth 7 covers every synthetic trie"
    );
    let empty = w.accounts.iter().find(|a| a.storage.is_empty()).unwrap();
    let (r, c) = snap.storage(&empty.hashed, &B256::repeat_byte(9));
    assert_eq!(r, Read::VerifiedAbsent(AbsentBy::EmptyTrie));
    let (ra, ca) = snap.account(&empty.hashed);
    assert!(matches!(ra, Read::Verified(_)));
    // The storage pages are speculated in the account's round, so an
    // empty storage root costs bytes it did not need but never a round.
    assert_eq!(c.rounds, ca.rounds, "empty storage costs no extra round");
    assert!(c.requests >= ca.requests);
    let (r, _) = snap.storage(&random_absent(&mut rng, &present), &B256::repeat_byte(9));
    assert!(r.is_absent());

    // Code: inline, blob, empty, unknown.
    let mut blobs = 0;
    for a in w
        .accounts
        .iter()
        .filter(|a| a.account.code_hash != KECCAK_EMPTY)
    {
        let (r, c) = snap.code(&a.account.code_hash);
        assert_eq!(r, Read::Verified(w.code[&a.account.code_hash].clone()));
        if c.rounds == 2 {
            blobs += 1;
        }
    }
    assert!(blobs > 0);
    let (r, c) = snap.code(&KECCAK_EMPTY);
    assert_eq!((r, c.requests), (Read::Verified(vec![]), 0));
    let (r, _) = snap.code(&B256::repeat_byte(0xEE));
    assert!(matches!(r, Read::Insufficient(Reason::Missing { .. })));

    // A different trusted root: the snapshot refuses to open.
    assert!(Snapshot::open(DirDriver::new(&dir), None, B256::repeat_byte(1)).is_err());

    std::fs::remove_dir_all(&dir).ok();
}

/// Flip bytes all over the node tables, truncate files, remove a table:
/// every read is still the right answer or `Insufficient`; never a wrong
/// value and never an absence for a present key.
#[test]
fn faults_never_become_false_answers() {
    let w = world(600, 2);
    let dir = scratch("faults");
    let produced = produce(&dir, &w.head, "", w.accounts.iter().cloned(), &w.code).unwrap();
    let bucket = DirDriver::new(&dir);
    let present: BTreeMap<B256, ()> = w.accounts.iter().map(|a| (a.hashed, ())).collect();
    let mut rng = ChaCha8Rng::seed_from_u64(3);
    let mut absent_keys = Vec::new();
    for _ in 0..100 {
        absent_keys.push(random_absent(&mut rng, &present));
    }

    fn check_with<D: Driver>(
        w: &World,
        absent_keys: &[B256],
        snap: &mut Snapshot<D>,
        label: &str,
    ) -> (usize, usize) {
        let mut insufficient = 0;
        let mut ok = 0;
        for a in &w.accounts {
            match snap.account(&a.hashed).0 {
                Read::Verified(v) => {
                    assert_eq!(v, a.account, "{label}: wrong value");
                    ok += 1;
                }
                Read::VerifiedAbsent(by) => {
                    panic!("{label}: false absence {by:?} for {}", a.hashed)
                }
                Read::Insufficient(_) => insufficient += 1,
            }
            if let Some((s, v)) = a.storage.first() {
                match snap.storage(&a.hashed, s).0 {
                    Read::Verified(got) => assert_eq!(got, *v, "{label}: wrong storage"),
                    Read::VerifiedAbsent(by) => panic!("{label}: false storage absence {by:?}"),
                    Read::Insufficient(_) => insufficient += 1,
                }
            }
        }
        for k in absent_keys {
            match snap.account(k).0 {
                Read::Verified(_) => panic!("{label}: absent key reported present"),
                Read::VerifiedAbsent(_) => ok += 1,
                Read::Insufficient(_) => insufficient += 1,
            }
        }
        (ok, insufficient)
    }
    let check =
        |snap: &mut Snapshot<DirDriver>, label: &str| check_with(&w, &absent_keys, snap, label);

    let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
    let (ok, ins) = check(&mut snap, "clean");
    assert_eq!(ins, 0);
    eprintln!("clean: {ok} ok");

    let acct_file = dir.join(table_path(&w.head.block_hash, TABLE_ACCOUNT_NODES));
    let stor_file = dir.join(table_path(&w.head.block_hash, TABLE_STORAGE_NODES));
    let clean_acct = std::fs::read(&acct_file).unwrap();
    let clean_stor = std::fs::read(&stor_file).unwrap();

    // Random byte flips in the account and storage tables, past the header.
    for round in 0..6 {
        let mut a = clean_acct.clone();
        let mut s = clean_stor.clone();
        for _ in 0..40 {
            let i = rng.random_range(4096..a.len());
            a[i] ^= 1 << rng.random_range(0..8);
            let j = rng.random_range(4096..s.len());
            s[j] ^= 1 << rng.random_range(0..8);
        }
        std::fs::write(&acct_file, &a).unwrap();
        std::fs::write(&stor_file, &s).unwrap();
        let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
        let (ok, ins) = check(&mut snap, &format!("flips round {round}"));
        eprintln!("flips round {round}: {ok} ok, {ins} insufficient");
        assert!(ins > 0, "40 flips per table should break something");
    }

    // Truncated tables.
    std::fs::write(&acct_file, &clean_acct[..clean_acct.len() / 2]).unwrap();
    std::fs::write(&stor_file, &clean_stor).unwrap();
    let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
    let (_, ins) = check(&mut snap, "truncated");
    assert!(ins > 0);

    // A table removed entirely: the snapshot still opens, accounts still
    // verify, and every storage read is Insufficient with the table's error.
    std::fs::write(&acct_file, &clean_acct).unwrap();
    std::fs::remove_file(&stor_file).unwrap();
    let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
    let (ok, ins) = check(&mut snap, "no storage table");
    assert!(
        ok > 0 && ins > 0,
        "accounts verify, storage is insufficient: {ok} ok, {ins} insufficient"
    );
    let with_storage = w.accounts.iter().find(|a| !a.storage.is_empty()).unwrap();
    assert!(
        matches!(
            snap.storage(&with_storage.hashed, &with_storage.storage[0].0)
                .0,
            Read::Insufficient(Reason::Run { table: 1, .. })
        ),
        "storage names the missing table"
    );
    std::fs::write(&stor_file, &clean_stor).unwrap();

    // A node omitted from its page is Missing then Insufficient, never
    // absent: serve the storage table from a bucket that drops every read
    // of one page.
    struct DropPage(DirDriver, u64);
    impl Driver for DropPage {
        fn fetch(&self, wants: &[Want]) -> Vec<Got> {
            let dropped = self.1 * 4096;
            wants
                .iter()
                .map(|w| match w {
                    Want::Range { rel, off, len }
                        if rel.ends_with("account_nodes.run")
                            && *off < dropped + 4096
                            && off + *len as u64 > dropped =>
                    {
                        Err("dropped".to_string())
                    }
                    w => self.0.fetch(std::slice::from_ref(w)).remove(0),
                })
                .collect()
        }
    }
    let pages = produced
        .manifest
        .table(TABLE_ACCOUNT_NODES)
        .unwrap()
        .page_count;
    let mut snap =
        Snapshot::open(DropPage(bucket, pages / 2 + 1), None, w.head.state_root).unwrap();
    let (ok, ins) = check_with(&w, &absent_keys, &mut snap, "dropped page");
    eprintln!("dropped page: {ok} ok, {ins} insufficient");
    assert!(ins > 0 && ok > 0);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn producer_rejects_wrong_roots_and_missing_code() {
    let w = world(50, 4);
    let dir = scratch("reject");
    let mut bad_head = w.head;
    bad_head.state_root = B256::repeat_byte(1);
    assert!(matches!(
        produce(&dir, &bad_head, "", w.accounts.iter().cloned(), &w.code),
        Err(csl_eth_store::ProduceError::StateRoot { .. })
    ));

    let mut accounts = w.accounts.clone();
    let i = accounts.iter().position(|a| !a.storage.is_empty()).unwrap();
    accounts[i].storage.pop();
    assert!(matches!(
        produce(&dir, &w.head, "", accounts.iter().cloned(), &w.code),
        Err(csl_eth_store::ProduceError::StorageRoot { .. })
    ));

    let mut code = w.code.clone();
    let some = *code.keys().next().unwrap();
    code.remove(&some);
    assert!(matches!(
        produce(&dir, &w.head, "", w.accounts.iter().cloned(), &code),
        Err(csl_eth_store::ProduceError::Code { .. })
    ));

    let mut rev = w.accounts.clone();
    rev.reverse();
    assert!(matches!(
        produce(&dir, &w.head, "", rev, &w.code),
        Err(csl_eth_store::ProduceError::Unsorted { .. })
    ));

    assert!(produce(&dir, &w.head, "", w.accounts.iter().cloned(), &w.code).is_ok());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn walk_invalid_shapes_are_insufficient_not_absent() {
    // A snapshot whose state_root the client trusts but whose root node
    // was replaced by another valid node: HashMismatch at the root.
    let w = world(100, 5);
    let dir = scratch("invalid");
    produce(&dir, &w.head, "", w.accounts.iter().cloned(), &w.code).unwrap();
    let other = world(100, 6);
    let dir2 = scratch("invalid2");
    produce(
        &dir2,
        &other.head,
        "",
        other.accounts.iter().cloned(),
        &other.code,
    )
    .unwrap();
    let f = dir.join(table_path(&w.head.block_hash, TABLE_ACCOUNT_NODES));
    std::fs::copy(
        dir2.join(table_path(&other.head.block_hash, TABLE_ACCOUNT_NODES)),
        &f,
    )
    .unwrap();
    // The manifest still names the real root and page counts; opening may
    // fail on the model root or reads may fail on shape. Either is fine;
    // what is never fine is an answer.
    if let Ok(mut snap) = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root) {
        for a in w.accounts.iter().take(20) {
            let (r, _) = snap.account(&a.hashed);
            assert!(
                matches!(
                    r,
                    Read::Insufficient(
                        Reason::Invalid {
                            what: Invalid::HashMismatch,
                            ..
                        } | Reason::Run { .. }
                            | Reason::Missing { .. }
                    )
                ),
                "{r:?}"
            );
        }
    }
    let _ = Nibbles::new();
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&dir2).ok();
}

/// Requests per lookup against model bytes as ε varies. Each page the
/// prediction is off is one dependent request, so this is the number that
/// decides the profile's ε, printed for the decisions log and asserted
/// only for correctness.
#[test]
fn epsilon_against_requests_per_read() {
    let w = world(3000, 11);
    let present: BTreeMap<B256, ()> = w.accounts.iter().map(|a| (a.hashed, ())).collect();
    for eps in [1u16, 2, 4] {
        let dir = scratch(&format!("eps{eps}"));
        let produced = csl_eth_store::produce_with(
            &dir,
            &w.head,
            "",
            w.accounts.iter().cloned(),
            &w.code,
            csl_eth_store::ProduceOptions {
                epsilon: eps,
                ..Default::default()
            },
        )
        .unwrap();
        let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
        let mut rng = ChaCha8Rng::seed_from_u64(eps as u64);
        let (mut req, mut bytes, mut n, mut max) = (0u64, 0u64, 0u64, 0u64);
        for a in w.accounts.iter().step_by(3) {
            let (r, c) = snap.account(&a.hashed);
            assert_eq!(r, Read::Verified(a.account));
            req += c.requests;
            bytes += c.bytes;
            max = max.max(c.requests);
            n += 1;
        }
        let (mut areq, mut arounds, mut an) = (0u64, 0u64, 0u64);
        for _ in 0..500 {
            let k = random_absent(&mut rng, &present);
            let (r, c) = snap.account(&k);
            assert!(r.is_absent());
            areq += c.requests;
            arounds += c.rounds as u64;
            an += 1;
        }
        let acct = produced.stats.tables[TABLE_ACCOUNT_NODES as usize].unwrap();
        eprintln!(
            "ε={eps}: account table {} pages, model {} B; present read mean {:.1} requests / {:.0} B, max {max}; absent read mean {:.2} requests / {:.2} rounds",
            acct.pages,
            acct.model_bytes,
            req as f64 / n as f64,
            bytes as f64 / n as f64,
            areq as f64 / an as f64,
            arounds as f64 / an as f64,
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
