//! Producer to client over a directory: synthetic state with every shape
//! the workload names (profile §2, PoC §M1), every present key verified,
//! every absent key proven absent by the trie, every injected fault ending
//! in `Insufficient` or a correct answer, never a false absence.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{HashBuilder, Nibbles, KECCAK_EMPTY};
use csl_eth_client::{
    Cost, DirDriver, Driver, Got, Origin, Pending, Read, Reason, Snapshot, Trie, WalkTrace, Want,
};
use csl_eth_store::{
    produce, table_path, trie::AbsentBy, AccountLeaf, Head, TABLE_ACCOUNT_NODES,
    TABLE_STORAGE_NODES,
};
use csl_eth_trie::{encode_word, path_of, Account, Invalid, NodeKey, Shape, Step};
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

/// The rounds a read with no repairs takes: one, plus one when the read
/// had to fetch a model page first (a cold neighbourhood: the model page
/// round, then the data pages it predicts).
fn warm_rounds(c: &Cost) -> u32 {
    1 + u32::from(c.model_pages > 0)
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
        assert_eq!((c.repairs, c.rounds), (0, warm_rounds(&c)), "{}: {c:?}", a.hashed);
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
        assert_eq!(c.rounds, warm_rounds(&c), "{k}: {c:?}");
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
            storage_max.rounds = storage_max.rounds.max(c.rounds - (warm_rounds(&c) - 1));
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
        "storage speculation to depth 7 covers every synthetic trie (model pages aside)"
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

/// The content-addressed baseline (profile §9) over the same bucket: the
/// same answers as the path-keyed read, every node one dependent round,
/// and a tampered node by hash is `Insufficient`, never a value.
#[test]
fn baseline_by_hash_agrees_and_costs_a_round_per_node() {
    let w = world(1500, 11);
    let dir = scratch("baseline");
    produce(&dir, &w.head, "", w.accounts.iter().cloned(), &w.code).unwrap();
    let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
    let eps = snap.manifest().table(TABLE_ACCOUNT_NODES).unwrap().epsilon_pages as u64;
    snap.hint = csl_eth_client::Hint::symmetric(eps + 1);

    let mut path_rounds = 0u64;
    let mut hash_rounds = 0u64;
    let mut hash_max = Cost::default();
    for a in w.accounts.iter().step_by(7) {
        let (p, pc) = snap.account(&a.hashed);
        let (h, hc) = snap.account_by_hash(&a.hashed);
        assert_eq!(p, Read::Verified(a.account));
        assert_eq!(h, p, "{}", a.hashed);
        // Every node on the path is one fetch and, unless the widened
        // round of an earlier node happened to bring its page, one round;
        // the aggregate below is where "serial" is asserted.
        assert!(hc.repairs >= 1 && hc.rounds >= 1, "{}: {hc:?}", a.hashed);
        assert!(hc.repairs as usize <= hc.nodes, "a node fetched by hash is a node walked (embedded ones are walked, not fetched)");
        path_rounds += pc.rounds as u64;
        hash_rounds += hc.rounds as u64;
        hash_max.rounds = hash_max.rounds.max(hc.rounds);
        hash_max.requests = hash_max.requests.max(hc.requests);
        hash_max.bytes = hash_max.bytes.max(hc.bytes);
    }
    eprintln!("rounds: path {path_rounds}, by hash {hash_rounds}; by hash max {hash_max:?}");
    assert!(hash_rounds > 3 * path_rounds, "the baseline is serial");

    // Absent keys: proven by the trie, the same shape either way.
    let present: BTreeMap<B256, ()> = w.accounts.iter().map(|a| (a.hashed, ())).collect();
    let mut rng = ChaCha8Rng::seed_from_u64(3);
    for _ in 0..50 {
        let k = random_absent(&mut rng, &present);
        let (p, _) = snap.account(&k);
        let (h, hc) = snap.account_by_hash(&k);
        assert!(p.is_absent() && h == p, "{k}: {p:?} / {h:?}");
        assert!(hc.rounds >= 1);
    }

    // Storage: account nodes then slot nodes, all by hash.
    let mut slots = 0;
    for a in w.accounts.iter().filter(|a| !a.storage.is_empty()).take(30) {
        let (s, v) = a.storage[a.storage.len() / 2];
        let (p, pc) = snap.storage(&a.hashed, &s);
        let (h, hc) = snap.storage_by_hash(&a.hashed, &s);
        assert_eq!(p, Read::Verified(v));
        assert_eq!(h, p);
        assert!(hc.rounds > pc.rounds, "{}: path {pc:?} hash {hc:?}", a.hashed);
        slots += 1;
    }
    assert!(slots > 0);
    let empty = w.accounts.iter().find(|a| a.storage.is_empty()).unwrap();
    let (r, _) = snap.storage_by_hash(&empty.hashed, &B256::repeat_byte(9));
    assert_eq!(r, Read::VerifiedAbsent(AbsentBy::EmptyTrie));

    // With the top levels cached, the baseline skips those rounds too.
    snap.top_levels = 3;
    let a = &w.accounts[5];
    let (_, first) = snap.account_by_hash(&a.hashed);
    let b = &w.accounts[6];
    let (r, second) = snap.account_by_hash(&b.hashed);
    assert_eq!(r, Read::Verified(b.account));
    assert!(second.repairs < first.repairs || first.repairs <= 3, "cache: {first:?} then {second:?}");
    snap.top_levels = 0;

    // Tamper with nodes_by_hash: a value byte flipped in the middle of the
    // table. Every read is still right or Insufficient.
    let rel = table_path(&snap.manifest().block_hash, csl_eth_store::TABLE_NODES_BY_HASH);
    let path = dir.join(&rel);
    let mut bytes = std::fs::read(&path).unwrap();
    let mut rng = ChaCha8Rng::seed_from_u64(9);
    for _ in 0..400 {
        let i = rng.random_range(4096..bytes.len());
        bytes[i] ^= 0x01;
    }
    std::fs::write(&path, &bytes).unwrap();
    let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
    let (mut ok, mut insufficient) = (0, 0);
    for a in w.accounts.iter().step_by(5) {
        match snap.account_by_hash(&a.hashed).0 {
            Read::Verified(got) => {
                assert_eq!(got, a.account);
                ok += 1;
            }
            Read::VerifiedAbsent(_) => panic!("tampering made {} absent", a.hashed),
            Read::Insufficient(_) => insufficient += 1,
        }
    }
    eprintln!("tampered nodes_by_hash: {ok} verified, {insufficient} insufficient");
    assert!(insufficient > 0, "400 flipped bytes hit something");
    std::fs::remove_dir_all(&dir).ok();
}

/// A directory host that records every want, round by round, so a test
/// can check what a read put on the wire and when.
struct Recording {
    dir: DirDriver,
    wants: std::sync::Mutex<Vec<Vec<Want>>>,
}

impl Recording {
    fn new(dir: &std::path::Path) -> Recording {
        Recording {
            dir: DirDriver::new(dir),
            wants: Default::default(),
        }
    }
}

impl Driver for Recording {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        self.wants.lock().unwrap().push(wants.to_vec());
        self.dir.fetch(wants)
    }
}

/// Check a traced node's shape against its own bytes, decoded here: a
/// branch's occupied slots, an extension's nibbles, a leaf's rest and value.
fn check_shape(bytes: &[u8], shape: &Shape) {
    use alloy_rlp::Decodable;
    use alloy_trie::nodes::TrieNode;
    let mut b = bytes;
    match (
        TrieNode::decode(&mut b).expect("a verified node decodes"),
        shape,
    ) {
        (
            TrieNode::Branch(br),
            Shape::Branch {
                occupied,
                next,
                taken,
            },
        ) => {
            assert_eq!(
                *occupied,
                br.state_mask.get(),
                "the branch's occupied slots"
            );
            assert_eq!(*taken, br.state_mask.is_bit_set(*next));
        }
        (TrieNode::Extension(e), Shape::Extension { nibbles, .. }) => {
            assert_eq!(*nibbles, e.key, "the extension's nibbles")
        }
        (TrieNode::Leaf(l), Shape::Leaf { rest, value, .. }) => {
            assert_eq!(*rest, l.key, "the leaf's rest of key");
            assert_eq!(*value, l.value);
        }
        (node, shape) => panic!("{node:?} traced as {shape:?}"),
    }
}

/// The child a decoded node commits to for the step after it.
fn committed_child(parent: &[u8], shape: &Shape) -> Option<alloy_trie::nodes::RlpNode> {
    use alloy_rlp::Decodable;
    use alloy_trie::nodes::TrieNode;
    let mut b = parent;
    match (TrieNode::decode(&mut b).ok()?, shape) {
        (TrieNode::Branch(br), Shape::Branch { next, .. }) => br
            .as_ref()
            .children()
            .find(|(i, _)| i == next)
            .and_then(|(_, c)| c.cloned()),
        (TrieNode::Extension(e), Shape::Extension { .. }) => Some(e.child),
        _ => None,
    }
}

/// Check one traced walk against the trie built independently from the
/// world (`reference`), the wants the read made, and the pages on disk.
#[allow(clippy::too_many_arguments)]
fn check_walk(
    wt: &WalkTrace,
    reference: &HashMap<NodeKey, Vec<u8>>,
    wants: &[Vec<Want>],
    dir: &std::path::Path,
    snap: &Snapshot<Recording>,
    owner: &B256,
    rounds: u32,
) {
    if wt.root == alloy_trie::EMPTY_ROOT_HASH {
        assert!(wt.nodes.is_empty());
        return;
    }
    assert_eq!(wt.nodes[0].step.key, NodeKey::ROOT);
    assert_eq!(
        wt.nodes[0].step.hash,
        Some(wt.root),
        "the root is what the walk trusted"
    );
    assert_eq!(wants.len() as u32, rounds, "one fetch per round");
    let tables = snap.tables();
    let mut embedded_bytes: HashMap<NodeKey, Vec<u8>> = HashMap::new();
    // The attempt that checked the node before this one: a walk checks
    // its nodes in order, so no node is checked before its parent.
    let mut parent_at = 0;
    for (i, n) in wt.nodes.iter().enumerate() {
        let s = &n.step;
        let failed = matches!(s.shape, Shape::Missing | Shape::Invalid { .. });
        assert_eq!(n.checked_at.is_none(), failed, "{s:?}");
        // The attempt at which this node's bytes were first in hand: 0 for
        // the cache and embedded nodes, else the round that fetched its page.
        let mut landed = parent_at;
        let bytes = match s.hash {
            Some(h) => {
                let b = reference
                    .get(&s.key)
                    .unwrap_or_else(|| panic!("{:?} is in the trie", s.key));
                assert_eq!(
                    keccak256(b),
                    h,
                    "the node hashes to what its parent committed"
                );
                assert_eq!(s.len, b.len());
                let tk = n.table_key.expect("a hashed node has a table key");
                let expect_tk = if wt.by_hash {
                    h.0
                } else if wt.trie == Trie::Account {
                    s.key.table_key().unwrap()
                } else {
                    s.key.storage_table_key(owner).unwrap()
                };
                assert_eq!(tk, expect_tk);
                match n.origin {
                    Origin::Page { table, page } => {
                        assert_eq!(table, wt.table);
                        let info = &tables[table as usize];
                        let ro = 4096 + (page - 1) * info.record_bytes;
                        let round = wants.iter().position(|ws| {
                            ws.iter().any(|w| match w {
                                Want::Range { rel, off, len } => {
                                    *rel == info.path
                                        && *off <= ro
                                        && ro + 4096 <= off + *len as u64
                                }
                                _ => false,
                            })
                        });
                        let round = round.unwrap_or_else(|| {
                            panic!("page {page} of {} was fetched by this read", info.name)
                        });
                        // Fetched in round r (1-based): in hand from attempt r.
                        landed = landed.max(round as u32 + 1);
                        let file = std::fs::read(dir.join(&info.path)).unwrap();
                        let pg = csl_run::Page::decode_with(
                            &file[ro as usize..ro as usize + 4096],
                            csl_eth_store::RUN_FORMAT.layout,
                            page == info.page_count,
                            page,
                        )
                        .unwrap();
                        assert_eq!(
                            pg.find(&tk).map(|e| e.value.clone()),
                            Some(b.clone()),
                            "the page holds the node"
                        );
                    }
                    Origin::Cache => {
                        assert!(wt.trie == Trie::Account && s.key.depth() < snap.top_levels);
                    }
                    o => panic!("a verified hashed node from {o:?}"),
                }
                b.clone()
            }
            None => {
                assert_eq!(n.origin, Origin::Embedded);
                assert!(n.table_key.is_none());
                embedded_bytes
                    .get(&s.key)
                    .cloned()
                    .expect("an embedded node follows its parent")
            }
        };
        if let Some(a) = n.checked_at {
            assert!(
                a <= rounds,
                "checked at attempt {a} of a {rounds}-round read"
            );
            // Never checked before its bytes landed, nor before its parent.
            // (Later is allowed: the path walk waits for all of the round's
            // depths, and a storage walk waits for its account's walk.)
            assert!(
                a >= landed,
                "{:?} landed by attempt {landed}, checked at {a}",
                s.key
            );
            parent_at = a;
            check_shape(&bytes, &s.shape);
        }
        // The next node is the child this one commits to.
        if let Some(c) = wt.nodes.get(i + 1) {
            let child =
                committed_child(&bytes, &s.shape).expect("a node with a successor commits to it");
            let depth = match &s.shape {
                Shape::Branch { taken, .. } => {
                    assert!(taken);
                    s.key.depth() + 1
                }
                Shape::Extension { nibbles, follows } => {
                    assert!(follows);
                    s.key.depth() + nibbles.len()
                }
                other => panic!("a {other:?} has no successor"),
            };
            assert_eq!(c.step.key.depth(), depth);
            match (child.as_hash(), c.step.hash) {
                (Some(h), Some(ch)) => {
                    assert_eq!(h, ch, "each child's hash is what its parent committed")
                }
                (None, None) => {
                    embedded_bytes.insert(c.step.key, child.as_slice().to_vec());
                }
                (a, b) => panic!("parent commits {a:?}, child traced {b:?}"),
            }
        }
    }
}

fn reference_trie(leaves: Vec<(Nibbles, Vec<u8>)>) -> HashMap<NodeKey, Vec<u8>> {
    let mut leaves = leaves;
    leaves.sort();
    csl_eth_trie::build::build_all(&leaves)
        .unwrap()
        .1
        .into_iter()
        .collect()
}

fn steps_of(wt: &WalkTrace) -> Vec<Step> {
    wt.nodes.iter().map(|n| n.step.clone()).collect()
}

#[test]
fn traces_chain_name_fetched_pages_and_agree_across_modes() {
    let w = world(1500, 21);
    let dir = scratch("trace");
    produce(&dir, &w.head, "", w.accounts.iter().cloned(), &w.code).unwrap();
    let mut snap = Snapshot::open(Recording::new(&dir), None, w.head.state_root).unwrap();
    snap.tracing = true;
    let eps = snap
        .manifest()
        .table(TABLE_ACCOUNT_NODES)
        .unwrap()
        .epsilon_pages as u64;
    snap.hint = csl_eth_client::Hint::symmetric(eps + 1);
    snap.top_levels = 3;
    let accounts = reference_trie(
        w.accounts
            .iter()
            .map(|a| (path_of(&a.hashed), a.account.encode()))
            .collect(),
    );
    let take =
        |snap: &Snapshot<Recording>| std::mem::take(&mut *snap.driver().wants.lock().unwrap());

    // The run layout the trace's page indices are numbered in.
    for t in snap.tables() {
        let len = std::fs::metadata(dir.join(&t.path)).unwrap().len();
        assert_eq!(t.total_len, len, "{}", t.name);
        assert_eq!(
            t.model_off,
            (t.page_count + 1) * 4096,
            "data pages follow page 0"
        );
        assert_eq!(t.model_pages * t.model_record_bytes, t.model_bytes);
        assert!(t.error.is_none());
    }

    // Accounts and absences, both modes: every trace chains and names the
    // pages the read fetched; the two modes walk the same nodes.
    let present: BTreeMap<B256, ()> = w.accounts.iter().map(|a| (a.hashed, ())).collect();
    let mut rng = ChaCha8Rng::seed_from_u64(5);
    let absent: Vec<B256> = (0..20).map(|_| random_absent(&mut rng, &present)).collect();
    let keys: Vec<B256> = w
        .accounts
        .iter()
        .step_by(37)
        .map(|a| a.hashed)
        .chain(absent)
        .collect();
    let (mut from_cache, mut absences) = (0, 0);
    for k in &keys {
        take(&snap);
        let (p, pc) = snap.account(k);
        let pt = snap.trace().clone();
        let pw = take(&snap);
        let (h, hc) = snap.account_by_hash(k);
        let ht = snap.trace().clone();
        let hw = take(&snap);
        assert_eq!(p, h);
        assert_eq!((pt.walks.len(), ht.walks.len()), (1, 1));
        check_walk(&pt.walks[0], &accounts, &pw, &dir, &snap, k, pc.rounds);
        check_walk(&ht.walks[0], &accounts, &hw, &dir, &snap, k, hc.rounds);
        assert_eq!(
            steps_of(&pt.walks[0]),
            steps_of(&ht.walks[0]),
            "{k}: path and baseline walk the same nodes"
        );
        assert!(!pt.walks[0].by_hash && ht.walks[0].by_hash);
        assert_eq!(pt.walks[0].table, TABLE_ACCOUNT_NODES);
        assert_eq!(ht.walks[0].table, csl_eth_store::TABLE_NODES_BY_HASH);
        assert_eq!(
            pt.walks[0].nodes.len(),
            pc.nodes,
            "every node walked is traced"
        );
        let last = &pt.walks[0].nodes.last().unwrap().step.shape;
        match &p {
            Read::Verified(_) => assert!(matches!(last, Shape::Leaf { matches: true, .. })),
            Read::VerifiedAbsent(AbsentBy::EmptySlot) => {
                assert!(matches!(last, Shape::Branch { taken: false, .. }))
            }
            Read::VerifiedAbsent(AbsentBy::ExtensionMismatch) => {
                assert!(matches!(last, Shape::Extension { follows: false, .. }))
            }
            Read::VerifiedAbsent(AbsentBy::LeafMismatch) => {
                assert!(matches!(last, Shape::Leaf { matches: false, .. }))
            }
            other => panic!("{k}: {other:?}"),
        }
        absences += usize::from(p.is_absent());
        from_cache += pt.walks[0]
            .nodes
            .iter()
            .filter(|n| n.origin == Origin::Cache)
            .count();
        // The baseline fetches one node per round: node k is first checked
        // after the round that brought it, so checks only move forward.
        let at: Vec<u32> = ht.walks[0]
            .nodes
            .iter()
            .filter_map(|n| n.checked_at)
            .collect();
        assert!(at.windows(2).all(|p| p[0] <= p[1]), "{at:?}");
    }
    assert!(from_cache > 0, "the top-level cache shows in the trace");
    assert_eq!(absences, 20);

    // Storage: the account walk, then the storage walk from its root.
    for a in w.accounts.iter().filter(|a| !a.storage.is_empty()).take(12) {
        let storage = reference_trie(
            a.storage
                .iter()
                .map(|(s, v)| (path_of(s), csl_eth_trie::encode_word(v)))
                .collect(),
        );
        let (slot, v) = a.storage[a.storage.len() / 3];
        for baseline in [false, true] {
            take(&snap);
            let (r, c) = if baseline {
                snap.storage_by_hash(&a.hashed, &slot)
            } else {
                snap.storage(&a.hashed, &slot)
            };
            assert_eq!(r, Read::Verified(v));
            let t = snap.trace().clone();
            let wants = take(&snap);
            assert_eq!(t.walks.len(), 2);
            assert_eq!(
                (t.walks[0].trie, t.walks[1].trie),
                (Trie::Account, Trie::Storage)
            );
            assert_eq!(t.walks[1].root, a.account.storage_root);
            assert_eq!(t.walks[1].key, slot);
            check_walk(
                &t.walks[0],
                &accounts,
                &wants,
                &dir,
                &snap,
                &a.hashed,
                c.rounds,
            );
            check_walk(
                &t.walks[1],
                &storage,
                &wants,
                &dir,
                &snap,
                &a.hashed,
                c.rounds,
            );
        }
    }
    // An account with no storage: the storage walk is the empty trie.
    let empty = w.accounts.iter().find(|a| a.storage.is_empty()).unwrap();
    let (r, _) = snap.storage(&empty.hashed, &B256::repeat_byte(4));
    assert_eq!(r, Read::VerifiedAbsent(AbsentBy::EmptyTrie));
    assert!(snap.trace().walks[1].nodes.is_empty());

    // Code: the entry's page, and the blob it names.
    let (h, c) = w.code.iter().max_by_key(|(_, c)| c.len()).unwrap();
    let (r, _) = snap.code(h);
    assert_eq!(r.verified().as_ref(), Some(c));
    let ct = snap.trace().code.clone().unwrap();
    assert!(ct.page.is_some() && ct.blob.is_some() && ct.len == Some(c.len()));

    // Tamper, as the page does: flip one byte inside the deepest node of
    // the round's responses that the read asked for. The read stops at
    // that node, insufficient, its hash failing; never a wrong answer.
    let a = &w.accounts[700];
    snap.begin_read();
    let mut flipped: Option<csl_eth_client::EntryAt> = None;
    let (r, _) = loop {
        match snap.try_account(&a.hashed) {
            Ok(done) => break done,
            Err(Pending) => {
                let wants = snap.store().take_wanted(true);
                let mut got = snap.driver().fetch(&wants);
                if flipped.is_none() {
                    let mut best: Option<(usize, csl_eth_client::EntryAt)> = None;
                    for (i, (w, g)) in wants.iter().zip(&got).enumerate() {
                        if let (Want::Range { rel, off, .. }, Ok(Some(body))) = (w, g) {
                            for e in snap.entries_in(rel, *off, body) {
                                // A target is a non-empty interval inside the body.
                                assert!(e.value_len > 0 && e.value_off + e.value_len <= body.len());
                                if best.as_ref().is_none_or(|(_, b)| e.at.depth > b.at.depth) {
                                    best = Some((i, e));
                                }
                            }
                        }
                    }
                    if let Some((i, e)) = best {
                        if let Ok(Some(body)) = &mut got[i] {
                            body[e.value_off + e.value_len / 2] ^= 0xff;
                        }
                        flipped = Some(e);
                    }
                }
                for (w, g) in wants.iter().zip(got) {
                    snap.store().supply(w, g);
                }
            }
        }
    };
    let e = flipped.expect("the round carried the path's nodes");
    match &r {
        Read::Insufficient(Reason::Invalid {
            what: Invalid::HashMismatch,
            key,
            ..
        }) => assert_eq!(*key, e.at.key),
        other => panic!("tampered read: {other:?}"),
    }
    let last = snap.trace().walks[0].nodes.last().unwrap();
    assert_eq!(last.step.key.depth(), e.at.depth);
    assert!(
        matches!(last.step.shape, Shape::Invalid { what: Invalid::HashMismatch, got: Some(g) } if Some(g) != last.step.hash)
    );
    assert_eq!(last.checked_at, None);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn tracing_changes_no_want_and_no_cost() {
    // The trace is additive: a tracing snapshot puts the same wants on the
    // wire, round by round, and reports the same cost as one that does not.
    let w = world(800, 23);
    let dir = scratch("trace-additive");
    produce(&dir, &w.head, "", w.accounts.iter().cloned(), &w.code).unwrap();
    let open = |tracing: bool| {
        let mut s = Snapshot::open(Recording::new(&dir), None, w.head.state_root).unwrap();
        let eps = s
            .manifest()
            .table(TABLE_ACCOUNT_NODES)
            .unwrap()
            .epsilon_pages as u64;
        s.hint = csl_eth_client::Hint::symmetric(eps + 1);
        s.top_levels = 2;
        s.tracing = tracing;
        s
    };
    let (mut plain, mut traced) = (open(false), open(true));
    let take = |s: &Snapshot<Recording>| std::mem::take(&mut *s.driver().wants.lock().unwrap());
    assert_eq!(take(&plain), take(&traced), "opening");

    let present: BTreeMap<B256, ()> = w.accounts.iter().map(|a| (a.hashed, ())).collect();
    let mut rng = ChaCha8Rng::seed_from_u64(8);
    let absent: Vec<B256> = (0..10).map(|_| random_absent(&mut rng, &present)).collect();
    let mut compare = |what: &str, f: &dyn Fn(&mut Snapshot<Recording>) -> Cost| {
        let (pc, tc) = (f(&mut plain), f(&mut traced));
        assert_eq!(pc, tc, "{what}: cost");
        assert_eq!(take(&plain), take(&traced), "{what}: wants per round");
        assert!(plain.trace().walks.is_empty() && plain.trace().code.is_none());
        assert!(!traced.trace().walks.is_empty() || traced.trace().code.is_some());
    };
    for k in w
        .accounts
        .iter()
        .step_by(41)
        .map(|a| a.hashed)
        .chain(absent)
    {
        compare("account", &|s| s.account(&k).1);
        compare("account by hash", &|s| s.account_by_hash(&k).1);
    }
    for a in w.accounts.iter().filter(|a| !a.storage.is_empty()).take(6) {
        let slot = a.storage[0].0;
        compare("storage", &|s| s.storage(&a.hashed, &slot).1);
        compare("storage by hash", &|s| {
            s.storage_by_hash(&a.hashed, &slot).1
        });
    }
    for h in w.code.keys().take(4) {
        compare("code", &|s| s.code(h).1);
    }
    std::fs::remove_dir_all(&dir).ok();
}
