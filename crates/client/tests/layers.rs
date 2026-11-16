//! A base plus layers (`docs/delta-producer.md`, prototype step 3): a base
//! from state S0, layers from S1 and S2, and the client over base plus
//! layers answers every key of S2 exactly as a fresh build of S2 does,
//! through the transitions that break a naive "newest wins" reader: an
//! owner whose storage root another account already has, an account
//! deleted and recreated, a branch collapsing, an extension splitting, and
//! nodes moving between hashed and embedded. Dropping, corrupting,
//! reordering or adding layers ends in a correct answer or
//! `Insufficient`, never a wrong one.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{HashBuilder, KECCAK_EMPTY};
use csl_eth_client::{Cost, DirDriver, Driver, Read, Snapshot};
use csl_eth_store::{
    build_rows, manifest_path, merge_layers, produce, run_path, write_layer,
    write_layered_manifest, AccountLeaf, Head, LayerRows, Manifest, ProduceOptions, Rows4, EPSILON,
};
use csl_eth_trie::{encode_word, path_of, Account};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Acct {
    nonce: u64,
    balance: U256,
    storage: BTreeMap<B256, U256>,
    code: Option<Vec<u8>>,
}

type State = BTreeMap<B256, Acct>;

fn storage_root(slots: &BTreeMap<B256, U256>) -> B256 {
    let mut hb = HashBuilder::default();
    for (k, v) in slots {
        hb.add_leaf(path_of(k), &encode_word(v));
    }
    hb.root()
}

fn account_of(a: &Acct) -> Account {
    Account {
        nonce: a.nonce,
        balance: a.balance,
        storage_root: storage_root(&a.storage),
        code_hash: a.code.as_ref().map_or(KECCAK_EMPTY, keccak256),
    }
}

fn leaves(s: &State) -> Vec<AccountLeaf> {
    s.iter()
        .map(|(h, a)| AccountLeaf {
            hashed: *h,
            account: account_of(a),
            storage: a.storage.iter().map(|(k, v)| (*k, *v)).collect(),
        })
        .collect()
}

fn code_of(s: &State) -> HashMap<B256, Vec<u8>> {
    s.values()
        .filter_map(|a| a.code.clone())
        .map(|c| (keccak256(&c), c))
        .collect()
}

fn head_of(s: &State, n: u8) -> Head {
    let mut hb = HashBuilder::default();
    for (h, a) in s {
        hb.add_leaf(path_of(h), &account_of(a).encode());
    }
    Head {
        block_hash: B256::repeat_byte(0xA0 + n),
        block_number: 1_000 + n as u64,
        timestamp: 1_761_800_000 + 12 * n as u64,
        state_root: hb.root(),
    }
}

fn rows(s: &State, head: &Head) -> Rows4 {
    build_rows(head, leaves(s), &code_of(s), ProduceOptions::default())
        .unwrap()
        .0
}

fn key(b: u8, rng: &mut ChaCha8Rng) -> B256 {
    let mut h = [0u8; 32];
    rng.fill_bytes(&mut h);
    h[0] = b;
    B256::from(h)
}

fn code(rng: &mut ChaCha8Rng, len: usize) -> Vec<u8> {
    let mut c = vec![0u8; len];
    rng.fill_bytes(&mut c);
    c
}

/// The crafted keys, by name.
struct Keys {
    p1: B256,
    p2: B256,
    p3: B256,
    shared_b: B256,
    shared_x: B256,
    recreated: B256,
    embedded: B256,
    deleted: Vec<B256>,
}

/// S0, S1, S2, and the keys every transition touches.
fn states() -> (State, State, State, Keys) {
    let mut rng = ChaCha8Rng::seed_from_u64(11);
    let mut s0 = State::new();
    for i in 0..1500usize {
        let h = key(rng.random(), &mut rng);
        let mut storage = BTreeMap::new();
        if i % 3 == 0 {
            for _ in 0..rng.random_range(1..=30) {
                storage.insert(
                    key(rng.random(), &mut rng),
                    U256::from(rng.random::<u64>() | 1),
                );
            }
        }
        let code = match i % 8 {
            1 => Some(code(&mut rng, 600)),
            5 => Some(code(&mut rng, 6000)),
            _ => None,
        };
        s0.insert(
            h,
            Acct {
                nonce: rng.random_range(0..100),
                balance: U256::from(rng.random::<u64>()),
                storage,
                code,
            },
        );
    }
    // A pair under a 60-nibble extension (as e2e's): an extension split in
    // S1, a branch collapse in S2.
    let mut p = [0x33u8; 32];
    p[30] = 0x10;
    let p1 = B256::from(p);
    p[30] = 0x70;
    let p2 = B256::from(p);
    let mut p = [0x33u8; 32];
    p[15] = 0x44;
    let p3 = B256::from(p);
    for k in [p1, p2] {
        s0.insert(
            k,
            Acct {
                nonce: 1,
                balance: U256::from(5u64),
                storage: BTreeMap::new(),
                code: None,
            },
        );
    }
    // An account whose storage another will share in S1.
    let shared_b = key(0x5B, &mut rng);
    let mut bs = BTreeMap::new();
    for _ in 0..200 {
        bs.insert(
            key(rng.random(), &mut rng),
            U256::from(rng.random::<u64>() | 1),
        );
    }
    s0.insert(
        shared_b,
        Acct {
            nonce: 1,
            balance: U256::ZERO,
            storage: bs,
            code: Some(code(&mut rng, 900)),
        },
    );
    let shared_x = key(0x5C, &mut rng);
    // Deleted in S1, recreated in S2 with storage partly the same.
    let recreated = key(0x7E, &mut rng);
    let mut rs = BTreeMap::new();
    for _ in 0..60 {
        rs.insert(
            key(rng.random(), &mut rng),
            U256::from(rng.random::<u64>() | 1),
        );
    }
    s0.insert(
        recreated,
        Acct {
            nonce: 3,
            balance: U256::from(9u64),
            storage: rs,
            code: Some(code(&mut rng, 300)),
        },
    );
    // Two slots sharing 60 nibbles with one-byte values: their branch is
    // under 32 bytes and sits inside its parent. A 32-byte value in S1
    // makes it hashed; S2 makes it small (embedded) again.
    let embedded = key(0xE0, &mut rng);
    let mut es = BTreeMap::new();
    let mut a = [0x21u8; 32];
    a[30] = 0x10;
    es.insert(B256::from(a), U256::from(1u64));
    a[30] = 0x20;
    es.insert(B256::from(a), U256::from(2u64));
    for _ in 0..20 {
        es.insert(
            key(rng.random(), &mut rng),
            U256::from(rng.random::<u64>() | 1),
        );
    }
    s0.insert(
        embedded,
        Acct {
            nonce: 0,
            balance: U256::ZERO,
            storage: es,
            code: None,
        },
    );

    // S1: churn, the split, the shared root, the deletion, hashed.
    let mut s1 = s0.clone();
    let ks: Vec<B256> = s1.keys().copied().collect();
    for k in ks.iter().step_by(7) {
        let a = s1.get_mut(k).unwrap();
        a.balance += U256::from(1u64);
        a.nonce += 1;
        if !a.storage.is_empty() && k[1] % 2 == 0 {
            let first = *a.storage.keys().next().unwrap();
            a.storage.insert(first, U256::from(77u64));
            a.storage
                .insert(key(rng.random(), &mut rng), U256::from(78u64));
        }
    }
    let mut deleted = Vec::new();
    for k in ks.iter().skip(3).step_by(97).take(8) {
        if ![p1, p2, shared_b, recreated, embedded].contains(k) {
            s1.remove(k);
            deleted.push(*k);
        }
    }
    for _ in 0..40 {
        let k = key(rng.random(), &mut rng);
        let c = if rng.random_bool(0.3) {
            let n = rng.random_range(10..8000);
            Some(code(&mut rng, n))
        } else {
            None
        };
        s1.insert(
            k,
            Acct {
                nonce: 0,
                balance: U256::from(1u64),
                storage: BTreeMap::new(),
                code: c,
            },
        );
    }
    s1.insert(
        p3,
        Acct {
            nonce: 0,
            balance: U256::from(3u64),
            storage: BTreeMap::new(),
            code: None,
        },
    );
    let bstore = s1[&shared_b].storage.clone();
    let bcode = s1[&shared_b].code.clone();
    s1.insert(
        shared_x,
        Acct {
            nonce: 1,
            balance: U256::from(2u64),
            storage: bstore,
            code: bcode,
        },
    );
    s1.remove(&recreated);
    let mut a = [0x21u8; 32];
    a[30] = 0x10;
    s1.get_mut(&embedded)
        .unwrap()
        .storage
        .insert(B256::from(a), U256::MAX - U256::from(5u64));

    // S2: more churn, the collapse, the recreation, embedded again, and a
    // slot of the shared owner changed so the two tries part.
    let mut s2 = s1.clone();
    let ks: Vec<B256> = s2.keys().copied().collect();
    for k in ks.iter().skip(2).step_by(5) {
        let a = s2.get_mut(k).unwrap();
        a.balance += U256::from(2u64);
        if a.storage.len() > 2 && k[2] % 3 == 0 {
            let last = *a.storage.keys().last().unwrap();
            a.storage.remove(&last);
        }
    }
    s2.remove(&p2);
    let mut rs: BTreeMap<B256, U256> = s0[&recreated]
        .storage
        .iter()
        .take(30)
        .map(|(k, v)| (*k, *v))
        .collect();
    for _ in 0..10 {
        rs.insert(key(rng.random(), &mut rng), U256::from(5u64));
    }
    let rc = code(&mut rng, 5000);
    s2.insert(
        recreated,
        Acct {
            nonce: 0,
            balance: U256::from(1u64),
            storage: rs,
            code: Some(rc),
        },
    );
    s2.get_mut(&embedded)
        .unwrap()
        .storage
        .insert(B256::from(a), U256::from(3u64));
    let first = *s2[&shared_b].storage.keys().next().unwrap();
    s2.get_mut(&shared_b)
        .unwrap()
        .storage
        .insert(first, U256::from(4242u64));
    (
        s0,
        s1,
        s2,
        Keys {
            p1,
            p2,
            p3,
            shared_b,
            shared_x,
            recreated,
            embedded,
            deleted,
        },
    )
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "csl-eth-layers-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// A bucket with the base S0, layers L1 (S0→S1) and L2 (S1→S2), the
/// layered manifests of S1 and S2, and a fresh plain build of S2 in
/// another directory.
struct Fixture {
    dir: PathBuf,
    fresh: PathBuf,
    s: [State; 3],
    heads: [Head; 3],
    base: Manifest,
    l1: csl_eth_store::Layer,
    l2: csl_eth_store::Layer,
    keys: Keys,
}

fn fixture(name: &str) -> Fixture {
    let (s0, s1, s2, keys) = states();
    let heads = [head_of(&s0, 0), head_of(&s1, 1), head_of(&s2, 2)];
    let dir = scratch(name);
    let base = produce(&dir, &heads[0], "", leaves(&s0), &code_of(&s0))
        .unwrap()
        .manifest;
    let r = [
        rows(&s0, &heads[0]),
        rows(&s1, &heads[1]),
        rows(&s2, &heads[2]),
    ];
    let d1 = LayerRows::diff(&r[0], &r[1]);
    let d2 = LayerRows::diff(&r[1], &r[2]);
    assert!(
        !d1.storage.is_empty()
            && !d1.code.is_empty()
            && !d2.account.is_empty()
            && !d2.code.is_empty()
    );
    let l1 = write_layer(
        &dir,
        heads[0].block_number,
        heads[1].block_number,
        &d1,
        EPSILON,
    )
    .unwrap();
    let l2 = write_layer(
        &dir,
        heads[1].block_number,
        heads[2].block_number,
        &d2,
        EPSILON,
    )
    .unwrap();
    write_layered_manifest(&dir, &heads[1], &base, vec![l1.clone()], false).unwrap();
    write_layered_manifest(&dir, &heads[2], &base, vec![l1.clone(), l2.clone()], true).unwrap();
    let fresh = scratch(&format!("{name}-fresh"));
    produce(&fresh, &heads[2], "", leaves(&s2), &code_of(&s2)).unwrap();
    Fixture {
        dir,
        fresh,
        s: [s0, s1, s2],
        heads,
        base,
        l1,
        l2,
        keys,
    }
}

/// Every probe: each account of any of the three states (present, deleted
/// or recreated in S2), a slot of each of their tries (present in some
/// state), absent slots, random absent accounts, and every code hash.
#[derive(Clone, Debug)]
enum Probe {
    Account(B256),
    Slot(B256, B256),
    Code(B256),
}

fn probes(f: &Fixture) -> Vec<Probe> {
    let mut rng = ChaCha8Rng::seed_from_u64(5);
    let mut out = Vec::new();
    let mut accts: BTreeMap<B256, ()> = BTreeMap::new();
    for s in &f.s {
        accts.extend(s.keys().map(|k| (*k, ())));
    }
    for k in accts.keys() {
        out.push(Probe::Account(*k));
        for s in &f.s {
            if let Some(a) = s.get(k) {
                for slot in a.storage.keys().step_by((a.storage.len() / 6).max(1)) {
                    out.push(Probe::Slot(*k, *slot));
                }
                if let Some(c) = &a.code {
                    out.push(Probe::Code(keccak256(c)));
                }
            }
        }
        out.push(Probe::Slot(*k, key(rng.random(), &mut rng)));
    }
    for _ in 0..300 {
        out.push(Probe::Account(key(rng.random(), &mut rng)));
    }
    // The crafted ones again, so a failure names them.
    let k = &f.keys;
    for a in [
        k.p1,
        k.p2,
        k.p3,
        k.shared_b,
        k.shared_x,
        k.recreated,
        k.embedded,
    ] {
        out.push(Probe::Account(a));
    }
    for a in [k.shared_b, k.shared_x, k.recreated, k.embedded] {
        for s in &f.s {
            if let Some(acct) = s.get(&a) {
                for slot in acct.storage.keys() {
                    out.push(Probe::Slot(a, *slot));
                }
            }
        }
    }
    out.extend(k.deleted.iter().map(|d| Probe::Account(*d)));
    out
}

/// What one probe reads, as comparable values.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Answer {
    Account(Read<Account>),
    Slot(Read<U256>),
    Code(Read<Vec<u8>>),
}

fn ask<D: Driver>(snap: &mut Snapshot<D>, p: &Probe) -> (Answer, Cost) {
    match p {
        Probe::Account(h) => {
            let (r, c) = snap.account(h);
            (Answer::Account(r), c)
        }
        Probe::Slot(h, s) => {
            let (r, c) = snap.storage(h, s);
            (Answer::Slot(r), c)
        }
        Probe::Code(h) => {
            let (r, c) = snap.code(h);
            (Answer::Code(r), c)
        }
    }
}

fn short(a: &Answer) -> String {
    match a {
        Answer::Code(Read::Verified(b)) => format!("Code(Verified({} bytes))", b.len()),
        a => format!("{a:?}"),
    }
}

fn insufficient(a: &Answer) -> bool {
    match a {
        Answer::Account(r) => r.is_insufficient(),
        Answer::Slot(r) => r.is_insufficient(),
        Answer::Code(r) => r.is_insufficient(),
    }
}

/// The truth: each probe against the fresh build of S2.
fn truth(f: &Fixture, ps: &[Probe]) -> Vec<Answer> {
    let mut snap = Snapshot::open(DirDriver::new(&f.fresh), None, f.heads[2].state_root).unwrap();
    ps.iter().map(|p| ask(&mut snap, p).0).collect()
}

#[derive(Default, Debug, Clone, Copy)]
struct Tally {
    reads: u64,
    requests: u64,
    bytes: u64,
    rounds: u64,
    max_rounds: u32,
}

impl Tally {
    fn add(&mut self, c: &Cost) {
        self.reads += 1;
        self.requests += c.requests;
        self.bytes += c.bytes;
        self.rounds += c.rounds as u64;
        self.max_rounds = self.max_rounds.max(c.rounds);
    }
    fn line(&self) -> String {
        let n = self.reads.max(1) as f64;
        format!(
            "{} reads: {:.1} requests, {:.1} KB, {:.2} rounds per read (max {})",
            self.reads,
            self.requests as f64 / n,
            self.bytes as f64 / n / 1024.0,
            self.rounds as f64 / n,
            self.max_rounds
        )
    }
}

/// Read every probe from `dir` at S2's root; every answer must be the
/// truth, or (only when `faulty`) `Insufficient`. Returns the
/// insufficient count and the cost of the account and slot reads.
fn check(
    dir: &Path,
    f: &Fixture,
    ps: &[Probe],
    want: &[Answer],
    faulty: bool,
    top_levels: usize,
    label: &str,
) -> (usize, Tally) {
    let mut snap = match Snapshot::open(
        DirDriver::new(dir),
        Some(f.heads[2].block_hash),
        f.heads[2].state_root,
    ) {
        Ok(s) => s,
        Err(e) if faulty => {
            eprintln!("{label}: refused to open: {e}");
            return (ps.len(), Tally::default());
        }
        Err(e) => panic!("{label}: {e}"),
    };
    snap.top_levels = top_levels;
    let mut ins = 0;
    let mut t = Tally::default();
    for (p, w) in ps.iter().zip(want) {
        let (a, c) = ask(&mut snap, p);
        if !matches!(p, Probe::Code(_)) {
            t.add(&c);
        }
        if a == *w {
            continue;
        }
        // Code is read by hash, not under the state root: old code a base
        // still holds is not in a fresh build of S2, and is right anyway
        // when it hashes to the code hash.
        if let (
            Probe::Code(h),
            Answer::Code(Read::Verified(b)),
            Answer::Code(Read::Insufficient(_)),
        ) = (p, &a, w)
        {
            assert_eq!(keccak256(b), *h, "{label}: code that does not hash");
            continue;
        }
        assert!(
            faulty && insufficient(&a),
            "{label}: {p:?} gave {}, truth {}",
            short(&a),
            short(w)
        );
        ins += 1;
    }
    (ins, t)
}

#[test]
fn base_plus_layers_answers_as_a_fresh_build() {
    let f = fixture("answers");
    let ps = probes(&f);
    let want = truth(&f, &ps);
    // The truth itself is S2's: spot-check against the model.
    let k = &f.keys;
    for (p, w) in ps.iter().zip(&want) {
        match (p, w) {
            (Probe::Account(h), Answer::Account(r)) => match f.s[2].get(h) {
                Some(a) => assert_eq!(*r, Read::Verified(account_of(a))),
                None => assert!(r.is_absent(), "{h}"),
            },
            (Probe::Slot(h, s), Answer::Slot(r)) => {
                match f.s[2].get(h).and_then(|a| a.storage.get(s)) {
                    Some(v) => assert_eq!(*r, Read::Verified(*v)),
                    None => assert!(r.is_absent()),
                }
            }
            (Probe::Code(_), Answer::Code(r)) => {
                assert!(!r.is_insufficient() || matches!(r, Read::Insufficient(_)))
            }
            _ => unreachable!(),
        }
    }
    assert!(f.s[2].contains_key(&k.shared_x) && !f.s[2].contains_key(&k.p2));

    let (ins, layered) = check(&f.dir, &f, &ps, &want, false, 0, "base + 2 layers");
    assert_eq!(ins, 0);
    let (_, plain) = check(&f.fresh, &f, &ps, &want, false, 0, "fresh S2");
    eprintln!("fresh S2:        {}", plain.line());
    eprintln!("base + 2 layers: {}", layered.line());
    // The success bar of the design: within twice the base-only read.
    assert!(
        layered.requests <= 4 * plain.requests,
        "requests {layered:?} vs {plain:?}"
    );
    // With the top-levels cache on, stale candidates are never cached.
    let (ins, cached) = check(&f.dir, &f, &ps, &want, false, 3, "base + 2 layers, cache");
    assert_eq!(ins, 0);
    eprintln!("cache 3 levels:  {}", cached.line());

    // S1 as base + L1: every key of S1.
    let mut snap = Snapshot::open(
        DirDriver::new(&f.dir),
        Some(f.heads[1].block_hash),
        f.heads[1].state_root,
    )
    .unwrap();
    for (h, a) in &f.s[1] {
        assert_eq!(snap.account(h).0, Read::Verified(account_of(a)));
        if let Some((s, v)) = a.storage.iter().next() {
            assert_eq!(snap.storage(h, s).0, Read::Verified(*v));
        }
    }
    for d in &k.deleted {
        assert!(snap.account(d).0.is_absent());
    }
    assert!(snap.account(&k.recreated).0.is_absent());

    // L1 and L2 merged, newest wins, nothing dropped: S2 again.
    let m = merge_layers(&f.dir, &[f.l1.clone(), f.l2.clone()], EPSILON).unwrap();
    assert_eq!((m.from_block, m.to_block), (f.l1.from_block, f.l2.to_block));
    claim(&f, vec![m]);
    let (ins, merged) = check(&f.dir, &f, &ps, &want, false, 3, "merged");
    assert_eq!(ins, 0);
    eprintln!("merged, cache 3: {}", merged.line());
    std::fs::remove_dir_all(&f.dir).ok();
    std::fs::remove_dir_all(&f.fresh).ok();
}

/// Write a manifest for S2 claiming `layers` over the base.
fn claim(f: &Fixture, layers: Vec<csl_eth_store::Layer>) {
    write_layered_manifest(&f.dir, &f.heads[2], &f.base, layers, true).unwrap();
}

#[test]
fn layer_faults_never_become_false_answers() {
    let f = fixture("faults");
    let ps = probes(&f);
    let want = truth(&f, &ps);
    let mut rng = ChaCha8Rng::seed_from_u64(9);
    let run = |l: &csl_eth_store::Layer, t: u16| {
        f.dir.join(run_path(
            &l.tables.iter().find(|x| x.table_id == t).unwrap().root,
        ))
    };

    // L2 left out: the manifest still claims S2's root. Everything L2
    // changed is Insufficient; nothing is wrong.
    claim(&f, vec![f.l1.clone()]);
    let (ins, _) = check(&f.dir, &f, &ps, &want, true, 0, "L2 dropped");
    assert!(ins > 0);
    eprintln!("L2 dropped: {ins} of {} insufficient", ps.len());
    // L1 left out.
    claim(&f, vec![f.l2.clone()]);
    let (ins, _) = check(&f.dir, &f, &ps, &want, true, 3, "L1 dropped");
    assert!(ins > 0);
    eprintln!("L1 dropped: {ins} insufficient");
    // Order reversed, and a layer listed twice: candidates are chosen by
    // hash, so order is no evidence and every read is still right.
    claim(&f, vec![f.l2.clone(), f.l1.clone(), f.l2.clone()]);
    let (ins, _) = check(&f.dir, &f, &ps, &want, false, 3, "reordered");
    assert_eq!(ins, 0);
    claim(&f, vec![f.l1.clone(), f.l2.clone()]);

    // Byte flips in each of L2's runs, over a third of the probes.
    let some: Vec<Probe> = ps.iter().step_by(3).cloned().collect();
    let some_want: Vec<Answer> = want.iter().step_by(3).cloned().collect();
    for t in f.l2.tables.iter().map(|x| x.table_id) {
        let p = run(&f.l2, t);
        let clean = std::fs::read(&p).unwrap();
        for round in 0..2 {
            let mut b = clean.clone();
            for _ in 0..30 {
                let i = rng.random_range(0..b.len());
                b[i] ^= 1 << rng.random_range(0..8);
            }
            std::fs::write(&p, &b).unwrap();
            let (ins, _) = check(
                &f.dir,
                &f,
                &some,
                &some_want,
                true,
                (round % 2) * 3,
                &format!("L2 table {t} flips {round}"),
            );
            eprintln!("L2 table {t} flips {round}: {ins} insufficient");
        }
        // Truncated, then gone.
        std::fs::write(&p, &clean[..clean.len() / 2]).unwrap();
        check(
            &f.dir,
            &f,
            &some,
            &some_want,
            true,
            0,
            &format!("L2 table {t} truncated"),
        );
        std::fs::remove_file(&p).unwrap();
        let (ins, _) = check(
            &f.dir,
            &f,
            &some,
            &some_want,
            true,
            0,
            &format!("L2 table {t} missing"),
        );
        assert!(ins > 0, "table {t}");
        std::fs::write(&p, &clean).unwrap();
    }
    let (ins, _) = check(&f.dir, &f, &ps, &want, false, 0, "restored");
    assert_eq!(ins, 0);

    // A layer of another branch (S2 with different churn) listed too: its
    // nodes are candidates nothing commits to, so nothing changes.
    let mut other = f.s[2].clone();
    for a in other.values_mut().step_by(3) {
        a.balance += U256::from(1_000u64);
    }
    let oh = head_of(&other, 9);
    let ro = rows(&other, &oh);
    let r2 = rows(&f.s[2], &f.heads[2]);
    let fork = write_layer(&f.dir, 1002, 1009, &LayerRows::diff(&r2, &ro), EPSILON).unwrap();
    claim(&f, vec![f.l1.clone(), f.l2.clone(), fork]);
    let (ins, _) = check(&f.dir, &f, &ps, &want, false, 3, "foreign layer");
    assert_eq!(ins, 0);

    // A manifest that says it is plain but lists layers is refused.
    let mut m: Manifest = Manifest::from_json(
        &std::fs::read(f.dir.join(manifest_path(&f.heads[2].block_hash))).unwrap(),
    )
    .unwrap();
    m.format_version = csl_eth_store::FORMAT_VERSION;
    std::fs::write(
        f.dir.join(manifest_path(&f.heads[2].block_hash)),
        m.to_json(),
    )
    .unwrap();
    assert!(Snapshot::open(
        DirDriver::new(&f.dir),
        Some(f.heads[2].block_hash),
        f.heads[2].state_root
    )
    .is_err());
    std::fs::remove_dir_all(&f.dir).ok();
    std::fs::remove_dir_all(&f.fresh).ok();
}

/// The read cost of a plain snapshot, pinned: the layered client must not
/// change what a base-only read fetches. The numbers are this workload's
/// on `main` before layers (bf8a7d5), measured there.
#[test]
fn plain_snapshot_read_cost_is_unchanged() {
    let (s0, _, _, _) = states();
    let h = head_of(&s0, 0);
    let dir = scratch("plain-cost");
    produce(&dir, &h, "", leaves(&s0), &code_of(&s0)).unwrap();
    let mut snap = Snapshot::open(DirDriver::new(&dir), None, h.state_root).unwrap();
    let mut t = Tally::default();
    let mut rng = ChaCha8Rng::seed_from_u64(3);
    for (k, a) in s0.iter().step_by(3) {
        t.add(&snap.account(k).1);
        if let Some(s) = a.storage.keys().next() {
            t.add(&snap.storage(k, s).1);
        }
        t.add(&snap.account(&key(rng.random(), &mut rng)).1);
    }
    snap.top_levels = 3;
    for (k, _) in s0.iter().step_by(5) {
        t.add(&snap.account(k).1);
    }
    eprintln!("plain: {t:?}");
    assert_eq!((t.reads, t.requests, t.bytes, t.rounds), PLAIN_COST);
    std::fs::remove_dir_all(&dir).ok();
}

const PLAIN_COST: (u64, u64, u64, u64) = (1469, 7897, 34_340_864, 2805);

/// One step of churn: about 2% of accounts change balance, a third of
/// those a slot, and a few accounts are created.
fn churn(s: &State, rng: &mut ChaCha8Rng) -> State {
    let mut next = s.clone();
    let keys: Vec<B256> = next.keys().copied().collect();
    for _ in 0..keys.len() / 50 {
        let k = keys[rng.random_range(0..keys.len())];
        let a = next.get_mut(&k).unwrap();
        a.balance += U256::from(1u64);
        if !a.storage.is_empty() && rng.random_bool(0.3) {
            a.storage
                .insert(key(rng.random(), rng), U256::from(rng.random::<u64>() | 1));
        }
    }
    for _ in 0..3 {
        let k = key(rng.random(), rng);
        next.insert(
            k,
            Acct {
                nonce: 0,
                balance: U256::from(1u64),
                storage: BTreeMap::new(),
                code: None,
            },
        );
    }
    next
}

/// The read cost over N layers, against a fresh build of the same state,
/// and the same layers merged into one: printed for the record, with the
/// answers checked each time.
#[test]
fn read_cost_over_n_layers_and_merged() {
    let (s0, _, _, _) = states();
    let mut rng = ChaCha8Rng::seed_from_u64(21);
    let dir = scratch("n-layers");
    let h0 = head_of(&s0, 0);
    let base = produce(&dir, &h0, "", leaves(&s0), &code_of(&s0))
        .unwrap()
        .manifest;
    let mut s = s0.clone();
    let mut r_prev = rows(&s0, &h0);
    let mut layers = Vec::new();
    let mut lines = Vec::new();
    for n in 1..=16u8 {
        let next = churn(&s, &mut rng);
        let h = head_of(&next, n);
        let r = rows(&next, &h);
        layers.push(
            write_layer(
                &dir,
                h0.block_number + n as u64 - 1,
                h.block_number,
                &LayerRows::diff(&r_prev, &r),
                EPSILON,
            )
            .unwrap(),
        );
        s = next;
        r_prev = r;
        if ![1, 2, 4, 8, 16].contains(&n) {
            continue;
        }
        let fresh = scratch(&format!("n-layers-fresh-{n}"));
        produce(&fresh, &h, "", leaves(&s), &code_of(&s)).unwrap();
        // Probes: a third of the accounts, their first slot, absent keys.
        let mut ps = Vec::new();
        for (k, a) in s.iter().step_by(3) {
            ps.push(Probe::Account(*k));
            if let Some(slot) = a.storage.keys().next() {
                ps.push(Probe::Slot(*k, *slot));
            }
            ps.push(Probe::Account(key(rng.random(), &mut rng)));
        }
        let mut t = Snapshot::open(DirDriver::new(&fresh), None, h.state_root).unwrap();
        let want: Vec<Answer> = ps.iter().map(|p| ask(&mut t, p).0).collect();
        let f = Fixture {
            dir: dir.clone(),
            fresh: fresh.clone(),
            s: [s0.clone(), s0.clone(), s.clone()],
            heads: [h0, h0, h],
            base: base.clone(),
            l1: layers[0].clone(),
            l2: layers[0].clone(),
            keys: states().3,
        };
        write_layered_manifest(&dir, &h, &base, layers.clone(), true).unwrap();
        let (ins, layered) = check(&dir, &f, &ps, &want, false, 0, &format!("{n} layers"));
        assert_eq!(ins, 0);
        let (_, plain) = check(&fresh, &f, &ps, &want, false, 0, "fresh");
        let merged = merge_layers(&dir, &layers, EPSILON).unwrap();
        write_layered_manifest(&dir, &h, &base, vec![merged], true).unwrap();
        let (ins, one) = check(
            &dir,
            &f,
            &ps,
            &want,
            false,
            0,
            &format!("{n} layers merged"),
        );
        assert_eq!(ins, 0);
        lines.push(format!(
            "{n:>2} layers: {:.2}x requests, {:.2}x bytes, {:.2} vs {:.2} rounds; merged: {:.2}x requests, {:.2}x bytes",
            layered.requests as f64 / plain.requests as f64,
            layered.bytes as f64 / plain.bytes as f64,
            layered.rounds as f64 / layered.reads as f64,
            plain.rounds as f64 / plain.reads as f64,
            one.requests as f64 / plain.requests as f64,
            one.bytes as f64 / plain.bytes as f64,
        ));
        std::fs::remove_dir_all(&fresh).ok();
    }
    for l in &lines {
        eprintln!("{l}");
    }
    std::fs::remove_dir_all(&dir).ok();
}
