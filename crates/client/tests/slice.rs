//! A path-prefix slice, as milestone 1 fetches it: the leaves under one
//! nibble plus the sealed subtrees a snap range proof supplies, built up
//! through the ancestors to `state_root`. Reads inside the slice verify or
//! are proven absent; reads outside end in `Insufficient` from missing
//! pages, never in an answer.

use alloy_primitives::{keccak256, B256, U256};
use csl_eth_client::{DirBucket, Read, Reason, Snapshot};
use csl_eth_store::{produce_with, AccountLeaf, Head, ProduceError, ProduceOptions};
use csl_eth_trie::{build::build_all, encode_word, path_of, proof_for, verify_range, Account, Nibbles, Sealed, EMPTY_ROOT, KECCAK_EMPTY};
use std::{collections::HashMap, path::PathBuf};

const PREFIX: u8 = 0x7;

struct World {
    accounts: Vec<AccountLeaf>,
    code: HashMap<B256, Vec<u8>>,
    root: B256,
    nodes: HashMap<B256, Vec<u8>>,
}

fn world(n: u32) -> World {
    let mut code = HashMap::new();
    let mut accounts: Vec<AccountLeaf> = (0..n)
        .map(|i| {
            let hashed = keccak256(i.to_be_bytes());
            let storage: Vec<(B256, U256)> = if i % 3 == 0 {
                let mut s: Vec<(B256, U256)> = (0..(1 + i % 7)).map(|j| (keccak256([i.to_be_bytes(), j.to_be_bytes()].concat()), U256::from(j + 1))).collect();
                s.sort();
                s
            } else {
                Vec::new()
            };
            let storage_root = if storage.is_empty() {
                EMPTY_ROOT
            } else {
                let leaves: Vec<(Nibbles, Vec<u8>)> = storage.iter().map(|(k, v)| (path_of(k), encode_word(v))).collect();
                build_all(&leaves).unwrap().0.root
            };
            let code_hash = if i % 4 == 0 {
                let c = vec![0x60u8; 40 + (i % 100) as usize];
                let h = keccak256(&c);
                code.insert(h, c);
                h
            } else {
                KECCAK_EMPTY
            };
            AccountLeaf {
                hashed,
                account: Account { nonce: i as u64, balance: U256::from(i) * U256::from(1_000_000_007u64), storage_root, code_hash },
                storage,
            }
        })
        .collect();
    accounts.sort_by_key(|a| a.hashed);
    let leaves: Vec<(Nibbles, Vec<u8>)> = accounts.iter().map(|a| (path_of(&a.hashed), a.account.encode())).collect();
    let (built, nodes) = build_all(&leaves).unwrap();
    let nodes = nodes.into_iter().map(|(_, r)| (keccak256(&r), r)).collect();
    World { accounts, code, root: built.root, nodes }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("csl-eth-slice-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// What the fetcher assembles from the first and last chunk: the slice's
/// leaves and the boundary.
fn slice_of(w: &World) -> (Vec<AccountLeaf>, Vec<Sealed>) {
    let mut lo = [0u8; 32];
    lo[0] = PREFIX << 4;
    let mut hi = [0xffu8; 32];
    hi[0] = (PREFIX << 4) | 0x0f;
    let (lo, hi) = (B256::from(lo), B256::from(hi));
    // One chunk: every leaf from lo, plus the first past hi.
    let mut chunk: Vec<(B256, Vec<u8>)> = Vec::new();
    for a in w.accounts.iter().filter(|a| a.hashed >= lo) {
        chunk.push((a.hashed, a.account.encode()));
        if a.hashed > hi {
            break;
        }
    }
    let lookup = |h: &B256| w.nodes.get(h).cloned();
    let mut proof = proof_for(w.root, &path_of(&lo), lookup).unwrap();
    proof.extend(proof_for(w.root, &path_of(&chunk.last().unwrap().0), lookup).unwrap());
    let v = verify_range(w.root, &lo, &chunk, &proof).unwrap();
    let dropped = chunk.last().unwrap().0 > hi;
    let mut boundary = v.left;
    boundary.extend(v.right);
    if dropped {
        boundary.push(v.last.unwrap());
    }
    let inside: Vec<AccountLeaf> = w.accounts.iter().filter(|a| a.hashed >= lo && a.hashed <= hi).cloned().collect();
    (inside, boundary)
}

#[test]
fn slice_reads_inside_and_insufficient_outside() {
    let w = world(4000);
    let (inside, boundary) = slice_of(&w);
    assert!(inside.len() > 200 && inside.len() < 300, "{}", inside.len());
    let head = Head { block_hash: B256::repeat_byte(0xAB), block_number: 1, timestamp: 1, state_root: w.root };
    let dir = scratch("ok");
    let produced = produce_with(&dir, &head, "7", inside.iter().cloned(), &w.code, ProduceOptions { epsilon: 4, boundary: boundary.clone() }).unwrap();
    assert_eq!(produced.stats.sealed as usize, boundary.len());
    assert_eq!(produced.stats.accounts as usize, inside.len());

    let mut snap = Snapshot::open(DirBucket::new(&dir), None, w.root).unwrap();
    let mut rounds_max = 0;
    for a in &inside {
        let (r, c) = snap.account(&a.hashed);
        match r {
            Read::Verified(got) => assert_eq!(got, a.account),
            other => panic!("inside account {}: {other:?}", a.hashed),
        }
        rounds_max = rounds_max.max(c.rounds);
        for (slot, value) in &a.storage {
            match snap.storage(&a.hashed, slot).0 {
                Read::Verified(v) => assert_eq!(v, *value),
                other => panic!("inside slot: {other:?}"),
            }
        }
        if a.account.code_hash != KECCAK_EMPTY {
            match snap.code(&a.account.code_hash).0 {
                Read::Verified(c) => assert_eq!(c, w.code[&a.account.code_hash]),
                other => panic!("inside code: {other:?}"),
            }
        }
    }
    assert!(rounds_max <= 2, "rounds {rounds_max}");

    // Absent keys inside the prefix are proven absent by the slice's own trie.
    let mut absent_inside = 0;
    for i in 0..400u32 {
        let mut k = keccak256([0xEE, i as u8, (i >> 8) as u8]);
        k.0[0] = (PREFIX << 4) | (k.0[0] & 0x0f);
        if inside.iter().any(|a| a.hashed == k) {
            continue;
        }
        match snap.account(&k).0 {
            Read::VerifiedAbsent(_) => absent_inside += 1,
            other => panic!("absent inside {k}: {other:?}"),
        }
    }
    assert!(absent_inside > 300);

    // Present and absent keys outside the prefix: the root is there, the
    // depth-1 node under their nibble is sealed and missing. Never an answer.
    let mut outside = 0;
    for a in w.accounts.iter().filter(|a| a.hashed.0[0] >> 4 != PREFIX).step_by(37) {
        match snap.account(&a.hashed).0 {
            Read::Insufficient(Reason::Missing { .. }) => outside += 1,
            other => panic!("outside present {}: {other:?}", a.hashed),
        }
    }
    for i in 0..100u32 {
        let mut k = keccak256([0xDD, i as u8]);
        if k.0[0] >> 4 == PREFIX {
            k.0[0] ^= 0x10;
        }
        match snap.account(&k).0 {
            Read::Insufficient(Reason::Missing { .. }) => outside += 1,
            other => panic!("outside absent {k}: {other:?}"),
        }
    }
    assert!(outside > 150);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wrong_or_missing_boundary_fails_the_root_check() {
    let w = world(1500);
    let (inside, boundary) = slice_of(&w);
    let head = Head { block_hash: B256::repeat_byte(0xAC), block_number: 1, timestamp: 1, state_root: w.root };
    let dir = scratch("bad");
    // No boundary: the slice alone is not the trie.
    let r = produce_with(&dir, &head, "7", inside.iter().cloned(), &w.code, ProduceOptions { epsilon: 4, boundary: Vec::new() });
    assert!(matches!(r, Err(ProduceError::StateRoot { .. })), "{r:?}");
    // One sealed reference altered.
    let mut bad = boundary.clone();
    let (p, node) = bad[0].clone();
    let mut raw = node.as_slice().to_vec();
    let last = raw.len() - 1;
    raw[last] ^= 1;
    bad[0] = (p, alloy_trie::nodes::RlpNode::from_raw(&raw).unwrap());
    let r = produce_with(&dir, &head, "7", inside.iter().cloned(), &w.code, ProduceOptions { epsilon: 4, boundary: bad });
    assert!(matches!(r, Err(ProduceError::StateRoot { .. })), "{r:?}");
    // One boundary subtree dropped.
    let mut bad = boundary.clone();
    bad.remove(bad.len() / 2);
    let r = produce_with(&dir, &head, "7", inside.iter().cloned(), &w.code, ProduceOptions { epsilon: 4, boundary: bad });
    assert!(matches!(r, Err(ProduceError::StateRoot { .. })), "{r:?}");
    let _ = std::fs::remove_dir_all(&dir);
}
