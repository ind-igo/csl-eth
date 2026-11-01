//! Synthetic worlds for the workload and fault-table tests: a whole-trie
//! slice, and a prefix slice whose subtrees outside the prefix are sealed
//! the way a snap range proof seals them.

#![allow(dead_code)]

use alloy_primitives::{keccak256, B256, U256};
use csl_eth_snap::{Slice, SliceHead};
use csl_eth_store::{produce_with, AccountLeaf, Head, ProduceOptions};
use csl_eth_trie::{
    build::build_all, encode_word, path_of, proof_for, verify_range, Account, Nibbles, Sealed,
    EMPTY_ROOT, KECCAK_EMPTY,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
};

pub fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "csl-eth-snap-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn storage_root(slots: &[(B256, U256)]) -> B256 {
    if slots.is_empty() {
        return EMPTY_ROOT;
    }
    let leaves: Vec<(Nibbles, Vec<u8>)> = slots
        .iter()
        .map(|(k, v)| (path_of(k), encode_word(v)))
        .collect();
    build_all(&leaves).unwrap().0.root
}

/// Random code on either side of the blob threshold.
fn code_of(rng: &mut ChaCha8Rng, big: bool) -> Vec<u8> {
    let len = if big {
        rng.random_range(3969..=24576)
    } else {
        rng.random_range(1..=3000)
    };
    let mut c = vec![0u8; len];
    rng.fill_bytes(&mut c);
    c
}

fn head_of(state_root: B256, tag: u8) -> Head {
    Head {
        block_hash: B256::repeat_byte(tag),
        block_number: 24_400_000,
        timestamp: 1_761_800_000,
        state_root,
    }
}

fn slice_of(
    head: &Head,
    prefix: &str,
    leaves: &[AccountLeaf],
    code: &HashMap<B256, Vec<u8>>,
    boundary: Vec<Sealed>,
) -> Slice {
    let mut storage: HashMap<B256, Vec<(B256, U256)>> = HashMap::new();
    for a in leaves {
        if !a.storage.is_empty() {
            storage.insert(a.account.storage_root, a.storage.clone());
        }
    }
    let code: HashMap<B256, Vec<u8>> = leaves
        .iter()
        .filter(|a| a.account.code_hash != KECCAK_EMPTY)
        .map(|a| (a.account.code_hash, code[&a.account.code_hash].clone()))
        .collect();
    Slice {
        head: SliceHead {
            block_hash: head.block_hash,
            block_number: head.block_number,
            timestamp: head.timestamp,
            state_root: head.state_root,
            prefix: prefix.to_string(),
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
        boundary,
    }
}

/// A world's accounts: a third with storage (`deep` of them with
/// thousands of slots), a quarter with code (some above the blob
/// threshold), sorted by hashed address.
fn accounts(
    keys: impl Iterator<Item = B256>,
    deep: &[usize],
    deep_slots: usize,
    rng: &mut ChaCha8Rng,
) -> (Vec<AccountLeaf>, HashMap<B256, Vec<u8>>) {
    let mut by_key: BTreeMap<B256, AccountLeaf> = BTreeMap::new();
    let mut code = HashMap::new();
    for (i, hashed) in keys.enumerate() {
        let mut storage: Vec<(B256, U256)> = Vec::new();
        if i.is_multiple_of(3) {
            let slots = if deep.contains(&i) {
                deep_slots
            } else {
                rng.random_range(1..=40)
            };
            let mut m = BTreeMap::new();
            while m.len() < slots {
                let mut s = [0u8; 32];
                rng.fill_bytes(&mut s);
                m.insert(B256::from(s), U256::from(rng.random::<u64>() | 1));
            }
            storage = m.into_iter().collect();
        }
        let code_hash = if i % 4 == 1 {
            let c = code_of(rng, i % 8 != 1);
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
    }
    (by_key.into_values().collect(), code)
}

fn trie_root(leaves: &[AccountLeaf]) -> (B256, HashMap<B256, Vec<u8>>) {
    let kv: Vec<(Nibbles, Vec<u8>)> = leaves
        .iter()
        .map(|a| (path_of(&a.hashed), a.account.encode()))
        .collect();
    let (built, nodes) = build_all(&kv).unwrap();
    let by_hash = nodes.into_iter().map(|(_, r)| (keccak256(&r), r)).collect();
    (built.root, by_hash)
}

pub struct World {
    pub slice: Slice,
    /// The slice's accounts with their slots: the producer's input.
    pub leaves: Vec<AccountLeaf>,
    pub head: Head,
}

impl World {
    /// The bucket for this world, in a fresh directory.
    pub fn produce(&self, name: &str) -> PathBuf {
        let dir = scratch(name);
        self.produce_into(&dir);
        dir
    }

    pub fn produce_into(&self, dir: &Path) {
        produce_with(
            dir,
            &self.head,
            &self.slice.head.prefix,
            self.leaves.iter().cloned(),
            &self.slice.code,
            ProduceOptions {
                boundary: self.slice.boundary.clone(),
                ..ProduceOptions::default()
            },
        )
        .unwrap();
    }
}

/// The whole trie as a slice: `n` random accounts, two with deep storage,
/// and a pair sharing 60 nibbles so the account trie has a long extension.
pub fn whole(n: usize, seed: u64) -> World {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut keys = Vec::with_capacity(n);
    for i in 0..n {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        if i < 2 {
            h = [0x33; 32];
            h[30] = if i == 0 { 0x10 } else { 0x70 };
        }
        keys.push(B256::from(h));
    }
    let (leaves, code) = accounts(keys.into_iter(), &[3, 6], 2000, &mut rng);
    let (root, _) = trie_root(&leaves);
    let head = head_of(root, 0xAB);
    let slice = slice_of(&head, "", &leaves, &code, Vec::new());
    World {
        slice,
        leaves,
        head,
    }
}

/// A slice of nibble `7` of an `n`-account trie, as the fetcher assembles
/// it: the leaves under the prefix and the boundary a range proof of the
/// first and last chunk yields, so the slice builds up to the full trie's
/// root and keys outside it end at a sealed subtree.
pub fn prefix(n: u32, seed: u64) -> World {
    const PREFIX: u8 = 0x7;
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    // Deep storage on a few accounts that land inside the prefix.
    let keys: Vec<B256> = (0..n).map(|i| keccak256(i.to_be_bytes())).collect();
    let deep: Vec<usize> = keys
        .iter()
        .enumerate()
        .filter(|(i, k)| i.is_multiple_of(3) && k.0[0] >> 4 == PREFIX)
        .map(|(i, _)| i)
        .take(2)
        .collect();
    let (all, code) = accounts(keys.into_iter(), &deep, 1500, &mut rng);
    let (root, nodes) = trie_root(&all);

    let mut lo = [0u8; 32];
    lo[0] = PREFIX << 4;
    let mut hi = [0xffu8; 32];
    hi[0] = (PREFIX << 4) | 0x0f;
    let (lo, hi) = (B256::from(lo), B256::from(hi));
    // One chunk: every leaf from lo, plus the first past hi.
    let mut chunk: Vec<(B256, Vec<u8>)> = Vec::new();
    for a in all.iter().filter(|a| a.hashed >= lo) {
        chunk.push((a.hashed, a.account.encode()));
        if a.hashed > hi {
            break;
        }
    }
    let lookup = |h: &B256| nodes.get(h).cloned();
    let mut proof = proof_for(root, &path_of(&lo), lookup).unwrap();
    proof.extend(proof_for(root, &path_of(&chunk.last().unwrap().0), lookup).unwrap());
    let v = verify_range(root, &lo, &chunk, &proof).unwrap();
    let dropped = chunk.last().unwrap().0 > hi;
    let mut boundary = v.left;
    boundary.extend(v.right);
    if dropped {
        boundary.push(v.last.unwrap());
    }
    let inside: Vec<AccountLeaf> = all
        .iter()
        .filter(|a| a.hashed >= lo && a.hashed <= hi)
        .cloned()
        .collect();
    let head = head_of(root, 0xAC);
    let slice = slice_of(&head, "7", &inside, &code, boundary);
    World {
        slice,
        leaves: inside,
        head,
    }
}
