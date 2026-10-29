//! The builder against `alloy_trie::HashBuilder` for the root, and the walk
//! against the builder for completeness: every leaf is reachable from the
//! root through emitted nodes alone, every emitted node is on some leaf's
//! path, every absent key is proven absent by the shape the trie has, and
//! any tampered or withheld node is caught.

use alloy_trie::HashBuilder;
use csl_eth_trie::{
    build::build_all, keccak256, walk, AbsentBy, Invalid, Nibbles, NodeKey, Outcome, B256,
    EMPTY_ROOT_HASH,
};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::{HashMap, HashSet};

type Leaves = Vec<(Nibbles, Vec<u8>)>;

fn sorted(mut leaves: Leaves) -> Leaves {
    leaves.sort_by(|a, b| a.0.cmp(&b.0));
    leaves.dedup_by(|a, b| a.0 == b.0);
    leaves
}

/// Hashed-looking keys with values of a given size range.
fn uniform(n: usize, seed: u64, value_len: std::ops::RangeInclusive<usize>) -> Leaves {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        let len = rng.random_range(value_len.clone());
        let mut v = vec![0u8; len];
        rng.fill_bytes(&mut v);
        if v.is_empty() {
            v.push(1);
        }
        out.push((Nibbles::unpack(k), v));
    }
    sorted(out)
}

/// Keys crowded under a few long shared prefixes, with one-byte values, so
/// that leaves, branches and extensions fall under 32 bytes and embed.
fn crowded(n: usize, seed: u64) -> Leaves {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let mut k = [0x5Au8; 32];
        // Diverge only in the last one to three bytes.
        let tail = rng.random_range(1..=3usize);
        for b in &mut k[32 - tail..] {
            *b = rng.random();
        }
        out.push((Nibbles::unpack(k), vec![rng.random::<u8>() | 1]));
    }
    sorted(out)
}

fn reference_root(leaves: &Leaves) -> B256 {
    let mut hb = HashBuilder::default();
    for (k, v) in leaves {
        hb.add_leaf(*k, v);
    }
    hb.root()
}

fn nodes_map(nodes: &[(NodeKey, Vec<u8>)]) -> HashMap<NodeKey, Vec<u8>> {
    let mut m = HashMap::with_capacity(nodes.len());
    for (k, v) in nodes {
        assert!(
            m.insert(*k, v.clone()).is_none(),
            "node {k:?} emitted twice"
        );
    }
    m
}

fn check_trie(leaves: &Leaves, what: &str) {
    let (built, nodes) = build_all(leaves).unwrap();
    assert_eq!(
        built.root,
        reference_root(leaves),
        "{what}: root differs from HashBuilder"
    );
    assert_eq!(built.leaves as usize, leaves.len());
    assert_eq!(built.nodes as usize, nodes.len());
    let src = nodes_map(&nodes);

    // Every emitted node is ≥ 32 bytes except possibly the root.
    for (k, rlp) in &nodes {
        assert!(
            rlp.len() >= 32 || *k == NodeKey::ROOT,
            "{what}: short non-root node {k:?}"
        );
    }

    // Every leaf is present and verified; collect the positions touched.
    let mut touched: HashSet<NodeKey> = HashSet::new();
    for (k, v) in leaves {
        let w = walk(built.root, k, &src);
        assert_eq!(w.outcome, Outcome::Present(v.clone()), "{what}: leaf {k:?}");
        touched.extend(w.fetched.iter().copied());
        assert!(w.nodes <= 65);
    }
    // Every emitted node is on some leaf's path: nothing is dead weight.
    let emitted: HashSet<NodeKey> = src.keys().copied().collect();
    assert_eq!(
        touched, emitted,
        "{what}: emitted nodes differ from the nodes walks fetch"
    );

    // Random keys are absent, proven by the trie.
    let mut rng = ChaCha8Rng::seed_from_u64(99);
    let present: HashSet<Nibbles> = leaves.iter().map(|(k, _)| *k).collect();
    for _ in 0..200 {
        let mut k = [0u8; 32];
        rng.fill_bytes(&mut k);
        let k = Nibbles::unpack(k);
        if present.contains(&k) {
            continue;
        }
        let w = walk(built.root, &k, &src);
        assert!(
            matches!(w.outcome, Outcome::Absent(_)),
            "{what}: random key {k:?} gave {:?}",
            w.outcome
        );
    }
}

#[test]
fn uniform_tries_match_the_reference_root_and_walk_completely() {
    for (n, seed) in [
        (2usize, 1u64),
        (3, 2),
        (16, 3),
        (17, 4),
        (100, 5),
        (1_000, 6),
        (5_000, 7),
    ] {
        check_trie(&uniform(n, seed, 40..=120), &format!("uniform n={n}"));
    }
}

#[test]
fn crowded_tries_with_embedded_nodes_match_and_walk() {
    for (n, seed) in [(2usize, 10u64), (5, 11), (30, 12), (300, 13), (3_000, 14)] {
        let leaves = crowded(n, seed);
        let (built, _) = build_all(&leaves).unwrap();
        assert!(
            built.embedded > 0 || n < 3,
            "crowded n={n} should embed some nodes"
        );
        check_trie(&leaves, &format!("crowded n={n}"));
    }
}

#[test]
fn absence_shapes_are_distinguished() {
    // Two keys sharing a 60-nibble prefix: root extension of 60 nibbles,
    // then a branch, then two leaves.
    let mut a = [0x33u8; 32];
    let mut b = [0x33u8; 32];
    a[30] = 0x31;
    b[30] = 0x37;
    let leaves = sorted(vec![
        (Nibbles::unpack(a), vec![1u8; 40]),
        (Nibbles::unpack(b), vec![2u8; 40]),
    ]);
    let (built, nodes) = build_all(&leaves).unwrap();
    let src = nodes_map(&nodes);

    // Leaves the extension: differs inside the first 60 nibbles.
    let mut x = a;
    x[0] = 0x44;
    assert_eq!(
        walk(built.root, &Nibbles::unpack(x), &src).outcome,
        Outcome::Absent(AbsentBy::ExtensionMismatch)
    );
    // Reaches the branch, empty slot: nibble 61 is neither 1 nor 7.
    let mut y = a;
    y[30] = 0x35;
    assert_eq!(
        walk(built.root, &Nibbles::unpack(y), &src).outcome,
        Outcome::Absent(AbsentBy::EmptySlot)
    );
    // Reaches leaf a, remaining path differs in the last byte.
    let mut z = a;
    z[31] = 0x00;
    assert_eq!(
        walk(built.root, &Nibbles::unpack(z), &src).outcome,
        Outcome::Absent(AbsentBy::LeafMismatch)
    );
    // And the real keys.
    assert_eq!(
        walk(built.root, &Nibbles::unpack(a), &src).outcome,
        Outcome::Present(vec![1u8; 40])
    );
    assert_eq!(
        walk(built.root, &Nibbles::unpack(b), &src).outcome,
        Outcome::Present(vec![2u8; 40])
    );
}

#[test]
fn tampered_and_withheld_nodes_are_caught() {
    let leaves = uniform(500, 21, 40..=100);
    let (built, nodes) = build_all(&leaves).unwrap();
    let src = nodes_map(&nodes);
    let (k, v) = &leaves[123];
    let good = walk(built.root, k, &src);
    assert_eq!(good.outcome, Outcome::Present(v.clone()));
    assert!(good.fetched.len() >= 2);

    for victim in &good.fetched {
        // Withheld: Missing at exactly that position.
        let mut without = src.clone();
        without.remove(victim);
        let w = walk(built.root, k, &without);
        assert_eq!(w.outcome, Outcome::Missing(*victim));
        assert_eq!(w.fetched.last(), Some(victim));

        // One byte flipped: HashMismatch at that position, never a different answer.
        let mut flipped = src.clone();
        let bytes = flipped.get_mut(victim).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
        let w = walk(built.root, k, &flipped);
        assert_eq!(w.outcome, Outcome::Invalid(*victim, Invalid::HashMismatch));

        // Swapped with another node of the same trie: HashMismatch.
        let other = nodes.iter().find(|(nk, _)| nk != victim).unwrap();
        let mut swapped = src.clone();
        swapped.insert(*victim, other.1.clone());
        let w = walk(built.root, k, &swapped);
        assert_eq!(w.outcome, Outcome::Invalid(*victim, Invalid::HashMismatch));
    }

    // A root hash for a different trie: the root node fails.
    let other_root = reference_root(&uniform(500, 22, 40..=100));
    assert_ne!(other_root, built.root);
    let w = walk(other_root, k, &src);
    assert_eq!(
        w.outcome,
        Outcome::Invalid(NodeKey::ROOT, Invalid::HashMismatch)
    );

    // A truncated node: RLP error, not a hash mismatch, when the hash is
    // forged to match. Here we check the plain case: truncation changes
    // the hash, so it is a mismatch.
    let mut truncated = src.clone();
    let root_bytes = truncated.get_mut(&NodeKey::ROOT).unwrap();
    root_bytes.pop();
    assert_eq!(
        walk(built.root, k, &truncated).outcome,
        Outcome::Invalid(NodeKey::ROOT, Invalid::HashMismatch)
    );
}

#[test]
fn an_oversized_node_is_rejected_before_hashing_is_trusted() {
    // A branch with one giant embedded... cannot exist; instead hand the
    // walk a 2 KB blob at the root whose hash we claim as root.
    let blob = vec![0xC0u8; 2048];
    let root = keccak256(&blob);
    let mut src = HashMap::new();
    src.insert(NodeKey::ROOT, blob);
    let w = walk(root, &Nibbles::unpack([0u8; 32]), &src);
    assert_eq!(
        w.outcome,
        Outcome::Invalid(NodeKey::ROOT, Invalid::TooLarge(2048))
    );
    assert_ne!(root, EMPTY_ROOT_HASH);
}
