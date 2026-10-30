//! Snap range proofs: verifying a consecutive run of leaves against a root,
//! and turning the proof into the sealed subtrees a slice build needs.
//!
//! A `snap` range response is a sorted run of leaves starting at or after
//! `origin`, plus the hashed nodes on the paths of `origin` and of the last
//! leaf. Those two paths bound the run: every node hanging left of the
//! origin path holds keys below `origin`, every node hanging right of the
//! last leaf's path holds keys above it, and between the two paths the trie
//! is determined by the leaves alone. So the proof is checked by
//! rebuilding: the left references, the leaves and the right references
//! go through [`Builder`] in key order and the root must come out. A leaf
//! omitted from the middle, a forged value, or a reference that is not
//! where the proof says all change the root.
//!
//! The references are the parent's child slots as the proof carries them
//! (a hash, or an embedded node under 32 bytes), keyed by the path the slot
//! addresses; that is exactly [`Builder::push_sealed`]'s input, so the same
//! references let the producer build a path-prefix slice up through its
//! ancestors to `state_root`.
//!
//! Three cases follow snap's conventions: an empty trie has no proof and
//! no leaves; a response with leaves and no proof claims the whole trie
//! (storage tries that fit in one response); otherwise a proof is required,
//! and when it carries no leaves it must show nothing lies at or after
//! `origin`.

use crate::{
    build::{BuildError, Builder, Discard},
    key::path_of,
    MAX_NODE_BYTES, PATH_NIBBLES,
};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Decodable;
use alloy_trie::{
    nodes::{RlpNode, TrieNode},
    Nibbles, EMPTY_ROOT_HASH,
};
use core::{cmp::Ordering, fmt};
use std::collections::HashMap;

/// A subtree taken as given: the path its parent's slot addresses, and the
/// reference held there.
pub type Sealed = (Nibbles, RlpNode);

/// What a verified range establishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Subtrees entirely below `origin`, ascending.
    pub left: Vec<Sealed>,
    /// Subtrees entirely above the last leaf (or above `origin` when there
    /// are no leaves), ascending.
    pub right: Vec<Sealed>,
    /// Whether the trie has keys after the last leaf.
    pub more: bool,
    /// The last leaf as its parent references it, for a caller that keeps
    /// the leaf's position but not the leaf (snap servers return the first
    /// key past the limit). `None` without leaves or without a proof.
    pub last: Option<Sealed>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProofError {
    /// A hashed node on a bound's path is not in the proof.
    Missing(B256),
    TooLarge(usize),
    Rlp,
    Shape,
    /// The proof does not reach the last leaf.
    BoundNotProven(B256),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RangeError {
    Unsorted {
        prev: B256,
        next: B256,
    },
    BelowOrigin(B256),
    EmptyValue(B256),
    /// A non-empty trie answered without a proof and without leaves.
    NoProof,
    /// `EMPTY_ROOT_HASH` with leaves.
    EmptyTrieWithLeaves,
    Proof(ProofError),
    Build(BuildError),
    RootMismatch {
        expected: B256,
        got: B256,
    },
}

impl fmt::Display for RangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RangeError::Unsorted { prev, next } => write!(f, "leaves out of order: {prev} then {next}"),
            RangeError::BelowOrigin(k) => write!(f, "leaf {k} below the origin"),
            RangeError::EmptyValue(k) => write!(f, "empty value at {k}"),
            RangeError::NoProof => write!(f, "no proof for a non-empty trie"),
            RangeError::EmptyTrieWithLeaves => write!(f, "leaves under the empty root"),
            RangeError::Proof(e) => write!(f, "proof: {e:?}"),
            RangeError::Build(e) => write!(f, "build: {e}"),
            RangeError::RootMismatch { expected, got } => {
                write!(f, "root mismatch: expected {expected}, rebuilt {got}")
            }
        }
    }
}

impl std::error::Error for RangeError {}

impl From<ProofError> for RangeError {
    fn from(e: ProofError) -> Self {
        RangeError::Proof(e)
    }
}

impl From<BuildError> for RangeError {
    fn from(e: BuildError) -> Self {
        RangeError::Build(e)
    }
}

/// Verify `leaves` (hashed key, trie leaf value) as the complete run of
/// keys from `origin` to the last leaf under `root`, given snap's proof
/// nodes.
pub fn verify_range<P: AsRef<[u8]>>(root: B256, origin: &B256, leaves: &[(B256, Vec<u8>)], proof: &[P]) -> Result<Verified, RangeError> {
    let mut prev: Option<B256> = None;
    for (k, v) in leaves {
        if k < origin {
            return Err(RangeError::BelowOrigin(*k));
        }
        if let Some(p) = prev {
            if *k <= p {
                return Err(RangeError::Unsorted { prev: p, next: *k });
            }
        }
        if v.is_empty() {
            return Err(RangeError::EmptyValue(*k));
        }
        prev = Some(*k);
    }

    if proof.is_empty() {
        if root == EMPTY_ROOT_HASH {
            return if leaves.is_empty() {
                Ok(Verified { left: Vec::new(), right: Vec::new(), more: false, last: None })
            } else {
                Err(RangeError::EmptyTrieWithLeaves)
            };
        }
        if leaves.is_empty() {
            return Err(RangeError::NoProof);
        }
        let got = rebuild(&[], leaves, &[])?;
        if got != root {
            return Err(RangeError::RootMismatch { expected: root, got });
        }
        return Ok(Verified { left: Vec::new(), right: Vec::new(), more: false, last: None });
    }

    let mut nodes: HashMap<B256, &[u8]> = HashMap::with_capacity(proof.len());
    for p in proof {
        let p = p.as_ref();
        if p.len() > MAX_NODE_BYTES {
            return Err(ProofError::TooLarge(p.len()).into());
        }
        nodes.insert(keccak256(p), p);
    }

    let origin_path = path_of(origin);
    let mut left = walk_side(root, &nodes, &origin_path, Side::Left)?.refs;
    let (mut right, last) = match leaves.last() {
        Some((k, _)) => {
            let w = walk_side(root, &nodes, &path_of(k), Side::Right)?;
            let found = w.found.ok_or(ProofError::BoundNotProven(*k))?;
            (w.refs, Some(found))
        }
        None => (walk_side(root, &nodes, &origin_path, Side::Right)?.refs, None),
    };
    left.sort_by_key(|a| a.0);
    right.sort_by_key(|a| a.0);

    let got = rebuild(&left, leaves, &right)?;
    if got != root {
        return Err(RangeError::RootMismatch { expected: root, got });
    }
    let more = !right.is_empty();
    Ok(Verified { left, right, more, last })
}

fn rebuild(left: &[Sealed], leaves: &[(B256, Vec<u8>)], right: &[Sealed]) -> Result<B256, BuildError> {
    let mut b = Builder::new(Discard);
    for (p, n) in left {
        b.push_sealed(*p, n.clone())?;
    }
    for (k, v) in leaves {
        b.push(path_of(k), v.clone())?;
    }
    for (p, n) in right {
        b.push_sealed(*p, n.clone())?;
    }
    Ok(b.finish().0.root)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Side {
    Left,
    Right,
}

struct Walked {
    refs: Vec<Sealed>,
    /// The bound's own leaf, if the path ends at it.
    found: Option<Sealed>,
}

/// Follow `bound` from the root through the proof, collecting every
/// subtree that hangs entirely on `side` of it.
fn walk_side(root: B256, nodes: &HashMap<B256, &[u8]>, bound: &Nibbles, side: Side) -> Result<Walked, ProofError> {
    debug_assert_eq!(bound.len(), PATH_NIBBLES);
    let mut refs = Vec::new();
    let mut depth = 0usize;
    let mut expect = RlpNode::word_rlp(&root);
    loop {
        let bytes: &[u8] = match expect.as_hash() {
            Some(h) => nodes.get(&h).copied().ok_or(ProofError::Missing(h))?,
            None => expect.as_slice(),
        };
        let mut rest = bytes;
        let node = TrieNode::decode(&mut rest).map_err(|_| ProofError::Rlp)?;
        if !rest.is_empty() {
            return Err(ProofError::Rlp);
        }
        match node {
            TrieNode::EmptyRoot => return Err(ProofError::Shape),
            TrieNode::Branch(b) => {
                if depth >= PATH_NIBBLES {
                    return Err(ProofError::Shape);
                }
                let nib = bound.get_unchecked(depth);
                let mut next = None;
                for (i, c) in b.as_ref().children() {
                    let Some(c) = c else { continue };
                    match (i.cmp(&nib), side) {
                        (Ordering::Less, Side::Left) | (Ordering::Greater, Side::Right) => {
                            let mut p = bound.slice(..depth);
                            p.push(i);
                            refs.push((p, c.clone()));
                        }
                        (Ordering::Equal, _) => next = Some(c.clone()),
                        _ => {}
                    }
                }
                match next {
                    None => return Ok(Walked { refs, found: None }),
                    Some(c) => {
                        expect = c;
                        depth += 1;
                    }
                }
            }
            TrieNode::Extension(e) => {
                let n = e.key.len();
                if n == 0 || depth + n > PATH_NIBBLES {
                    return Err(ProofError::Shape);
                }
                match e.key.cmp(&bound.slice(depth..depth + n)) {
                    Ordering::Equal => {
                        expect = e.child;
                        depth += n;
                    }
                    Ordering::Less => {
                        if side == Side::Left {
                            refs.push((bound.slice(..depth), expect));
                        }
                        return Ok(Walked { refs, found: None });
                    }
                    Ordering::Greater => {
                        if side == Side::Right {
                            refs.push((bound.slice(..depth), expect));
                        }
                        return Ok(Walked { refs, found: None });
                    }
                }
            }
            TrieNode::Leaf(l) => {
                let full = bound.slice(..depth).join(&l.key);
                if full.len() != PATH_NIBBLES {
                    return Err(ProofError::Shape);
                }
                let here = (bound.slice(..depth), expect);
                return Ok(match (full.cmp(bound), side) {
                    (Ordering::Equal, _) => Walked { refs, found: Some(here) },
                    (Ordering::Less, Side::Left) | (Ordering::Greater, Side::Right) => {
                        refs.push(here);
                        Walked { refs, found: None }
                    }
                    _ => Walked { refs, found: None },
                });
            }
        }
    }
}

/// The proof nodes a snap server attaches for one key: every hashed node
/// on `path` from the root down to the leaf, the empty slot or the
/// mismatching node. `lookup` resolves a node by hash. For local range
/// servers (tests, the producer's self-check).
pub fn proof_for<F: Fn(&B256) -> Option<Vec<u8>>>(root: B256, path: &Nibbles, lookup: F) -> Result<Vec<Vec<u8>>, ProofError> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut expect = RlpNode::word_rlp(&root);
    loop {
        let bytes: Vec<u8> = match expect.as_hash() {
            Some(h) => {
                let b = lookup(&h).ok_or(ProofError::Missing(h))?;
                out.push(b.clone());
                b
            }
            None => expect.as_slice().to_vec(),
        };
        let mut rest = bytes.as_slice();
        let node = TrieNode::decode(&mut rest).map_err(|_| ProofError::Rlp)?;
        match node {
            TrieNode::EmptyRoot => return Err(ProofError::Shape),
            TrieNode::Branch(b) => {
                if depth >= PATH_NIBBLES {
                    return Err(ProofError::Shape);
                }
                let nib = path.get_unchecked(depth);
                let child = b.as_ref().children().find(|(i, _)| *i == nib).and_then(|(_, c)| c.cloned());
                match child {
                    None => return Ok(out),
                    Some(c) => {
                        expect = c;
                        depth += 1;
                    }
                }
            }
            TrieNode::Extension(e) => {
                let n = e.key.len();
                if n == 0 || depth + n > PATH_NIBBLES {
                    return Err(ProofError::Shape);
                }
                if path.slice(depth..depth + n) != e.key {
                    return Ok(out);
                }
                expect = e.child;
                depth += n;
            }
            TrieNode::Leaf(_) => return Ok(out),
        }
    }
}

#[cfg(test)]
#[allow(clippy::type_complexity)]
mod tests {
    use super::*;
    use crate::build::build_all;

    /// A deterministic trie of `n` leaves with 40-byte values (hashed
    /// nodes throughout, like the account trie).
    fn world(n: u32, seed: u8) -> (B256, Vec<(B256, Vec<u8>)>, HashMap<B256, Vec<u8>>) {
        let mut leaves: Vec<(B256, Vec<u8>)> = (0..n)
            .map(|i| {
                let k = keccak256([seed, (i >> 24) as u8, (i >> 16) as u8, (i >> 8) as u8, i as u8]);
                (k, vec![(i % 251) as u8 + 1; 40])
            })
            .collect();
        leaves.sort();
        let paths: Vec<(Nibbles, Vec<u8>)> = leaves.iter().map(|(k, v)| (path_of(k), v.clone())).collect();
        let (built, nodes) = build_all(&paths).unwrap();
        let by_hash = nodes.into_iter().map(|(_, rlp)| (keccak256(&rlp), rlp)).collect();
        (built.root, leaves, by_hash)
    }

    /// What a snap server answers for `GetAccountRange(root, origin, limit, bytes)`
    /// over `leaves`: consecutive leaves from `origin`, including the first
    /// past `limit`, with the proofs for `origin` and the last leaf.
    fn serve(
        root: B256,
        leaves: &[(B256, Vec<u8>)],
        nodes: &HashMap<B256, Vec<u8>>,
        origin: B256,
        limit: B256,
        max: usize,
    ) -> (Vec<(B256, Vec<u8>)>, Vec<Vec<u8>>) {
        let mut out = Vec::new();
        for (k, v) in leaves.iter().filter(|(k, _)| *k >= origin) {
            out.push((*k, v.clone()));
            if *k >= limit || out.len() >= max {
                break;
            }
        }
        let lookup = |h: &B256| nodes.get(h).cloned();
        let mut proof = proof_for(root, &path_of(&origin), lookup).unwrap();
        if let Some((last, _)) = out.last() {
            proof.extend(proof_for(root, &path_of(last), lookup).unwrap());
        }
        (out, proof)
    }

    #[test]
    fn chunks_cover_the_trie_and_boundaries_rebuild_the_root() {
        let (root, leaves, nodes) = world(3000, 1);
        let mut origin = B256::ZERO;
        let mut seen = Vec::new();
        let mut chunks = 0;
        loop {
            let (chunk, proof) = serve(root, &leaves, &nodes, origin, B256::repeat_byte(0xff), 97);
            let v = verify_range(root, &origin, &chunk, &proof).unwrap();
            chunks += 1;
            seen.extend(chunk.iter().cloned());
            if !v.more {
                assert!(v.right.is_empty());
                break;
            }
            let last = chunk.last().unwrap().0;
            origin = B256::from(alloy_primitives::U256::from_be_bytes(last.0) + alloy_primitives::U256::from(1));
        }
        assert_eq!(seen, leaves);
        assert!(chunks > 30);

        // A slice [prefix 0x3.., prefix 0x3f..]: the first chunk's left refs
        // and the last chunk's right refs seal everything outside it, and
        // the slice's own leaves build back to the root.
        let lo = B256::from({
            let mut b = [0u8; 32];
            b[0] = 0x30;
            b
        });
        let hi = B256::from({
            let mut b = [0xffu8; 32];
            b[0] = 0x3f;
            b
        });
        let (chunk, proof) = serve(root, &leaves, &nodes, lo, hi, 10_000);
        let v = verify_range(root, &lo, &chunk, &proof).unwrap();
        // The server included the first key past `hi`; drop it and keep its reference.
        let (inside, dropped): (Vec<_>, Vec<_>) = chunk.iter().cloned().partition(|(k, _)| *k <= hi);
        assert_eq!(dropped.len(), 1);
        let mut right = v.right.clone();
        right.push(v.last.clone().unwrap());
        right.sort_by_key(|a| a.0);
        let mut b = Builder::new(Vec::new());
        for (p, n) in &v.left {
            b.push_sealed(*p, n.clone()).unwrap();
        }
        for (k, val) in &inside {
            b.push(path_of(k), val.clone()).unwrap();
        }
        for (p, n) in &right {
            b.push_sealed(*p, n.clone()).unwrap();
        }
        let (built, emitted) = b.finish();
        assert_eq!(built.root, root);
        assert_eq!(built.leaves as usize, inside.len());
        assert!(inside.len() > 150 && inside.len() < 230, "{}", inside.len());
        // Emitted at depth 1: the slice's own branch, and the branch the
        // dropped leaf hangs under (rebuilt from its sealed children, since
        // the proof reaches through it). Every other depth-1 subtree is
        // sealed and absent.
        let depth1: Vec<u8> = emitted.iter().filter(|(k, _)| k.depth() == 1).map(|(k, _)| k.path.get_unchecked(0)).collect();
        assert_eq!(depth1, vec![3, 4]);
        assert!(emitted
            .iter()
            .filter(|(k, _)| k.depth() >= 2)
            .all(|(k, _)| k.path.get_unchecked(0) == 3 || k.path.starts_with(&dropped_path(&dropped[0].0, k.depth()))));
        fn dropped_path(k: &B256, depth: usize) -> Nibbles {
            path_of(k).slice(..depth)
        }
    }

    #[test]
    fn tampering_is_rejected() {
        let (root, leaves, nodes) = world(500, 2);
        let origin = leaves[100].0;
        let (chunk, proof) = serve(root, &leaves, &nodes, origin, B256::repeat_byte(0xff), 50);
        assert!(verify_range(root, &origin, &chunk, &proof).is_ok());

        // A leaf omitted from the middle.
        let mut c = chunk.clone();
        c.remove(20);
        assert!(matches!(verify_range(root, &origin, &c, &proof), Err(RangeError::RootMismatch { .. })));
        // A value changed.
        let mut c = chunk.clone();
        c[7].1[0] ^= 1;
        assert!(matches!(verify_range(root, &origin, &c, &proof), Err(RangeError::RootMismatch { .. })));
        // A leaf inserted.
        let mut c = chunk.clone();
        let mut k = c[3].0;
        k.0[31] ^= 1;
        c.push((k, vec![1; 40]));
        c.sort();
        assert!(matches!(verify_range(root, &origin, &c, &proof), Err(RangeError::RootMismatch { .. }) | Err(RangeError::Unsorted { .. })));
        // The last leaf dropped: its proof no longer matches the new last.
        let mut c = chunk.clone();
        c.pop();
        assert!(verify_range(root, &origin, &c, &proof).is_err());
        // A proof node missing.
        let mut p = proof.clone();
        p.remove(p.len() - 1);
        assert!(verify_range(root, &origin, &chunk, &p).is_err());
        // Wrong root.
        assert!(verify_range(B256::repeat_byte(9), &origin, &chunk, &proof).is_err());
        // A leaf below the origin.
        let mut c = chunk.clone();
        c.insert(0, leaves[99].clone());
        assert!(matches!(verify_range(root, &origin, &c, &proof), Err(RangeError::BelowOrigin(_))));
        // No proof, not the whole trie.
        assert!(matches!(verify_range(root, &origin, &chunk, &Vec::<Vec<u8>>::new()), Err(RangeError::RootMismatch { .. })));
    }

    #[test]
    fn whole_trie_empty_trie_and_empty_tail() {
        let (root, leaves, nodes) = world(40, 3);
        // Whole trie without a proof.
        let v = verify_range(root, &B256::ZERO, &leaves, &Vec::<Vec<u8>>::new()).unwrap();
        assert!(!v.more && v.left.is_empty() && v.right.is_empty());
        // Empty trie.
        let v = verify_range(EMPTY_ROOT_HASH, &B256::ZERO, &[], &Vec::<Vec<u8>>::new()).unwrap();
        assert!(!v.more);
        assert!(matches!(verify_range(EMPTY_ROOT_HASH, &B256::ZERO, &leaves[..1], &Vec::<Vec<u8>>::new()), Err(RangeError::EmptyTrieWithLeaves)));
        assert!(matches!(verify_range(root, &B256::ZERO, &[], &Vec::<Vec<u8>>::new()), Err(RangeError::NoProof)));
        // Nothing at or after an origin past the last key: proof of origin alone, no more.
        let origin = B256::repeat_byte(0xff);
        let (chunk, proof) = serve(root, &leaves, &nodes, origin, origin, 10);
        assert!(chunk.is_empty());
        let v = verify_range(root, &origin, &chunk, &proof).unwrap();
        assert!(!v.more && v.right.is_empty() && !v.left.is_empty());
        // The same claim at an origin that does have keys after it is a lie.
        let origin = leaves[10].0;
        let (_, proof) = serve(root, &leaves, &nodes, origin, origin, 1);
        assert!(verify_range(root, &origin, &[], &proof).is_err());
    }

    /// Storage-shaped tries: tiny values, embedded leaves, extensions.
    #[test]
    fn small_values_with_embedded_nodes() {
        for n in [1u32, 2, 3, 17, 300] {
            let mut leaves: Vec<(B256, Vec<u8>)> = (0..n).map(|i| (keccak256(i.to_be_bytes()), vec![(i % 200) as u8 + 1])).collect();
            leaves.sort();
            let paths: Vec<(Nibbles, Vec<u8>)> = leaves.iter().map(|(k, v)| (path_of(k), v.clone())).collect();
            let (built, nodes) = build_all(&paths).unwrap();
            let nodes: HashMap<B256, Vec<u8>> = nodes.into_iter().map(|(_, r)| (keccak256(&r), r)).collect();
            let mut origin = B256::ZERO;
            let mut all = Vec::new();
            loop {
                let (chunk, proof) = serve(built.root, &leaves, &nodes, origin, B256::repeat_byte(0xff), 5);
                let v = verify_range(built.root, &origin, &chunk, &proof).unwrap();
                all.extend(chunk.iter().cloned());
                if !v.more {
                    break;
                }
                let last = chunk.last().unwrap().0;
                origin = B256::from(alloy_primitives::U256::from_be_bytes(last.0) + alloy_primitives::U256::from(1));
            }
            assert_eq!(all, leaves, "n = {n}");
        }
    }
}
