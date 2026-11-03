//! The run's commitment tree: exactly `commonware-storage::bmt` over blake3
//! (core §6), reimplemented so that this crate carries no Commonware
//! dependency. `tests/bmt_compat.rs` checks roots and proofs against the
//! real crate.
//!
//! Leaf `i` (0-based, page `i + 1`) is `blake3(i as u32 BE ‖ page_digest)`.
//! Levels pair nodes left to right; an unpaired trailing node is hashed with
//! itself. The finalized root is `blake3(leaf_count as u32 BE ‖ tree_root)`.

use crate::DIGEST;

pub type Digest = [u8; DIGEST];

/// Compile-time pin that digests are 32 bytes.
pub const DIGEST_LEN_CHECK: [u8; 32] = [0u8; DIGEST];

#[inline]
pub fn leaf(position: u32, page_digest: &Digest) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&position.to_be_bytes());
    h.update(page_digest);
    *h.finalize().as_bytes()
}

#[inline]
pub fn node(left: &Digest, right: &Digest) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

#[inline]
pub fn finalize(leaf_count: u32, tree_root: &Digest) -> Digest {
    let mut h = blake3::Hasher::new();
    h.update(&leaf_count.to_be_bytes());
    h.update(tree_root);
    *h.finalize().as_bytes()
}

/// Levels in a tree of `leaf_count` leaves: 1 for one leaf, 2 for two, …
pub fn levels_in_tree(leaf_count: u64) -> usize {
    assert!(leaf_count >= 1);
    (64 - (leaf_count - 1).leading_zeros() + 1) as usize
}

/// Sibling slots per inline proof: `ceil(log2(page_count))`, 0 for one page.
pub fn depth(page_count: u64) -> usize {
    if page_count == 0 {
        return 0;
    }
    levels_in_tree(page_count) - 1
}

pub struct Tree {
    levels: Vec<Vec<Digest>>,
    root: Digest,
}

impl Tree {
    /// Build from page digests in page order (page 1 first). `page_count ≤ 2^31`.
    pub fn build(page_digests: &[Digest]) -> Tree {
        assert!(!page_digests.is_empty(), "a run has at least one page");
        assert!(page_digests.len() <= 1 << 31);
        let leaf_count = page_digests.len() as u32;
        let leaves: Vec<Digest> = page_digests.iter().enumerate().map(|(i, d)| leaf(i as u32, d)).collect();
        let mut levels = vec![leaves];
        while levels.last().unwrap().len() > 1 {
            let cur = levels.last().unwrap();
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            for pair in cur.chunks(2) {
                next.push(match pair {
                    [a, b] => node(a, b),
                    [a] => node(a, a),
                    _ => unreachable!(),
                });
            }
            levels.push(next);
        }
        let root = finalize(leaf_count, &levels.last().unwrap()[0]);
        Tree { levels, root }
    }

    pub fn root(&self) -> Digest {
        self.root
    }

    pub fn leaf_count(&self) -> u32 {
        self.levels[0].len() as u32
    }

    /// Siblings for leaf `position`, leaf level first. A level where the node
    /// is the unpaired last one contributes no sibling, so the vector may be
    /// shorter than `depth`.
    pub fn proof(&self, position: u32) -> Vec<Digest> {
        let mut out = Vec::with_capacity(self.levels.len());
        let mut pos = position as usize;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = if pos.is_multiple_of(2) { pos + 1 } else { pos - 1 };
            if sib < level.len() {
                out.push(level[sib]);
            }
            pos /= 2;
        }
        out
    }

    /// The inline proof region for a record: siblings then zero digests up to `depth`.
    pub fn inline_proof(&self, position: u32) -> Vec<u8> {
        let d = depth(self.leaf_count() as u64);
        let mut out = vec![0u8; DIGEST * d];
        for (i, s) in self.proof(position).iter().enumerate() {
            out[i * DIGEST..(i + 1) * DIGEST].copy_from_slice(s);
        }
        out
    }
}

/// Verify a page digest at `position` against `root` using the inline proof
/// region (`DIGEST × depth` bytes, zero-padded). Mirrors
/// `bmt::Proof::verify_element_inclusion`: a level whose node is the
/// unpaired last one consumes no sibling. The slots left after the
/// consumed siblings must be zero (v1-min §2), so a record is accepted only
/// in its canonical encoding.
pub fn verify_inline(leaf_count: u64, position: u32, page_digest: &Digest, proof: &[u8], root: &Digest) -> bool {
    if leaf_count == 0 || leaf_count > 1 << 31 || (position as u64) >= leaf_count || proof.len() != DIGEST * depth(leaf_count) {
        return false;
    }
    let mut computed = leaf(position, page_digest);
    let mut pos = position as u64;
    let mut level_size = leaf_count;
    let mut next = 0usize;
    while level_size > 1 {
        let is_last_odd = pos.is_multiple_of(2) && pos + 1 >= level_size;
        if is_last_odd {
            computed = node(&computed, &computed);
        } else {
            if next + DIGEST > proof.len() {
                return false;
            }
            let sib: Digest = proof[next..next + DIGEST].try_into().unwrap();
            next += DIGEST;
            computed = if pos.is_multiple_of(2) { node(&computed, &sib) } else { node(&sib, &computed) };
        }
        pos /= 2;
        level_size = level_size.div_ceil(2);
    }
    if proof[next..].iter().any(|b| *b != 0) {
        return false;
    }
    finalize(leaf_count as u32, &computed) == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digests(n: usize) -> Vec<Digest> {
        (0..n).map(|i| *blake3::hash(&(i as u64).to_le_bytes()).as_bytes()).collect()
    }

    #[test]
    fn depth_matches_ceil_log2() {
        for (n, d) in [(1u64, 0usize), (2, 1), (3, 2), (4, 2), (5, 3), (8, 3), (9, 4), (1 << 20, 20), ((1 << 20) + 1, 21)] {
            assert_eq!(depth(n), d, "n = {n}");
        }
    }

    #[test]
    fn every_leaf_verifies_every_size() {
        for n in 1..=40usize {
            let ds = digests(n);
            let t = Tree::build(&ds);
            for (i, d) in ds.iter().enumerate() {
                let p = t.inline_proof(i as u32);
                assert_eq!(p.len(), DIGEST * depth(n as u64));
                assert!(verify_inline(n as u64, i as u32, d, &p, &t.root()), "n={n} i={i}");
                // wrong digest, wrong position, wrong root
                let mut bad = *d;
                bad[0] ^= 1;
                assert!(!verify_inline(n as u64, i as u32, &bad, &p, &t.root()));
                if n > 1 {
                    assert!(!verify_inline(n as u64, ((i + 1) % n) as u32, d, &p, &t.root()));
                }
                let mut r = t.root();
                r[5] ^= 1;
                assert!(!verify_inline(n as u64, i as u32, d, &p, &r));
            }
        }
    }

    #[test]
    fn unused_proof_slots_must_be_zero() {
        // Three leaves: leaf 2 is the unpaired last one at level 0, so its
        // proof uses one of its two slots and the second must stay zero.
        let ds = digests(3);
        let t = Tree::build(&ds);
        let p = t.inline_proof(2);
        assert_eq!(p.len(), 2 * DIGEST);
        assert!(p[DIGEST..].iter().all(|b| *b == 0));
        assert!(verify_inline(3, 2, &ds[2], &p, &t.root()));
        for at in [DIGEST, 2 * DIGEST - 1] {
            let mut bad = p.clone();
            bad[at] = 1;
            assert!(!verify_inline(3, 2, &ds[2], &bad, &t.root()), "slot byte {at}");
        }
        // Every size: any nonzero byte past the consumed siblings fails.
        for n in 2..=40usize {
            let ds = digests(n);
            let t = Tree::build(&ds);
            for i in 0..n {
                let used = t.proof(i as u32).len();
                let mut p = t.inline_proof(i as u32);
                if used * DIGEST < p.len() {
                    let last = p.len() - 1;
                    p[last] ^= 0x80;
                    assert!(!verify_inline(n as u64, i as u32, &ds[i], &p, &t.root()), "n={n} i={i}");
                }
            }
        }
    }

    #[test]
    fn three_leaf_example_from_bmt_docs() {
        // root = hash(3 || hash(hash(hash(0,A),hash(1,B)), hash(hash(2,C),hash(2,C))))
        let ds = digests(3);
        let t = Tree::build(&ds);
        let l0 = leaf(0, &ds[0]);
        let l1 = leaf(1, &ds[1]);
        let l2 = leaf(2, &ds[2]);
        let expect = finalize(3, &node(&node(&l0, &l1), &node(&l2, &l2)));
        assert_eq!(t.root(), expect);
        assert_eq!(t.proof(2), vec![node(&l0, &l1)], "leaf 2 is duplicated at level 0");
    }
}
