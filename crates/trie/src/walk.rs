//! The verifier, profile §2: one walk for every read.
//!
//! Starting from a root hash the caller trusts, the walk asks the source
//! for the node at each position on the key's path and checks that it
//! hashes to what its parent committed. A branch whose slot for the next
//! nibble is empty, an extension whose nibbles leave the path, or a leaf
//! whose remaining path differs: `Absent`, proven by the trie. A node the
//! source does not have: `Missing`, which is the client's repair round, and
//! never absence. Anything that fails to hash or decode: `Invalid`, which
//! is `Insufficient` for the client and a fault on whoever served the page.

use crate::{key::NodeKey, MAX_NODE_BYTES, MAX_WALK_NODES, PATH_NIBBLES};
use alloy_primitives::{keccak256, B256};
use alloy_rlp::Decodable;
use alloy_trie::{
    nodes::{RlpNode, TrieNode},
    Nibbles, EMPTY_ROOT_HASH,
};
use std::collections::HashMap;

/// Nodes the client already holds, by position.
pub trait NodeSource {
    fn node(&self, key: &NodeKey) -> Option<&[u8]>;
}

impl NodeSource for HashMap<NodeKey, Vec<u8>> {
    fn node(&self, key: &NodeKey) -> Option<&[u8]> {
        self.get(key).map(Vec::as_slice)
    }
}

impl<T: NodeSource> NodeSource for &T {
    fn node(&self, key: &NodeKey) -> Option<&[u8]> {
        (**self).node(key)
    }
}

/// How an absence was proven; the workload counts each shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AbsentBy {
    /// The trie is empty.
    EmptyTrie,
    /// A branch has no child for the next nibble.
    EmptySlot,
    /// An extension's nibbles leave the path.
    ExtensionMismatch,
    /// A leaf's remaining path is not the rest of the key.
    LeafMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The node does not hash to what its parent committed.
    HashMismatch,
    /// The node is longer than `MAX_NODE_BYTES`.
    TooLarge(usize),
    /// Not a trie node, or bytes after it.
    Rlp,
    /// A branch below depth 64, an extension past it, or an empty extension.
    Shape,
    /// More than `MAX_WALK_NODES` consumed.
    TooManyNodes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The leaf's value, verified to the root.
    Present(Vec<u8>),
    Absent(AbsentBy),
    /// The source lacks this node; fetch it and walk again.
    Missing(NodeKey),
    /// The node at this position is wrong.
    Invalid(NodeKey, Invalid),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Walk {
    pub outcome: Outcome,
    /// Nodes decoded, embedded ones included.
    pub nodes: usize,
    /// Positions asked of the source, in order; the last one may be the
    /// `Missing` key.
    pub fetched: Vec<NodeKey>,
    /// The hash the parent committed to at the last position asked of the
    /// source: for a `Missing` outcome, the node to fetch by hash (the
    /// content-addressed baseline's key). `None` before the first ask.
    pub expected: Option<B256>,
}

/// Walk `path` (64 nibbles) from `root` over `src`.
pub fn walk<S: NodeSource>(root: B256, path: &Nibbles, src: S) -> Walk {
    debug_assert_eq!(path.len(), PATH_NIBBLES);
    let mut fetched = Vec::with_capacity(10);
    let mut nodes = 0usize;
    let done = |outcome, nodes, fetched, expected| Walk {
        outcome,
        nodes,
        fetched,
        expected,
    };
    if root == EMPTY_ROOT_HASH {
        return done(Outcome::Absent(AbsentBy::EmptyTrie), 0, fetched, None);
    }
    let mut expected: Option<B256> = None;
    let mut depth = 0usize;
    let mut expect = RlpNode::word_rlp(&root);
    loop {
        let key = NodeKey::prefix(path, depth);
        if nodes >= MAX_WALK_NODES {
            return done(Outcome::Invalid(key, Invalid::TooManyNodes), nodes, fetched, expected);
        }
        let bytes: &[u8] = if let Some(h) = expect.as_hash() {
            fetched.push(key);
            expected = Some(h);
            let Some(b) = src.node(&key) else {
                return done(Outcome::Missing(key), nodes, fetched, expected);
            };
            if b.len() > MAX_NODE_BYTES {
                return done(
                    Outcome::Invalid(key, Invalid::TooLarge(b.len())),
                    nodes,
                    fetched,
                    expected,
                );
            }
            if keccak256(b) != h {
                return done(Outcome::Invalid(key, Invalid::HashMismatch), nodes, fetched, expected);
            }
            b
        } else {
            // Embedded in the parent, already covered by the parent's hash.
            expect.as_slice()
        };
        nodes += 1;
        let mut rest = bytes;
        let Ok(node) = TrieNode::decode(&mut rest) else {
            return done(Outcome::Invalid(key, Invalid::Rlp), nodes, fetched, expected);
        };
        if !rest.is_empty() {
            return done(Outcome::Invalid(key, Invalid::Rlp), nodes, fetched, expected);
        }
        match node {
            // keccak(0x80) is EMPTY_ROOT_HASH, handled above; anywhere else it is malformed.
            TrieNode::EmptyRoot => {
                return done(Outcome::Invalid(key, Invalid::Shape), nodes, fetched, expected)
            }
            TrieNode::Branch(b) => {
                if depth >= PATH_NIBBLES {
                    return done(Outcome::Invalid(key, Invalid::Shape), nodes, fetched, expected);
                }
                let nib = path.get_unchecked(depth);
                let child = b
                    .as_ref()
                    .children()
                    .find(|(i, _)| *i == nib)
                    .and_then(|(_, c)| c.cloned());
                match child {
                    None => return done(Outcome::Absent(AbsentBy::EmptySlot), nodes, fetched, expected),
                    Some(c) => {
                        expect = c;
                        depth += 1;
                    }
                }
            }
            TrieNode::Extension(e) => {
                let n = e.key.len();
                if n == 0 || depth + n > PATH_NIBBLES {
                    return done(Outcome::Invalid(key, Invalid::Shape), nodes, fetched, expected);
                }
                if path.slice(depth..depth + n) != e.key {
                    return done(Outcome::Absent(AbsentBy::ExtensionMismatch), nodes, fetched, expected);
                }
                expect = e.child;
                depth += n;
            }
            TrieNode::Leaf(l) => {
                if path.slice(depth..) != l.key {
                    return done(Outcome::Absent(AbsentBy::LeafMismatch), nodes, fetched, expected);
                }
                return done(Outcome::Present(l.value), nodes, fetched, expected);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build::build_all;

    fn map(nodes: Vec<(NodeKey, Vec<u8>)>) -> HashMap<NodeKey, Vec<u8>> {
        nodes.into_iter().collect()
    }

    #[test]
    fn empty_root_is_absent_without_a_fetch() {
        let w = walk(EMPTY_ROOT_HASH, &Nibbles::unpack([0; 32]), HashMap::new());
        assert_eq!(w.outcome, Outcome::Absent(AbsentBy::EmptyTrie));
        assert!(w.fetched.is_empty());
    }

    #[test]
    fn single_leaf_root_present_and_mismatch() {
        let k = Nibbles::unpack([7; 32]);
        let (b, nodes) = build_all(&[(k, vec![9; 10])]).unwrap();
        let src = map(nodes);
        let w = walk(b.root, &k, &src);
        assert_eq!(w.outcome, Outcome::Present(vec![9; 10]));
        assert_eq!(w.fetched, vec![NodeKey::ROOT]);
        let w = walk(b.root, &Nibbles::unpack([8; 32]), &src);
        assert_eq!(w.outcome, Outcome::Absent(AbsentBy::LeafMismatch));
        let w = walk(B256::repeat_byte(1), &k, &src);
        assert_eq!(
            w.outcome,
            Outcome::Invalid(NodeKey::ROOT, Invalid::HashMismatch)
        );
        let w = walk(b.root, &k, HashMap::new());
        assert_eq!(w.outcome, Outcome::Missing(NodeKey::ROOT));
    }
}
