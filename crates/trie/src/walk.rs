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

/// One node a walk reached, in order, for a caller that shows its work
/// ([`walk_traced`]). Nothing here changes what the walk decides.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// Where the node sits: the nibbles consumed to reach it.
    pub key: NodeKey,
    /// The hash its parent committed to (the root hash for the root), which
    /// the node's bytes were checked against; `None` for a node embedded in
    /// its parent, covered by the parent's hash.
    pub hash: Option<B256>,
    /// Its RLP length: the bytes served for a hashed node, the bytes inside
    /// the parent for an embedded one; 0 when nothing was served.
    pub len: usize,
    pub shape: Shape,
}

/// What a walk found at one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A branch: the slots that hold a child (bit `i` for nibble `i`), the
    /// path's next nibble, and whether that slot has a child (if not, the
    /// key is absent: `AbsentBy::EmptySlot`).
    Branch {
        occupied: u16,
        next: u8,
        taken: bool,
    },
    /// An extension: its nibbles, and whether the path follows them (if
    /// not, `AbsentBy::ExtensionMismatch`).
    Extension { nibbles: Nibbles, follows: bool },
    /// A leaf: the rest of the key it holds, whether that is the rest of
    /// the path (if not, `AbsentBy::LeafMismatch`), and its value.
    Leaf {
        rest: Nibbles,
        matches: bool,
        value: Vec<u8>,
    },
    /// The source did not have it (`Outcome::Missing`).
    Missing,
    /// Served but rejected (`Outcome::Invalid`); `got` is the keccak of the
    /// bytes served, when they were hashed.
    Invalid { what: Invalid, got: Option<B256> },
}

/// Walk `path` (64 nibbles) from `root` over `src`.
pub fn walk<S: NodeSource>(root: B256, path: &Nibbles, src: S) -> Walk {
    walk_inner(root, path, src, None)
}

/// [`walk`], also recording every node it reached in `trace`, in order
/// (the last one is where it stopped). The outcome is [`walk`]'s.
pub fn walk_traced<S: NodeSource>(
    root: B256,
    path: &Nibbles,
    src: S,
    trace: &mut Vec<Step>,
) -> Walk {
    walk_inner(root, path, src, Some(trace))
}

fn walk_inner<S: NodeSource>(
    root: B256,
    path: &Nibbles,
    src: S,
    mut trace: Option<&mut Vec<Step>>,
) -> Walk {
    debug_assert_eq!(path.len(), PATH_NIBBLES);
    let mut fetched = Vec::with_capacity(10);
    let mut nodes = 0usize;
    let done = |outcome, nodes, fetched, expected| Walk {
        outcome,
        nodes,
        fetched,
        expected,
    };
    // Trace-only data that costs an allocation is built only when tracing.
    let tracing = trace.is_some();
    let mut note = |key: NodeKey, hash: Option<B256>, len: usize, shape: Shape| {
        if let Some(t) = trace.as_deref_mut() {
            t.push(Step {
                key,
                hash,
                len,
                shape,
            });
        }
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
            let what = Invalid::TooManyNodes;
            note(key, expect.as_hash(), 0, Shape::Invalid { what, got: None });
            return done(Outcome::Invalid(key, what), nodes, fetched, expected);
        }
        let hash = expect.as_hash();
        let bytes: &[u8] = if let Some(h) = hash {
            fetched.push(key);
            expected = Some(h);
            let Some(b) = src.node(&key) else {
                note(key, hash, 0, Shape::Missing);
                return done(Outcome::Missing(key), nodes, fetched, expected);
            };
            if b.len() > MAX_NODE_BYTES {
                let what = Invalid::TooLarge(b.len());
                note(key, hash, b.len(), Shape::Invalid { what, got: None });
                return done(Outcome::Invalid(key, what), nodes, fetched, expected);
            }
            let got = keccak256(b);
            if got != h {
                let what = Invalid::HashMismatch;
                note(
                    key,
                    hash,
                    b.len(),
                    Shape::Invalid {
                        what,
                        got: Some(got),
                    },
                );
                return done(Outcome::Invalid(key, what), nodes, fetched, expected);
            }
            b
        } else {
            // Embedded in the parent, already covered by the parent's hash.
            expect.as_slice()
        };
        let len = bytes.len();
        let rejected = |what| Shape::Invalid { what, got: None };
        nodes += 1;
        let mut rest = bytes;
        let Ok(node) = TrieNode::decode(&mut rest) else {
            note(key, hash, len, rejected(Invalid::Rlp));
            return done(
                Outcome::Invalid(key, Invalid::Rlp),
                nodes,
                fetched,
                expected,
            );
        };
        if !rest.is_empty() {
            note(key, hash, len, rejected(Invalid::Rlp));
            return done(
                Outcome::Invalid(key, Invalid::Rlp),
                nodes,
                fetched,
                expected,
            );
        }
        match node {
            // keccak(0x80) is EMPTY_ROOT_HASH, handled above; anywhere else it is malformed.
            TrieNode::EmptyRoot => {
                note(key, hash, len, rejected(Invalid::Shape));
                return done(
                    Outcome::Invalid(key, Invalid::Shape),
                    nodes,
                    fetched,
                    expected,
                );
            }
            TrieNode::Branch(b) => {
                if depth >= PATH_NIBBLES {
                    note(key, hash, len, rejected(Invalid::Shape));
                    return done(
                        Outcome::Invalid(key, Invalid::Shape),
                        nodes,
                        fetched,
                        expected,
                    );
                }
                let nib = path.get_unchecked(depth);
                let child = b
                    .as_ref()
                    .children()
                    .find(|(i, _)| *i == nib)
                    .and_then(|(_, c)| c.cloned());
                let shape = Shape::Branch {
                    occupied: b.state_mask.get(),
                    next: nib,
                    taken: child.is_some(),
                };
                note(key, hash, len, shape);
                match child {
                    None => {
                        return done(
                            Outcome::Absent(AbsentBy::EmptySlot),
                            nodes,
                            fetched,
                            expected,
                        )
                    }
                    Some(c) => {
                        expect = c;
                        depth += 1;
                    }
                }
            }
            TrieNode::Extension(e) => {
                let n = e.key.len();
                if n == 0 || depth + n > PATH_NIBBLES {
                    note(key, hash, len, rejected(Invalid::Shape));
                    return done(
                        Outcome::Invalid(key, Invalid::Shape),
                        nodes,
                        fetched,
                        expected,
                    );
                }
                let follows = path.slice(depth..depth + n) == e.key;
                note(
                    key,
                    hash,
                    len,
                    Shape::Extension {
                        nibbles: e.key,
                        follows,
                    },
                );
                if !follows {
                    return done(
                        Outcome::Absent(AbsentBy::ExtensionMismatch),
                        nodes,
                        fetched,
                        expected,
                    );
                }
                expect = e.child;
                depth += n;
            }
            TrieNode::Leaf(l) => {
                let matches = path.slice(depth..) == l.key;
                if tracing {
                    note(
                        key,
                        hash,
                        len,
                        Shape::Leaf {
                            rest: l.key,
                            matches,
                            value: l.value.clone(),
                        },
                    );
                }
                if !matches {
                    return done(
                        Outcome::Absent(AbsentBy::LeafMismatch),
                        nodes,
                        fetched,
                        expected,
                    );
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
    fn a_traced_walk_decides_as_the_walk_does_and_names_each_node() {
        let k = Nibbles::unpack([7; 32]);
        let other = Nibbles::unpack([
            7, 7, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
            22, 23, 24, 25, 26, 27, 28,
        ]);
        let (b, nodes) = build_all(&[(k, vec![9; 40]), (other, vec![3; 40])]).unwrap();
        let src = map(nodes);
        for q in [
            k,
            other,
            Nibbles::unpack([7, 7, 7, 9].repeat(8)),
            Nibbles::unpack([1; 32]),
        ] {
            let mut t = Vec::new();
            let w = walk_traced(b.root, &q, &src, &mut t);
            assert_eq!(w, walk(b.root, &q, &src));
            assert_eq!(t[0].hash, Some(b.root));
            assert_eq!(t[0].key, NodeKey::ROOT);
            for s in &t {
                if let (Some(h), Some(v)) = (s.hash, src.get(&s.key)) {
                    assert_eq!(keccak256(v), h);
                    assert_eq!(s.len, v.len());
                }
            }
        }
        let mut t = Vec::new();
        walk_traced(b.root, &k, &src, &mut t);
        assert!(matches!(t[0].shape, Shape::Extension { follows: true, .. }));
        assert!(matches!(
            t[1].shape,
            Shape::Branch {
                taken: true,
                next: 7,
                ..
            }
        ));
        assert!(
            matches!(&t.last().unwrap().shape, Shape::Leaf { matches: true, value, .. } if *value == vec![9; 40])
        );
        let mut t = Vec::new();
        walk_traced(B256::repeat_byte(1), &k, &src, &mut t);
        assert!(matches!(
            t[0].shape,
            Shape::Invalid {
                what: Invalid::HashMismatch,
                got: Some(_)
            }
        ));
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
