//! A streaming trie builder that emits every node, profile §5.
//!
//! Leaves arrive sorted by their full 64-nibble path. The builder keeps one
//! frame per open branch on the path of the last item, plus that item
//! itself, which is not placed until the next key says how deep it hangs.
//! When a new key diverges at nibble `cpl`, every frame deeper than `cpl` is
//! complete: the pending item, then each branch in turn, is encoded and
//! attached to the frame above it, with an extension node bridging any
//! skipped nibbles. Memory is one frame per branch on the current path, at
//! most 64.
//!
//! Besides leaves the builder accepts *sealed subtrees*: a reference (hash
//! or embedded node) at a path shorter than 64 nibbles, standing for
//! everything under that path without any of it being present. They are
//! what a snap range proof supplies for the parts of the trie outside the
//! range, so a slice of leaves can be built up through its ancestors to the
//! header's `state_root` ([`crate::range`]). A sealed subtree takes part in
//! ordering like a key; no leaf or other subtree may lie under it.
//!
//! The sink receives each node at the position traversal enters it
//! ([`NodeKey`]) with its exact RLP. Nodes shorter than 32 bytes are
//! embedded in their parent's RLP and are not sent, except the root, which
//! is always sent so that a walk can start. Nothing under a sealed subtree
//! is sent. The root hash is `keccak(rlp(root))` whatever its length, and
//! `EMPTY_ROOT_HASH` with no items. The roots agree with
//! `alloy_trie::HashBuilder` (`tests/roundtrip.rs`).

use crate::{key::NodeKey, PATH_NIBBLES};
use alloy_primitives::{hex, keccak256, B256};
use alloy_rlp::Encodable;
use alloy_trie::{
    nodes::{BranchNodeRef, ExtensionNodeRef, LeafNodeRef, RlpNode},
    Nibbles, TrieMask, EMPTY_ROOT_HASH,
};
use core::fmt;

/// Receives every emitted node.
pub trait Sink {
    fn node(&mut self, key: NodeKey, rlp: &[u8]);
}

impl<F: FnMut(NodeKey, &[u8])> Sink for F {
    fn node(&mut self, key: NodeKey, rlp: &[u8]) {
        self(key, rlp)
    }
}

/// A sink that keeps nothing; for verification-only builds.
#[derive(Clone, Copy, Debug, Default)]
pub struct Discard;

impl Sink for Discard {
    fn node(&mut self, _key: NodeKey, _rlp: &[u8]) {}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// Keys must be strictly increasing, and no key may lie under a sealed
    /// subtree or have one under it.
    Unsorted { prev: Nibbles, next: Nibbles },
    /// Every leaf key is a full hashed path; a sealed subtree's path is
    /// shorter than one and not empty.
    BadKeyLength(usize),
    /// A leaf never has an empty value; zero storage words are absent.
    EmptyValue(Nibbles),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::Unsorted { prev, next } => {
                write!(
                    f,
                    "keys out of order or nested: {} ({} nibbles) then {} ({} nibbles)",
                    hex::encode(prev.pack()),
                    prev.len(),
                    hex::encode(next.pack()),
                    next.len()
                )
            }
            BuildError::BadKeyLength(n) => write!(f, "key of {n} nibbles"),
            BuildError::EmptyValue(k) => write!(f, "empty value at {}", hex::encode(k.pack())),
        }
    }
}

impl std::error::Error for BuildError {}

/// What a finished build reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Built {
    pub root: B256,
    pub leaves: u64,
    /// Sealed subtrees taken as given.
    pub sealed: u64,
    /// Nodes handed to the sink.
    pub nodes: u64,
    /// Nodes embedded in a parent and therefore not emitted.
    pub embedded: u64,
}

/// An open branch at `depth`, collecting children in nibble order.
struct Frame {
    depth: usize,
    children: Vec<RlpNode>,
    mask: TrieMask,
}

impl Frame {
    fn new(depth: usize) -> Frame {
        Frame { depth, children: Vec::with_capacity(16), mask: TrieMask::default() }
    }
}

enum Body {
    Leaf(Vec<u8>),
    Sealed(RlpNode),
}

/// The last item, placed once the next key fixes its depth.
struct Pending {
    key: Nibbles,
    body: Body,
}

pub struct Builder<S: Sink> {
    sink: S,
    stack: Vec<Frame>,
    pending: Option<Pending>,
    buf: Vec<u8>,
    leaves: u64,
    sealed: u64,
    nodes: u64,
    embedded: u64,
}

impl<S: Sink> Builder<S> {
    pub fn new(sink: S) -> Builder<S> {
        Builder { sink, stack: Vec::with_capacity(PATH_NIBBLES), pending: None, buf: Vec::with_capacity(600), leaves: 0, sealed: 0, nodes: 0, embedded: 0 }
    }

    /// The next leaf in key order.
    pub fn push(&mut self, key: Nibbles, value: Vec<u8>) -> Result<(), BuildError> {
        if key.len() != PATH_NIBBLES {
            return Err(BuildError::BadKeyLength(key.len()));
        }
        if value.is_empty() {
            return Err(BuildError::EmptyValue(key));
        }
        self.push_item(key, Body::Leaf(value))?;
        self.leaves += 1;
        Ok(())
    }

    /// The next sealed subtree in key order: `node` is the reference the
    /// parent holds for everything under `path` (a hash, or an embedded
    /// node shorter than 32 bytes), exactly as a branch child slot or an
    /// extension's child carries it.
    pub fn push_sealed(&mut self, path: Nibbles, node: RlpNode) -> Result<(), BuildError> {
        if path.is_empty() || path.len() >= PATH_NIBBLES {
            return Err(BuildError::BadKeyLength(path.len()));
        }
        self.push_item(path, Body::Sealed(node))?;
        self.sealed += 1;
        Ok(())
    }

    fn push_item(&mut self, key: Nibbles, body: Body) -> Result<(), BuildError> {
        if let Some(p) = &self.pending {
            let cpl = p.key.common_prefix_length(&key);
            // Nested (one a prefix of the other) or not ascending.
            if cpl == p.key.len() || cpl == key.len() || key < p.key {
                return Err(BuildError::Unsorted { prev: p.key, next: key });
            }
            self.close_to(cpl);
        }
        self.pending = Some(Pending { key, body });
        Ok(())
    }

    /// Place the pending item and resolve every frame deeper than `cpl`
    /// into the frame at `cpl`, opening it if needed.
    fn close_to(&mut self, cpl: usize) {
        let p = self.pending.take().expect("a pending item");
        let mut hang: Option<(usize, RlpNode)> = None;
        while self.stack.last().is_some_and(|f| f.depth > cpl) {
            let mut f = self.stack.pop().expect("checked");
            self.attach(&mut f, &p, &mut hang);
            let node = self.resolve(&f, &p.key);
            hang = Some((f.depth, node));
        }
        if self.stack.last().is_none_or(|f| f.depth < cpl) {
            self.stack.push(Frame::new(cpl));
        }
        let mut f = self.stack.pop().expect("just ensured");
        debug_assert_eq!(f.depth, cpl);
        self.attach(&mut f, &p, &mut hang);
        self.stack.push(f);
    }

    /// Attach the subtree under `f` at nibble `p.key[f.depth]`: the pending
    /// item if nothing has been resolved yet, otherwise the resolved child
    /// behind an extension for any nibbles between.
    fn attach(&mut self, f: &mut Frame, p: &Pending, hang: &mut Option<(usize, RlpNode)>) {
        let nib = p.key.get_unchecked(f.depth);
        let child_depth = f.depth + 1;
        let child = match hang.take() {
            None => self.place(p, child_depth),
            Some((q, node)) if q == child_depth => node,
            Some((q, node)) => {
                let ext = p.key.slice(child_depth..q);
                self.buf.clear();
                ExtensionNodeRef::new(&ext, &node).encode(&mut self.buf);
                self.emit(NodeKey::prefix(&p.key, child_depth), false)
            }
        };
        f.children.push(child);
        f.mask.set_bit(nib);
    }

    /// The reference a parent at `depth - 1` holds for the pending item.
    fn place(&mut self, p: &Pending, depth: usize) -> RlpNode {
        match &p.body {
            Body::Leaf(value) => {
                let rest = p.key.slice(depth..);
                self.buf.clear();
                LeafNodeRef::new(&rest, value).encode(&mut self.buf);
                self.emit(NodeKey::prefix(&p.key, depth), false)
            }
            Body::Sealed(node) if depth == p.key.len() => node.clone(),
            Body::Sealed(node) => {
                // The reference sits deeper than the parent slot that would
                // hold it; only an extension can bridge the gap. A correct
                // proof never produces this, and the root check rejects it
                // when a peer does.
                let ext = p.key.slice(depth..);
                self.buf.clear();
                ExtensionNodeRef::new(&ext, node).encode(&mut self.buf);
                self.emit(NodeKey::prefix(&p.key, depth), false)
            }
        }
    }

    /// Encode a complete branch. A branch at depth 0 is the root and is
    /// always emitted.
    fn resolve(&mut self, f: &Frame, prev: &Nibbles) -> RlpNode {
        self.buf.clear();
        BranchNodeRef::new(&f.children, f.mask).encode(&mut self.buf);
        self.emit(NodeKey::prefix(prev, f.depth), f.depth == 0)
    }

    /// Hand `buf` to the sink if it is a hashed node (or `force`), and
    /// return how the parent references it.
    fn emit(&mut self, key: NodeKey, force: bool) -> RlpNode {
        let node = RlpNode::from_rlp(&self.buf);
        if force || node.is_hash() {
            self.sink.node(key, &self.buf);
            self.nodes += 1;
        } else {
            self.embedded += 1;
        }
        node
    }

    pub fn finish(mut self) -> (Built, S) {
        let Some(p) = self.pending.take() else {
            debug_assert!(self.stack.is_empty());
            return (Built { root: EMPTY_ROOT_HASH, leaves: 0, sealed: 0, nodes: 0, embedded: 0 }, self.sink);
        };
        let mut hang: Option<(usize, RlpNode)> = None;
        while let Some(mut f) = self.stack.pop() {
            self.attach(&mut f, &p, &mut hang);
            let node = self.resolve(&f, &p.key);
            hang = Some((f.depth, node));
        }
        match hang {
            None => match &p.body {
                Body::Leaf(value) => {
                    // One leaf: the root, holding the whole path.
                    self.buf.clear();
                    LeafNodeRef::new(&p.key, value).encode(&mut self.buf);
                    self.emit(NodeKey::ROOT, true);
                }
                Body::Sealed(node) => {
                    // One sealed subtree and nothing else: the root can only
                    // be an extension to it. A proof never yields this.
                    self.buf.clear();
                    ExtensionNodeRef::new(&p.key, node).encode(&mut self.buf);
                    self.emit(NodeKey::ROOT, true);
                }
            },
            Some((0, _)) => {
                // The root branch was emitted by `resolve`; `buf` still holds it.
            }
            Some((q, node)) => {
                let ext = p.key.slice(..q);
                self.buf.clear();
                ExtensionNodeRef::new(&ext, &node).encode(&mut self.buf);
                self.emit(NodeKey::ROOT, true);
            }
        }
        let root = keccak256(&self.buf);
        (Built { root, leaves: self.leaves, sealed: self.sealed, nodes: self.nodes, embedded: self.embedded }, self.sink)
    }
}

/// Every node of a small trie, keyed as the tables key them.
pub type Nodes = Vec<(NodeKey, Vec<u8>)>;

/// Build from an in-memory sorted list, collecting nodes. For tests and
/// small tries; the producer streams.
pub fn build_all(leaves: &[(Nibbles, Vec<u8>)]) -> Result<(Built, Nodes), BuildError> {
    let mut b = Builder::new(Vec::new());
    for (k, v) in leaves {
        b.push(*k, v.clone())?;
    }
    let (built, nodes) = b.finish();
    Ok((built, nodes))
}

impl Sink for Vec<(NodeKey, Vec<u8>)> {
    fn node(&mut self, key: NodeKey, rlp: &[u8]) {
        self.push((key, rlp.to_vec()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(bytes: [u8; 32]) -> Nibbles {
        Nibbles::unpack(bytes)
    }

    #[test]
    fn empty_single_and_order_checks() {
        let (b, nodes) = build_all(&[]).unwrap();
        assert_eq!(b.root, EMPTY_ROOT_HASH);
        assert!(nodes.is_empty());

        let (b, nodes) = build_all(&[(path([1; 32]), vec![0x05])]).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].0, NodeKey::ROOT);
        assert_eq!(b.root, keccak256(&nodes[0].1));
        assert_eq!(b.nodes, 1);

        let mut bl = Builder::new(Vec::new());
        bl.push(path([2; 32]), vec![1]).unwrap();
        assert!(matches!(bl.push(path([2; 32]), vec![1]), Err(BuildError::Unsorted { .. })));
        assert!(matches!(bl.push(path([1; 32]), vec![1]), Err(BuildError::Unsorted { .. })));
        assert!(matches!(bl.push(Nibbles::from_nibbles([1, 2]), vec![1]), Err(BuildError::BadKeyLength(2))));
        assert!(matches!(bl.push(path([3; 32]), vec![]), Err(BuildError::EmptyValue(_))));
    }

    #[test]
    fn two_leaves_diverging_at_the_root_make_a_branch_and_two_leaves() {
        let (b, nodes) = build_all(&[(path([0x10; 32]), vec![0xAA; 40]), (path([0x20; 32]), vec![0xBB; 40])]).unwrap();
        let keys: Vec<(usize, Vec<u8>)> = nodes.iter().map(|(k, _)| (k.depth(), k.path.pack().to_vec())).collect();
        // Sink order is completion order: both leaves (depth 1), then the root.
        assert_eq!(keys, vec![(1, vec![0x10]), (1, vec![0x20]), (0, vec![])]);
        assert_eq!(b.nodes, 3);
        assert_eq!(b.embedded, 0);
    }

    #[test]
    fn shared_prefix_makes_a_root_extension() {
        let mut a = [0x55; 32];
        let mut c = [0x55; 32];
        a[31] = 0x50;
        c[31] = 0x5F;
        let (b, nodes) = build_all(&[(path(a), vec![0xAA; 40]), (path(c), vec![0xBB; 40])]).unwrap();
        // Leaves at depth 64 (empty remaining path), a branch at 63, an extension at 0.
        let depths: Vec<usize> = nodes.iter().map(|(k, _)| k.depth()).collect();
        assert_eq!(depths, vec![64, 64, 63, 0]);
        assert_eq!(b.nodes, 4);
    }

    /// Sealing two depth-1 subtrees reproduces the root of the full build
    /// and emits nothing under the seals.
    #[test]
    fn sealed_subtrees_reproduce_the_root() {
        let mut leaves: Vec<(Nibbles, Vec<u8>)> = (0u8..40)
            .map(|i| {
                let mut k = [i.wrapping_mul(37); 32];
                k[0] = i.wrapping_mul(6); // top nibbles spread over the 16 slots
                (path(k), vec![i.max(1); 40])
            })
            .collect();
        leaves.sort();
        leaves.dedup_by(|a, b| a.0 == b.0);
        let (full, nodes) = build_all(&leaves).unwrap();
        let seal_of = |nib: u8| {
            let key = NodeKey { path: Nibbles::from_nibbles([nib]) };
            nodes.iter().find(|(k, _)| *k == key).map(|(_, r)| RlpNode::from_rlp(r)).expect("a hashed node at depth 1")
        };
        let s6 = seal_of(6);
        let sc = seal_of(0xC);
        let mut b = Builder::new(Vec::new());
        let (mut did6, mut didc) = (false, false);
        for (k, v) in &leaves {
            let top = k.get_unchecked(0);
            if top > 6 && !did6 {
                b.push_sealed(Nibbles::from_nibbles([6]), s6.clone()).unwrap();
                did6 = true;
            }
            if top > 0xC && !didc {
                b.push_sealed(Nibbles::from_nibbles([0xC]), sc.clone()).unwrap();
                didc = true;
            }
            if top == 6 || top == 0xC {
                continue;
            }
            b.push(*k, v.clone()).unwrap();
        }
        let (partial, emitted) = b.finish();
        assert_eq!(partial.root, full.root);
        assert_eq!(partial.sealed, 2);
        assert!(emitted.iter().all(|(k, _)| k.depth() == 0 || !matches!(k.path.get_unchecked(0), 6 | 0xC)));
        assert!(emitted.iter().any(|(k, _)| *k == NodeKey::ROOT));
        assert!(partial.nodes < full.nodes);

        // Nesting is refused both ways, and so is an empty seal path.
        let mut b = Builder::new(Discard);
        b.push_sealed(Nibbles::from_nibbles([6]), s6.clone()).unwrap();
        let mut under = [0u8; 32];
        under[0] = 0x61;
        assert!(matches!(b.push(path(under), vec![1]), Err(BuildError::Unsorted { .. })));
        let mut b = Builder::new(Discard);
        b.push(path(under), vec![1]).unwrap();
        assert!(matches!(b.push_sealed(Nibbles::from_nibbles([6, 1]), s6.clone()), Err(BuildError::Unsorted { .. })));
        assert!(matches!(b.push_sealed(Nibbles::new(), s6), Err(BuildError::BadKeyLength(0))));
    }
}
