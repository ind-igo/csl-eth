//! A streaming trie builder that emits every node, profile §5.
//!
//! Leaves arrive sorted by their full 64-nibble path. The builder keeps one
//! frame per open branch on the path of the last leaf, plus that leaf itself,
//! which is not placed until the next key says how deep it hangs. When a new
//! key diverges at nibble `cpl`, every frame deeper than `cpl` is complete:
//! the pending leaf, then each branch in turn, is encoded and attached to
//! the frame above it, with an extension node bridging any skipped nibbles.
//! Memory is one frame per branch on the current path, at most 64.
//!
//! The sink receives each node at the position traversal enters it
//! ([`NodeKey`]) with its exact RLP. Nodes shorter than 32 bytes are
//! embedded in their parent's RLP and are not sent, except the root, which
//! is always sent so that a walk can start. The root hash is
//! `keccak(rlp(root))` whatever its length, and `EMPTY_ROOT_HASH` with no
//! leaves. The roots agree with `alloy_trie::HashBuilder`
//! (`tests/roundtrip.rs`).

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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// Keys must be strictly increasing.
    Unsorted { prev: Nibbles, next: Nibbles },
    /// Every key is a full hashed path.
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
                    "leaves out of order: {} then {}",
                    hex::encode(prev.pack()),
                    hex::encode(next.pack())
                )
            }
            BuildError::BadKeyLength(n) => write!(f, "key of {n} nibbles, expected {PATH_NIBBLES}"),
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
        Frame {
            depth,
            children: Vec::with_capacity(16),
            mask: TrieMask::default(),
        }
    }
}

pub struct Builder<S: Sink> {
    sink: S,
    stack: Vec<Frame>,
    /// The last leaf, placed once the next key fixes its depth.
    pending: Option<(Nibbles, Vec<u8>)>,
    buf: Vec<u8>,
    leaves: u64,
    nodes: u64,
    embedded: u64,
}

impl<S: Sink> Builder<S> {
    pub fn new(sink: S) -> Builder<S> {
        Builder {
            sink,
            stack: Vec::with_capacity(PATH_NIBBLES),
            pending: None,
            buf: Vec::with_capacity(600),
            leaves: 0,
            nodes: 0,
            embedded: 0,
        }
    }

    /// The next leaf in key order.
    pub fn push(&mut self, key: Nibbles, value: Vec<u8>) -> Result<(), BuildError> {
        if key.len() != PATH_NIBBLES {
            return Err(BuildError::BadKeyLength(key.len()));
        }
        if value.is_empty() {
            return Err(BuildError::EmptyValue(key));
        }
        if let Some((prev, _)) = &self.pending {
            if key <= *prev {
                return Err(BuildError::Unsorted {
                    prev: *prev,
                    next: key,
                });
            }
            let cpl = prev.common_prefix_length(&key);
            self.close_to(cpl);
        }
        self.pending = Some((key, value));
        self.leaves += 1;
        Ok(())
    }

    /// Place the pending leaf and resolve every frame deeper than `cpl`
    /// into the frame at `cpl`, opening it if needed.
    fn close_to(&mut self, cpl: usize) {
        let (prev, value) = self.pending.take().expect("a pending leaf");
        let mut hang: Option<(usize, RlpNode)> = None;
        while self.stack.last().is_some_and(|f| f.depth > cpl) {
            let mut f = self.stack.pop().expect("checked");
            self.attach(&mut f, &prev, &value, &mut hang);
            let node = self.resolve(&f, &prev);
            hang = Some((f.depth, node));
        }
        if self.stack.last().is_none_or(|f| f.depth < cpl) {
            self.stack.push(Frame::new(cpl));
        }
        let mut f = self.stack.pop().expect("just ensured");
        debug_assert_eq!(f.depth, cpl);
        self.attach(&mut f, &prev, &value, &mut hang);
        self.stack.push(f);
    }

    /// Attach the subtree under `f` at nibble `prev[f.depth]`: the pending
    /// leaf if nothing has been resolved yet, otherwise the resolved child
    /// behind an extension for any nibbles between.
    fn attach(
        &mut self,
        f: &mut Frame,
        prev: &Nibbles,
        value: &[u8],
        hang: &mut Option<(usize, RlpNode)>,
    ) {
        let nib = prev.get_unchecked(f.depth);
        let child_depth = f.depth + 1;
        let child = match hang.take() {
            None => {
                let rest = prev.slice(child_depth..);
                self.buf.clear();
                LeafNodeRef::new(&rest, value).encode(&mut self.buf);
                self.emit(NodeKey::prefix(prev, child_depth), false)
            }
            Some((q, node)) if q == child_depth => node,
            Some((q, node)) => {
                let ext = prev.slice(child_depth..q);
                self.buf.clear();
                ExtensionNodeRef::new(&ext, &node).encode(&mut self.buf);
                self.emit(NodeKey::prefix(prev, child_depth), false)
            }
        };
        f.children.push(child);
        f.mask.set_bit(nib);
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
        let Some((prev, value)) = self.pending.take() else {
            debug_assert!(self.stack.is_empty());
            return (
                Built {
                    root: EMPTY_ROOT_HASH,
                    leaves: 0,
                    nodes: 0,
                    embedded: 0,
                },
                self.sink,
            );
        };
        let mut hang: Option<(usize, RlpNode)> = None;
        while let Some(mut f) = self.stack.pop() {
            self.attach(&mut f, &prev, &value, &mut hang);
            let node = self.resolve(&f, &prev);
            hang = Some((f.depth, node));
        }
        match hang {
            None => {
                // One leaf: the root, holding the whole path.
                self.buf.clear();
                LeafNodeRef::new(&prev, &value).encode(&mut self.buf);
                self.emit(NodeKey::ROOT, true);
            }
            Some((0, _)) => {
                // The root branch was emitted by `resolve`; `buf` still holds it.
            }
            Some((q, node)) => {
                let ext = prev.slice(..q);
                self.buf.clear();
                ExtensionNodeRef::new(&ext, &node).encode(&mut self.buf);
                self.emit(NodeKey::ROOT, true);
            }
        }
        let root = keccak256(&self.buf);
        (
            Built {
                root,
                leaves: self.leaves,
                nodes: self.nodes,
                embedded: self.embedded,
            },
            self.sink,
        )
    }
}

/// Build from an in-memory sorted list, collecting nodes. For tests and
/// small tries; the producer streams.
pub fn build_all(
    leaves: &[(Nibbles, Vec<u8>)],
) -> Result<(Built, Vec<(NodeKey, Vec<u8>)>), BuildError> {
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
        assert!(matches!(
            bl.push(path([2; 32]), vec![1]),
            Err(BuildError::Unsorted { .. })
        ));
        assert!(matches!(
            bl.push(path([1; 32]), vec![1]),
            Err(BuildError::Unsorted { .. })
        ));
        assert!(matches!(
            bl.push(Nibbles::from_nibbles([1, 2]), vec![1]),
            Err(BuildError::BadKeyLength(2))
        ));
        assert!(matches!(
            bl.push(path([3; 32]), vec![]),
            Err(BuildError::EmptyValue(_))
        ));
    }

    #[test]
    fn two_leaves_diverging_at_the_root_make_a_branch_and_two_leaves() {
        let (b, nodes) = build_all(&[
            (path([0x10; 32]), vec![0xAA; 40]),
            (path([0x20; 32]), vec![0xBB; 40]),
        ])
        .unwrap();
        let keys: Vec<(usize, Vec<u8>)> = nodes
            .iter()
            .map(|(k, _)| (k.depth(), k.path.pack().to_vec()))
            .collect();
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
        let (b, nodes) =
            build_all(&[(path(a), vec![0xAA; 40]), (path(c), vec![0xBB; 40])]).unwrap();
        // Leaves at depth 64 (empty remaining path), a branch at 63, an extension at 0.
        let depths: Vec<usize> = nodes.iter().map(|(k, _)| k.depth()).collect();
        assert_eq!(depths, vec![64, 64, 63, 0]);
        assert_eq!(b.nodes, 4);
    }
}
