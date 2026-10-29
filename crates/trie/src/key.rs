//! Node position and table keys, profile §1.
//!
//! A node's position is where traversal enters it: `depth` nibbles consumed
//! from the root, and those nibbles as the path. A leaf's or extension's own
//! remaining path is inside its RLP, not in the key. The 32-byte table key
//! is `packed_path[31] ‖ depth`, nibbles left-aligned with unused nibbles
//! zero, so `depth` is at most 62.

use crate::PATH_NIBBLES;
use alloy_primitives::{hex, keccak256, B256};
use alloy_trie::Nibbles;
use core::fmt;

/// The deepest node position the 31-byte packed path can hold. A trie
/// needing more would require two keys sharing 248 bits of keccak output.
pub const MAX_DEPTH: usize = 62;

/// Domain separator for storage-node keys.
pub const STORAGE_NODE_DOMAIN: &[u8] = b"csl/eth/storage-node/v1";

/// Where a node sits in its trie: the nibbles consumed to reach it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeKey {
    /// `depth()` nibbles, the prefix of every key under this node.
    pub path: Nibbles,
}

impl fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NodeKey({}@{})",
            hex::encode(self.path.pack()),
            self.depth()
        )
    }
}

/// A node deeper than [`MAX_DEPTH`]: the table key cannot hold it and the
/// producer must abort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooDeep(pub usize);

impl fmt::Display for TooDeep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "node at depth {} cannot be keyed (max {MAX_DEPTH})",
            self.0
        )
    }
}

impl std::error::Error for TooDeep {}

impl NodeKey {
    /// The root: nothing consumed.
    pub const ROOT: NodeKey = NodeKey {
        path: Nibbles::new(),
    };

    /// The node entered after consuming `depth` nibbles of `full`.
    pub fn prefix(full: &Nibbles, depth: usize) -> NodeKey {
        NodeKey {
            path: full.slice(..depth),
        }
    }

    pub fn depth(&self) -> usize {
        self.path.len()
    }

    /// `packed_path[31] ‖ depth`: the account table's key, and the preimage
    /// tail of the storage table's.
    pub fn table_key(&self) -> Result<[u8; 32], TooDeep> {
        let depth = self.depth();
        if depth > MAX_DEPTH {
            return Err(TooDeep(depth));
        }
        let mut out = [0u8; 32];
        // At most 31 bytes for 62 nibbles; an odd depth leaves its low nibble zero.
        self.path.pack_to(&mut out[..31]);
        out[31] = depth as u8;
        Ok(out)
    }

    /// The storage table's key: `keccak(domain ‖ owner ‖ packed_path[31] ‖ depth)`,
    /// where `owner` is `keccak(address)`. Hashing makes the key uniform so a
    /// large contract's trie is not one prefix group; using the owner's
    /// hashed address rather than its storage root keeps keys stable across
    /// snapshots.
    pub fn storage_table_key(&self, owner: &B256) -> Result<[u8; 32], TooDeep> {
        let tail = self.table_key()?;
        let mut pre = Vec::with_capacity(STORAGE_NODE_DOMAIN.len() + 64);
        pre.extend_from_slice(STORAGE_NODE_DOMAIN);
        pre.extend_from_slice(owner.as_slice());
        pre.extend_from_slice(&tail);
        Ok(keccak256(&pre).0)
    }
}

/// The code table's key: `keccak(code)`, the account's `codeHash`.
pub fn code_key(code: &[u8]) -> [u8; 32] {
    keccak256(code).0
}

/// The full 64-nibble path of a hashed key.
pub fn path_of(hashed: &B256) -> Nibbles {
    Nibbles::unpack(hashed.as_slice())
}

/// The node keys a client requests speculatively for `path` before it has
/// seen any node: depths `0 ..= max_depth` (profile §2). Depths an
/// extension skips are wasted requests; depths past the leaf are too.
pub fn speculative_keys(path: &Nibbles, max_depth: usize) -> Vec<NodeKey> {
    debug_assert_eq!(path.len(), PATH_NIBBLES);
    (0..=max_depth.min(MAX_DEPTH))
        .map(|d| NodeKey::prefix(path, d))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_key_packs_left_aligned_with_depth_last() {
        let full = Nibbles::unpack([0xAB; 32]);
        let k = NodeKey::prefix(&full, 3).table_key().unwrap();
        assert_eq!(&k[..2], &[0xAB, 0xA0]);
        assert!(k[2..31].iter().all(|b| *b == 0));
        assert_eq!(k[31], 3);
        let root = NodeKey::ROOT.table_key().unwrap();
        assert_eq!(root, [0u8; 32]);
        assert_eq!(NodeKey::prefix(&full, 62).table_key().unwrap()[31], 62);
        assert_eq!(NodeKey::prefix(&full, 63).table_key(), Err(TooDeep(63)));
    }

    #[test]
    fn path_order_is_table_key_order_within_a_depth_and_parent_before_child() {
        // (p, d) is immediately followed by its nibble-0 child's subtree:
        // the parent's key has zero nibbles where the child has its own,
        // and a smaller depth byte.
        let full = Nibbles::unpack([0x12; 32]);
        let parent = NodeKey::prefix(&full, 4).table_key().unwrap();
        let child0 = {
            let mut p = full.slice(..4);
            p.push(0);
            NodeKey { path: p }.table_key().unwrap()
        };
        let child1 = NodeKey::prefix(&full, 5).table_key().unwrap();
        assert!(parent < child0);
        assert!(child0 < child1);
    }

    #[test]
    fn storage_key_depends_on_owner_and_position() {
        let full = Nibbles::unpack([0x77; 32]);
        let a = NodeKey::prefix(&full, 2)
            .storage_table_key(&B256::repeat_byte(1))
            .unwrap();
        let b = NodeKey::prefix(&full, 2)
            .storage_table_key(&B256::repeat_byte(2))
            .unwrap();
        let c = NodeKey::prefix(&full, 3)
            .storage_table_key(&B256::repeat_byte(1))
            .unwrap();
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn speculative_keys_are_the_prefixes() {
        let full = Nibbles::unpack([0x5A; 32]);
        let ks = speculative_keys(&full, 9);
        assert_eq!(ks.len(), 10);
        for (d, k) in ks.iter().enumerate() {
            assert_eq!(k.depth(), d);
            assert!(full.starts_with(&k.path));
        }
    }
}
