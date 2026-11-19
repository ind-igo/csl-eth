//! The Ethereum profile's trie layer for the cold state layer
//! (`wiki/projects/cold-state-layer/specs/profiles/ethereum.md`).
//!
//! Three things, all over consensus objects only (hashed leaves, canonical
//! MPT node RLP, the header's `state_root`):
//!
//! - [`key`]: where a node sits (§1). A node is keyed by the nibbles
//!   consumed to reach it, `packed_path[31] ‖ depth`, so the account table
//!   sorts by path and every subtree is contiguous; the storage table hashes
//!   that position under its owner so a contract's trie is not one prefix
//!   group.
//! - [`build`]: a streaming builder from sorted leaves that emits every
//!   node the trie has (§5), not only the root. Embedded nodes (RLP shorter
//!   than 32 bytes) live inside their parent and are not emitted.
//! - [`range`]: snap range proofs checked by rebuilding, and the sealed
//!   subtrees they yield so a slice builds up to `state_root`.
//! - [`walk`]: the one verifier (§2). Hash nodes from `state_root` down to
//!   a leaf or an empty branch slot; anything the files fail to provide is
//!   `Missing`, never absence.
//!
//! Nothing here reads files or talks to a network. The producer feeds the
//! builder's nodes through the run writer; the client feeds the walk with
//! pages it fetched.

pub mod build;
pub mod key;
pub mod range;
pub mod value;
pub mod walk;

pub use alloy_primitives::{keccak256, B256, U256};
pub use alloy_trie::{Nibbles, EMPTY_ROOT_HASH, KECCAK_EMPTY};
pub use build::{BuildError, Builder, Built, Discard, Sink};
pub use range::{proof_for, verify_range, ProofError, RangeError, Sealed, Verified};
pub use key::{code_key, path_of, speculative_keys, NodeKey, TooDeep, MAX_DEPTH};
pub use value::{decode_word, encode_word, Account, EMPTY_ROOT};
pub use walk::{walk, walk_traced, AbsentBy, Invalid, NodeSource, Outcome, Shape, Step, Walk};

/// The profile's `max_entry_bytes`: the largest node RLP a client decodes.
/// A full branch of hashed children is 532 bytes; an account leaf is about
/// 110; a storage leaf under 80.
pub const MAX_NODE_BYTES: usize = 1024;

/// Nodes a single walk may consume (profile §2 resource bounds). A path is
/// 64 nibbles, so an honest trie never needs more than 65 nodes on it.
pub const MAX_WALK_NODES: usize = 64;

/// Nibbles in a full key path: 32 bytes of keccak output.
pub const PATH_NIBBLES: usize = 64;
