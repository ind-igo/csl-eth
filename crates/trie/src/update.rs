//! Applying post-state changes to a trie held elsewhere: the core of
//! following the chain with block access lists (EIP-7928).
//!
//! A [`Trie`] starts as one root hash. Nodes are read on demand through a
//! [`Load`] (the tracker reads its runs by position; a test or a replay
//! reads whatever it holds) as inserts and removals walk down, and every
//! node the update rewrites is kept in memory. [`World`] puts the account
//! trie and the storage tries together: a changed account's storage trie
//! is updated first and its root goes into the account leaf.
//!
//! Every node an update might need is a node of the trie it started from,
//! since anything newer is in memory. A node the loader cannot give makes
//! that subtree *lost*: its contents and hash are unknown, and so is every
//! ancestor's hash, but the rest of the trie stays exact. The caller can
//! fetch what the loader reported missing and run the update again, or
//! keep the nodes that came out exact: a lost subtree only means some new
//! nodes are not computed, never that a computed node is wrong, as long as
//! the changes themselves are right. (Nothing here trusts that: a node is
//! only ever used after its hash matches what its parent committed to.)
//!
//! The cases a deletion or an insert brings with it are all here: a branch
//! left with one child collapses into its child (which must be read to know
//! whether it is a leaf, an extension or a branch); an insert splits a leaf
//! or an extension; nodes cross between hashed and embedded (under 32
//! bytes of RLP, inside their parent) as their keys grow or shrink.

use crate::{encode_word, path_of, value::Account, EMPTY_ROOT, KECCAK_EMPTY};
use alloy_primitives::{keccak256, Bytes, B256, U256};
use alloy_rlp::Decodable;
use alloy_trie::{
    nodes::{BranchNodeRef, ExtensionNodeRef, LeafNodeRef, RlpNode, TrieNode},
    Nibbles, TrieMask,
};
use std::collections::HashMap;

/// Reads the trie an update starts from.
pub trait Load {
    /// The node at `path` of the account trie (`owner` none) or of
    /// `owner`'s storage trie that hashes to `hash`, if the loader has it.
    /// What the loader cannot give, it notes as needed (or not, when it
    /// knows nobody can give it).
    fn load(&mut self, owner: Option<B256>, path: &Nibbles, hash: &B256) -> Option<Vec<u8>>;
}

/// A leaf value being inserted: known bytes, or unknown (a change the
/// caller cannot follow, such as an account outside the part of state it
/// holds), which makes the leaf lost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Set(Vec<u8>),
    Unknown,
}

#[derive(Clone, Debug)]
enum Kind {
    Empty,
    /// Not read: a subtree of the trie the update started from.
    Hash(B256),
    /// Changed, but how is unknown.
    Lost,
    Leaf { key: Nibbles, value: Vec<u8> },
    Ext { key: Nibbles, child: Box<Node> },
    Branch { kids: Box<[Node; 16]> },
}

#[derive(Clone, Debug)]
struct Node {
    kind: Kind,
    /// Written by an update (else as read).
    fresh: bool,
    /// The node's RLP, once known.
    enc: Option<Bytes>,
}

impl Node {
    fn new(kind: Kind) -> Node {
        Node {
            kind,
            fresh: true,
            enc: None,
        }
    }

    fn empty() -> Node {
        Node {
            kind: Kind::Empty,
            fresh: false,
            enc: None,
        }
    }

    fn lose(&mut self) {
        *self = Node::new(Kind::Lost);
    }

    fn touch(&mut self) {
        self.fresh = true;
        self.enc = None;
    }

    fn is_empty(&self) -> bool {
        matches!(self.kind, Kind::Empty)
    }
}

fn leaf(key: Nibbles, v: Value) -> Node {
    match v {
        Value::Set(value) => Node::new(Kind::Leaf { key, value }),
        Value::Unknown => Node::new(Kind::Lost),
    }
}

fn empty_kids() -> Box<[Node; 16]> {
    Box::new(std::array::from_fn(|_| Node::empty()))
}

/// A child as its parent references it.
fn child_of(r: &RlpNode) -> Result<Node, alloy_rlp::Error> {
    if let Some(h) = r.as_hash() {
        return Ok(Node {
            kind: Kind::Hash(h),
            fresh: false,
            enc: None,
        });
    }
    Ok(Node {
        kind: decode(r.as_ref())?,
        fresh: false,
        enc: Some(Bytes::copy_from_slice(r.as_ref())),
    })
}

fn decode(rlp: &[u8]) -> Result<Kind, alloy_rlp::Error> {
    let mut buf = rlp;
    let n = TrieNode::decode(&mut buf)?;
    if !buf.is_empty() {
        return Err(alloy_rlp::Error::UnexpectedLength);
    }
    Ok(match n {
        TrieNode::EmptyRoot => Kind::Empty,
        TrieNode::Branch(b) => {
            let mut kids = empty_kids();
            for (nib, c) in b.as_ref().children() {
                if let Some(c) = c {
                    kids[nib as usize] = child_of(c)?;
                }
            }
            Kind::Branch { kids }
        }
        TrieNode::Extension(e) => Kind::Ext {
            key: e.key,
            child: Box::new(child_of(&e.child)?),
        },
        TrieNode::Leaf(l) => Kind::Leaf {
            key: l.key,
            value: l.value,
        },
    })
}

/// Read `n` if it is a hash. False if it could not be read (it stays a
/// hash) or is lost.
fn reveal(n: &mut Node, owner: Option<B256>, path: &Nibbles, ld: &mut dyn Load) -> bool {
    match &n.kind {
        Kind::Lost => false,
        Kind::Hash(h) => {
            let h = *h;
            let Some(rlp) = ld.load(owner, path, &h) else {
                return false;
            };
            if keccak256(&rlp) != h {
                return false;
            }
            match decode(&rlp) {
                Ok(k) => {
                    *n = Node {
                        kind: k,
                        fresh: false,
                        enc: Some(Bytes::from(rlp)),
                    };
                    true
                }
                Err(_) => false,
            }
        }
        _ => true,
    }
}

fn nib(p: &Nibbles, i: u8) -> Nibbles {
    let mut q = *p;
    q.push(i);
    q
}

fn cat(a: &Nibbles, b: &Nibbles) -> Nibbles {
    a.join(b)
}

/// Put `v` at `key` (relative to `n`, at `path`). Returns whether `n`
/// changed.
fn insert(
    n: &mut Node,
    owner: Option<B256>,
    path: &Nibbles,
    key: Nibbles,
    v: Value,
    ld: &mut dyn Load,
) -> bool {
    if !reveal(n, owner, path, ld) {
        n.lose();
        return true;
    }
    match &mut n.kind {
        Kind::Empty => {
            *n = leaf(key, v);
            true
        }
        Kind::Leaf { key: k, value } => {
            if *k == key {
                match v {
                    Value::Set(b) if b == *value => false,
                    Value::Set(b) => {
                        *value = b;
                        n.touch();
                        true
                    }
                    Value::Unknown => {
                        n.lose();
                        true
                    }
                }
            } else {
                let c = k.common_prefix_length(&key);
                let mut kids = empty_kids();
                let old = Node::new(Kind::Leaf {
                    key: k.slice(c + 1..),
                    value: std::mem::take(value),
                });
                kids[k.get_unchecked(c) as usize] = old;
                kids[key.get_unchecked(c) as usize] = leaf(key.slice(c + 1..), v);
                let b = Node::new(Kind::Branch { kids });
                *n = if c > 0 {
                    Node::new(Kind::Ext {
                        key: key.slice(..c),
                        child: Box::new(b),
                    })
                } else {
                    b
                };
                true
            }
        }
        Kind::Ext { key: k, child } => {
            let c = k.common_prefix_length(&key);
            if c == k.len() {
                let at = cat(path, k);
                let ch = insert(child, owner, &at, key.slice(c..), v, ld);
                if ch {
                    n.touch();
                }
                ch
            } else {
                let mut kids = empty_kids();
                let rest = k.slice(c + 1..);
                let child = std::mem::replace(child.as_mut(), Node::empty());
                kids[k.get_unchecked(c) as usize] = if rest.is_empty() {
                    child
                } else {
                    Node::new(Kind::Ext {
                        key: rest,
                        child: Box::new(child),
                    })
                };
                kids[key.get_unchecked(c) as usize] = leaf(key.slice(c + 1..), v);
                let b = Node::new(Kind::Branch { kids });
                *n = if c > 0 {
                    Node::new(Kind::Ext {
                        key: key.slice(..c),
                        child: Box::new(b),
                    })
                } else {
                    b
                };
                true
            }
        }
        Kind::Branch { kids } => {
            let i = key.get_unchecked(0);
            let ch = insert(
                &mut kids[i as usize],
                owner,
                &nib(path, i),
                key.slice(1..),
                v,
                ld,
            );
            if ch {
                n.touch();
            }
            ch
        }
        Kind::Lost => true,
        Kind::Hash(_) => unreachable!("revealed"),
    }
}

/// Merge `n` (an extension or a branch slot's only child, at `path ‖ k`)
/// up under the key `k`: what replaces their parent.
fn absorb(k: Nibbles, child: Node) -> Node {
    match child.kind {
        Kind::Leaf { key, value } => Node::new(Kind::Leaf {
            key: cat(&k, &key),
            value,
        }),
        Kind::Ext { key, child } => Node::new(Kind::Ext {
            key: cat(&k, &key),
            child,
        }),
        Kind::Lost => Node::new(Kind::Lost),
        Kind::Empty => Node::empty(),
        _ => Node::new(Kind::Ext {
            key: k,
            child: Box::new(child),
        }),
    }
}

/// Remove `key` (relative to `n`, at `path`). Returns whether `n` changed.
fn remove(
    n: &mut Node,
    owner: Option<B256>,
    path: &Nibbles,
    key: Nibbles,
    ld: &mut dyn Load,
) -> bool {
    if !reveal(n, owner, path, ld) {
        n.lose();
        return true;
    }
    match &mut n.kind {
        Kind::Empty => false,
        Kind::Leaf { key: k, .. } => {
            if *k == key {
                *n = Node::new(Kind::Empty);
                true
            } else {
                false
            }
        }
        Kind::Ext { key: k, child } => {
            if !key.starts_with(k) {
                return false;
            }
            let at = cat(path, k);
            if !remove(child, owner, &at, key.slice(k.len()..), ld) {
                return false;
            }
            // A branch under an extension never empties; it may collapse.
            let k = *k;
            let child = std::mem::replace(child.as_mut(), Node::empty());
            *n = match child.kind {
                Kind::Branch { .. } | Kind::Hash(_) => Node::new(Kind::Ext {
                    key: k,
                    child: Box::new(child),
                }),
                _ => absorb(k, child),
            };
            true
        }
        Kind::Branch { kids } => {
            let i = key.get_unchecked(0);
            if !remove(
                &mut kids[i as usize],
                owner,
                &nib(path, i),
                key.slice(1..),
                ld,
            ) {
                return false;
            }
            let left: Vec<usize> = (0..16).filter(|&j| !kids[j].is_empty()).collect();
            if left.len() == 1 {
                // Collapse into the one child left, which must be read to
                // know what it is.
                let m = left[0];
                let at = nib(path, m as u8);
                let only = &mut kids[m];
                if !reveal(only, owner, &at, ld) {
                    n.lose();
                    return true;
                }
                let only = std::mem::replace(only, Node::empty());
                let k = Nibbles::from_nibbles([m as u8]);
                *n = absorb(k, only);
            } else if left.is_empty() {
                *n = Node::new(Kind::Empty);
            } else {
                n.touch();
            }
            true
        }
        Kind::Lost => true,
        Kind::Hash(_) => unreachable!("revealed"),
    }
}

/// The value at `key`, reading as needed; `Err` when a node on the way is
/// not available or is lost.
fn get(
    n: &mut Node,
    owner: Option<B256>,
    path: &Nibbles,
    key: Nibbles,
    ld: &mut dyn Load,
) -> Result<Option<Vec<u8>>, ()> {
    if !reveal(n, owner, path, ld) {
        return Err(());
    }
    match &mut n.kind {
        Kind::Empty => Ok(None),
        Kind::Leaf { key: k, value } => Ok((*k == key).then(|| value.clone())),
        Kind::Ext { key: k, child } => {
            if !key.starts_with(k) {
                return Ok(None);
            }
            let at = cat(path, k);
            get(child, owner, &at, key.slice(k.len()..), ld)
        }
        Kind::Branch { kids } => {
            let i = key.get_unchecked(0);
            get(
                &mut kids[i as usize],
                owner,
                &nib(path, i),
                key.slice(1..),
                ld,
            )
        }
        Kind::Lost => Err(()),
        Kind::Hash(_) => unreachable!("revealed"),
    }
}

/// How a parent references `n`: its hash, or its RLP when under 32 bytes.
/// None when it is lost or has a lost descendant.
fn reference(n: &mut Node, buf: &mut Vec<u8>) -> Option<RlpNode> {
    if let Kind::Hash(h) = &n.kind {
        return Some(RlpNode::word_rlp(h));
    }
    encode(n, buf).map(|b| RlpNode::from_rlp(&b))
}

/// `n`'s RLP, computed once.
fn encode(n: &mut Node, buf: &mut Vec<u8>) -> Option<Bytes> {
    if let Some(e) = &n.enc {
        return Some(e.clone());
    }
    let mut out = Vec::new();
    match &mut n.kind {
        Kind::Empty => out.push(0x80),
        Kind::Hash(_) | Kind::Lost => return None,
        Kind::Leaf { key, value } => {
            LeafNodeRef::new(key, value).rlp(&mut out);
        }
        Kind::Ext { key, child } => {
            let c = reference(child, buf)?;
            ExtensionNodeRef::new(key, &c).rlp(&mut out);
        }
        Kind::Branch { kids } => {
            let mut stack = Vec::with_capacity(16);
            let mut mask = TrieMask::default();
            for (i, k) in kids.iter_mut().enumerate() {
                if k.is_empty() {
                    continue;
                }
                stack.push(reference(k, buf)?);
                mask.set_bit(i as u8);
            }
            BranchNodeRef::new(&stack, mask).rlp(&mut out);
        }
    }
    let b = Bytes::from(out);
    n.enc = Some(b.clone());
    Some(b)
}

/// Every node an update wrote that has its own hash, by that hash.
fn written(n: &mut Node, root: bool, buf: &mut Vec<u8>, out: &mut HashMap<B256, Bytes>) {
    if !n.fresh {
        return;
    }
    match &mut n.kind {
        Kind::Ext { child, .. } => written(child, false, buf, out),
        Kind::Branch { kids } => {
            for k in kids.iter_mut() {
                written(k, false, buf, out);
            }
        }
        _ => {}
    }
    if matches!(n.kind, Kind::Empty | Kind::Lost | Kind::Hash(_)) {
        return;
    }
    if let Some(b) = encode(n, buf) {
        if root || b.len() >= 32 {
            out.insert(keccak256(&b), b);
        }
    }
}

/// One trie: the account trie (`owner` none) or an account's storage trie.
#[derive(Clone, Debug)]
pub struct Trie {
    owner: Option<B256>,
    root: Node,
}

impl Trie {
    /// The trie with root `root`, nothing read yet.
    pub fn new(owner: Option<B256>, root: B256) -> Trie {
        let root = if root == EMPTY_ROOT {
            Node::empty()
        } else {
            Node {
                kind: Kind::Hash(root),
                fresh: false,
                enc: None,
            }
        };
        Trie { owner, root }
    }

    /// A trie whose contents are unknown.
    pub fn lost(owner: Option<B256>) -> Trie {
        Trie {
            owner,
            root: Node::new(Kind::Lost),
        }
    }

    /// The leaf value under the full path `key`; `Err` if a node on the way
    /// is unavailable or lost.
    #[allow(clippy::result_unit_err)] // Err: lost or unreadable; the loader says which node
    pub fn get(&mut self, key: &Nibbles, ld: &mut dyn Load) -> Result<Option<Vec<u8>>, ()> {
        get(&mut self.root, self.owner, &Nibbles::new(), *key, ld)
    }

    pub fn insert(&mut self, key: &Nibbles, v: Value, ld: &mut dyn Load) {
        insert(&mut self.root, self.owner, &Nibbles::new(), *key, v, ld);
    }

    pub fn remove(&mut self, key: &Nibbles, ld: &mut dyn Load) {
        remove(&mut self.root, self.owner, &Nibbles::new(), *key, ld);
    }

    /// The root hash, unless something under it is lost.
    pub fn root(&mut self) -> Option<B256> {
        match &self.root.kind {
            Kind::Empty => Some(EMPTY_ROOT),
            Kind::Hash(h) => Some(*h),
            Kind::Lost => None,
            _ => encode(&mut self.root, &mut Vec::new()).map(keccak256),
        }
    }

    /// Every node the updates wrote that is referenced by hash, and the
    /// root whatever its size (a walk starts from it), into `out` by hash.
    pub fn written(&mut self, out: &mut HashMap<B256, Bytes>) {
        written(&mut self.root, true, &mut Vec::new(), out);
    }
}

/// One account's post-state in a block: each field the block changed, and
/// its storage writes by hashed slot (zero deletes).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Change {
    pub nonce: Option<u64>,
    pub balance: Option<U256>,
    pub code_hash: Option<B256>,
    pub storage: Vec<(B256, U256)>,
}

impl Change {
    pub fn is_empty(&self) -> bool {
        self.nonce.is_none()
            && self.balance.is_none()
            && self.code_hash.is_none()
            && self.storage.is_empty()
    }
}

/// The state: the account trie and every storage trie touched so far.
#[derive(Clone)]
pub struct World {
    accounts: Trie,
    storage: HashMap<B256, Trie>,
}

impl World {
    /// The state at `root`.
    pub fn new(root: B256) -> World {
        World {
            accounts: Trie::new(None, root),
            storage: HashMap::new(),
        }
    }

    /// Read what applying `ch` to the account `hashed` reads first (its
    /// leaf, and each written slot), without changing anything: a caller
    /// that fetches what the loader lacked and reads again until nothing
    /// is missing has every node the update needs, except the sibling a
    /// deletion collapses into.
    pub fn read(&mut self, hashed: B256, ch: &Change, ld: &mut dyn Load) {
        let Ok(v) = self.accounts.get(&path_of(&hashed), ld) else {
            return;
        };
        let root = match v.map(|v| Account::decode(&v)) {
            Some(Ok(a)) => a.storage_root,
            Some(Err(_)) => return,
            None => EMPTY_ROOT,
        };
        let st = self
            .storage
            .entry(hashed)
            .or_insert_with(|| Trie::new(Some(hashed), root));
        for (slot, _) in &ch.storage {
            let _ = st.get(&path_of(slot), ld);
        }
    }

    /// Apply one account's post-state for a block, by its hashed address.
    /// An account left with no nonce, balance or code is deleted (EIP-161;
    /// it is how a list shows an account created and destroyed in one
    /// transaction, EIP-6780), and its storage with it.
    pub fn apply(&mut self, hashed: B256, ch: &Change, ld: &mut dyn Load) {
        if ch.is_empty() {
            return;
        }
        let key = path_of(&hashed);
        let old = match self.accounts.get(&key, ld) {
            Ok(None) => None,
            Ok(Some(v)) => match Account::decode(&v) {
                Ok(a) => Some(a),
                Err(_) => return self.lose(hashed, ld),
            },
            Err(()) => return self.lose(hashed, ld),
        };
        let old = old.unwrap_or(Account {
            nonce: 0,
            balance: U256::ZERO,
            storage_root: EMPTY_ROOT,
            code_hash: KECCAK_EMPTY,
        });
        let st = self
            .storage
            .entry(hashed)
            .or_insert_with(|| Trie::new(Some(hashed), old.storage_root));
        for (slot, v) in &ch.storage {
            let k = path_of(slot);
            if v.is_zero() {
                st.remove(&k, ld);
            } else {
                st.insert(&k, Value::Set(encode_word(v)), ld);
            }
        }
        let Some(storage_root) = st.root() else {
            self.accounts.insert(&key, Value::Unknown, ld);
            return;
        };
        let new = Account {
            nonce: ch.nonce.unwrap_or(old.nonce),
            balance: ch.balance.unwrap_or(old.balance),
            storage_root,
            code_hash: ch.code_hash.unwrap_or(old.code_hash),
        };
        if new.nonce == 0 && new.balance.is_zero() && new.code_hash == KECCAK_EMPTY {
            self.accounts.remove(&key, ld);
            self.storage.insert(hashed, Trie::new(Some(hashed), EMPTY_ROOT));
        } else {
            self.accounts.insert(&key, Value::Set(new.encode()), ld);
        }
    }

    /// An account changed in a way not followed (outside the part of state
    /// held, or unreadable): its leaf and storage are lost.
    pub fn lose(&mut self, hashed: B256, ld: &mut dyn Load) {
        self.accounts
            .insert(&path_of(&hashed), Value::Unknown, ld);
        self.storage.insert(hashed, Trie::lost(Some(hashed)));
    }

    /// The state root, unless something under it is lost.
    pub fn root(&mut self) -> Option<B256> {
        self.accounts.root()
    }

    /// Every node the updates wrote, by hash: account-trie and storage
    /// nodes alike (a node's hash names it wherever it sits).
    pub fn written(&mut self) -> HashMap<B256, Bytes> {
        let mut out = HashMap::new();
        self.accounts.written(&mut out);
        for t in self.storage.values_mut() {
            t.written(&mut out);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{build::Builder, key::NodeKey};
    use alloy_trie::HashBuilder;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_chacha::ChaCha8Rng;
    use std::collections::{BTreeMap, HashSet};

    /// Every node of a trie by hash, as a store would hold them.
    fn nodes_of(leaves: &BTreeMap<B256, Vec<u8>>) -> (B256, HashMap<B256, Vec<u8>>) {
        let mut out = HashMap::new();
        let mut b = Builder::new(|_: NodeKey, rlp: &[u8]| {
            out.insert(keccak256(rlp), rlp.to_vec());
        });
        for (k, v) in leaves {
            b.push(path_of(k), v.clone()).unwrap();
        }
        let (built, _) = b.finish();
        (built.root, out)
    }

    fn root_of(leaves: &BTreeMap<B256, Vec<u8>>) -> B256 {
        let mut hb = HashBuilder::default();
        for (k, v) in leaves {
            hb.add_leaf(path_of(k), v);
        }
        hb.root()
    }

    struct Map<'a>(&'a HashMap<B256, Vec<u8>>, HashSet<B256>);

    impl Load for Map<'_> {
        fn load(&mut self, _: Option<B256>, _: &Nibbles, h: &B256) -> Option<Vec<u8>> {
            match self.0.get(h) {
                Some(b) => Some(b.clone()),
                None => {
                    self.1.insert(*h);
                    None
                }
            }
        }
    }

    fn key(rng: &mut ChaCha8Rng) -> B256 {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        B256::from(h)
    }

    /// Random inserts, updates and deletes (small values, so leaves cross
    /// the embedded line), checked against a fresh build: the root, and
    /// every new node the fresh build has is among those written.
    #[test]
    fn updates_match_a_fresh_build() {
        for seed in 0..60u64 {
            let mut rng = ChaCha8Rng::seed_from_u64(seed);
            let mut leaves = BTreeMap::new();
            let n = [1usize, 2, 3, 17, 200][seed as usize % 5];
            // Clustered keys make extensions and deep branches.
            let base = key(&mut rng);
            for _ in 0..n {
                let mut k = key(&mut rng);
                if rng.random_bool(0.5) {
                    let c = rng.random_range(1..31);
                    k[..c].copy_from_slice(&base[..c]);
                }
                let len = rng.random_range(1..40);
                leaves.insert(k, vec![rng.random::<u8>() | 1; len]);
            }
            let (r0, held) = nodes_of(&leaves);
            let mut t = Trie::new(None, r0);
            let mut ld = Map(&held, HashSet::new());
            let mut next = leaves.clone();
            let keys: Vec<B256> = leaves.keys().copied().collect();
            for _ in 0..rng.random_range(1..12) {
                match rng.random_range(0..3) {
                    0 if !keys.is_empty() => {
                        let k = keys[rng.random_range(0..keys.len())];
                        next.remove(&k);
                        t.remove(&path_of(&k), &mut ld);
                    }
                    1 if !keys.is_empty() => {
                        let k = keys[rng.random_range(0..keys.len())];
                        let v = vec![7u8; rng.random_range(1..50)];
                        next.insert(k, v.clone());
                        t.insert(&path_of(&k), Value::Set(v), &mut ld);
                    }
                    _ => {
                        let mut k = key(&mut rng);
                        if rng.random_bool(0.6) {
                            let c = rng.random_range(1..31);
                            k[..c].copy_from_slice(&base[..c]);
                        }
                        let v = vec![9u8; rng.random_range(1..50)];
                        next.insert(k, v.clone());
                        t.insert(&path_of(&k), Value::Set(v), &mut ld);
                    }
                }
            }
            assert!(ld.1.is_empty(), "seed {seed}: every node was held");
            let want = root_of(&next);
            assert_eq!(t.root(), Some(want), "seed {seed}");
            let mut got = HashMap::new();
            t.written(&mut got);
            let (_, fresh) = nodes_of(&next);
            for (h, b) in &fresh {
                if !held.contains_key(h) {
                    assert_eq!(got.get(h).map(|x| x.to_vec()), Some(b.clone()), "seed {seed}: node {h}");
                }
            }
            for (h, b) in &got {
                assert_eq!(keccak256(b), *h);
            }
        }
    }

    /// A node the loader lacks is reported, and only the part of the trie
    /// above it is lost: the update elsewhere is exact.
    #[test]
    fn a_missing_node_is_reported_and_loses_only_its_ancestors() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut leaves = BTreeMap::new();
        for _ in 0..500 {
            leaves.insert(key(&mut rng), vec![1u8; 40]);
        }
        let (r0, mut held) = nodes_of(&leaves);
        let a = *leaves.keys().next().unwrap();
        let b = *leaves.keys().last().unwrap();
        // Drop the node one level under the root on a's side.
        let Kind::Branch { kids } = decode(&held[&r0]).unwrap() else {
            panic!("root is a branch")
        };
        let Kind::Hash(gone) = kids[(a[0] >> 4) as usize].kind else {
            panic!("hashed child")
        };
        held.remove(&gone);
        let mut t = Trie::new(None, r0);
        let mut ld = Map(&held, HashSet::new());
        t.insert(&path_of(&a), Value::Set(vec![2u8; 40]), &mut ld);
        t.insert(&path_of(&b), Value::Set(vec![3u8; 40]), &mut ld);
        assert_eq!(ld.1, HashSet::from([gone]));
        assert_eq!(t.root(), None);
        let mut got = HashMap::new();
        t.written(&mut got);
        let mut next = leaves.clone();
        next.insert(a, vec![2u8; 40]);
        next.insert(b, vec![3u8; 40]);
        let (_, fresh) = nodes_of(&next);
        // b's leaf and the nodes over it below the root are exact.
        let exact: Vec<&B256> = got.keys().filter(|h| fresh.contains_key(*h)).collect();
        assert!(!exact.is_empty());
        assert_eq!(exact.len(), got.len(), "nothing wrong is written");
    }

    /// A world: accounts with storage, a deletion that empties an account,
    /// a creation, storage zeroed out, against fresh builds.
    #[test]
    fn world_matches_a_fresh_build() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        type St = BTreeMap<B256, (Account, BTreeMap<B256, U256>)>;
        let mut s: St = BTreeMap::new();
        for i in 0..300u64 {
            let mut st = BTreeMap::new();
            if i % 4 == 0 {
                for _ in 0..rng.random_range(1..30) {
                    st.insert(key(&mut rng), U256::from(rng.random::<u32>() | 1));
                }
            }
            s.insert(
                key(&mut rng),
                (
                    Account {
                        nonce: 1,
                        balance: U256::from(i),
                        storage_root: EMPTY_ROOT,
                        code_hash: KECCAK_EMPTY,
                    },
                    st,
                ),
            );
        }
        fn built(s: &St) -> (B256, HashMap<B256, Vec<u8>>) {
            let mut all = HashMap::new();
            let mut acc = BTreeMap::new();
            for (k, (a, st)) in s {
                let sl: BTreeMap<B256, Vec<u8>> = st.iter().map(|(k, v)| (*k, encode_word(v))).collect();
                let (r, n) = nodes_of(&sl);
                all.extend(n);
                let mut a = *a;
                a.storage_root = r;
                acc.insert(*k, a.encode());
            }
            let (r, n) = nodes_of(&acc);
            all.extend(n);
            (r, all)
        }
        let (r0, held) = built(&s);
        let mut w = World::new(r0);
        let mut ld = Map(&held, HashSet::new());
        let mut next = s.clone();
        let ks: Vec<B256> = s.keys().copied().collect();
        // A storage slot zeroed, one set, and one account emptied.
        let with: Vec<B256> = ks.iter().copied().filter(|k| !s[k].1.is_empty()).collect();
        let (k1, k2) = (with[0], with[1]);
        let z = *s[&k1].1.keys().next().unwrap();
        next.get_mut(&k1).unwrap().1.remove(&z);
        w.apply(k1, &Change { storage: vec![(z, U256::ZERO)], ..Default::default() }, &mut ld);
        let all2: Vec<(B256, U256)> = s[&k2].1.keys().map(|k| (*k, U256::ZERO)).collect();
        next.remove(&k2);
        w.apply(
            k2,
            &Change { nonce: Some(0), balance: Some(U256::ZERO), storage: all2, ..Default::default() },
            &mut ld,
        );
        let k3 = key(&mut rng);
        let code = keccak256([1u8, 2, 3]);
        let slot = key(&mut rng);
        next.insert(
            k3,
            (
                Account { nonce: 1, balance: U256::ZERO, storage_root: EMPTY_ROOT, code_hash: code },
                BTreeMap::from([(slot, U256::from(5u64))]),
            ),
        );
        w.apply(
            k3,
            &Change { nonce: Some(1), code_hash: Some(code), storage: vec![(slot, U256::from(5u64))], ..Default::default() },
            &mut ld,
        );
        let k4 = ks[7];
        next.get_mut(&k4).unwrap().0.balance = U256::from(1_000_000u64);
        w.apply(k4, &Change { balance: Some(U256::from(1_000_000u64)), ..Default::default() }, &mut ld);
        assert!(ld.1.is_empty());
        let (want, fresh) = built(&next);
        assert_eq!(w.root(), Some(want));
        let got = w.written();
        for (h, b) in &fresh {
            if !held.contains_key(h) {
                assert_eq!(got.get(h).map(|x| x.to_vec()), Some(b.clone()), "node {h}");
            }
        }
    }
}
