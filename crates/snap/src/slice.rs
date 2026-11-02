//! A fetched slice on disk, separate from the bucket it becomes: the
//! network step and the build step can be rerun independently.
//!
//! `head.json` names the pivot block and what the fetch cost; the rest is
//! RLP records back to back (self-delimiting, so appended and read in a
//! stream): `accounts.rlp` is every account in the slice in hashed order,
//! `storage.rlp` one record per distinct storage root with its sorted
//! slots, `code.rlp` bytecode by hash, `boundary.rlp` the sealed subtrees
//! outside the slice from the range proofs.

use alloy_primitives::{Bytes, B256, U256};
use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use alloy_trie::nodes::RlpNode;
use csl_eth_store::{AccountLeaf, Head};
use csl_eth_trie::{Account, Nibbles, Sealed};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    path::Path,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SliceHead {
    pub block_hash: B256,
    pub block_number: u64,
    pub timestamp: u64,
    pub state_root: B256,
    /// Hex nibbles of the covered prefix.
    pub prefix: String,
    pub fetched_at: u64,
    pub accounts: u64,
    pub storage_tries: u64,
    pub storage_slots: u64,
    pub codes: u64,
    pub peers_used: u64,
    pub bytes_in: u64,
    pub requests: u64,
    pub wall_ms: u64,
    pub repivots: u64,
    /// Unix milliseconds when the (last) pivot was taken: in epoch mode,
    /// how long after the boundary the block was found; the transfer is
    /// from here to `fetched_at`. 0 when unknown (older slices).
    #[serde(default)]
    pub pivot_set_ms: u64,
}

#[derive(RlpEncodable, RlpDecodable)]
struct AccountRec {
    hash: B256,
    nonce: u64,
    balance: U256,
    storage_root: B256,
    code_hash: B256,
}

#[derive(RlpEncodable, RlpDecodable)]
struct SlotRec {
    hash: B256,
    value: U256,
}

#[derive(RlpEncodable, RlpDecodable)]
struct StorageRec {
    root: B256,
    slots: Vec<SlotRec>,
}

#[derive(RlpEncodable, RlpDecodable)]
struct CodeRec {
    hash: B256,
    code: Bytes,
}

#[derive(RlpEncodable, RlpDecodable)]
struct SealedRec {
    /// One byte per nibble.
    path: Bytes,
    node: Bytes,
}

pub struct Slice {
    pub head: SliceHead,
    /// Ascending by hashed address.
    pub accounts: Vec<(B256, Account)>,
    /// By storage root, slots ascending by hashed key.
    pub storage: HashMap<B256, Vec<(B256, U256)>>,
    pub code: HashMap<B256, Vec<u8>>,
    pub boundary: Vec<Sealed>,
}

#[derive(Debug, thiserror::Error)]
pub enum SliceError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("rlp: {0}")]
    Rlp(#[from] alloy_rlp::Error),
    #[error("bad sealed record")]
    Sealed,
}

impl Slice {
    pub fn write(&self, dir: &Path) -> Result<(), SliceError> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join("head.json"), serde_json::to_vec_pretty(&self.head)?)?;
        let mut w = io::BufWriter::new(fs::File::create(dir.join("accounts.rlp"))?);
        let mut buf = Vec::with_capacity(256);
        for (h, a) in &self.accounts {
            buf.clear();
            AccountRec { hash: *h, nonce: a.nonce, balance: a.balance, storage_root: a.storage_root, code_hash: a.code_hash }.encode(&mut buf);
            w.write_all(&buf)?;
        }
        w.flush()?;
        let mut w = io::BufWriter::new(fs::File::create(dir.join("storage.rlp"))?);
        let mut roots: Vec<&B256> = self.storage.keys().collect();
        roots.sort();
        for root in roots {
            buf.clear();
            StorageRec { root: *root, slots: self.storage[root].iter().map(|(h, v)| SlotRec { hash: *h, value: *v }).collect() }.encode(&mut buf);
            w.write_all(&buf)?;
        }
        w.flush()?;
        let mut w = io::BufWriter::new(fs::File::create(dir.join("code.rlp"))?);
        let mut hashes: Vec<&B256> = self.code.keys().collect();
        hashes.sort();
        for h in hashes {
            buf.clear();
            CodeRec { hash: *h, code: Bytes::from(self.code[h].clone()) }.encode(&mut buf);
            w.write_all(&buf)?;
        }
        w.flush()?;
        let mut w = io::BufWriter::new(fs::File::create(dir.join("boundary.rlp"))?);
        for (p, n) in &self.boundary {
            buf.clear();
            SealedRec { path: Bytes::from(p.to_vec()), node: Bytes::from(n.as_slice().to_vec()) }.encode(&mut buf);
            w.write_all(&buf)?;
        }
        w.flush()?;
        Ok(())
    }

    pub fn read(dir: &Path) -> Result<Slice, SliceError> {
        let head: SliceHead = serde_json::from_slice(&fs::read(dir.join("head.json"))?)?;
        let data = fs::read(dir.join("accounts.rlp"))?;
        let mut buf: &[u8] = &data;
        let mut accounts = Vec::new();
        while !buf.is_empty() {
            let r = AccountRec::decode(&mut buf)?;
            accounts.push((r.hash, Account { nonce: r.nonce, balance: r.balance, storage_root: r.storage_root, code_hash: r.code_hash }));
        }
        let data = fs::read(dir.join("storage.rlp"))?;
        let mut buf: &[u8] = &data;
        let mut storage = HashMap::new();
        while !buf.is_empty() {
            let r = StorageRec::decode(&mut buf)?;
            storage.insert(r.root, r.slots.into_iter().map(|s| (s.hash, s.value)).collect());
        }
        let data = fs::read(dir.join("code.rlp"))?;
        let mut buf: &[u8] = &data;
        let mut code = HashMap::new();
        while !buf.is_empty() {
            let r = CodeRec::decode(&mut buf)?;
            code.insert(r.hash, r.code.to_vec());
        }
        let data = fs::read(dir.join("boundary.rlp"))?;
        let mut buf: &[u8] = &data;
        let mut boundary = Vec::new();
        while !buf.is_empty() {
            let r = SealedRec::decode(&mut buf)?;
            let node = RlpNode::from_raw(&r.node).ok_or(SliceError::Sealed)?;
            boundary.push((Nibbles::from_nibbles(&r.path[..]), node));
        }
        Ok(Slice { head, accounts, storage, code, boundary })
    }

    pub fn produce_head(&self) -> Head {
        Head { block_hash: self.head.block_hash, block_number: self.head.block_number, timestamp: self.head.timestamp, state_root: self.head.state_root }
    }

    /// The producer's input: each account with its slots (joined by
    /// storage root; an account whose root has no record gets none, and
    /// the producer then rejects the root).
    pub fn leaves(&self) -> impl Iterator<Item = AccountLeaf> + '_ {
        self.accounts.iter().map(move |(h, a)| AccountLeaf { hashed: *h, account: *a, storage: self.storage.get(&a.storage_root).cloned().unwrap_or_default() })
    }
}
