//! The bucket, profile §1, §3 and §5: what a snapshot is made of and where
//! each piece lives. The client reads these paths with byte ranges; the
//! producer in [`producer`] writes them.
//!
//! ```text
//! snapshots/latest                          hex block hash of the newest snapshot
//! snapshots/<block_hash>/manifest.json      Manifest
//! snapshots/<block_hash>/account_nodes.run  table 0
//! snapshots/<block_hash>/storage_nodes.run  table 1
//! snapshots/<block_hash>/code.run           table 2
//! snapshots/<block_hash>/nodes_by_hash.run  table 3, the content-addressed baseline
//! blobs/<blake3>                            code above the inline threshold
//! ```
//!
//! Nothing here is evidence. The manifest names a block and its
//! `state_root` so the client knows which trusted header the files claim to
//! serve; every value and absence is still proven by the trie walk to the
//! `state_root` the client verified for itself.

pub mod producer;

use alloy_primitives::B256;
use csl_run::RunRef;
use serde::{Deserialize, Serialize};

pub use csl_eth_trie as trie;
pub use producer::{
    produce, produce_with, AccountLeaf, Head, Options as ProduceOptions, ProduceError, Produced,
    Stats as ProduceStats,
};

/// Bumped to 2 on 2026-10-31 when the run format paged its model
/// (core §4.1): `model_root` became `blake3` of page 0 and the model
/// section a tree of model pages. A client reading a manifest of another
/// version refuses it.
pub const FORMAT_VERSION: u32 = 2;

/// The format every table is written and read in: variable layout, no
/// inline proofs (the trie proves values), the model paged so a client
/// reads one model page per key neighbourhood instead of the whole model.
pub const RUN_FORMAT: csl_run::Format = csl_run::Format::variable().paged();

/// Tables, profile §1, plus the content-addressed baseline of §9.
pub const TABLE_ACCOUNT_NODES: u16 = 0;
pub const TABLE_STORAGE_NODES: u16 = 1;
pub const TABLE_CODE: u16 = 2;
pub const TABLE_NODES_BY_HASH: u16 = 3;
pub const TABLE_COUNT: usize = 4;
pub const TABLE_FILES: [&str; TABLE_COUNT] = [
    "account_nodes.run",
    "storage_nodes.run",
    "code.run",
    "nodes_by_hash.run",
];

/// Tunables, profile §6.
pub const EPSILON: u16 = 4;
pub const D_ACCOUNT: usize = 9;
pub const D_STORAGE: usize = 7;
/// Code longer than this is a blob entry (tag 2) and lives under `blobs/`.
/// Core §3.2's threshold; the profile's "4,096" cannot fit a page.
pub const CODE_BLOB_THRESHOLD: usize = 3968;

pub const MANIFEST_FILE: &str = "manifest.json";
pub const LATEST_FILE: &str = "snapshots/latest";

/// `blake3("csl/eth/profile/v1")`, the run header's `profile_id`.
pub fn profile_id() -> [u8; 32] {
    *blake3::hash(b"csl/eth/profile/v1").as_bytes()
}

pub fn snapshot_dir(block_hash: &B256) -> String {
    format!("snapshots/{}", hex::encode(block_hash))
}

pub fn table_path(block_hash: &B256, table_id: u16) -> String {
    format!(
        "{}/{}",
        snapshot_dir(block_hash),
        TABLE_FILES[table_id as usize]
    )
}

pub fn manifest_path(block_hash: &B256) -> String {
    format!("{}/{MANIFEST_FILE}", snapshot_dir(block_hash))
}

pub fn blob_path(hash: &[u8; 32]) -> String {
    format!("blobs/{}", hex::encode(hash))
}

/// One table's run, as the manifest carries it: the `RunRef` fields of
/// v1-min §3 with the block range implied by the snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TableRef {
    pub table_id: u16,
    /// `blake3` of the run file.
    #[serde(with = "hex32")]
    pub root: [u8; 32],
    pub page_count: u64,
    pub entry_count: u64,
    pub epsilon_pages: u16,
    pub model_bytes: u32,
    #[serde(with = "hex32")]
    pub model_root: [u8; 32],
}

impl TableRef {
    pub fn run_ref(&self, block_number: u64) -> RunRef {
        RunRef {
            root: self.root,
            block_lo: block_number,
            block_hi: block_number,
            page_count: self.page_count,
            entry_count: self.entry_count,
            epsilon_pages: self.epsilon_pages,
            model_bytes: self.model_bytes,
            model_root: self.model_root,
        }
    }
}

/// A snapshot, profile §3: the execution block it holds the state of, and
/// the runs. `prefix` is the covered slice of the account trie as hex
/// nibbles (empty for the whole trie); keys outside it end in
/// `Insufficient` through missing pages, and the client does not consult it
/// to avoid that.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub format_version: u32,
    #[serde(with = "hex32")]
    pub profile_id: [u8; 32],
    pub block_hash: B256,
    pub block_number: u64,
    pub timestamp: u64,
    pub state_root: B256,
    pub prefix: String,
    /// Tables with at least one entry; an empty table has no run.
    pub tables: Vec<TableRef>,
}

impl Manifest {
    pub fn table(&self, table_id: u16) -> Option<&TableRef> {
        self.tables.iter().find(|t| t.table_id == table_id)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serializes")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Manifest, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

mod hex32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_json_roundtrip() {
        let m = Manifest {
            format_version: FORMAT_VERSION,
            profile_id: profile_id(),
            block_hash: B256::repeat_byte(1),
            block_number: 7,
            timestamp: 1_700_000_000,
            state_root: B256::repeat_byte(2),
            prefix: "a".into(),
            tables: vec![TableRef {
                table_id: 0,
                root: [3; 32],
                page_count: 4,
                entry_count: 5,
                epsilon_pages: 4,
                model_bytes: 6,
                model_root: [7; 32],
            }],
        };
        let j = m.to_json();
        assert_eq!(Manifest::from_json(j.as_bytes()).unwrap(), m);
        assert_eq!(m.table(0).unwrap().run_ref(7).block_hi, 7);
        assert!(m.table(1).is_none());
        assert_eq!(
            table_path(&m.block_hash, 2),
            format!("snapshots/{}/code.run", "01".repeat(32))
        );
    }
}
