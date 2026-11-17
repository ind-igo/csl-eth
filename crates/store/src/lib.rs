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

pub mod beacon;
pub mod export;
pub mod extsort;
pub mod hints;
pub mod history;
pub mod layer;
pub mod producer;

use alloy_primitives::B256;
use csl_run::RunRef;
use serde::{Deserialize, Serialize};

pub use csl_eth_trie as trie;
pub use export::{
    export, AccountRange, CodeIter, ExportError, ExportOptions, ExportStats, Exported,
    Phase as ExportPhase, SourceAccount, Sources, StateSource, VecSource, DEFAULT_RANGES,
    MIN_WORKER_BYTES,
};
pub use layer::{
    layer_hints, layer_sorter, merge_layers, write_layer, write_layer_sorted,
    write_layered_manifest, LayerRows, SORT_ACCOUNT, SORT_STORAGE,
};
pub use producer::{
    build_rows, produce, produce_with, storage_positions, AccountLeaf, Head,
    Options as ProduceOptions, ProduceError, Produced, Rows, Rows4, Stats as ProduceStats,
};

/// Bumped to 2 on 2026-10-31 when the run format paged its model
/// (core §4.1): `model_root` became `blake3` of page 0 and the model
/// section a tree of model pages. A client reading a manifest of another
/// version refuses it.
pub const FORMAT_VERSION: u32 = 2;

/// A snapshot that is a base plus layers (`docs/delta-producer.md`): the
/// base's tables under the base snapshot's directory, each layer's under
/// `runs/<blake3>.run`. A client of version 2 refuses it, which is right:
/// it would read the base alone and find its nodes stale.
pub const FORMAT_VERSION_LAYERED: u32 = 3;

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

/// A layer's run file, named by its `blake3`, so manifests share it.
pub fn run_path(root: &[u8; 32]) -> String {
    format!("runs/{}.run", hex::encode(root))
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
    /// Tables with at least one entry; an empty table has no run. For a
    /// layered snapshot these are the base's.
    pub tables: Vec<TableRef>,
    /// A layered snapshot's base: the snapshot whose directory holds
    /// `tables`. `None`: this snapshot's own directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<B256>,
    /// The layers over the base, oldest first. A reader takes, at each
    /// position, the candidate that hashes to what its parent committed
    /// to, never the newest, so a stale node in an older run is never
    /// accepted and nothing is deleted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub layers: Vec<Layer>,
}

/// One layer: the nodes and code that changed between the state of
/// `from_block` and that of `to_block`, a run per table at
/// [`run_path`]`(root)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Layer {
    pub from_block: u64,
    pub to_block: u64,
    pub tables: Vec<TableRef>,
    /// Which keys it may hold, for scheduling reads only
    /// ([`hints`]); absent for a table, every key is asked of it.
    #[serde(default, skip_serializing_if = "hints::Hints::is_empty")]
    pub hints: hints::Hints,
    /// Hints too large for the manifest: the `blake3` of the file at
    /// [`hints::hints_path`]. The client reads `hints` from it.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex32_opt")]
    pub hints_file: Option<[u8; 32]>,
}

/// One run a table is read from: its path in the bucket and its ref.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunAt {
    pub path: String,
    pub table: TableRef,
    /// The blocks its contents come from (the base's: its own block).
    pub block_lo: u64,
    pub block_hi: u64,
    /// The index of its layer in [`Manifest::layers`]; `None` for the
    /// base.
    pub layer: Option<usize>,
}

impl Manifest {
    pub fn table(&self, table_id: u16) -> Option<&TableRef> {
        self.tables.iter().find(|t| t.table_id == table_id)
    }

    /// The block whose directory holds the base tables.
    pub fn base_hash(&self) -> B256 {
        self.base.unwrap_or(self.block_hash)
    }

    /// Whether this is a base plus layers.
    pub fn is_layered(&self) -> bool {
        self.base.is_some() || !self.layers.is_empty()
    }

    /// Every run `table_id` is read from: the base's, then each layer's,
    /// oldest first.
    pub fn runs(&self, table_id: u16) -> Vec<RunAt> {
        let mut out = Vec::new();
        let base_block = if self.base.is_some() {
            self.layers
                .first()
                .map_or(self.block_number, |l| l.from_block)
        } else {
            self.block_number
        };
        if let Some(t) = self.table(table_id) {
            out.push(RunAt {
                path: table_path(&self.base_hash(), table_id),
                table: *t,
                block_lo: base_block,
                block_hi: base_block,
                layer: None,
            });
        }
        for (i, l) in self.layers.iter().enumerate() {
            if let Some(t) = l.tables.iter().find(|t| t.table_id == table_id) {
                out.push(RunAt {
                    path: run_path(&t.root),
                    table: *t,
                    block_lo: l.from_block,
                    block_hi: l.to_block,
                    layer: Some(i),
                });
            }
        }
        out
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("manifest serializes")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Manifest, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

pub(crate) mod hex32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => s.serialize_str(&hex::encode(v)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let s = Option::<String>::deserialize(d)?;
        s.map(|s| {
            let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
            v.try_into()
                .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
        })
        .transpose()
    }
}

pub(crate) mod hex32 {
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
            base: None,
            layers: Vec::new(),
        };
        let j = m.to_json();
        assert_eq!(Manifest::from_json(j.as_bytes()).unwrap(), m);
        // A plain manifest's JSON has no layer fields, so a version-2
        // reader parses it as before.
        assert!(!j.contains("layers") && !j.contains("\"base\""));
        assert_eq!(m.runs(0).len(), 1);
        assert_eq!(m.runs(0)[0].path, table_path(&m.block_hash, 0));
        let mut l = m.clone();
        l.base = Some(B256::repeat_byte(9));
        l.layers.push(Layer {
            from_block: 7,
            to_block: 9,
            tables: vec![TableRef {
                root: [8; 32],
                ..m.tables[0]
            }],
            hints: Default::default(),
            hints_file: None,
        });
        let j = l.to_json();
        assert_eq!(Manifest::from_json(j.as_bytes()).unwrap(), l);
        let runs = l.runs(0);
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].path, table_path(&B256::repeat_byte(9), 0));
        assert_eq!(runs[1].path, format!("runs/{}.run", "08".repeat(32)));
        assert_eq!((runs[1].block_lo, runs[1].block_hi), (7, 9));
        assert_eq!(m.table(0).unwrap().run_ref(7).block_hi, 7);
        assert!(m.table(1).is_none());
        assert_eq!(
            table_path(&m.block_hash, 2),
            format!("snapshots/{}/code.run", "01".repeat(32))
        );
    }
}
