//! Layers (`docs/delta-producer.md`): a snapshot that is a base plus the
//! nodes and code that changed since, so keeping the full state current
//! writes megabytes a block, not the 344 GiB base.
//!
//! A layer is one run per table, in the same format as the base's, holding
//! a step's nodes under the same position keys. A run is named by its
//! `blake3` (`runs/<blake3>.run`), so layers are shared between the
//! manifests that list them. Nothing here is evidence: a reader takes, at
//! each position, the candidate that hashes to what its parent committed
//! to, so a stale node in an older run is never accepted, a missing one is
//! `Insufficient`, and nothing ever needs deleting for a read to be right.

use crate::producer::Head;
use crate::{
    blob_path, manifest_path, producer::write_atomic, profile_id, run_path, Layer, Manifest,
    ProduceError, Rows, TableRef, CODE_BLOB_THRESHOLD, FORMAT_VERSION_LAYERED, LATEST_FILE,
    RUN_FORMAT, TABLE_ACCOUNT_NODES, TABLE_CODE, TABLE_STORAGE_NODES,
};
use csl_run::{Config, Entry, Writer};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    path::Path,
};

/// What one layer holds: the path-keyed nodes of the account and storage
/// tables and new code, each by key. A key appears once per table; the
/// value is the node at that position in the layer's target state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayerRows {
    pub account: BTreeMap<[u8; 32], Vec<u8>>,
    pub storage: BTreeMap<[u8; 32], Vec<u8>>,
    pub code: BTreeMap<[u8; 32], Vec<u8>>,
}

impl LayerRows {
    pub fn is_empty(&self) -> bool {
        self.account.is_empty() && self.storage.is_empty() && self.code.is_empty()
    }

    /// Node bytes (account and storage), the layer's main size.
    pub fn node_bytes(&self) -> u64 {
        self.account
            .values()
            .chain(self.storage.values())
            .map(|v| v.len() as u64)
            .sum()
    }

    /// The rows of `new` that `old` does not hold with the same bytes: a
    /// layer from a state to the next, computed from two full row sets
    /// (tests and small states; the healer computes it from the trie).
    pub fn diff(old: &crate::producer::Rows4, new: &crate::producer::Rows4) -> LayerRows {
        fn d(old: &Rows, new: &Rows) -> BTreeMap<[u8; 32], Vec<u8>> {
            let o: std::collections::HashMap<&[u8; 32], &Vec<u8>> =
                old.iter().map(|(k, v)| (k, v)).collect();
            new.iter()
                .filter(|(k, v)| o.get(k) != Some(&v))
                .map(|(k, v)| (*k, v.clone()))
                .collect()
        }
        LayerRows {
            account: d(&old.account, &new.account),
            storage: d(&old.storage, &new.storage),
            code: new
                .code
                .iter()
                .filter(|(k, _)| !old.code.contains_key(*k))
                .map(|(k, v)| (*k, v.clone()))
                .collect(),
        }
    }
}

/// Write one run of `entries` (in key order) under `root` at
/// `runs/<blake3>.run`, returning its ref.
fn write_run(
    root: &Path,
    table_id: u16,
    epsilon: u16,
    entries: impl ExactSizeIterator<Item = Entry>,
) -> Result<TableRef, ProduceError> {
    let dir = root.join("runs");
    fs::create_dir_all(&dir)?;
    let tmp = dir.join(format!(
        ".tmp-{}-{table_id}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp)?;
    let cfg = Config {
        profile_id: profile_id(),
        table_id,
        value_size: 0,
        epsilon,
    };
    let mut w = Writer::with_format(file, cfg, RUN_FORMAT, entries.len() as u64)?;
    for e in entries {
        w.push(e)?;
    }
    let built = w.finish()?;
    // Without inline proofs the run's root is `blake3` of the file; the
    // name is checked against the bytes, not taken on trust.
    let bytes = fs::read(&tmp)?;
    let h = *blake3::hash(&bytes).as_bytes();
    if h != built.root {
        let _ = fs::remove_file(&tmp);
        return Err(ProduceError::Io(std::io::Error::other(
            "run root is not the file's blake3",
        )));
    }
    fs::rename(&tmp, root.join(run_path(&built.root)))?;
    Ok(TableRef {
        table_id,
        root: built.root,
        page_count: built.page_count,
        entry_count: built.entry_count,
        epsilon_pages: epsilon,
        model_bytes: built.layout.model_bytes as u32,
        model_root: built.model_root,
    })
}

/// Write `rows` as a layer from `from_block`'s state to `to_block`'s under
/// `root` (`runs/`, and `blobs/` for code above the inline size).
pub fn write_layer(
    root: &Path,
    from_block: u64,
    to_block: u64,
    rows: &LayerRows,
    epsilon: u16,
) -> Result<Layer, ProduceError> {
    let mut tables = Vec::new();
    for (t, m) in [
        (TABLE_ACCOUNT_NODES, &rows.account),
        (TABLE_STORAGE_NODES, &rows.storage),
    ] {
        if !m.is_empty() {
            tables.push(write_run(
                root,
                t,
                epsilon,
                m.iter().map(|(k, v)| Entry::value(*k, v.clone())),
            )?);
        }
    }
    if !rows.code.is_empty() {
        let mut entries = Vec::with_capacity(rows.code.len());
        for (k, v) in &rows.code {
            if v.len() > CODE_BLOB_THRESHOLD {
                let h = *blake3::hash(v).as_bytes();
                let p = root.join(blob_path(&h));
                if !p.exists() {
                    write_atomic(&p, v)?;
                }
                entries.push(Entry::blob(*k, h));
            } else {
                entries.push(Entry::value(*k, v.clone()));
            }
        }
        tables.push(write_run(root, TABLE_CODE, epsilon, entries.into_iter())?);
    }
    tables.sort_by_key(|t| t.table_id);
    Ok(Layer {
        from_block,
        to_block,
        tables,
    })
}

/// The manifest of `head`'s state as `base` plus `layers` (oldest first),
/// written under `root` at `snapshots/<hash>/manifest.json`, and
/// `snapshots/latest` pointed at it when `latest`.
pub fn write_layered_manifest(
    root: &Path,
    head: &Head,
    base: &Manifest,
    layers: Vec<Layer>,
    latest: bool,
) -> Result<Manifest, ProduceError> {
    if base.is_layered() {
        return Err(ProduceError::Io(std::io::Error::other(
            "a base must be a plain snapshot",
        )));
    }
    let m = Manifest {
        format_version: FORMAT_VERSION_LAYERED,
        profile_id: profile_id(),
        block_hash: head.block_hash,
        block_number: head.block_number,
        timestamp: head.timestamp,
        state_root: head.state_root,
        prefix: base.prefix.clone(),
        // The base's tables; a by-hash table there serves only the
        // baseline, which reads stale nodes over layers, so it is left out.
        tables: base
            .tables
            .iter()
            .filter(|t| t.table_id != crate::TABLE_NODES_BY_HASH)
            .copied()
            .collect(),
        base: Some(base.block_hash),
        layers,
    };
    write_atomic(
        &root.join(manifest_path(&head.block_hash)),
        m.to_json().as_bytes(),
    )?;
    if latest {
        write_atomic(
            &root.join(LATEST_FILE),
            hex::encode(head.block_hash).as_bytes(),
        )?;
    }
    Ok(m)
}
