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
use csl_run::{Config, Entry, Reader, RunRef, Writer};
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
    let n = entries.len() as u64;
    write_run_with(root, table_id, epsilon, n, |push| {
        for e in entries {
            push(e)?;
        }
        Ok(())
    })
}

/// [`write_run`], the `count` entries pushed by `fill`.
fn write_run_with(
    root: &Path,
    table_id: u16,
    epsilon: u16,
    count: u64,
    fill: impl FnOnce(&mut dyn FnMut(Entry) -> Result<(), ProduceError>) -> Result<(), ProduceError>,
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
    let mut w = Writer::with_format(file, cfg, RUN_FORMAT, count)?;
    let filled = fill(&mut |e| w.push(e).map_err(ProduceError::from));
    if let Err(e) = filled {
        let _ = fs::remove_file(&tmp);
        return Err(e);
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

/// Sorter tables a step's rows stream into: account nodes, storage nodes.
pub const SORT_ACCOUNT: usize = 0;
pub const SORT_STORAGE: usize = 1;

/// A sorter for a step's rows, one table each for account and storage
/// nodes, in `dir` under `budget` bytes; a repeated key must carry the same
/// node.
pub fn layer_sorter(dir: &Path, budget: u64) -> crate::extsort::ExtSort {
    use crate::extsort::{Budget, Dups, ExtSort};
    ExtSort::new(dir, Budget::new(budget), &[Dups::KeepOne, Dups::KeepOne])
}

/// [`write_layer`] from rows streamed into a [`layer_sorter`] (any order)
/// and code by hash: a step too big for memory.
pub fn write_layer_sorted(
    root: &Path,
    from_block: u64,
    to_block: u64,
    sort: &mut crate::extsort::ExtSort,
    code: &BTreeMap<[u8; 32], Vec<u8>>,
    epsilon: u16,
) -> Result<Layer, ProduceError> {
    sort.prepare().map_err(sort_err)?;
    let mut tables = Vec::new();
    for (t, s) in [
        (TABLE_ACCOUNT_NODES, SORT_ACCOUNT),
        (TABLE_STORAGE_NODES, SORT_STORAGE),
    ] {
        let n = sort.stats(s).entries;
        if n > 0 {
            tables.push(write_run_with(root, t, epsilon, n, |push| {
                sort.merge::<ProduceError>(s, |k, v| push(Entry::value(*k, v.to_vec())))
                    .map(|_| ())
            })?);
        }
    }
    let rows = LayerRows {
        code: code.clone(),
        ..LayerRows::default()
    };
    let mut l = write_layer(root, from_block, to_block, &rows, epsilon)?;
    tables.extend(l.tables.drain(..));
    tables.sort_by_key(|t| t.table_id);
    Ok(Layer {
        from_block,
        to_block,
        tables,
    })
}

fn sort_err(e: crate::extsort::SortError) -> ProduceError {
    ProduceError::Io(std::io::Error::other(e.to_string()))
}

impl From<crate::extsort::SortError> for ProduceError {
    fn from(e: crate::extsort::SortError) -> Self {
        sort_err(e)
    }
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

fn run_err(e: csl_run::Error) -> ProduceError {
    ProduceError::Io(std::io::Error::other(e.to_string()))
}

/// A run read front to back, page by page.
struct Cursor {
    reader: Reader<File>,
    pages: u64,
    next_page: u64,
    buf: std::vec::IntoIter<Entry>,
    head: Option<Entry>,
}

impl Cursor {
    fn open(root: &Path, t: &TableRef, rref: RunRef) -> Result<Cursor, ProduceError> {
        let f = File::open(root.join(run_path(&t.root)))?;
        let mut reader = Reader::try_with_format(f, rref, RUN_FORMAT).map_err(run_err)?;
        reader.prepare().map_err(run_err)?;
        let mut c = Cursor {
            reader,
            pages: t.page_count,
            next_page: 1,
            buf: Vec::new().into_iter(),
            head: None,
        };
        c.advance()?;
        Ok(c)
    }

    fn advance(&mut self) -> Result<(), ProduceError> {
        loop {
            if let Some(e) = self.buf.next() {
                self.head = Some(e);
                return Ok(());
            }
            if self.next_page > self.pages {
                self.head = None;
                return Ok(());
            }
            let p = self.reader.fetch_page(self.next_page).map_err(run_err)?;
            self.next_page += 1;
            self.buf = p.entries.into_iter();
        }
    }
}

/// The entries of `cursors` (newest first) in key order, one per key: the
/// newest run's.
fn merged(
    mut cursors: Vec<Cursor>,
    mut f: impl FnMut(Entry) -> Result<(), ProduceError>,
) -> Result<u64, ProduceError> {
    let mut n = 0;
    loop {
        let Some(min) = cursors
            .iter()
            .filter_map(|c| c.head.as_ref().map(|e| e.key))
            .min()
        else {
            return Ok(n);
        };
        let mut took = false;
        for c in cursors.iter_mut() {
            if c.head.as_ref().is_some_and(|e| e.key == min) {
                let e = c.head.take().expect("head");
                if !took {
                    f(e)?;
                    took = true;
                    n += 1;
                }
                c.advance()?;
            }
        }
    }
}

/// Merge consecutive `layers` (oldest first) into one layer from the
/// first's `from_block` to the last's `to_block`: per table and key, the
/// newest layer's entry.
///
/// Nothing is dropped. A layer holds every position whose node changed in
/// its step (a position whose node is unchanged keeps its hash, so the
/// whole subtree under it is unchanged too), so for any position of the
/// last state, the newest layer that wrote it wrote that state's node.
/// Older entries at positions the last state no longer has are dead
/// weight, never a wrong answer: a reader takes the candidate that hashes
/// to its parent's reference. Dropping them would need the last state's
/// trie to say which positions are dead, and dropping a subtree on a
/// restructure can remove descendants still reachable through a new
/// extension (`docs/delta-producer.md`), so a merge does not try.
pub fn merge_layers(root: &Path, layers: &[Layer], epsilon: u16) -> Result<Layer, ProduceError> {
    let (Some(first), Some(last)) = (layers.first(), layers.last()) else {
        return Err(ProduceError::Io(std::io::Error::other("nothing to merge")));
    };
    let mut tables = Vec::new();
    for t in [TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES, TABLE_CODE] {
        let open = || -> Result<Vec<Cursor>, ProduceError> {
            layers
                .iter()
                .rev()
                .filter_map(|l| l.tables.iter().find(|x| x.table_id == t).map(|x| (l, x)))
                .map(|(l, x)| {
                    let mut rref = x.run_ref(l.from_block);
                    rref.block_hi = l.to_block;
                    Cursor::open(root, x, rref)
                })
                .collect()
        };
        let count = merged(open()?, |_| Ok(()))?;
        if count == 0 {
            continue;
        }
        // Two passes, streamed: the writer needs the count first.
        let cursors = open()?;
        tables.push(write_run_with(root, t, epsilon, count, |push| {
            merged(cursors, |e| push(e)).map(|_| ())
        })?);
    }
    Ok(Layer {
        from_block: first.from_block,
        to_block: last.to_block,
        tables,
    })
}
