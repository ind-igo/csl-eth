//! The producer, profile §5: sorted hashed leaves in, a snapshot out.
//!
//! For each account in hashed-address order it builds the storage trie
//! from the account's sorted slots and checks the root against the leaf's
//! `storageRoot`; then it builds the account trie and checks the root
//! against the header's `state_root`; then it checks every `codeHash` has
//! its bytecode. Only then does it write anything. Every emitted node goes
//! to its path-keyed table and to the content-addressed table, and the runs
//! are written through the shared `csl-run` writer in key order.
//!
//! Nodes are sorted in memory. A 1/256 mainnet slice is a few million
//! nodes, well within a workstation; the full-trie export of milestone 4
//! needs the external sort cinder's sealer has, which is a later change
//! behind the same `produce` call.

use crate::{
    blob_path, manifest_path, profile_id, snapshot_dir, Manifest, TableRef, CODE_BLOB_THRESHOLD, EPSILON, FORMAT_VERSION, LATEST_FILE, TABLE_ACCOUNT_NODES,
    TABLE_CODE, TABLE_COUNT, TABLE_FILES, TABLE_NODES_BY_HASH, TABLE_STORAGE_NODES,
};
use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{Nibbles, KECCAK_EMPTY};
use csl_eth_trie::Sealed;
use csl_eth_trie::{code_key, encode_word, path_of, Account, BuildError, Builder, NodeKey, TooDeep, EMPTY_ROOT, MAX_NODE_BYTES};
use csl_run::{Config, Entry, Format, Writer};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    fs::{self, File},
    io::Write as _,
    path::{Path, PathBuf},
};

/// The block whose state is being written, from a header the producer
/// trusts (the finalized header of profile §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Head {
    pub block_hash: B256,
    pub block_number: u64,
    pub timestamp: u64,
    pub state_root: B256,
}

/// One account as the input stream delivers it: its hashed address, the
/// leaf, and every non-zero slot by hashed key in ascending order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountLeaf {
    pub hashed: B256,
    pub account: Account,
    pub storage: Vec<(B256, U256)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Subtrees outside a slice taken from its boundary proof.
    pub sealed: u64,
    pub accounts: u64,
    pub storage_slots: u64,
    pub storage_tries: u64,
    pub code_entries: u64,
    pub code_blobs: u64,
    /// Nodes handed to the sink by the account build.
    pub account_nodes: u64,
    pub storage_nodes: u64,
    /// Nodes short enough to be embedded in their parent (not entries).
    pub embedded: u64,
    /// Per table: entries, pages, model bytes, file bytes.
    pub tables: [Option<TableStats>; TABLE_COUNT],
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableStats {
    pub entries: u64,
    pub pages: u64,
    pub model_bytes: u64,
    pub file_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct Produced {
    pub manifest: Manifest,
    pub stats: Stats,
    pub dir: PathBuf,
}

#[derive(Debug)]
pub enum ProduceError {
    Io(std::io::Error),
    Unsorted {
        prev: B256,
        next: B256,
    },
    Build(BuildError),
    TooDeep(TooDeep),
    /// A storage trie did not hash to the account's `storageRoot`.
    StorageRoot {
        owner: B256,
        expected: B256,
        got: B256,
    },
    /// The account trie did not hash to the header's `state_root`.
    StateRoot {
        expected: B256,
        got: B256,
    },
    /// A leaf's `codeHash` has no bytecode, or the bytecode hashes differently.
    Code {
        hash: B256,
        what: &'static str,
    },
    /// A node longer than the profile allows (cannot happen for well-formed
    /// Ethereum state; a branch of sixteen hashes is 532 bytes).
    NodeTooLarge {
        key: [u8; 32],
        len: usize,
    },
    Run(csl_run::Error),
}

impl fmt::Display for ProduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProduceError::Io(e) => write!(f, "io: {e}"),
            ProduceError::Unsorted { prev, next } => {
                write!(f, "accounts out of order: {prev} then {next}")
            }
            ProduceError::Build(e) => write!(f, "trie build: {e}"),
            ProduceError::TooDeep(e) => write!(f, "{e}"),
            ProduceError::StorageRoot { owner, expected, got } => write!(f, "storage root of {owner}: leaf says {expected}, slots build {got}"),
            ProduceError::StateRoot { expected, got } => {
                write!(f, "state root: header says {expected}, leaves build {got}")
            }
            ProduceError::Code { hash, what } => write!(f, "code {hash}: {what}"),
            ProduceError::NodeTooLarge { key, len } => {
                write!(f, "node {} is {len} bytes", hex::encode(key))
            }
            ProduceError::Run(e) => write!(f, "run: {e}"),
        }
    }
}

impl std::error::Error for ProduceError {}

impl From<std::io::Error> for ProduceError {
    fn from(e: std::io::Error) -> Self {
        ProduceError::Io(e)
    }
}
impl From<BuildError> for ProduceError {
    fn from(e: BuildError) -> Self {
        ProduceError::Build(e)
    }
}
impl From<TooDeep> for ProduceError {
    fn from(e: TooDeep) -> Self {
        ProduceError::TooDeep(e)
    }
}
impl From<csl_run::Error> for ProduceError {
    fn from(e: csl_run::Error) -> Self {
        ProduceError::Run(e)
    }
}

type Rows = Vec<([u8; 32], Vec<u8>)>;

/// Collects a trie build's nodes under their table keys and by hash.
struct Collect<'a> {
    keyed: &'a mut Rows,
    by_hash: &'a mut Rows,
    /// `None` for the account trie; the owner's hashed address for storage.
    owner: Option<B256>,
    err: Option<ProduceError>,
}

impl csl_eth_trie::Sink for Collect<'_> {
    fn node(&mut self, key: NodeKey, rlp: &[u8]) {
        if self.err.is_some() {
            return;
        }
        let k = match self.owner {
            None => key.table_key(),
            Some(owner) => key.storage_table_key(&owner),
        };
        let k = match k {
            Ok(k) => k,
            Err(e) => {
                self.err = Some(e.into());
                return;
            }
        };
        if rlp.len() > MAX_NODE_BYTES {
            self.err = Some(ProduceError::NodeTooLarge { key: k, len: rlp.len() });
            return;
        }
        self.keyed.push((k, rlp.to_vec()));
        self.by_hash.push((keccak256(rlp).0, rlp.to_vec()));
    }
}

/// What the producer may vary per snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The learned index bound for every table. Each page the prediction
    /// is off costs the client one dependent request, so this trades model
    /// bytes against requests per lookup; `EPSILON` is the profile's default.
    pub epsilon: u16,
    /// For a path-prefix slice: the subtrees outside the slice as a snap
    /// range proof seals them ([`csl_eth_trie::verify_range`]), so the
    /// slice's leaves build up through their ancestors to `state_root`.
    /// Empty for a full export. Any order; sorted here.
    pub boundary: Vec<Sealed>,
}

impl Default for Options {
    fn default() -> Self {
        Options { epsilon: EPSILON, boundary: Vec::new() }
    }
}

/// Write the snapshot of `head` under `root` (`snapshots/<hash>/`, `blobs/`)
/// from `accounts` in ascending hashed-address order and `code` by hash.
pub fn produce<I>(root: &Path, head: &Head, prefix: &str, accounts: I, code: &HashMap<B256, Vec<u8>>) -> Result<Produced, ProduceError>
where
    I: IntoIterator<Item = AccountLeaf>,
{
    produce_with(root, head, prefix, accounts, code, Options::default())
}

pub fn produce_with<I>(root: &Path, head: &Head, prefix: &str, accounts: I, code: &HashMap<B256, Vec<u8>>, opts: Options) -> Result<Produced, ProduceError>
where
    I: IntoIterator<Item = AccountLeaf>,
{
    let epsilon = opts.epsilon;
    let mut stats = Stats::default();
    let mut account_rows: Rows = Vec::new();
    let mut storage_rows: Rows = Vec::new();
    let mut by_hash: Rows = Vec::new();
    let mut code_rows: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();

    // Account trie, with every storage trie built and checked as its
    // account streams past.
    let mut account_builder = Builder::new(Collect { keyed: &mut account_rows, by_hash: &mut by_hash, owner: None, err: None });
    let mut boundary = opts.boundary;
    boundary.sort_by_key(|a| a.0);
    let mut next_sealed = 0usize;
    let mut prev: Option<B256> = None;
    let mut storage_sink_rows: Rows = Vec::new();
    let mut storage_by_hash: Rows = Vec::new();
    for leaf in accounts {
        if let Some(p) = prev {
            if leaf.hashed <= p {
                return Err(ProduceError::Unsorted { prev: p, next: leaf.hashed });
            }
        }
        prev = Some(leaf.hashed);
        stats.accounts += 1;

        // Storage.
        if leaf.storage.is_empty() {
            if leaf.account.storage_root != EMPTY_ROOT {
                return Err(ProduceError::StorageRoot { owner: leaf.hashed, expected: leaf.account.storage_root, got: EMPTY_ROOT });
            }
        } else {
            let mut b = Builder::new(Collect { keyed: &mut storage_sink_rows, by_hash: &mut storage_by_hash, owner: Some(leaf.hashed), err: None });
            for (slot, word) in &leaf.storage {
                b.push(path_of(slot), encode_word(word))?;
            }
            let (built, sink) = b.finish();
            if let Some(e) = sink.err {
                return Err(e);
            }
            if built.root != leaf.account.storage_root {
                return Err(ProduceError::StorageRoot { owner: leaf.hashed, expected: leaf.account.storage_root, got: built.root });
            }
            stats.storage_slots += built.leaves;
            stats.storage_tries += 1;
            stats.storage_nodes += built.nodes;
            stats.embedded += built.embedded;
            storage_rows.append(&mut storage_sink_rows);
        }

        // Code.
        let ch = leaf.account.code_hash;
        if ch != KECCAK_EMPTY && !code_rows.contains_key(&ch.0) {
            let Some(bytes) = code.get(&ch) else {
                return Err(ProduceError::Code { hash: ch, what: "no bytecode" });
            };
            if code_key(bytes) != ch.0 {
                return Err(ProduceError::Code { hash: ch, what: "bytecode hashes differently" });
            }
            if bytes.is_empty() {
                return Err(ProduceError::Code { hash: ch, what: "empty bytecode under a non-empty hash" });
            }
            code_rows.insert(ch.0, bytes.clone());
        }

        let path = path_of(&leaf.hashed);
        while next_sealed < boundary.len() && boundary[next_sealed].0 < path {
            let (p, node) = &boundary[next_sealed];
            account_builder.push_sealed(*p, node.clone())?;
            next_sealed += 1;
        }
        account_builder.push(path, leaf.account.encode())?;
    }
    for (p, node) in &boundary[next_sealed..] {
        account_builder.push_sealed(*p, node.clone())?;
    }
    let (built, sink) = account_builder.finish();
    if let Some(e) = sink.err {
        return Err(e);
    }
    if built.root != head.state_root {
        return Err(ProduceError::StateRoot { expected: head.state_root, got: built.root });
    }
    stats.account_nodes = built.nodes;
    stats.sealed = built.sealed;
    stats.embedded += built.embedded;
    by_hash.append(&mut storage_by_hash);
    stats.code_entries = code_rows.len() as u64;

    // Key order. Positions are unique within a trie and owners separate
    // storage tries; the by-hash table deduplicates identical nodes.
    account_rows.sort_unstable_by_key(|a| a.0);
    storage_rows.sort_unstable_by_key(|a| a.0);
    by_hash.sort_unstable_by_key(|a| a.0);
    by_hash.dedup_by(|a, b| a.0 == b.0);
    debug_assert!(account_rows.windows(2).all(|w| w[0].0 < w[1].0));
    debug_assert!(storage_rows.windows(2).all(|w| w[0].0 < w[1].0));

    // Files.
    let dir = root.join(snapshot_dir(&head.block_hash));
    fs::create_dir_all(&dir)?;
    fs::create_dir_all(root.join("blobs"))?;
    let mut tables = Vec::new();
    let cfg = |table_id: u16| Config { profile_id: profile_id(), table_id, value_size: 0, epsilon };

    let mut write_rows = |table_id: u16, rows: &Rows, stats: &mut Stats| -> Result<(), ProduceError> {
        if rows.is_empty() {
            return Ok(());
        }
        let path = dir.join(TABLE_FILES[table_id as usize]);
        let file = File::options().read(true).write(true).create(true).truncate(true).open(&path)?;
        let mut w = Writer::with_format(file, cfg(table_id), Format::variable(), rows.len() as u64)?;
        for (k, v) in rows {
            w.push(Entry::value(*k, v.clone()))?;
        }
        let built = w.finish()?;
        tables.push(TableRef {
            table_id,
            root: built.root,
            page_count: built.page_count,
            entry_count: built.entry_count,
            epsilon_pages: epsilon,
            model_bytes: built.layout.model_bytes as u32,
            model_root: built.model_root,
        });
        stats.tables[table_id as usize] =
            Some(TableStats { entries: built.entry_count, pages: built.page_count, model_bytes: built.layout.model_bytes, file_bytes: built.layout.total_len });
        Ok(())
    };
    write_rows(TABLE_ACCOUNT_NODES, &account_rows, &mut stats)?;
    write_rows(TABLE_STORAGE_NODES, &storage_rows, &mut stats)?;
    write_rows(TABLE_NODES_BY_HASH, &by_hash, &mut stats)?;

    // Code: inline up to the threshold, a blob file above it.
    if !code_rows.is_empty() {
        let path = dir.join(TABLE_FILES[TABLE_CODE as usize]);
        let file = File::options().read(true).write(true).create(true).truncate(true).open(&path)?;
        let mut w = Writer::with_format(file, cfg(TABLE_CODE), Format::variable(), code_rows.len() as u64)?;
        for (k, v) in &code_rows {
            if v.len() > CODE_BLOB_THRESHOLD {
                let h = *blake3::hash(v).as_bytes();
                write_atomic(&root.join(blob_path(&h)), v)?;
                stats.code_blobs += 1;
                w.push(Entry::blob(*k, h))?;
            } else {
                w.push(Entry::value(*k, v.clone()))?;
            }
        }
        let built = w.finish()?;
        tables.push(TableRef {
            table_id: TABLE_CODE,
            root: built.root,
            page_count: built.page_count,
            entry_count: built.entry_count,
            epsilon_pages: epsilon,
            model_bytes: built.layout.model_bytes as u32,
            model_root: built.model_root,
        });
        stats.tables[TABLE_CODE as usize] =
            Some(TableStats { entries: built.entry_count, pages: built.page_count, model_bytes: built.layout.model_bytes, file_bytes: built.layout.total_len });
    }
    tables.sort_by_key(|t| t.table_id);

    let manifest = Manifest {
        format_version: FORMAT_VERSION,
        profile_id: profile_id(),
        block_hash: head.block_hash,
        block_number: head.block_number,
        timestamp: head.timestamp,
        state_root: head.state_root,
        prefix: prefix.to_string(),
        tables,
    };
    write_atomic(&root.join(manifest_path(&head.block_hash)), manifest.to_json().as_bytes())?;
    write_atomic(&root.join(LATEST_FILE), hex::encode(head.block_hash).as_bytes())?;
    Ok(Produced { manifest, stats, dir })
}

/// Write to a temporary name and rename, so a reader never sees a partial
/// file.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut f = File::create(&tmp)?;
        f.write_all(bytes)?;
        f.flush()?;
    }
    fs::rename(&tmp, path)
}

/// Build a `Nibbles` path from a hex prefix string for manifests and tests.
pub fn prefix_nibbles(hex_nibbles: &str) -> Option<Nibbles> {
    let mut n = Nibbles::new();
    for c in hex_nibbles.chars() {
        n.push(c.to_digit(16)? as u8);
    }
    Some(n)
}
