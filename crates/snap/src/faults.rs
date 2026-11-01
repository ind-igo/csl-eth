//! The milestone 1 fault table (PoC spec, "Fault injection"): each named
//! corruption of a bucket or of the host's responses, applied on the way
//! from the bucket to the client, read through with the workload's shapes,
//! and tabulated: every row must end in `Insufficient` or a correct
//! answer, never a wrong value and never a false absence.
//!
//! Faults are injected by a [`FaultDriver`], not by editing files on disk.
//! The client does no I/O: it computes over a `Store` and a `Driver`
//! answers its wants, so a driver that lies is exactly the hostile host
//! the design must survive (a CDN serving a stale page, a mirror with a
//! bit flipped, a range request answered from the wrong offset). The
//! driver wraps a clean [`DirDriver`], classifies every want by file and
//! region (page 0, data pages, model pages, the manifest, a blob) from the
//! manifest of a clean open, and rewrites the response as the fault says,
//! deterministically from a seed.
//!
//! Most faults are *aimed*. A fault that damages every page a read touches
//! mostly damages the account root (table key `0^32`, the first entry of
//! the account table's first page), so every walk stops at the top and
//! nothing below it is exercised. Instead, before the table runs, a clean
//! walk of every read ([`routes`]) records the nodes it needs: their table,
//! key, depth, the page that holds each and the page the model predicts
//! for it, path-keyed (tables 0 and 1) and by hash (table 3, the
//! baseline's). Each read then aims at one node, cycling over the depths
//! across the plan (root, middle and deepest account node; every storage
//! depth for slot reads), and the driver corrupts only the response that
//! holds that node's page, leaving every other response clean. The row
//! reports which (table, trie, depth) each read aimed at, and the reads
//! whose aim the fault could not land ("untargeted"). Faults that are about
//! a whole file or region (page 0, model pages, the manifest, `latest`,
//! blobs) and `bit_flip` (random bits in every data response) are not
//! aimed.
//!
//! The format carries no Bloom filter (pages route by chained fences and
//! the learned model), so the spec's "zeroed Bloom" has nothing to zero;
//! the table says so.
//!
//! The reads are the workload's ([`workload::plan`] at small sizes: crafted
//! leaf and extension mismatches, deep storage, extension-crossing paths,
//! keys outside the prefix) and are scored by the workload's scorer, so a
//! value or an absence for an outside key fails the table as it fails the
//! workload. `Insufficient` is the acceptable failure; the `Reason`s seen
//! per fault and mode say how the client caught it: at the page (`Run`),
//! at the trie (`Invalid`, `Missing`) or at the hash of the bytes (`Code`,
//! `Blob`), and in which table.

use crate::workload::{self, Draw, Expect, Plan, Sizes, Target, Verdict};
use crate::Slice;
use alloy_primitives::{keccak256, B256};
use clap::Args as ClapArgs;
use csl_eth_client::{DirDriver, Driver, Got, Hint, Reason, Snapshot, Want};
use csl_eth_store::{
    manifest_path, table_path, Manifest, LATEST_FILE, RUN_FORMAT, TABLE_ACCOUNT_NODES, TABLE_CODE,
    TABLE_COUNT, TABLE_NODES_BY_HASH, TABLE_STORAGE_NODES,
};
use csl_eth_trie::{path_of, walk, Account, Nibbles, NodeKey, Outcome, EMPTY_ROOT_HASH};
use csl_run::{EntryLayout, Layout, Page, Reader, KEY_MAX, KEY_MIN, PAGE};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    fs::File,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

pub use crate::workload::Mode;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The slice the bucket was built from (keys and expected values).
    #[arg(long)]
    pub slice: PathBuf,
    /// A bucket directory on disk; faults are applied to its responses.
    #[arg(long)]
    pub bucket: PathBuf,
    /// Where to write the JSON table.
    #[arg(long)]
    pub out: PathBuf,
    /// Reads per kind in the plan (present and absent accounts, present and
    /// absent slots; a quarter as many outside the prefix; code of every
    /// contract drawn).
    #[arg(long, default_value_t = 200)]
    pub keys: usize,
    /// Fraction of reads an aimed fault fires on, or of the qualifying
    /// responses an unaimed one touches.
    #[arg(long, default_value_t = 1.0)]
    pub rate: f64,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    #[arg(long, value_enum, default_value_t = Mode::Both)]
    pub mode: Mode,
    /// Account-trie depths kept across reads (0: every node comes through
    /// the faulty driver on every read).
    #[arg(long, default_value_t = 0)]
    pub top_levels: usize,
    /// Run only these faults (repeatable); every fault when absent. The
    /// control row always runs.
    #[arg(long = "fault")]
    pub faults: Vec<String>,
}

/// One named corruption. `none` is the control row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Fault {
    None,
    NodeOmitted,
    PageMalformed,
    ForgedFence,
    FenceGap,
    FenceExcludes,
    TruncatedPage,
    TruncatedLatest,
    TruncatedManifest,
    TruncatedBlob,
    WrongRunPage,
    WrongRange,
    BitFlip,
    BitFlipPage,
    ModelPageTamper,
    Page0Tamper,
    Page0Missing,
    ManifestStateRoot,
    ManifestModelRoot,
    ManifestTableRoot,
    MissingRange,
    HttpError,
    StaleValue,
    StalePage,
}

impl Fault {
    pub const ALL: [Fault; 24] = [
        Fault::None,
        Fault::NodeOmitted,
        Fault::PageMalformed,
        Fault::ForgedFence,
        Fault::FenceGap,
        Fault::FenceExcludes,
        Fault::TruncatedPage,
        Fault::TruncatedLatest,
        Fault::TruncatedManifest,
        Fault::TruncatedBlob,
        Fault::WrongRunPage,
        Fault::WrongRange,
        Fault::BitFlip,
        Fault::BitFlipPage,
        Fault::ModelPageTamper,
        Fault::Page0Tamper,
        Fault::Page0Missing,
        Fault::ManifestStateRoot,
        Fault::ManifestModelRoot,
        Fault::ManifestTableRoot,
        Fault::MissingRange,
        Fault::HttpError,
        Fault::StaleValue,
        Fault::StalePage,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Fault::None => "none",
            Fault::NodeOmitted => "node_omitted",
            Fault::PageMalformed => "page_malformed",
            Fault::ForgedFence => "forged_fence",
            Fault::FenceGap => "fence_gap",
            Fault::FenceExcludes => "fence_excludes",
            Fault::TruncatedPage => "truncated_page",
            Fault::TruncatedLatest => "truncated_latest",
            Fault::TruncatedManifest => "truncated_manifest",
            Fault::TruncatedBlob => "truncated_blob",
            Fault::WrongRunPage => "wrong_run_page",
            Fault::WrongRange => "wrong_range",
            Fault::BitFlip => "bit_flip",
            Fault::BitFlipPage => "bit_flip_page",
            Fault::ModelPageTamper => "model_page_tamper",
            Fault::Page0Tamper => "page0_tamper",
            Fault::Page0Missing => "page0_missing",
            Fault::ManifestStateRoot => "manifest_state_root",
            Fault::ManifestModelRoot => "manifest_model_root",
            Fault::ManifestTableRoot => "manifest_table_root",
            Fault::MissingRange => "missing_range",
            Fault::HttpError => "http_error",
            Fault::StaleValue => "stale_value",
            Fault::StalePage => "stale_page",
        }
    }

    pub fn parse(s: &str) -> Option<Fault> {
        Fault::ALL.iter().copied().find(|f| f.name() == s)
    }

    /// What the driver does to a qualifying response. "The aimed node" is
    /// the one node of the read's path the fault is aimed at (module doc).
    pub fn describe(self) -> &'static str {
        match self {
            Fault::None => "control: responses pass through untouched",
            Fault::NodeOmitted => "the page holding the aimed node re-encoded without it; fences and count stay consistent, so the node is silently missing",
            Fault::PageMalformed => "the page holding the aimed node re-encoded without it but the header's count left as it was: the offset table no longer matches",
            Fault::ForgedFence => "the page the model predicts for the aimed node, when that is not the page holding it, re-encoded with fences [0^32, FF^32]: it claims to cover the node, so the node is found absent from it instead of on its neighbour (a node the model predicts exactly cannot be misrouted this way, and is aimed past)",
            Fault::FenceGap => "the page holding the aimed node re-encoded with fences narrowed to its first entry and the successor of its last: keys in the former gaps fall between pages, but every node a walk needs is an entry and stays covered, so this cannot misroute a read (a negative control)",
            Fault::FenceExcludes => "the page holding the aimed node re-encoded with its upper fence lowered onto its last entry, so a key the page holds is outside its fences; the page's own validation rejects it (not aimable on the table's last page, whose upper fence must stay FF^32)",
            Fault::TruncatedPage => "the range response holding the aimed node's page answered with half the bytes asked",
            Fault::TruncatedLatest => "snapshots/latest answered with its first half",
            Fault::TruncatedManifest => "the manifest answered with its first half (latest served whole)",
            Fault::TruncatedBlob => "blob files answered with their first half",
            Fault::WrongRunPage => "the range response holding the aimed node's page answered with the same range of another table (account_nodes from storage_nodes and back, nodes_by_hash from code and back)",
            Fault::WrongRange => "the range response holding the aimed node's page answered from one page further into the same file",
            Fault::BitFlip => "unaimed: one random bit flipped in every data range response",
            Fault::BitFlipPage => "one random bit flipped in the page holding the aimed node",
            Fault::ModelPageTamper => "one random bit flipped in each model page record",
            Fault::Page0Tamper => "one random bit flipped in page 0 (header and top model) of every table",
            Fault::Page0Missing => "page 0 of every table answered Ok(None): no table can route",
            Fault::ManifestStateRoot => "manifest state_root altered",
            Fault::ManifestModelRoot => "every table's model_root in the manifest altered",
            Fault::ManifestTableRoot => "every table's root (blake3 of the run file) in the manifest altered; the client never checks it, the trie proves values",
            Fault::MissingRange => "the range response holding the aimed node's page answered Ok(None) (the host says the file is not there); page 0 and model pages are served, so the refusal lands mid-walk",
            Fault::HttpError => "the range response holding the aimed node's page answered Err(500); page 0 and model pages are served, so the refusal lands mid-walk",
            Fault::StaleValue => "the aimed node's value bytes altered in place (one byte), the page re-encoded",
            Fault::StalePage => "every entry's value bytes altered in place on the page holding the aimed node",
        }
    }

    /// Aimed at one node per read (module doc).
    pub fn aimed(self) -> bool {
        matches!(
            self,
            Fault::NodeOmitted
                | Fault::PageMalformed
                | Fault::ForgedFence
                | Fault::FenceGap
                | Fault::FenceExcludes
                | Fault::TruncatedPage
                | Fault::WrongRunPage
                | Fault::WrongRange
                | Fault::BitFlipPage
                | Fault::MissingRange
                | Fault::HttpError
                | Fault::StaleValue
                | Fault::StalePage
        )
    }

    /// The fault should change some response; a row where it changed none
    /// is flagged (its reads say nothing about the fault).
    pub fn fires(self) -> bool {
        self != Fault::None
    }

    fn qualifies(self, k: &Kind) -> bool {
        if self.aimed() {
            return matches!(k, Kind::Data(_));
        }
        match self {
            Fault::BitFlip => matches!(k, Kind::Data(_)),
            Fault::TruncatedLatest => matches!(k, Kind::Latest),
            Fault::TruncatedManifest => matches!(k, Kind::Manifest),
            Fault::TruncatedBlob => matches!(k, Kind::Blob),
            Fault::ModelPageTamper => matches!(k, Kind::Model(_)),
            Fault::Page0Tamper | Fault::Page0Missing => matches!(k, Kind::Page0(_)),
            Fault::ManifestStateRoot | Fault::ManifestModelRoot | Fault::ManifestTableRoot => {
                matches!(k, Kind::Manifest)
            }
            _ => false,
        }
    }

    /// The row's seed: from the fault's name, the base seed and the mode,
    /// so `--fault x` alone reproduces row x of a full table.
    fn seed(self, base: u64, mode: &str) -> u64 {
        let h = keccak256(format!("{}/{mode}/{base}", self.name()));
        u64::from_le_bytes(h.0[..8].try_into().expect("8 bytes"))
    }
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a want is for, so a fault can aim at one kind of response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Latest,
    Manifest,
    Blob,
    File,
    /// Index into [`Geometry::tables`].
    Page0(usize),
    Data(usize),
    Model(usize),
    /// A range of a file the geometry does not know.
    Range,
}

#[derive(Clone, Debug)]
struct TableGeom {
    table: u16,
    rel: String,
    layout: Layout,
}

/// Where each table's regions lie, from the manifest of a clean open. The
/// client computes the same offsets from the same manifest, so a range
/// classifies by its first byte: 0 is page 0, below `model_off` a data
/// page, from `model_off` the model section.
#[derive(Clone, Debug)]
pub struct Geometry {
    tables: Vec<TableGeom>,
    manifest: String,
}

impl Geometry {
    pub fn of(m: &Manifest) -> Result<Geometry, String> {
        let mut tables = Vec::new();
        for t in 0..TABLE_COUNT as u16 {
            let Some(tr) = m.table(t) else { continue };
            let layout = Layout::try_new_with(
                tr.page_count,
                u64::from(tr.model_bytes),
                RUN_FORMAT.inline_proofs,
            )
            .map_err(|e| format!("table {t}: {e}"))?;
            tables.push(TableGeom {
                table: t,
                rel: table_path(&m.block_hash, t),
                layout,
            });
        }
        Ok(Geometry {
            tables,
            manifest: manifest_path(&m.block_hash),
        })
    }

    fn by_table(&self, table: u16) -> Option<&TableGeom> {
        self.tables.iter().find(|g| g.table == table)
    }

    fn classify(&self, w: &Want) -> Kind {
        match w {
            Want::File { rel } if rel == LATEST_FILE => Kind::Latest,
            Want::File { rel } if *rel == self.manifest => Kind::Manifest,
            Want::File { rel } if rel.starts_with("blobs/") => Kind::Blob,
            Want::File { .. } => Kind::File,
            Want::Range { rel, off, .. } => {
                let Some(i) = self.tables.iter().position(|g| g.rel == *rel) else {
                    return Kind::Range;
                };
                let l = &self.tables[i].layout;
                if *off < PAGE as u64 {
                    Kind::Page0(i)
                } else if *off < l.model_off {
                    Kind::Data(i)
                } else {
                    Kind::Model(i)
                }
            }
        }
    }
}

/// Which trie a node belongs to (the baseline's table 3 holds both).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Trie {
    Account,
    Storage,
    Code,
}

impl Trie {
    fn name(self) -> &'static str {
        match self {
            Trie::Account => "account",
            Trie::Storage => "storage",
            Trie::Code => "code",
        }
    }
}

/// One node a clean read needs, where it lives in its table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Aim {
    pub table: u16,
    pub trie: Trie,
    /// Nibbles consumed to reach the node (0 for code).
    pub depth: usize,
    pub key: [u8; 32],
    /// The data page that holds it.
    pub page: u64,
    /// The data page the model predicts for its key: the first the reader
    /// visits.
    pub predicted: u64,
}

impl Aim {
    /// The coverage label: table, trie and depth.
    pub fn label(&self) -> String {
        format!(
            "table {} {} depth {}",
            self.table,
            self.trie.name(),
            self.depth
        )
    }
}

/// The nodes a clean read of one draw needs, in walk order, as the path
/// mode and the baseline fetch them.
#[derive(Clone, Debug, Default)]
pub struct Route {
    pub path: Vec<Aim>,
    pub baseline: Vec<Aim>,
}

#[derive(Default)]
struct State {
    rng: Option<ChaCha8Rng>,
    aim: Option<Aim>,
    /// The aim landed: a response holding it was changed this read.
    hit: bool,
    responses: u64,
    /// Responses whose bytes or status the fault changed.
    faulted: u64,
}

/// A handle on a driver's counters that survives the driver being moved
/// into a snapshot (or dropped by an open that refused).
#[derive(Clone, Default)]
pub struct Handle(Arc<Mutex<State>>);

impl Handle {
    /// The node the next read is aimed at (`None`: the read is spared).
    pub fn set_aim(&self, aim: Option<Aim>) {
        let mut st = self.0.lock().unwrap();
        st.aim = aim;
        st.hit = false;
    }

    /// Whether the aim of the read just made landed.
    pub fn take_hit(&self) -> bool {
        let mut st = self.0.lock().unwrap();
        std::mem::take(&mut st.hit)
    }

    /// Responses seen and responses the fault changed.
    pub fn stats(&self) -> (u64, u64) {
        let st = self.0.lock().unwrap();
        (st.responses, st.faulted)
    }
}

/// A host that answers from a clean driver and lies as one [`Fault`] says.
pub struct FaultDriver<D> {
    inner: D,
    fault: Fault,
    rate: f64,
    geometry: Geometry,
    state: Handle,
}

/// What a page edit does with a decoded page.
enum Edit {
    Keep,
    Reencode,
    /// Re-encode, then write this entry count into the header: the page's
    /// shape no longer matches its own count.
    ReencodeWithCount(u16),
}

impl<D: Driver> FaultDriver<D> {
    pub fn new(inner: D, fault: Fault, rate: f64, geometry: Geometry, seed: u64) -> FaultDriver<D> {
        let state = Handle::default();
        state.0.lock().unwrap().rng = Some(ChaCha8Rng::seed_from_u64(seed));
        FaultDriver {
            inner,
            fault,
            rate: rate.clamp(0.0, 1.0),
            geometry,
            state,
        }
    }

    pub fn handle(&self) -> Handle {
        self.state.clone()
    }

    fn apply(&self, w: &Want, got: Got) -> Got {
        let kind = self.geometry.classify(w);
        let mut guard = self.state.0.lock().unwrap();
        let st = &mut *guard;
        st.responses += 1;
        if !self.fault.qualifies(&kind) {
            return got;
        }
        let rng = st.rng.as_mut().expect("seeded");
        // An aimed fault's rate is per read (see `run_table`).
        if !self.fault.aimed() && self.rate < 1.0 && !rng.random_bool(self.rate) {
            return got;
        }
        let out = match (&kind, w) {
            (Kind::Data(i), Want::Range { rel, off, len }) => {
                let g = &self.geometry.tables[*i];
                if self.fault.aimed() {
                    match &st.aim {
                        Some(aim) if aim.table == g.table => {
                            self.aimed(rng, aim, g, rel, *off, *len, &got)
                        }
                        _ => None,
                    }
                } else {
                    // `bit_flip`: anywhere in the response.
                    got.clone().ok().flatten().map(|mut v| {
                        flip_bit(rng, &mut v);
                        Ok(Some(v))
                    })
                }
            }
            (Kind::Page0(_), Want::Range { .. }) if self.fault == Fault::Page0Missing => {
                Some(Ok(None))
            }
            (Kind::Model(_) | Kind::Page0(_), Want::Range { .. }) => {
                got.clone().ok().flatten().map(|mut v| {
                    flip_bit(rng, &mut v);
                    Ok(Some(v))
                })
            }
            (Kind::Manifest, Want::File { .. }) => match self.fault {
                Fault::TruncatedManifest => truncate(&got),
                _ => got
                    .clone()
                    .ok()
                    .flatten()
                    .and_then(|v| self.manifest_fault(v)),
            },
            (Kind::Latest | Kind::Blob, Want::File { .. }) => truncate(&got),
            _ => None,
        };
        match out {
            // A re-encode can reproduce the bytes it was given; only a
            // response that actually changed counts as faulted.
            Some(g) if g != got => {
                st.faulted += 1;
                if self.fault.aimed() {
                    st.hit = true;
                }
                g
            }
            _ => got,
        }
    }

    /// The host is down for this want: not there, or a server error.
    fn refusal(&self) -> Got {
        match self.fault {
            Fault::HttpError => Err("500 internal server error".to_string()),
            _ => Ok(None),
        }
    }

    /// An aimed fault on one data range response of the aim's table: only
    /// a response holding the aimed page is touched, and within it only
    /// that page (or the whole response, for the faults that are about the
    /// response: refused, cut short, served from elsewhere).
    #[allow(clippy::too_many_arguments)]
    fn aimed(
        &self,
        rng: &mut ChaCha8Rng,
        aim: &Aim,
        g: &TableGeom,
        rel: &str,
        off: u64,
        len: usize,
        got: &Got,
    ) -> Option<Got> {
        let l = &g.layout;
        // Byte offset of record `q` in this response, when it holds all of it.
        let at = |q: u64| -> Option<usize> {
            let start = l.checked_record_off(q)?;
            let end = start + l.record_bytes;
            (start >= off && end <= off + len as u64).then(|| (start - off) as usize)
        };
        match self.fault {
            Fault::MissingRange | Fault::HttpError => {
                at(aim.page)?;
                return Some(self.refusal());
            }
            Fault::TruncatedPage => {
                at(aim.page)?;
                return truncate(got);
            }
            Fault::WrongRunPage => {
                at(aim.page)?;
                let partner = self.geometry.by_table(g.table ^ 1)?;
                let span = partner.layout.page_count * PAGE as u64;
                let off2 = PAGE as u64 + (off - PAGE as u64) % span;
                let w = Want::Range {
                    rel: partner.rel.clone(),
                    off: off2,
                    len,
                };
                return Some(self.inner.fetch(&[w]).remove(0));
            }
            Fault::WrongRange => {
                at(aim.page)?;
                let w = Want::Range {
                    rel: rel.to_string(),
                    off: off + PAGE as u64,
                    len,
                };
                return Some(self.inner.fetch(&[w]).remove(0));
            }
            _ => {}
        }
        let q = if self.fault == Fault::ForgedFence {
            aim.predicted
        } else {
            aim.page
        };
        let b = at(q)?;
        let mut bytes = got.clone().ok().flatten()?;
        let slot = &mut bytes[b..b + PAGE];
        if self.fault == Fault::BitFlipPage {
            flip_bit(rng, slot);
            return Some(Ok(Some(bytes)));
        }
        let mut page = Page::decode_with(slot, EntryLayout::Variable, q == l.page_count, q).ok()?;
        let find = |page: &Page| page.entries.iter().position(|e| e.key == aim.key);
        let edit = match self.fault {
            Fault::NodeOmitted => match find(&page) {
                Some(i) => {
                    page.entries.remove(i);
                    Edit::Reencode
                }
                None => Edit::Keep,
            },
            Fault::PageMalformed => match find(&page) {
                Some(i) => {
                    let n = page.entries.len() as u16;
                    page.entries.remove(i);
                    Edit::ReencodeWithCount(n)
                }
                None => Edit::Keep,
            },
            Fault::StaleValue => match find(&page) {
                // A value, or a blob's reference; a tombstone has no bytes.
                Some(i) if !page.entries[i].value.is_empty() => {
                    stale(&mut page.entries[i].value);
                    Edit::Reencode
                }
                _ => Edit::Keep,
            },
            Fault::ForgedFence => {
                page.lo = KEY_MIN;
                page.hi = KEY_MAX;
                Edit::Reencode
            }
            Fault::FenceGap => {
                let (Some(first), Some(last)) = (page.entries.first(), page.entries.last()) else {
                    return None;
                };
                let lo = first.key;
                let hi = if page.hi == KEY_MAX {
                    KEY_MAX
                } else {
                    succ(last.key)?
                };
                page.lo = lo;
                page.hi = hi;
                Edit::Reencode
            }
            Fault::FenceExcludes => match page.entries.last() {
                // The last page's hi must stay FF^32 to decode at all;
                // lowering it is a different malformation, skipped here.
                Some(last) if page.hi != KEY_MAX => {
                    page.hi = last.key;
                    Edit::Reencode
                }
                _ => Edit::Keep,
            },
            Fault::StalePage => {
                let mut any = false;
                for e in page.entries.iter_mut().filter(|e| !e.value.is_empty()) {
                    stale(&mut e.value);
                    any = true;
                }
                if any {
                    Edit::Reencode
                } else {
                    Edit::Keep
                }
            }
            _ => Edit::Keep,
        };
        let count = match edit {
            Edit::Keep => return None,
            Edit::Reencode => None,
            Edit::ReencodeWithCount(n) => Some(n),
        };
        slot.copy_from_slice(&page.encode_with(EntryLayout::Variable));
        if let Some(n) = count {
            slot[0..2].copy_from_slice(&n.to_le_bytes());
        }
        Some(Ok(Some(bytes)))
    }

    /// The manifest with one field forged. `state_root` is what the client
    /// compares to the root it verified; `model_root` is what page 0 must
    /// hash to; `root` is the run file's identity, which nothing checks.
    fn manifest_fault(&self, bytes: Vec<u8>) -> Option<Got> {
        let mut m: Value = serde_json::from_slice(&bytes).ok()?;
        match self.fault {
            Fault::ManifestStateRoot => forge_hex(m.get_mut("state_root")?),
            Fault::ManifestModelRoot | Fault::ManifestTableRoot => {
                let field = if self.fault == Fault::ManifestModelRoot {
                    "model_root"
                } else {
                    "root"
                };
                for t in m.get_mut("tables")?.as_array_mut()? {
                    forge_hex(t.get_mut(field)?);
                }
            }
            _ => return None,
        }
        Some(Ok(Some(serde_json::to_vec(&m).ok()?)))
    }
}

impl<D: Driver> Driver for FaultDriver<D> {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        let got = self.inner.fetch(wants);
        wants
            .iter()
            .zip(got)
            .map(|(w, g)| self.apply(w, g))
            .collect()
    }
}

/// A value altered in place: same length, one byte in the middle changed.
fn stale(v: &mut [u8]) {
    let i = v.len() / 2;
    v[i] ^= 0x01;
}

fn flip_bit(rng: &mut ChaCha8Rng, v: &mut [u8]) {
    if v.is_empty() {
        return;
    }
    let i = rng.random_range(0..v.len());
    v[i] ^= 1 << rng.random_range(0..8);
}

fn truncate(got: &Got) -> Option<Got> {
    let mut v = got.clone().ok().flatten()?;
    v.truncate(v.len() / 2);
    Some(Ok(Some(v)))
}

/// The next key in byte order; `None` past `FF^32`.
fn succ(mut k: [u8; 32]) -> Option<[u8; 32]> {
    for b in k.iter_mut().rev() {
        if *b == 0xff {
            *b = 0;
        } else {
            *b += 1;
            return Some(k);
        }
    }
    None
}

/// Change the last hex digit of a JSON hex string in place.
fn forge_hex(v: &mut Value) {
    if let Some(s) = v.as_str() {
        let mut s = s.to_string();
        let last = s.pop().unwrap_or('0');
        s.push(if last == 'a' { 'b' } else { 'a' });
        *v = Value::String(s);
    }
}

// ----------------------------------------------------------------------
// Routes: what a clean read needs.

/// The bucket's tables read directly from disk, for the clean walks.
struct Clean {
    readers: Vec<Option<Reader<File>>>,
    state_root: B256,
}

impl Clean {
    fn open(bucket: &Path, m: &Manifest) -> Result<Clean, String> {
        let mut readers = Vec::new();
        for t in 0..TABLE_COUNT as u16 {
            let Some(tr) = m.table(t) else {
                readers.push(None);
                continue;
            };
            let p = bucket.join(table_path(&m.block_hash, t));
            let f = File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            let mut r = Reader::try_with_format(f, tr.run_ref(m.block_number), RUN_FORMAT)
                .map_err(|e| format!("table {t}: {e}"))?;
            r.prepare().map_err(|e| format!("table {t}: {e}"))?;
            readers.push(Some(r));
        }
        Ok(Clean {
            readers,
            state_root: m.state_root,
        })
    }

    fn reader(&mut self, t: u16) -> Result<&mut Reader<File>, String> {
        self.readers[t as usize]
            .as_mut()
            .ok_or_else(|| format!("the bucket has no table {t}"))
    }

    fn aim(&mut self, table: u16, trie: Trie, depth: usize, key: [u8; 32]) -> Result<Aim, String> {
        let r = self.reader(table)?;
        let (page, _, _) = r.locate(&key).map_err(|e| format!("table {table}: {e}"))?;
        let predicted = r
            .predict_page(csl_run::k64(&key))
            .map_err(|e| format!("table {table}: {e}"))?;
        Ok(Aim {
            table,
            trie,
            depth,
            key,
            page,
            predicted,
        })
    }

    /// Walk `path` from `root` over `table`, fetching each node by its
    /// path key until the trie answers or the table lacks one (outside the
    /// slice). The nodes the walk took, in order, with their bytes, and
    /// the walk's outcome.
    #[allow(clippy::type_complexity)]
    fn walk(
        &mut self,
        table: u16,
        root: B256,
        path: &Nibbles,
        key_of: impl Fn(&NodeKey) -> [u8; 32],
    ) -> Result<(Vec<(NodeKey, Vec<u8>)>, Outcome), String> {
        let mut nodes: HashMap<NodeKey, Vec<u8>> = HashMap::new();
        loop {
            let w = walk(root, path, &nodes);
            if let Outcome::Missing(nk) = &w.outcome {
                let r = self.reader(table)?;
                let (e, _) = r
                    .get_entry(&key_of(nk))
                    .map_err(|e| format!("table {table}: {e}"))?;
                if let Some(e) = e.filter(|e| e.tag == 0) {
                    nodes.insert(*nk, e.value);
                    continue;
                }
            }
            let held = w
                .fetched
                .iter()
                .filter_map(|nk| nodes.get(nk).map(|v| (*nk, v.clone())))
                .collect();
            return Ok((held, w.outcome));
        }
    }

    /// One trie's part of a route: path-keyed in `table`, by hash in 3.
    fn trie_route(
        &mut self,
        route: &mut Route,
        table: u16,
        trie: Trie,
        held: &[(NodeKey, Vec<u8>)],
        key_of: impl Fn(&NodeKey) -> [u8; 32],
    ) -> Result<(), String> {
        for (nk, bytes) in held {
            route
                .path
                .push(self.aim(table, trie, nk.depth(), key_of(nk))?);
            route.baseline.push(self.aim(
                TABLE_NODES_BY_HASH,
                trie,
                nk.depth(),
                keccak256(bytes).0,
            )?);
        }
        Ok(())
    }

    fn route(&mut self, draw: &Draw) -> Result<Route, String> {
        let mut route = Route::default();
        let account_key = |nk: &NodeKey| nk.table_key().expect("walk depth ≤ 62");
        match &draw.target {
            Target::Code(h) => {
                let a = self.aim(TABLE_CODE, Trie::Code, 0, h.0)?;
                route.path.push(a);
                route.baseline.push(a);
            }
            Target::Account(h) | Target::Slot(h, _) => {
                let root = self.state_root;
                let (held, outcome) =
                    self.walk(TABLE_ACCOUNT_NODES, root, &path_of(h), account_key)?;
                self.trie_route(
                    &mut route,
                    TABLE_ACCOUNT_NODES,
                    Trie::Account,
                    &held,
                    account_key,
                )?;
                let (Target::Slot(owner, slot), Outcome::Present(v)) = (&draw.target, outcome)
                else {
                    return Ok(route);
                };
                let account = Account::decode(&v).map_err(|e| format!("account {owner}: {e}"))?;
                if account.storage_root == EMPTY_ROOT_HASH {
                    return Ok(route);
                }
                let owner = *owner;
                let storage_key =
                    move |nk: &NodeKey| nk.storage_table_key(&owner).expect("walk depth ≤ 62");
                let (held, _) = self.walk(
                    TABLE_STORAGE_NODES,
                    account.storage_root,
                    &path_of(slot),
                    storage_key,
                )?;
                self.trie_route(
                    &mut route,
                    TABLE_STORAGE_NODES,
                    Trie::Storage,
                    &held,
                    storage_key,
                )?;
            }
        }
        Ok(route)
    }
}

/// The clean route of every draw, read from the bucket's own files.
pub fn routes(bucket: &Path, m: &Manifest, plan: &Plan) -> Result<Vec<Route>, String> {
    let mut clean = Clean::open(bucket, m)?;
    plan.draws.iter().map(|d| clean.route(d)).collect()
}

/// Cycles the aim over depths across the plan, per mode.
#[derive(Default)]
struct Aimer {
    account: usize,
    storage: usize,
}

impl Aimer {
    /// The node this read aims at: a slot read with a storage walk aims at
    /// the storage trie, each depth in turn; any other read at the root,
    /// the middle or the deepest node of its account walk (or its code
    /// entry). `forged_fence` needs a node the model does not predict
    /// exactly, and takes the nearest one on the same walk when the chosen
    /// depth has none.
    fn choose(&mut self, nodes: &[Aim], fault: Fault) -> Option<Aim> {
        let storage: Vec<&Aim> = nodes.iter().filter(|a| a.trie == Trie::Storage).collect();
        let (pool, i) = if !storage.is_empty() {
            let c = self.storage;
            self.storage += 1;
            let n = storage.len();
            (storage, c % n)
        } else {
            let pool: Vec<&Aim> = nodes.iter().collect();
            if pool.is_empty() {
                return None;
            }
            let c = self.account;
            self.account += 1;
            let n = pool.len();
            let i = match c % 3 {
                0 => 0,
                1 => n / 2,
                _ => n - 1,
            };
            (pool, i)
        };
        if fault != Fault::ForgedFence {
            return Some(*pool[i]);
        }
        (0..pool.len())
            .filter(|j| pool[*j].predicted != pool[*j].page)
            .min_by_key(|j| j.abs_diff(i))
            .map(|j| *pool[j])
    }
}

// ----------------------------------------------------------------------
// The table.

/// `Reason` as a short class, page numbers and offsets stripped, so a
/// fault's row says how it was caught rather than where.
fn reason_key(r: &Reason) -> String {
    match r {
        Reason::NoTable(t) => format!("NoTable(table {t})"),
        Reason::Missing { table, .. } => format!("Missing(table {table})"),
        Reason::Invalid { table, what, .. } => format!("Invalid({what:?}, table {table})"),
        Reason::Run { table, error } => format!("Run({}, table {table})", run_class(error)),
        Reason::Code(w) => format!("Code({w})"),
        Reason::Blob(w) => format!("Blob({})", run_class(w)),
        Reason::Budget => "Budget".into(),
        Reason::Value(w) => format!("Value({w})"),
    }
}

/// A `csl_run` error message reduced to its kind.
fn run_class(e: &str) -> String {
    if let Some(i) = e.find("malformed: ") {
        return format!("malformed: {}", &e[i + "malformed: ".len()..]);
    }
    for (needle, class) in [
        ("fences do not cover", "FenceGap"),
        ("model section does not match", "ModelMismatch"),
        ("short range", "io: short range"),
        ("not found", "io: not found"),
        ("not in the bucket", "not in the bucket"),
        ("does not hash to its name", "does not hash to its name"),
        ("short read", "ShortRead"),
        ("outside 1..=", "PageOutOfRange"),
        ("decode:", "Decode"),
        ("layout:", "Layout"),
    ] {
        if e.contains(needle) {
            return class.to_string();
        }
    }
    // Anything else: the message with offsets and hashes (runs of four or
    // more digits) collapsed; a short number such as a status code stays.
    let mut out = String::new();
    let mut run = String::new();
    for c in e.chars().take(80).chain(std::iter::once(' ')) {
        if c.is_ascii_digit() {
            run.push(c);
            continue;
        }
        if run.len() >= 4 {
            out.push('#');
        } else {
            out.push_str(&run);
        }
        run.clear();
        out.push(c);
    }
    out.pop();
    out
}

#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    pub reads: u64,
    pub correct: u64,
    pub insufficient: u64,
    pub wrong_value: u64,
    pub false_absent: u64,
    pub false_present: u64,
    /// A key outside the prefix answered with a value or an absence.
    pub outside_answered: u64,
    /// A right answer whose walk the shape model did not predict.
    pub shape_mismatch: u64,
}

impl Counts {
    fn add(&mut self, v: &Verdict, outside: bool, mismatches: u64) {
        self.reads += 1;
        self.shape_mismatch += mismatches;
        match v {
            Verdict::Correct => self.correct += 1,
            // Outside the prefix, a missing node is the right answer.
            Verdict::Insufficient(Reason::Missing { .. }) if outside => self.correct += 1,
            Verdict::Insufficient(_) => self.insufficient += 1,
            Verdict::WrongValue(_) | Verdict::Kind => self.wrong_value += 1,
            Verdict::FalseAbsent(_) => self.false_absent += 1,
            Verdict::FalsePresent(_) => self.false_present += 1,
            Verdict::OutsideAnswered(_) => self.outside_answered += 1,
        }
    }

    fn merge(&mut self, o: &Counts) {
        self.reads += o.reads;
        self.correct += o.correct;
        self.insufficient += o.insufficient;
        self.wrong_value += o.wrong_value;
        self.false_absent += o.false_absent;
        self.false_present += o.false_present;
        self.outside_answered += o.outside_answered;
        self.shape_mismatch += o.shape_mismatch;
    }

    /// Reads that fail the design.
    pub fn failures(&self) -> u64 {
        self.wrong_value + self.false_absent + self.false_present + self.outside_answered
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Failure {
    pub fault: String,
    pub mode: &'static str,
    pub shape: String,
    pub target: Value,
    /// The node the read was aimed at, when it was.
    pub aim: Option<String>,
    pub got: String,
    pub expected: String,
}

/// One fault under one mode.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ModeRow {
    /// The open refused: no reads were made.
    pub open_error: Option<String>,
    /// Responses the driver saw and responses the fault changed.
    pub responses: u64,
    pub faulted: u64,
    pub total: Counts,
    /// `Reason` classes seen, with counts: how the fault was caught.
    pub reasons: BTreeMap<String, u64>,
    /// Aimed faults: the (table, trie, depth) of each read whose aim
    /// landed.
    pub coverage: BTreeMap<String, u64>,
    /// Aimed faults: reads with no node to aim at, or whose aimed node the
    /// fault could not reach (see each fault's description).
    pub untargeted: u64,
    /// Reads the rate spared.
    pub spared: u64,
    /// Insufficient reads by the trie nodes their last walk decoded before
    /// it stopped: a refusal mid-walk stops below the root.
    pub caught_after_nodes: BTreeMap<usize, u64>,
    /// shape → counts.
    pub shapes: BTreeMap<String, Counts>,
}

/// One fault's row.
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub name: String,
    pub description: &'static str,
    pub aimed: bool,
    /// The first mode's refusal, when the open refused.
    pub open_error: Option<String>,
    /// Summed over the modes run.
    pub responses: u64,
    pub faulted: u64,
    /// Expected to fire but changed no response: its reads say nothing
    /// about the fault.
    pub flagged: bool,
    pub total: Counts,
    /// Summed over the modes; per mode in `modes`.
    pub reasons: BTreeMap<String, u64>,
    pub modes: BTreeMap<&'static str, ModeRow>,
}

impl Row {
    pub fn pass(&self) -> bool {
        self.total.failures() == 0 && self.total.shape_mismatch == 0
    }

    pub fn mode(&self, mode: &str) -> Option<&ModeRow> {
        self.modes.get(mode)
    }

    pub fn counts(&self, mode: &str, shape: &str) -> Option<&Counts> {
        self.modes.get(mode)?.shapes.get(shape)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Table {
    pub block_number: u64,
    pub state_root: B256,
    pub prefix: String,
    pub keys: usize,
    pub rate: f64,
    pub seed: u64,
    pub mode: &'static str,
    pub top_levels: usize,
    pub bloom: &'static str,
    pub plan: Value,
    /// Reads per shape.
    pub shapes: BTreeMap<String, usize>,
    /// The control row read every key right, and no row has a wrong value,
    /// a false absence or presence, an answered outside key, or a walk the
    /// shape model did not predict.
    pub pass: bool,
    pub control_correct: bool,
    /// Rows expected to fire that changed no response.
    pub flagged: Vec<String>,
    pub faults: Vec<Row>,
    /// Every failing read, in full (empty when `pass`).
    pub failures: Vec<Failure>,
}

impl Table {
    pub fn row(&self, name: &str) -> Option<&Row> {
        self.faults.iter().find(|r| r.name == name)
    }
}

#[derive(Clone, Debug)]
pub struct Options {
    pub keys: usize,
    pub rate: f64,
    pub seed: u64,
    pub mode: Mode,
    pub top_levels: usize,
    pub faults: Vec<Fault>,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            keys: 200,
            rate: 1.0,
            seed: 1,
            mode: Mode::Both,
            top_levels: 0,
            faults: Fault::ALL.to_vec(),
        }
    }
}

/// The plan the table reads: the workload's, at `keys` per kind.
pub fn plan_for(slice: &Slice, keys: usize, seed: u64) -> Result<Plan, String> {
    let keys = keys.max(1);
    let sizes = Sizes {
        accounts: keys,
        absent: keys,
        slots: keys,
        absent_slots: keys,
        outside: (keys / 4).max(1),
        d_account: csl_eth_store::D_ACCOUNT,
        d_storage: csl_eth_store::D_STORAGE,
    };
    workload::plan(slice, &sizes, seed)
}

/// The table: every fault in `o.faults` applied to `bucket`'s responses,
/// the workload's plan drawn from `slice` read under each, scored.
pub fn run_table(slice: &Slice, bucket: &Path, o: &Options) -> Result<Table, String> {
    let plan = plan_for(slice, o.keys, o.seed)?;
    run_table_plan(slice, bucket, &plan, o)
}

/// As [`run_table`], over a given plan. Each fault and mode gets its own
/// snapshot over its own driver, so nothing one fault verified (a kept
/// model page, a cached top level) serves the next.
pub fn run_table_plan(
    slice: &Slice,
    bucket: &Path,
    plan: &Plan,
    o: &Options,
) -> Result<Table, String> {
    let clean = Snapshot::open(DirDriver::new(bucket), None, slice.head.state_root)?;
    let geometry = Geometry::of(clean.manifest())?;
    let routes = routes(bucket, clean.manifest(), plan)?;
    drop(clean);
    let mut shapes: BTreeMap<String, usize> = BTreeMap::new();
    for d in &plan.draws {
        *shapes.entry(shape(d).to_string()).or_default() += 1;
    }
    // The control row always runs, first.
    let mut faults = vec![Fault::None];
    faults.extend(o.faults.iter().copied().filter(|f| *f != Fault::None));
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for fault in faults {
        let mut row = Row {
            name: fault.name().to_string(),
            description: fault.describe(),
            aimed: fault.aimed(),
            open_error: None,
            responses: 0,
            faulted: 0,
            flagged: false,
            total: Counts::default(),
            reasons: BTreeMap::new(),
            modes: BTreeMap::new(),
        };
        for baseline in o.mode.each() {
            let mode = workload::mode_label(baseline);
            let seed = fault.seed(o.seed, mode);
            let driver = FaultDriver::new(
                DirDriver::new(bucket),
                fault,
                o.rate,
                geometry.clone(),
                seed,
            );
            let handle = driver.handle();
            let mut mr = ModeRow::default();
            match Snapshot::open(driver, None, slice.head.state_root) {
                Ok(mut snap) => {
                    snap.hint = Hint::symmetric(1);
                    snap.top_levels = o.top_levels;
                    read_all(
                        &mut snap,
                        &handle,
                        fault,
                        o,
                        plan,
                        &routes,
                        slice,
                        baseline,
                        &mut mr,
                        &mut failures,
                    );
                }
                Err(e) => {
                    row.open_error.get_or_insert(e.clone());
                    mr.open_error = Some(e);
                }
            }
            (mr.responses, mr.faulted) = handle.stats();
            row.responses += mr.responses;
            row.faulted += mr.faulted;
            row.total.merge(&mr.total);
            for (k, n) in &mr.reasons {
                *row.reasons.entry(k.clone()).or_default() += n;
            }
            row.modes.insert(mode, mr);
        }
        row.flagged = fault.fires() && row.faulted == 0;
        rows.push(row);
    }
    let control_correct = rows.first().is_some_and(|r| {
        r.open_error.is_none() && r.total.reads > 0 && r.total.correct == r.total.reads
    });
    let pass = control_correct && rows.iter().all(Row::pass);
    let flagged = rows
        .iter()
        .filter(|r| r.flagged)
        .map(|r| r.name.clone())
        .collect();
    Ok(Table {
        block_number: slice.head.block_number,
        state_root: slice.head.state_root,
        prefix: slice.head.prefix.clone(),
        keys: o.keys,
        rate: o.rate,
        seed: o.seed,
        mode: o.mode.name(),
        top_levels: o.top_levels,
        bloom: "this format has no Bloom filter (pages route by chained fences and the learned model); nothing to zero",
        plan: plan.meta.clone(),
        shapes,
        pass,
        control_correct,
        flagged,
        faults: rows,
        failures,
    })
}

/// A draw's shape for the table: its first series (the read's kind).
fn shape(d: &Draw) -> &str {
    d.series.first().map_or("unknown", String::as_str)
}

/// Every draw of the plan through one faulted snapshot, aimed and scored.
#[allow(clippy::too_many_arguments)]
fn read_all<D: Driver>(
    snap: &mut Snapshot<D>,
    handle: &Handle,
    fault: Fault,
    o: &Options,
    plan: &Plan,
    routes: &[Route],
    slice: &Slice,
    baseline: bool,
    mr: &mut ModeRow,
    failures: &mut Vec<Failure>,
) {
    let mode = workload::mode_label(baseline);
    let mut aimer = Aimer::default();
    let mut rng = ChaCha8Rng::seed_from_u64(fault.seed(o.seed, mode) ^ 0x5eed);
    for (draw, route) in plan.draws.iter().zip(routes) {
        // The baseline changes only the trie walks; code is the same read.
        if baseline && matches!(draw.target, Target::Code(_)) {
            continue;
        }
        let mut aim = None;
        if fault.aimed() {
            let nodes = if baseline {
                &route.baseline
            } else {
                &route.path
            };
            aim = aimer.choose(nodes, fault);
            if o.rate < 1.0 && !rng.random_bool(o.rate) {
                aim = None;
                mr.spared += 1;
            } else if aim.is_none() {
                mr.untargeted += 1;
            }
        }
        handle.set_aim(aim);
        let (answer, cost) = workload::read_draw(snap, baseline, draw);
        if let Some(a) = &aim {
            if handle.take_hit() {
                *mr.coverage.entry(a.label()).or_default() += 1;
            } else {
                mr.untargeted += 1;
            }
        }
        let v = workload::score(draw, slice, &answer);
        let outside = matches!(draw.expect, Expect::Insufficient);
        let mismatches = if v == Verdict::Correct {
            workload::shape_mismatches(draw, &answer, &cost).len() as u64
        } else {
            0
        };
        mr.total.add(&v, outside, mismatches);
        mr.shapes
            .entry(shape(draw).to_string())
            .or_default()
            .add(&v, outside, mismatches);
        match &v {
            Verdict::Insufficient(r) if !(outside && matches!(r, Reason::Missing { .. })) => {
                *mr.reasons.entry(reason_key(r)).or_default() += 1;
                *mr.caught_after_nodes.entry(cost.nodes).or_default() += 1;
            }
            Verdict::Correct | Verdict::Insufficient(_) if mismatches == 0 => {}
            _ => failures.push(Failure {
                fault: fault.name().to_string(),
                mode,
                shape: shape(draw).to_string(),
                target: workload::target_json(&draw.target),
                aim: aim.map(|a| a.label()),
                got: if v == Verdict::Correct {
                    "right answer, walk not as the shape model predicts".into()
                } else {
                    format!("{v:?}")
                },
                expected: format!("{:?}", draw.expect),
            }),
        }
    }
}

pub fn run(args: Args) -> Result<Value, String> {
    let slice = Slice::read(&args.slice).map_err(|e| format!("slice: {e}"))?;
    let faults = if args.faults.is_empty() {
        Fault::ALL.to_vec()
    } else {
        args.faults
            .iter()
            .map(|s| {
                Fault::parse(s).ok_or_else(|| {
                    let names: Vec<&str> = Fault::ALL.iter().map(|f| f.name()).collect();
                    format!("unknown fault {s}; one of: {}", names.join(", "))
                })
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    let o = Options {
        keys: args.keys,
        rate: args.rate,
        seed: args.seed,
        mode: args.mode,
        top_levels: args.top_levels,
        faults,
    };
    let t = std::time::Instant::now();
    let table = run_table(&slice, &args.bucket, &o)?;
    let text = serde_json::to_string_pretty(&table).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, text).map_err(|e| format!("{}: {e}", args.out.display()))?;
    let summary: Vec<Value> = table
        .faults
        .iter()
        .map(|r| {
            let modes: BTreeMap<&str, Value> = r
                .modes
                .iter()
                .map(|(m, mr)| {
                    (
                        *m,
                        json!({
                            "open_error": mr.open_error,
                            "faulted": mr.faulted,
                            "reads": mr.total.reads,
                            "correct": mr.total.correct,
                            "insufficient": mr.total.insufficient,
                            "failures": mr.total.failures(),
                            "untargeted": mr.untargeted,
                            "coverage": mr.coverage,
                            "reasons": mr.reasons,
                        }),
                    )
                })
                .collect();
            json!({"fault": r.name, "flagged": r.flagged, "modes": modes})
        })
        .collect();
    let out = json!({
        "out": args.out,
        "pass": table.pass,
        "control_correct": table.control_correct,
        "flagged": table.flagged,
        "shapes": table.shapes,
        "wall_ms": t.elapsed().as_millis() as u64,
        "faults": summary,
        "failures": table.failures.len(),
    });
    if !table.pass {
        return Err(format!(
            "fault table failed (control row all correct: {}, {} failing reads); report at {}",
            table.control_correct,
            table.failures.len(),
            args.out.display()
        ));
    }
    Ok(out)
}
