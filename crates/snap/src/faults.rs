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
//! The format carries no Bloom filter (pages route by chained fences and
//! the learned model), so the spec's "zeroed Bloom" has nothing to zero;
//! the table says so.
//!
//! Scoring: a read is correct when it returns the slice's value or the
//! absence the slice implies; `Insufficient` is the acceptable failure;
//! a wrong value, an absence for a present key or a value for an absent
//! key fails the design. The `Reason` variants seen per fault say how the
//! client caught it: at the page (`Run`), at the trie (`Invalid`,
//! `Missing`) or at the hash of the bytes (`Code`, `Blob`).

use crate::Slice;
use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use clap::{Args as ClapArgs, ValueEnum};
use csl_eth_client::{DirDriver, Driver, Got, Hint, Read, Reason, Snapshot, Want};
use csl_eth_store::{manifest_path, table_path, Manifest, LATEST_FILE, RUN_FORMAT, TABLE_COUNT};
use csl_eth_trie::{path_of, Account, Nibbles, NodeKey};
use csl_run::{EntryLayout, Layout, Page, KEY_MAX, KEY_MIN, PAGE};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fmt,
    path::{Path, PathBuf},
    sync::Mutex,
};

/// Which client reads the keys: the path-keyed read, the content-addressed
/// baseline, or both.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Path,
    Baseline,
    Both,
}

impl Mode {
    /// The modes to run, as "is the baseline".
    fn each(self) -> Vec<bool> {
        match self {
            Mode::Path => vec![false],
            Mode::Baseline => vec![true],
            Mode::Both => vec![false, true],
        }
    }

    fn name(self) -> &'static str {
        match self {
            Mode::Path => "path",
            Mode::Baseline => "baseline",
            Mode::Both => "both",
        }
    }
}

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
    /// Keys per shape (present accounts, absent accounts, present slots,
    /// absent slots, code).
    #[arg(long, default_value_t = 200)]
    pub keys: usize,
    /// Fraction of the qualifying responses each fault touches.
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
    /// Run only these faults (repeatable); every fault when absent.
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
    TruncatedFile,
    TruncatedBlob,
    WrongRunPage,
    WrongRange,
    BitFlip,
    ModelPageTamper,
    Page0Tamper,
    ManifestStateRoot,
    ManifestModelRoot,
    ManifestTableRoot,
    MissingRange,
    HttpError,
    StaleValue,
    StalePage,
}

impl Fault {
    pub const ALL: [Fault; 21] = [
        Fault::None,
        Fault::NodeOmitted,
        Fault::PageMalformed,
        Fault::ForgedFence,
        Fault::FenceGap,
        Fault::FenceExcludes,
        Fault::TruncatedPage,
        Fault::TruncatedFile,
        Fault::TruncatedBlob,
        Fault::WrongRunPage,
        Fault::WrongRange,
        Fault::BitFlip,
        Fault::ModelPageTamper,
        Fault::Page0Tamper,
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
            Fault::TruncatedFile => "truncated_file",
            Fault::TruncatedBlob => "truncated_blob",
            Fault::WrongRunPage => "wrong_run_page",
            Fault::WrongRange => "wrong_range",
            Fault::BitFlip => "bit_flip",
            Fault::ModelPageTamper => "model_page_tamper",
            Fault::Page0Tamper => "page0_tamper",
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

    /// What the driver does to a qualifying response.
    pub fn describe(self) -> &'static str {
        match self {
            Fault::None => "control: responses pass through untouched",
            Fault::NodeOmitted => "data page re-encoded with one entry removed (the deepest node on the read's path when the page holds one, else a random entry); fences and count stay consistent, so the node is silently missing",
            Fault::PageMalformed => "data page re-encoded with one entry removed but the header's count left as it was: the offset table no longer matches",
            Fault::ForgedFence => "data page fences widened to [0^32, FF^32]: the page claims to cover every key, so a key the model predicts onto it is found absent from the page instead of on its neighbour",
            Fault::FenceGap => "data page fences narrowed to its first entry and the successor of its last: keys in the former gaps fall between pages, but every node a walk needs is an entry and stays covered, so this cannot misroute a read",
            Fault::FenceExcludes => "data page upper fence lowered onto its last entry, so a key the page holds is outside its fences; the page's own validation rejects it",
            Fault::TruncatedPage => "data range answered with half the bytes asked",
            Fault::TruncatedFile => "every whole-file want (latest, manifest, blobs) answered with its first half",
            Fault::TruncatedBlob => "blob files answered with their first half",
            Fault::WrongRunPage => "data range of a table answered with the same range of another table (account_nodes from storage_nodes and back, code from nodes_by_hash and back)",
            Fault::WrongRange => "data range answered from one page further into the same file",
            Fault::BitFlip => "one random bit flipped in each data range response",
            Fault::ModelPageTamper => "one random bit flipped in each model page record",
            Fault::Page0Tamper => "one random bit flipped in page 0 (header and top model)",
            Fault::ManifestStateRoot => "manifest state_root altered",
            Fault::ManifestModelRoot => "every table's model_root in the manifest altered",
            Fault::ManifestTableRoot => "every table's root (blake3 of the run file) in the manifest altered; the client never checks it, the trie proves values",
            Fault::MissingRange => "range wants answered Ok(None): the host says the file is not there",
            Fault::HttpError => "range wants answered Err(500)",
            Fault::StaleValue => "one entry's value bytes altered in place on each data page (the deepest node on the read's path when the page holds one, else a random entry)",
            Fault::StalePage => "every entry's value bytes altered in place on each data page",
        }
    }

    fn qualifies(self, k: &Kind) -> bool {
        match self {
            Fault::None => false,
            Fault::NodeOmitted
            | Fault::PageMalformed
            | Fault::ForgedFence
            | Fault::FenceGap
            | Fault::FenceExcludes
            | Fault::TruncatedPage
            | Fault::WrongRunPage
            | Fault::WrongRange
            | Fault::BitFlip
            | Fault::StaleValue
            | Fault::StalePage => matches!(k, Kind::Data(_)),
            Fault::TruncatedFile => {
                matches!(k, Kind::Latest | Kind::Manifest | Kind::Blob | Kind::File)
            }
            Fault::TruncatedBlob => matches!(k, Kind::Blob),
            Fault::ModelPageTamper => matches!(k, Kind::Model(_)),
            Fault::Page0Tamper => matches!(k, Kind::Page0(_)),
            Fault::ManifestStateRoot | Fault::ManifestModelRoot | Fault::ManifestTableRoot => {
                matches!(k, Kind::Manifest)
            }
            Fault::MissingRange | Fault::HttpError => {
                matches!(
                    k,
                    Kind::Page0(_) | Kind::Data(_) | Kind::Model(_) | Kind::Range
                )
            }
        }
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

struct State {
    rng: ChaCha8Rng,
    /// Table keys of the nodes the current read walks, deepest first:
    /// rank 0 is the leaf's position. A page-level fault that must hit the
    /// path picks the lowest-ranked entry it finds.
    focus: HashMap<[u8; 32], usize>,
    responses: u64,
    faulted: u64,
}

/// A host that answers from a clean driver and lies as one [`Fault`] says.
pub struct FaultDriver<D> {
    inner: D,
    fault: Fault,
    rate: f64,
    geometry: Geometry,
    state: Mutex<State>,
}

/// What `edit_pages` does with a decoded page after the closure ran.
enum Edit {
    Keep,
    Reencode,
    /// Re-encode, then write this entry count into the header: the page's
    /// shape no longer matches its own count.
    ReencodeWithCount(u16),
}

impl<D: Driver> FaultDriver<D> {
    pub fn new(inner: D, fault: Fault, rate: f64, geometry: Geometry, seed: u64) -> FaultDriver<D> {
        FaultDriver {
            inner,
            fault,
            rate: rate.clamp(0.0, 1.0),
            geometry,
            state: Mutex::new(State {
                rng: ChaCha8Rng::seed_from_u64(seed),
                focus: HashMap::new(),
                responses: 0,
                faulted: 0,
            }),
        }
    }

    /// The nodes the next read walks, deepest first, so an omitted or
    /// stale entry lands on the path rather than anywhere on the page.
    pub fn set_focus(&self, keys: &[[u8; 32]]) {
        let mut st = self.state.lock().unwrap();
        st.focus = keys.iter().enumerate().map(|(i, k)| (*k, i)).collect();
    }

    /// Responses seen and responses the fault changed.
    pub fn stats(&self) -> (u64, u64) {
        let st = self.state.lock().unwrap();
        (st.responses, st.faulted)
    }

    fn apply(&self, w: &Want, got: Got) -> Got {
        let kind = self.geometry.classify(w);
        let mut st = self.state.lock().unwrap();
        st.responses += 1;
        if !self.fault.qualifies(&kind) {
            return got;
        }
        if self.rate < 1.0 && !st.rng.random_bool(self.rate) {
            return got;
        }
        let st = &mut *st;
        let out = match (&kind, w) {
            (Kind::Data(i), Want::Range { rel, off, len }) => {
                let g = &self.geometry.tables[*i];
                self.data_fault(st, g, rel, *off, *len, got.clone())
            }
            (Kind::Model(_) | Kind::Page0(_), Want::Range { .. }) => match self.fault {
                Fault::MissingRange | Fault::HttpError => Some(self.refusal()),
                _ => got.clone().ok().flatten().map(|mut v| {
                    flip_bit(&mut st.rng, &mut v);
                    Ok(Some(v))
                }),
            },
            (Kind::Range, Want::Range { .. }) => Some(self.refusal()),
            (Kind::Manifest, Want::File { .. }) => match self.fault {
                Fault::TruncatedFile => truncate(got.clone()),
                _ => got
                    .clone()
                    .ok()
                    .flatten()
                    .and_then(|v| self.manifest_fault(v)),
            },
            (Kind::Latest | Kind::Blob | Kind::File, Want::File { .. }) => truncate(got.clone()),
            _ => None,
        };
        match out {
            Some(g) => {
                st.faulted += 1;
                g
            }
            None => got,
        }
    }

    /// The host is down for this want: not there, or a server error.
    fn refusal(&self) -> Got {
        match self.fault {
            Fault::HttpError => Err("500 internal server error".to_string()),
            _ => Ok(None),
        }
    }

    fn data_fault(
        &self,
        st: &mut State,
        g: &TableGeom,
        rel: &str,
        off: u64,
        len: usize,
        got: Got,
    ) -> Option<Got> {
        match self.fault {
            Fault::MissingRange | Fault::HttpError => return Some(self.refusal()),
            Fault::WrongRunPage => {
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
                let w = Want::Range {
                    rel: rel.to_string(),
                    off: off + PAGE as u64,
                    len,
                };
                return Some(self.inner.fetch(&[w]).remove(0));
            }
            Fault::TruncatedPage => return truncate(got),
            _ => {}
        }
        let mut bytes = got.ok().flatten()?;
        if self.fault == Fault::BitFlip {
            flip_bit(&mut st.rng, &mut bytes);
            return Some(Ok(Some(bytes)));
        }
        let fault = self.fault;
        let edited = edit_pages(&mut bytes, off, &g.layout, &mut |page| match fault {
            Fault::NodeOmitted => match pick(page, &st.focus, &mut st.rng, |_| true) {
                Some(i) => {
                    page.entries.remove(i);
                    Edit::Reencode
                }
                None => Edit::Keep,
            },
            Fault::PageMalformed => match pick(page, &st.focus, &mut st.rng, |_| true) {
                Some(i) => {
                    let n = page.entries.len() as u16;
                    page.entries.remove(i);
                    Edit::ReencodeWithCount(n)
                }
                None => Edit::Keep,
            },
            Fault::ForgedFence => {
                page.lo = KEY_MIN;
                page.hi = KEY_MAX;
                Edit::Reencode
            }
            Fault::FenceGap => {
                let (Some(first), Some(last)) = (page.entries.first(), page.entries.last()) else {
                    return Edit::Keep;
                };
                let lo = first.key;
                let hi = if page.hi == KEY_MAX {
                    KEY_MAX
                } else {
                    match succ(last.key) {
                        Some(h) => h,
                        None => return Edit::Keep,
                    }
                };
                if lo == page.lo && hi == page.hi {
                    return Edit::Keep;
                }
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
            Fault::StaleValue => {
                match pick(page, &st.focus, &mut st.rng, |e| {
                    e.tag == 0 && !e.value.is_empty()
                }) {
                    Some(i) => {
                        stale(&mut page.entries[i].value);
                        Edit::Reencode
                    }
                    None => Edit::Keep,
                }
            }
            Fault::StalePage => {
                let mut any = false;
                for e in page
                    .entries
                    .iter_mut()
                    .filter(|e| e.tag == 0 && !e.value.is_empty())
                {
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
        });
        (edited > 0).then_some(Ok(Some(bytes)))
    }

    /// The manifest with one field forged. `state_root` is what the client
    /// compares to the root it verified; `model_root` is what page 0 must
    /// hash to; `root` is the run file's identity, which nothing checks.
    fn manifest_fault(&self, bytes: Vec<u8>) -> Option<Got> {
        let mut m: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
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

/// Decode every whole data page in a range response, let `f` edit it, and
/// write the canonical re-encoding back. Pages that do not decode (the
/// range ran into the model section, or an earlier fault) are left alone.
/// Returns how many pages changed.
fn edit_pages(
    bytes: &mut [u8],
    off: u64,
    l: &Layout,
    f: &mut dyn FnMut(&mut Page) -> Edit,
) -> usize {
    if !off.is_multiple_of(PAGE as u64) {
        return 0;
    }
    let mut edited = 0;
    for i in 0..bytes.len() / PAGE {
        let page_off = off + (i * PAGE) as u64;
        if page_off < PAGE as u64 || page_off >= l.model_off {
            continue;
        }
        let page_no = page_off / PAGE as u64;
        let last = page_no == l.page_count;
        let slot = &mut bytes[i * PAGE..(i + 1) * PAGE];
        let Ok(mut page) = Page::decode_with(slot, EntryLayout::Variable, last, page_no) else {
            continue;
        };
        let count = match f(&mut page) {
            Edit::Keep => continue,
            Edit::Reencode => None,
            Edit::ReencodeWithCount(n) => Some(n),
        };
        slot.copy_from_slice(&page.encode_with(EntryLayout::Variable));
        if let Some(n) = count {
            slot[0..2].copy_from_slice(&n.to_le_bytes());
        }
        edited += 1;
    }
    edited
}

/// The entry a page-level fault aims at: the one on the read's path
/// nearest the leaf when the page holds any, else a random one.
fn pick(
    page: &Page,
    focus: &HashMap<[u8; 32], usize>,
    rng: &mut ChaCha8Rng,
    ok: impl Fn(&csl_run::Entry) -> bool,
) -> Option<usize> {
    let candidates: Vec<usize> = page
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| ok(e))
        .map(|(i, _)| i)
        .collect();
    if candidates.is_empty() {
        return None;
    }
    candidates
        .iter()
        .copied()
        .filter_map(|i| focus.get(&page.entries[i].key).map(|rank| (*rank, i)))
        .min()
        .map(|(_, i)| i)
        .or_else(|| Some(candidates[rng.random_range(0..candidates.len())]))
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

fn truncate(got: Got) -> Option<Got> {
    let mut v = got.ok().flatten()?;
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
fn forge_hex(v: &mut serde_json::Value) {
    if let Some(s) = v.as_str() {
        let mut s = s.to_string();
        let last = s.pop().unwrap_or('0');
        s.push(if last == 'a' { 'b' } else { 'a' });
        *v = serde_json::Value::String(s);
    }
}

/// The reads of one fault row: every shape, drawn once from the slice and
/// read under every fault.
enum Probe {
    /// `Some`: a present account; `None`: absent inside the prefix.
    Account {
        hashed: B256,
        expect: Option<Account>,
    },
    /// Outside the covered prefix: `Insufficient` is the only right answer.
    Outside {
        hashed: B256,
    },
    /// `Some`: a present slot; `None`: absent (the account may have no
    /// storage at all, see `shape`).
    Slot {
        owner: B256,
        slot: B256,
        expect: Option<U256>,
        empty_storage: bool,
    },
    Code {
        hash: B256,
        bytes: Vec<u8>,
    },
}

impl Probe {
    fn shape(&self) -> &'static str {
        match self {
            Probe::Account {
                expect: Some(_), ..
            } => "account_present",
            Probe::Account { expect: None, .. } => "account_absent",
            Probe::Outside { .. } => "account_outside",
            Probe::Slot {
                expect: Some(_), ..
            } => "slot_present",
            Probe::Slot {
                empty_storage: true,
                ..
            } => "slot_empty_storage",
            Probe::Slot { .. } => "slot_absent",
            Probe::Code { .. } => "code",
        }
    }

    /// Table keys of the nodes this read walks, deepest first.
    fn focus(&self) -> Vec<[u8; 32]> {
        fn account_keys(h: &B256) -> Vec<[u8; 32]> {
            let p = path_of(h);
            (0..=csl_eth_trie::MAX_DEPTH)
                .rev()
                .map(|d| NodeKey::prefix(&p, d).table_key().expect("depth ≤ 62"))
                .collect()
        }
        match self {
            Probe::Account { hashed, .. } | Probe::Outside { hashed } => account_keys(hashed),
            Probe::Slot { owner, slot, .. } => {
                let p = path_of(slot);
                let mut keys: Vec<[u8; 32]> = (0..=csl_eth_trie::MAX_DEPTH)
                    .rev()
                    .map(|d| {
                        NodeKey::prefix(&p, d)
                            .storage_table_key(owner)
                            .expect("depth ≤ 62")
                    })
                    .collect();
                keys.extend(account_keys(owner));
                keys
            }
            Probe::Code { hash, .. } => vec![hash.0],
        }
    }

    fn key(&self) -> B256 {
        match self {
            Probe::Account { hashed, .. } | Probe::Outside { hashed } => *hashed,
            Probe::Slot { owner, .. } => *owner,
            Probe::Code { hash, .. } => *hash,
        }
    }

    fn slot(&self) -> Option<B256> {
        match self {
            Probe::Slot { slot, .. } => Some(*slot),
            _ => None,
        }
    }

    fn expected(&self) -> String {
        match self {
            Probe::Account {
                expect: Some(a), ..
            } => format!("{a:?}"),
            Probe::Account { expect: None, .. } | Probe::Slot { expect: None, .. } => {
                "absent".into()
            }
            Probe::Outside { .. } => "insufficient".into(),
            Probe::Slot {
                expect: Some(v), ..
            } => format!("{v}"),
            Probe::Code { hash, .. } => format!("code {hash}"),
        }
    }
}

fn prefix_nibbles(s: &str) -> Nibbles {
    let n: Vec<u8> = s
        .trim_start_matches("0x")
        .chars()
        .map(|c| c.to_digit(16).expect("slice prefix is hex") as u8)
        .collect();
    Nibbles::from_nibbles(n)
}

/// A random key under the slice's prefix.
fn random_in_prefix(rng: &mut ChaCha8Rng, prefix: &Nibbles) -> B256 {
    let mut k = [0u8; 32];
    rng.fill_bytes(&mut k);
    for (i, n) in prefix.iter().enumerate() {
        let b = i / 2;
        k[b] = if i % 2 == 0 {
            (k[b] & 0x0f) | (n << 4)
        } else {
            (k[b] & 0xf0) | n
        };
    }
    B256::from(k)
}

/// Draw the probes: `n` per shape, strided over the slice so the same
/// seed and slice give the same table.
fn probes(s: &Slice, n: usize, seed: u64) -> Vec<Probe> {
    let n = n.max(1);
    let mut rng = ChaCha8Rng::seed_from_u64(seed ^ 0x9e37_79b9_7f4a_7c15);
    let prefix = prefix_nibbles(&s.head.prefix);
    let present = |k: &B256| s.accounts.binary_search_by(|(x, _)| x.cmp(k)).is_ok();
    let mut out = Vec::new();
    if s.accounts.is_empty() {
        return out;
    }
    let stride = (s.accounts.len() / n).max(1);

    // Present accounts, then absent keys under the prefix.
    for (h, a) in s.accounts.iter().step_by(stride).take(n) {
        out.push(Probe::Account {
            hashed: *h,
            expect: Some(*a),
        });
    }
    let mut absent = 0;
    while absent < n {
        let k = random_in_prefix(&mut rng, &prefix);
        if !present(&k) {
            out.push(Probe::Account {
                hashed: k,
                expect: None,
            });
            absent += 1;
        }
    }
    // Outside the prefix: the first nibble flipped. None when the slice is
    // the whole trie.
    if !prefix.is_empty() {
        for (h, _) in s.accounts.iter().step_by(stride).take(8) {
            let mut k = *h;
            k.0[0] ^= 0x10;
            if !path_of(&k).starts_with(&prefix) {
                out.push(Probe::Outside { hashed: k });
            }
        }
    }

    // Storage: the largest tries first (deep walks), then strided owners.
    let with_storage: Vec<(B256, &Vec<(B256, U256)>)> = s
        .accounts
        .iter()
        .filter_map(|(h, a)| {
            s.storage
                .get(&a.storage_root)
                .filter(|v| !v.is_empty())
                .map(|v| (*h, v))
        })
        .collect();
    if !with_storage.is_empty() {
        let mut by_size: Vec<usize> = (0..with_storage.len()).collect();
        by_size.sort_by_key(|&i| {
            (
                std::cmp::Reverse(with_storage[i].1.len()),
                with_storage[i].0,
            )
        });
        let mut slots = Vec::new();
        let big = (n / 8).max(1);
        for &i in by_size.iter().take(4) {
            let (owner, v) = &with_storage[i];
            for (k, val) in v.iter().step_by((v.len() / big).max(1)).take(big) {
                slots.push((*owner, *k, *val));
            }
        }
        let sstride = (with_storage.len() / n).max(1);
        let mut i = 0usize;
        while slots.len() < n && i <= 4 * n {
            let (owner, v) = &with_storage[(i * sstride) % with_storage.len()];
            let (k, val) = v[(i * 7) % v.len()];
            slots.push((*owner, k, val));
            i += 1;
        }
        for (owner, slot, val) in slots {
            out.push(Probe::Slot {
                owner,
                slot,
                expect: Some(val),
                empty_storage: false,
            });
        }
        for (owner, v) in with_storage.iter().step_by(sstride).take(n) {
            let slot = loop {
                let mut k = [0u8; 32];
                rng.fill_bytes(&mut k);
                let k = B256::from(k);
                if v.binary_search_by(|(x, _)| x.cmp(&k)).is_err() {
                    break k;
                }
            };
            out.push(Probe::Slot {
                owner: *owner,
                slot,
                expect: None,
                empty_storage: false,
            });
        }
    }
    let empties: Vec<B256> = s
        .accounts
        .iter()
        .filter(|(_, a)| a.storage_root == EMPTY_ROOT_HASH)
        .map(|(h, _)| *h)
        .collect();
    if !empties.is_empty() {
        let m = (n / 10).max(1);
        for owner in empties.iter().step_by((empties.len() / m).max(1)).take(m) {
            let mut k = [0u8; 32];
            rng.fill_bytes(&mut k);
            out.push(Probe::Slot {
                owner: *owner,
                slot: B256::from(k),
                expect: None,
                empty_storage: true,
            });
        }
    }

    // Code of the slice's contracts across the size range: inline entries
    // and blobs both.
    let mut seen = HashSet::new();
    let mut codes: Vec<(usize, B256)> = s
        .accounts
        .iter()
        .filter(|(_, a)| a.code_hash != KECCAK_EMPTY && seen.insert(a.code_hash))
        .filter_map(|(_, a)| s.code.get(&a.code_hash).map(|c| (c.len(), a.code_hash)))
        .collect();
    codes.sort();
    for (_, h) in codes.iter().step_by((codes.len() / n).max(1)).take(n) {
        out.push(Probe::Code {
            hash: *h,
            bytes: s.code[h].clone(),
        });
    }
    out
}

/// How one read scored.
enum Verdict {
    Correct,
    Insufficient(Reason),
    WrongValue(String),
    FalseAbsent(String),
    FalsePresent(String),
    /// An outside-prefix key answered with a value or an absence: the
    /// trie proved it, so it is not a failure, but the slice cannot score
    /// it and the control row would not produce it.
    Unexpected(String),
}

fn judge<T: PartialEq + fmt::Debug>(r: Read<T>, expect: Option<&T>) -> Verdict {
    match (r, expect) {
        (Read::Insufficient(why), _) => Verdict::Insufficient(why),
        (Read::Verified(v), Some(e)) if v == *e => Verdict::Correct,
        (Read::Verified(v), Some(_)) => Verdict::WrongValue(format!("{v:?}")),
        (Read::Verified(v), None) => Verdict::FalsePresent(format!("{v:?}")),
        (Read::VerifiedAbsent(by), Some(_)) => Verdict::FalseAbsent(format!("{by:?}")),
        (Read::VerifiedAbsent(_), None) => Verdict::Correct,
    }
}

fn read_probe<D: Driver>(snap: &mut Snapshot<D>, baseline: bool, p: &Probe) -> Verdict {
    match p {
        Probe::Account { hashed, expect } => {
            let (r, _) = if baseline {
                snap.account_by_hash(hashed)
            } else {
                snap.account(hashed)
            };
            judge(r, expect.as_ref())
        }
        Probe::Outside { hashed } => {
            let (r, _) = if baseline {
                snap.account_by_hash(hashed)
            } else {
                snap.account(hashed)
            };
            match r {
                Read::Insufficient(_) => Verdict::Correct,
                Read::Verified(a) => Verdict::Unexpected(format!("verified {a:?}")),
                Read::VerifiedAbsent(by) => Verdict::Unexpected(format!("absent {by:?}")),
            }
        }
        Probe::Slot {
            owner,
            slot,
            expect,
            ..
        } => {
            let (r, _) = if baseline {
                snap.storage_by_hash(owner, slot)
            } else {
                snap.storage(owner, slot)
            };
            judge(r, expect.as_ref())
        }
        Probe::Code { hash, bytes } => {
            let (r, _) = snap.code(hash);
            if let Read::Verified(b) = &r {
                if keccak256(b) != *hash {
                    return Verdict::WrongValue(format!(
                        "{} bytes not hashing to codeHash",
                        b.len()
                    ));
                }
            }
            judge(r, Some(bytes))
        }
    }
}

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
    pub unexpected: u64,
}

impl Counts {
    fn add(&mut self, v: &Verdict) {
        self.reads += 1;
        match v {
            Verdict::Correct => self.correct += 1,
            Verdict::Insufficient(_) => self.insufficient += 1,
            Verdict::WrongValue(_) => self.wrong_value += 1,
            Verdict::FalseAbsent(_) => self.false_absent += 1,
            Verdict::FalsePresent(_) => self.false_present += 1,
            Verdict::Unexpected(_) => self.unexpected += 1,
        }
    }

    /// Reads that fail the design.
    pub fn failures(&self) -> u64 {
        self.wrong_value + self.false_absent + self.false_present
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Failure {
    pub fault: String,
    pub mode: &'static str,
    pub shape: &'static str,
    pub key: B256,
    pub slot: Option<B256>,
    pub got: String,
    pub expected: String,
}

/// One fault's row.
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub name: String,
    pub description: &'static str,
    /// The open refused (a manifest fault): no reads were made.
    pub open_error: Option<String>,
    /// Responses the driver saw and responses the fault changed, summed
    /// over the modes run.
    pub responses: u64,
    pub faulted: u64,
    pub total: Counts,
    /// `Reason` classes seen, with counts: how the fault was caught.
    pub reasons: BTreeMap<String, u64>,
    /// mode → shape → counts.
    pub modes: BTreeMap<&'static str, BTreeMap<&'static str, Counts>>,
}

impl Row {
    pub fn pass(&self) -> bool {
        self.total.failures() == 0
    }

    pub fn counts(&self, mode: &str, shape: &str) -> Option<&Counts> {
        self.modes.get(mode)?.get(shape)
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
    /// Probes per shape.
    pub shapes: BTreeMap<&'static str, usize>,
    /// No wrong value, no false absence, no false presence in any row.
    pub pass: bool,
    pub faults: Vec<Row>,
    /// Every failing or unexpected read, in full (empty when `pass` and
    /// nothing was unexpected).
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

/// The table: every fault in `o.faults` applied to `bucket`'s responses,
/// the probes drawn from `slice` read under each, scored. Each fault and
/// mode gets its own snapshot over its own driver, so nothing one fault
/// verified (a kept model page, a cached top level) serves the next.
pub fn run_table(slice: &Slice, bucket: &Path, o: &Options) -> Result<Table, String> {
    let clean = Snapshot::open(DirDriver::new(bucket), None, slice.head.state_root)?;
    let geometry = Geometry::of(clean.manifest())?;
    drop(clean);
    let probes = probes(slice, o.keys, o.seed);
    let mut shapes: BTreeMap<&'static str, usize> = BTreeMap::new();
    for p in &probes {
        *shapes.entry(p.shape()).or_default() += 1;
    }
    let mut rows = Vec::new();
    let mut failures = Vec::new();
    for (fi, fault) in o.faults.iter().copied().enumerate() {
        let mut row = Row {
            name: fault.name().to_string(),
            description: fault.describe(),
            open_error: None,
            responses: 0,
            faulted: 0,
            total: Counts::default(),
            reasons: BTreeMap::new(),
            modes: BTreeMap::new(),
        };
        for (mi, baseline) in o.mode.each().into_iter().enumerate() {
            let mode = if baseline { "baseline" } else { "path" };
            let seed = o.seed ^ ((fi as u64 + 1) << 32) ^ ((mi as u64 + 1) << 48);
            let driver = FaultDriver::new(
                DirDriver::new(bucket),
                fault,
                o.rate,
                geometry.clone(),
                seed,
            );
            let mut snap = match Snapshot::open(driver, None, slice.head.state_root) {
                Ok(s) => s,
                Err(e) => {
                    row.open_error = Some(e);
                    continue;
                }
            };
            snap.hint = Hint::symmetric(1);
            snap.top_levels = o.top_levels;
            let per_shape = row.modes.entry(mode).or_default();
            for p in &probes {
                if baseline && matches!(p, Probe::Code { .. }) {
                    continue;
                }
                snap.driver().set_focus(&p.focus());
                let v = read_probe(&mut snap, baseline, p);
                per_shape.entry(p.shape()).or_default().add(&v);
                row.total.add(&v);
                match &v {
                    Verdict::Insufficient(r) if !matches!(p, Probe::Outside { .. }) => {
                        *row.reasons.entry(reason_key(r)).or_default() += 1;
                    }
                    Verdict::WrongValue(g)
                    | Verdict::FalseAbsent(g)
                    | Verdict::FalsePresent(g)
                    | Verdict::Unexpected(g) => {
                        failures.push(Failure {
                            fault: fault.name().to_string(),
                            mode,
                            shape: p.shape(),
                            key: p.key(),
                            slot: p.slot(),
                            got: g.clone(),
                            expected: p.expected(),
                        });
                    }
                    _ => {}
                }
            }
            let (responses, faulted) = snap.driver().stats();
            row.responses += responses;
            row.faulted += faulted;
        }
        rows.push(row);
    }
    let pass = rows.iter().all(Row::pass);
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
        shapes,
        pass,
        faults: rows,
        failures,
    })
}

pub fn run(args: Args) -> Result<serde_json::Value, String> {
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
    let json = serde_json::to_string_pretty(&table).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, json).map_err(|e| format!("{}: {e}", args.out.display()))?;
    let summary: Vec<serde_json::Value> = table
        .faults
        .iter()
        .map(|r| {
            serde_json::json!({
                "fault": r.name,
                "open_error": r.open_error,
                "faulted": r.faulted,
                "reads": r.total.reads,
                "correct": r.total.correct,
                "insufficient": r.total.insufficient,
                "failures": r.total.failures(),
                "unexpected": r.total.unexpected,
                "reasons": r.reasons,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "out": args.out,
        "pass": table.pass,
        "shapes": table.shapes,
        "wall_ms": t.elapsed().as_millis() as u64,
        "faults": summary,
        "failures": table.failures.len(),
    }))
}
