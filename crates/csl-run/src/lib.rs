//! Run files for the cold state layer, v1-min §2 and core §3: sorted pages
//! with chained fences, an optional `bmt` sibling proof stored after every
//! page, and the learned-index model section. Plus the manifest and
//! `ColdRoot` codecs of §3 and §5.
//!
//! Two formats share one writer and one reader. v1-min (cinder) is fixed
//! layout with inline proofs: a record is `page ‖ proof` and the run root is
//! the `bmt` root over page digests. The Ethereum profile is variable layout
//! with no proofs: a record is the page alone, nothing anchors a run root,
//! and a run's identity is `blake3` of its bytes. The reader verifies pages
//! against the run root only when the format has proofs; without them a
//! page is routing data and the profile's own verifier judges its contents.
//!
//! Either format may page its model (`Format::paged_model`, core §4.1):
//! the segments go into 4096-byte model pages under a `bmt` tree, and page
//! 0 carries a top model and the tree root, so a client reads one model
//! page per key neighbourhood instead of the whole section. `model_root`
//! is then `blake3` of page 0.
//!
//! The writer is canonical: two writers given the same sorted entries and
//! the same configuration produce identical bytes.

pub mod manifest;
pub mod model;
pub mod page;
pub mod reader;
pub mod tree;
pub mod writer;

pub use manifest::{ColdRoot, Manifest, RunRef};
pub use model::{ModelPage, Top, MODEL_PAGE_SEGMENTS, TOP_MAX_SEGMENTS};
pub use page::{Entry, Page, MAX_INLINE_VALUE};
pub use reader::{Lookup, Path, Reader, Source, Stats};
pub use writer::{write_all, write_all_with, Built, Writer};

use std::fmt;

/// Page size and section alignment.
pub const PAGE: usize = 4096;
pub const KEY: usize = 32;
pub const DIGEST: usize = 32;
/// Page header: `n: u16 ‖ lo[32] ‖ hi[32]`.
pub const PAGE_HEADER: usize = 66;
pub const FORMAT_VERSION: u32 = 1;

pub const KEY_MIN: [u8; 32] = [0u8; 32];
pub const KEY_MAX: [u8; 32] = [0xFFu8; 32];

/// Per-run configuration. Everything a writer needs besides the entries.
/// `value_size` is the fixed layout's; [`Config::format`] is v1-min's
/// format, and [`Writer::with_format`] takes another.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub profile_id: [u8; 32],
    pub table_id: u16,
    pub value_size: u32,
    pub epsilon: u16,
}

impl Config {
    /// v1-min: fixed layout of `value_size` bytes, inline proofs.
    pub const fn format(&self) -> Format {
        Format::fixed(self.value_size)
    }
}

/// How entries sit in a page, core §3.2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryLayout {
    /// `floor(4030 / (33 + value_size))` entries per page; tag 0 bodies are
    /// exactly `value_size` bytes.
    Fixed { value_size: u32 },
    /// An offset table, then entries packed greedily in key order while
    /// `66 + 2n + Σ bytes ≤ 4096`; tag 0 bodies are `len: u16 ‖ value`,
    /// tag 2 bodies a 32-byte blob hash.
    Variable,
}

/// What a run file carries besides its pages.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Format {
    pub layout: EntryLayout,
    /// v1-min: every record is `page ‖ bmt siblings` and the run root is
    /// the tree root. Without proofs a record is the page alone and the
    /// run's identity is `blake3` of the whole file (Ethereum profile §1).
    pub inline_proofs: bool,
    /// The model section is pages under a tree and page 0 is the top
    /// model (core §4.1, [`crate::model`]); `model_root` is `blake3` of
    /// page 0. Without, the section is one `Model` and `model_root` its
    /// `blake3`.
    pub paged_model: bool,
}

impl Format {
    pub const fn fixed(value_size: u32) -> Format {
        Format { layout: EntryLayout::Fixed { value_size }, inline_proofs: true, paged_model: false }
    }

    /// This format with the model paged.
    pub const fn paged(self) -> Format {
        Format { paged_model: true, ..self }
    }

    /// Variable layout, no proofs. The only variable format the writer
    /// streams: with proofs a record's size depends on the page count,
    /// which a variable run knows only at the end.
    pub const fn variable() -> Format {
        Format { layout: EntryLayout::Variable, inline_proofs: false, paged_model: false }
    }
}

/// Byte layout of a run file, computed from `page_count`, `model_bytes` and
/// whether records carry proofs, and never read from the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub page_count: u64,
    /// Sibling slots per inline proof; 0 without proofs.
    pub depth: usize,
    pub record_bytes: u64,
    pub model_off: u64,
    pub model_bytes: u64,
    pub total_len: u64,
    pub inline_proofs: bool,
}

impl Layout {
    /// The v1-min layout (inline proofs) for `page_count` pages and a
    /// `model_bytes`-byte model, with every offset computed in checked
    /// `u64` arithmetic. Rejects a `page_count` outside `[1, 2^31]`
    /// (v1-min §2) and any offset that would overflow, so it is safe on
    /// untrusted `RunRef` fields and on a 32-bit target.
    pub fn try_new(page_count: u64, model_bytes: u64) -> Result<Layout, Error> {
        Self::try_new_with(page_count, model_bytes, true)
    }

    /// As [`Layout::try_new`], with or without inline proofs.
    pub fn try_new_with(page_count: u64, model_bytes: u64, inline_proofs: bool) -> Result<Layout, Error> {
        if page_count == 0 || page_count > pgm::MAX_PAGES {
            return Err(Error::Layout("page_count outside [1, 2^31]"));
        }
        let depth = if inline_proofs { tree::depth(page_count) } else { 0 };
        let page = PAGE as u64;
        // depth ≤ 31, so this cannot overflow; checked anyway for symmetry.
        let record_bytes = (DIGEST as u64).checked_mul(depth as u64).and_then(|p| p.checked_add(page)).ok_or(Error::Layout("record size overflows"))?;
        let model_off = page_count
            .checked_mul(record_bytes)
            .and_then(|r| r.checked_add(page))
            .and_then(|x| checked_round_up(x, page))
            .ok_or(Error::Layout("model offset overflows u64"))?;
        let total_len = model_off.checked_add(model_bytes).and_then(|x| checked_round_up(x, page)).ok_or(Error::Layout("run length overflows u64"))?;
        Ok(Layout { page_count, depth, record_bytes, model_off, model_bytes, total_len, inline_proofs })
    }

    /// [`Layout::try_new`] for inputs the caller has already validated
    /// (the writer, or a `RunRef` checked against a profile).
    ///
    /// # Panics
    ///
    /// On a `page_count` outside `[1, 2^31]` or an offset overflow, with a
    /// message rather than a wrapped value. Untrusted input goes through
    /// `try_new`.
    pub fn new(page_count: u64, model_bytes: u64) -> Layout {
        match Self::try_new(page_count, model_bytes) {
            Ok(l) => l,
            Err(e) => panic!("Layout::new({page_count}, {model_bytes}): {e}"),
        }
    }

    /// Offset of record `i`, pages numbered from 1; `None` outside
    /// `1..=page_count`.
    pub fn checked_record_off(&self, i: u64) -> Option<u64> {
        if i == 0 || i > self.page_count {
            return None;
        }
        // (i − 1) · record_bytes < model_off, which try_new bounded.
        Some(PAGE as u64 + (i - 1) * self.record_bytes)
    }

    /// Offset of record `i`, pages numbered from 1.
    pub fn record_off(&self, i: u64) -> u64 {
        debug_assert!(i >= 1 && i <= self.page_count);
        PAGE as u64 + (i - 1) * self.record_bytes
    }

    pub fn proof_bytes(&self) -> usize {
        DIGEST * self.depth
    }
}

pub fn round_up(x: u64, to: u64) -> u64 {
    x.div_ceil(to) * to
}

/// `round_up` that returns `None` instead of overflowing.
pub fn checked_round_up(x: u64, to: u64) -> Option<u64> {
    x.div_ceil(to).checked_mul(to)
}

/// `k64`: the leading 8 key bytes, big-endian.
#[inline]
pub fn k64(key: &[u8; 32]) -> u64 {
    u64::from_be_bytes(key[..8].try_into().unwrap())
}

/// Advisory header on page 0, v1-min §2 / core §3.1. Clients never act on it.
/// It names no role: a base and a delta with the same entries are one file,
/// and only the manifest says which is which. In a paged-model run the
/// rest of page 0 is the [`Top`], which clients do act on, after checking
/// the page against `model_root`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RunHeader {
    pub format_version: u32,
    pub profile_id: [u8; 32],
    pub table_id: u16,
    pub page_count: u64,
    pub entry_count: u64,
    pub epsilon_pages: u16,
}

impl RunHeader {
    pub const LEN: usize = 4 + 32 + 2 + 8 + 8 + 2;

    pub fn encode_page(&self) -> [u8; PAGE] {
        let mut out = [0u8; PAGE];
        let mut o = 0;
        out[o..o + 4].copy_from_slice(&self.format_version.to_le_bytes());
        o += 4;
        out[o..o + 32].copy_from_slice(&self.profile_id);
        o += 32;
        out[o..o + 2].copy_from_slice(&self.table_id.to_le_bytes());
        o += 2;
        out[o..o + 8].copy_from_slice(&self.page_count.to_le_bytes());
        o += 8;
        out[o..o + 8].copy_from_slice(&self.entry_count.to_le_bytes());
        o += 8;
        out[o..o + 2].copy_from_slice(&self.epsilon_pages.to_le_bytes());
        out
    }

    pub fn decode(b: &[u8]) -> Option<RunHeader> {
        if b.len() < Self::LEN {
            return None;
        }
        Some(RunHeader {
            format_version: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            profile_id: b[4..36].try_into().unwrap(),
            table_id: u16::from_le_bytes(b[36..38].try_into().unwrap()),
            page_count: u64::from_le_bytes(b[38..46].try_into().unwrap()),
            entry_count: u64::from_le_bytes(b[46..54].try_into().unwrap()),
            epsilon_pages: u16::from_le_bytes(b[54..56].try_into().unwrap()),
        })
    }
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Entries out of order or duplicated.
    Unsorted {
        prev: [u8; 32],
        next: [u8; 32],
    },
    BadTag(u8),
    BadValueLen {
        expected: usize,
        got: usize,
    },
    /// Writer finished with a different number of entries than declared.
    CountMismatch {
        declared: u64,
        got: u64,
    },
    /// Model could not be fitted (unrepresentable prefix group) or failed verify-on-build.
    Fit(pgm::FitError),
    /// Page bytes do not hash to the committed digest, or the inline proof does not reach the root.
    ProofFailed {
        page: u64,
    },
    /// Model bytes do not hash to `model_root`, or do not decode; in a
    /// paged run, page 0 does not hash to it, a model page's proof does
    /// not reach the tree root it carries, or the section's size is not
    /// the page count's.
    ModelMismatch,
    /// A verified page is malformed: bad count, unsorted entries, keys outside fences, bad tag.
    MalformedPage {
        page: u64,
        what: &'static str,
    },
    /// Fences do not chain the way the format requires; the key fell into a gap.
    FenceGap,
    /// Short read from the source.
    ShortRead {
        off: u64,
        want: usize,
        got: usize,
    },
    Decode(&'static str),
    /// The `RunRef`'s page count or model size gives no valid layout.
    Layout(&'static str),
    /// A record index outside `1..=page_count`.
    PageOutOfRange {
        page: u64,
        page_count: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Unsorted { prev, next } => write!(f, "unsorted: {} then {}", hex::encode(prev), hex::encode(next)),
            Error::BadTag(t) => write!(f, "bad tag {t}"),
            Error::BadValueLen { expected, got } => {
                write!(f, "value length {got}, expected {expected}")
            }
            Error::CountMismatch { declared, got } => {
                write!(f, "declared {declared} entries, got {got}")
            }
            Error::Fit(e) => write!(f, "model: {e}"),
            Error::ProofFailed { page } => write!(f, "page {page}: proof failed"),
            Error::ModelMismatch => write!(f, "model section does not match model_root"),
            Error::MalformedPage { page, what } => write!(f, "page {page}: malformed: {what}"),
            Error::FenceGap => write!(f, "fences do not cover the key"),
            Error::ShortRead { off, want, got } => {
                write!(f, "short read at {off}: wanted {want}, got {got}")
            }
            Error::Decode(w) => write!(f, "decode: {w}"),
            Error::Layout(w) => write!(f, "layout: {w}"),
            Error::PageOutOfRange { page, page_count } => {
                write!(f, "page {page} outside 1..={page_count}")
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<pgm::FitError> for Error {
    fn from(e: pgm::FitError) -> Self {
        Error::Fit(e)
    }
}
