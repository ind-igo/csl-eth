//! The paged model section (core §4.1). A whole model at ε = 1 is about
//! half a byte per page of the run, which at Ethereum's size is tens of
//! megabytes per table that a following client cannot refetch every
//! snapshot. A paged run instead splits the segments into 4096-byte
//! **model pages**, commits to them with the same `bmt` tree the fixed
//! layout uses for its pages, and puts a **top model** on page 0 that
//! predicts which model page a key's segment is on. The client reads page
//! 0 once per snapshot and then one model page per key neighbourhood, and
//! `model_root` is `blake3` of page 0, which carries the tree root.
//!
//! ```text
//! page 0:     RunHeader ‖ model_pages: u32 ‖ epsilon_top: u16 ‖ tree_root: [u8; 32] ‖ Model (the top) ‖ zeros
//! model page: n: u16 ‖ lo: u64 ‖ hi: u64 ‖ next_intercept: i64 ‖ Segment[n] ‖ zeros to 4096
//! record:     model page ‖ bmt siblings (32 × depth(model_pages), zero-padded)
//! ```
//!
//! Model pages hold `MODEL_PAGE_SEGMENTS` segments each except the last,
//! in key order, and their fences chain in `k64` space exactly as data
//! pages do in key space: `lo(1) = 0`, `hi(i) = lo(i + 1)` = the first
//! `key_start` on page `i + 1`, `hi(last) = 2^64 − 1` inclusive. A page
//! that does not cover a key says which side the key is on, so the top
//! model's prediction is walked and searched like a data page's (core
//! §10). `next_intercept` is the first intercept of the next page (the
//! run's `page_count` on the last), so the cap of core §4 applies to a
//! page's last segment as it would in the whole model.

use crate::{tree::Digest, Error, RunHeader, DIGEST, PAGE};
use pgm::{Group, Model, Segment};

/// `n: u16 ‖ lo: u64 ‖ hi: u64 ‖ next_intercept: i64`.
pub const MODEL_PAGE_HEADER: usize = 26;
pub const SEGMENT_BYTES: usize = 24;
/// Segments per model page, every page but the last: 169.
pub const MODEL_PAGE_SEGMENTS: usize = (PAGE - MODEL_PAGE_HEADER) / SEGMENT_BYTES;
/// Where page 0's top section starts: right after the advisory header.
pub const TOP_OFF: usize = RunHeader::LEN;
/// Segments the top model may have: what fits page 0 after the header,
/// the page count, `epsilon_top`, the tree root and the segment count: 166.
pub const TOP_MAX_SEGMENTS: usize = (PAGE - TOP_OFF - 4 - 2 - DIGEST - 4) / SEGMENT_BYTES;

/// One page of segments with its fences in `k64` space.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelPage {
    pub lo: u64,
    /// Exclusive, except on the last page where it is `u64::MAX` inclusive.
    pub hi: u64,
    /// The next page's first intercept; `page_count` on the last page.
    pub next_intercept: i64,
    pub segments: Vec<Segment>,
}

impl ModelPage {
    pub fn covers(&self, k: u64, last: bool) -> bool {
        self.lo <= k && (k < self.hi || last)
    }

    pub fn encode(&self) -> [u8; PAGE] {
        assert!(!self.segments.is_empty() && self.segments.len() <= MODEL_PAGE_SEGMENTS);
        let mut out = [0u8; PAGE];
        out[0..2].copy_from_slice(&(self.segments.len() as u16).to_le_bytes());
        out[2..10].copy_from_slice(&self.lo.to_le_bytes());
        out[10..18].copy_from_slice(&self.hi.to_le_bytes());
        out[18..26].copy_from_slice(&self.next_intercept.to_le_bytes());
        let mut o = MODEL_PAGE_HEADER;
        for s in &self.segments {
            out[o..o + 8].copy_from_slice(&s.key_start.to_le_bytes());
            out[o + 8..o + 16].copy_from_slice(&s.intercept.to_le_bytes());
            out[o + 16..o + 24].copy_from_slice(&s.slope.to_le_bytes());
            o += SEGMENT_BYTES;
        }
        out
    }

    /// Decode model page `index` (1-based) of a run of `page_count` pages,
    /// checking its shape: a segment count in `1..=MODEL_PAGE_SEGMENTS`,
    /// fences in order and chained from zero on the first page to
    /// `u64::MAX` on the last, segments strictly increasing and inside the
    /// fences, every intercept a page of the run, zero padding.
    pub fn decode(bytes: &[u8], page_count: u64, index: u64, last: bool) -> Result<ModelPage, Error> {
        let bad = |what: &'static str| Error::MalformedPage { page: index, what };
        if bytes.len() != PAGE {
            return Err(bad("model page is not 4096 bytes"));
        }
        let n = u16::from_le_bytes(bytes[0..2].try_into().unwrap()) as usize;
        if n == 0 || n > MODEL_PAGE_SEGMENTS {
            return Err(bad("segment count"));
        }
        let lo = u64::from_le_bytes(bytes[2..10].try_into().unwrap());
        let hi = u64::from_le_bytes(bytes[10..18].try_into().unwrap());
        let next_intercept = i64::from_le_bytes(bytes[18..26].try_into().unwrap());
        if index == 1 && lo != 0 {
            return Err(bad("first model page does not start at zero"));
        }
        if last {
            if hi != u64::MAX {
                return Err(bad("last model page does not end at the key maximum"));
            }
        } else if hi <= lo {
            return Err(bad("model page fences out of order"));
        }
        if next_intercept < 1 || next_intercept as u64 > page_count {
            return Err(bad("next intercept is not a page"));
        }
        let mut segments = Vec::with_capacity(n);
        let mut o = MODEL_PAGE_HEADER;
        let mut prev: Option<u64> = None;
        for _ in 0..n {
            let key_start = u64::from_le_bytes(bytes[o..o + 8].try_into().unwrap());
            let intercept = i64::from_le_bytes(bytes[o + 8..o + 16].try_into().unwrap());
            let slope = u64::from_le_bytes(bytes[o + 16..o + 24].try_into().unwrap());
            o += SEGMENT_BYTES;
            match prev {
                None if key_start < lo => return Err(bad("segment below the lower fence")),
                Some(p) if key_start <= p => return Err(bad("segments unsorted")),
                _ => {}
            }
            if !last && key_start >= hi {
                return Err(bad("segment beyond the upper fence"));
            }
            if intercept < 1 || intercept as u64 > page_count {
                return Err(bad("intercept is not a page"));
            }
            prev = Some(key_start);
            segments.push(Segment { key_start, intercept, slope });
        }
        if bytes[o..].iter().any(|b| *b != 0) {
            return Err(bad("padding not zero"));
        }
        Ok(ModelPage { lo, hi, next_intercept, segments })
    }

    /// The model that routes the keys this page covers: its segments and
    /// a sentinel at `hi` carrying `next_intercept`, so the last real
    /// segment is capped as core §4 caps every segment but the model's
    /// last. For keys in `[lo, hi)` the sentinel is never selected; on the
    /// last page the key `u64::MAX` selects it and gets `page_count`,
    /// which is its page.
    pub fn routing(&self, page_count: u64, epsilon: u16) -> Model {
        let mut segments = self.segments.clone();
        segments.push(Segment {
            key_start: self.hi,
            intercept: self.next_intercept,
            slope: 0,
        });
        Model { page_count, epsilon, segments }
    }
}

/// Split a whole model into pages of `MODEL_PAGE_SEGMENTS`, the last
/// taking the remainder. Canonical: two writers with one model agree.
pub fn split(model: &Model) -> Vec<ModelPage> {
    let chunks: Vec<&[Segment]> = model.segments.chunks(MODEL_PAGE_SEGMENTS).collect();
    chunks
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let lo = if i == 0 { 0 } else { c[0].key_start };
            let (hi, next_intercept) = match chunks.get(i + 1) {
                Some(next) => (next[0].key_start, next[0].intercept),
                None => (u64::MAX, model.page_count as i64),
            };
            ModelPage {
                lo,
                hi,
                next_intercept,
                segments: c.to_vec(),
            }
        })
        .collect()
}

/// Fit the top model over the pages' segment starts: group `key_start → its
/// model page`, `ε_top = epsilon` doubled until the model fits page 0.
/// `Layout` if it does not fit at `ε_top = 2^15`; verify-on-build included.
pub fn fit_top(pages: &[ModelPage], epsilon: u16) -> Result<Model, Error> {
    let groups: Vec<Group> = pages
        .iter()
        .enumerate()
        .flat_map(|(i, p)| {
            let m = i as u64 + 1;
            p.segments.iter().map(move |s| Group { k64: s.key_start, p_min: m, p_max: m })
        })
        .collect();
    let mut eps = epsilon.max(1);
    loop {
        let m = pgm::fit(&groups, eps, pages.len() as u64)?;
        if m.segments.len() <= TOP_MAX_SEGMENTS {
            return Ok(m);
        }
        if eps > (1 << 14) {
            return Err(Error::Layout("top model does not fit page 0"));
        }
        eps *= 2;
    }
}

/// What page 0 of a paged run carries after the advisory header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Top {
    pub model_pages: u64,
    /// `bmt` root over the model pages' digests.
    pub tree_root: Digest,
    /// Predicts the model page (1-based) whose fences cover a `k64`: for
    /// every segment's `key_start` the prediction is within `epsilon_top`
    /// of its page, and for every other key within `epsilon_top + 1`. The
    /// writer starts at the run's `ε` and doubles until the top fits page
    /// 0, so `epsilon_top` is the model's own and is read from here.
    pub model: Model,
}

impl Top {
    /// Page 0: the header, then this. `Layout` if the top does not fit.
    pub fn encode_page(&self, header: &RunHeader) -> Result<[u8; PAGE], Error> {
        if self.model.segments.len() > TOP_MAX_SEGMENTS {
            return Err(Error::Layout("top model does not fit page 0"));
        }
        let mut out = header.encode_page();
        let mut o = TOP_OFF;
        out[o..o + 4].copy_from_slice(&(self.model_pages as u32).to_le_bytes());
        o += 4;
        out[o..o + 2].copy_from_slice(&self.model.epsilon.to_le_bytes());
        o += 2;
        out[o..o + DIGEST].copy_from_slice(&self.tree_root);
        o += DIGEST;
        let m = self.model.encode();
        out[o..o + m.len()].copy_from_slice(&m);
        Ok(out)
    }

    pub fn decode(page: &[u8]) -> Result<Top, Error> {
        let bad = |what: &'static str| Error::Decode(what);
        if page.len() != PAGE {
            return Err(bad("page 0 is not 4096 bytes"));
        }
        let mut o = TOP_OFF;
        let model_pages = u64::from(u32::from_le_bytes(page[o..o + 4].try_into().unwrap()));
        o += 4;
        if model_pages == 0 {
            return Err(bad("no model pages"));
        }
        let epsilon = u16::from_le_bytes(page[o..o + 2].try_into().unwrap());
        o += 2;
        let tree_root: Digest = page[o..o + DIGEST].try_into().unwrap();
        o += DIGEST;
        let n = u32::from_le_bytes(page[o..o + 4].try_into().unwrap()) as usize;
        if n > TOP_MAX_SEGMENTS {
            return Err(bad("top model segment count"));
        }
        let end = o + 4 + n * SEGMENT_BYTES;
        let model = Model::decode(&page[o..end], model_pages, epsilon).map_err(|_| bad("top model"))?;
        if page[end..].iter().any(|b| *b != 0) {
            return Err(bad("page 0 padding not zero"));
        }
        Ok(Top { model_pages, tree_root, model })
    }
}
