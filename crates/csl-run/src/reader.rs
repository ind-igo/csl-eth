//! Reader over a byte-range source. With inline proofs every page is checked
//! against the run root before its fences are trusted; without them a page
//! is routing data, parsed for shape only, and whatever the profile's own
//! verifier does with its entries is the client's business. `locate` is
//! core §10: model prediction, a walk of up to `ε + 1` pages in the direction
//! the fences indicate, then a binary search over the remaining pages.
//! Requests are counted by execution path.
//!
//! With a paged model (core §4.1) the prediction itself is a lookup: page 0
//! gives the top model and the tree root, the top predicts a model page,
//! that page is fetched, proved against the tree root and walked by its
//! `k64` fences like a data page, and its segments predict the data page.
//! Model pages are kept once verified, so a neighbourhood's second key
//! costs no model request.

use crate::model::{ModelPage, Top};
use crate::page::Page;
use crate::tree::{self, verify_inline};
use crate::{k64, Entry, Error, Format, Layout, RunRef, DIGEST, KEY, PAGE};
use pgm::Model;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;

pub trait Source {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, Error>;
}

impl Source for Vec<u8> {
    /// Exactly `len` bytes at `off`, or `ShortRead`. The offset is converted
    /// with a check, so a `u64` offset past a 32-bit `usize` is a short read,
    /// not a truncated index.
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        let short = |got: usize| Error::ShortRead { off, want: len, got };
        let Ok(start) = usize::try_from(off) else {
            return Err(short(0));
        };
        let Some(end) = start.checked_add(len) else {
            return Err(short(self.len().saturating_sub(start)));
        };
        match self.get(start..end) {
            Some(b) => Ok(b.to_vec()),
            None => Err(short(self.len().saturating_sub(start))),
        }
    }
}

/// A run file on disk. Unix only (positional reads through `FileExt`); the
/// browser build (`wasm32-unknown-unknown`) has no filesystem and reads runs
/// through its own [`Source`].
#[cfg(unix)]
impl Source for File {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        use std::os::unix::fs::FileExt;
        let mut buf = vec![0u8; len];
        let mut done = 0;
        while done < len {
            let at = off.checked_add(done as u64).ok_or(Error::ShortRead { off, want: len, got: done })?;
            let n = FileExt::read_at(self, &mut buf[done..], at)?;
            if n == 0 {
                return Err(Error::ShortRead { off, want: len, got: done });
            }
            done += n;
        }
        Ok(buf)
    }
}

/// How a lookup found its page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Path {
    /// The predicted page covered the key.
    Direct,
    /// Found within `ε + 1` steps of the prediction; the number of extra pages
    /// read. `ε` bounds the prediction for stored prefixes; a key absent
    /// between two stored prefixes is covered by one of their pages, which
    /// can be one page further (core §10).
    Walk(u32),
    /// The walk was exhausted; binary search over fences took this many extra pages.
    Fallback(u32),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub record_requests: u64,
    pub record_bytes: u64,
    /// Model section reads: the section, or page 0 and each model page.
    pub model_requests: u64,
    pub model_bytes: u64,
    pub direct: u64,
    pub walk: u64,
    pub walk_pages: u64,
    pub fallback: u64,
    pub fallback_pages: u64,
    pub max_requests_one_lookup: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// A tag 0 value, or for a tag 2 entry the 32-byte blob hash
    /// ([`Reader::get_entry`] tells them apart).
    Found(Vec<u8>),
    Tombstone,
    /// The fence page that would hold the key does not. Verified absent
    /// with inline proofs; "not in this file" without them.
    Absent,
}

pub struct Reader<S: Source> {
    src: S,
    rref: RunRef,
    format: Format,
    /// `Err` when the `RunRef` gives no valid layout (`Reader::new` does not
    /// fail; every read then returns the error).
    layout: Result<Layout, &'static str>,
    model: Option<Model>,
    /// Paged model: page 0 once read, and the model pages verified so far
    /// with the routing model each gives (`ModelPage::routing`).
    top: Option<Top>,
    model_pages: BTreeMap<u64, (ModelPage, Model)>,
    pub stats: Stats,
}

impl<S: Source> Reader<S> {
    /// A v1-min reader (fixed layout, inline proofs) that never panics on a
    /// bad `RunRef`: if its page count or model size gives no valid layout,
    /// every read returns [`Error::Layout`]. Use [`Reader::try_new`] to fail
    /// up front.
    pub fn new(src: S, rref: RunRef, value_size: u32) -> Reader<S> {
        Self::with_format(src, rref, Format::fixed(value_size))
    }

    /// As [`Reader::new`] for any format.
    pub fn with_format(src: S, rref: RunRef, format: Format) -> Reader<S> {
        let layout = Layout::try_new_with(rref.page_count, u64::from(rref.model_bytes), format.inline_proofs).map_err(|e| match e {
            Error::Layout(w) => w,
            _ => "invalid layout",
        });
        Reader { src, rref, format, layout, model: None, top: None, model_pages: BTreeMap::new(), stats: Stats::default() }
    }

    /// As [`Reader::new`], but rejects a `RunRef` with no valid layout
    /// (`page_count` outside `[1, 2^31]`, or offsets overflowing `u64`).
    pub fn try_new(src: S, rref: RunRef, value_size: u32) -> Result<Reader<S>, Error> {
        Self::try_with_format(src, rref, Format::fixed(value_size))
    }

    pub fn try_with_format(src: S, rref: RunRef, format: Format) -> Result<Reader<S>, Error> {
        let r = Self::with_format(src, rref, format);
        r.layout.map_err(Error::Layout)?;
        Ok(r)
    }

    pub fn run_ref(&self) -> &RunRef {
        &self.rref
    }

    pub fn format(&self) -> Format {
        self.format
    }

    /// The run's layout, or `None` when the `RunRef` gives none.
    pub fn layout(&self) -> Option<&Layout> {
        self.layout.as_ref().ok()
    }

    fn valid_layout(&self) -> Result<Layout, Error> {
        self.layout.map_err(Error::Layout)
    }

    /// What routing needs before the first lookup: the model section, or
    /// with a paged model page 0. Every lookup does this on demand; a
    /// client that wants the fetch in a round of its own calls it first.
    pub fn prepare(&mut self) -> Result<(), Error> {
        if self.format.paged_model {
            self.load_top().map(|_| ())
        } else {
            self.load_model().map(|_| ())
        }
    }

    /// Fetch, hash-check and decode the model section. A paged model has
    /// no whole section to load: use [`Reader::predict_page`].
    pub fn load_model(&mut self) -> Result<&Model, Error> {
        if self.format.paged_model {
            return Err(Error::Layout("model is paged; predict_page routes by key"));
        }
        if self.model.is_none() {
            let layout = self.valid_layout()?;
            let want = usize::try_from(self.rref.model_bytes).map_err(|_| Error::Layout("model_bytes exceeds usize"))?;
            let bytes = self.src.read_at(layout.model_off, want)?;
            self.stats.model_requests += 1;
            self.stats.model_bytes += bytes.len() as u64;
            if bytes.len() != want {
                return Err(Error::ShortRead { off: layout.model_off, want, got: bytes.len() });
            }
            if *blake3::hash(&bytes).as_bytes() != self.rref.model_root {
                return Err(Error::ModelMismatch);
            }
            let m = Model::decode(&bytes, self.rref.page_count, self.rref.epsilon_pages).map_err(|_| Error::ModelMismatch)?;
            self.model = Some(m);
        }
        Ok(self.model.as_ref().expect("set above"))
    }

    /// Page 0 of a paged run: hash-checked against `model_root`, decoded,
    /// and its page count checked against the section's size.
    pub fn load_top(&mut self) -> Result<&Top, Error> {
        if !self.format.paged_model {
            return Err(Error::Layout("model is not paged"));
        }
        if self.top.is_none() {
            let layout = self.valid_layout()?;
            let bytes = self.src.read_at(0, PAGE)?;
            self.stats.model_requests += 1;
            self.stats.model_bytes += bytes.len() as u64;
            if bytes.len() != PAGE {
                return Err(Error::ShortRead { off: 0, want: PAGE, got: bytes.len() });
            }
            if *blake3::hash(&bytes).as_bytes() != self.rref.model_root {
                return Err(Error::ModelMismatch);
            }
            let top = Top::decode(&bytes).map_err(|_| Error::ModelMismatch)?;
            let record = Self::model_record_bytes(top.model_pages);
            if top.model_pages.checked_mul(record) != Some(layout.model_bytes) {
                return Err(Error::ModelMismatch);
            }
            self.top = Some(top);
        }
        Ok(self.top.as_ref().expect("set above"))
    }

    /// A model page record: the page and its inline proof.
    fn model_record_bytes(model_pages: u64) -> u64 {
        PAGE as u64 + (DIGEST * tree::depth(model_pages)) as u64
    }

    /// Model page `m` (1-based): fetched, proved against the tree root on
    /// page 0, shape-checked and kept.
    fn model_page(&mut self, m: u64) -> Result<&(ModelPage, Model), Error> {
        if !self.model_pages.contains_key(&m) {
            let layout = self.valid_layout()?;
            let (mp, tree_root) = {
                let t = self.load_top()?;
                (t.model_pages, t.tree_root)
            };
            if m == 0 || m > mp {
                return Err(Error::PageOutOfRange { page: m, page_count: mp });
            }
            let record = Self::model_record_bytes(mp);
            let off = layout.model_off + (m - 1) * record;
            let want = usize::try_from(record).map_err(|_| Error::Layout("record size exceeds usize"))?;
            let rec = self.src.read_at(off, want)?;
            self.stats.model_requests += 1;
            self.stats.model_bytes += rec.len() as u64;
            if rec.len() != want {
                return Err(Error::ShortRead { off, want, got: rec.len() });
            }
            let (page, proof) = rec.split_at(PAGE);
            let digest = *blake3::hash(page).as_bytes();
            if !verify_inline(mp, (m - 1) as u32, &digest, proof, &tree_root) {
                return Err(Error::ModelMismatch);
            }
            let page = ModelPage::decode(page, self.rref.page_count, m, m == mp)?;
            let routing = page.routing(self.rref.page_count, self.rref.epsilon_pages);
            self.model_pages.insert(m, (page, routing));
        }
        Ok(&self.model_pages[&m])
    }

    /// The model page whose fences cover `k`: the top's prediction, a
    /// walk of `ε_top + 1`, then a binary search, as `locate` does over
    /// data pages. The fallback is reached only by a top that violates
    /// its bound, and a chain of fences that does not partition the key
    /// space is a `FenceGap`.
    fn locate_model_page(&mut self, k: u64) -> Result<u64, Error> {
        let (mp, eps, p) = {
            let t = self.load_top()?;
            (t.model_pages, t.model.epsilon as u64, t.model.predict(k))
        };
        let covers = |r: &mut Self, m: u64| -> Result<bool, Error> { Ok(r.model_page(m)?.0.covers(k, m == mp)) };
        if covers(self, p)? {
            return Ok(p);
        }
        let down = k < self.model_pages[&p].0.lo;
        for step in 1..=eps + 1 {
            let q = if down { p.checked_sub(step).filter(|q| *q >= 1) } else { Some(p + step).filter(|q| *q <= mp) };
            let Some(q) = q else { break };
            if covers(self, q)? {
                return Ok(q);
            }
        }
        let (mut lo, mut hi) = if down { (1u64, p.saturating_sub(eps + 2)) } else { (p + eps + 2, mp) };
        while lo >= 1 && hi <= mp && lo <= hi {
            let mid = lo + (hi - lo) / 2;
            if covers(self, mid)? {
                return Ok(mid);
            }
            if k < self.model_pages[&mid].0.lo {
                if mid == 0 {
                    break;
                }
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }
        Err(Error::FenceGap)
    }

    /// The page the model predicts for `k`, whole or paged. With a paged
    /// model this may fetch page 0 and model pages; a source that cannot
    /// serve one yet returns its error from here, and the next call
    /// resumes with what was kept.
    pub fn predict_page(&mut self, k: u64) -> Result<u64, Error> {
        if !self.format.paged_model {
            return Ok(self.load_model()?.predict(k));
        }
        let m = self.locate_model_page(k)?;
        Ok(self.model_pages[&m].1.predict(k))
    }

    /// One range request for record `i`; with inline proofs, verify the
    /// page against the run root before parsing it. A record index outside
    /// `1..=page_count` or a source that returns other than exactly one
    /// record is an error, not a panic.
    pub fn fetch_page(&mut self, i: u64) -> Result<Page, Error> {
        let layout = self.valid_layout()?;
        let off = layout.checked_record_off(i).ok_or(Error::PageOutOfRange { page: i, page_count: self.rref.page_count })?;
        let want = usize::try_from(layout.record_bytes).map_err(|_| Error::Layout("record size exceeds usize"))?;
        let rec = self.src.read_at(off, want)?;
        self.stats.record_requests += 1;
        self.stats.record_bytes += rec.len() as u64;
        if rec.len() != want {
            return Err(Error::ShortRead { off, want, got: rec.len() });
        }
        let (page, proof) = rec.split_at(PAGE);
        if layout.inline_proofs {
            let digest = *blake3::hash(page).as_bytes();
            // i ≤ page_count ≤ 2^31, so i − 1 fits a u32.
            if !verify_inline(self.rref.page_count, (i - 1) as u32, &digest, proof, &self.rref.root) {
                return Err(Error::ProofFailed { page: i });
            }
        }
        Page::decode_with(page, self.format.layout, i == self.rref.page_count, i)
    }

    /// The page whose fences cover `key`, with the path taken.
    pub fn locate(&mut self, key: &[u8; KEY]) -> Result<(u64, Page, Path), Error> {
        let before = self.stats.record_requests;
        let r = self.locate_inner(key);
        let used = self.stats.record_requests - before;
        if used > self.stats.max_requests_one_lookup {
            self.stats.max_requests_one_lookup = used;
        }
        r
    }

    fn locate_inner(&mut self, key: &[u8; KEY]) -> Result<(u64, Page, Path), Error> {
        let pc = self.rref.page_count;
        let eps = self.rref.epsilon_pages as u64;
        let p = self.predict_page(k64(key))?;
        let page = self.fetch_page(p)?;
        if page.covers(key, p == pc) {
            self.stats.direct += 1;
            return Ok((p, page, Path::Direct));
        }
        let down = *key < page.lo;
        // Walk up to ε + 1 pages: ε for a stored prefix, one more for an
        // absent key between two stored prefixes (its page is one of
        // theirs, and the neighbour's prediction may sit ε off the other
        // way). A chain of 10^7 uniform keys put 0.2% of absent keys at
        // exactly ε + 1, each paying the full binary search below before
        // the walk was extended.
        let mut extra = 0u32;
        for step in 1..=eps + 1 {
            let q = if down { p.checked_sub(step).filter(|q| *q >= 1) } else { Some(p + step).filter(|q| *q <= pc) };
            let Some(q) = q else { break };
            let page = self.fetch_page(q)?;
            extra += 1;
            if page.covers(key, q == pc) {
                self.stats.walk += 1;
                self.stats.walk_pages += extra as u64;
                return Ok((q, page, Path::Walk(extra)));
            }
        }
        // Fallback: binary search over the pages beyond the walk.
        let (mut lo, mut hi) = if down { (1u64, p.saturating_sub(eps + 2)) } else { (p + eps + 2, pc) };
        let mut fb = 0u32;
        while lo >= 1 && hi <= pc && lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let page = self.fetch_page(mid)?;
            fb += 1;
            if page.covers(key, mid == pc) {
                self.stats.fallback += 1;
                self.stats.fallback_pages += (extra + fb) as u64;
                return Ok((mid, page, Path::Fallback(extra + fb)));
            }
            if *key < page.lo {
                if mid == 0 {
                    break;
                }
                hi = mid - 1;
            } else {
                lo = mid + 1;
            }
        }
        Err(Error::FenceGap)
    }

    /// The entry under `key` on its fence page, tag and all, or `None` when
    /// the page does not hold it.
    pub fn get_entry(&mut self, key: &[u8; KEY]) -> Result<(Option<Entry>, Path), Error> {
        let (_, page, path) = self.locate(key)?;
        Ok((page.find(key).cloned(), path))
    }

    pub fn get(&mut self, key: &[u8; KEY]) -> Result<(Lookup, Path), Error> {
        let (e, path) = self.get_entry(key)?;
        let r = match e {
            Some(e) if e.tag == 1 => Lookup::Tombstone,
            Some(e) => Lookup::Found(e.value),
            None => Lookup::Absent,
        };
        Ok((r, path))
    }
}
