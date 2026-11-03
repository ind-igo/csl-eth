//! Canonical run writer. Entries arrive sorted; `entry_count` is declared up
//! front. In the fixed layout that fixes the page count and so every record
//! offset before the first byte is written; in the variable layout pages
//! are counted as they close, which is why that layout is written without
//! inline proofs (a record's size would depend on the final count).
//!
//! Pass 1 writes a provisional header and each page at its final offset,
//! keeping page digests when the format has proofs and feeding the model
//! fitter. At `finish` the tree is built and the inline proofs written (with
//! proofs), the model section and padding follow, the header is rewritten
//! with the final counts, the pages are read back to verify the model on
//! build, and without proofs the whole file is hashed for its identity.

use crate::model::{self, ModelPage, Top};
use crate::page::{entries_per_page, variable_fits, Entry, Page};
use crate::tree::{self as tree, Digest, Tree};
use crate::{k64, Config, EntryLayout, Error, Format, Layout, RunHeader, RunRef, DIGEST, KEY, KEY_MAX, KEY_MIN, PAGE};
use pgm::{Fitter, Grouper, Model};
use std::io::{Read, Seek, SeekFrom, Write};

pub struct Built {
    /// The `bmt` root with inline proofs; `blake3` of the file without.
    pub root: Digest,
    /// The whole model, paged or not.
    pub model: Model,
    /// `blake3` of the model section, or of page 0 when the model is paged.
    pub model_root: Digest,
    /// Paged model: how many model pages, and the top model on page 0.
    pub model_pages: u64,
    pub top: Option<Model>,
    pub layout: Layout,
    pub page_count: u64,
    pub entry_count: u64,
}

impl Built {
    pub fn run_ref(&self, block_lo: u64, block_hi: u64, epsilon: u16) -> RunRef {
        RunRef {
            root: self.root,
            block_lo,
            block_hi,
            page_count: self.page_count,
            entry_count: self.entry_count,
            epsilon_pages: epsilon,
            model_bytes: self.layout.model_bytes as u32,
            model_root: self.model_root,
        }
    }
}

pub struct Writer<W: Read + Write + Seek> {
    out: W,
    cfg: Config,
    format: Format,
    /// Fixed layout only.
    epp: Option<usize>,
    entry_count: u64,
    /// Known up front in the fixed layout; counted in the variable one.
    fixed_page_count: Option<u64>,
    record_bytes: u64,
    seen: u64,
    cur: Vec<Entry>,
    /// Variable layout: entry bytes on the open page, offsets excluded.
    cur_bytes: usize,
    cur_lo: [u8; KEY],
    next_page: u64,
    digests: Vec<Digest>,
    grouper: Grouper,
    fitter: Fitter,
    prev_key: Option<[u8; KEY]>,
}

impl<W: Read + Write + Seek> Writer<W> {
    /// v1-min: `cfg.format()`. `entry_count ≥ 1`: an empty table has no run.
    pub fn new(out: W, cfg: Config, entry_count: u64) -> Result<Writer<W>, Error> {
        Self::with_format(out, cfg, cfg.format(), entry_count)
    }

    /// A run in `format`; `cfg.value_size` is read only for the fixed layout.
    pub fn with_format(mut out: W, cfg: Config, format: Format, entry_count: u64) -> Result<Writer<W>, Error> {
        assert!(entry_count >= 1, "empty tables have no run");
        let (epp, fixed_page_count, record_bytes) = match format.layout {
            EntryLayout::Fixed { value_size } => {
                let epp = entries_per_page(value_size);
                let page_count = pgm::page_count(entry_count, epp as u64);
                assert!(page_count <= 1 << 31, "page_count above 2^31");
                // Model bytes are unknown until the fit finishes; records do
                // not depend on them, so a provisional layout serves pass 1.
                let layout = Layout::try_new_with(page_count, 0, format.inline_proofs)?;
                (Some(epp), Some(page_count), layout.record_bytes)
            }
            EntryLayout::Variable => {
                if format.inline_proofs {
                    return Err(Error::Layout("variable layout is written without inline proofs"));
                }
                (None, None, PAGE as u64)
            }
        };
        let header = RunHeader {
            format_version: crate::FORMAT_VERSION,
            profile_id: cfg.profile_id,
            table_id: cfg.table_id,
            page_count: fixed_page_count.unwrap_or(0),
            entry_count,
            epsilon_pages: cfg.epsilon,
        };
        out.seek(SeekFrom::Start(0))?;
        out.write_all(&header.encode_page())?;
        Ok(Writer {
            out,
            cfg,
            format,
            epp,
            entry_count,
            fixed_page_count,
            record_bytes,
            seen: 0,
            cur: Vec::with_capacity(epp.unwrap_or(64)),
            cur_bytes: 0,
            cur_lo: KEY_MIN,
            next_page: 1,
            digests: Vec::new(),
            grouper: Grouper::new(epp.unwrap_or(1) as u64),
            fitter: Fitter::new(cfg.epsilon, fixed_page_count.unwrap_or(pgm::MAX_PAGES)),
            prev_key: None,
        })
    }

    fn record_off(&self, i: u64) -> u64 {
        PAGE as u64 + (i - 1) * self.record_bytes
    }

    pub fn push(&mut self, e: Entry) -> Result<(), Error> {
        e.check_layout(self.format.layout)?;
        if let Some(p) = self.prev_key {
            if e.key <= p {
                return Err(Error::Unsorted { prev: p, next: e.key });
            }
        }
        if self.seen >= self.entry_count {
            return Err(Error::CountMismatch { declared: self.entry_count, got: self.seen + 1 });
        }
        self.prev_key = Some(e.key);
        self.seen += 1;
        let len = e.encoded_len(self.format.layout);
        let full = match self.epp {
            Some(epp) => self.cur.len() == epp,
            None => !self.cur.is_empty() && !variable_fits(self.cur.len() + 1, self.cur_bytes + len),
        };
        if full {
            // This entry's key is the upper fence of the full page.
            let hi = e.key;
            self.flush_page(hi)?;
            self.cur_lo = hi;
        }
        if let Some(g) = self.grouper.push_at(k64(&e.key), self.next_page) {
            self.fitter.push(g)?;
        }
        self.cur_bytes += len;
        self.cur.push(e);
        Ok(())
    }

    fn flush_page(&mut self, hi: [u8; KEY]) -> Result<(), Error> {
        let page = Page { lo: self.cur_lo, hi, entries: std::mem::take(&mut self.cur) };
        let bytes = page.encode_with(self.format.layout);
        if self.format.inline_proofs {
            self.digests.push(*blake3::hash(&bytes).as_bytes());
        }
        self.out.seek(SeekFrom::Start(self.record_off(self.next_page)))?;
        self.out.write_all(&bytes)?;
        self.next_page += 1;
        self.cur_bytes = 0;
        self.cur.reserve(self.epp.unwrap_or(0));
        Ok(())
    }

    pub fn finish(mut self) -> Result<Built, Error> {
        if self.seen != self.entry_count {
            return Err(Error::CountMismatch { declared: self.entry_count, got: self.seen });
        }
        let grouper = std::mem::replace(&mut self.grouper, Grouper::new(1));
        if let Some(g) = grouper.finish() {
            self.fitter.push(g)?;
        }
        self.flush_page(KEY_MAX)?;
        let page_count = self.next_page - 1;
        if let Some(pc) = self.fixed_page_count {
            debug_assert_eq!(pc, page_count);
        }
        if page_count > pgm::MAX_PAGES {
            return Err(Error::Layout("page_count above 2^31"));
        }

        // Model, then the real layout. Paged: the segments split into
        // model pages under a tree, the top fitted over their starts, page
        // 0 carrying the top and the tree root (model §4.1).
        let fitter = std::mem::replace(&mut self.fitter, Fitter::new(self.cfg.epsilon, 1));
        let model = fitter.finish_with(page_count)?;
        let header = RunHeader {
            format_version: crate::FORMAT_VERSION,
            profile_id: self.cfg.profile_id,
            table_id: self.cfg.table_id,
            page_count,
            entry_count: self.entry_count,
            epsilon_pages: self.cfg.epsilon,
        };
        let (model_bytes, model_root, page0, model_pages, top) = if self.format.paged_model {
            let pages = model::split(&model);
            let mp = pages.len() as u64;
            let digests: Vec<Digest> = pages.iter().map(|p| *blake3::hash(&p.encode()).as_bytes()).collect();
            let mtree = Tree::build(&digests);
            let top = Top { model_pages: mp, tree_root: mtree.root(), model: model::fit_top(&pages, self.cfg.epsilon)? };
            let page0 = top.encode_page(&header)?;
            let mut section = Vec::with_capacity(mp as usize * (PAGE + DIGEST * tree::depth(mp)));
            for (i, p) in pages.iter().enumerate() {
                let bytes = p.encode();
                // What was encoded decodes to what was meant.
                let back = ModelPage::decode(&bytes, page_count, i as u64 + 1, i + 1 == pages.len())?;
                debug_assert_eq!(&back, p);
                section.extend_from_slice(&bytes);
                section.extend_from_slice(&mtree.inline_proof(i as u32));
            }
            (section, *blake3::hash(&page0).as_bytes(), page0, mp, Some(top.model))
        } else {
            let bytes = model.encode();
            (bytes.clone(), *blake3::hash(&bytes).as_bytes(), header.encode_page(), 0, None)
        };
        let layout = Layout::try_new_with(page_count, model_bytes.len() as u64, self.format.inline_proofs)?;
        debug_assert_eq!(layout.record_bytes, self.record_bytes);

        // Tree and inline proofs.
        let tree = if self.format.inline_proofs {
            let tree = Tree::build(&self.digests);
            if layout.depth > 0 {
                for i in 0..page_count {
                    self.out.seek(SeekFrom::Start(layout.record_off(i + 1) + PAGE as u64))?;
                    self.out.write_all(&tree.inline_proof(i as u32))?;
                }
            }
            Some(tree)
        } else {
            None
        };

        // Model section and zero padding. The gap between the last record
        // and model_off is also zero.
        let last_end = layout.record_off(page_count) + layout.record_bytes;
        self.out.seek(SeekFrom::Start(last_end))?;
        self.out.write_all(&vec![0u8; (layout.model_off - last_end) as usize])?;
        self.out.write_all(&model_bytes)?;
        self.out.write_all(&vec![0u8; (layout.total_len - layout.model_off - model_bytes.len() as u64) as usize])?;

        // Page 0 with the final counts (only the variable layout's page
        // count was provisional), and the top when the model is paged.
        self.out.seek(SeekFrom::Start(0))?;
        self.out.write_all(&page0)?;
        self.out.flush()?;

        // Verify-on-build from the written pages.
        let mut grouper = Grouper::new(1);
        let mut buf = vec![0u8; PAGE];
        for i in 1..=page_count {
            self.out.seek(SeekFrom::Start(layout.record_off(i)))?;
            self.out.read_exact(&mut buf)?;
            let page = Page::decode_with(&buf, self.format.layout, i == page_count, i)?;
            for e in &page.entries {
                if let Some(g) = grouper.push_at(k64(&e.key), i) {
                    model.check(&g).map_err(pgm::FitError::Bound)?;
                }
            }
        }
        if let Some(g) = grouper.finish() {
            model.check(&g).map_err(pgm::FitError::Bound)?;
        }

        // Identity: the tree root, or blake3 of every byte.
        let root = match tree {
            Some(t) => t.root(),
            None => {
                let mut h = blake3::Hasher::new();
                self.out.seek(SeekFrom::Start(0))?;
                let mut left = layout.total_len;
                let mut buf = vec![0u8; 1 << 16];
                while left > 0 {
                    let n = buf.len().min(left as usize);
                    self.out.read_exact(&mut buf[..n])?;
                    h.update(&buf[..n]);
                    left -= n as u64;
                }
                *h.finalize().as_bytes()
            }
        };

        Ok(Built { root, model, model_root, model_pages, top, layout, page_count, entry_count: self.entry_count })
    }
}

/// Write a whole v1-min run from an in-memory entry list. Convenience for
/// tests and vectors.
pub fn write_all(cfg: Config, entries: &[Entry]) -> Result<(Vec<u8>, Built), Error> {
    write_all_with(cfg, cfg.format(), entries)
}

pub fn write_all_with(cfg: Config, format: Format, entries: &[Entry]) -> Result<(Vec<u8>, Built), Error> {
    let mut cur = std::io::Cursor::new(Vec::new());
    let mut w = Writer::with_format(&mut cur, cfg, format, entries.len() as u64)?;
    for e in entries {
        w.push(e.clone())?;
    }
    let built = w.finish()?;
    Ok((cur.into_inner(), built))
}

#[allow(dead_code)]
fn _assert_digest_len() {
    let _ = [0u8; DIGEST];
}
