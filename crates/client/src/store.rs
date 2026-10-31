//! The client's I/O boundary. The client never performs I/O: it computes
//! over what the [`Store`] holds, and when something it needs is not there
//! it notes the [`Want`] and returns [`Pending`]. The host fetches every
//! want of a round however it likes (threads, `fetch` with `Promise.all`,
//! a directory on disk), supplies the results, and runs the computation
//! again; the store only grows within a read, so each run gets at least as
//! far as the last. One round is one dependent network round trip, and
//! every want in it goes out in parallel. A [`Driver`] is the synchronous
//! host for that loop; an asynchronous host drives it itself.

use csl_run::{Error, Source};
use std::{
    collections::{BTreeMap, HashMap},
    io,
    sync::{Arc, Mutex},
};

/// One thing the client needs from the bucket: a whole file, or a byte
/// range of a run.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Want {
    File { rel: String },
    Range { rel: String, off: u64, len: usize },
}

impl Want {
    pub fn rel(&self) -> &str {
        match self {
            Want::File { rel } | Want::Range { rel, .. } => rel,
        }
    }
}

/// What the host got for a want: the bytes; `Ok(None)` for a file that is
/// not there (which the head verifier and `latest` treat differently from
/// a failure); or why it could not be fetched. A range answers `Ok(Some)`
/// with exactly the bytes asked for, or `Err`.
pub type Got = Result<Option<Vec<u8>>, String>;

/// The computation needs something the store does not hold yet; see
/// [`Store::take_wanted`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending;

/// How a pending read shows through a `String` error (the head verifier's
/// source trait).
pub const PENDING: &str = "\u{0}pending";

pub fn is_pending(e: &Error) -> bool {
    matches!(e, Error::Io(e) if e.kind() == io::ErrorKind::WouldBlock)
}

fn pending_error() -> Error {
    Error::Io(io::Error::new(io::ErrorKind::WouldBlock, PENDING))
}

/// One run file's fetched ranges by offset; a failed range keeps its
/// length so it covers exactly what was asked.
type Ranges = BTreeMap<u64, Result<Vec<u8>, (usize, String)>>;

#[derive(Default)]
struct Inner {
    /// Whole files, kept for the store's life (manifests, head files,
    /// `latest`, blobs are small and few).
    files: HashMap<String, Got>,
    /// Ranges by run file, one read's worth.
    ranges: HashMap<String, Ranges>,
    wanted: Vec<Want>,
    rounds: u32,
    requests: u64,
    bytes: u64,
}

/// What has been fetched, and what is wanted next.
#[derive(Default)]
pub struct Store(Mutex<Inner>);

/// The bytes of `[off, off + len)` from the range that covers them, or the
/// error of a failed range that does.
fn covered(ready: &Ranges, off: u64, len: usize) -> Option<Result<Vec<u8>, String>> {
    let (start, v) = ready.range(..=off).next_back()?;
    let lo = (off - start) as usize;
    match v {
        Ok(v) => v.get(lo..lo + len).map(|b| Ok(b.to_vec())),
        Err((elen, e)) => (lo + len <= *elen).then(|| Err(e.clone())),
    }
}

impl Store {
    pub fn new() -> Arc<Store> {
        Arc::new(Store::default())
    }

    /// A whole file, or `Pending` after noting the want.
    pub fn file(&self, rel: &str) -> Result<Got, Pending> {
        let mut g = self.0.lock().unwrap();
        if let Some(got) = g.files.get(rel) {
            return Ok(got.clone());
        }
        let w = Want::File {
            rel: rel.to_string(),
        };
        if !g.wanted.contains(&w) {
            g.wanted.push(w);
        }
        Err(Pending)
    }

    /// A byte range of a run, or `Pending` after noting the want.
    pub fn range(
        &self,
        rel: &str,
        off: u64,
        len: usize,
    ) -> Result<Result<Vec<u8>, String>, Pending> {
        let mut g = self.0.lock().unwrap();
        if let Some(r) = g.ranges.get(rel).and_then(|m| covered(m, off, len)) {
            return Ok(r);
        }
        g.wanted.push(Want::Range {
            rel: rel.to_string(),
            off,
            len,
        });
        Err(Pending)
    }

    /// Note a range to fetch with the next round, if not held already.
    pub fn want_range(&self, rel: &str, off: u64, len: usize) {
        let mut g = self.0.lock().unwrap();
        if g.ranges
            .get(rel)
            .and_then(|m| covered(m, off, len))
            .is_some()
        {
            return;
        }
        g.wanted.push(Want::Range {
            rel: rel.to_string(),
            off,
            len,
        });
    }

    /// The round's wants, normalised: files once each, ranges sorted by
    /// file and offset with overlaps coalesced, and touching ranges joined
    /// into one when `merge` (the depths of one path share pages in a
    /// pre-order table, so a read's pages come in a few runs). Counts a
    /// round when there is anything to fetch.
    pub fn take_wanted(&self, merge: bool) -> Vec<Want> {
        let mut g = self.0.lock().unwrap();
        let wanted = std::mem::take(&mut g.wanted);
        let mut files: Vec<String> = Vec::new();
        let mut ranges: Vec<(String, u64, u64)> = Vec::new();
        for w in wanted {
            match w {
                Want::File { rel } => {
                    if !files.contains(&rel) {
                        files.push(rel);
                    }
                }
                Want::Range { rel, off, len } => ranges.push((rel, off, off + len as u64)),
            }
        }
        ranges.sort();
        let mut out: Vec<Want> = files.into_iter().map(|rel| Want::File { rel }).collect();
        let mut cur: Option<(String, u64, u64)> = None;
        for (rel, lo, hi) in ranges {
            match &mut cur {
                Some((r, a, b)) if *r == rel && (lo < *b || (merge && lo == *b)) => {
                    *b = (*b).max(hi)
                }
                _ => {
                    if let Some((r, a, b)) = cur.take() {
                        out.push(Want::Range {
                            rel: r,
                            off: a,
                            len: (b - a) as usize,
                        });
                    }
                    cur = Some((rel, lo, hi));
                }
            }
        }
        if let Some((r, a, b)) = cur {
            out.push(Want::Range {
                rel: r,
                off: a,
                len: (b - a) as usize,
            });
        }
        if !out.is_empty() {
            g.rounds += 1;
        }
        out
    }

    /// What the host got for a want.
    pub fn supply(&self, want: &Want, got: Got) {
        let mut g = self.0.lock().unwrap();
        g.requests += 1;
        if let Ok(Some(v)) = &got {
            g.bytes += v.len() as u64;
        }
        match want {
            Want::File { rel } => {
                g.files.insert(rel.clone(), got);
            }
            Want::Range { rel, off, len } => {
                let r = match got {
                    Ok(Some(v)) if v.len() == *len => Ok(v),
                    Ok(Some(v)) => Err((
                        *len,
                        format!("short range: {} of {len} bytes at {off}", v.len()),
                    )),
                    Ok(None) => Err((*len, format!("{rel}: not found"))),
                    Err(e) => Err((*len, e)),
                };
                g.ranges.entry(rel.clone()).or_default().insert(*off, r);
            }
        }
    }

    /// A read is starting: drop the last one's ranges and counters. Whole
    /// files stay. What a store keeps across reads is never pages, so
    /// every read is measured and verified on its own.
    pub fn begin_read(&self) {
        let mut g = self.0.lock().unwrap();
        g.ranges.clear();
        g.wanted.clear();
        g.rounds = 0;
        g.requests = 0;
        g.bytes = 0;
    }

    /// Requests, bytes and rounds since `begin_read`.
    pub fn cost(&self) -> (u64, u64, u32) {
        let g = self.0.lock().unwrap();
        (g.requests, g.bytes, g.rounds)
    }
}

/// One run file seen through the store: `csl_run`'s reader reads it, and
/// a page the store lacks is a pending read.
pub struct RunView {
    pub store: Arc<Store>,
    pub rel: String,
}

impl Source for RunView {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        match self.store.range(&self.rel, off, len) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(Error::Io(io::Error::other(e))),
            Err(Pending) => Err(pending_error()),
        }
    }
}

/// A synchronous host: fetches a round's wants, all at once where it can.
pub trait Driver {
    fn fetch(&self, wants: &[Want]) -> Vec<Got>;
}

/// One round: take the wants, fetch them, supply the results.
pub fn drive<D: Driver + ?Sized>(driver: &D, store: &Store, merge: bool) {
    let wants = store.take_wanted(merge);
    if wants.is_empty() {
        return;
    }
    let got = driver.fetch(&wants);
    debug_assert_eq!(got.len(), wants.len());
    for (w, g) in wants.iter().zip(got) {
        store.supply(w, g);
    }
}

/// No host at all: every want fails, so a computation driven by nothing
/// ends `Insufficient` rather than spinning. The asynchronous host (the
/// browser) uses this and supplies the store itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoDriver;

impl Driver for NoDriver {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        wants.iter().map(|_| Err("no driver".to_string())).collect()
    }
}

/// A directory on disk (the producer's output, or a mirror).
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Debug)]
pub struct DirDriver(pub std::path::PathBuf);

#[cfg(not(target_arch = "wasm32"))]
impl DirDriver {
    pub fn new(p: impl AsRef<std::path::Path>) -> DirDriver {
        DirDriver(p.as_ref().to_path_buf())
    }

    fn one(&self, w: &Want) -> Got {
        match w {
            Want::File { rel } => match std::fs::read(self.0.join(rel)) {
                Ok(v) => Ok(Some(v)),
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(format!("{rel}: {e}")),
            },
            Want::Range { rel, off, len } => {
                let f = std::fs::File::open(self.0.join(rel)).map_err(|e| format!("{rel}: {e}"))?;
                f.read_at(*off, *len)
                    .map(Some)
                    .map_err(|e| format!("{rel}: {e}"))
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Driver for DirDriver {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        wants.iter().map(|w| self.one(w)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_read_is_served_from_any_range_that_covers_it() {
        let mut ready = BTreeMap::new();
        ready.insert(
            4096u64,
            Ok((0u8..=255).cycle().take(3 * 4096).collect::<Vec<u8>>()),
        );
        ready.insert(40960, Ok(vec![7u8; 4096]));
        ready.insert(81920, Err((4096, "dropped".to_string())));
        for p in 1..=3u64 {
            let v = covered(&ready, p * 4096, 4096).unwrap().unwrap();
            assert_eq!(v.len(), 4096);
            assert_eq!(v[0], ((p - 1) * 4096 % 256) as u8);
        }
        assert_eq!(
            covered(&ready, 40960, 4096).unwrap().unwrap(),
            vec![7u8; 4096]
        );
        assert!(covered(&ready, 4 * 4096, 4096).is_none());
        assert!(covered(&ready, 0, 4096).is_none());
        assert!(covered(&ready, 3 * 4096 + 1, 4096).is_none());
        assert!(covered(&ready, 36864, 4096).is_none());
        assert_eq!(
            covered(&ready, 81920, 100),
            Some(Err("dropped".to_string()))
        );
        assert_eq!(
            covered(&ready, 81920, 4096),
            Some(Err("dropped".to_string()))
        );
        assert!(
            covered(&ready, 81920 + 4096, 1).is_none(),
            "a failure covers only what it asked"
        );
    }

    #[test]
    fn wants_coalesce_and_rounds_count() {
        let s = Store::default();
        assert_eq!(s.range("t", 8192, 4096), Err(Pending));
        s.want_range("t", 4096, 4096);
        s.want_range("t", 4096, 4096);
        s.want_range("t", 20480, 4096);
        assert_eq!(s.file("m"), Err(Pending));
        assert_eq!(s.file("m"), Err(Pending));
        let w = s.take_wanted(true);
        assert_eq!(
            w,
            vec![
                Want::File { rel: "m".into() },
                Want::Range {
                    rel: "t".into(),
                    off: 4096,
                    len: 8192
                },
                Want::Range {
                    rel: "t".into(),
                    off: 20480,
                    len: 4096
                },
            ]
        );
        s.supply(&w[1], Ok(Some(vec![1u8; 8192])));
        s.supply(&w[2], Err("nope".into()));
        s.supply(&w[0], Ok(None));
        assert_eq!(s.range("t", 8192, 4096), Ok(Ok(vec![1u8; 4096])));
        assert_eq!(s.range("t", 20480, 10), Ok(Err("nope".into())));
        assert_eq!(s.file("m"), Ok(Ok(None)));
        assert_eq!(s.cost(), (3, 8192, 1));
        // Without merge, touching ranges stay apart; overlaps still coalesce.
        s.want_range("t", 40960, 4096);
        s.want_range("t", 45056, 4096);
        s.want_range("t", 45056 + 100, 4096);
        let w = s.take_wanted(false);
        assert_eq!(w.len(), 2);
        assert_eq!(
            w[1],
            Want::Range {
                rel: "t".into(),
                off: 45056,
                len: 4196
            }
        );
        assert_eq!(s.take_wanted(true), vec![]);
        assert_eq!(s.cost().2, 2);
        s.begin_read();
        assert_eq!(s.cost(), (0, 0, 0));
        assert_eq!(s.file("m"), Ok(Ok(None)), "files survive a read");
        assert_eq!(s.range("t", 8192, 4096), Err(Pending), "ranges do not");
    }
}
