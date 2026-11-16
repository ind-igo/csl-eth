//! The tracker's base, read from the bucket by byte range instead of a
//! local copy.
//!
//! A tracker without the 344 GiB base on disk still needs the old side of
//! a diff: the held state's node at each changed position. Peers serve it
//! at the parent root while that root is inside their window (about 128
//! blocks). After a longer gap the old root is gone from every peer, and
//! the base's nodes are read here from the runs this project published:
//! one ranged GET per page, many in flight at once. Every node is checked
//! against the hash its parent committed to, so a bucket that serves wrong
//! bytes costs a lookup, never a wrong diff.
//!
//! The run reader is synchronous; here it reads from a page cache, and a
//! page it lacks is recorded and reported as pending. A batch of lookups
//! runs, the pages they want are fetched concurrently, and the batch runs
//! again until every lookup is answered (at most a few rounds: page 0, a
//! model page, a data page, a neighbour when the model's guess was off).

use crate::heal::Need;
use alloy_primitives::{keccak256, Bytes};
use csl_eth_store::{Manifest, RUN_FORMAT, TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES};
use csl_eth_trie::NodeKey;
use csl_run::Reader;
use futures::StreamExt;
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};

/// Bytes of a file by range: the bucket over HTTPS, or a directory (tests).
pub trait RangeGet: Send + Sync + 'static {
    /// `len` bytes of `rel` at `off` (blocking).
    fn get(&self, rel: &str, off: u64, len: usize) -> Result<Vec<u8>, String>;
    /// All of `rel` (a manifest).
    fn file(&self, rel: &str) -> Result<Vec<u8>, String>;
}

/// A public bucket prefix, e.g.
/// `https://storage.googleapis.com/csl-eth-demo/full/`.
pub struct HttpRanges {
    base: String,
    agent: ureq::Agent,
}

impl HttpRanges {
    pub fn new(base: &str) -> HttpRanges {
        let base = if base.ends_with('/') {
            base.to_string()
        } else {
            format!("{base}/")
        };
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .build()
            .into();
        HttpRanges { base, agent }
    }
}

impl RangeGet for HttpRanges {
    fn get(&self, rel: &str, off: u64, len: usize) -> Result<Vec<u8>, String> {
        let url = format!("{}{rel}", self.base);
        let range = format!("bytes={}-{}", off, off + len as u64 - 1);
        let mut last = String::new();
        for _ in 0..3 {
            match self.agent.get(&url).header("Range", &range).call() {
                Ok(r) => {
                    let b = r
                        .into_body()
                        .with_config()
                        .limit(len as u64 + 1)
                        .read_to_vec()
                        .map_err(|e| format!("{rel}: {e}"))?;
                    // A short body is the file's end; the reader decides.
                    return Ok(b);
                }
                Err(e) => last = format!("{rel}@{off}: {e}"),
            }
        }
        Err(last)
    }

    fn file(&self, rel: &str) -> Result<Vec<u8>, String> {
        let url = format!("{}{rel}", self.base);
        self.agent
            .get(&url)
            .call()
            .map_err(|e| format!("{url}: {e}"))?
            .into_body()
            .with_config()
            .limit(64 << 20)
            .read_to_vec()
            .map_err(|e| format!("{url}: {e}"))
    }
}

/// A directory standing in for the bucket.
pub struct DirRanges(pub PathBuf);

impl RangeGet for DirRanges {
    fn get(&self, rel: &str, off: u64, len: usize) -> Result<Vec<u8>, String> {
        use std::os::unix::fs::FileExt;
        let f = std::fs::File::open(self.0.join(rel)).map_err(|e| format!("{rel}: {e}"))?;
        let mut b = vec![0u8; len];
        let mut done = 0;
        while done < len {
            let n = f
                .read_at(&mut b[done..], off + done as u64)
                .map_err(|e| format!("{rel}: {e}"))?;
            if n == 0 {
                break;
            }
            done += n;
        }
        b.truncate(done);
        Ok(b)
    }

    fn file(&self, rel: &str) -> Result<Vec<u8>, String> {
        std::fs::read(self.0.join(rel)).map_err(|e| format!("{rel}: {e}"))
    }
}

/// Pages a batch has fetched, and the ones it asked for and lacked.
#[derive(Default)]
struct Pages {
    got: HashMap<(usize, u64), Arc<Vec<u8>>>,
    wanted: HashSet<(usize, u64, usize)>,
}

/// One run's view of the page cache, for the run reader.
struct Part {
    pages: Arc<Mutex<Pages>>,
    run: usize,
}

const PENDING: &str = "csl-eth: page pending";

impl csl_run::Source for Part {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, csl_run::Error> {
        let mut p = self.pages.lock().expect("pages");
        if let Some(b) = p.got.get(&(self.run, off)) {
            if b.len() >= len {
                return Ok(b[..len].to_vec());
            }
            // The file ends here: the reader reports a short read.
            return Ok(b.to_vec());
        }
        p.wanted.insert((self.run, off, len));
        Err(csl_run::Error::Io(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            PENDING,
        )))
    }
}

fn pending(e: &csl_run::Error) -> bool {
    matches!(e, csl_run::Error::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock)
}

/// The base's runs, read by range.
pub struct RemoteBase {
    get: Arc<dyn RangeGet>,
    pages: Arc<Mutex<Pages>>,
    /// Per table (account, storage): the run's path and its reader.
    runs: [Vec<(String, Reader<Part>)>; 2],
    paths: Vec<String>,
    /// Pages fetched, and their bytes.
    pub requests: u64,
    pub bytes: u64,
    pub failures: u64,
    /// Requests in flight at once.
    pub parallel: usize,
}

/// Fetched pages kept between batches; past this the cache starts over
/// (the readers keep their verified model pages).
const PAGE_CACHE: usize = 65_536;
/// Rounds of fetching per batch, and rounds in a row without a page.
const MAX_ROUNDS: usize = 64;
const IDLE_ROUNDS: usize = 3;

impl RemoteBase {
    /// The base tables of `manifest` (its plain tables, not its layers).
    pub fn new(get: Arc<dyn RangeGet>, manifest: &Manifest) -> Result<RemoteBase, String> {
        let pages = Arc::new(Mutex::new(Pages::default()));
        let mut runs: [Vec<(String, Reader<Part>)>; 2] = Default::default();
        let mut paths = Vec::new();
        for (i, t) in [TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES]
            .into_iter()
            .enumerate()
        {
            for at in manifest.runs(t) {
                if at.layer.is_some() {
                    continue;
                }
                let mut rref = at.table.run_ref(at.block_lo);
                rref.block_hi = at.block_hi;
                let part = Part {
                    pages: pages.clone(),
                    run: paths.len(),
                };
                let r = Reader::try_with_format(part, rref, RUN_FORMAT)
                    .map_err(|e| format!("{}: {e}", at.path))?;
                paths.push(at.path.clone());
                runs[i].push((at.path.clone(), r));
            }
        }
        Ok(RemoteBase {
            get,
            pages,
            runs,
            paths,
            requests: 0,
            bytes: 0,
            failures: 0,
            parallel: 128,
        })
    }

    /// One lookup against the cache: the node, none, or pending.
    fn lookup(&mut self, n: &Need) -> Result<Option<Bytes>, bool> {
        let nk = NodeKey::prefix(&n.path, n.path.len());
        let (t, key) = match n.owner {
            None => (0, nk.table_key()),
            Some(o) => (1, nk.storage_table_key(&o)),
        };
        let Ok(key) = key else { return Ok(None) };
        let mut wait = false;
        for (_, r) in self.runs[t].iter_mut() {
            if let Err(e) = r.prepare() {
                if pending(&e) {
                    wait = true;
                }
                continue;
            }
            match r.get_entry(&key) {
                Ok((Some(e), _)) if e.tag == 0 && keccak256(&e.value) == n.hash => {
                    return Ok(Some(Bytes::from(e.value)));
                }
                Ok(_) => {}
                Err(e) if pending(&e) => wait = true,
                Err(_) => {}
            }
        }
        Err(wait)
    }

    /// The nodes the base holds for `needs`, by need index, each checked
    /// against its hash. A need the base lacks, or whose pages do not
    /// verify, is left out.
    pub async fn nodes(&mut self, needs: &[Need]) -> Result<HashMap<usize, Bytes>, String> {
        {
            let mut p = self.pages.lock().expect("pages");
            if p.got.len() > PAGE_CACHE {
                p.got.clear();
            }
        }
        let mut out = HashMap::new();
        let mut open: Vec<usize> = (0..needs.len()).collect();
        let mut missed = false;
        // A cold lookup may walk several model pages in turn: go on while
        // pages come, and stop after a few rounds in which none did.
        let mut idle = 0;
        for _ in 0..MAX_ROUNDS {
            let mut next = Vec::new();
            for i in open {
                match self.lookup(&needs[i]) {
                    Ok(Some(b)) => {
                        out.insert(i, b);
                    }
                    Ok(None) | Err(false) => missed = true,
                    Err(true) => next.push(i),
                }
            }
            open = next;
            if open.is_empty() {
                break;
            }
            if self.fill().await == 0 {
                idle += 1;
                if idle >= IDLE_ROUNDS {
                    break;
                }
            } else {
                idle = 0;
            }
        }
        // An old node the base should hold and did not answer: its pages
        // may have come short or wrong. Drop the fetched pages so the next
        // ask fetches them again (the readers keep their verified models).
        if missed || !open.is_empty() {
            self.pages.lock().expect("pages").got.clear();
        }
        Ok(out)
    }

    /// Fetch every wanted page, `parallel` at a time; how many came.
    async fn fill(&mut self) -> usize {
        let wanted: Vec<(usize, u64, usize)> = {
            let mut p = self.pages.lock().expect("pages");
            p.wanted.drain().collect()
        };
        let jobs = wanted.into_iter().map(|(run, off, len)| {
            let get = self.get.clone();
            let rel = self.paths[run].clone();
            async move {
                let r = tokio::task::spawn_blocking(move || get.get(&rel, off, len))
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| r);
                ((run, off), r)
            }
        });
        // A page that fails to come leaves its lookups pending for the
        // next round; past the rounds they are left out.
        let mut s = futures::stream::iter(jobs).buffer_unordered(self.parallel.max(1));
        let mut came = 0;
        while let Some(((run, off), r)) = s.next().await {
            match r {
                Ok(b) => {
                    came += 1;
                    self.requests += 1;
                    self.bytes += b.len() as u64;
                    self.pages
                        .lock()
                        .expect("pages")
                        .got
                        .insert((run, off), Arc::new(b));
                }
                Err(e) => {
                    self.failures += 1;
                    tracing::debug!(error = %e, "base page");
                }
            }
        }
        came
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::heal::{shape, Ref, Shape};
    use alloy_primitives::B256;
    use csl_eth_trie::Nibbles;

    /// Against the real bucket (`CSL_TRACK_BASE_URL`, e.g.
    /// `https://storage.googleapis.com/csl-eth-demo/full/`, and
    /// `CSL_TRACK_BASE` the base's block hash): the root node and every
    /// child of it and of its children, by range, checked by hash.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn remote_base_reads_the_bucket() {
        let url = std::env::var("CSL_TRACK_BASE_URL").expect("CSL_TRACK_BASE_URL");
        let base: B256 = std::env::var("CSL_TRACK_BASE")
            .expect("CSL_TRACK_BASE")
            .parse()
            .unwrap();
        let get = Arc::new(HttpRanges::new(&url));
        let m =
            Manifest::from_json(&get.file(&csl_eth_store::manifest_path(&base)).unwrap()).unwrap();
        let mut rb = RemoteBase::new(get, &m).unwrap();
        let mut level = vec![Need {
            owner: None,
            path: Nibbles::default(),
            hash: m.state_root,
        }];
        for depth in 0..3 {
            let t = std::time::Instant::now();
            let got = rb.nodes(&level).await.unwrap();
            eprintln!(
                "depth {depth}: {} of {} nodes in {:.2} s, {} requests so far, {} KiB",
                got.len(),
                level.len(),
                t.elapsed().as_secs_f64(),
                rb.requests,
                rb.bytes >> 10
            );
            assert_eq!(got.len(), level.len(), "every node at depth {depth}");
            let mut next = Vec::new();
            for (i, b) in got {
                if let Ok(Shape::Inner(kids)) = shape(&level[i].path, &b) {
                    for (q, r) in kids {
                        if let Ref::Hash(h) = r {
                            next.push(Need {
                                owner: None,
                                path: q,
                                hash: h,
                            });
                        }
                    }
                }
            }
            level = next;
        }
    }
}
