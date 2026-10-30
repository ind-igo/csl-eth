//! A bucket behind HTTP: files by GET, runs by `Range` requests. A
//! prefetch hint starts a round: it fans its ranges out over threads, one
//! request each, and the reads of that round are served from what came
//! back; a read of anything else is one synchronous request, kept for the
//! round as well. Nothing here verifies
//! anything: the reader hashes every page and the walk every node, as for
//! any source. An optional proxy URL (`socks5h://host:port`,
//! `http://host:port`) covers hosts reached through a tunnel.

use crate::{Bucket, Prefetch};
use csl_run::{Error, Source};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

pub struct HttpBucket {
    base: String,
    agent: ureq::Agent,
    /// Threads a prefetch may use at once.
    pub parallel: usize,
    /// HTTP requests made and bytes received by every run opened from
    /// this bucket, for comparison with the reader's logical counts.
    pub requests: Arc<AtomicU64>,
    pub bytes: Arc<AtomicU64>,
    /// Distinct ranges handed to `prefetch`, over all hints: the pages a
    /// speculative round touches once each.
    pub hinted: Arc<AtomicU64>,
}

impl HttpBucket {
    pub fn new(base: &str, proxy: Option<&str>) -> Result<HttpBucket, String> {
        let mut cfg = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_idle_connections_per_host(64)
            .max_idle_connections(128);
        if let Some(p) = proxy {
            cfg = cfg.proxy(Some(ureq::Proxy::new(p).map_err(|e| e.to_string())?));
        }
        Ok(HttpBucket {
            base: base.trim_end_matches('/').to_string(),
            agent: cfg.build().new_agent(),
            parallel: 32,
            requests: Arc::new(AtomicU64::new(0)),
            bytes: Arc::new(AtomicU64::new(0)),
            hinted: Arc::new(AtomicU64::new(0)),
        })
    }

    fn url(&self, rel: &str) -> String {
        format!("{}/{}", self.base, rel)
    }
}

fn get_range(agent: &ureq::Agent, url: &str, off: u64, len: usize) -> Result<Vec<u8>, Error> {
    let io = |m: String| Error::Io(std::io::Error::other(m));
    let end = off + len as u64 - 1;
    let mut resp = agent
        .get(url)
        .header("Range", &format!("bytes={off}-{end}"))
        .call()
        .map_err(|e| io(format!("GET {url} [{off}..={end}]: {e}")))?;
    if resp.status() != 206 {
        return Err(io(format!(
            "GET {url}: status {} for a range",
            resp.status()
        )));
    }
    // ureq's limit is exclusive: a body of exactly `limit` bytes is "too
    // large". One byte of slack, then the length is checked here.
    let v = resp
        .body_mut()
        .with_config()
        .limit(len as u64 + 1)
        .read_to_vec()
        .map_err(|e| io(format!("GET {url} body: {e}")))?;
    if v.len() != len {
        return Err(Error::ShortRead {
            off,
            want: len,
            got: v.len(),
        });
    }
    Ok(v)
}

pub struct HttpRun {
    agent: ureq::Agent,
    url: String,
    parallel: usize,
    ready: Mutex<HashMap<(u64, usize), Vec<u8>>>,
    requests: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
    hinted: Arc<AtomicU64>,
}

impl Source for HttpRun {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        if let Some(v) = self.ready.lock().unwrap().get(&(off, len)) {
            return Ok(v.clone());
        }
        let v = get_range(&self.agent, &self.url, off, len)?;
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(v.len() as u64, Ordering::Relaxed);
        // Kept for the rest of this round: the depths of one path share
        // pages, and the walk from a predicted page lands on neighbours
        // another depth may predict.
        self.ready.lock().unwrap().insert((off, len), v.clone());
        Ok(v)
    }
}

impl Prefetch for HttpRun {
    /// Pages held are one read's (`forget` starts a read), a few dozen at
    /// most.
    fn forget(&self) {
        self.ready.lock().unwrap().clear();
    }

    fn prefetch(&self, ranges: &[(u64, usize)]) {
        let todo: Vec<(u64, usize)> = {
            let ready = self.ready.lock().unwrap();
            ranges
                .iter()
                .copied()
                .filter(|r| !ready.contains_key(r))
                .collect()
        };
        self.hinted
            .fetch_add(ranges.len() as u64, Ordering::Relaxed);
        if todo.is_empty() {
            return;
        }
        let chunk = todo.len().div_ceil(self.parallel.max(1));
        std::thread::scope(|sc| {
            let handles: Vec<_> = todo
                .chunks(chunk)
                .map(|part| {
                    sc.spawn(move || {
                        let mut got = Vec::with_capacity(part.len());
                        for &(off, len) in part {
                            if let Ok(v) = get_range(&self.agent, &self.url, off, len) {
                                self.requests.fetch_add(1, Ordering::Relaxed);
                                self.bytes.fetch_add(v.len() as u64, Ordering::Relaxed);
                                got.push(((off, len), v));
                            }
                        }
                        got
                    })
                })
                .collect();
            let mut ready = self.ready.lock().unwrap();
            for h in handles {
                for (k, v) in h.join().unwrap_or_default() {
                    ready.insert(k, v);
                }
            }
        });
    }
}

impl Bucket for HttpBucket {
    type Run = HttpRun;

    fn open_run(&self, rel: &str) -> Result<HttpRun, String> {
        Ok(HttpRun {
            agent: self.agent.clone(),
            url: self.url(rel),
            parallel: self.parallel,
            ready: Mutex::new(HashMap::new()),
            requests: self.requests.clone(),
            bytes: self.bytes.clone(),
            hinted: self.hinted.clone(),
        })
    }

    fn read_file(&self, rel: &str) -> Result<Vec<u8>, String> {
        let url = self.url(rel);
        let mut resp = self
            .agent
            .get(&url)
            .call()
            .map_err(|e| format!("GET {url}: {e}"))?;
        let v = resp
            .body_mut()
            .with_config()
            .limit(64 * 1024 * 1024)
            .read_to_vec()
            .map_err(|e| format!("GET {url} body: {e}"))?;
        self.requests.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(v.len() as u64, Ordering::Relaxed);
        Ok(v)
    }
}
