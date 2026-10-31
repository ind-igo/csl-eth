//! A bucket behind HTTP: files by GET, runs by `Range` requests. A round's
//! wants fan out over threads, one request each, so a round is one round
//! trip however many ranges it has. Nothing here verifies anything: the
//! reader hashes every page and the walk every node, as for any source.
//! An optional proxy URL (`socks5h://host:port`, `http://host:port`)
//! covers hosts reached through a tunnel.

use crate::{Driver, Got, Want};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

#[derive(Clone)]
pub struct HttpDriver {
    base: String,
    agent: ureq::Agent,
    /// Threads a round may use at once.
    pub parallel: usize,
    /// HTTP requests made and bytes received through this driver, for the
    /// session's totals.
    pub requests: Arc<AtomicU64>,
    pub bytes: Arc<AtomicU64>,
}

impl HttpDriver {
    pub fn new(base: &str, proxy: Option<&str>) -> Result<HttpDriver, String> {
        let mut cfg = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .max_idle_connections_per_host(64)
            .max_idle_connections(128);
        if let Some(p) = proxy {
            cfg = cfg.proxy(Some(ureq::Proxy::new(p).map_err(|e| e.to_string())?));
        }
        Ok(HttpDriver {
            base: base.trim_end_matches('/').to_string(),
            agent: cfg.build().new_agent(),
            parallel: 32,
            requests: Arc::new(AtomicU64::new(0)),
            bytes: Arc::new(AtomicU64::new(0)),
        })
    }

    fn url(&self, rel: &str) -> String {
        format!("{}/{}", self.base, rel)
    }

    fn get_range(&self, url: &str, off: u64, len: usize) -> Result<Vec<u8>, String> {
        let end = off + len as u64 - 1;
        let mut resp = self
            .agent
            .get(url)
            .header("Range", &format!("bytes={off}-{end}"))
            .call()
            .map_err(|e| format!("GET {url} [{off}..={end}]: {e}"))?;
        if resp.status() != 206 {
            return Err(format!("GET {url}: status {} for a range", resp.status()));
        }
        // ureq's limit is exclusive: a body of exactly `limit` bytes is "too
        // large". One byte of slack, then the length is checked here.
        let v = resp
            .body_mut()
            .with_config()
            .limit(len as u64 + 1)
            .read_to_vec()
            .map_err(|e| format!("GET {url} body: {e}"))?;
        if v.len() != len {
            return Err(format!(
                "GET {url}: short range, {} of {len} bytes",
                v.len()
            ));
        }
        Ok(v)
    }

    fn get_file(&self, url: &str) -> Got {
        match self.agent.get(url).call() {
            Ok(mut resp) => {
                let v = resp
                    .body_mut()
                    .with_config()
                    .limit(64 * 1024 * 1024)
                    .read_to_vec()
                    .map_err(|e| format!("GET {url} body: {e}"))?;
                Ok(Some(v))
            }
            Err(ureq::Error::StatusCode(404)) => Ok(None),
            Err(e) => Err(format!("GET {url}: {e}")),
        }
    }

    fn one(&self, w: &Want) -> Got {
        let got = match w {
            Want::File { rel } => self.get_file(&self.url(rel)),
            Want::Range { rel, off, len } => self.get_range(&self.url(rel), *off, *len).map(Some),
        };
        self.requests.fetch_add(1, Ordering::Relaxed);
        if let Ok(Some(v)) = &got {
            self.bytes.fetch_add(v.len() as u64, Ordering::Relaxed);
        }
        got
    }
}

impl Driver for HttpDriver {
    fn fetch(&self, wants: &[Want]) -> Vec<Got> {
        if wants.len() <= 1 {
            return wants.iter().map(|w| self.one(w)).collect();
        }
        let chunk = wants.len().div_ceil(self.parallel.max(1));
        std::thread::scope(|sc| {
            let handles: Vec<_> = wants
                .chunks(chunk)
                .map(|part| {
                    sc.spawn(move || part.iter().map(|w| self.one(w)).collect::<Vec<Got>>())
                })
                .collect();
            handles
                .into_iter()
                .flat_map(|h| h.join().unwrap_or_default())
                .collect()
        })
    }
}
