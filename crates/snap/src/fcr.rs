//! The producer's fast-confirmation probe: when did a named RPC's `safe`
//! tag first reach the block a cycle published, and how far does that
//! `safe` trail `latest`. The answer is published as `head/fcr`, a note a
//! client shows beside an attested head and never trusts: fast
//! confirmation is a full node's judgement over all the attestations it
//! has seen, nothing a light client can check, so the client can only show
//! it as the producer's report from a named source.
//!
//! A probe is a background thread started at the epoch boundary, before
//! the cycle knows its block, polling `safe` and `latest` every
//! `--fcr-poll-secs`. Once the cycle names its block, the first poll whose
//! `safe` is at or past it is the confirmation, if the source's block at
//! that height is ours (otherwise a conflict). The thread ends at its
//! deadline whatever the source does, each request has its own timeout,
//! and nothing in the cycle waits on it: an outcome is collected when it
//! is there.
//!
//! What the probe establishes is two answers from the source, not a chain:
//! a `safe` block at or past our height, and our hash when asked for the
//! block at our height, in separate requests. A load-balanced source with
//! backends on different forks, or a reorg between the two, could give
//! both without our block ever being an ancestor of that `safe` block;
//! nothing here walks parents. It is a report, shown as one.
//!
//! The RPC URL may carry an API key (Ankr's does). Only its host is ever
//! logged, stored or published. An error is kept as its kind only (the
//! transport error's, the HTTP status, the JSON-RPC error code, a parse
//! failure), never as text the source or the HTTP client wrote, which
//! could quote the key; and the binary never lets the HTTP client's own
//! logs through, since they print the request's URI.

use alloy_primitives::B256;
use csl_eth_head::{FcrClass, FcrReport};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::JoinHandle,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

/// The env var read when `--fcr-rpc` is absent.
pub const ENV: &str = "CSL_ETH_FCR_RPC";

/// An RPC endpoint whose URL is never shown: `Debug` and every message
/// name its host only.
#[derive(Clone)]
pub struct Source {
    url: String,
    host: String,
}

/// A URL as typed, which may carry a key: it parses from anything (so clap
/// never echoes it in an error) and prints as `Secret(..)`.
#[derive(Clone)]
pub struct Secret(pub String);

impl std::str::FromStr for Secret {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Secret(s.to_string()))
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl std::fmt::Debug for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Source({})", self.host)
    }
}

impl Source {
    pub fn new(url: &str) -> Result<Source, String> {
        let url = url.trim();
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .ok_or("the FCR RPC must be an http(s) URL")?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        // Drop any userinfo (`user:key@host`) and the port.
        let host = authority.rsplit('@').next().unwrap_or("");
        let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
        if host.is_empty() {
            return Err("the FCR RPC URL has no host".into());
        }
        Ok(Source {
            url: url.to_string(),
            host,
        })
    }

    /// `--fcr-rpc` if given, else [`ENV`], else none.
    /// Errors name the flag or variable, never the URL.
    pub fn from_arg_or_env(arg: Option<&str>) -> Result<Option<Source>, String> {
        if let Some(u) = arg {
            return Source::new(u)
                .map(Some)
                .map_err(|e| format!("--fcr-rpc: {e}"));
        }
        match std::env::var(ENV).ok().filter(|s| !s.trim().is_empty()) {
            Some(u) => Source::new(&u).map(Some).map_err(|e| format!("{ENV}: {e}")),
            None => Ok(None),
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }
}

/// A request's failure as its kind, never its text: ureq's messages can
/// carry the URI (`BadUri`), and a TLS or I/O error's text is not ours to
/// vouch for.
fn transport(e: &ureq::Error) -> String {
    match e {
        ureq::Error::StatusCode(c) => format!("http {c}"),
        ureq::Error::Timeout(t) => format!("timeout ({t})"),
        ureq::Error::Io(e) => format!("io {:?}", e.kind()),
        ureq::Error::HostNotFound => "host not found".into(),
        ureq::Error::ConnectionFailed => "connection failed".into(),
        ureq::Error::Tls(_) => "tls".into(),
        ureq::Error::BodyExceedsLimit(_) => "response too large".into(),
        ureq::Error::Protocol(_) | ureq::Error::Http(_) => "http protocol".into(),
        _ => "transport".into(),
    }
}

/// A JSON-RPC error object as its code: its `message` and `data` are the
/// source's text, which may quote the URL or the key.
fn rpc_error(e: &Value) -> String {
    match e.get("code").and_then(Value::as_i64) {
        Some(c) => format!("rpc error {c}"),
        None => "rpc error".into(),
    }
}

/// A block as the source reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    pub number: u64,
    pub hash: B256,
}

/// What the probe asks of a source; an RPC in production, a script in
/// tests.
pub trait Rpc: Send + 'static {
    /// `eth_getBlockByNumber(tag, false)` for `safe`, `latest`, or a hex
    /// number. An error says what kind of failure it was, in words of our
    /// own (it is logged and published as is).
    fn block(&self, tag: &str) -> Result<Tip, String>;
}

/// JSON-RPC over HTTP with a per-request timeout.
pub struct Http {
    source: Source,
    agent: ureq::Agent,
}

impl Http {
    pub fn new(source: Source, timeout: Duration) -> Http {
        Http {
            source,
            agent: ureq::Agent::config_builder()
                .timeout_global(Some(timeout))
                .build()
                .into(),
        }
    }
}

impl Rpc for Http {
    fn block(&self, tag: &str) -> Result<Tip, String> {
        let body = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBlockByNumber",
            "params": [tag, false],
        });
        let host = self.source.host();
        let text = self
            .agent
            .post(&self.source.url)
            .header("Content-Type", "application/json")
            .send(body.to_string().as_bytes())
            .and_then(|mut r| r.body_mut().read_to_string())
            .map_err(|e| format!("{host}: {tag}: {}", transport(&e)))?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|_| format!("{host}: {tag}: the response is not JSON"))?;
        if let Some(e) = v.get("error") {
            return Err(format!("{host}: {tag}: {}", rpc_error(e)));
        }
        let r = &v["result"];
        let number = r["number"]
            .as_str()
            .and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok())
            .ok_or_else(|| format!("{host}: {tag}: no block number"))?;
        let hash = r["hash"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("{host}: {tag}: no block hash"))?;
        Ok(Tip { number, hash })
    }
}

/// The block a cycle published, set once the fetch knows it.
#[derive(Clone, Copy, Debug)]
pub struct Target {
    pub number: u64,
    pub hash: B256,
    /// The block's timestamp, unix seconds.
    pub timestamp: u64,
}

/// One poll: when, and what `safe` and `latest` were.
#[derive(Clone, Copy, Debug)]
struct Obs {
    at_ms: u64,
    safe: Tip,
    latest: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// `safe` reached our height, and the source returned our hash when
    /// asked for the block at that height (two answers, not a proof that
    /// our block is an ancestor of that `safe` block).
    Confirmed(FcrReport),
    /// `safe` reached our height, and the source's block there is not ours.
    Conflict { theirs: B256, after_secs: u64 },
    /// The deadline came first.
    Unreached {
        safe: Option<u64>,
        trail: Option<u64>,
    },
    /// The cycle that started it failed before naming its block.
    Cancelled,
}

#[derive(Debug, Clone)]
pub struct Report {
    pub outcome: Outcome,
    pub polls: u64,
    pub errors: u64,
    pub last_error: Option<String>,
    /// The smallest and largest `latest - safe` seen, in blocks.
    pub trail_range: Option<(u64, u64)>,
}

impl Report {
    /// The cycle JSON's view: the host and what happened, never the URL.
    pub fn json(&self, host: &str) -> Value {
        let mut v = json!({
            "source": host,
            "polls": self.polls,
            "errors": self.errors,
        });
        if let Some(e) = &self.last_error {
            v["last_error"] = json!(e);
        }
        if let Some((lo, hi)) = self.trail_range {
            v["trail_min"] = json!(lo);
            v["trail_max"] = json!(hi);
        }
        match &self.outcome {
            Outcome::Confirmed(r) => {
                v["outcome"] = json!("confirmed");
                v["classification"] = json!(r.classification.name());
                v["confirmed_after_secs"] = json!(r.confirmed_after_secs);
                v["trail_blocks"] = json!(r.trail_blocks);
                v["block_number"] = json!(r.block_number);
            }
            Outcome::Conflict { theirs, after_secs } => {
                v["outcome"] = json!("conflict");
                v["theirs"] = json!(theirs);
                v["after_secs"] = json!(after_secs);
            }
            Outcome::Unreached { safe, trail } => {
                v["outcome"] = json!("unreached");
                v["last_safe"] = json!(safe);
                v["last_trail"] = json!(trail);
            }
            Outcome::Cancelled => v["outcome"] = json!("cancelled"),
        }
        v
    }
}

/// A probe running in the background.
pub struct Probe {
    host: String,
    target: Arc<Mutex<Option<Target>>>,
    cancel: Arc<AtomicBool>,
    thread: Option<JoinHandle<Report>>,
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Probe {
    /// Poll `rpc` every `every` until `deadline_ms` (unix milliseconds).
    pub fn start(rpc: impl Rpc, host: &str, every: Duration, deadline_ms: u64) -> Probe {
        let target = Arc::new(Mutex::new(None));
        let cancel = Arc::new(AtomicBool::new(false));
        let (t, c, h) = (target.clone(), cancel.clone(), host.to_string());
        let thread = std::thread::spawn(move || run(&rpc, &h, every, deadline_ms, &t, &c));
        Probe {
            host: host.to_string(),
            target,
            cancel,
            thread: Some(thread),
        }
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// The block to look for.
    pub fn aim(&self, t: Target) {
        *self.target.lock().unwrap() = Some(t);
    }

    /// The block it was aimed at, if any.
    pub fn target(&self) -> Option<Target> {
        *self.target.lock().unwrap()
    }

    /// Stop at the next poll.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// The report once the thread has ended, without waiting.
    pub fn try_take(&mut self) -> Option<Report> {
        if !self.thread.as_ref()?.is_finished() {
            return None;
        }
        Some(self.thread.take()?.join().unwrap_or_else(|_| Report {
            outcome: Outcome::Cancelled,
            polls: 0,
            errors: 1,
            last_error: Some("the probe panicked".into()),
            trail_range: None,
        }))
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        self.cancel();
    }
}

fn run(
    rpc: &dyn Rpc,
    host: &str,
    every: Duration,
    deadline_ms: u64,
    target: &Mutex<Option<Target>>,
    cancel: &AtomicBool,
) -> Report {
    let mut obs: Vec<Obs> = Vec::new();
    let mut report = Report {
        outcome: Outcome::Cancelled,
        polls: 0,
        errors: 0,
        last_error: None,
        trail_range: None,
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            report.outcome = Outcome::Cancelled;
            return report;
        }
        if unix_ms() >= deadline_ms {
            let last = obs.last();
            report.outcome = Outcome::Unreached {
                safe: last.map(|o| o.safe.number),
                trail: last.map(|o| o.latest.saturating_sub(o.safe.number)),
            };
            return report;
        }
        let next = unix_ms() + every.as_millis() as u64;
        report.polls += 1;
        match rpc
            .block("safe")
            .and_then(|s| rpc.block("latest").map(|l| (s, l)))
        {
            Ok((safe, latest)) => {
                let o = Obs {
                    at_ms: unix_ms(),
                    safe,
                    latest: latest.number,
                };
                let trail = o.latest.saturating_sub(o.safe.number);
                report.trail_range = Some(match report.trail_range {
                    None => (trail, trail),
                    Some((lo, hi)) => (lo.min(trail), hi.max(trail)),
                });
                obs.push(o);
            }
            Err(e) => {
                report.errors += 1;
                report.last_error = Some(e);
            }
        }
        let aimed = *target.lock().unwrap();
        if let Some(t) = aimed {
            if let Some(first) = obs.iter().find(|o| o.safe.number >= t.number).copied() {
                let theirs = if first.safe.number == t.number {
                    Ok(first.safe.hash)
                } else {
                    rpc.block(&format!("0x{:x}", t.number)).map(|b| b.hash)
                };
                match theirs {
                    Ok(h) => {
                        report.outcome = decide(t, first, h, host);
                        return report;
                    }
                    Err(e) => {
                        report.errors += 1;
                        report.last_error = Some(e);
                    }
                }
            }
        }
        while unix_ms() < next.min(deadline_ms) && !cancel.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

/// The first poll with `safe` at or past our block, and the source's hash
/// at our height: a confirmation, or a conflict. When `safe` is past our
/// height the hash comes from a request of its own, so the two answers
/// may not be from one view of one chain.
fn decide(t: Target, first: Obs, theirs: B256, host: &str) -> Outcome {
    let after_secs = (first.at_ms / 1000).saturating_sub(t.timestamp);
    if theirs != t.hash {
        return Outcome::Conflict { theirs, after_secs };
    }
    let trail = first.latest.saturating_sub(first.safe.number);
    Outcome::Confirmed(FcrReport {
        block_hash: t.hash,
        block_number: t.number,
        confirmed_after_secs: after_secs,
        trail_blocks: trail,
        classification: FcrClass::of_trail(trail),
        source: host.to_string(),
        checked_at: first.at_ms / 1000,
    })
}

/// A local JSON-RPC server for tests that quotes a fake key back in every
/// way a real source might: in a JSON-RPC error's message and data, in an
/// HTTP error's body, in a body that is not JSON.
#[cfg(test)]
pub(crate) mod leaky {
    use std::io::{Read, Write};

    /// Obviously not a key.
    pub const KEY: &str = "FAKEKEYdeadbeef0123";

    /// What the server answers to every request.
    #[derive(Clone, Copy)]
    pub enum Answer {
        RpcError,
        Unauthorized,
        NotJson,
    }

    /// A server answering `answer` forever; the URL to reach it, with
    /// [`KEY`] in its path and its query.
    pub fn serve(answer: Answer) -> String {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for c in l.incoming() {
                let Ok(mut c) = c else { continue };
                // The request: headers, then as much body as it declares.
                let mut buf = Vec::new();
                let mut b = [0u8; 4096];
                while let Ok(n) = c.read(&mut b) {
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&b[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    if let Some(i) = text.find("\r\n\r\n") {
                        let len = text[..i]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                            })
                            .unwrap_or(0);
                        if buf.len() >= i + 4 + len {
                            break;
                        }
                    }
                }
                let (status, body) = match answer {
                    Answer::RpcError => (
                        "200 OK",
                        format!(
                            r#"{{"jsonrpc":"2.0","id":1,"error":{{"code":-32000,"message":"invalid API key {KEY} for /eth/{KEY}","data":"{KEY}"}}}}"#
                        ),
                    ),
                    Answer::Unauthorized => {
                        ("401 Unauthorized", format!("bad key {KEY} at /eth/{KEY}"))
                    }
                    Answer::NotJson => ("200 OK", format!("<html>key {KEY} is not valid</html>")),
                };
                let _ = write!(
                    c,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!("http://127.0.0.1:{port}/eth/{KEY}?apikey={KEY}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_host_is_ever_shown() {
        let s = Source::new("https://rpc.ankr.com/eth/0123456789abcdef?x=1").unwrap();
        assert_eq!(s.host(), "rpc.ankr.com");
        assert_eq!(format!("{s:?}"), "Source(rpc.ankr.com)");
        assert_eq!(
            Source::new("https://user:key@Host.example:8545/")
                .unwrap()
                .host(),
            "host.example"
        );
        assert!(Source::new("wss://x").is_err());
        assert!(Source::new("https:///path").is_err());
        let e =
            Source::from_arg_or_env(Some("wss://rpc.ankr.com/eth/0123456789abcdef")).unwrap_err();
        assert!(
            e.starts_with("--fcr-rpc") && !e.contains("0123456789abcdef"),
            "{e}"
        );
        let raw: Secret = "https://rpc.ankr.com/eth/0123456789abcdef".parse().unwrap();
        assert_eq!(format!("{raw:?}"), "Secret(..)");
    }

    /// A source following a script: `safe` and `latest` as functions of
    /// the poll count, and the hash it has at each height.
    struct Script {
        n: Mutex<u64>,
        safe: fn(u64) -> u64,
        lag: u64,
        ours: B256,
        fail: bool,
    }

    impl Rpc for Script {
        fn block(&self, tag: &str) -> Result<Tip, String> {
            if self.fail {
                return Err("rpc.example: 503".into());
            }
            let mut n = self.n.lock().unwrap();
            let hash_at = |num: u64| {
                if num == 100 {
                    self.ours
                } else {
                    B256::with_last_byte(num as u8)
                }
            };
            Ok(match tag {
                "safe" => {
                    *n += 1;
                    let s = (self.safe)(*n);
                    Tip {
                        number: s,
                        hash: hash_at(s),
                    }
                }
                "latest" => {
                    let s = (self.safe)(*n) + self.lag;
                    Tip {
                        number: s,
                        hash: hash_at(s),
                    }
                }
                hex => {
                    let num = u64::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap();
                    Tip {
                        number: num,
                        hash: hash_at(num),
                    }
                }
            })
        }
    }

    fn target(hash: B256) -> Target {
        Target {
            number: 100,
            hash,
            timestamp: unix_ms() / 1000,
        }
    }

    fn wait(mut p: Probe) -> Report {
        loop {
            if let Some(r) = p.try_take() {
                return r;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_trailing_safe_is_justified_and_a_close_one_fcr() {
        let ours = B256::repeat_byte(0xab);
        for (lag, class) in [(2, FcrClass::FcrLike), (40, FcrClass::JustifiedLike)] {
            let rpc = Script {
                n: Mutex::new(0),
                safe: |n| 96 + n,
                lag,
                ours,
                fail: false,
            };
            let p = Probe::start(
                rpc,
                "rpc.example",
                Duration::from_millis(10),
                unix_ms() + 5000,
            );
            p.aim(target(ours));
            let r = wait(p);
            let Outcome::Confirmed(c) = &r.outcome else {
                panic!("{r:?}");
            };
            assert_eq!(c.classification, class);
            assert_eq!(c.trail_blocks, lag);
            assert_eq!((c.block_number, c.block_hash), (100, ours));
            assert_eq!(c.source, "rpc.example");
            assert!(r.polls >= 4, "{}", r.polls);
            assert_eq!(r.json("rpc.example")["classification"], class.name());
        }
    }

    #[test]
    fn another_block_at_our_height_is_a_conflict() {
        let rpc = Script {
            n: Mutex::new(0),
            safe: |n| 98 + 2 * n,
            lag: 2,
            ours: B256::repeat_byte(0xab),
            fail: false,
        };
        let p = Probe::start(
            rpc,
            "rpc.example",
            Duration::from_millis(10),
            unix_ms() + 5000,
        );
        p.aim(target(B256::repeat_byte(0xcd)));
        let r = wait(p);
        assert!(
            matches!(r.outcome, Outcome::Conflict { theirs, .. } if theirs == B256::repeat_byte(0xab)),
            "{r:?}"
        );
    }

    #[test]
    fn a_failing_or_slow_source_ends_at_its_deadline() {
        let t0 = std::time::Instant::now();
        let rpc = Script {
            n: Mutex::new(0),
            safe: |n| n,
            lag: 40,
            ours: B256::ZERO,
            fail: true,
        };
        let p = Probe::start(
            rpc,
            "rpc.example",
            Duration::from_millis(50),
            unix_ms() + 400,
        );
        p.aim(target(B256::ZERO));
        let r = wait(p);
        assert!(
            matches!(r.outcome, Outcome::Unreached { safe: None, .. }),
            "{r:?}"
        );
        assert!(r.errors >= 2 && r.last_error.as_deref() == Some("rpc.example: 503"));
        assert!(
            t0.elapsed() < Duration::from_millis(1500),
            "{:?}",
            t0.elapsed()
        );
        // Never reaching our block: unreached at the deadline, with the
        // last trail seen.
        let rpc = Script {
            n: Mutex::new(0),
            safe: |_| 50,
            lag: 40,
            ours: B256::ZERO,
            fail: false,
        };
        let p = Probe::start(
            rpc,
            "rpc.example",
            Duration::from_millis(50),
            unix_ms() + 300,
        );
        p.aim(target(B256::ZERO));
        let r = wait(p);
        assert_eq!(
            r.outcome,
            Outcome::Unreached {
                safe: Some(50),
                trail: Some(40)
            }
        );
        // Cancelled when the cycle fails.
        let rpc = Script {
            n: Mutex::new(0),
            safe: |_| 50,
            lag: 40,
            ours: B256::ZERO,
            fail: false,
        };
        let p = Probe::start(
            rpc,
            "rpc.example",
            Duration::from_millis(50),
            unix_ms() + 60_000,
        );
        p.cancel();
        assert_eq!(wait(p).outcome, Outcome::Cancelled);
    }

    #[test]
    fn a_key_in_the_url_or_quoted_back_never_reaches_a_report() {
        use leaky::{serve, Answer, KEY};
        // Nothing listens on the port of a dropped listener: a connection
        // refused, whose error text would name the address.
        let refused = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let port = l.local_addr().unwrap().port();
            format!("http://127.0.0.1:{port}/eth/{KEY}?apikey={KEY}")
        };
        for (url, want) in [
            (serve(Answer::RpcError), "127.0.0.1: safe: rpc error -32000"),
            (serve(Answer::Unauthorized), "127.0.0.1: safe: http 401"),
            (
                serve(Answer::NotJson),
                "127.0.0.1: safe: the response is not JSON",
            ),
            (refused, "127.0.0.1: safe: "),
        ] {
            let src = Source::new(&url).unwrap();
            assert!(!format!("{src:?}").contains(KEY));
            let http = Http::new(src.clone(), Duration::from_secs(5));
            let e = http.block("safe").unwrap_err();
            assert!(e.starts_with(want) && !e.contains(KEY), "{e}");
            // Through a probe: its report, as Debug and as the cycle's
            // JSON, says the kind and the host, never the key.
            let p = Probe::start(
                Http::new(src, Duration::from_secs(5)),
                "127.0.0.1",
                Duration::from_millis(50),
                unix_ms() + 300,
            );
            p.aim(target(B256::ZERO));
            let r = wait(p);
            assert!(r.errors >= 1, "{r:?}");
            for out in [format!("{r:?}"), r.json("127.0.0.1").to_string()] {
                assert!(!out.contains(KEY), "{out}");
                assert!(!out.contains("/eth/"), "{out}");
            }
            assert!(r.last_error.as_deref().is_some_and(|e| e.starts_with(want)));
        }
    }
}
