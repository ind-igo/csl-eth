//! The client in the browser. The read path is synchronous (one hint, then
//! the fetches the reader asks for as it walks), so the module runs in a
//! Web Worker, where a synchronous `XMLHttpRequest` is allowed: the worker
//! defines `globalThis.cslFetch(url, offset, len)` and this crate's bucket
//! calls it for every file and byte range. Nothing on the JavaScript side
//! verifies anything; it transports bytes and renders results. Every
//! answer here is the same `csl-eth-client` answer the CLI gives, with the
//! head verified in the tab from one checkpoint root.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use csl_eth_client::{open_at_head, Bucket, Cost, Hint, Prefetch, Read, Snapshot, VerifiedHead};
use csl_run::{Error, Source};
use js_sys::{Reflect, Uint8Array};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime},
};
use wasm_bindgen::{prelude::*, JsCast};

#[wasm_bindgen]
extern "C" {
    /// `globalThis.cslFetch(url, offset, len)`: a synchronous GET, with
    /// `Range: bytes=offset-(offset+len-1)` when both are numbers. Returns
    /// `{status, body: Uint8Array}` or `{status: 0, error}`.
    #[wasm_bindgen(catch, js_namespace = globalThis, js_name = cslFetch)]
    fn csl_fetch(url: &str, offset: JsValue, len: JsValue) -> Result<JsValue, JsValue>;

    #[wasm_bindgen(js_namespace = console, js_name = error)]
    fn console_error(message: &str);
}

fn panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            console_error(&format!("csl-eth-wasm: {info}"))
        }));
    });
}

fn describe(v: &JsValue) -> String {
    v.as_string()
        .or_else(|| {
            v.dyn_ref::<js_sys::Error>()
                .map(|e| String::from(e.message()))
        })
        .unwrap_or_else(|| format!("{v:?}"))
}

fn field(v: &JsValue, name: &str) -> JsValue {
    Reflect::get(v, &JsValue::from_str(name)).unwrap_or(JsValue::UNDEFINED)
}

/// One request as the page sees it.
#[derive(Clone)]
struct Req {
    rel: String,
    range: Option<(u64, usize)>,
    status: u16,
    bytes: usize,
    ms: f64,
}

#[derive(Default)]
struct Counters {
    requests: AtomicU64,
    bytes: AtomicU64,
    log: Mutex<Vec<Req>>,
}

fn now_ms() -> f64 {
    js_sys::Date::now()
}

/// GET `url`, whole or one range. The status is the caller's to judge.
fn get(
    c: &Counters,
    base: &str,
    rel: &str,
    range: Option<(u64, usize)>,
) -> Result<(u16, Vec<u8>), String> {
    let url = format!("{base}/{rel}");
    let (off, len) = match range {
        Some((o, l)) => (JsValue::from_f64(o as f64), JsValue::from_f64(l as f64)),
        None => (JsValue::NULL, JsValue::NULL),
    };
    let t0 = now_ms();
    let r = csl_fetch(&url, off, len).map_err(|e| format!("cslFetch threw: {}", describe(&e)))?;
    let status = field(&r, "status")
        .as_f64()
        .ok_or("cslFetch result has no status")? as u16;
    if status == 0 {
        let e = field(&r, "error");
        let e = if e.is_undefined() || e.is_null() {
            "network error".to_string()
        } else {
            describe(&e)
        };
        c.log.lock().unwrap().push(Req {
            rel: rel.to_string(),
            range,
            status: 0,
            bytes: 0,
            ms: now_ms() - t0,
        });
        return Err(format!("GET {rel}: {e}"));
    }
    let body = field(&r, "body");
    let body = if body.is_null() || body.is_undefined() {
        Vec::new()
    } else {
        body.dyn_into::<Uint8Array>()
            .map_err(|_| "cslFetch body is not a Uint8Array")?
            .to_vec()
    };
    c.requests.fetch_add(1, Ordering::Relaxed);
    c.bytes.fetch_add(body.len() as u64, Ordering::Relaxed);
    c.log.lock().unwrap().push(Req {
        rel: rel.to_string(),
        range,
        status,
        bytes: body.len(),
        ms: now_ms() - t0,
    });
    Ok((status, body))
}

/// The bucket behind a base URL, read through `cslFetch`.
pub struct JsBucket {
    base: String,
    c: Arc<Counters>,
}

impl Bucket for JsBucket {
    type Run = JsRun;
    fn open_run(&self, rel: &str) -> Result<JsRun, String> {
        Ok(JsRun {
            base: self.base.clone(),
            rel: rel.to_string(),
            ready: Mutex::new(BTreeMap::new()),
            c: self.c.clone(),
        })
    }
    fn read_file(&self, rel: &str) -> Result<Vec<u8>, String> {
        match get(&self.c, &self.base, rel, None)? {
            (200, v) => Ok(v),
            (s, _) => Err(format!("GET {rel}: status {s}")),
        }
    }
    fn read_file_opt(&self, rel: &str) -> Result<Option<Vec<u8>>, String> {
        match get(&self.c, &self.base, rel, None)? {
            (200, v) => Ok(Some(v)),
            (404, _) => Ok(None),
            (s, _) => Err(format!("GET {rel}: status {s}")),
        }
    }
}

/// One run file: ranges by `Range` request, a hinted round kept until the
/// next read begins. Requests are sequential (one synchronous XHR at a
/// time); merged ranges keep their number small.
pub struct JsRun {
    base: String,
    rel: String,
    ready: Mutex<BTreeMap<u64, Vec<u8>>>,
    c: Arc<Counters>,
}

fn covered(ready: &BTreeMap<u64, Vec<u8>>, off: u64, len: usize) -> Option<Vec<u8>> {
    let (start, v) = ready.range(..=off).next_back()?;
    let lo = (off - start) as usize;
    v.get(lo..lo + len).map(<[u8]>::to_vec)
}

impl JsRun {
    fn range(&self, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        let io = |m: String| Error::Io(std::io::Error::other(m));
        let (status, v) = get(&self.c, &self.base, &self.rel, Some((off, len))).map_err(io)?;
        if status != 206 {
            return Err(io(format!("GET {}: status {status} for a range", self.rel)));
        }
        if v.len() != len {
            return Err(Error::ShortRead {
                off,
                want: len,
                got: v.len(),
            });
        }
        Ok(v)
    }
}

impl Source for JsRun {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        if let Some(v) = covered(&self.ready.lock().unwrap(), off, len) {
            return Ok(v);
        }
        let v = self.range(off, len)?;
        self.ready.lock().unwrap().insert(off, v.clone());
        Ok(v)
    }
}

impl Prefetch for JsRun {
    fn forget(&self) {
        self.ready.lock().unwrap().clear();
    }
    fn prefetch(&self, ranges: &[(u64, usize)]) {
        for &(off, len) in ranges {
            if covered(&self.ready.lock().unwrap(), off, len).is_some() {
                continue;
            }
            // Errors here are not errors: the read that needs the page
            // asks again and reports.
            if let Ok(v) = self.range(off, len) {
                self.ready.lock().unwrap().insert(off, v);
            }
        }
    }
}

fn parse_b256(s: &str, what: &str) -> Result<B256, String> {
    let h = s.trim().trim_start_matches("0x");
    if h.len() != 64 {
        return Err(format!("{what}: expected 32 bytes of hex"));
    }
    hex::decode(h)
        .map(|v| B256::from_slice(&v))
        .map_err(|e| format!("{what}: {e}"))
}

/// An address (20 bytes) hashes to its trie key; 32 bytes is the hashed
/// key itself (what a slice's sampler produces).
fn account_key(s: &str) -> Result<(B256, Option<String>), String> {
    let h = s.trim().trim_start_matches("0x");
    match h.len() {
        40 => {
            let a = hex::decode(h).map_err(|e| format!("address: {e}"))?;
            Ok((keccak256(&a), Some(format!("0x{}", h.to_lowercase()))))
        }
        64 => Ok((parse_b256(h, "hashed key")?, None)),
        _ => Err("expected an address (20 bytes) or a hashed key (32 bytes)".into()),
    }
}

fn slot_key(s: &str) -> Result<B256, String> {
    let t = s.trim();
    let v = if let Some(h) = t.strip_prefix("0x") {
        U256::from_str_radix(h, 16).map_err(|e| format!("slot: {e}"))?
    } else {
        U256::from_str_radix(t, 10).map_err(|e| format!("slot: {e}"))?
    };
    Ok(keccak256(v.to_be_bytes::<32>()))
}

fn cost_json(c: &Cost) -> serde_json::Value {
    serde_json::json!({ "requests": c.requests, "bytes": c.bytes, "rounds": c.rounds, "repairs": c.repairs, "nodes": c.nodes })
}

fn status_json<T>(r: &Read<T>) -> (&'static str, serde_json::Value) {
    match r {
        Read::Verified(_) => ("verified", serde_json::Value::Null),
        Read::VerifiedAbsent(by) => ("absent", serde_json::json!(format!("{by:?}"))),
        Read::Insufficient(why) => ("insufficient", serde_json::json!(why.to_string())),
    }
}

fn error_json(e: String) -> String {
    serde_json::json!({ "status": "error", "error": e }).to_string()
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// The client: a snapshot opened at the finalized head, counters, and the
/// request log the page reads after each call.
#[wasm_bindgen]
pub struct Client {
    snap: Snapshot<JsBucket>,
    head: VerifiedHead,
    c: Arc<Counters>,
    open_requests: u64,
    open_bytes: u64,
    open_ms: f64,
}

impl Client {
    fn take_log(&self) -> serde_json::Value {
        let log: Vec<Req> = std::mem::take(&mut *self.c.log.lock().unwrap());
        serde_json::Value::Array(
            log.into_iter()
                .map(|r| {
                    serde_json::json!({
                        "file": r.rel,
                        "offset": r.range.map(|(o, _)| o),
                        "length": r.range.map(|(_, l)| l),
                        "status": r.status,
                        "bytes": r.bytes,
                        "ms": round1(r.ms),
                    })
                })
                .collect(),
        )
    }

    fn finish(&self, mut v: serde_json::Value, t0: f64, cost: &Cost) -> String {
        let log = self.take_log();
        let (req, bytes) = log.as_array().map_or((0, 0), |a| {
            (
                a.len() as u64,
                a.iter().map(|r| r["bytes"].as_u64().unwrap_or(0)).sum(),
            )
        });
        v["cost"] = cost_json(cost);
        v["http"] = serde_json::json!({ "requests": req, "bytes": bytes, "log": log });
        v["ms"] = serde_json::json!(round1(now_ms() - t0));
        v.to_string()
    }
}

#[wasm_bindgen]
impl Client {
    /// Open the bucket at `base` through the head: verify `head/` from
    /// `checkpoint` (a beacon block root, hex) as of `now_ms`, then open the
    /// snapshot at the finalized block. `prefetch` pages each side of the
    /// prediction (0: none, sequential reads); `top_levels` account-trie
    /// depths kept across reads of this snapshot (0: off).
    #[wasm_bindgen(constructor)]
    pub fn new(
        base: &str,
        checkpoint: &str,
        now_ms: f64,
        prefetch: u32,
        top_levels: u32,
    ) -> Result<Client, JsValue> {
        panic_hook();
        let c = Arc::new(Counters::default());
        let bucket = JsBucket {
            base: base.trim_end_matches('/').to_string(),
            c: c.clone(),
        };
        let checkpoint = parse_b256(checkpoint, "checkpoint").map_err(|e| JsValue::from_str(&e))?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_millis(now_ms.max(0.0) as u64);
        let t0 = self::now_ms();
        let (mut snap, head) =
            open_at_head(bucket, checkpoint, now).map_err(|e| JsValue::from_str(&e.to_string()))?;
        if prefetch > 0 {
            snap.prefetch = Some(Hint::symmetric(prefetch as u64));
        }
        snap.top_levels = top_levels as usize;
        let open_requests = c.requests.load(Ordering::Relaxed);
        let open_bytes = c.bytes.load(Ordering::Relaxed);
        Ok(Client {
            snap,
            head,
            c,
            open_requests,
            open_bytes,
            open_ms: self::now_ms() - t0,
        })
    }

    /// The verified head and what opening cost, as JSON. Takes the request
    /// log of the open.
    pub fn head(&self) -> String {
        let h = &self.head;
        let m = self.snap.manifest();
        serde_json::json!({
            "checkpoint": format!("{}", h.checkpoint),
            "slot": h.slot,
            "period": h.period,
            "beacon_root": format!("{}", h.beacon_root),
            "participants": h.participants,
            "updates_applied": h.updates_applied,
            "finality_lag_secs": h.finality_lag_secs,
            "block_number": h.execution.block_number,
            "block_hash": format!("{}", h.execution.block_hash),
            "state_root": format!("{}", h.execution.state_root),
            "timestamp": h.execution.timestamp,
            "snapshot": {
                "block_number": m.block_number,
                "block_hash": format!("{}", m.block_hash),
                "state_root": format!("{}", m.state_root),
                "prefix": m.prefix,
            },
            "open": { "requests": self.open_requests, "bytes": self.open_bytes, "ms": round1(self.open_ms), "log": self.take_log() },
        })
        .to_string()
    }

    /// The account under an address or a hashed key.
    pub fn account(&mut self, key: &str) -> String {
        let t0 = now_ms();
        let (hashed, address) = match account_key(key) {
            Ok(k) => k,
            Err(e) => return error_json(e),
        };
        let (r, cost) = self.snap.account(&hashed);
        let (status, why) = status_json(&r);
        let mut v = serde_json::json!({ "status": status, "why": why, "hashed": format!("{hashed}"), "address": address });
        if let Read::Verified(a) = &r {
            v["nonce"] = serde_json::json!(a.nonce);
            v["balance"] = serde_json::json!(a.balance.to_string());
            v["storage_root"] = serde_json::json!(format!("{}", a.storage_root));
            v["code_hash"] = serde_json::json!(format!("{}", a.code_hash));
            v["has_code"] = serde_json::json!(a.code_hash != KECCAK_EMPTY);
            v["has_storage"] = serde_json::json!(a.storage_root != EMPTY_ROOT_HASH);
        }
        self.finish(v, t0, &cost)
    }

    /// Storage slot `slot` (hex or decimal) of the account under `key`.
    pub fn storage(&mut self, key: &str, slot: &str) -> String {
        let t0 = now_ms();
        let (hashed, address) = match account_key(key) {
            Ok(k) => k,
            Err(e) => return error_json(e),
        };
        let hashed_slot = match slot_key(slot) {
            Ok(k) => k,
            Err(e) => return error_json(e),
        };
        let (r, cost) = self.snap.storage(&hashed, &hashed_slot);
        let (status, why) = status_json(&r);
        let mut v = serde_json::json!({
            "status": status, "why": why, "hashed": format!("{hashed}"), "address": address, "hashed_slot": format!("{hashed_slot}")
        });
        if let Read::Verified(x) = &r {
            v["value"] = serde_json::json!(format!("{x:#x}"));
            v["value_dec"] = serde_json::json!(x.to_string());
        }
        self.finish(v, t0, &cost)
    }

    /// The bytecode under a code hash.
    pub fn code(&mut self, code_hash: &str) -> String {
        let t0 = now_ms();
        let h = match parse_b256(code_hash, "code hash") {
            Ok(h) => h,
            Err(e) => return error_json(e),
        };
        let (r, cost) = self.snap.code(&h);
        let (status, why) = status_json(&r);
        let mut v =
            serde_json::json!({ "status": status, "why": why, "code_hash": format!("{h}") });
        if let Read::Verified(b) = &r {
            v["size"] = serde_json::json!(b.len());
            v["prefix"] = serde_json::json!(format!("0x{}", hex::encode(&b[..b.len().min(32)])));
        }
        self.finish(v, t0, &cost)
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    panic_hook();
    env!("CARGO_PKG_VERSION").to_string()
}
