//! The client in the browser. The client does no I/O: each call either
//! finishes or says which files and byte ranges it needs next (`need`), the
//! page fetches them all at once with `fetch` and `Promise.all`, supplies
//! the bodies, and calls `step` again. One `need` list is one round, one
//! network round trip. Nothing on the JavaScript side verifies anything; it
//! transports bytes and renders results. Every answer here is the same
//! `csl-eth-client` answer the CLI gives, with the head verified in the tab
//! from one checkpoint root.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{EMPTY_ROOT_HASH, KECCAK_EMPTY};
use csl_eth_client::{
    Cost, HeadOpener, Hint, NoDriver, Pending, Read, Snapshot, VerifiedHead, Want,
};
use js_sys::Uint8Array;
use std::time::{Duration, SystemTime};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
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
    serde_json::json!({ "requests": c.requests, "bytes": c.bytes, "rounds": c.rounds, "repairs": c.repairs, "nodes": c.nodes, "model_pages": c.model_pages })
}

fn status_json<T>(r: &Read<T>) -> (&'static str, serde_json::Value) {
    match r {
        Read::Verified(_) => ("verified", serde_json::Value::Null),
        Read::VerifiedAbsent(by) => ("absent", serde_json::json!(format!("{by:?}"))),
        Read::Insufficient(why) => ("insufficient", serde_json::json!(why.to_string())),
    }
}

fn error_json(e: impl std::fmt::Display) -> String {
    serde_json::json!({ "error": e.to_string() }).to_string()
}

fn head_json(h: &VerifiedHead, snap: &Snapshot<NoDriver>) -> serde_json::Value {
    let m = snap.manifest();
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
    })
}

/// What a call is in the middle of.
enum Op {
    Idle,
    Open,
    Account {
        hashed: B256,
        address: Option<String>,
        baseline: bool,
    },
    Storage {
        hashed: B256,
        address: Option<String>,
        hashed_slot: B256,
        baseline: bool,
    },
    Code(B256),
}

/// The client: an opener until the head is verified and the snapshot open,
/// then the snapshot; between calls, the wants of the last `need`.
#[wasm_bindgen]
pub struct Client {
    opener: Option<HeadOpener<NoDriver>>,
    snap: Option<Snapshot<NoDriver>>,
    head: Option<VerifiedHead>,
    hint: Hint,
    top_levels: usize,
    op: Op,
    wants: Vec<Want>,
}

impl Client {
    fn need(&mut self, wants: Vec<Want>) -> String {
        let list: Vec<serde_json::Value> = wants
            .iter()
            .map(|w| match w {
                Want::File { rel } => serde_json::json!({ "file": rel }),
                Want::Range { rel, off, len } => {
                    serde_json::json!({ "file": rel, "offset": off, "length": len })
                }
            })
            .collect();
        self.wants = wants;
        serde_json::json!({ "need": list }).to_string()
    }

    fn done(&mut self, v: serde_json::Value) -> String {
        self.op = Op::Idle;
        self.wants.clear();
        serde_json::json!({ "done": v }).to_string()
    }

    fn fail(&mut self, e: impl std::fmt::Display) -> String {
        self.op = Op::Idle;
        self.wants.clear();
        error_json(e)
    }

    fn snap_mut(&mut self) -> Result<&mut Snapshot<NoDriver>, String> {
        self.snap.as_mut().ok_or_else(|| "open first".to_string())
    }

    fn start(&mut self, op: Op) -> String {
        match self.snap_mut() {
            Ok(s) => s.begin_read(),
            Err(e) => return self.fail(e),
        }
        self.op = op;
        self.step()
    }

    fn finish<T>(
        &mut self,
        r: Read<T>,
        cost: Cost,
        mut v: serde_json::Value,
        extra: impl FnOnce(&T, &mut serde_json::Value),
    ) -> String {
        let (status, why) = status_json(&r);
        v["status"] = serde_json::json!(status);
        v["why"] = why;
        if let Read::Verified(x) = &r {
            extra(x, &mut v);
        }
        v["cost"] = cost_json(&cost);
        self.done(v)
    }
}

#[wasm_bindgen]
impl Client {
    /// A client that will verify `head/` from `checkpoint` (a beacon block
    /// root, hex) as of `now_ms` and open the snapshot at the finalized
    /// block. `prefetch` pages each side of every predicted page;
    /// `top_levels` account-trie depths kept across reads of the snapshot
    /// (0: off). `open()` starts the rounds.
    #[wasm_bindgen(constructor)]
    pub fn new(
        checkpoint: &str,
        now_ms: f64,
        prefetch: u32,
        top_levels: u32,
    ) -> Result<Client, JsValue> {
        panic_hook();
        let checkpoint = parse_b256(checkpoint, "checkpoint").map_err(|e| JsValue::from_str(&e))?;
        let now = SystemTime::UNIX_EPOCH + Duration::from_millis(now_ms.max(0.0) as u64);
        Ok(Client {
            opener: Some(HeadOpener::new(NoDriver, checkpoint, now)),
            snap: None,
            head: None,
            hint: Hint::symmetric(prefetch as u64),
            top_levels: top_levels as usize,
            op: Op::Idle,
            wants: Vec::new(),
        })
    }

    /// Begin opening: the first `need` is the head bootstrap.
    pub fn open(&mut self) -> String {
        if self.opener.is_none() {
            return self.fail("already open");
        }
        self.op = Op::Open;
        self.step()
    }

    /// The account under an address or a hashed key. `baseline` reads it
    /// the content-addressed way (every node by hash, one round each)
    /// instead of the path-keyed one.
    pub fn account(&mut self, key: &str, baseline: bool) -> String {
        match account_key(key) {
            Ok((hashed, address)) => self.start(Op::Account { hashed, address, baseline }),
            Err(e) => self.fail(e),
        }
    }

    /// Storage slot `slot` (hex or decimal) of the account under `key`.
    pub fn storage(&mut self, key: &str, slot: &str, baseline: bool) -> String {
        match (account_key(key), slot_key(slot)) {
            (Ok((hashed, address)), Ok(hashed_slot)) => self.start(Op::Storage {
                hashed,
                address,
                hashed_slot,
                baseline,
            }),
            (Err(e), _) | (_, Err(e)) => self.fail(e),
        }
    }

    /// The bytecode under a code hash.
    pub fn code(&mut self, code_hash: &str) -> String {
        match parse_b256(code_hash, "code hash") {
            Ok(h) => self.start(Op::Code(h)),
            Err(e) => self.fail(e),
        }
    }

    /// What the page got for want `i` of the last `need`: the HTTP status
    /// and body (`status` 0 and `error` for a failed request). A whole
    /// file is 200 or 404; a range must be 206.
    pub fn supply(
        &mut self,
        i: usize,
        status: u16,
        body: Option<Uint8Array>,
        error: Option<String>,
    ) -> Result<(), JsValue> {
        let Some(w) = self.wants.get(i).cloned() else {
            return Err(JsValue::from_str(&format!("supply: no want {i}")));
        };
        let store = match (&self.snap, &self.opener) {
            (Some(s), _) => s.store().clone(),
            (None, Some(o)) => o.store().clone(),
            (None, None) => return Err(JsValue::from_str("supply: nothing open")),
        };
        let body = body.map(|b| b.to_vec()).unwrap_or_default();
        let got = match (&w, status) {
            (_, 0) => Err(error.unwrap_or_else(|| "network error".into())),
            (Want::File { .. }, 200) => Ok(Some(body)),
            (Want::File { .. }, 404) => Ok(None),
            (Want::Range { .. }, 206) => Ok(Some(body)),
            (_, s) => Err(format!("GET {}: status {s}", w.rel())),
        };
        store.supply(&w, got);
        Ok(())
    }

    /// Continue the call in progress from what has been supplied: another
    /// `need`, or `done` with the result, or `error`.
    pub fn step(&mut self) -> String {
        match std::mem::replace(&mut self.op, Op::Idle) {
            Op::Idle => self.fail("nothing in progress"),
            Op::Open => {
                let Some(o) = self.opener.as_mut() else {
                    return self.fail("already open");
                };
                match o.try_open() {
                    Err(Pending) => {
                        self.op = Op::Open;
                        let w = o.store().take_wanted(true);
                        self.need(w)
                    }
                    Ok(Err(e)) => self.fail(e),
                    Ok(Ok((mut snap, head))) => {
                        snap.hint = self.hint;
                        snap.top_levels = self.top_levels;
                        let (requests, bytes, rounds) = snap.store().cost();
                        let mut v = head_json(&head, &snap);
                        v["open"] = serde_json::json!({ "requests": requests, "bytes": bytes, "rounds": rounds });
                        self.opener = None;
                        self.snap = Some(snap);
                        self.head = Some(head);
                        self.done(v)
                    }
                }
            }
            op => {
                let merge = self.hint.merge;
                let snap = match self.snap.as_mut() {
                    Some(s) => s,
                    None => return self.fail("open first"),
                };
                match op {
                    Op::Account { hashed, address, baseline } => match if baseline {
                        snap.try_account_by_hash(&hashed)
                    } else {
                        snap.try_account(&hashed)
                    } {
                        Err(Pending) => {
                            let w = snap.store().take_wanted(merge);
                            self.op = Op::Account { hashed, address, baseline };
                            self.need(w)
                        }
                        Ok((r, cost)) => {
                            let v = serde_json::json!({ "hashed": format!("{hashed}"), "address": address, "baseline": baseline });
                            self.finish(r, cost, v, |a, v| {
                                v["nonce"] = serde_json::json!(a.nonce);
                                v["balance"] = serde_json::json!(a.balance.to_string());
                                v["storage_root"] =
                                    serde_json::json!(format!("{}", a.storage_root));
                                v["code_hash"] = serde_json::json!(format!("{}", a.code_hash));
                                v["has_code"] = serde_json::json!(a.code_hash != KECCAK_EMPTY);
                                v["has_storage"] =
                                    serde_json::json!(a.storage_root != EMPTY_ROOT_HASH);
                            })
                        }
                    },
                    Op::Storage {
                        hashed,
                        address,
                        hashed_slot,
                        baseline,
                    } => match if baseline {
                        snap.try_storage_by_hash(&hashed, &hashed_slot)
                    } else {
                        snap.try_storage(&hashed, &hashed_slot)
                    } {
                        Err(Pending) => {
                            let w = snap.store().take_wanted(merge);
                            self.op = Op::Storage {
                                hashed,
                                address,
                                hashed_slot,
                                baseline,
                            };
                            self.need(w)
                        }
                        Ok((r, cost)) => {
                            let v = serde_json::json!({
                                "hashed": format!("{hashed}"), "address": address, "hashed_slot": format!("{hashed_slot}"), "baseline": baseline
                            });
                            self.finish(r, cost, v, |x, v| {
                                v["value"] = serde_json::json!(format!("{x:#x}"));
                                v["value_dec"] = serde_json::json!(x.to_string());
                            })
                        }
                    },
                    Op::Code(h) => match snap.try_code(&h) {
                        Err(Pending) => {
                            let w = snap.store().take_wanted(merge);
                            self.op = Op::Code(h);
                            self.need(w)
                        }
                        Ok((r, cost)) => {
                            let v = serde_json::json!({ "code_hash": format!("{h}") });
                            self.finish(r, cost, v, |b, v| {
                                v["size"] = serde_json::json!(b.len());
                                v["prefix"] = serde_json::json!(format!(
                                    "0x{}",
                                    hex::encode(&b[..b.len().min(32)])
                                ));
                            })
                        }
                    },
                    Op::Idle | Op::Open => unreachable!(),
                }
            }
        }
    }

    /// The verified head and the snapshot it named, once open.
    pub fn head(&self) -> String {
        match (&self.head, &self.snap) {
            (Some(h), Some(s)) => head_json(h, s).to_string(),
            _ => error_json("not open"),
        }
    }
}

#[wasm_bindgen]
pub fn version() -> String {
    panic_hook();
    env!("CARGO_PKG_VERSION").to_string()
}
