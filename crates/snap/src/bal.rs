//! `csl-eth bal-probe`: do testnet peers serve EIP-7928 block access lists
//! over the wire (`eth/71`, EIP-8159; `snap/2`, EIP-8189), so that per-block
//! state diffs could come from peers with no execution node?
//!
//! Each peer that connects is reported (client, negotiated versions, head).
//! On an `eth/71` peer the probe takes its head header and 8 parents, plus
//! headers at fixed depths back toward the fork, asks for their access
//! lists, and checks each list against its header's
//! `block_access_list_hash` (keccak of the list's RLP) before decoding it.

use crate::{
    discovery,
    peer::{self, Net, Peer},
};
use alloy_consensus::Header;
use alloy_eip7928::bal::Bal;
use alloy_primitives::{keccak256, Bytes, B256};
use alloy_rlp::Decodable;
use reth_ethereum_forks::{EthereumHardfork, EthereumHardforks};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::mpsc;
use tracing::debug;

/// How far behind the head, in blocks, to ask for older lists: about 1000
/// blocks (3.3 h), a day, a week, two weeks, three weeks.
pub const DEPTHS: [u64; 5] = [1000, 7200, 50_400, 100_800, 151_200];

const SLOT_SECS: u64 = 12;

/// `snap/2` soft response limit.
const SNAP_RESPONSE_BYTES: u64 = 2 * 1024 * 1024;

pub struct ProbeConfig {
    pub net: Net,
    /// Stop after this many connected peers.
    pub peers: usize,
    /// Or after this long.
    pub secs: u64,
    pub udp_port: u16,
    /// Per handshake step and per request.
    pub timeout: Duration,
}

/// What a probe saw.
pub struct Probed {
    /// One per peer that completed the handshakes.
    pub reports: Vec<Value>,
    /// Dials that did not, by error.
    pub dial_errors: BTreeMap<String, usize>,
}

/// Run the probe. Each peer's report goes to `out` as it completes.
pub async fn probe(cfg: &ProbeConfig, out: mpsc::Sender<Value>) -> Probed {
    let net = cfg.net;
    let key = peer::random_key();
    let (status, fork_filter) = peer::status_on(net, None);
    let mut candidates =
        discovery::start_on(net, key, cfg.udp_port, fork_filter.clone(), true, true).await;
    let sem = Arc::new(tokio::sync::Semaphore::new(24));
    let (tx, mut rx) = mpsc::channel::<Value>(64);
    let timeout = cfg.timeout;
    let dialer = tokio::spawn(async move {
        while let Some(record) = candidates.recv().await {
            let permit = sem.clone().acquire_owned().await.expect("open");
            let tx = tx.clone();
            let (status, fork_filter) = (status, fork_filter.clone());
            tokio::spawn(async move {
                let _permit = permit;
                match Peer::connect_on(net, record, &key, status, fork_filter, timeout, false).await
                {
                    Ok(peer) => {
                        let report = examine(net, peer).await;
                        let _ = tx.send(report).await;
                    }
                    Err(e) => {
                        debug!(addr = %record.address, error = %e, "dial failed");
                        let _ = tx.send(json!({ "dial_error": e.to_string() })).await;
                    }
                }
            });
        }
    });
    let deadline = Instant::now() + Duration::from_secs(cfg.secs);
    let mut reports = Vec::new();
    let mut dial_errors = BTreeMap::new();
    while reports.len() < cfg.peers {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(r)) => {
                if let Some(e) = r["dial_error"].as_str() {
                    *dial_errors.entry(e.to_string()).or_default() += 1;
                    continue;
                }
                let _ = out.send(r.clone()).await;
                reports.push(r);
            }
            _ => break,
        }
    }
    dialer.abort();
    Probed {
        reports,
        dial_errors,
    }
}

/// One peer's report.
async fn examine(net: Net, mut peer: Peer) -> Value {
    let spec = net.spec();
    let mut r = json!({
        "addr": format!("{}:{}", peer.record.address, peer.record.tcp_port),
        "client": peer.client,
        "eth": peer.eth_version(),
        "snap": peer.snap_version,
        "status_latest": peer.status.latest_block,
        "status_earliest": peer.status.earliest_block,
    });
    let head = match peer.own_head().await {
        Ok(Some(h)) => h,
        Ok(None) => {
            r["error"] = json!("no head header");
            peer.close().await;
            return r;
        }
        Err(e) => {
            r["error"] = json!(format!("head: {e}"));
            peer.close().await;
            return r;
        }
    };
    let amsterdam = spec.is_amsterdam_active_at_timestamp(head.timestamp);
    r["head"] = json!(head.number);
    r["head_timestamp"] = json!(head.timestamp);
    r["amsterdam_active"] = json!(amsterdam);
    r["head_has_bal_hash"] = json!(head.block_access_list_hash.is_some());
    if peer.eth_version() < 71 {
        peer.close().await;
        return r;
    }

    // Recent: the head and 8 parents.
    let recent = match peer.headers_back(head.hash_slow(), 9).await {
        Ok(v) if !v.is_empty() => v,
        Ok(_) => vec![head.clone()],
        Err(e) => {
            r["headers_error"] = json!(format!("{e}"));
            vec![head.clone()]
        }
    };
    r["recent"] = Value::Array(lists(&mut peer, &recent, false).await);

    // Older: fixed depths, not before the fork's first block.
    let first = spec
        .ethereum_fork_activation(EthereumHardfork::Amsterdam)
        .as_timestamp()
        .and_then(|t| (t <= head.timestamp).then_some(t));
    let mut older = Vec::new();
    for d in DEPTHS {
        let Some(n) = head.number.checked_sub(d) else {
            continue;
        };
        match peer.header_at(n).await {
            Ok(Some(h)) => {
                if first.is_some_and(|t| h.timestamp < t) {
                    break;
                }
                older.push(h);
            }
            Ok(None) => older.push(Header {
                number: n,
                ..Default::default()
            }),
            Err(e) => {
                r["older_headers_error"] = json!(format!("{e}"));
                break;
            }
        }
    }
    // And the fork's first block, or one a few after it: estimate from the
    // slot time (never past it, since missed slots only make blocks fewer),
    // then step forward while still before the fork.
    if let Some(t) = first {
        let mut n = head.number.saturating_sub((head.timestamp - t) / SLOT_SECS);
        for _ in 0..6 {
            match peer.header_at(n).await {
                Ok(Some(h)) if h.timestamp >= t => {
                    if older.iter().all(|o| o.number != h.number) {
                        older.push(h);
                    }
                    break;
                }
                Ok(Some(h)) => n = h.number + (t - h.timestamp) / SLOT_SECS + 1,
                Ok(None) => {
                    older.push(Header {
                        number: n,
                        ..Default::default()
                    });
                    break;
                }
                Err(e) => {
                    r["fork_header_error"] = json!(format!("{e}"));
                    break;
                }
            }
        }
    }
    // A header the peer did not have (number only) is reported, not asked.
    let (have, missing): (Vec<Header>, Vec<Header>) =
        older.into_iter().partition(|h| h.timestamp != 0);
    let mut older_reports = lists(&mut peer, &have, false).await;
    for h in missing {
        older_reports.push(
            json!({ "number": h.number, "depth": head.number - h.number, "header": "missing" }),
        );
    }
    for o in &mut older_reports {
        if let Some(n) = o["number"].as_u64() {
            o["depth"] = json!(head.number - n);
        }
    }
    r["older"] = Value::Array(older_reports);

    if peer.snap_version >= 2 {
        r["snap2_recent"] =
            Value::Array(lists(&mut peer, &recent[..recent.len().min(3)], true).await);
    }
    r["bytes_in"] = json!(peer.bytes_in);
    peer.close().await;
    r
}

/// Ask for the lists of `headers` in one request (over `snap/2` if `snap`)
/// and report each.
async fn lists(peer: &mut Peer, headers: &[Header], snap: bool) -> Vec<Value> {
    if headers.is_empty() {
        return vec![];
    }
    let hashes: Vec<B256> = headers.iter().map(|h| h.hash_slow()).collect();
    let got = if snap {
        peer.snap_block_access_lists(hashes, SNAP_RESPONSE_BYTES)
            .await
    } else {
        peer.block_access_lists(hashes).await
    };
    match got {
        Ok(v) => {
            let mut out: Vec<Value> = headers
                .iter()
                .zip(v.iter().map(Some).chain(std::iter::repeat(None)))
                .map(|(h, b)| one(h, b.cloned().flatten()))
                .collect();
            if v.len() > headers.len() {
                out.push(
                    json!({ "error": format!("{} entries for {} hashes", v.len(), headers.len()) }),
                );
            }
            out
        }
        Err(e) => vec![json!({ "error": format!("{e}") })],
    }
}

fn one(h: &Header, bal: Option<Bytes>) -> Value {
    let mut r = json!({ "number": h.number });
    let Some(raw) = bal else {
        r["served"] = json!(false);
        return r;
    };
    r["served"] = json!(true);
    r["bytes"] = json!(raw.len());
    r["verified"] = json!(match h.block_access_list_hash {
        Some(want) => keccak256(&raw) == want,
        None => false,
    });
    if h.block_access_list_hash.is_none() {
        r["note"] = json!("header has no block_access_list_hash");
    }
    match Bal::decode(&mut &raw[..]) {
        Ok(bal) => {
            r["accounts"] = json!(bal.len());
            r["storage_changes"] = json!(bal.total_storage_changes());
            r["storage_reads"] = json!(bal.total_storage_reads());
            r["balance_changes"] = json!(bal.total_balance_changes());
            r["nonce_changes"] = json!(bal.total_nonce_changes());
            r["code_changes"] = json!(bal.total_code_changes());
        }
        Err(e) => r["decode_error"] = json!(format!("{e}")),
    }
    r
}

/// Totals over the reports: peers by client and versions, lists served
/// and verified, and the size distribution of the verified ones.
pub fn summarize(reports: &[Value]) -> Value {
    let mut by_client: BTreeMap<String, usize> = Default::default();
    let (mut eth71, mut snap2, mut served_peers, mut verified_peers) = (0, 0, 0, 0);
    let mut sizes: Vec<(u64, u64, u64, u64)> = vec![];
    let mut deepest_served: Option<u64> = None;
    let mut seen = std::collections::HashSet::new();
    for r in reports {
        let client = r["client"].as_str().unwrap_or("?");
        let name = client.split('/').take(2).collect::<Vec<_>>().join("/");
        *by_client
            .entry(format!("{name} eth/{} snap/{}", r["eth"], r["snap"]))
            .or_default() += 1;
        if r["eth"].as_u64() >= Some(71) {
            eth71 += 1;
        }
        if r["snap"].as_u64() >= Some(2) {
            snap2 += 1;
        }
        let entries: Vec<&Value> = ["recent", "older"]
            .iter()
            .flat_map(|k| r[*k].as_array().into_iter().flatten())
            .collect();
        if entries.iter().any(|e| e["served"] == json!(true)) {
            served_peers += 1;
        }
        if entries.iter().any(|e| e["verified"] == json!(true)) {
            verified_peers += 1;
        }
        for e in entries {
            if e["verified"] == json!(true) {
                if let Some(d) = e["depth"].as_u64() {
                    deepest_served = Some(deepest_served.map_or(d, |x: u64| x.max(d)));
                }
                if seen.insert(e["number"].as_u64()) {
                    let g = |k: &str| e[k].as_u64().unwrap_or(0);
                    sizes.push((
                        g("bytes"),
                        g("accounts"),
                        g("storage_changes"),
                        g("storage_reads"),
                    ));
                }
            }
        }
    }
    let dist = |f: fn(&(u64, u64, u64, u64)) -> u64| {
        let mut v: Vec<u64> = sizes.iter().map(f).collect();
        v.sort_unstable();
        if v.is_empty() {
            return json!(null);
        }
        let q = |p: usize| v[(v.len() - 1) * p / 100];
        json!({ "min": v[0], "p50": q(50), "p90": q(90), "max": v[v.len() - 1] })
    };
    json!({
        "peers": reports.len(),
        "by_client": by_client,
        "eth71_peers": eth71,
        "snap2_peers": snap2,
        "peers_serving_bals": served_peers,
        "peers_with_verified_bals": verified_peers,
        "distinct_blocks_verified": sizes.len(),
        "bytes": dist(|s| s.0),
        "accounts": dist(|s| s.1),
        "storage_changes": dist(|s| s.2),
        "storage_reads": dist(|s| s.3),
        "deepest_verified_depth": deepest_served,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_trees_match_alloy_chains() {
        for net in [Net::Mainnet, Net::Sepolia, Net::Hoodi] {
            let want = net
                .spec()
                .chain
                .named()
                .and_then(|c| c.public_dns_network_protocol());
            assert_eq!(Some(net.dns_tree().to_string()), want, "{}", net.name());
        }
    }

    #[test]
    fn served_list_is_checked_against_the_header() {
        let raw = Bytes::from(alloy_rlp::encode(Bal::default()));
        let mut h = Header {
            block_access_list_hash: Some(keccak256(&raw)),
            ..Default::default()
        };
        let r = one(&h, Some(raw.clone()));
        assert_eq!(
            (r["verified"].clone(), r["accounts"].clone()),
            (json!(true), json!(0))
        );
        h.block_access_list_hash = Some(B256::ZERO);
        assert_eq!(one(&h, Some(raw))["verified"], json!(false));
        assert_eq!(one(&h, None)["served"], json!(false));
    }
}
