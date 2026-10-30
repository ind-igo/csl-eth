//! Peer candidates: EIP-1459 DNS trees first (a signed list, no UDP
//! needed), discv4 from the hardcoded bootnodes beside it. Records are
//! deduplicated by node id and, where the record carries a fork id, dropped
//! if it is incompatible with mainnet now.

use reth_discv4::{DiscoveryUpdate, Discv4, Discv4Config};
use reth_dns_discovery::{DnsDiscoveryConfig, DnsDiscoveryService, DnsResolver};
use reth_ethereum_forks::ForkFilter;
use reth_network_peers::{mainnet_nodes, NodeRecord, PeerId};
use secp256k1::SecretKey;
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tracing::{info, warn};

/// Mainnet's EIP-1459 tree (geth's constant).
pub const MAINNET_DNS_TREE: &str = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net";

/// Start the sources and return the stream of candidates. Each source
/// that fails to start is logged and skipped; with none the receiver ends.
pub async fn start(key: SecretKey, udp_port: u16, fork_filter: ForkFilter, use_dns: bool, use_discv4: bool) -> mpsc::Receiver<NodeRecord> {
    let (tx, rx) = mpsc::channel::<NodeRecord>(4096);
    // By node id and by socket address: crawlers answer from one address
    // under fresh keys, and one address is one node.
    let seen: Arc<Mutex<(HashSet<PeerId>, HashSet<SocketAddr>)>> = Arc::new(Mutex::new((HashSet::new(), HashSet::new())));

    if use_dns {
        match DnsResolver::from_system_conf() {
            Ok(resolver) => {
                let (mut service, handle) = DnsDiscoveryService::new_pair(Arc::new(resolver), DnsDiscoveryConfig::default());
                let mut updates = service.node_record_stream();
                if let Err(e) = handle.sync_tree(MAINNET_DNS_TREE) {
                    warn!(error = %e, "dns tree link rejected");
                } else {
                    service.spawn();
                    let tx = tx.clone();
                    let seen = seen.clone();
                    let ff = fork_filter.clone();
                    tokio::spawn(async move {
                        let mut n = 0usize;
                        while let Some(u) = updates.next().await {
                            if let Some(fid) = u.fork_id {
                                if ff.validate(fid).is_err() {
                                    continue;
                                }
                            }
                            if first_sight(&seen, &u.node_record) {
                                n += 1;
                                if n.is_multiple_of(200) {
                                    info!(n, "dns candidates");
                                }
                                if tx.send(u.node_record).await.is_err() {
                                    break;
                                }
                            }
                        }
                    });
                }
            }
            Err(e) => warn!(error = %e, "no system dns resolver; dns discovery off"),
        }
    }

    if use_discv4 {
        let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), udp_port);
        let local = NodeRecord::from_secret_key(addr, &key);
        let mut builder = Discv4Config::builder();
        builder.add_boot_nodes(mainnet_nodes());
        let config = builder.build();
        match Discv4::bind(addr, local, key, config).await {
            Ok((handle, mut service)) => {
                let mut updates = service.update_stream();
                service.spawn();
                let tx = tx.clone();
                let seen = seen.clone();
                tokio::spawn(async move {
                    // The handle keeps the service's command channel open.
                    let _handle = handle;
                    let mut n = 0usize;
                    while let Some(u) = updates.next().await {
                        let mut records = Vec::new();
                        collect(u, &fork_filter, &mut records);
                        for record in records {
                            if record.tcp_port == 0 {
                                continue;
                            }
                            if first_sight(&seen, &record) {
                                n += 1;
                                if n.is_multiple_of(200) {
                                    info!(n, "discv4 candidates");
                                }
                                if tx.send(record).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
            Err(e) => warn!(error = %e, "discv4 bind failed; discv4 off"),
        }
    }

    drop(tx);
    rx
}

/// Flatten an update (batches nest) into fork-compatible records.
fn collect(u: DiscoveryUpdate, fork_filter: &ForkFilter, out: &mut Vec<NodeRecord>) {
    match u {
        DiscoveryUpdate::Added(r) | DiscoveryUpdate::DiscoveredAtCapacity(r) => out.push(r),
        DiscoveryUpdate::EnrForkId(r, fid) => {
            if fork_filter.validate(fid).is_ok() {
                out.push(r);
            }
        }
        DiscoveryUpdate::Removed(_) => {}
        DiscoveryUpdate::Batch(v) => {
            for u in v {
                collect(u, fork_filter, out);
            }
        }
    }
}

fn first_sight(seen: &Mutex<(HashSet<PeerId>, HashSet<SocketAddr>)>, r: &NodeRecord) -> bool {
    let mut g = seen.lock().unwrap();
    let addr = SocketAddr::new(r.address, r.tcp_port);
    let new_id = g.0.insert(r.id);
    let new_addr = g.1.insert(addr);
    new_id && new_addr
}
