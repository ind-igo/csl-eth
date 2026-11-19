//! One RLPx connection to a mainnet peer speaking `eth` and `snap`.
//! (Sepolia and Hoodi too, for probes: [`Net`]. There `eth/71` is offered
//! as well, for its block access lists, and `snap` may be absent.)
//!
//! ECIES on a fresh node key, the `p2p` hello, the `eth` status exchange
//! (reth's handshake, with mainnet's fork id computed from
//! `reth-chainspec`), then requests over `snap` with the `eth` side kept
//! polite: header, body, receipt and pooled-transaction requests from the
//! peer get empty answers so it does not score us down as silent, and
//! broadcasts are dropped. `snap/1` and `snap/2` share the message ids this
//! crate uses (0x00 to 0x05), so both are offered and whichever the peer
//! has is taken.
//!
//! Message ids: [`P2PStream`] delivers and accepts frames whose first byte
//! is the capability-relative id (eth from 0, snap from `eth`'s message
//! count), so a snap frame is rebased by `snap_offset` on the way out and
//! back.

use alloy_consensus::{Header, TxReceipt};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Bytes, B256};
use futures::{SinkExt, StreamExt};
use reth_chainspec::{ChainSpec, HOODI, MAINNET, SEPOLIA};
use reth_ecies::{stream::ECIESStream, ECIESError};
use reth_eth_wire::{
    errors::{EthStreamError, P2PStreamError},
    handshake::{EthHandshake, EthRlpxHandshake},
    protocol::Protocol,
    BlockAccessLists, BlockBodies, BlockHeaders, Capability, DisconnectReason, EthMessage, EthNetworkPrimitives, EthVersion, GetBlockAccessLists,
    GetBlockHeaders, HeadersDirection, HelloMessageWithProtocols, P2PStream, PooledTransactions, ProtocolMessage, Receipts, UnauthedP2PStream,
    UnifiedStatus,
};
use reth_eth_wire_types::{message::RequestPair, GetBlockBodies, GetReceipts, GetReceipts70, NetworkPrimitives};
use reth_eth_wire_types::snap::{
    AccountRangeMessage, BlockAccessListsMessage, ByteCodesMessage, GetAccountRangeMessage, GetBlockAccessListsMessage, GetByteCodesMessage,
    GetStorageRangesMessage, RangeBound, SnapMessageId, SnapProtocolMessage, StorageRangesMessage,
};
use reth_ethereum_forks::{ForkFilter, Head};
use reth_network_peers::{hoodi_nodes, mainnet_nodes, pk2id, sepolia_nodes, NodeRecord, PeerId};
use secp256k1::{SecretKey, SECP256K1};
use std::{
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpStream, time::timeout};

pub const CLIENT_VERSION: &str = "csl-eth/0.1.0";

/// A block body as `eth` carries it.
pub type EthBlockBody = <EthNetworkPrimitives as NetworkPrimitives>::BlockBody;
/// A receipt as `eth` carries it (without its bloom from `eth/69`).
pub type EthReceipt = <EthNetworkPrimitives as NetworkPrimitives>::Receipt;

/// A block height every mainnet block-number fork is below, so the fork id
/// we announce depends only on the wall clock (timestamp forks).
pub const FORK_HEAD_NUMBER: u64 = 20_000_000;

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("ecies: {0}")]
    Ecies(#[from] ECIESError),
    #[error("p2p: {0}")]
    P2p(#[from] P2PStreamError),
    #[error("eth: {0}")]
    Eth(#[from] EthStreamError),
    #[error("peer offers no snap capability")]
    NoSnap,
    #[error("timed out")]
    Timeout,
    #[error("connection closed")]
    Closed,
    #[error("rlp: {0}")]
    Rlp(#[from] alloy_rlp::Error),
    #[error("protocol: {0}")]
    Protocol(&'static str),
}

/// The chain a connection is on. The fetcher and the producer are mainnet
/// only; Sepolia and Hoodi are for probing what testnet peers serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Net {
    Mainnet,
    Sepolia,
    Hoodi,
}

impl Net {
    pub fn parse(s: &str) -> Result<Net, String> {
        match s {
            "mainnet" => Ok(Net::Mainnet),
            "sepolia" => Ok(Net::Sepolia),
            "hoodi" => Ok(Net::Hoodi),
            _ => Err(format!("unknown chain {s}: mainnet, sepolia or hoodi")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Net::Mainnet => "mainnet",
            Net::Sepolia => "sepolia",
            Net::Hoodi => "hoodi",
        }
    }

    pub fn spec(self) -> &'static ChainSpec {
        match self {
            Net::Mainnet => &MAINNET,
            Net::Sepolia => &SEPOLIA,
            Net::Hoodi => &HOODI,
        }
    }

    /// A height above every block-number fork of the chain, so the fork id
    /// depends only on the clock (mainnet's is [`FORK_HEAD_NUMBER`]).
    pub fn fork_head_number(self) -> u64 {
        match self {
            Net::Mainnet => FORK_HEAD_NUMBER,
            Net::Sepolia => 12_000_000,
            Net::Hoodi => 2_000_000,
        }
    }

    pub fn bootnodes(self) -> Vec<NodeRecord> {
        match self {
            Net::Mainnet => mainnet_nodes(),
            Net::Sepolia => sepolia_nodes(),
            Net::Hoodi => hoodi_nodes(),
        }
    }

    /// The chain's EIP-1459 tree: the Ethereum Foundation's signing key
    /// (geth's) at `all.<chain>.ethdisco.net`.
    pub fn dns_tree(self) -> &'static str {
        match self {
            Net::Mainnet => crate::discovery::MAINNET_DNS_TREE,
            Net::Sepolia => "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.sepolia.ethdisco.net",
            Net::Hoodi => "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.hoodi.ethdisco.net",
        }
    }

    /// `eth/71` (EIP-8159, block access lists) is offered off mainnet only,
    /// so what a mainnet fetch negotiates does not change.
    pub fn offers_eth71(self) -> bool {
        self != Net::Mainnet
    }
}

/// The status and fork filter to present: mainnet, the fork id for the
/// current time, no history. `blockhash` is informational; peers do not
/// validate it, and a client that has verified a head passes that.
pub fn mainnet_status(blockhash: Option<B256>) -> (UnifiedStatus, ForkFilter) {
    status_on(Net::Mainnet, blockhash)
}

/// [`mainnet_status`] for any [`Net`].
pub fn status_on(net: Net, blockhash: Option<B256>) -> (UnifiedStatus, ForkFilter) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let number = net.fork_head_number();
    let head = Head { number, timestamp: now, ..Default::default() };
    let spec = net.spec();
    let mut status = UnifiedStatus::spec_builder(spec, &head);
    status.blockhash = blockhash.unwrap_or_else(|| spec.genesis_hash());
    status.set_history_range(number, number);
    (status, spec.fork_filter(head))
}

/// A fresh random node key.
pub fn random_key() -> SecretKey {
    loop {
        let bytes: [u8; 32] = rand::random();
        if let Ok(k) = SecretKey::from_slice(&bytes) {
            return k;
        }
    }
}

pub struct Peer {
    conn: P2PStream<ECIESStream<TcpStream>>,
    eth_version: EthVersion,
    snap_offset: u8,
    pub snap_version: u8,
    pub status: UnifiedStatus,
    pub record: NodeRecord,
    pub client: String,
    pub timeout: Duration,
    next_id: u64,
    /// Bytes received in snap and header responses.
    pub bytes_in: u64,
    /// The last snap/1 `TrieNodes` frame, held for [`Peer::trie_nodes`].
    trie_reply: Option<TrieNodesMessage>,
}

/// snap/1 `GetTrieNodes` (0x06): nodes by path at `root`. Each path set is
/// either `[compact(path)]` in the account trie or
/// `[account_hash, compact(path)...]` in that account's storage trie.
#[derive(Debug, Clone, PartialEq, Eq, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
pub struct GetTrieNodesMessage {
    pub request_id: u64,
    pub root: B256,
    pub paths: Vec<Vec<Bytes>>,
    pub bytes: u64,
}

/// snap/1 `TrieNodes` (0x07): the nodes in request order, cut short at the
/// byte limit; a path the peer cannot resolve comes back empty or not at all.
#[derive(Debug, Clone, PartialEq, Eq, alloy_rlp::RlpEncodable, alloy_rlp::RlpDecodable)]
pub struct TrieNodesMessage {
    pub request_id: u64,
    pub nodes: Vec<Bytes>,
}

const GET_TRIE_NODES: u8 = 0x06;
const TRIE_NODES: u8 = 0x07;

enum Inbound {
    Eth(EthMessage<EthNetworkPrimitives>),
    Snap(SnapProtocolMessage),
    /// A frame this crate does not decode (snap/1 trie-node messages, odd ids).
    Ignored,
}

impl Peer {
    /// Dial `record` and run every handshake. `timeout` bounds each step
    /// and, afterwards, each request.
    pub async fn connect(
        record: NodeRecord,
        key: &SecretKey,
        status: UnifiedStatus,
        fork_filter: ForkFilter,
        timeout_each: Duration,
    ) -> Result<Peer, PeerError> {
        Peer::connect_on(Net::Mainnet, record, key, status, fork_filter, timeout_each, true).await
    }

    /// [`Peer::connect`] on `net`, and without `snap` if `require_snap` is
    /// false (then `snap_version` is 0 and every frame is `eth`'s).
    pub async fn connect_on(
        net: Net,
        record: NodeRecord,
        key: &SecretKey,
        status: UnifiedStatus,
        fork_filter: ForkFilter,
        timeout_each: Duration,
        require_snap: bool,
    ) -> Result<Peer, PeerError> {
        Peer::connect_with(net, record, key, status, fork_filter, timeout_each, require_snap, false, false).await
    }

    /// A mainnet connection offering `snap/1` only, for its trie-node
    /// messages (snap/2 drops them for block access lists): a peer without
    /// `snap/1` fails with [`PeerError::NoSnap`].
    pub async fn connect_snap1(
        record: NodeRecord,
        key: &SecretKey,
        status: UnifiedStatus,
        fork_filter: ForkFilter,
        timeout_each: Duration,
    ) -> Result<Peer, PeerError> {
        Peer::connect_with(Net::Mainnet, record, key, status, fork_filter, timeout_each, true, false, true).await
    }

    /// A mainnet connection for history: `eth/68`, `eth/69` and `eth/70`
    /// offered (the newest shared is taken), `snap` too but not required.
    /// Bodies and receipts come over [`Peer::bodies`] and
    /// [`Peer::receipts`], which handle each version's encoding.
    pub async fn connect_history(
        record: NodeRecord,
        key: &SecretKey,
        status: UnifiedStatus,
        fork_filter: ForkFilter,
        timeout_each: Duration,
    ) -> Result<Peer, PeerError> {
        Peer::connect_with(Net::Mainnet, record, key, status, fork_filter, timeout_each, false, true, false).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn connect_with(
        net: Net,
        record: NodeRecord,
        key: &SecretKey,
        status: UnifiedStatus,
        fork_filter: ForkFilter,
        timeout_each: Duration,
        require_snap: bool,
        eth70: bool,
        snap1_only: bool,
    ) -> Result<Peer, PeerError> {
        let addr = SocketAddr::new(record.address, record.tcp_port);
        let tcp = timeout(timeout_each, TcpStream::connect(addr)).await.map_err(|_| PeerError::Timeout)??;
        tcp.set_nodelay(true)?;
        let ecies = ECIESStream::connect_with_timeout(tcp, *key, record.id, timeout_each).await?;
        let our_id = pk2id(&key.public_key(SECP256K1));
        let mut hello = HelloMessageWithProtocols::builder(our_id).protocol(Protocol::eth_68()).protocol(Protocol::eth(EthVersion::Eth69));
        if eth70 {
            hello = hello.protocol(Protocol::eth(EthVersion::Eth70));
        }
        if net.offers_eth71() {
            hello = hello.protocol(Protocol::eth(EthVersion::Eth71));
        }
        let hello = hello.protocol(Protocol::new(Capability::new_static("snap", 1), 8));
        let hello = if snap1_only { hello } else { hello.protocol(Protocol::snap_2()) };
        let hello = hello.client_version(CLIENT_VERSION).build();
        let (mut conn, their_hello) = timeout(timeout_each, UnauthedP2PStream::new(ecies).handshake(hello)).await.map_err(|_| PeerError::Timeout)??;
        let (eth_version, snap_offset, snap_version) = {
            let caps = conn.shared_capabilities();
            let eth_version = caps.eth_version()?;
            match caps.find(&Capability::snap_2()).or_else(|| caps.find(&Capability::new_static("snap", 1))) {
                Some(snap) => (eth_version, snap.relative_message_id_offset(), snap.version()),
                None if !require_snap => (eth_version, u8::MAX, 0),
                None => return Err(PeerError::NoSnap),
            }
        };
        let mut status = status;
        status.version = eth_version;
        let their_status = EthHandshake::default().handshake(&mut conn, status, fork_filter, timeout_each).await?;
        Ok(Peer {
            conn,
            eth_version,
            snap_offset,
            snap_version,
            status: their_status,
            record,
            client: their_hello.client_version,
            timeout: timeout_each,
            next_id: 1,
            bytes_in: 0,
            trie_reply: None,
        })
    }

    pub fn id(&self) -> PeerId {
        self.record.id
    }

    pub async fn close(mut self) {
        let _ = timeout(Duration::from_secs(2), self.conn.disconnect(DisconnectReason::ClientQuitting)).await;
    }

    fn request_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// `GetAccountRange` at `root`; the peer answers with consecutive
    /// accounts from `origin`, including the first past `limit`, and the
    /// boundary proofs, or with nothing if it no longer has `root`.
    pub async fn account_range(&mut self, root: B256, origin: B256, limit: B256, response_bytes: u64) -> Result<AccountRangeMessage, PeerError> {
        let request_id = self.request_id();
        let req = SnapProtocolMessage::GetAccountRange(GetAccountRangeMessage {
            request_id,
            root_hash: root,
            starting_hash: origin,
            limit_hash: limit,
            response_bytes,
        });
        match self.snap_request(req, SnapMessageId::AccountRange, request_id).await? {
            SnapProtocolMessage::AccountRange(m) => Ok(m),
            _ => Err(PeerError::Protocol("wrong snap response")),
        }
    }

    /// `GetStorageRanges` at `root` for `accounts` (hashed addresses). With
    /// one account and an origin, the slots from that origin on.
    pub async fn storage_ranges(
        &mut self,
        root: B256,
        accounts: Vec<B256>,
        origin: Option<B256>,
        response_bytes: u64,
    ) -> Result<StorageRangesMessage, PeerError> {
        let request_id = self.request_id();
        let req = SnapProtocolMessage::GetStorageRanges(GetStorageRangesMessage {
            request_id,
            root_hash: root,
            account_hashes: accounts,
            starting_hash: origin.map(RangeBound::from).unwrap_or_default(),
            limit_hash: RangeBound::default(),
            response_bytes,
        });
        match self.snap_request(req, SnapMessageId::StorageRanges, request_id).await? {
            SnapProtocolMessage::StorageRanges(m) => Ok(m),
            _ => Err(PeerError::Protocol("wrong snap response")),
        }
    }

    pub async fn byte_codes(&mut self, hashes: Vec<B256>, response_bytes: u64) -> Result<ByteCodesMessage, PeerError> {
        let request_id = self.request_id();
        let req = SnapProtocolMessage::GetByteCodes(GetByteCodesMessage { request_id, hashes, response_bytes });
        match self.snap_request(req, SnapMessageId::ByteCodes, request_id).await? {
            SnapProtocolMessage::ByteCodes(m) => Ok(m),
            _ => Err(PeerError::Protocol("wrong snap response")),
        }
    }

    /// The header for `hash` over `eth`, checked to hash to it. `None` if
    /// the peer does not have it.
    pub async fn header(&mut self, hash: B256) -> Result<Option<Header>, PeerError> {
        let request_id = self.request_id();
        let msg = EthMessage::<EthNetworkPrimitives>::GetBlockHeaders(RequestPair {
            request_id,
            message: GetBlockHeaders { start_block: hash.into(), limit: 1, skip: 0, direction: HeadersDirection::Rising },
        });
        self.send_eth(msg).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.next_before(deadline).await? {
                Inbound::Eth(EthMessage::BlockHeaders(rp)) if rp.request_id == request_id => {
                    let Some(h) = rp.message.0.into_iter().next() else {
                        return Ok(None);
                    };
                    if h.hash_slow() != hash {
                        return Err(PeerError::Protocol("header does not hash to the requested hash"));
                    }
                    return Ok(Some(h));
                }
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Ignored => {}
            }
        }
    }

    /// The header at `number` over `eth`, checked to carry that number.
    /// Nothing proves it canonical; in epoch mode finality does, later.
    pub async fn header_at(&mut self, number: u64) -> Result<Option<Header>, PeerError> {
        let request_id = self.request_id();
        let msg = EthMessage::<EthNetworkPrimitives>::GetBlockHeaders(RequestPair {
            request_id,
            message: GetBlockHeaders { start_block: number.into(), limit: 1, skip: 0, direction: HeadersDirection::Rising },
        });
        self.send_eth(msg).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.next_before(deadline).await? {
                Inbound::Eth(EthMessage::BlockHeaders(rp)) if rp.request_id == request_id => {
                    let Some(h) = rp.message.0.into_iter().next() else {
                        return Ok(None);
                    };
                    if h.number != number {
                        return Err(PeerError::Protocol("header is not at the requested number"));
                    }
                    return Ok(Some(h));
                }
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Ignored => {}
            }
        }
    }

    /// Up to `limit` headers from `hash` toward genesis, each checked to be
    /// the parent of the one before (the first to hash to `hash`).
    pub async fn headers_back(&mut self, hash: B256, limit: u64) -> Result<Vec<Header>, PeerError> {
        let request_id = self.request_id();
        let msg = EthMessage::<EthNetworkPrimitives>::GetBlockHeaders(RequestPair {
            request_id,
            message: GetBlockHeaders { start_block: hash.into(), limit, skip: 0, direction: HeadersDirection::Falling },
        });
        self.send_eth(msg).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.next_before(deadline).await? {
                Inbound::Eth(EthMessage::BlockHeaders(rp)) if rp.request_id == request_id => {
                    let mut want = hash;
                    for h in &rp.message.0 {
                        if h.hash_slow() != want {
                            return Err(PeerError::Protocol("headers do not chain back from the requested hash"));
                        }
                        want = h.parent_hash;
                    }
                    return Ok(rp.message.0);
                }
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Ignored => {}
            }
        }
    }

    /// `eth/71` `GetBlockAccessLists`: one entry per hash, `None` where the
    /// peer has none. The raw RLP of each list, unchecked.
    pub async fn block_access_lists(&mut self, hashes: Vec<B256>) -> Result<Vec<Option<Bytes>>, PeerError> {
        if self.eth_version < EthVersion::Eth71 {
            return Err(PeerError::Protocol("block access lists need eth/71"));
        }
        let request_id = self.request_id();
        let msg = EthMessage::<EthNetworkPrimitives>::GetBlockAccessLists(RequestPair { request_id, message: GetBlockAccessLists(hashes) });
        self.send_eth(msg).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.next_before(deadline).await? {
                Inbound::Eth(EthMessage::BlockAccessLists(rp)) if rp.request_id == request_id => return Ok(rp.message.0),
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Ignored => {}
            }
        }
    }

    /// `snap/2` `GetBlockAccessLists` (EIP-8189), as [`Peer::block_access_lists`].
    pub async fn snap_block_access_lists(&mut self, hashes: Vec<B256>, response_bytes: u64) -> Result<Vec<Option<Bytes>>, PeerError> {
        if self.snap_version < 2 {
            return Err(PeerError::Protocol("block access lists over snap need snap/2"));
        }
        let request_id = self.request_id();
        let req = SnapProtocolMessage::GetBlockAccessLists(GetBlockAccessListsMessage { request_id, block_hashes: hashes, response_bytes });
        match self.snap_request(req, SnapMessageId::BlockAccessLists, request_id).await? {
            SnapProtocolMessage::BlockAccessLists(m) => Ok(m.block_access_lists.0),
            _ => Err(PeerError::Protocol("wrong snap response")),
        }
    }

    /// `GetBlockBodies` for `hashes`: the bodies of a prefix of them, in
    /// order (a peer answers fewer when its response fills, or none when it
    /// lacks the first). Unchecked: the caller holds the headers.
    pub async fn bodies(&mut self, hashes: Vec<B256>) -> Result<Vec<EthBlockBody>, PeerError> {
        let request_id = self.request_id();
        let msg = EthMessage::<EthNetworkPrimitives>::GetBlockBodies(RequestPair { request_id, message: GetBlockBodies(hashes) });
        self.send_eth(msg).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.next_before(deadline).await? {
                Inbound::Eth(EthMessage::BlockBodies(rp)) if rp.request_id == request_id => return Ok(rp.message.0),
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Ignored => {}
            }
        }
    }

    /// `GetReceipts` for `hashes`: for a prefix of them, each block's
    /// receipt-trie leaves (EIP-2718 receipts with their bloom), in order.
    /// `eth/68` sends the bloom, which the leaf keeps as sent; `eth/69` and
    /// `eth/70` omit it and it is recomputed from the logs. On `eth/70` a
    /// peer may cut the last block short (`lastBlockIncomplete`); that
    /// block is continued from its next index until it is whole, and it is
    /// dropped if the peer stops serving it. An answer with more lists than
    /// blocks asked, or marked incomplete with no block in it, is a
    /// protocol error. Unchecked otherwise: the caller rebuilds each
    /// block's `receiptsRoot`.
    pub async fn receipts(&mut self, hashes: Vec<B256>) -> Result<Vec<Vec<Vec<u8>>>, PeerError> {
        let eth70 = self.eth_version >= EthVersion::Eth70;
        receipts_continued(self, hashes, eth70).await
    }

    async fn receipts_page(&mut self, hashes: Vec<B256>, first_index: u64) -> Result<ReceiptsPage, PeerError> {
        let request_id = self.request_id();
        let msg = if self.eth_version >= EthVersion::Eth70 {
            EthMessage::<EthNetworkPrimitives>::GetReceipts70(RequestPair {
                request_id,
                message: GetReceipts70 { first_block_receipt_index: first_index, block_hashes: hashes },
            })
        } else {
            EthMessage::<EthNetworkPrimitives>::GetReceipts(RequestPair { request_id, message: GetReceipts(hashes) })
        };
        self.send_eth(msg).await?;
        let deadline = Instant::now() + self.timeout;
        let with_bloom = |blocks: Vec<Vec<EthReceipt>>| -> Vec<Vec<Vec<u8>>> {
            blocks.into_iter().map(|b| b.iter().map(|r| r.with_bloom_ref().encoded_2718()).collect()).collect()
        };
        loop {
            match self.next_before(deadline).await? {
                Inbound::Eth(EthMessage::Receipts(rp)) if rp.request_id == request_id => {
                    let blocks = rp.message.0.into_iter().map(|b| b.into_iter().map(|r| r.encoded_2718()).collect()).collect();
                    return Ok((blocks, false));
                }
                Inbound::Eth(EthMessage::Receipts69(rp)) if rp.request_id == request_id => return Ok((with_bloom(rp.message.0), false)),
                Inbound::Eth(EthMessage::Receipts70(rp)) if rp.request_id == request_id => {
                    return Ok((with_bloom(rp.message.receipts), rp.message.last_block_incomplete));
                }
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Ignored => {}
            }
        }
    }

    /// The peer's own head header, from the hash in its status.
    pub async fn own_head(&mut self) -> Result<Option<Header>, PeerError> {
        let hash = self.status.blockhash;
        self.header(hash).await
    }

    async fn snap_request(&mut self, req: SnapProtocolMessage, want: SnapMessageId, request_id: u64) -> Result<SnapProtocolMessage, PeerError> {
        self.send_snap(req).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.next_before(deadline).await? {
                Inbound::Snap(m) if m.message_id() == want && snap_request_id(&m) == Some(request_id) => return Ok(m),
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Ignored => {}
            }
        }
    }

    async fn send_snap(&mut self, msg: SnapProtocolMessage) -> Result<(), PeerError> {
        let mut bytes = msg.encode().to_vec();
        bytes[0] += self.snap_offset;
        self.conn.send(bytes::Bytes::from(bytes)).await?;
        Ok(())
    }

    async fn send_eth(&mut self, msg: EthMessage<EthNetworkPrimitives>) -> Result<(), PeerError> {
        let bytes: bytes::Bytes = alloy_rlp::encode(ProtocolMessage::from(msg)).into();
        self.conn.send(bytes).await?;
        Ok(())
    }

    /// Keep the connection alive while there is nothing to ask: read for
    /// `for_` servicing the peer's pings and requests. Reading a ping only
    /// queues the pong; it reaches the wire when the sink is polled, so the
    /// sink is driven every second (which also sends our own pings). Read
    /// without that, an idle peer heard nothing from us and Geth closed the
    /// connection after its 30 s read timeout.
    pub async fn idle(&mut self, for_: Duration) -> Result<(), PeerError> {
        let deadline = Instant::now() + for_;
        loop {
            self.flush_control().await?;
            let slice = deadline.min(Instant::now() + Duration::from_secs(1));
            match self.next_before(slice).await {
                Ok(Inbound::Eth(m)) => self.service_eth(m).await?,
                Ok(Inbound::Snap(m)) => self.service_snap(m).await?,
                Ok(Inbound::Ignored) => {}
                Err(PeerError::Timeout) if Instant::now() < deadline => {}
                Err(PeerError::Timeout) => return self.flush_control().await,
                Err(e) => return Err(e),
            }
        }
    }

    /// Send what the stream queued on its own: pongs, its pings.
    async fn flush_control(&mut self) -> Result<(), PeerError> {
        std::future::poll_fn(|cx| futures::Sink::<bytes::Bytes>::poll_ready(std::pin::Pin::new(&mut self.conn), cx)).await?;
        self.conn.flush().await?;
        Ok(())
    }

    /// snap/1 `GetTrieNodes` at `root`; the reply's nodes in request order
    /// (see [`TrieNodesMessage`]). Needs a `snap/1` connection.
    pub async fn trie_nodes(&mut self, root: B256, paths: Vec<Vec<Bytes>>, bytes: u64) -> Result<Vec<Bytes>, PeerError> {
        if self.snap_version != 1 {
            return Err(PeerError::Protocol("trie nodes need snap/1"));
        }
        let request_id = self.request_id();
        let req = GetTrieNodesMessage { request_id, root, paths, bytes };
        self.send_snap_raw(GET_TRIE_NODES, &alloy_rlp::encode(&req)).await?;
        let deadline = Instant::now() + self.timeout;
        loop {
            match self.next_before(deadline).await? {
                Inbound::Snap(m) => self.service_snap(m).await?,
                Inbound::Eth(m) => self.service_eth(m).await?,
                Inbound::Ignored => {}
            }
            if let Some(r) = self.trie_reply.take() {
                if r.request_id == request_id {
                    return Ok(r.nodes);
                }
            }
        }
    }

    /// A snap/1 trie-node frame: hold a reply for [`Peer::trie_nodes`],
    /// answer a request with no nodes (we hold no state).
    async fn trie_frame(&mut self, rel: u8, mut body: &[u8]) -> Result<Inbound, PeerError> {
        use alloy_rlp::Decodable;
        if rel == TRIE_NODES {
            if let Ok(m) = TrieNodesMessage::decode(&mut body) {
                self.trie_reply = Some(m);
            }
        } else if let Ok(m) = GetTrieNodesMessage::decode(&mut body) {
            let empty = TrieNodesMessage { request_id: m.request_id, nodes: vec![] };
            self.send_snap_raw(TRIE_NODES, &alloy_rlp::encode(&empty)).await?;
        }
        Ok(Inbound::Ignored)
    }

    async fn send_snap_raw(&mut self, rel: u8, rlp: &[u8]) -> Result<(), PeerError> {
        let mut bytes = Vec::with_capacity(rlp.len() + 1);
        bytes.push(rel + self.snap_offset);
        bytes.extend_from_slice(rlp);
        self.conn.send(bytes::Bytes::from(bytes)).await?;
        Ok(())
    }

    /// The negotiated `eth` version.
    pub fn eth_version(&self) -> u8 {
        self.eth_version as u8
    }

    async fn next_before(&mut self, deadline: Instant) -> Result<Inbound, PeerError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(PeerError::Timeout);
        }
        let frame = timeout(remaining, self.conn.next()).await.map_err(|_| PeerError::Timeout)?.ok_or(PeerError::Closed)??;
        if frame.is_empty() {
            return Ok(Inbound::Ignored);
        }
        self.bytes_in += frame.len() as u64;
        let id = frame[0];
        if id >= self.snap_offset {
            let rel = id - self.snap_offset;
            if self.snap_version == 1 && (rel == GET_TRIE_NODES || rel == TRIE_NODES) {
                return self.trie_frame(rel, &frame[1..]).await;
            }
            return Ok(match SnapProtocolMessage::decode(rel, &mut &frame[1..]) {
                Ok(m) => Inbound::Snap(m),
                Err(_) => Inbound::Ignored,
            });
        }
        Ok(match ProtocolMessage::<EthNetworkPrimitives>::decode_message(self.eth_version, &mut &frame[..]) {
            Ok(m) => Inbound::Eth(m.message),
            Err(_) => Inbound::Ignored,
        })
    }

    /// Answer the peer's `eth` requests with nothing; drop its broadcasts.
    async fn service_eth(&mut self, m: EthMessage<EthNetworkPrimitives>) -> Result<(), PeerError> {
        let reply = match m {
            EthMessage::GetBlockHeaders(rp) => Some(EthMessage::BlockHeaders(RequestPair { request_id: rp.request_id, message: BlockHeaders(vec![]) })),
            EthMessage::GetBlockBodies(rp) => Some(EthMessage::BlockBodies(RequestPair { request_id: rp.request_id, message: BlockBodies(vec![]) })),
            EthMessage::GetPooledTransactions(rp) => {
                Some(EthMessage::PooledTransactions(RequestPair { request_id: rp.request_id, message: PooledTransactions(vec![]) }))
            }
            EthMessage::GetReceipts(rp) => Some(EthMessage::Receipts(RequestPair { request_id: rp.request_id, message: Receipts(vec![]) })),
            EthMessage::GetBlockAccessLists(rp) => {
                let none = vec![None; rp.message.0.len()];
                Some(EthMessage::BlockAccessLists(RequestPair { request_id: rp.request_id, message: BlockAccessLists(none) }))
            }
            _ => None,
        };
        if let Some(r) = reply {
            self.send_eth(r).await?;
        }
        Ok(())
    }

    /// Answer the peer's `snap` requests with nothing (we hold no state);
    /// drop responses to requests we are not waiting for.
    async fn service_snap(&mut self, m: SnapProtocolMessage) -> Result<(), PeerError> {
        let reply = match m {
            SnapProtocolMessage::GetAccountRange(r) => {
                Some(SnapProtocolMessage::AccountRange(AccountRangeMessage { request_id: r.request_id, accounts: vec![], proof: vec![] }))
            }
            SnapProtocolMessage::GetStorageRanges(r) => {
                Some(SnapProtocolMessage::StorageRanges(StorageRangesMessage { request_id: r.request_id, slots: vec![], proof: vec![] }))
            }
            SnapProtocolMessage::GetByteCodes(r) => Some(SnapProtocolMessage::ByteCodes(ByteCodesMessage { request_id: r.request_id, codes: vec![] })),
            SnapProtocolMessage::GetBlockAccessLists(r) => {
                Some(SnapProtocolMessage::BlockAccessLists(BlockAccessListsMessage { request_id: r.request_id, block_access_lists: Default::default() }))
            }
            _ => None,
        };
        if let Some(r) = reply {
            self.send_snap(r).await?;
        }
        Ok(())
    }
}

fn snap_request_id(m: &SnapProtocolMessage) -> Option<u64> {
    Some(match m {
        SnapProtocolMessage::GetAccountRange(x) => x.request_id,
        SnapProtocolMessage::AccountRange(x) => x.request_id,
        SnapProtocolMessage::GetStorageRanges(x) => x.request_id,
        SnapProtocolMessage::StorageRanges(x) => x.request_id,
        SnapProtocolMessage::GetByteCodes(x) => x.request_id,
        SnapProtocolMessage::ByteCodes(x) => x.request_id,
        SnapProtocolMessage::GetBlockAccessLists(x) => x.request_id,
        SnapProtocolMessage::BlockAccessLists(x) => x.request_id,
    })
}

/// One `GetReceipts` answer: the receipt-trie leaves of a prefix of the
/// asked blocks, and `eth/70`'s `lastBlockIncomplete`.
pub(crate) type ReceiptsPage = (Vec<Vec<Vec<u8>>>, bool);

/// Where [`receipts_continued`] gets each answer: a peer, or a test's
/// scripted one.
pub(crate) trait ReceiptPages {
    async fn receipt_page(&mut self, hashes: Vec<B256>, first_index: u64) -> Result<ReceiptsPage, PeerError>;
}

impl ReceiptPages for Peer {
    async fn receipt_page(&mut self, hashes: Vec<B256>, first_index: u64) -> Result<ReceiptsPage, PeerError> {
        self.receipts_page(hashes, first_index).await
    }
}

/// An answer to `asked` hashes is at most `asked` lists, and only an
/// answer with a block in it can leave its last block incomplete. Checked
/// before anything indexes the request by the answer.
fn receipts_shape(asked: usize, (blocks, incomplete): &ReceiptsPage) -> Result<(), PeerError> {
    if blocks.len() > asked {
        return Err(PeerError::Protocol("more receipt lists than blocks asked"));
    }
    if *incomplete && blocks.is_empty() {
        return Err(PeerError::Protocol("an incomplete receipts answer with no block"));
    }
    Ok(())
}

/// [`Peer::receipts`] over any source of answers: the first answer, then
/// on `eth/70` the last block continued while the peer marks it
/// incomplete. Every answer's shape is checked first.
pub(crate) async fn receipts_continued(src: &mut impl ReceiptPages, hashes: Vec<B256>, eth70: bool) -> Result<Vec<Vec<Vec<u8>>>, PeerError> {
    let first = src.receipt_page(hashes.clone(), 0).await?;
    receipts_shape(hashes.len(), &first)?;
    let (mut blocks, incomplete) = first;
    if !eth70 {
        return Ok(blocks);
    }
    let mut incomplete = incomplete;
    let mut rounds = 0;
    while incomplete {
        rounds += 1;
        if rounds > 256 {
            return Err(PeerError::Protocol("receipts never completed"));
        }
        // Non-empty: an incomplete answer has a block (checked above and
        // below), and a block is popped only with `incomplete` cleared.
        let i = blocks.len() - 1;
        let have = blocks[i].len() as u64;
        let more = src.receipt_page(vec![hashes[i]], have).await?;
        receipts_shape(1, &more)?;
        let (more, inc) = more;
        match more.into_iter().next() {
            Some(rest) if !rest.is_empty() => {
                blocks[i].extend(rest);
                incomplete = inc;
            }
            _ => {
                blocks.pop();
                incomplete = false;
            }
        }
    }
    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    /// Scripted answers, and the requests that drew them.
    struct Scripted {
        answers: VecDeque<ReceiptsPage>,
        asked: Vec<(Vec<B256>, u64)>,
    }

    impl ReceiptPages for Scripted {
        async fn receipt_page(&mut self, hashes: Vec<B256>, first_index: u64) -> Result<ReceiptsPage, PeerError> {
            self.asked.push((hashes, first_index));
            self.answers.pop_front().ok_or(PeerError::Protocol("no more scripted answers"))
        }
    }

    fn scripted(answers: Vec<ReceiptsPage>) -> Scripted {
        Scripted { answers: answers.into(), asked: Vec::new() }
    }

    fn hashes(n: u8) -> Vec<B256> {
        (0..n).map(B256::repeat_byte).collect()
    }

    fn leaves(xs: &[u8]) -> Vec<Vec<u8>> {
        xs.iter().map(|x| vec![*x]).collect()
    }

    #[tokio::test]
    async fn more_receipt_lists_than_asked_is_a_protocol_error() {
        for eth70 in [false, true] {
            for incomplete in [false, true] {
                let mut p = scripted(vec![(vec![leaves(&[1]), leaves(&[2]), leaves(&[3])], incomplete)]);
                let r = receipts_continued(&mut p, hashes(2), eth70).await;
                assert!(matches!(r, Err(PeerError::Protocol(_))), "eth70={eth70} incomplete={incomplete}: {r:?}");
                assert_eq!(p.asked.len(), 1);
            }
        }
    }

    #[tokio::test]
    async fn a_malformed_continuation_is_a_protocol_error() {
        // Incomplete with no block at all.
        let mut p = scripted(vec![(vec![], true)]);
        assert!(matches!(receipts_continued(&mut p, hashes(2), true).await, Err(PeerError::Protocol(_))));
        // A continuation of one block answered with two lists.
        let mut p = scripted(vec![(vec![leaves(&[1]), leaves(&[2])], true), (vec![leaves(&[3]), leaves(&[4])], false)]);
        assert!(matches!(receipts_continued(&mut p, hashes(2), true).await, Err(PeerError::Protocol(_))));
        // A continuation answered incomplete with no block.
        let mut p = scripted(vec![(vec![leaves(&[1])], true), (vec![], true)]);
        assert!(matches!(receipts_continued(&mut p, hashes(2), true).await, Err(PeerError::Protocol(_))));
    }

    #[tokio::test]
    async fn an_incomplete_last_block_is_continued_or_dropped() {
        let h = hashes(3);
        let mut p = scripted(vec![(vec![leaves(&[1]), leaves(&[2, 3])], true), (vec![leaves(&[4])], true), (vec![leaves(&[5])], false)]);
        let r = receipts_continued(&mut p, h.clone(), true).await.unwrap();
        assert_eq!(r, vec![leaves(&[1]), leaves(&[2, 3, 4, 5])]);
        assert_eq!(p.asked[1..], [(vec![h[1]], 2), (vec![h[1]], 3)]);
        // The peer stops serving the cut block: it is dropped, the rest kept.
        let mut p = scripted(vec![(vec![leaves(&[1]), leaves(&[2])], true), (vec![], false)]);
        assert_eq!(receipts_continued(&mut p, h.clone(), true).await.unwrap(), vec![leaves(&[1])]);
        // Before eth/70 the flag cannot be set and nothing is continued.
        let mut p = scripted(vec![(vec![leaves(&[1]), leaves(&[2])], false)]);
        assert_eq!(receipts_continued(&mut p, h, false).await.unwrap().len(), 2);
        assert_eq!(p.asked.len(), 1);
    }
}
