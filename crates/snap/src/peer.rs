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

use alloy_consensus::Header;
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
use reth_eth_wire_types::message::RequestPair;
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
}

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
        let addr = SocketAddr::new(record.address, record.tcp_port);
        let tcp = timeout(timeout_each, TcpStream::connect(addr)).await.map_err(|_| PeerError::Timeout)??;
        tcp.set_nodelay(true)?;
        let ecies = ECIESStream::connect_with_timeout(tcp, *key, record.id, timeout_each).await?;
        let our_id = pk2id(&key.public_key(SECP256K1));
        let mut hello = HelloMessageWithProtocols::builder(our_id).protocol(Protocol::eth_68()).protocol(Protocol::eth(EthVersion::Eth69));
        if net.offers_eth71() {
            hello = hello.protocol(Protocol::eth(EthVersion::Eth71));
        }
        let hello = hello.protocol(Protocol::new(Capability::new_static("snap", 1), 8)).protocol(Protocol::snap_2()).client_version(CLIENT_VERSION).build();
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
    /// `for_` servicing the peer's pings and requests. `P2PStream` answers
    /// pings only when polled, so an idle peer that is not read drops us
    /// with "ping timeout".
    pub async fn idle(&mut self, for_: Duration) -> Result<(), PeerError> {
        let deadline = Instant::now() + for_;
        loop {
            match self.next_before(deadline).await {
                Ok(Inbound::Eth(m)) => self.service_eth(m).await?,
                Ok(Inbound::Snap(m)) => self.service_snap(m).await?,
                Ok(Inbound::Ignored) => {}
                Err(PeerError::Timeout) => return Ok(()),
                Err(e) => return Err(e),
            }
        }
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
