//! State acquisition over `snap` from mainnet peers, with no node: the
//! milestone 1 input of `wiki/projects/cold-state-layer/specs/poc-ethereum.md`.
//!
//! - [`peer`]: one RLPx connection (ECIES, hello, eth status) carrying
//!   `eth` requests for headers and `snap` requests for ranges and code.
//! - [`discovery`]: candidates from the EIP-1459 DNS tree and discv4.
//! - [`fetch`]: the slice fetcher, which verifies every range proof and
//!   every bytecode as it arrives and re-pivots when peers forget the root.
//! - [`slice`]: the fetched slice on disk, the build's input.
//!
//! The `csl-eth` binary drives it: `fetch` a prefix, `build` a bucket
//! from a slice, `check` a bucket, `peers` to probe connectivity,
//! `bal-probe` to ask testnet peers for block access lists ([`bal`]),
//! `bal-replay` to reproduce a testnet's recent state roots from them
//! ([`replay`]), and the
//! milestone 1 exit tests: [`workload`] and [`faults`]; `track` keeps a
//! published state at the verified head ([`track`]), uploading through
//! [`publish`].
//! `history` acquires blocks, receipts and headers below the verified head
//! and writes and reads the §3c history tables ([`history`]).

pub mod bal;
pub mod beacon;
pub mod discovery;
pub mod faults;
pub mod fetch;
pub mod heal;
pub mod track;
pub mod history;
pub mod peer;
pub mod publish;
pub mod remote;
pub mod replay;
pub mod slice;
pub mod workload;

pub use fetch::{fetch, probe, Config as FetchConfig, FetchError};
pub use peer::{Peer, PeerError};
pub use slice::{Slice, SliceError, SliceHead};
