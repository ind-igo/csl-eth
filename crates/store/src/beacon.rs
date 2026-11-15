//! The accumulator route to old execution headers (profile §3c, "Old
//! headers"): files that prove, from a verified beacon block, that an
//! execution block hash is the payload of the canonical beacon block at a
//! slot. A client holding the header's RLP checks `keccak` against that
//! hash and the header's number against the one it asked for, and has the
//! header without walking `parentHash` over every block in between.
//!
//! The proof, Capella onward (all SSZ `hash_tree_root`, sha256):
//!
//! 1. the head's beacon block header hashes to the root the light client
//!    verified, and names a `state_root`;
//! 2. that state commits to `block_roots` (the last 8,192 slots, a ring)
//!    and to `historical_summaries` (one `block_summary_root` per closed
//!    8,192-slot period since Capella, each the root of that period's
//!    `block_roots`);
//! 3. so a slot's beacon block root is a leaf of the ring (the head's own
//!    period) or of a closed period's vector;
//! 4. the block root commits to the block's `body_root`, the body to its
//!    `execution_payload`, and the payload to `block_hash`.
//!
//! Layout (fixed-size records, so a client knows every offset from the
//! slot alone and fetches one range per file):
//!
//! ```text
//! beacon/heads/<beacon_root>   per verified head: preamble (576 B) + 128 ring records (224 B)
//! beacon/periods/<p>           per closed period: 128 records (224 B), chunk root -> block_summary_root
//! beacon/summaries/<len>       per historical_summaries length: len records (32 (1 + d) B)
//! beacon/chunks/<c>            per 64-slot chunk (slots 64c .. 64c + 63): 64 records (576 B)
//! ```
//!
//! A chunk record for slot `s` holds the 6 sibling roots from `s`'s leaf to
//! its chunk's root, then the block's body proof (payload 5, body 4,
//! header 3). The chunk's root is the same whether the ring or a closed
//! period holds it, so chunk files are written once. A period record, or
//! the head's ring record, holds the 7 siblings from the chunk root to the
//! vector root. A summaries record holds `state_summary_root` and the `d`
//! siblings within the list's data tree (`d = ceil(log2 len)`); above `d`
//! the siblings are zero subtrees the client computes.
//!
//! Nothing here is evidence until it hashes to the verified head: every
//! file is untrusted, and the slot a client asks about comes from the
//! header's own timestamp, so a wrong slot only fails to verify.
//!
//! Before Capella there are no `historical_summaries`: Bellatrix blocks
//! would need the frozen `historical_roots` (each root commits to a period's
//! block and state roots together) and pre-merge blocks the era1
//! accumulator. Neither is built.

use alloy_primitives::B256;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Mainnet fork slots the layouts depend on.
pub const CAPELLA_SLOT: u64 = 194_048 * 32;
pub const DENEB_SLOT: u64 = 269_568 * 32;
pub const ELECTRA_SLOT: u64 = 364_032 * 32;

pub const SLOTS_PER_HISTORICAL_ROOT: u64 = 8192;
/// The period `historical_summaries[0]` covers.
pub const CAPELLA_PERIOD: u64 = CAPELLA_SLOT / SLOTS_PER_HISTORICAL_ROOT;
/// `HISTORICAL_ROOTS_LIMIT`: the list's limit, so its data tree's depth.
pub const SUMMARIES_LIMIT_DEPTH: usize = 24;

pub const CHUNK_DEPTH: usize = 6;
pub const CHUNK_SLOTS: u64 = 1 << CHUNK_DEPTH;
pub const TOP_DEPTH: usize = 13 - CHUNK_DEPTH;
pub const CHUNKS_PER_PERIOD: u64 = 1 << TOP_DEPTH;

/// `BeaconState` field indices.
pub const STATE_BLOCK_ROOTS: u64 = 5;
pub const STATE_HISTORICAL_SUMMARIES: u64 = 27;
/// The state tree's depth: 28 fields to Deneb, 37 from Electra, 38 Fulu.
pub fn state_depth(slot: u64) -> usize {
    if slot >= ELECTRA_SLOT {
        6
    } else {
        5
    }
}
const MAX_STATE_DEPTH: usize = 6;

/// `ExecutionPayload`: `block_hash` is field 12 of 15 (Capella) or 17.
pub const PAYLOAD_BLOCK_HASH: u64 = 12;
pub fn payload_depth(slot: u64) -> usize {
    if slot >= DENEB_SLOT {
        5
    } else {
        4
    }
}
/// `BeaconBlockBody`: `execution_payload` is field 9 of 11 to 13.
pub const BODY_EXECUTION_PAYLOAD: u64 = 9;
pub const BODY_DEPTH: usize = 4;
/// `BeaconBlockHeader` (and `BeaconBlock`): `body_root` is field 4 of 5.
pub const HEADER_BODY_ROOT: u64 = 4;
pub const HEADER_DEPTH: usize = 3;

const PAYLOAD_SLOTS: usize = 5;
const R: usize = 32;
pub const CHUNK_RECORD: usize = R * (CHUNK_DEPTH + PAYLOAD_SLOTS + BODY_DEPTH + HEADER_DEPTH);
pub const TOP_RECORD: usize = R * TOP_DEPTH;
pub const HEAD_MAGIC: &[u8; 8] = b"csl-bcn1";
pub const HEAD_PREAMBLE: usize =
    8 + 8 + 8 + 3 * R + R + MAX_STATE_DEPTH * R + R + 8 + MAX_STATE_DEPTH * R;
pub const HEAD_FILE: usize = HEAD_PREAMBLE + CHUNKS_PER_PERIOD as usize * TOP_RECORD;

pub fn head_path(beacon_root: &B256) -> String {
    format!("beacon/heads/{beacon_root}")
}
pub fn period_path(period: u64) -> String {
    format!("beacon/periods/{period}")
}
pub fn summaries_path(len: u64) -> String {
    format!("beacon/summaries/{len}")
}
pub fn chunk_path(chunk: u64) -> String {
    format!("beacon/chunks/{chunk}")
}

pub fn sha(a: &B256, b: &B256) -> B256 {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    B256::from_slice(&h.finalize())
}

pub fn u64_leaf(v: u64) -> B256 {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&v.to_le_bytes());
    B256::from(b)
}

/// `zero[i]`: the root of an all-zero subtree of depth `i`.
pub fn zero_hashes() -> [B256; 41] {
    let mut z = [B256::ZERO; 41];
    for i in 1..41 {
        z[i] = sha(&z[i - 1], &z[i - 1]);
    }
    z
}

/// The root from `leaf` at `index` with `branch` bottom-up.
pub fn climb(leaf: B256, index: u64, branch: &[B256]) -> B256 {
    let mut node = leaf;
    for (i, s) in branch.iter().enumerate() {
        node = if (index >> i) & 1 == 1 {
            sha(s, &node)
        } else {
            sha(&node, s)
        };
    }
    node
}

/// A complete tree over `leaves` (a power of two): levels, leaves first.
pub fn levels(leaves: Vec<B256>) -> Vec<Vec<B256>> {
    assert!(leaves.len().is_power_of_two(), "a power of two of leaves");
    let mut out = vec![leaves];
    while out.last().expect("one level").len() > 1 {
        let l = out.last().expect("one level");
        let up = l.chunks(2).map(|p| sha(&p[0], &p[1])).collect();
        out.push(up);
    }
    out
}

/// The siblings of leaf `index` bottom-up, in a tree from [`levels`].
pub fn branch_of(levels: &[Vec<B256>], index: usize) -> Vec<B256> {
    let mut out = Vec::new();
    let mut i = index;
    for l in &levels[..levels.len() - 1] {
        out.push(l[i ^ 1]);
        i >>= 1;
    }
    out
}

fn take(b: &[u8], i: usize) -> B256 {
    B256::from_slice(&b[i * R..(i + 1) * R])
}

/// `BeaconBlockHeader`'s fields; its root is the block's root.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BeaconHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: B256,
    pub state_root: B256,
    pub body_root: B256,
}

impl BeaconHeader {
    pub fn root(&self) -> B256 {
        let z = B256::ZERO;
        let l = levels(vec![
            u64_leaf(self.slot),
            u64_leaf(self.proposer_index),
            self.parent_root,
            self.state_root,
            self.body_root,
            z,
            z,
            z,
        ]);
        l[3][0]
    }

    /// The 3 siblings of `body_root`, bottom-up.
    pub fn body_branch(&self) -> [B256; 3] {
        let z = zero_hashes();
        let left = sha(
            &sha(&u64_leaf(self.slot), &u64_leaf(self.proposer_index)),
            &sha(&self.parent_root, &self.state_root),
        );
        [z[0], z[1], left]
    }
}

/// One block's proof of its execution `block_hash`, from the block root
/// down: what a chunk record carries after the chunk siblings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyProof {
    pub slot: u64,
    pub block_root: B256,
    pub block_hash: B256,
    /// `payload_depth(slot)` siblings, bottom-up.
    pub payload: Vec<B256>,
    pub body: [B256; BODY_DEPTH],
    pub header: [B256; HEADER_DEPTH],
}

/// The block root that `block_hash` and a body proof (the record's tail,
/// from offset `CHUNK_DEPTH * 32`) hash to, for a block in `slot`'s fork.
pub fn block_root_from(slot: u64, block_hash: &B256, tail: &[u8]) -> B256 {
    let pd = payload_depth(slot);
    let payload: Vec<B256> = (0..pd).map(|i| take(tail, i)).collect();
    let body: Vec<B256> = (0..BODY_DEPTH)
        .map(|i| take(tail, PAYLOAD_SLOTS + i))
        .collect();
    let header: Vec<B256> = (0..HEADER_DEPTH)
        .map(|i| take(tail, PAYLOAD_SLOTS + BODY_DEPTH + i))
        .collect();
    let payload_root = climb(*block_hash, PAYLOAD_BLOCK_HASH, &payload);
    let body_root = climb(payload_root, BODY_EXECUTION_PAYLOAD, &body);
    climb(body_root, HEADER_BODY_ROOT, &header)
}

impl BodyProof {
    pub fn root(&self) -> B256 {
        block_root_from(self.slot, &self.block_hash, &self.tail())
    }

    fn tail(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHUNK_RECORD - CHUNK_DEPTH * R);
        for i in 0..PAYLOAD_SLOTS {
            out.extend_from_slice(self.payload.get(i).unwrap_or(&B256::ZERO).as_slice());
        }
        for b in self.body.iter().chain(&self.header) {
            out.extend_from_slice(b.as_slice());
        }
        out
    }
}

/// Chunk `chunk`'s file from its 64 block roots (slot order; an empty slot
/// repeats the root before it) and body proofs by root.
///
/// A slot's record carries a body proof only when its root is the block
/// of that slot. A root repeated from the slot before is an empty slot
/// and has no block of its own: its record is the chunk siblings and a
/// zero tail, and nothing is looked up for it. The chunk's first root may
/// be a predecessor, the last block before the chunk (from an earlier
/// chunk, or before Capella at Capella's first chunk): its proof must
/// hash to the root and name an earlier slot, and its records get a zero
/// tail too. Any other root is the block at its slot, and its proof must
/// say so. A zero tail proves nothing, so no block is ever claimed for an
/// empty slot.
pub fn chunk_file(
    chunk: u64,
    roots: &[B256],
    bodies: &HashMap<B256, BodyProof>,
) -> Result<Vec<u8>, String> {
    if roots.len() != CHUNK_SLOTS as usize {
        return Err(format!("chunk {chunk}: {} roots", roots.len()));
    }
    let tree = levels(roots.to_vec());
    let zero_tail = vec![0u8; CHUNK_RECORD - CHUNK_DEPTH * R];
    let mut out = Vec::with_capacity(CHUNK_SLOTS as usize * CHUNK_RECORD);
    for (k, root) in roots.iter().enumerate() {
        let slot = chunk * CHUNK_SLOTS + k as u64;
        for s in branch_of(&tree, k) {
            out.extend_from_slice(s.as_slice());
        }
        if k > 0 && roots[k - 1] == *root {
            out.extend_from_slice(&zero_tail);
            continue;
        }
        let b = bodies
            .get(root)
            .ok_or_else(|| format!("chunk {chunk}: no body proof for {root} (slot {slot})"))?;
        if b.root() != *root {
            return Err(format!(
                "chunk {chunk}: body proof for {root} does not hash to it"
            ));
        }
        if b.slot == slot {
            out.extend_from_slice(&b.tail());
        } else if k == 0 && b.slot < slot {
            out.extend_from_slice(&zero_tail);
        } else {
            return Err(format!(
                "chunk {chunk}: {root} first appears at slot {slot} but is the block of slot {}",
                b.slot
            ));
        }
    }
    Ok(out)
}

/// The roots of a chunk whose body proofs [`chunk_file`] needs: each
/// root's first appearance (a repeat is an empty slot).
pub fn chunk_blocks(roots: &[B256]) -> Vec<B256> {
    roots
        .iter()
        .enumerate()
        .filter(|(k, r)| *k == 0 || roots[k - 1] != **r)
        .map(|(_, r)| *r)
        .collect()
}

/// The root of a chunk's 64 block roots.
pub fn chunk_root(roots: &[B256]) -> B256 {
    levels(roots.to_vec()).last().expect("root")[0]
}

/// 128 records of 7 siblings: each chunk root up to the vector's root.
pub fn top_records(chunk_roots: &[B256]) -> Vec<u8> {
    assert_eq!(chunk_roots.len(), CHUNKS_PER_PERIOD as usize);
    let tree = levels(chunk_roots.to_vec());
    let mut out = Vec::with_capacity(CHUNKS_PER_PERIOD as usize * TOP_RECORD);
    for c in 0..chunk_roots.len() {
        for s in branch_of(&tree, c) {
            out.extend_from_slice(s.as_slice());
        }
    }
    out
}

/// The vector root over 128 chunk roots.
pub fn vector_root(chunk_roots: &[B256]) -> B256 {
    levels(chunk_roots.to_vec()).last().expect("root")[0]
}

/// The depth of the summaries records for a list of `len`.
pub fn summaries_depth(len: u64) -> usize {
    (64 - len.saturating_sub(1).leading_zeros()) as usize
}

pub fn summary_record_len(len: u64) -> usize {
    R * (1 + summaries_depth(len))
}

/// `historical_summaries` as records, and the list's root (its
/// `hash_tree_root`, length mixed in).
pub fn summaries_file(items: &[(B256, B256)]) -> (Vec<u8>, B256) {
    let len = items.len() as u64;
    let d = summaries_depth(len);
    let mut leaves: Vec<B256> = items.iter().map(|(b, s)| sha(b, s)).collect();
    leaves.resize(1 << d, B256::ZERO);
    let tree = levels(leaves);
    let mut out = Vec::with_capacity(items.len() * summary_record_len(len));
    for (i, (_, s)) in items.iter().enumerate() {
        out.extend_from_slice(s.as_slice());
        for b in branch_of(&tree, i) {
            out.extend_from_slice(b.as_slice());
        }
    }
    let z = zero_hashes();
    let mut data = tree.last().expect("root")[0];
    for zi in z.iter().take(SUMMARIES_LIMIT_DEPTH).skip(d) {
        data = sha(&data, zi);
    }
    (out, sha(&data, &u64_leaf(len)))
}

/// What a head file proves about its state, before the ring records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeadPreamble {
    pub header: BeaconHeader,
    pub block_roots_root: B256,
    pub block_roots_branch: Vec<B256>,
    pub summaries_data_root: B256,
    pub summaries_len: u64,
    pub summaries_branch: Vec<B256>,
}

impl HeadPreamble {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEAD_PREAMBLE);
        out.extend_from_slice(HEAD_MAGIC);
        out.extend_from_slice(&self.header.slot.to_le_bytes());
        out.extend_from_slice(&self.header.proposer_index.to_le_bytes());
        for r in [
            self.header.parent_root,
            self.header.state_root,
            self.header.body_root,
            self.block_roots_root,
        ] {
            out.extend_from_slice(r.as_slice());
        }
        let pad = |out: &mut Vec<u8>, b: &[B256]| {
            for i in 0..MAX_STATE_DEPTH {
                out.extend_from_slice(b.get(i).unwrap_or(&B256::ZERO).as_slice());
            }
        };
        pad(&mut out, &self.block_roots_branch);
        out.extend_from_slice(self.summaries_data_root.as_slice());
        out.extend_from_slice(&self.summaries_len.to_le_bytes());
        pad(&mut out, &self.summaries_branch);
        debug_assert_eq!(out.len(), HEAD_PREAMBLE);
        out
    }

    pub fn decode(b: &[u8]) -> Result<HeadPreamble, String> {
        if b.len() != HEAD_PREAMBLE || &b[..8] != HEAD_MAGIC {
            return Err("not a beacon head preamble".into());
        }
        let u = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
        let r = |o: usize| B256::from_slice(&b[o..o + R]);
        let slot = u(8);
        let depth = state_depth(slot);
        let branch = |o: usize| (0..depth).map(|i| r(o + i * R)).collect::<Vec<_>>();
        Ok(HeadPreamble {
            header: BeaconHeader {
                slot,
                proposer_index: u(16),
                parent_root: r(24),
                state_root: r(56),
                body_root: r(88),
            },
            block_roots_root: r(120),
            block_roots_branch: branch(152),
            summaries_data_root: r(344),
            summaries_len: u(376),
            summaries_branch: branch(384),
        })
    }

    /// The list root `historical_summaries` hashes to.
    pub fn summaries_root(&self) -> B256 {
        sha(&self.summaries_data_root, &u64_leaf(self.summaries_len))
    }

    /// Check the preamble against the verified head: its header hashes to
    /// `beacon_root` at `slot`, and both fields climb to its state root.
    pub fn verify(&self, slot: u64, beacon_root: &B256) -> Result<(), String> {
        let h = &self.header;
        if h.slot != slot || h.root() != *beacon_root {
            return Err(format!(
                "head file's header is slot {} root {}, the head is slot {slot} root {beacon_root}",
                h.slot,
                h.root()
            ));
        }
        if climb(
            self.block_roots_root,
            STATE_BLOCK_ROOTS,
            &self.block_roots_branch,
        ) != h.state_root
        {
            return Err("block_roots does not climb to the head's state root".into());
        }
        if climb(
            self.summaries_root(),
            STATE_HISTORICAL_SUMMARIES,
            &self.summaries_branch,
        ) != h.state_root
        {
            return Err("historical_summaries does not climb to the head's state root".into());
        }
        Ok(())
    }
}

/// Which vector holds a slot's block root, as seen from a head at
/// `head_slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    /// The head state's `block_roots`, record `chunk % 128` of the head
    /// file: the slot is in the head's own period.
    Ring { chunk: u64 },
    /// `historical_summaries[index]`'s vector, record `chunk % 128` of
    /// `beacon/periods/<period>`.
    Closed { chunk: u64, period: u64, index: u64 },
}

impl Route {
    pub fn chunk(&self) -> u64 {
        match self {
            Route::Ring { chunk } | Route::Closed { chunk, .. } => *chunk,
        }
    }
}

/// Route a slot from a head, or why the accumulator cannot reach it.
pub fn route(head_slot: u64, slot: u64) -> Result<Route, String> {
    if slot < CAPELLA_SLOT {
        return Err(format!(
            "slot {slot} is before Capella: no historical_summaries (needs historical_roots or era1)"
        ));
    }
    if slot >= head_slot {
        return Err(format!(
            "slot {slot} is not below the head's slot {head_slot}"
        ));
    }
    let chunk = slot / CHUNK_SLOTS;
    let period = slot / SLOTS_PER_HISTORICAL_ROOT;
    let head_period = head_slot / SLOTS_PER_HISTORICAL_ROOT;
    if period == head_period {
        // The ring holds the slot, and its chunk is whole only once every
        // slot of it is below the head.
        if (chunk + 1) * CHUNK_SLOTS > head_slot {
            return Err(format!(
                "slot {slot}'s chunk is not complete at head slot {head_slot}"
            ));
        }
        Ok(Route::Ring { chunk })
    } else {
        Ok(Route::Closed {
            chunk,
            period,
            index: period - CAPELLA_PERIOD,
        })
    }
}

/// Where a route's records above the chunk live, (path, offset, length):
/// the top record, then for a closed period the summaries record of a
/// list of `summaries_len`.
pub fn route_ranges(summaries_len: u64, head_root: &B256, r: &Route) -> Vec<(String, u64, usize)> {
    let pos = (r.chunk() % CHUNKS_PER_PERIOD) as usize;
    let mut out = Vec::with_capacity(2);
    match r {
        Route::Ring { .. } => out.push((
            head_path(head_root),
            (HEAD_PREAMBLE + pos * TOP_RECORD) as u64,
            TOP_RECORD,
        )),
        Route::Closed { period, index, .. } => {
            out.push((period_path(*period), (pos * TOP_RECORD) as u64, TOP_RECORD));
            let rl = summary_record_len(summaries_len);
            out.push((summaries_path(summaries_len), *index * rl as u64, rl));
        }
    }
    out
}

/// The chunk record's range for a slot.
pub fn chunk_record_range(slot: u64) -> (String, u64, usize) {
    let chunk = slot / CHUNK_SLOTS;
    (
        chunk_path(chunk),
        (slot % CHUNK_SLOTS) * CHUNK_RECORD as u64,
        CHUNK_RECORD,
    )
}

/// Verify that `block_hash` is the execution payload of the canonical
/// beacon block at `slot`, from a verified preamble and the route's
/// records: the chunk record, then the top record (ring or period), then
/// for a closed period the summaries record.
pub fn verify_block_hash(
    pre: &HeadPreamble,
    slot: u64,
    block_hash: &B256,
    chunk_rec: &[u8],
    top_rec: &[u8],
    summary_rec: Option<&[u8]>,
) -> Result<(), String> {
    let r = route(pre.header.slot, slot)?;
    if chunk_rec.len() != CHUNK_RECORD || top_rec.len() != TOP_RECORD {
        return Err("record of the wrong size".into());
    }
    let block_root = block_root_from(slot, block_hash, &chunk_rec[CHUNK_DEPTH * R..]);
    let chunk_sibs: Vec<B256> = (0..CHUNK_DEPTH).map(|i| take(chunk_rec, i)).collect();
    let chunk_root = climb(block_root, slot % CHUNK_SLOTS, &chunk_sibs);
    let top: Vec<B256> = (0..TOP_DEPTH).map(|i| take(top_rec, i)).collect();
    let vector = climb(chunk_root, r.chunk() % CHUNKS_PER_PERIOD, &top);
    match r {
        Route::Ring { .. } => {
            if vector != pre.block_roots_root {
                return Err(format!(
                    "slot {slot}: block {block_hash} does not climb to the head's block_roots"
                ));
            }
        }
        Route::Closed { index, period, .. } => {
            if index >= pre.summaries_len {
                return Err(format!(
                    "period {period} is summary {index}, the head's list has {}",
                    pre.summaries_len
                ));
            }
            let d = summaries_depth(pre.summaries_len);
            let rec = summary_rec.ok_or("no summaries record")?;
            if rec.len() != R * (1 + d) {
                return Err("summaries record of the wrong size".into());
            }
            let item = sha(&vector, &take(rec, 0));
            let sibs: Vec<B256> = (0..d).map(|i| take(rec, 1 + i)).collect();
            let mut data = climb(item, index, &sibs);
            let z = zero_hashes();
            for zi in z.iter().take(SUMMARIES_LIMIT_DEPTH).skip(d) {
                data = sha(&data, zi);
            }
            if data != pre.summaries_data_root {
                return Err(format!(
                    "slot {slot}: block {block_hash} does not climb to historical_summaries[{index}]"
                ));
            }
        }
    }
    Ok(())
}

/// A synthetic beacon chain over given execution blocks, for tests and
/// fault tables: made-up body proofs, states and summaries, all
/// consistent, so every file verifies to the head it builds.
#[doc(hidden)]
pub mod synthetic {
    use super::*;
    use alloy_primitives::keccak256;
    use std::{collections::BTreeMap, path::Path};

    pub struct World {
        pub head: BeaconHeader,
        pub head_root: B256,
        /// Every file, by bucket path.
        pub files: BTreeMap<String, Vec<u8>>,
        /// Block root by slot (an empty slot repeats the last).
        pub roots: BTreeMap<u64, B256>,
    }

    fn fake(tag: &str, i: u64) -> B256 {
        keccak256(format!("synthetic beacon {tag} {i}"))
    }

    /// A made-up block at `slot` whose proof hashes consistently.
    pub fn body(slot: u64, block_hash: B256) -> BodyProof {
        let mut b = BodyProof {
            slot,
            block_root: B256::ZERO,
            block_hash,
            payload: (0..payload_depth(slot) as u64)
                .map(|i| fake("payload", slot * 8 + i))
                .collect(),
            body: std::array::from_fn(|i| fake("body", slot * 8 + i as u64)),
            header: BeaconHeader {
                slot,
                proposer_index: slot % 1000,
                parent_root: fake("parent", slot),
                state_root: fake("state", slot),
                body_root: B256::ZERO,
            }
            .body_branch(),
        };
        b.block_root = b.root();
        b
    }

    /// Execution blocks `(slot, block_hash)`, rising; slots between them
    /// are empty. The head is at `head_slot`, past every block; the vector
    /// of every period from the first block's to the head's is built
    /// (slots before the first block repeat a made-up root), and
    /// `historical_summaries` has its real length at the head, made-up
    /// items where no block was given.
    pub fn world(blocks: &[(u64, B256)], head_slot: u64) -> World {
        let first = blocks.first().expect("a block").0;
        let first_period = first / SLOTS_PER_HISTORICAL_ROOT;
        let head_period = head_slot / SLOTS_PER_HISTORICAL_ROOT;
        let by_slot: BTreeMap<u64, B256> = blocks.iter().copied().collect();
        let mut bodies: HashMap<B256, BodyProof> = HashMap::new();
        let mut roots = BTreeMap::new();
        let start = first_period * SLOTS_PER_HISTORICAL_ROOT;
        let pre = body(start.saturating_sub(1), fake("before", start));
        bodies.insert(pre.block_root, pre.clone());
        let mut last = pre.block_root;
        for s in start..head_slot {
            if let Some(h) = by_slot.get(&s) {
                let b = body(s, *h);
                last = b.block_root;
                bodies.insert(last, b);
            }
            roots.insert(s, last);
        }
        let mut files = BTreeMap::new();
        let len = head_period - CAPELLA_PERIOD;
        let mut items: Vec<(B256, B256)> =
            (0..len).map(|i| (fake("bsr", i), fake("ssr", i))).collect();
        let mut ring_chunks = vec![B256::ZERO; CHUNKS_PER_PERIOD as usize];
        for p in first_period..=head_period {
            let mut chunk_roots = Vec::new();
            for c in 0..CHUNKS_PER_PERIOD {
                let chunk = p * CHUNKS_PER_PERIOD + c;
                let s0 = chunk * CHUNK_SLOTS;
                if s0 + CHUNK_SLOTS > head_slot {
                    // Not whole: the ring holds last period's roots past
                    // the head, the slots below it this period's.
                    let rs: Vec<B256> = (s0..s0 + CHUNK_SLOTS)
                        .map(|s| match roots.get(&s) {
                            Some(r) => *r,
                            None => *roots
                                .get(&(s - SLOTS_PER_HISTORICAL_ROOT))
                                .unwrap_or(&fake("old", s)),
                        })
                        .collect();
                    chunk_roots.push(chunk_root(&rs));
                    continue;
                }
                let rs: Vec<B256> = (s0..s0 + CHUNK_SLOTS).map(|s| roots[&s]).collect();
                files.insert(
                    chunk_path(chunk),
                    chunk_file(chunk, &rs, &bodies).expect("consistent"),
                );
                chunk_roots.push(chunk_root(&rs));
            }
            if p < head_period {
                files.insert(period_path(p), top_records(&chunk_roots));
                items[(p - CAPELLA_PERIOD) as usize].0 = vector_root(&chunk_roots);
            } else {
                ring_chunks = chunk_roots;
            }
        }
        let (sum_file, sum_root) = summaries_file(&items);
        files.insert(summaries_path(len), sum_file);
        let depth = state_depth(head_slot);
        let block_roots_root = vector_root(&ring_chunks);
        // A made-up state with both fields where they belong.
        let mut leaves: Vec<B256> = (0..1u64 << depth).map(|i| fake("field", i)).collect();
        leaves[STATE_BLOCK_ROOTS as usize] = block_roots_root;
        leaves[STATE_HISTORICAL_SUMMARIES as usize] = sum_root;
        let state = levels(leaves);
        let header = BeaconHeader {
            slot: head_slot,
            proposer_index: 7,
            parent_root: fake("head parent", head_slot),
            state_root: state.last().expect("root")[0],
            body_root: fake("head body", head_slot),
        };
        let z = zero_hashes();
        let mut data = levels({
            let d = summaries_depth(len);
            let mut l: Vec<B256> = items.iter().map(|(b, s)| sha(b, s)).collect();
            l.resize(1 << d, B256::ZERO);
            l
        })
        .last()
        .expect("root")[0];
        for zi in z
            .iter()
            .take(SUMMARIES_LIMIT_DEPTH)
            .skip(summaries_depth(len))
        {
            data = sha(&data, zi);
        }
        let pre = HeadPreamble {
            header,
            block_roots_root,
            block_roots_branch: branch_of(&state, STATE_BLOCK_ROOTS as usize),
            summaries_data_root: data,
            summaries_len: len,
            summaries_branch: branch_of(&state, STATE_HISTORICAL_SUMMARIES as usize),
        };
        let mut head_file = pre.encode();
        head_file.extend_from_slice(&top_records(&ring_chunks));
        let head_root = header.root();
        files.insert(head_path(&head_root), head_file);
        World {
            head: header,
            head_root,
            files,
            roots,
        }
    }

    impl World {
        pub fn write(&self, dir: &Path) -> std::io::Result<()> {
            for (rel, b) in &self.files {
                let p = dir.join(rel);
                std::fs::create_dir_all(p.parent().expect("parent"))?;
                std::fs::write(p, b)?;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_sizes() {
        assert_eq!(CHUNK_RECORD, 576);
        assert_eq!(TOP_RECORD, 224);
        assert_eq!(HEAD_PREAMBLE, 576);
        assert_eq!(CAPELLA_PERIOD, 758);
        assert_eq!(summaries_depth(1), 0);
        assert_eq!(summaries_depth(2), 1);
        assert_eq!(summaries_depth(1153), 11);
        assert_eq!(summaries_depth(1024), 10);
    }

    #[test]
    fn summaries_root_matches_a_plain_merkleization() {
        // hash_tree_root(List[HistoricalSummary, 2^24]) for 3 items.
        let items: Vec<(B256, B256)> = (0..3u8)
            .map(|i| (B256::repeat_byte(i), B256::repeat_byte(i + 100)))
            .collect();
        let (_, root) = summaries_file(&items);
        let z = zero_hashes();
        let mut leaves: Vec<B256> = items.iter().map(|(a, b)| sha(a, b)).collect();
        leaves.push(B256::ZERO);
        let mut data = levels(leaves).last().unwrap()[0];
        for zi in z.iter().take(24).skip(2) {
            data = sha(&data, zi);
        }
        assert_eq!(root, sha(&data, &u64_leaf(3)));
    }

    #[test]
    fn a_synthetic_world_verifies_both_routes() {
        let head: u64 = 1912 * 8192 + 700;
        let blocks: Vec<(u64, B256)> = (1911 * 8192..head - 1)
            .filter(|s| s % 7 != 3)
            .map(|s| (s, alloy_primitives::keccak256(s.to_be_bytes())))
            .collect();
        let w = synthetic::world(&blocks, head);
        let hf = &w.files[&head_path(&w.head_root)];
        let pre = HeadPreamble::decode(&hf[..HEAD_PREAMBLE]).unwrap();
        pre.verify(head, &w.head_root).unwrap();
        for &(s, h) in blocks.iter().step_by(97) {
            let Ok(r) = route(head, s) else { continue };
            let (cp, co, cl) = chunk_record_range(s);
            let chunk = &w.files[&cp][co as usize..co as usize + cl];
            let rs = route_ranges(pre.summaries_len, &w.head_root, &r);
            let get = |i: usize| {
                let (p, o, l) = &rs[i];
                w.files[p][*o as usize..*o as usize + l].to_vec()
            };
            let top = get(0);
            let sum = (rs.len() > 1).then(|| get(1));
            verify_block_hash(&pre, s, &h, chunk, &top, sum.as_deref()).unwrap();
            let wrong = alloy_primitives::keccak256(h);
            assert!(verify_block_hash(&pre, s, &wrong, chunk, &top, sum.as_deref()).is_err());
        }
    }

    /// Capella's first chunk on mainnet: slots 6,209,536 and 537 were
    /// missed, so the chunk opens on the root of the last Bellatrix block
    /// (6,209,535). Its records carry no proof, only that block's root is
    /// looked up, and no block is ever proven at those slots; pre-Capella
    /// slots stay unroutable.
    #[test]
    fn a_chunk_opening_on_a_predecessor_root() {
        use alloy_primitives::keccak256;
        let chunk = CAPELLA_SLOT / CHUNK_SLOTS;
        let s0 = chunk * CHUNK_SLOTS;
        let pred = synthetic::body(s0 - 1, keccak256("bellatrix"));
        let mut bodies = HashMap::new();
        bodies.insert(pred.block_root, pred.clone());
        let mut roots = vec![pred.block_root; 2];
        let mut last = pred.block_root;
        for s in s0 + 2..s0 + CHUNK_SLOTS {
            // Slot s0 + 40 missed as well, inside the chunk.
            if s != s0 + 40 {
                let b = synthetic::body(s, keccak256(s.to_le_bytes()));
                last = b.block_root;
                bodies.insert(last, b);
            }
            roots.push(last);
        }
        assert_eq!(chunk_blocks(&roots).len(), 62);
        assert_eq!(chunk_blocks(&roots)[0], pred.block_root);
        let file = chunk_file(chunk, &roots, &bodies).unwrap();
        let tail = |k: usize| &file[k * CHUNK_RECORD + CHUNK_DEPTH * R..(k + 1) * CHUNK_RECORD];
        for k in [0usize, 1, 40] {
            assert!(tail(k).iter().all(|b| *b == 0), "slot {k} has a tail");
        }
        for k in [2usize, 39, 41, 63] {
            assert!(tail(k).iter().any(|b| *b != 0));
        }
        // Every root climbs to the chunk root from its record, and only a
        // block's own slot proves its hash.
        let root = chunk_root(&roots);
        for k in 0..64usize {
            let rec = &file[k * CHUNK_RECORD..(k + 1) * CHUNK_RECORD];
            let sibs: Vec<B256> = (0..CHUNK_DEPTH).map(|i| take(rec, i)).collect();
            assert_eq!(climb(roots[k], k as u64, &sibs), root);
            let s = s0 + k as u64;
            let b = &bodies[&roots[k]];
            let proves = block_root_from(s, &b.block_hash, &rec[CHUNK_DEPTH * R..]) == roots[k];
            assert_eq!(proves, b.slot == s, "slot {s}");
        }
        assert!(route(s0 + 100, s0 - 1).is_err());

        // A new root inside the chunk must be its slot's block.
        let mut late = bodies.clone();
        let moved = synthetic::body(s0 + 1, keccak256("moved"));
        let mut bad = roots.clone();
        bad[2] = moved.block_root;
        late.insert(moved.block_root, moved);
        assert!(chunk_file(chunk, &bad, &late).is_err());
        // The first root may not name a later block, nor go unproven.
        let later = synthetic::body(s0 + 5, keccak256("later"));
        let mut bad = roots.clone();
        bad[0] = later.block_root;
        late.insert(later.block_root, later);
        assert!(chunk_file(chunk, &bad, &late).is_err());
        let mut gone = bodies.clone();
        gone.remove(&pred.block_root);
        assert!(chunk_file(chunk, &roots, &gone).is_err());
    }
}
