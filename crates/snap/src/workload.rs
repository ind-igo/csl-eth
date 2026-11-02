//! The milestone 1 workload (PoC spec, "Workload" and the exit table):
//! a fixed, deterministic set of reads drawn from a slice, classified by
//! the shape of the trie's answer, run through the path-keyed client and
//! the content-addressed baseline, scored, and written as one JSON report.
//!
//! The shapes are predicted from the slice itself, not read back from the
//! client: the slice holds every leaf of the covered subtrie and of every
//! storage trie in it (all proven to `state_root` by peers' range proofs at
//! fetch time), and a Merkle-Patricia trie's node positions are a function
//! of its sorted keys alone. [`Sorted::shape`] computes, for any key, the
//! branch depths on its path, where the walk ends and how (a leaf, an empty
//! branch slot, an extension or a leaf whose path differs), and how many
//! nodes a walk decodes. That lets the plan draw keys *by* shape (a leaf
//! mismatch rather than an empty slot, a path through an extension, a slot
//! of an account with no storage) and lets the run check the client's
//! answer against an independent model: the `AbsentBy` it reports and the
//! `nodes` it decoded must be the predicted ones. A disagreement
//! (`shape_mismatch`) fails the run: the answer may still be right, but one
//! of the two is wrong about the trie, and an account wrongly proven absent
//! during an absent-slot read would show only here (both say "absent").
//!
//! The plan draws each kind to the count asked for: forced picks (the
//! largest tries, keys through extensions) come first and the strided
//! rest is drawn from the candidates not yet chosen, so a forced pick
//! never costs a draw. The plan then checks itself ([`plan`]'s
//! `complete` and `incomplete`): every kind drawn to its request and
//! every shape the spec names present (see `required_shapes`). A slice
//! that cannot supply one is reported, never padded.
//!
//! Pass or fail follows the spec's rows: a false absence or a wrong value
//! fails outright, as does any other unexpected outcome or a walk the
//! shape model did not predict (`safe` in the report); on a remote host,
//! the warmed account read (present and absent) must stay within 50 KB
//! and two dependent rounds at the 95th percentile; and the plan must be
//! complete, unless `--allow-short` marks the run as a reduced
//! measurement (the report then says `complete: false` and passes on the
//! other rules).
//!
//! The scorer ([`score`]) and the read itself ([`read_draw`]) are shared
//! with the fault table, which reads a small plan of the same shapes
//! through a lying host.

use crate::Slice;
use alloy_primitives::{keccak256, B256, U256};
use clap::{Args as ClapArgs, ValueEnum};
use csl_eth_client::{
    open_at_head, Cost, DirDriver, Driver, Hint, HttpDriver, Read, Reason, Snapshot,
};
use csl_eth_store::CODE_BLOB_THRESHOLD;
use csl_eth_trie::{path_of, AbsentBy, Account, Nibbles, EMPTY_ROOT_HASH, KECCAK_EMPTY};
use rand::{seq::SliceRandom, Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde_json::{json, Value};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashSet},
    path::PathBuf,
    sync::atomic::Ordering as Atomic,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    /// The path-keyed client (profile §2).
    Path,
    /// The content-addressed baseline (profile §9).
    Baseline,
    Both,
}

impl Mode {
    /// The modes to run, as "is the baseline".
    pub(crate) fn each(self) -> Vec<bool> {
        match self {
            Mode::Path => vec![false],
            Mode::Baseline => vec![true],
            Mode::Both => vec![false, true],
        }
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Mode::Path => "path",
            Mode::Baseline => "baseline",
            Mode::Both => "both",
        }
    }
}

/// A mode's label in reports.
pub(crate) fn mode_label(baseline: bool) -> &'static str {
    if baseline {
        "baseline"
    } else {
        "path"
    }
}

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// The slice the bucket was built from (keys and expected values).
    #[arg(long)]
    pub slice: PathBuf,
    /// A bucket directory on disk.
    #[arg(long, conflicts_with = "url")]
    pub bucket: Option<PathBuf>,
    /// A bucket behind HTTP (the directory's base URL).
    #[arg(long)]
    pub url: Option<String>,
    /// Proxy for the URL, e.g. socks5h://localhost:1055.
    #[arg(long)]
    pub proxy: Option<String>,
    /// Verify the head from the bucket's `head/` files starting at this
    /// checkpoint root and read at the finalized block's `state_root`
    /// instead of the slice's pinned header.
    #[arg(long)]
    pub checkpoint: Option<B256>,
    /// Where to write the JSON report.
    #[arg(long)]
    pub out: PathBuf,
    #[arg(long, value_enum, default_value_t = Mode::Both)]
    pub mode: Mode,
    /// Present accounts (the largest contracts and a share of keys through
    /// extensions forced in, the rest strided).
    #[arg(long, default_value_t = 10_000)]
    pub accounts: usize,
    /// Absent accounts inside the prefix: random tails and keys crafted to
    /// miss at a leaf, an empty slot and an extension.
    #[arg(long, default_value_t = 10_000)]
    pub absent: usize,
    /// Present storage slots, with extra draws from the largest tries.
    #[arg(long, default_value_t = 10_000)]
    pub slots: usize,
    /// Absent slots: in tries, of accounts with no storage, of absent
    /// accounts.
    #[arg(long, default_value_t = 10_000)]
    pub absent_slots: usize,
    /// Keys outside the prefix, which must end Insufficient.
    #[arg(long, default_value_t = 1_000)]
    pub outside: usize,
    /// A reduced measurement: pass on safety alone when the slice cannot
    /// supply a requested count or shape (the report still says
    /// `complete: false` and lists what is missing). Without it an
    /// incomplete plan fails the run.
    #[arg(long)]
    pub allow_short: bool,
    #[arg(long, default_value_t = 1)]
    pub seed: u64,
    /// Pages each side of the predicted page in the speculative round.
    #[arg(long, default_value_t = 1)]
    pub prefetch: u64,
    /// Account-trie depths kept across reads (0: off).
    #[arg(long, default_value_t = 4)]
    pub top_levels: usize,
    /// Speculated account depth (profile: 9) and storage depth (7).
    #[arg(long)]
    pub d_account: Option<usize>,
    #[arg(long)]
    pub d_storage: Option<usize>,
    /// JSON-RPC endpoint for `eth_getProof` at the slice's block.
    #[arg(long)]
    pub oracle: Option<String>,
    /// Addresses to score against the oracle (0: off).
    #[arg(long, default_value_t = 0)]
    pub oracle_samples: usize,
    /// Recent blocks scanned for addresses inside the prefix.
    #[arg(long, default_value_t = 300)]
    pub oracle_blocks: u64,
}

/// How many reads of each kind the plan draws.
#[derive(Clone, Copy, Debug)]
pub struct Sizes {
    pub accounts: usize,
    pub absent: usize,
    pub slots: usize,
    pub absent_slots: usize,
    pub outside: usize,
    /// The client's speculated depths, for the `beyond_d` shapes.
    pub d_account: usize,
    pub d_storage: usize,
}

/// A storage leaf at this depth or deeper counts as "deep": the largest
/// contracts a 1/4096 slice holds (up to 15,000 slots) put their leaves at
/// depths 4 to 6, while a trie of a few hundred slots ends at 2 or 3.
pub const DEEP_STORAGE: usize = 4;

/// Accounts with the most slots forced into the plan.
const LARGEST: usize = 20;

// Series names. A read lands in every series its shape qualifies for, so
// the subsets (extension, deep, largest) are measured beside the whole.
const ACCOUNT_PRESENT: &str = "account_present";
const ACCOUNT_PRESENT_EXTENSION: &str = "account_present_extension";
const ACCOUNT_PRESENT_BEYOND_D: &str = "account_present_beyond_d";
const ACCOUNT_PRESENT_LARGEST: &str = "account_present_largest";
const ACCOUNT_ABSENT: &str = "account_absent";
const STORAGE_PRESENT: &str = "storage_present";
const STORAGE_PRESENT_EXTENSION: &str = "storage_present_extension";
const STORAGE_PRESENT_BEYOND_D: &str = "storage_present_beyond_d";
const STORAGE_PRESENT_LARGEST: &str = "storage_present_largest";
const STORAGE_PRESENT_DEEP: &str = "storage_present_deep";
const STORAGE_ABSENT: &str = "storage_absent";
const STORAGE_ABSENT_LARGEST: &str = "storage_absent_largest";
const STORAGE_EMPTY_TRIE: &str = "storage_empty_trie";
const STORAGE_ABSENT_ACCOUNT: &str = "storage_absent_account";
const CODE: &str = "code";
const CODE_INLINE: &str = "code_inline";
const CODE_BLOB: &str = "code_blob";
const OUTSIDE: &str = "outside";

fn absent_series(prefix: &str, by: AbsentBy) -> String {
    let by = match by {
        AbsentBy::EmptyTrie => "empty_trie",
        AbsentBy::EmptySlot => "empty_slot",
        AbsentBy::ExtensionMismatch => "extension_mismatch",
        AbsentBy::LeafMismatch => "leaf_mismatch",
    };
    format!("{prefix}_absent_{by}")
}

// ----------------------------------------------------------------------
// The trie's shape from its sorted keys.

fn nibble(k: &B256, i: usize) -> u8 {
    let b = k.0[i / 2];
    if i.is_multiple_of(2) {
        b >> 4
    } else {
        b & 0xf
    }
}

fn set_nibble(k: &mut [u8; 32], i: usize, v: u8) {
    let b = &mut k[i / 2];
    if i.is_multiple_of(2) {
        *b = (*b & 0x0f) | (v << 4);
    } else {
        *b = (*b & 0xf0) | (v & 0xf);
    }
}

/// `k`'s first `d` nibbles against `p`'s.
fn cmp_prefix(k: &B256, p: &B256, d: usize) -> Ordering {
    let bytes = d / 2;
    match k.0[..bytes].cmp(&p.0[..bytes]) {
        Ordering::Equal => {}
        o => return o,
    }
    if d % 2 == 1 {
        (k.0[bytes] >> 4).cmp(&(p.0[bytes] >> 4))
    } else {
        Ordering::Equal
    }
}

/// Where a walk for one key goes, predicted from the trie's sorted keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathShape {
    /// Depths of the branches on the path, ascending.
    pub branches: Vec<usize>,
    /// Depth (nibbles consumed) at which the walk's last node sits: the
    /// leaf for a present key; the branch, extension or leaf that proves
    /// an absence.
    pub depth: usize,
    /// Nodes a walk decodes, extensions and the final node included.
    pub nodes: usize,
    /// An extension lies on the path above the final node (a depth the
    /// speculative round asks for and the table does not have).
    pub extension: bool,
    /// `None` for a present key.
    pub absent: Option<AbsentBy>,
}

/// Leaves of one trie in ascending hashed-key order, with a key accessor so
/// the slice's own vectors are used in place.
struct Sorted<'a, T> {
    items: &'a [T],
    key: fn(&T) -> &B256,
}

impl<'a, T> Sorted<'a, T> {
    fn len(&self) -> usize {
        self.items.len()
    }

    fn key(&self, i: usize) -> &B256 {
        (self.key)(&self.items[i])
    }

    fn contains(&self, k: &B256) -> bool {
        self.items
            .binary_search_by(|t| (self.key)(t).cmp(k))
            .is_ok()
    }

    /// Of the items in `lo..hi` (all sharing `p`'s first `d - 1` nibbles),
    /// the sub-range sharing its first `d`.
    fn narrow(&self, p: &B256, d: usize, lo: usize, hi: usize) -> (usize, usize) {
        let s = &self.items[lo..hi];
        let a = s.partition_point(|t| cmp_prefix((self.key)(t), p, d) == Ordering::Less);
        let b = s.partition_point(|t| cmp_prefix((self.key)(t), p, d) != Ordering::Greater);
        (lo + a, lo + b)
    }

    /// The walk's shape for `key`. `below` says, for each depth above the
    /// keys this set can see (a slice's ancestors), whether the node there
    /// is a branch: taken from the boundary proof, since every key here
    /// shares those nibbles and the set alone cannot tell. `None` when the
    /// key leaves the covered subtrie above the set (outside the slice).
    fn shape(&self, key: &B256, below: &[bool]) -> Option<PathShape> {
        if self.len() == 0 {
            return Some(PathShape {
                branches: vec![],
                depth: 0,
                nodes: 0,
                extension: false,
                absent: Some(AbsentBy::EmptyTrie),
            });
        }
        let mut branches = Vec::with_capacity(12);
        // Every key here shares the `below` nibbles; a key that does not is
        // outside, which the first visible depth reports as an empty range.
        let (mut lo, mut hi) = self.narrow(key, below.len(), 0, self.len());
        let mut d = 0usize;
        let (depth, absent) = loop {
            if d < below.len() {
                if below[d] {
                    branches.push(d);
                }
                d += 1;
                continue;
            }
            let count = hi - lo;
            if count == 0 {
                return None;
            }
            let after_last = branches.last().map_or(0, |b| b + 1);
            assert!(d < 64, "duplicate keys in a sorted leaf set");
            let (lo1, hi1) = self.narrow(key, d + 1, lo, hi);
            let count1 = hi1 - lo1;
            if count1 == 0 {
                // Nothing continues with key[d]. The `count` keys sharing
                // key[..d] decide what stands here.
                if count == 1 {
                    break (after_last, Some(AbsentBy::LeafMismatch));
                }
                if nibble(self.key(lo), d) == nibble(self.key(hi - 1), d) {
                    // All continue with one other nibble: an extension
                    // covers this depth and the key leaves it.
                    break (after_last, Some(AbsentBy::ExtensionMismatch));
                }
                branches.push(d);
                break (d, Some(AbsentBy::EmptySlot));
            }
            if count1 < count {
                branches.push(d);
            }
            if count1 == 1 && self.key(lo1) == key {
                break (branches.last().map_or(0, |b| b + 1), None);
            }
            lo = lo1;
            hi = hi1;
            d += 1;
        };
        // Node positions on the path: the branches and the final node (a
        // branch itself for an empty slot). A gap between consecutive
        // positions, or above the first, is an extension node.
        let mut positions = branches.clone();
        if positions.last() != Some(&depth) {
            positions.push(depth);
        }
        let mut gaps = 0usize;
        let mut prev = 0usize;
        for (i, p) in positions.iter().enumerate() {
            if (i == 0 && *p > 0) || (i > 0 && *p > prev + 1) {
                gaps += 1;
            }
            prev = *p;
        }
        Some(PathShape {
            branches,
            depth,
            nodes: positions.len() + gaps,
            extension: gaps > 0,
            absent,
        })
    }

    /// The child nibbles of the branch at depth `b` on `key`'s path, as a
    /// bitmask; `b` must be at or below the set's own depths.
    fn children(&self, key: &B256, b: usize) -> u16 {
        let (mut lo, mut hi) = (0, self.len());
        for d in 1..=b {
            (lo, hi) = self.narrow(key, d, lo, hi);
        }
        let mut mask = 0u16;
        for i in lo..hi {
            mask |= 1 << nibble(self.key(i), b);
        }
        mask
    }
}

/// `k` with nibbles from `from` on drawn at random.
fn with_tail(k: &B256, from: usize, rng: &mut ChaCha8Rng) -> B256 {
    let mut out = k.0;
    let mut r = [0u8; 32];
    rng.fill_bytes(&mut r);
    let r = B256::from(r);
    for i in from..64 {
        set_nibble(&mut out, i, nibble(&r, i));
    }
    B256::from(out)
}

/// A random key under `prefix`.
fn random_in(prefix: &Nibbles, rng: &mut ChaCha8Rng) -> B256 {
    let mut r = [0u8; 32];
    rng.fill_bytes(&mut r);
    for i in 0..prefix.len() {
        set_nibble(&mut r, i, prefix.get_unchecked(i));
    }
    B256::from(r)
}

/// Which absence a crafted key aims for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Craft {
    LeafMismatch,
    EmptySlot,
    ExtensionMismatch,
}

/// An absent key whose walk ends as `craft` says, built from a present
/// key's shape: the same path to the point of divergence, then a random
/// tail. `min_depth` keeps the divergence inside the depths the set can
/// see. `None` when the shape offers no such point (no extension on the
/// path, every branch full).
fn craft<T>(
    set: &Sorted<'_, T>,
    key: &B256,
    shape: &PathShape,
    craft: Craft,
    min_depth: usize,
    rng: &mut ChaCha8Rng,
) -> Option<B256> {
    let candidate = match craft {
        Craft::LeafMismatch => {
            if shape.depth < min_depth {
                return None;
            }
            // Share the path to the leaf's position, then differ at the
            // leaf's own first nibble so the mismatch is the leaf's.
            let mut raw = with_tail(key, shape.depth, rng).0;
            if shape.depth < 64 {
                set_nibble(&mut raw, shape.depth, nibble(key, shape.depth) ^ 0x8);
            }
            B256::from(raw)
        }
        Craft::EmptySlot => {
            // The deepest branch with a free slot.
            let mut found = None;
            for b in shape.branches.iter().rev() {
                if *b < min_depth {
                    break;
                }
                let mask = set.children(key, *b);
                if mask != 0xffff {
                    let free: Vec<u8> = (0..16u8).filter(|n| mask & (1 << n) == 0).collect();
                    found = Some((*b, free[rng.random_range(0..free.len())]));
                    break;
                }
            }
            let (b, nib) = found?;
            let mut raw = with_tail(key, b + 1, rng).0;
            set_nibble(&mut raw, b, nib);
            B256::from(raw)
        }
        Craft::ExtensionMismatch => {
            // The first nibble an extension covers: the position after a
            // branch when the next branch (or the leaf) is not adjacent.
            let mut positions = shape.branches.clone();
            if positions.last() != Some(&shape.depth) {
                positions.push(shape.depth);
            }
            let mut at = None;
            let mut prev: Option<usize> = None;
            for p in &positions {
                let start = prev.map_or(0, |q| q + 1);
                if *p > start && start >= min_depth {
                    at = Some(start);
                }
                prev = Some(*p);
            }
            let start = at?;
            let mut raw = with_tail(key, start + 1, rng).0;
            set_nibble(&mut raw, start, nibble(key, start) ^ 0x8);
            B256::from(raw)
        }
    };
    if set.contains(&candidate) {
        return None;
    }
    Some(candidate)
}

// ----------------------------------------------------------------------
// The plan.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Account(B256),
    /// Owner's hashed address, hashed slot.
    Slot(B256, B256),
    Code(B256),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expect {
    Account(Account),
    Slot(U256),
    /// The bytecode's length; the bytes are checked against the slice.
    Code(usize),
    Absent(AbsentBy),
    /// Outside the slice: `Insufficient` from a missing node.
    Insufficient,
}

#[derive(Clone, Debug)]
pub struct Draw {
    pub target: Target,
    pub expect: Expect,
    /// Nodes the read's walks decode, predicted (account and storage
    /// walks summed for a slot).
    pub nodes: usize,
    /// The final node's depth in the trie that answers (the storage trie
    /// for a slot, the account trie otherwise).
    pub depth: usize,
    pub extension: bool,
    pub series: Vec<String>,
}

pub struct Plan {
    pub draws: Vec<Draw>,
    /// How the plan was drawn, for the report.
    pub meta: Value,
}

pub(crate) fn parse_prefix(s: &str) -> Result<Nibbles, String> {
    let s = s.trim_start_matches("0x");
    if s.len() > 62 {
        return Err("prefix must be at most 62 hex nibbles".into());
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        out.push(
            c.to_digit(16)
                .ok_or_else(|| format!("not a hex nibble: {c}"))? as u8,
        );
    }
    Ok(Nibbles::from_nibbles(out))
}

fn account_key(t: &(B256, Account)) -> &B256 {
    &t.0
}

fn slot_key(t: &(B256, U256)) -> &B256 {
    &t.0
}

/// Evenly spaced indices: `n` of `len` (all of them when `n >= len`).
fn strided(len: usize, n: usize) -> impl Iterator<Item = usize> {
    let stride = len.checked_div(n).unwrap_or(len).max(1);
    (0..len).step_by(stride).take(n)
}

/// `n` more of `0..len`, evenly spaced over those `taken` does not
/// already hold: a quota filled from the unselected candidates, so picks
/// forced in earlier never cost the strided rest a draw. Fewer only when
/// fewer are free.
fn fill(len: usize, n: usize, taken: impl Fn(usize) -> bool) -> Vec<usize> {
    let free: Vec<usize> = (0..len).filter(|i| !taken(*i)).collect();
    strided(free.len(), n).map(|k| free[k]).collect()
}

/// Draw the workload from the slice. Deterministic for a seed.
pub fn plan(s: &Slice, sizes: &Sizes, seed: u64) -> Result<Plan, String> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let prefix = parse_prefix(&s.head.prefix)?;
    // Branches above the slice, from the boundary proof: a sealed sibling
    // at depth d + 1 means the node at d is a branch.
    let mut below = vec![false; prefix.len()];
    for (path, _) in &s.boundary {
        let l = path.len();
        if l >= 1 && l <= prefix.len() && path.slice(..l - 1) == prefix.slice(..l - 1) {
            below[l - 1] = true;
        }
    }
    if !prefix.is_empty() && !s.accounts.is_empty() && below.iter().any(|b| !b) {
        return Err(format!(
            "the boundary proof shows no branch at some depth above the prefix {}: {below:?}",
            s.head.prefix
        ));
    }
    let accounts = Sorted {
        items: &s.accounts,
        key: account_key,
    };
    let in_prefix = |h: &B256| path_of(h).starts_with(&prefix);
    let slots_of = |i: usize| -> Option<&Vec<(B256, U256)>> {
        let root = s.accounts[i].1.storage_root;
        if root == EMPTY_ROOT_HASH {
            return None;
        }
        s.storage.get(&root).filter(|v| !v.is_empty())
    };

    // Every account's shape: cheap (a dozen binary searches each) and it
    // tells which keys cross an extension or lie beyond the speculated
    // depth, which the plan wants represented.
    let shapes: Vec<PathShape> = s
        .accounts
        .iter()
        .map(|(h, _)| {
            accounts
                .shape(h, &below)
                .expect("a slice key is inside its prefix")
        })
        .collect();
    let ext_idx: Vec<usize> = (0..shapes.len()).filter(|i| shapes[*i].extension).collect();
    let mut with_storage: Vec<usize> = (0..s.accounts.len())
        .filter(|i| slots_of(*i).is_some())
        .collect();
    with_storage.sort_by_key(|i| std::cmp::Reverse(slots_of(*i).map_or(0, Vec::len)));
    let largest: Vec<usize> = with_storage.iter().copied().take(LARGEST).collect();
    let largest_set: HashSet<usize> = largest.iter().copied().collect();
    let empty_storage: Vec<usize> = (0..s.accounts.len())
        .filter(|i| s.accounts[*i].1.storage_root == EMPTY_ROOT_HASH)
        .collect();

    let mut draws: Vec<Draw> = Vec::new();

    // Present accounts: the largest contracts, a twentieth through
    // extensions, the rest strided over the accounts not yet chosen, so
    // the count is the one asked for whenever the slice holds that many.
    let mut chosen: Vec<usize> = Vec::new();
    let mut seen: HashSet<usize> = HashSet::new();
    let forced = largest.iter().copied().chain(
        strided(ext_idx.len(), (sizes.accounts / 20).min(ext_idx.len())).map(|i| ext_idx[i]),
    );
    for i in forced {
        if chosen.len() < sizes.accounts && seen.insert(i) {
            chosen.push(i);
        }
    }
    let rest = sizes.accounts - chosen.len();
    chosen.extend(fill(s.accounts.len(), rest, |i| seen.contains(&i)));
    let account_draw = |i: usize| -> Draw {
        let (h, a) = &s.accounts[i];
        let sh = &shapes[i];
        let mut series = vec![ACCOUNT_PRESENT.to_string()];
        if sh.extension {
            series.push(ACCOUNT_PRESENT_EXTENSION.into());
        }
        if sh.depth > sizes.d_account {
            series.push(ACCOUNT_PRESENT_BEYOND_D.into());
        }
        if largest_set.contains(&i) {
            series.push(ACCOUNT_PRESENT_LARGEST.into());
        }
        Draw {
            target: Target::Account(*h),
            expect: Expect::Account(*a),
            nodes: sh.nodes,
            depth: sh.depth,
            extension: sh.extension,
            series,
        }
    };
    for i in &chosen {
        draws.push(account_draw(*i));
    }
    let present_accounts = chosen;

    // Code of every contract touched, once per code hash.
    let mut codes: HashSet<B256> = HashSet::new();
    for i in &present_accounts {
        let ch = s.accounts[*i].1.code_hash;
        if ch != KECCAK_EMPTY && codes.insert(ch) {
            let len = s
                .code
                .get(&ch)
                .map(Vec::len)
                .ok_or_else(|| format!("slice lacks code {ch}"))?;
            let kind = if len > CODE_BLOB_THRESHOLD {
                CODE_BLOB
            } else {
                CODE_INLINE
            };
            draws.push(Draw {
                target: Target::Code(ch),
                expect: Expect::Code(len),
                nodes: 0,
                depth: 0,
                extension: false,
                series: vec![CODE.into(), kind.into()],
            });
        }
    }

    // Absent accounts: random tails inside the prefix, and keys crafted
    // from present leaves to end at a leaf, an empty slot and an extension.
    let absent_draw = |k: B256, crafted: bool, draws: &mut Vec<Draw>| -> bool {
        if !in_prefix(&k) || accounts.contains(&k) {
            return false;
        }
        let sh = accounts.shape(&k, &below).expect("inside the prefix");
        let by = sh.absent.expect("not present");
        let mut series = vec![ACCOUNT_ABSENT.to_string(), absent_series("account", by)];
        if crafted {
            series.push(format!("{ACCOUNT_ABSENT}_crafted"));
        }
        draws.push(Draw {
            target: Target::Account(k),
            expect: Expect::Absent(by),
            nodes: sh.nodes,
            depth: sh.depth,
            extension: sh.extension,
            series,
        });
        true
    };
    let crafts = [
        Craft::LeafMismatch,
        Craft::EmptySlot,
        Craft::ExtensionMismatch,
    ];
    let mut absent_made = 0usize;
    let mut attempts = 0usize;
    // Extension misses need a key through an extension; the others any
    // present leaf.
    let source = |n: usize| -> usize {
        if crafts[n % 3] == Craft::ExtensionMismatch && !ext_idx.is_empty() {
            ext_idx[(n / 3) % ext_idx.len()]
        } else {
            present_accounts[(n / 3) % present_accounts.len()]
        }
    };
    while absent_made < sizes.absent && attempts < sizes.absent * 4 && !present_accounts.is_empty()
    {
        let n = attempts;
        attempts += 1;
        // Two of five random, three of five crafted (one per kind).
        let crafted = if n % 5 < 2 {
            None
        } else {
            let i = source(n);
            craft(
                &accounts,
                &s.accounts[i].0,
                &shapes[i],
                crafts[n % 3],
                prefix.len(),
                &mut rng,
            )
        };
        let made = match crafted {
            Some(k) => absent_draw(k, true, &mut draws),
            None => absent_draw(random_in(&prefix, &mut rng), false, &mut draws),
        };
        if made {
            absent_made += 1;
        }
    }

    // Present slots: strided over every (account, slot) pair, a tenth
    // from the largest tries.
    let pairs: Vec<(usize, usize)> = with_storage
        .iter()
        .flat_map(|i| (0..slots_of(*i).map_or(0, Vec::len)).map(move |j| (*i, j)))
        .collect();
    let slot_shape = |i: usize, k: &B256| -> Option<PathShape> {
        let slots = slots_of(i)?;
        Sorted {
            items: slots,
            key: slot_key,
        }
        .shape(k, &[])
    };
    let slot_present_draw = |i: usize, j: usize| -> Draw {
        let (h, _) = &s.accounts[i];
        let (k, v) = slots_of(i).expect("has storage")[j];
        let sh = slot_shape(i, &k).expect("a slot of this trie");
        let mut series = vec![STORAGE_PRESENT.to_string()];
        if sh.extension {
            series.push(STORAGE_PRESENT_EXTENSION.into());
        }
        if sh.depth > sizes.d_storage {
            series.push(STORAGE_PRESENT_BEYOND_D.into());
        }
        if sh.depth >= DEEP_STORAGE {
            series.push(STORAGE_PRESENT_DEEP.into());
        }
        if largest_set.contains(&i) {
            series.push(STORAGE_PRESENT_LARGEST.into());
        }
        Draw {
            target: Target::Slot(*h, k),
            expect: Expect::Slot(v),
            nodes: shapes[i].nodes + sh.nodes,
            depth: sh.depth,
            extension: sh.extension,
            series,
        }
    };
    let mut seen_pairs: HashSet<(usize, usize)> = HashSet::new();
    let extra = sizes.slots / 10;
    if !largest.is_empty() {
        let per = (extra / largest.len()).max(1);
        for i in &largest {
            let n = slots_of(*i).map_or(0, Vec::len);
            for j in strided(n, per.min(n)) {
                if seen_pairs.len() < sizes.slots && seen_pairs.insert((*i, j)) {
                    draws.push(slot_present_draw(*i, j));
                }
            }
        }
    }
    // The rest strided over the pairs not yet drawn, as for accounts.
    let rest = sizes.slots - seen_pairs.len();
    for p in fill(pairs.len(), rest, |p| seen_pairs.contains(&pairs[p])) {
        seen_pairs.insert(pairs[p]);
        draws.push(slot_present_draw(pairs[p].0, pairs[p].1));
    }
    let slots_drawn = seen_pairs.len();

    // Absent slots, in thirds: in tries (half of them the largest, crafted
    // and random), of accounts with no storage, of absent accounts.
    let third = sizes.absent_slots / 3;
    let mut in_tries = 0usize;
    let mut attempts = 0usize;
    while in_tries < third && attempts < third * 4 && !with_storage.is_empty() {
        let n = attempts;
        attempts += 1;
        let i = if n.is_multiple_of(2) && !largest.is_empty() {
            largest[(n / 2) % largest.len()]
        } else {
            with_storage[rng.random_range(0..with_storage.len())]
        };
        let slots = slots_of(i).expect("has storage");
        let set = Sorted {
            items: slots,
            key: slot_key,
        };
        let k = if n % 4 == 1 {
            with_tail(&B256::ZERO, 0, &mut rng)
        } else {
            // An extension miss needs a slot whose path has one, which a
            // few dozen random slots of a trie usually turn up.
            let want = crafts[n % 3];
            let tries = if want == Craft::ExtensionMismatch {
                64
            } else {
                1
            };
            let mut made = None;
            for _ in 0..tries {
                let j = rng.random_range(0..slots.len());
                let sh = set.shape(&slots[j].0, &[]).expect("a slot of this trie");
                if want == Craft::ExtensionMismatch && !sh.extension {
                    continue;
                }
                made = craft(&set, &slots[j].0, &sh, want, 0, &mut rng);
                if made.is_some() {
                    break;
                }
            }
            made.unwrap_or_else(|| with_tail(&B256::ZERO, 0, &mut rng))
        };
        if set.contains(&k) {
            continue;
        }
        let sh = set.shape(&k, &[]).expect("storage tries are complete");
        let by = sh.absent.expect("not present");
        let mut series = vec![STORAGE_ABSENT.to_string(), absent_series("storage", by)];
        if largest_set.contains(&i) {
            series.push(STORAGE_ABSENT_LARGEST.into());
        }
        draws.push(Draw {
            target: Target::Slot(s.accounts[i].0, k),
            expect: Expect::Absent(by),
            nodes: shapes[i].nodes + sh.nodes,
            depth: sh.depth,
            extension: sh.extension,
            series,
        });
        in_tries += 1;
    }
    let mut empty_tries = 0usize;
    for i in strided(empty_storage.len(), third) {
        let i = empty_storage[i];
        draws.push(Draw {
            target: Target::Slot(s.accounts[i].0, with_tail(&B256::ZERO, 0, &mut rng)),
            expect: Expect::Absent(AbsentBy::EmptyTrie),
            nodes: shapes[i].nodes,
            depth: 0,
            extension: false,
            series: vec![STORAGE_EMPTY_TRIE.into()],
        });
        empty_tries += 1;
    }
    let mut of_absent = 0usize;
    let mut attempts = 0usize;
    let want = sizes.absent_slots.saturating_sub(2 * third);
    while of_absent < want && attempts < want * 4 && !s.accounts.is_empty() {
        attempts += 1;
        let k = random_in(&prefix, &mut rng);
        if accounts.contains(&k) {
            continue;
        }
        let sh = accounts.shape(&k, &below).expect("inside the prefix");
        let by = sh.absent.expect("not present");
        draws.push(Draw {
            target: Target::Slot(k, with_tail(&B256::ZERO, 0, &mut rng)),
            expect: Expect::Absent(by),
            nodes: sh.nodes,
            depth: sh.depth,
            extension: sh.extension,
            series: vec![STORAGE_ABSENT_ACCOUNT.into()],
        });
        of_absent += 1;
    }

    // Outside the prefix: the first nibble flipped. A slice with no prefix
    // covers the whole trie and has no outside.
    let mut outside = 0usize;
    if !prefix.is_empty() {
        for i in strided(s.accounts.len(), sizes.outside) {
            let mut k = s.accounts[i].0;
            k.0[0] ^= 0x10;
            if in_prefix(&k) {
                continue;
            }
            draws.push(Draw {
                target: Target::Account(k),
                expect: Expect::Insufficient,
                nodes: 0,
                depth: 0,
                extension: false,
                series: vec![OUTSIDE.into()],
            });
            outside += 1;
        }
    }

    // One shuffled order for every mode, so no shape is read only after
    // the caches warmed and consecutive keys do not share neighbourhoods.
    draws.shuffle(&mut rng);

    let largest_sizes: Vec<usize> = largest
        .iter()
        .map(|i| slots_of(*i).map_or(0, Vec::len))
        .collect();

    // Completeness: every kind drawn to its request, and every shape the
    // spec asks for present among the draws of a kind that was requested.
    let requested = [
        ("accounts_present", sizes.accounts, present_accounts.len()),
        ("accounts_absent", sizes.absent, absent_made),
        ("slots_present", sizes.slots, slots_drawn),
        ("slots_absent_in_tries", third, in_tries),
        ("slots_of_empty_storage", third, empty_tries),
        ("slots_of_absent_accounts", want, of_absent),
        ("outside", sizes.outside, outside),
    ];
    let mut incomplete: Vec<String> = Vec::new();
    for (kind, asked, got) in requested {
        if got != asked {
            incomplete.push(format!("{kind}: requested {asked}, drawn {got}"));
        }
    }
    let mut series_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &draws {
        for s in &d.series {
            *series_counts.entry(s.as_str()).or_default() += 1;
        }
    }
    let required = required_shapes(sizes, third, want);
    for shape in &required {
        if !series_counts.contains_key(shape.as_str()) {
            incomplete.push(format!("shape {shape}: none drawn"));
        }
    }
    let meta = json!({
        "seed": seed,
        "slice_accounts": s.accounts.len(),
        "slice_storage_tries": s.storage.len(),
        "slice_slots": pairs.len(),
        "slice_codes": s.code.len(),
        "accounts_through_extension": ext_idx.len(),
        "accounts_beyond_d": shapes.iter().filter(|sh| sh.depth > sizes.d_account).count(),
        "account_leaf_depths": shapes.iter().fold(BTreeMap::new(), |mut m: BTreeMap<String, usize>, sh| {
            *m.entry(sh.depth.to_string()).or_default() += 1;
            m
        }),
        "largest_tries_slots": largest_sizes,
        "drawn": {
            "accounts_present": present_accounts.len(),
            "accounts_absent": absent_made,
            "slots_present": slots_drawn,
            "slots_absent_in_tries": in_tries,
            "slots_of_empty_storage": empty_tries,
            "slots_of_absent_accounts": of_absent,
            "codes": codes.len(),
            "outside": outside,
            "total": draws.len(),
        },
        "requested": requested.iter().map(|(k, asked, _)| (k.to_string(), *asked)).collect::<BTreeMap<_, _>>(),
        "required_shapes": required.iter().map(|s| (s.clone(), series_counts.get(s.as_str()).copied().unwrap_or(0))).collect::<BTreeMap<_, _>>(),
        "complete": incomplete.is_empty(),
        "incomplete": incomplete,
        "deep_storage_depth": DEEP_STORAGE,
    });
    Ok(Plan { draws, meta })
}

/// The shapes the spec's workload must contain, for the kinds requested:
/// present accounts through an extension and with the leaf below the
/// speculated depth, inline and blob-sized code, each kind of absence in
/// the account trie and in storage tries, deep slots and slots of the
/// largest tries, slots of accounts with empty storage and of absent
/// accounts, and keys outside the prefix. A storage leaf below the
/// speculated storage depth (7) is not required: the largest tries a
/// 1/4096 slice holds end at depth 6 (see [`DEEP_STORAGE`]); it is drawn
/// and reported when the slice has one.
fn required_shapes(sizes: &Sizes, third: usize, of_absent: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |names: &[&str]| out.extend(names.iter().map(|s| s.to_string()));
    if sizes.accounts > 0 {
        add(&[
            ACCOUNT_PRESENT_EXTENSION,
            ACCOUNT_PRESENT_BEYOND_D,
            CODE_INLINE,
            CODE_BLOB,
        ]);
    }
    if sizes.absent > 0 {
        add(&[
            "account_absent_empty_slot",
            "account_absent_leaf_mismatch",
            "account_absent_extension_mismatch",
        ]);
    }
    if sizes.slots > 0 {
        add(&[
            STORAGE_PRESENT_EXTENSION,
            STORAGE_PRESENT_DEEP,
            STORAGE_PRESENT_LARGEST,
        ]);
    }
    if third > 0 {
        add(&[
            "storage_absent_empty_slot",
            "storage_absent_leaf_mismatch",
            "storage_absent_extension_mismatch",
            STORAGE_EMPTY_TRIE,
        ]);
    }
    if of_absent > 0 {
        add(&[STORAGE_ABSENT_ACCOUNT]);
    }
    if sizes.outside > 0 {
        add(&[OUTSIDE]);
    }
    out
}

// ----------------------------------------------------------------------
// Running and scoring.

/// Costs of one kind of read.
#[derive(Default)]
struct Series {
    requests: Vec<u64>,
    bytes: Vec<u64>,
    rounds: Vec<u64>,
    repairs: Vec<u64>,
    nodes: Vec<u64>,
    model_pages: Vec<u64>,
    micros: Vec<u64>,
    /// Final-node depth histogram and how many crossed an extension.
    depths: BTreeMap<usize, usize>,
    extension: usize,
}

fn stats(v: &[u64]) -> Value {
    if v.is_empty() {
        return Value::Null;
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    let mean = s.iter().sum::<u64>() as f64 / s.len() as f64;
    json!({
        "mean": (mean * 10.0).round() / 10.0,
        "p50": s[s.len() / 2],
        "p95": s[(s.len() * 95 / 100).min(s.len() - 1)],
        "max": s[s.len() - 1],
    })
}

fn percentile(v: &[u64], p: usize) -> Option<u64> {
    if v.is_empty() {
        return None;
    }
    let mut s = v.to_vec();
    s.sort_unstable();
    Some(s[(s.len() * p / 100).min(s.len() - 1)])
}

impl Series {
    fn push(&mut self, c: &Cost, wall: Duration, draw: &Draw) {
        self.requests.push(c.requests);
        self.bytes.push(c.bytes);
        self.rounds.push(c.rounds as u64);
        self.repairs.push(c.repairs as u64);
        self.nodes.push(c.nodes as u64);
        self.model_pages.push(c.model_pages);
        self.micros.push(wall.as_micros() as u64);
        *self.depths.entry(draw.depth).or_default() += 1;
        if draw.extension {
            self.extension += 1;
        }
    }

    fn summary(&self) -> Value {
        json!({
            "n": self.requests.len(),
            "requests": stats(&self.requests),
            "bytes": stats(&self.bytes),
            "rounds": stats(&self.rounds),
            "repairs": stats(&self.repairs),
            "nodes_walked": stats(&self.nodes),
            "model_pages": stats(&self.model_pages),
            "ms": stats(&self.micros.iter().map(|u| u / 1000).collect::<Vec<_>>()),
            "depths": self.depths.iter().map(|(d, n)| (d.to_string(), *n)).collect::<BTreeMap<_, _>>(),
            "through_extension": self.extension,
        })
    }
}

/// One mode's run over the plan.
#[derive(Default)]
pub struct Scored {
    pub mode: &'static str,
    pub reads: usize,
    pub ok: usize,
    pub wall: Duration,
    pub wrong_values: usize,
    pub false_absent: usize,
    pub false_present: usize,
    pub unexpected: usize,
    /// The client's `AbsentBy` or decoded node count differed from the
    /// prediction (the answer itself was right).
    pub shape_mismatch: usize,
    failures: Vec<Value>,
    mismatches: Vec<Value>,
    series: BTreeMap<String, Series>,
}

impl Scored {
    /// A wrong answer, an unexpected outcome, or a walk the shape model
    /// did not predict.
    pub fn failed(&self) -> bool {
        self.wrong_values
            + self.false_absent
            + self.false_present
            + self.unexpected
            + self.shape_mismatch
            > 0
    }

    /// The p95 of a series' column, for the budget rule.
    pub fn p95(&self, series: &str, column: &str) -> Option<u64> {
        let s = self.series.get(series)?;
        match column {
            "bytes" => percentile(&s.bytes, 95),
            "rounds" => percentile(&s.rounds, 95),
            _ => None,
        }
    }

    pub fn series_names(&self) -> Vec<&str> {
        self.series.keys().map(String::as_str).collect()
    }

    pub fn count(&self, series: &str) -> usize {
        self.series.get(series).map_or(0, |s| s.requests.len())
    }

    pub fn to_json(&self) -> Value {
        json!({
            "mode": self.mode,
            "reads": self.reads,
            "ok": self.ok,
            "wall_ms": self.wall.as_millis() as u64,
            "wrong_values": self.wrong_values,
            "false_absent": self.false_absent,
            "false_present": self.false_present,
            "unexpected": self.unexpected,
            "shape_mismatch": self.shape_mismatch,
            "failures": self.failures,
            "shape_mismatches": self.mismatches,
            "shapes": self.series.iter().map(|(k, v)| (k.clone(), v.summary())).collect::<BTreeMap<_, _>>(),
        })
    }
}

/// What a read answered, with the type erased for scoring.
pub(crate) enum Answer {
    Account(Account),
    Slot(U256),
    Code(Vec<u8>),
    Absent(AbsentBy),
    Insufficient(Reason),
}

pub(crate) fn target_json(t: &Target) -> Value {
    match t {
        Target::Account(h) => json!({"account": h}),
        Target::Slot(h, k) => json!({"account": h, "slot": k}),
        Target::Code(h) => json!({"code": h}),
    }
}

fn erase<T>(r: Read<T>, f: impl FnOnce(T) -> Answer) -> Answer {
    match r {
        Read::Verified(v) => f(v),
        Read::VerifiedAbsent(b) => Answer::Absent(b),
        Read::Insufficient(r) => Answer::Insufficient(r),
    }
}

/// One draw through `snap`: the baseline's methods when `baseline` (code
/// has one method; the baseline changes only the trie walks).
pub(crate) fn read_draw<D: Driver>(
    snap: &mut Snapshot<D>,
    baseline: bool,
    draw: &Draw,
) -> (Answer, Cost) {
    match &draw.target {
        Target::Account(h) => {
            let (r, c) = if baseline {
                snap.account_by_hash(h)
            } else {
                snap.account(h)
            };
            (erase(r, Answer::Account), c)
        }
        Target::Slot(h, k) => {
            let (r, c) = if baseline {
                snap.storage_by_hash(h, k)
            } else {
                snap.storage(h, k)
            };
            (erase(r, Answer::Slot), c)
        }
        Target::Code(h) => {
            let (r, c) = snap.code(h);
            (erase(r, Answer::Code), c)
        }
    }
}

/// How one answer scores against the slice. `Insufficient` is returned
/// as is: the workload accepts it only for an outside key with a missing
/// node, the fault table for any key (it is how a fault is caught).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    Correct,
    Insufficient(Reason),
    WrongValue(String),
    /// A present key proven absent.
    FalseAbsent(String),
    /// An absent key answered with a value.
    FalsePresent(String),
    /// A key outside the prefix answered with a value or an absence: the
    /// slice cannot prove either, and on mainnet every slot of the root is
    /// full, so only a bug produces one.
    OutsideAnswered(String),
    /// A value of another kind than the target's (the client's methods
    /// cannot do this).
    Kind,
}

pub(crate) fn score(draw: &Draw, s: &Slice, answer: &Answer) -> Verdict {
    match (&draw.expect, answer) {
        (_, Answer::Insufficient(r)) => Verdict::Insufficient(r.clone()),
        (Expect::Account(want), Answer::Account(got)) => {
            if got == want {
                Verdict::Correct
            } else {
                Verdict::WrongValue(format!("{got:?}"))
            }
        }
        (Expect::Slot(want), Answer::Slot(got)) => {
            if got == want {
                Verdict::Correct
            } else {
                Verdict::WrongValue(format!("{got}"))
            }
        }
        (Expect::Code(len), Answer::Code(got)) => {
            let Target::Code(h) = &draw.target else {
                return Verdict::Kind;
            };
            if got.len() == *len && keccak256(got) == *h && s.code.get(h) == Some(got) {
                Verdict::Correct
            } else {
                Verdict::WrongValue(format!("{} bytes", got.len()))
            }
        }
        (Expect::Account(_) | Expect::Slot(_) | Expect::Code(_), Answer::Absent(by)) => {
            Verdict::FalseAbsent(format!("{by:?}"))
        }
        // The kind of absence is the shape model's business (see
        // `shape_mismatches`); the answer is right.
        (Expect::Absent(_), Answer::Absent(_)) => Verdict::Correct,
        (Expect::Absent(_), Answer::Account(_) | Answer::Slot(_) | Answer::Code(_)) => {
            Verdict::FalsePresent("a value".into())
        }
        (Expect::Insufficient, Answer::Absent(by)) => {
            Verdict::OutsideAnswered(format!("absent {by:?}"))
        }
        (Expect::Insufficient, _) => Verdict::OutsideAnswered("a value".into()),
        _ => Verdict::Kind,
    }
}

/// Where a right answer's walk disagrees with the shape model: the kind of
/// absence, or the nodes decoded. Code reads walk nothing; outside keys
/// stop at the first missing node, which the model does not predict.
pub(crate) fn shape_mismatches(draw: &Draw, answer: &Answer, cost: &Cost) -> Vec<Value> {
    let mut out = Vec::new();
    if let (Expect::Absent(want), Answer::Absent(got)) = (&draw.expect, answer) {
        if got != want {
            out.push(json!({
                "what": "absent_by",
                "target": target_json(&draw.target),
                "predicted": format!("{want:?}"),
                "got": format!("{got:?}"),
            }));
        }
    }
    let predicted = !matches!(draw.expect, Expect::Code(_) | Expect::Insufficient);
    if predicted && cost.nodes != draw.nodes {
        out.push(json!({
            "what": "nodes",
            "target": target_json(&draw.target),
            "predicted": draw.nodes,
            "got": cost.nodes,
        }));
    }
    out
}

/// Run every draw through `snap` (the baseline's methods when `baseline`)
/// and score it against the slice.
pub fn run_mode<D: Driver>(
    plan: &Plan,
    s: &Slice,
    snap: &mut Snapshot<D>,
    baseline: bool,
) -> Scored {
    let mut out = Scored {
        mode: mode_label(baseline),
        ..Scored::default()
    };
    let t_all = Instant::now();
    for draw in &plan.draws {
        let t = Instant::now();
        let (answer, cost) = read_draw(snap, baseline, draw);
        let wall = t.elapsed();
        out.reads += 1;
        let fail = |out: &mut Scored, what: &str, got: String| {
            if out.failures.len() < 20 {
                out.failures.push(json!({
                    "what": what,
                    "target": target_json(&draw.target),
                    "expected": format!("{:?}", draw.expect),
                    "got": got,
                }));
            }
        };
        let ok = match score(draw, s, &answer) {
            Verdict::Correct => true,
            Verdict::Insufficient(Reason::Missing { .. })
                if matches!(draw.expect, Expect::Insufficient) =>
            {
                true
            }
            Verdict::Insufficient(r) => {
                out.unexpected += 1;
                fail(&mut out, "insufficient", r.to_string());
                false
            }
            Verdict::WrongValue(g) => {
                out.wrong_values += 1;
                fail(&mut out, "wrong_value", g);
                false
            }
            Verdict::FalseAbsent(g) => {
                out.false_absent += 1;
                fail(&mut out, "false_absent", g);
                false
            }
            Verdict::FalsePresent(g) => {
                out.false_present += 1;
                fail(&mut out, "false_present", g);
                false
            }
            Verdict::OutsideAnswered(g) => {
                out.unexpected += 1;
                fail(&mut out, "outside_answered", g);
                false
            }
            Verdict::Kind => {
                out.unexpected += 1;
                fail(&mut out, "kind", "a value of another kind".into());
                false
            }
        };
        if !ok {
            continue;
        }
        out.ok += 1;
        for m in shape_mismatches(draw, &answer, &cost) {
            out.shape_mismatch += 1;
            if out.mismatches.len() < 20 {
                out.mismatches.push(m);
            }
        }
        for name in &draw.series {
            out.series
                .entry(name.clone())
                .or_default()
                .push(&cost, wall, draw);
        }
    }
    out.wall = t_all.elapsed();
    out
}

// ----------------------------------------------------------------------
// The oracle.

fn rpc(agent: &ureq::Agent, url: &str, method: &str, params: Value) -> Result<Value, String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/json")
        .send(body.as_bytes())
        .map_err(|e| format!("{method}: {e}"))?;
    let status = resp.status();
    let text = resp
        .body_mut()
        .with_config()
        .limit(64 * 1024 * 1024)
        .read_to_string()
        .map_err(|e| format!("{method}: body: {e}"))?;
    // Public endpoints refuse with a status and a JSON-RPC error in the
    // body; the body is the useful part.
    let v: Value = serde_json::from_str(&text).map_err(|_| {
        format!(
            "{method}: http status {status}: {}",
            text.chars().take(200).collect::<String>()
        )
    })?;
    if let Some(err) = v.get("error") {
        return Err(format!("{method}: {err}"));
    }
    Ok(v.get("result").cloned().unwrap_or(Value::Null))
}

fn hex_u64(v: &Value) -> Result<u64, String> {
    let s = v.as_str().ok_or("not a hex string")?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn hex_u256(v: &Value) -> Result<U256, String> {
    let s = v.as_str().ok_or("not a hex string")?;
    U256::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn hex_b256(v: &Value) -> Result<B256, String> {
    v.as_str()
        .ok_or("not a hex string")?
        .parse::<B256>()
        .map_err(|e| e.to_string())
}

/// Addresses seen in recent blocks whose hashed path falls inside the
/// prefix, scored by `eth_getProof` at the slice's block against the
/// client's read of `keccak(address)`. Best effort: any failure is reported
/// in the block and never fails the workload.
fn oracle<D: Driver>(
    snap: &mut Snapshot<D>,
    s: &Slice,
    prefix: &Nibbles,
    url: &str,
    samples: usize,
    blocks: u64,
) -> Value {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .http_status_as_error(false)
        .build()
        .into();
    let mut out = json!({
        "endpoint": url,
        "block": s.head.block_number,
        "candidates": 0,
        "blocks_scanned": 0,
        "scored": 0,
        "agreed": 0,
        "disagreed": 0,
        "error": Value::Null,
        "disagreements": [],
    });
    let mut run = |out: &mut Value| -> Result<(), String> {
        let latest = hex_u64(&rpc(&agent, url, "eth_blockNumber", json!([]))?)?;
        let mut addrs: Vec<[u8; 20]> = Vec::new();
        let mut seen: HashSet<[u8; 20]> = HashSet::new();
        let mut scanned = 0u64;
        for n in (0..blocks).map(|i| latest.saturating_sub(i)) {
            if addrs.len() >= samples {
                break;
            }
            let block = rpc(
                &agent,
                url,
                "eth_getBlockByNumber",
                json!([format!("0x{n:x}"), true]),
            )?;
            scanned += 1;
            let Some(txs) = block.get("transactions").and_then(Value::as_array) else {
                continue;
            };
            for tx in txs {
                for field in ["from", "to"] {
                    let Some(a) = tx.get(field).and_then(Value::as_str) else {
                        continue;
                    };
                    let Ok(raw) = hex::decode(a.trim_start_matches("0x")) else {
                        continue;
                    };
                    let Ok(addr) = <[u8; 20]>::try_from(raw) else {
                        continue;
                    };
                    if !seen.insert(addr) {
                        continue;
                    }
                    if path_of(&keccak256(addr)).starts_with(prefix) && addrs.len() < samples {
                        addrs.push(addr);
                    }
                }
            }
        }
        out["blocks_scanned"] = scanned.into();
        out["candidates"] = addrs.len().into();
        let block_hex = format!("0x{:x}", s.head.block_number);
        for addr in &addrs {
            let a = format!("0x{}", hex::encode(addr));
            let proof = rpc(&agent, url, "eth_getProof", json!([a, [], block_hex]))?;
            let nonce = hex_u64(&proof["nonce"])?;
            let balance = hex_u256(&proof["balance"])?;
            let storage_root = hex_b256(&proof["storageHash"])?;
            let code_hash = hex_b256(&proof["codeHash"])?;
            let hashed = keccak256(addr);
            let (r, _) = snap.account(&hashed);
            let agree = match &r {
                Read::Verified(got) => {
                    *got == Account {
                        nonce,
                        balance,
                        storage_root,
                        code_hash,
                    }
                }
                // A proof of a non-existent account reports the empty
                // account.
                Read::VerifiedAbsent(_) => {
                    nonce == 0
                        && balance.is_zero()
                        && storage_root == EMPTY_ROOT_HASH
                        && code_hash == KECCAK_EMPTY
                }
                Read::Insufficient(_) => false,
            };
            out["scored"] = (out["scored"].as_u64().unwrap_or(0) + 1).into();
            if agree {
                out["agreed"] = (out["agreed"].as_u64().unwrap_or(0) + 1).into();
            } else {
                out["disagreed"] = (out["disagreed"].as_u64().unwrap_or(0) + 1).into();
                if let Some(v) = out["disagreements"].as_array_mut() {
                    v.push(json!({
                        "address": a,
                        "hashed": hashed,
                        "oracle": {"nonce": nonce, "balance": balance.to_string(), "storageHash": storage_root, "codeHash": code_hash},
                        "client": format!("{r:?}"),
                    }));
                }
            }
        }
        Ok(())
    };
    if let Err(e) = run(&mut out) {
        out["error"] = e.into();
    }
    out
}

// ----------------------------------------------------------------------
// The command.

/// The snapshot the workload reads: at the slice's pinned header, or at the
/// head the bucket proves when a checkpoint is given.
fn open<D: Driver>(
    b: D,
    s: &Slice,
    checkpoint: Option<B256>,
) -> Result<(Snapshot<D>, Option<Value>), String> {
    match checkpoint {
        None => Ok((Snapshot::open(b, None, s.head.state_root)?, None)),
        Some(c) => {
            let (snap, head) =
                open_at_head(b, c, std::time::SystemTime::now()).map_err(|e| e.to_string())?;
            if head.execution.state_root != s.head.state_root {
                return Err(format!(
                    "the slice is at block {} ({}), the finalized head at block {} ({})",
                    s.head.block_number,
                    s.head.state_root,
                    head.execution.block_number,
                    head.execution.state_root
                ));
            }
            Ok((
                snap,
                Some(json!({
                    "checkpoint": head.checkpoint,
                    "block_number": head.execution.block_number,
                    "block_hash": head.execution.block_hash,
                    "state_root": head.execution.state_root,
                    "finality_lag_secs": head.finality_lag_secs,
                })),
            ))
        }
    }
}

struct Tuning {
    hint: Hint,
    top_levels: usize,
    d_account: Option<usize>,
    d_storage: Option<usize>,
}

fn tune<D: Driver>(snap: &mut Snapshot<D>, t: &Tuning) {
    snap.hint = t.hint;
    snap.top_levels = t.top_levels;
    if let Some(d) = t.d_account {
        snap.d_account = d;
    }
    if let Some(d) = t.d_storage {
        snap.d_storage = d;
    }
}

/// The 50 KB / two rounds row of the exit table, at the 95th percentile
/// of the path-keyed account read; judged on a remote host only.
pub const BUDGET_BYTES: u64 = 50 * 1024;
pub const BUDGET_ROUNDS: u64 = 2;

/// The budget row over the path-keyed read's account series, present and
/// absent (a wallet asks for both, and an absence walks the same pages).
/// Judged only on a remote host, where it pushes onto `failed`; a run of
/// the baseline alone says so instead of reporting nothing.
fn budget(scored: &[Scored], remote: bool, failed: &mut Vec<String>) -> Value {
    let rule = format!(
        "path-keyed {ACCOUNT_PRESENT} and {ACCOUNT_ABSENT} p95: bytes <= {BUDGET_BYTES}, rounds <= {BUDGET_ROUNDS}"
    );
    let Some(sc) = scored.iter().find(|sc| sc.mode == "path") else {
        return json!({
            "rule": rule,
            "applies": remote,
            "judged": false,
            "note": "not judged: the budget applies to the path-keyed read, and only the baseline was run",
        });
    };
    let mut series = serde_json::Map::new();
    let mut within = true;
    for name in [ACCOUNT_PRESENT, ACCOUNT_ABSENT] {
        let bytes = sc.p95(name, "bytes");
        let rounds = sc.p95(name, "rounds");
        let ok =
            bytes.is_some_and(|b| b <= BUDGET_BYTES) && rounds.is_some_and(|r| r <= BUDGET_ROUNDS);
        if remote && !ok {
            failed.push(format!(
                "warmed {name} read on the remote host: p95 {} bytes, {} rounds (budget {BUDGET_BYTES} bytes, {BUDGET_ROUNDS} rounds)",
                bytes.map_or("-".into(), |b| b.to_string()),
                rounds.map_or("-".into(), |r| r.to_string())
            ));
        }
        within &= ok;
        series.insert(
            name.into(),
            json!({"n": sc.count(name), "bytes_p95": bytes, "rounds_p95": rounds, "within": ok}),
        );
    }
    json!({
        "rule": rule,
        "applies": remote,
        "judged": remote,
        // The present series at the top level, as earlier reports had it.
        "bytes_p95": sc.p95(ACCOUNT_PRESENT, "bytes"),
        "rounds_p95": sc.p95(ACCOUNT_PRESENT, "rounds"),
        "within": within,
        "series": series,
    })
}

pub fn run(args: Args) -> Result<Value, String> {
    let s = Slice::read(&args.slice).map_err(|e| e.to_string())?;
    let prefix = parse_prefix(&s.head.prefix)?;
    let tuning = Tuning {
        hint: Hint::symmetric(args.prefetch),
        top_levels: args.top_levels,
        d_account: args.d_account,
        d_storage: args.d_storage,
    };
    let sizes = Sizes {
        accounts: args.accounts,
        absent: args.absent,
        slots: args.slots,
        absent_slots: args.absent_slots,
        outside: args.outside,
        d_account: args.d_account.unwrap_or(csl_eth_store::D_ACCOUNT),
        d_storage: args.d_storage.unwrap_or(csl_eth_store::D_STORAGE),
    };
    let t_plan = Instant::now();
    let plan = plan(&s, &sizes, args.seed)?;
    let plan_ms = t_plan.elapsed().as_millis() as u64;
    eprintln!(
        "workload: {} reads planned in {plan_ms} ms: {}",
        plan.draws.len(),
        plan.meta["drawn"]
    );

    let modes = args.mode.each();
    let remote = args.url.is_some();
    let mut scored: Vec<Scored> = Vec::new();
    let mut http: Vec<Value> = Vec::new();
    let mut head: Option<Value> = None;
    let mut oracle_out = Value::Null;
    for baseline in modes {
        let label = mode_label(baseline);
        eprintln!("workload: {label} mode");
        let (sc, h, http_totals, o) = match (&args.bucket, &args.url) {
            (Some(dir), None) => {
                let (mut snap, h) = open(DirDriver::new(dir), &s, args.checkpoint)?;
                tune(&mut snap, &tuning);
                let sc = run_mode(&plan, &s, &mut snap, baseline);
                let o = oracle_if_asked(&args, &mut snap, &s, &prefix, &oracle_out);
                (sc, h, Value::Null, o)
            }
            (None, Some(base)) => {
                let b = HttpDriver::new(base, args.proxy.as_deref())?;
                let (mut snap, h) = open(b, &s, args.checkpoint)?;
                tune(&mut snap, &tuning);
                let before = (
                    snap.driver().requests.load(Atomic::Relaxed),
                    snap.driver().bytes.load(Atomic::Relaxed),
                );
                let sc = run_mode(&plan, &s, &mut snap, baseline);
                let after = (
                    snap.driver().requests.load(Atomic::Relaxed),
                    snap.driver().bytes.load(Atomic::Relaxed),
                );
                let totals = json!({
                    "mode": label,
                    "open_requests": before.0,
                    "open_bytes": before.1,
                    "requests": after.0 - before.0,
                    "bytes": after.1 - before.1,
                });
                let o = oracle_if_asked(&args, &mut snap, &s, &prefix, &oracle_out);
                (sc, h, totals, o)
            }
            _ => return Err("give --bucket <dir> or --url <base>".into()),
        };
        eprintln!(
            "workload: {label}: {} reads, {} ok, wrong {} false_absent {} false_present {} unexpected {} shape_mismatch {} in {} ms",
            sc.reads, sc.ok, sc.wrong_values, sc.false_absent, sc.false_present, sc.unexpected, sc.shape_mismatch, sc.wall.as_millis()
        );
        if !o.is_null() {
            oracle_out = o;
        }
        if head.is_none() {
            head = h;
        }
        if !http_totals.is_null() {
            http.push(http_totals);
        }
        scored.push(sc);
    }

    // Pass or fail.
    let mut failed: Vec<String> = Vec::new();
    for sc in &scored {
        if sc.failed() {
            failed.push(format!(
                "{}: wrong_values {} false_absent {} false_present {} unexpected {} shape_mismatch {}",
                sc.mode, sc.wrong_values, sc.false_absent, sc.false_present, sc.unexpected, sc.shape_mismatch
            ));
        }
    }
    // No wrong value, false absence or presence, unexpected outcome or
    // unpredicted walk in any mode (the budget is judged beside it).
    let safe = scored.iter().all(|sc| !sc.failed());
    let budget = budget(&scored, remote, &mut failed);
    let complete = plan.meta["complete"].as_bool().unwrap_or(false);
    if !complete && !args.allow_short {
        failed.push(format!(
            "incomplete plan (the slice cannot supply what was requested; --allow-short for a reduced measurement): {}",
            plan.meta["incomplete"]
        ));
    }
    let pass = failed.is_empty();

    let report = json!({
        "block_number": s.head.block_number,
        "block_hash": s.head.block_hash,
        "state_root": s.head.state_root,
        "prefix": s.head.prefix,
        "host": args.url.clone().unwrap_or_else(|| args.bucket.as_ref().map_or(String::new(), |p| p.display().to_string())),
        "remote": remote,
        "head": head,
        "modes": scored.iter().map(|sc| sc.mode).collect::<Vec<_>>(),
        "hint": {"below": tuning.hint.below, "above": tuning.hint.above, "merge": tuning.hint.merge},
        "top_levels": tuning.top_levels,
        "d_account": sizes.d_account,
        "d_storage": sizes.d_storage,
        "sizes": {
            "accounts": sizes.accounts, "absent": sizes.absent, "slots": sizes.slots,
            "absent_slots": sizes.absent_slots, "outside": sizes.outside,
        },
        "plan": plan.meta,
        "plan_ms": plan_ms,
        "pass": pass,
        "safe": safe,
        "complete": complete,
        "incomplete": plan.meta["incomplete"],
        "allow_short": args.allow_short,
        "failed_rules": failed,
        "budget": budget,
        "totals": {
            "reads": scored.iter().map(|sc| sc.reads).sum::<usize>(),
            "wall_ms": scored.iter().map(|sc| sc.wall.as_millis() as u64).sum::<u64>(),
            "http": http,
        },
        "results": scored.iter().map(Scored::to_json).collect::<Vec<_>>(),
        "oracle": oracle_out,
        "attestation": "Every leaf in the slice (accounts, slots, code hashes) was proven to state_root by mainnet peers' snap range proofs when fetched (crates/snap/src/fetch.rs, verify_range), independently of the bucket under test; the expected values here are those leaves.",
    });
    let text = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, &text).map_err(|e| format!("write {}: {e}", args.out.display()))?;
    if !pass {
        return Err(format!(
            "workload failed ({}); report at {}",
            report["failed_rules"],
            args.out.display()
        ));
    }
    Ok(report)
}

/// The oracle runs once, on the first mode's snapshot.
fn oracle_if_asked<D: Driver>(
    args: &Args,
    snap: &mut Snapshot<D>,
    s: &Slice,
    prefix: &Nibbles,
    done: &Value,
) -> Value {
    match (&args.oracle, args.oracle_samples) {
        (Some(url), n) if n > 0 && done.is_null() => {
            eprintln!(
                "workload: oracle {url}: up to {n} addresses from {} blocks",
                args.oracle_blocks
            );
            let o = oracle(snap, s, prefix, url, n, args.oracle_blocks);
            eprintln!("workload: oracle: {o}");
            o
        }
        _ => Value::Null,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SliceHead;
    use alloy_trie::HashBuilder;
    use csl_eth_store::{produce, AccountLeaf, Head};
    use csl_eth_trie::encode_word;
    use std::collections::HashMap;

    fn storage_root(slots: &[(B256, U256)]) -> B256 {
        let mut hb = HashBuilder::default();
        for (k, v) in slots {
            hb.add_leaf(path_of(k), &encode_word(v));
        }
        hb.root()
    }

    fn state_root(accounts: &[AccountLeaf]) -> B256 {
        let mut hb = HashBuilder::default();
        for a in accounts {
            hb.add_leaf(path_of(&a.hashed), &a.account.encode());
        }
        hb.root()
    }

    /// Synthetic state with every shape: a third of the accounts with
    /// storage (two tries large enough to reach the deep depths), a
    /// quarter with code on both sides of the blob threshold, and a pair
    /// sharing 60 nibbles so the account trie has a long extension.
    fn world(n: usize, seed: u64) -> (Slice, Head, HashMap<B256, Vec<u8>>) {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut by_key: BTreeMap<B256, AccountLeaf> = BTreeMap::new();
        let mut code = HashMap::new();
        let mut i = 0usize;
        while by_key.len() < n {
            let mut h = [0u8; 32];
            rng.fill_bytes(&mut h);
            if i < 2 {
                h = [0x33; 32];
                h[30] = if i == 0 { 0x10 } else { 0x70 };
            }
            let hashed = B256::from(h);
            let mut storage: Vec<(B256, U256)> = Vec::new();
            if i.is_multiple_of(3) {
                let slots = if i == 3 || i == 6 {
                    3000
                } else {
                    rng.random_range(1..=40)
                };
                let mut m = BTreeMap::new();
                while m.len() < slots {
                    let mut s = [0u8; 32];
                    rng.fill_bytes(&mut s);
                    m.insert(B256::from(s), U256::from(rng.random::<u64>() | 1));
                }
                storage = m.into_iter().collect();
            }
            let code_hash = if i % 4 == 1 {
                let len = if i % 8 == 1 {
                    rng.random_range(1..=3000)
                } else {
                    rng.random_range(3969..=24576)
                };
                let mut c = vec![0u8; len];
                rng.fill_bytes(&mut c);
                let h = keccak256(&c);
                code.insert(h, c);
                h
            } else {
                KECCAK_EMPTY
            };
            let account = Account {
                nonce: rng.random_range(0..1000),
                balance: U256::from(rng.random::<u128>()),
                storage_root: storage_root(&storage),
                code_hash,
            };
            by_key.insert(
                hashed,
                AccountLeaf {
                    hashed,
                    account,
                    storage,
                },
            );
            i += 1;
        }
        let leaves: Vec<AccountLeaf> = by_key.into_values().collect();
        let head = Head {
            block_hash: B256::repeat_byte(0xAB),
            block_number: 24_400_000,
            timestamp: 1_761_800_000,
            state_root: state_root(&leaves),
        };
        let mut storage = HashMap::new();
        for a in &leaves {
            if !a.storage.is_empty() {
                storage.insert(a.account.storage_root, a.storage.clone());
            }
        }
        let slice = Slice {
            head: SliceHead {
                block_hash: head.block_hash,
                block_number: head.block_number,
                timestamp: head.timestamp,
                state_root: head.state_root,
                prefix: String::new(),
                fetched_at: 0,
                accounts: leaves.len() as u64,
                storage_tries: storage.len() as u64,
                storage_slots: leaves.iter().map(|a| a.storage.len() as u64).sum(),
                codes: code.len() as u64,
                peers_used: 0,
                bytes_in: 0,
                requests: 0,
                wall_ms: 0,
                repivots: 0,
                pivot_set_ms: 0,
            },
            accounts: leaves.iter().map(|a| (a.hashed, a.account)).collect(),
            storage,
            code: code.clone(),
            boundary: vec![],
        };
        (slice, head, code)
    }

    fn scratch(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "csl-eth-workload-{}-{}-{name}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// The shape model on a trie whose nodes are known by hand: the e2e
    /// pair under a 60-nibble extension (the model against the client's
    /// own walk, node by node, is `both_modes_pass_on_a_synthetic_world`).
    #[test]
    fn shape_of_the_extension_pair() {
        let mut a = [0x33u8; 32];
        a[30] = 0x10;
        let mut b = [0x33u8; 32];
        b[30] = 0x70;
        let items = vec![(B256::from(a), U256::ZERO), (B256::from(b), U256::ZERO)];
        let set = Sorted {
            items: &items,
            key: slot_key,
        };
        // Root is an extension of 60 nibbles, then a branch at 60, leaves at 61.
        let sh = set.shape(&B256::from(a), &[]).unwrap();
        assert_eq!(
            (
                sh.branches.clone(),
                sh.depth,
                sh.nodes,
                sh.extension,
                sh.absent
            ),
            (vec![60], 61, 3, true, None)
        );
        // Leaving the extension at its first nibble.
        let mut k = [0x33u8; 32];
        k[5] = 0x44;
        let sh = set.shape(&B256::from(k), &[]).unwrap();
        assert_eq!(
            (sh.depth, sh.nodes, sh.absent),
            (0, 1, Some(AbsentBy::ExtensionMismatch))
        );
        // Under the branch, a free slot.
        let mut k = [0x33u8; 32];
        k[30] = 0x50;
        let sh = set.shape(&B256::from(k), &[]).unwrap();
        assert_eq!(
            (sh.depth, sh.nodes, sh.absent),
            (60, 2, Some(AbsentBy::EmptySlot))
        );
        // Reaching the first leaf with a different tail.
        let mut k = [0x33u8; 32];
        k[30] = 0x10;
        k[31] = 0x1f;
        let sh = set.shape(&B256::from(k), &[]).unwrap();
        assert_eq!(
            (sh.depth, sh.nodes, sh.absent),
            (61, 3, Some(AbsentBy::LeafMismatch))
        );
        // Crafting from the first leaf lands each kind.
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let sh = set.shape(&B256::from(a), &[]).unwrap();
        for (c, by) in [
            (Craft::LeafMismatch, AbsentBy::LeafMismatch),
            (Craft::EmptySlot, AbsentBy::EmptySlot),
            (Craft::ExtensionMismatch, AbsentBy::ExtensionMismatch),
        ] {
            let k = craft(&set, &B256::from(a), &sh, c, 0, &mut rng).unwrap();
            assert_eq!(set.shape(&k, &[]).unwrap().absent, Some(by), "{c:?}");
        }
        // The empty trie, and a key outside a covered prefix.
        let none: Vec<(B256, U256)> = vec![];
        let set = Sorted {
            items: &none,
            key: slot_key,
        };
        assert_eq!(
            set.shape(&B256::ZERO, &[]).unwrap().absent,
            Some(AbsentBy::EmptyTrie)
        );
        let set = Sorted {
            items: &items,
            key: slot_key,
        };
        assert!(set.shape(&B256::repeat_byte(0x44), &[true]).is_none());
    }

    #[test]
    fn both_modes_pass_on_a_synthetic_world() {
        let (slice, head, code) = world(1500, 1);
        let dir = scratch("world");
        let leaves = slice.accounts.iter().map(|(h, a)| AccountLeaf {
            hashed: *h,
            account: *a,
            storage: slice
                .storage
                .get(&a.storage_root)
                .cloned()
                .unwrap_or_default(),
        });
        produce(&dir, &head, "", leaves, &code).unwrap();
        let sizes = Sizes {
            accounts: 300,
            absent: 300,
            slots: 300,
            absent_slots: 300,
            outside: 0,
            d_account: csl_eth_store::D_ACCOUNT,
            d_storage: csl_eth_store::D_STORAGE,
        };
        let plan = plan(&slice, &sizes, 7).unwrap();
        eprintln!("plan: {}", plan.meta);
        // Every kind drawn to its size and every required shape present.
        assert_eq!(plan.meta["complete"], true, "{}", plan.meta["incomplete"]);
        for (kind, asked) in plan.meta["requested"].as_object().unwrap() {
            assert_eq!(&plan.meta["drawn"][kind], asked, "{kind}");
        }
        // A whole-trie slice has no outside: asking for one is reported.
        let short = super::plan(
            &slice,
            &Sizes {
                outside: 50,
                ..sizes
            },
            7,
        )
        .unwrap();
        assert_eq!(short.meta["complete"], false);
        assert_eq!(
            short.meta["incomplete"],
            json!([
                "outside: requested 50, drawn 0",
                "shape outside: none drawn"
            ])
        );
        let tuning = Tuning {
            hint: Hint::symmetric(1),
            top_levels: 4,
            d_account: None,
            d_storage: None,
        };
        for baseline in [false, true] {
            let mut snap = Snapshot::open(DirDriver::new(&dir), None, head.state_root).unwrap();
            tune(&mut snap, &tuning);
            let sc = run_mode(&plan, &slice, &mut snap, baseline);
            eprintln!(
                "{}: {} reads in {:?}; shapes {:?}",
                sc.mode,
                sc.reads,
                sc.wall,
                sc.series_names()
            );
            assert!(!sc.failed(), "{}", sc.to_json());
            assert_eq!(sc.ok, sc.reads);
            assert_eq!(sc.shape_mismatch, 0, "{}", sc.to_json()["shape_mismatches"]);
            for name in [
                ACCOUNT_PRESENT,
                ACCOUNT_PRESENT_EXTENSION,
                ACCOUNT_PRESENT_BEYOND_D,
                ACCOUNT_PRESENT_LARGEST,
                ACCOUNT_ABSENT,
                "account_absent_empty_slot",
                "account_absent_leaf_mismatch",
                "account_absent_extension_mismatch",
                STORAGE_PRESENT,
                STORAGE_PRESENT_EXTENSION,
                STORAGE_PRESENT_LARGEST,
                STORAGE_PRESENT_DEEP,
                STORAGE_ABSENT,
                STORAGE_ABSENT_LARGEST,
                "storage_absent_empty_slot",
                "storage_absent_leaf_mismatch",
                "storage_absent_extension_mismatch",
                STORAGE_EMPTY_TRIE,
                STORAGE_ABSENT_ACCOUNT,
                CODE,
                CODE_INLINE,
                CODE_BLOB,
            ] {
                assert!(sc.count(name) > 0, "{}: shape {name} is empty", sc.mode);
            }
            // The path-keyed read is one round when the prediction holds,
            // two with a cold model page; the baseline is one per node.
            if !baseline {
                assert!(
                    sc.p95(ACCOUNT_PRESENT, "rounds").unwrap() <= BUDGET_ROUNDS,
                    "{}",
                    sc.to_json()["shapes"][ACCOUNT_PRESENT]
                );
            } else {
                assert!(sc.p95(ACCOUNT_PRESENT, "rounds").unwrap() >= 2);
            }
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
