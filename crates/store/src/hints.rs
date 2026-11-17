//! Skip hints: which keys a layer may hold, so a read asks only the runs
//! that can answer it (`docs/delta-producer.md`).
//!
//! A hint is scheduling, never evidence. A read that skips a run on a
//! hint and then misses a node asks every run in a repair round before it
//! ends `Insufficient`, so a wrong or stale hint costs a round, never an
//! answer. A hint too large for the manifest is left out, and a layer
//! without one is asked for everything.
//!
//! - Account nodes: every node's position cut to `depth` nibbles (the
//!   smallest depth at which the cut positions cover at most
//!   [`HINT_COVERAGE`] of the prefixes), plus the positions shallower than
//!   `depth` that have nothing of the layer below them. Above `depth` the
//!   hint is exact: a layer holds a real node there iff it holds something
//!   under it.
//! - Storage nodes: the owners (`keccak(address)`) with nodes in the layer,
//!   and for the owners with many (a contract whose storage changes every
//!   block is in every layer), their positions as an account hint keeps
//!   them, cut per owner ([`StoragePaths`]). Without that, a read of a hot
//!   contract's slot would ask every layer at every depth below its root.
//! - Code: the code hashes.
//!
//! Owners and code hashes are kept as their first eight bytes.
//!
//! A layer's hints up to [`HINT_INLINE`] bytes of JSON sit in the
//! manifest; larger ones go to `runs/<blake3>.hints` (named by the hash of
//! their bytes, so immutable and shared like runs), which the client
//! fetches when it opens the snapshot. A hint file that is missing or does
//! not hash only costs the reader its hints.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};

/// The most entries a table's hint may have: an account hint of up to
/// 512 KiB of hex, a key set of up to 1 MiB. Mainnet's 64-block layers
/// (~50k accounts) fit; its 256-block ones do not, and go unhinted.
pub const HINT_CAP: usize = 65_536;
/// The most bytes of hints a manifest carries for one layer.
pub const HINT_INLINE: usize = 4096;
/// The most of the prefixes at its depth an account hint may cover.
pub const HINT_COVERAGE: f64 = 0.01;
const MAX_DEPTH: usize = 8;
/// An owner with at least this many storage nodes in a layer gets a path
/// hint; one with fewer is only named.
pub const HOT_MIN: usize = 64;
/// The most entries all of a layer's storage path hints may have together;
/// past it, the owners with the most nodes are hinted first.
pub const STORAGE_PATHS_CAP: usize = 2 * HINT_CAP;
/// The most storage positions collected for path hints; a step past it (a
/// long catch-up, whose layer is too big to hint anyway) gets none.
const COLLECT_CAP: usize = 1 << 22;

/// A layer's hints; a table without one is asked for every key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<PathHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<KeySet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<KeySet>,
    /// Path hints for the hot owners in `storage`. An owner in `storage`
    /// without one may hold any position in its trie.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_paths: Option<StoragePaths>,
}

impl Hints {
    pub fn is_empty(&self) -> bool {
        self.account.is_none()
            && self.storage.is_none()
            && self.code.is_none()
            && self.storage_paths.is_none()
    }

    /// May the layer hold the storage position at `depth` on the path whose
    /// first eight nibbles are `top8`, in `owner`'s trie?
    pub fn storage_holds(&self, owner: &[u8; 32], top8: u32, depth: usize) -> Holds {
        let Some(s) = &self.storage else {
            return Holds::Maybe;
        };
        if !s.contains(owner) {
            return Holds::No;
        }
        match self.storage_paths.as_ref().and_then(|p| p.get(owner)) {
            Some(p) => p.holds(top8, depth),
            // Its storage changed in the layer: its root is there.
            None if depth == 0 => Holds::Yes,
            None => Holds::Maybe,
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("hints serialize")
    }

    /// Hints from a hint file's bytes, which must hash to `name`.
    pub fn from_file(bytes: &[u8], name: &[u8; 32]) -> Result<Hints, String> {
        if blake3::hash(bytes).as_bytes() != name {
            return Err("hint file does not hash to its name".into());
        }
        serde_json::from_slice(bytes).map_err(|e| format!("hint file: {e}"))
    }
}

/// Where a layer's hints file lives: `runs/<blake3>.hints`.
pub fn hints_path(name: &[u8; 32]) -> String {
    format!("runs/{}.hints", hex::encode(name))
}

/// Whether a run may hold a position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holds {
    /// It does not.
    No,
    /// It might.
    Maybe,
    /// It holds the node there if the position is a node of its state, so
    /// older runs need not be asked.
    Yes,
}

/// Account-trie positions a layer holds, cut to `depth` nibbles.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PathHintJson", into = "PathHintJson")]
pub struct PathHint {
    pub depth: u8,
    /// Positions at `depth` or deeper, cut to `depth` nibbles, sorted.
    pub cut: Vec<u32>,
    /// Positions shallower than `depth` with nothing of the layer under
    /// them: (depth, nibbles), sorted.
    pub short: Vec<(u8, u32)>,
}

impl PathHint {
    /// May the layer hold the position at `depth` on the path whose first
    /// eight nibbles are `top8`?
    pub fn holds(&self, top8: u32, depth: usize) -> Holds {
        let d = self.depth as usize;
        if depth >= d {
            let p = cut(top8, d);
            return if self.cut.binary_search(&p).is_ok() {
                Holds::Maybe
            } else {
                Holds::No
            };
        }
        let q = cut(top8, depth);
        let shift = 4 * (d - depth) as u32;
        let lo = (q as u64) << shift;
        let hi = (q as u64 + 1) << shift;
        let i = self.cut.partition_point(|&c| (c as u64) < lo);
        if self.cut.get(i).is_some_and(|&c| (c as u64) < hi)
            || self.short.binary_search(&(depth as u8, q)).is_ok()
        {
            Holds::Yes
        } else {
            Holds::No
        }
    }

    pub fn len(&self) -> usize {
        self.cut.len() + self.short.len()
    }

    /// A hint holding every position either holds (a merged layer's), at
    /// the shallower depth; `None` past [`HINT_CAP`].
    pub fn union(&self, other: &PathHint) -> Option<PathHint> {
        let d = self.depth.min(other.depth);
        let mut cut: BTreeSet<u32> = BTreeSet::new();
        let mut short: BTreeSet<(u8, u32)> = BTreeSet::new();
        for h in [self, other] {
            let down = 4 * (h.depth - d) as u32;
            cut.extend(h.cut.iter().map(|&c| c >> down));
            for &(sd, q) in &h.short {
                if sd < d {
                    short.insert((sd, q));
                } else {
                    // Shallower than its own cut, at or below the new one.
                    cut.insert(q >> (4 * (sd - d) as u32));
                }
            }
        }
        (cut.len() + short.len() <= HINT_CAP).then(|| PathHint {
            depth: d,
            cut: cut.into_iter().collect(),
            short: short.into_iter().collect(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The first `n` nibbles (n ≤ 8) of `top8`.
fn cut(top8: u32, n: usize) -> u32 {
    if n == 0 {
        0
    } else {
        top8 >> (32 - 4 * n as u32)
    }
}

/// The first eight nibbles of a key, as the client reads paths.
pub fn top8(key: &[u8; 32]) -> u32 {
    u32::from_be_bytes(key[..4].try_into().expect("4 bytes"))
}

fn prefix8(key: &[u8; 32]) -> u64 {
    u64::from_be_bytes(key[..8].try_into().expect("8 bytes"))
}

/// Builds a [`PathHint`] from account-table keys (packed path ‖ depth).
pub struct PathHintBuilder {
    /// `cuts[n]`: positions at depth ≥ n cut to n nibbles; `None` past
    /// the cap.
    cuts: Vec<Option<HashSet<u32>>>,
    /// `at[d]`: positions at exactly depth d < 8.
    at: Vec<Option<HashSet<u32>>>,
}

impl Default for PathHintBuilder {
    fn default() -> Self {
        PathHintBuilder {
            cuts: (0..=MAX_DEPTH).map(|_| Some(HashSet::new())).collect(),
            at: (0..MAX_DEPTH).map(|_| Some(HashSet::new())).collect(),
        }
    }
}

fn add(set: &mut Option<HashSet<u32>>, v: u32) {
    if let Some(s) = set {
        s.insert(v);
        if s.len() > HINT_CAP {
            *set = None;
        }
    }
}

impl PathHintBuilder {
    /// An account-table key: the position's nibbles packed into 31 bytes,
    /// its depth last.
    pub fn push(&mut self, key: &[u8; 32]) {
        let depth = key[31] as usize;
        let t = top8(key);
        for n in 1..=MAX_DEPTH.min(depth) {
            add(&mut self.cuts[n], cut(t, n));
        }
        if depth < MAX_DEPTH {
            add(&mut self.at[depth], cut(t, depth));
        }
    }

    /// The hint at the smallest depth that covers at most
    /// [`HINT_COVERAGE`] of its prefixes in at most [`HINT_CAP`] entries,
    /// or `None`.
    pub fn finish(self) -> Option<PathHint> {
        'depth: for d in 1..=MAX_DEPTH {
            let Some(c) = &self.cuts[d] else { continue };
            if c.len() as f64 > HINT_COVERAGE * 16f64.powi(d as i32) {
                continue;
            }
            let mut cut_sorted: Vec<u32> = c.iter().copied().collect();
            cut_sorted.sort_unstable();
            let mut short = Vec::new();
            for (depth, at) in self.at.iter().enumerate().take(d) {
                let Some(at) = at else { continue 'depth };
                for &q in at {
                    let shift = 4 * (d - depth) as u32;
                    let (lo, hi) = ((q as u64) << shift, (q as u64 + 1) << shift);
                    let i = cut_sorted.partition_point(|&x| (x as u64) < lo);
                    if !cut_sorted.get(i).is_some_and(|&x| (x as u64) < hi) {
                        short.push((depth as u8, q));
                    }
                }
            }
            if cut_sorted.len() + short.len() > HINT_CAP {
                continue;
            }
            short.sort_unstable();
            return Some(PathHint {
                depth: d as u8,
                cut: cut_sorted,
                short,
            });
        }
        None
    }
}

/// Keys cut to their first eight bytes, sorted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeySet(pub Vec<u64>);

impl KeySet {
    /// The set, or `None` past [`HINT_CAP`].
    pub fn of<'a>(keys: impl IntoIterator<Item = &'a [u8; 32]>) -> Option<KeySet> {
        let mut s = BTreeSet::new();
        for k in keys {
            s.insert(prefix8(k));
            if s.len() > HINT_CAP {
                return None;
            }
        }
        Some(KeySet(s.into_iter().collect()))
    }

    /// The union, or `None` past [`HINT_CAP`] or when either is unknown.
    pub fn union(a: Option<&KeySet>, b: Option<&KeySet>) -> Option<KeySet> {
        let (a, b) = (a?, b?);
        let s: BTreeSet<u64> = a.0.iter().chain(&b.0).copied().collect();
        (s.len() <= HINT_CAP).then(|| KeySet(s.into_iter().collect()))
    }

    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.0.binary_search(&prefix8(key)).is_ok()
    }
}

impl From<KeySet> for String {
    fn from(k: KeySet) -> String {
        let mut b = Vec::with_capacity(k.0.len() * 8);
        for v in k.0 {
            b.extend_from_slice(&v.to_be_bytes());
        }
        hex::encode(b)
    }
}

impl TryFrom<String> for KeySet {
    type Error = String;
    fn try_from(s: String) -> Result<KeySet, String> {
        let b = hex::decode(&s).map_err(|e| e.to_string())?;
        if b.len() % 8 != 0 {
            return Err("key set: not whole 8-byte keys".into());
        }
        let v: Vec<u64> = b
            .chunks(8)
            .map(|c| u64::from_be_bytes(c.try_into().expect("8")))
            .collect();
        if !v.windows(2).all(|w| w[0] < w[1]) {
            return Err("key set: not sorted".into());
        }
        Ok(KeySet(v))
    }
}

/// Path hints for a layer's hot owners, by the owner's first eight bytes:
/// `{"<16 hex>": <account-style hint over the owner's storage paths>}`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "BTreeMap<String, PathHint>",
    into = "BTreeMap<String, PathHint>"
)]
pub struct StoragePaths(pub BTreeMap<u64, PathHint>);

impl StoragePaths {
    pub fn get(&self, owner: &[u8; 32]) -> Option<&PathHint> {
        self.0.get(&prefix8(owner))
    }

    pub fn entries(&self) -> usize {
        self.0.values().map(PathHint::len).sum()
    }

    /// For merged layers, oldest first, each `(owners, paths)`: an owner
    /// keeps a path hint only if every layer that names it has one for it.
    /// `None` when any layer's owners are unknown.
    pub fn merge(layers: &[(Option<&KeySet>, Option<&StoragePaths>)]) -> Option<StoragePaths> {
        let mut acc: BTreeMap<u64, Option<PathHint>> = BTreeMap::new();
        for (owners, paths) in layers {
            let owners = (*owners)?;
            for &o in &owners.0 {
                let mine = paths.and_then(|p| p.0.get(&o));
                let e = acc.entry(o);
                match (e, mine) {
                    (std::collections::btree_map::Entry::Vacant(v), m) => {
                        v.insert(m.cloned());
                    }
                    (std::collections::btree_map::Entry::Occupied(mut v), Some(m)) => {
                        let u = v.get().as_ref().and_then(|h| h.union(m));
                        v.insert(u);
                    }
                    (std::collections::btree_map::Entry::Occupied(mut v), None) => {
                        v.insert(None);
                    }
                }
            }
        }
        let mut hot: Vec<(u64, PathHint)> =
            acc.into_iter().filter_map(|(o, h)| Some((o, h?))).collect();
        hot.sort_by_key(|(o, h)| (std::cmp::Reverse(h.len()), *o));
        Some(StoragePaths::capped(hot))
    }

    /// The hints in order until [`STORAGE_PATHS_CAP`] entries.
    fn capped(hints: Vec<(u64, PathHint)>) -> StoragePaths {
        let mut out = BTreeMap::new();
        let mut n = 0;
        for (o, h) in hints {
            if n + h.len() > STORAGE_PATHS_CAP {
                continue;
            }
            n += h.len();
            out.insert(o, h);
        }
        StoragePaths(out)
    }
}

impl From<StoragePaths> for BTreeMap<String, PathHint> {
    fn from(p: StoragePaths) -> Self {
        p.0.into_iter()
            .map(|(o, h)| (format!("{o:016x}"), h))
            .collect()
    }
}

impl TryFrom<BTreeMap<String, PathHint>> for StoragePaths {
    type Error = String;
    fn try_from(m: BTreeMap<String, PathHint>) -> Result<StoragePaths, String> {
        let mut out = BTreeMap::new();
        for (k, h) in m {
            if k.len() != 16 {
                return Err(format!("storage path hint owner {k}"));
            }
            let o = u64::from_str_radix(&k, 16)
                .map_err(|e| format!("storage path hint owner {k}: {e}"))?;
            out.insert(o, h);
        }
        Ok(StoragePaths(out))
    }
}

/// Collects a step's storage positions per owner for [`StoragePaths`].
#[derive(Clone, Debug)]
pub struct StoragePathsBuilder {
    /// owner's first eight bytes → (top8 << 8 | depth) of each position.
    per: std::collections::HashMap<u64, Vec<u64>>,
    n: usize,
    over: bool,
    min: usize,
}

impl Default for StoragePathsBuilder {
    fn default() -> Self {
        StoragePathsBuilder {
            per: Default::default(),
            n: 0,
            over: false,
            min: HOT_MIN,
        }
    }
}

impl StoragePathsBuilder {
    /// Hint owners with at least `min` positions instead of [`HOT_MIN`]
    /// (tests hint every owner).
    pub fn hot_min(mut self, min: usize) -> Self {
        self.min = min.max(1);
        self
    }

    /// A storage node of `owner` at the position `key` (its path's nibbles
    /// packed into 31 bytes, its depth last, as an account-table key).
    pub fn push(&mut self, owner: &[u8; 32], key: &[u8; 32]) {
        if self.over {
            return;
        }
        self.n += 1;
        if self.n > COLLECT_CAP {
            self.over = true;
            self.per = Default::default();
            return;
        }
        self.per
            .entry(prefix8(owner))
            .or_default()
            .push((top8(key) as u64) << 8 | key[31] as u64);
    }

    /// Hints for the owners with at least [`HOT_MIN`] positions (or the
    /// [`hot_min`](Self::hot_min) given), most
    /// positions first, up to [`STORAGE_PATHS_CAP`] entries; `None` past
    /// the collection cap.
    pub fn finish(self) -> Option<StoragePaths> {
        if self.over {
            return None;
        }
        let mut hot: Vec<(u64, Vec<u64>)> = self
            .per
            .into_iter()
            .filter(|(_, v)| v.len() >= self.min)
            .collect();
        hot.sort_by_key(|(o, v)| (std::cmp::Reverse(v.len()), *o));
        let hints = hot
            .into_iter()
            .filter_map(|(o, v)| {
                let mut b = PathHintBuilder::default();
                for p in v {
                    let mut k = [0u8; 32];
                    k[..4].copy_from_slice(&((p >> 8) as u32).to_be_bytes());
                    k[31] = p as u8;
                    b.push(&k);
                }
                Some((o, b.finish()?))
            })
            .collect();
        Some(StoragePaths::capped(hints))
    }
}

/// `{"depth": d, "cut": hex of ⌈d/2⌉-byte entries, "short": hex of
/// (depth byte, ⌈d/2⌉ bytes)}`.
#[derive(Serialize, Deserialize)]
struct PathHintJson {
    depth: u8,
    cut: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    short: String,
}

fn width(depth: u8) -> usize {
    (depth as usize).div_ceil(2)
}

fn put(out: &mut Vec<u8>, v: u32, w: usize) {
    out.extend_from_slice(&v.to_be_bytes()[4 - w..]);
}

fn get(b: &[u8]) -> u32 {
    let mut x = [0u8; 4];
    x[4 - b.len()..].copy_from_slice(b);
    u32::from_be_bytes(x)
}

impl From<PathHint> for PathHintJson {
    fn from(h: PathHint) -> Self {
        let w = width(h.depth);
        let mut c = Vec::with_capacity(h.cut.len() * w);
        for v in &h.cut {
            put(&mut c, *v, w);
        }
        let mut s = Vec::with_capacity(h.short.len() * (w + 1));
        for (d, v) in &h.short {
            s.push(*d);
            put(&mut s, *v, w);
        }
        PathHintJson {
            depth: h.depth,
            cut: hex::encode(c),
            short: hex::encode(s),
        }
    }
}

impl TryFrom<PathHintJson> for PathHint {
    type Error = String;
    fn try_from(j: PathHintJson) -> Result<PathHint, String> {
        if j.depth == 0 || j.depth as usize > MAX_DEPTH {
            return Err(format!("account hint depth {}", j.depth));
        }
        let w = width(j.depth);
        let c = hex::decode(&j.cut).map_err(|e| e.to_string())?;
        let s = hex::decode(&j.short).map_err(|e| e.to_string())?;
        if c.len() % w != 0 || s.len() % (w + 1) != 0 {
            return Err("account hint: ragged entries".into());
        }
        let cut: Vec<u32> = c.chunks(w).map(get).collect();
        let short: Vec<(u8, u32)> = s.chunks(w + 1).map(|e| (e[0], get(&e[1..]))).collect();
        let bound = 1u64 << (4 * j.depth as u32);
        if !cut.windows(2).all(|x| x[0] < x[1])
            || cut.iter().any(|&v| v as u64 >= bound)
            || !short.windows(2).all(|x| x[0] < x[1])
            || short
                .iter()
                .any(|&(d, v)| d >= j.depth || (v as u64) >= 1u64 << (4 * d as u32))
        {
            return Err("account hint: unsorted or out of range".into());
        }
        Ok(PathHint {
            depth: j.depth,
            cut,
            short,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    fn key(path: &[u8], depth: usize) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, n) in path.iter().take(depth).enumerate() {
            k[i / 2] |= n << (4 * (1 - i % 2));
        }
        k[31] = depth as u8;
        k
    }

    /// Every position pushed is `Yes` or `Maybe`, never `No`; a `Yes`
    /// above the cut is exact; the JSON round-trips.
    #[test]
    fn a_hint_never_says_no_to_a_position_it_holds() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        let mut b = PathHintBuilder::default();
        let mut held = Vec::new();
        for _ in 0..300 {
            let path: Vec<u8> = (0..64).map(|_| rng.random_range(0..16u8)).collect();
            // A leaf at depth 9 and all its ancestors.
            for d in 0..=9 {
                b.push(&key(&path, d));
                held.push((path.clone(), d));
            }
        }
        // And a shallow leaf with nothing under it.
        let shallow: Vec<u8> = vec![0xf, 0xf, 0xf, 0xe, 0, 0, 0, 0];
        b.push(&key(&shallow, 4));
        held.push((shallow.clone(), 4));
        let h = b.finish().expect("a hint");
        assert!(h.cut.len() as f64 <= HINT_COVERAGE * 16f64.powi(h.depth as i32));
        let top = |p: &[u8]| top8(&key(p, 8));
        for (p, d) in &held {
            let v = h.holds(top(p), *d);
            assert_ne!(v, Holds::No, "{p:?} {d}");
            if *d < h.depth as usize {
                assert_eq!(v, Holds::Yes);
            }
        }
        let mut misses = 0;
        for _ in 0..10_000 {
            let p: Vec<u8> = (0..8).map(|_| rng.random_range(0..16u8)).collect();
            if h.holds(top(&p), 8) == Holds::No {
                misses += 1;
            }
        }
        assert!(misses > 9_500, "{misses}");
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<PathHint>(&j).unwrap(), h);
        let ks = KeySet::of([[1u8; 32], [2u8; 32]].iter()).unwrap();
        assert!(ks.contains(&[1u8; 32]) && !ks.contains(&[3u8; 32]));
        let j = serde_json::to_string(&ks).unwrap();
        assert_eq!(serde_json::from_str::<KeySet>(&j).unwrap(), ks);
        assert!(serde_json::from_str::<KeySet>("\"02020202020202020101010101010101\"").is_err());
    }

    fn leaf_and_ancestors(rng: &mut ChaCha8Rng, depth: usize) -> Vec<(Vec<u8>, usize)> {
        let path: Vec<u8> = (0..64).map(|_| rng.random_range(0..16u8)).collect();
        (0..=depth).map(|d| (path.clone(), d)).collect()
    }

    /// A hot owner's path hint, a named owner's root, an unnamed owner:
    /// no position a layer holds is ever `No`, and a hot owner's random
    /// slots mostly are. Merged layers keep a path hint only for owners
    /// every layer hinted, and it holds both layers' positions.
    #[test]
    fn storage_path_hints_never_say_no_to_a_position_held() {
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let hot = [7u8; 32];
        let cold = [9u8; 32];
        let gone = [11u8; 32];
        let mut held: Vec<([u8; 32], Vec<u8>, usize)> = Vec::new();
        let mut b = StoragePathsBuilder::default();
        for _ in 0..200 {
            for (p, d) in leaf_and_ancestors(&mut rng, 7) {
                b.push(&hot, &key(&p, d));
                held.push((hot, p, d));
            }
        }
        for _ in 0..3 {
            for (p, d) in leaf_and_ancestors(&mut rng, 5) {
                b.push(&cold, &key(&p, d));
                held.push((cold, p, d));
            }
        }
        let paths = b.finish().expect("paths");
        assert!(paths.get(&hot).is_some(), "the hot owner is hinted");
        assert!(paths.get(&cold).is_none(), "18 positions is not hot");
        let h = Hints {
            storage: KeySet::of([hot, cold].iter()),
            storage_paths: Some(paths),
            ..Hints::default()
        };
        let top = |p: &[u8]| top8(&key(p, 8));
        for (o, p, d) in &held {
            assert_ne!(h.storage_holds(o, top(p), *d), Holds::No, "{o:?} {p:?} {d}");
        }
        assert_eq!(h.storage_holds(&cold, 0, 0), Holds::Yes);
        assert_eq!(h.storage_holds(&cold, 0, 3), Holds::Maybe);
        assert_eq!(h.storage_holds(&gone, 0, 0), Holds::No);
        let mut no = 0;
        for _ in 0..10_000 {
            let p: Vec<u8> = (0..8).map(|_| rng.random_range(0..16u8)).collect();
            if h.storage_holds(&hot, top(&p), 6) == Holds::No {
                no += 1;
            }
        }
        assert!(no > 9_000, "{no}");
        let j = serde_json::to_string(&h).unwrap();
        assert_eq!(serde_json::from_str::<Hints>(&j).unwrap(), h);
        // An old manifest's hints, without the field, read as before.
        let old: Hints = serde_json::from_str(r#"{"storage":"0707070707070707"}"#).unwrap();
        assert_eq!(old.storage_holds(&hot, 0, 3), Holds::Maybe);

        // A second layer with other positions of the hot owner.
        let mut b2 = StoragePathsBuilder::default();
        let mut held2 = Vec::new();
        for _ in 0..3000 {
            for (p, d) in leaf_and_ancestors(&mut rng, 9) {
                b2.push(&hot, &key(&p, d));
                held2.push((p, d));
            }
        }
        let h2 = Hints {
            storage: KeySet::of([hot].iter()),
            storage_paths: b2.finish(),
            ..Hints::default()
        };
        let d1 = h.storage_paths.as_ref().unwrap().get(&hot).unwrap().depth;
        let d2 = h2.storage_paths.as_ref().unwrap().get(&hot).unwrap().depth;
        assert_ne!(d1, d2, "the union has to change one hint's depth");
        let pair = |a: &Hints, b: &Hints| {
            StoragePaths::merge(&[
                (a.storage.as_ref(), a.storage_paths.as_ref()),
                (b.storage.as_ref(), b.storage_paths.as_ref()),
            ])
        };
        let merged = Hints {
            storage: KeySet::union(h.storage.as_ref(), h2.storage.as_ref()),
            storage_paths: pair(&h, &h2),
            ..Hints::default()
        };
        assert!(merged.storage_paths.as_ref().unwrap().get(&hot).is_some());
        for (o, p, d) in held
            .iter()
            .map(|(o, p, d)| (*o, p.clone(), *d))
            .chain(held2.iter().map(|(p, d)| (hot, p.clone(), *d)))
        {
            assert_ne!(merged.storage_holds(&o, top(&p), d), Holds::No, "{p:?} {d}");
        }
        // A layer that names the hot owner without a path hint: none after.
        let named = Hints {
            storage: KeySet::of([hot].iter()),
            ..Hints::default()
        };
        assert!(pair(&h, &named).unwrap().get(&hot).is_none());
        assert!(pair(&named, &h).unwrap().get(&hot).is_none());
        // A layer whose owners are unknown: no path hints at all.
        assert!(pair(&h, &Hints::default()).is_none());
    }
}
