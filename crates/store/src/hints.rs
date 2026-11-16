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
//! - Storage nodes: the owners (`keccak(address)`) with nodes in the layer.
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
use std::collections::{BTreeSet, HashSet};

/// The most entries a table's hint may have: an account hint of up to
/// 512 KiB of hex, a key set of up to 1 MiB. Mainnet's 64-block layers
/// (~50k accounts) fit; its 256-block ones do not, and go unhinted.
pub const HINT_CAP: usize = 65_536;
/// The most bytes of hints a manifest carries for one layer.
pub const HINT_INLINE: usize = 4096;
/// The most of the prefixes at its depth an account hint may cover.
pub const HINT_COVERAGE: f64 = 0.01;
const MAX_DEPTH: usize = 8;

/// A layer's hints; a table without one is asked for every key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hints {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<PathHint>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<KeySet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<KeySet>,
}

impl Hints {
    pub fn is_empty(&self) -> bool {
        self.account.is_none() && self.storage.is_none() && self.code.is_none()
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
}
