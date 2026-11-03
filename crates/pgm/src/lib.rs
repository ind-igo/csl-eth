//! Learned index for the cold state layer, as specified in core §4.
//!
//! The model maps a 64-bit key prefix (`k64`) to a page index with a hard
//! bound: for every stored entry with prefix `k64` on page `p`,
//! `|predict(k64) − p| ≤ ε`. It is a routing hint only. Absence is proven by
//! page fences, never by the model.
//!
//! Everything here is canonical: two producers fitting the same groups with
//! the same `ε` produce byte-identical models. Any change to the fit is a new
//! `format_version`.

pub mod workload;

use std::fmt;

/// `2^64` as `i128`, the Q0.64 scale.
pub const Q64: i128 = 1 << 64;
/// Largest representable slope.
pub const SLOPE_MAX: i128 = (1 << 64) - 1;
/// Bytes available for entries in a 4096-byte page after the 66-byte header.
pub const PAGE_PAYLOAD: u64 = 4030;
/// The largest page count a run may have (v1-min §2: `page_count ∈ [1, 2^31]`).
pub const MAX_PAGES: u64 = 1 << 31;

/// One linear piece of the model. `slope` is Q0.64 pages per unit of `k64`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub key_start: u64,
    pub intercept: i64,
    pub slope: u64,
}

/// Entries sharing one `k64`, occupying pages `p_min..=p_max` (1-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Group {
    pub k64: u64,
    pub p_min: u64,
    pub p_max: u64,
}

/// A fitted model with the context a client needs to evaluate it.
/// `page_count` and `epsilon` are not encoded; they live in the `RunRef`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Model {
    pub page_count: u64,
    pub epsilon: u16,
    pub segments: Vec<Segment>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BoundViolation {
    pub group: Group,
    pub predicted: u64,
}

impl fmt::Display for BoundViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "prediction {} for k64 {:#018x} outside pages [{}, {}] ± ε",
            self.predicted, self.group.k64, self.group.p_min, self.group.p_max
        )
    }
}

impl Model {
    /// Core §4 `predict`: last segment with `key_start ≤ k`, or the first
    /// segment with `dx = 0` when `k` precedes every segment; capped at the
    /// next segment's `intercept + ε`; clamped to `[1, page_count]`.
    ///
    /// The cap bounds keys the fit never saw. A segment's slope is fitted to
    /// its stored prefixes and says nothing past the last one; a key between
    /// that prefix and the next segment's `key_start` would be extrapolated
    /// without limit (nine pages off on a 236-page cinder delta). The next
    /// segment's intercept is its prediction for its first stored prefix,
    /// within `ε` of that prefix's pages, and the key's page is at most one
    /// page before them, so the capped prediction is within `ε + 1` of the
    /// page. A stored prefix is never moved out of its bound: its prediction
    /// is at most `p_min + ε`, and the cap is at least the next prefix's
    /// `p_max − ε + ε ≥ p_min`.
    ///
    /// Never panics: a model built by hand with no segments predicts page 1,
    /// and a `page_count` of 0 clamps as if it were 1. [`Model::decode`]
    /// rejects both, so a decoded model never reaches those branches.
    pub fn predict(&self, k: u64) -> u64 {
        let Some(first) = self.segments.first() else {
            return 1;
        };
        let i = self.segments.partition_point(|s| s.key_start <= k);
        let (s, dx) = match i {
            0 => (first, 0u64),
            i => {
                let s = &self.segments[i - 1];
                (s, k - s.key_start)
            }
        };
        // |intercept| < 2^63 and the product term is < 2^64: no i128 overflow.
        let mut p = s.intercept as i128 + (((dx as u128) * (s.slope as u128)) >> 64) as i128;
        if let Some(next) = self.segments.get(i.max(1)) {
            p = p.min(next.intercept as i128 + self.epsilon as i128);
        }
        p.clamp(1, self.page_count.max(1) as i128) as u64
    }

    /// The bound check for one group: the prediction must lie in
    /// `[p_max − ε, p_min + ε]`, which is `|predict − p| ≤ ε` for every page
    /// `p` the group touches.
    pub fn check(&self, g: &Group) -> Result<(), BoundViolation> {
        let predicted = self.predict(g.k64);
        let eps = self.epsilon as i128;
        let p = predicted as i128;
        if p >= g.p_max as i128 - eps && p <= g.p_min as i128 + eps {
            Ok(())
        } else {
            Err(BoundViolation { group: *g, predicted })
        }
    }

    /// Encoded length: `segment_count: u32` then 24 bytes per segment.
    /// Saturates instead of wrapping on a 32-bit target.
    pub fn encoded_len(&self) -> usize {
        self.segments.len().saturating_mul(24).saturating_add(4)
    }

    /// Core §4 encoding, little-endian, no alignment.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        out.extend_from_slice(&(self.segments.len() as u32).to_le_bytes());
        for s in &self.segments {
            out.extend_from_slice(&s.key_start.to_le_bytes());
            out.extend_from_slice(&s.intercept.to_le_bytes());
            out.extend_from_slice(&s.slope.to_le_bytes());
        }
        out
    }

    /// Decodes a model section for a run of `page_count` pages.
    ///
    /// Rejects, besides malformed bytes: a `page_count` outside
    /// `[1, 2^31]` (v1-min §2), and a segment whose intercept is outside
    /// `[1, page_count]` (the canonical fit puts every intercept at the
    /// middle of a group's page span, so it is always a page of the run).
    /// The segments are non-empty and strictly increasing in `key_start`,
    /// and the first one also serves every key below it, so they cover the
    /// whole `k64` space. Length arithmetic is checked, so a hostile
    /// segment count cannot wrap on a 32-bit target.
    pub fn decode(bytes: &[u8], page_count: u64, epsilon: u16) -> Result<Model, DecodeError> {
        if page_count == 0 || page_count > MAX_PAGES {
            return Err(DecodeError::PageCount(page_count));
        }
        if bytes.len() < 4 {
            return Err(DecodeError::Truncated);
        }
        let n = usize::try_from(u32::from_le_bytes(bytes[..4].try_into().unwrap())).map_err(|_| DecodeError::Overflow)?;
        let expected = n.checked_mul(24).and_then(|x| x.checked_add(4)).ok_or(DecodeError::Overflow)?;
        if bytes.len() != expected {
            return Err(DecodeError::Length { expected, got: bytes.len() });
        }
        if n == 0 {
            return Err(DecodeError::Empty);
        }
        let mut segments = Vec::with_capacity(n);
        let mut prev: Option<u64> = None;
        for c in bytes[4..].as_chunks::<24>().0 {
            let key_start = u64::from_le_bytes(c[0..8].try_into().unwrap());
            let intercept = i64::from_le_bytes(c[8..16].try_into().unwrap());
            let slope = u64::from_le_bytes(c[16..24].try_into().unwrap());
            if let Some(p) = prev {
                if key_start <= p {
                    return Err(DecodeError::Unsorted);
                }
            }
            if intercept < 1 || intercept as u64 > page_count {
                return Err(DecodeError::Intercept { key_start, intercept });
            }
            prev = Some(key_start);
            segments.push(Segment { key_start, intercept, slope });
        }
        Ok(Model { page_count, epsilon, segments })
    }

    /// `blake3` of exactly the encoded bytes.
    pub fn model_root(&self) -> [u8; 32] {
        *blake3::hash(&self.encode()).as_bytes()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Length { expected: usize, got: usize },
    Empty,
    Unsorted,
    /// The `page_count` the model is decoded for is outside `[1, 2^31]`.
    PageCount(u64),
    /// A segment's intercept is not a page of the run.
    Intercept { key_start: u64, intercept: i64 },
    /// The declared segment count does not fit the platform's `usize`.
    Overflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FitError {
    /// A prefix group spans more than `2ε + 1` pages. The profile's key
    /// derivation must hash its keys; the producer aborts.
    Unrepresentable(Group),
    /// Groups arrived out of key order.
    Unsorted { prev: u64, next: u64 },
    /// No groups: an empty table has no run and no model.
    Empty,
    /// Verify-on-build failed. This is a bug in the fitter, not in the data.
    Bound(BoundViolation),
}

impl fmt::Display for FitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FitError::Unrepresentable(g) => write!(
                f,
                "prefix group {:#018x} spans pages [{}, {}], more than 2ε + 1; hash the keys",
                g.k64, g.p_min, g.p_max
            ),
            FitError::Unsorted { prev, next } => {
                write!(f, "groups out of order: {prev:#018x} then {next:#018x}")
            }
            FitError::Empty => write!(f, "no groups"),
            FitError::Bound(b) => write!(f, "verify-on-build: {b}"),
        }
    }
}

impl std::error::Error for FitError {}

/// Signed ceiling division (`b > 0`).
#[inline]
pub fn ceil_div(a: i128, b: i128) -> i128 {
    let (q, r) = (a / b, a % b);
    if r > 0 { q + 1 } else { q }
}

/// Signed floor division (`b > 0`).
#[inline]
pub fn floor_div(a: i128, b: i128) -> i128 {
    let (q, r) = (a / b, a % b);
    if r < 0 { q - 1 } else { q }
}

/// The exact slope interval that places group `(p_min, p_max)` at distance
/// `dx > 0` from a segment with `intercept` within `ε`, before clamping to the
/// representable range `[0, SLOPE_MAX]`.
///
/// `lo` is the least `s` with `floor(dx·s / 2^64) ≥ p_max − ε − intercept`;
/// `hi` is the greatest `s` with `floor(dx·s / 2^64) ≤ p_min + ε − intercept`.
/// The returned interval is tight on both ends; `hi` may be below `lo`
/// (infeasible) or negative.
#[inline]
pub fn slope_bounds(eps: i128, intercept: i128, dx: i128, p_min: i128, p_max: i128) -> (i128, i128) {
    debug_assert!(dx > 0);
    let a = p_max - eps - intercept;
    let b = p_min + eps - intercept + 1;
    let lo = ceil_div(a * Q64, dx);
    let hi = floor_div(b * Q64 - 1, dx);
    (lo, hi)
}

struct Open {
    key_start: u64,
    intercept: i64,
    s_lo: i128,
    s_hi: i128,
    groups: u64,
}

impl Open {
    fn close(&self) -> Segment {
        let slope = if self.groups == 1 {
            0
        } else {
            (self.s_lo + (self.s_hi - self.s_lo) / 2) as u64
        };
        Segment { key_start: self.key_start, intercept: self.intercept, slope }
    }
}

/// Streaming canonical fit (core §4). Push groups in key order, then `finish`.
/// The caller verifies the model with a second pass over the groups
/// (`Model::check`), or uses [`fit`] which does both over a slice.
pub struct Fitter {
    eps: i128,
    page_count: u64,
    epsilon: u16,
    segments: Vec<Segment>,
    open: Option<Open>,
    last_key: Option<u64>,
    groups: u64,
}

impl Fitter {
    pub fn new(epsilon: u16, page_count: u64) -> Self {
        Fitter {
            eps: epsilon as i128,
            page_count,
            epsilon,
            segments: Vec::new(),
            open: None,
            last_key: None,
            groups: 0,
        }
    }

    pub fn groups_seen(&self) -> u64 {
        self.groups
    }

    pub fn segments_so_far(&self) -> usize {
        self.segments.len() + usize::from(self.open.is_some())
    }

    fn open_at(&self, g: &Group) -> Open {
        Open {
            key_start: g.k64,
            intercept: ((g.p_min + g.p_max) / 2) as i64,
            s_lo: 0,
            s_hi: SLOPE_MAX,
            groups: 1,
        }
    }

    pub fn push(&mut self, g: Group) -> Result<(), FitError> {
        if g.p_min > g.p_max || g.p_min == 0 || g.p_max > self.page_count {
            return Err(FitError::Unrepresentable(g));
        }
        if (g.p_max - g.p_min) as i128 > 2 * self.eps {
            return Err(FitError::Unrepresentable(g));
        }
        if let Some(prev) = self.last_key {
            if g.k64 <= prev {
                return Err(FitError::Unsorted { prev, next: g.k64 });
            }
        }
        self.last_key = Some(g.k64);
        self.groups += 1;

        let Some(open) = self.open.as_mut() else {
            self.open = Some(self.open_at(&g));
            return Ok(());
        };

        let dx = (g.k64 - open.key_start) as i128;
        let (lo, hi) = slope_bounds(self.eps, open.intercept as i128, dx, g.p_min as i128, g.p_max as i128);
        let s_lo = open.s_lo.max(lo);
        let s_hi = open.s_hi.min(hi);
        if s_lo <= s_hi {
            open.s_lo = s_lo;
            open.s_hi = s_hi;
            open.groups += 1;
        } else {
            self.segments.push(open.close());
            self.open = Some(self.open_at(&g));
        }
        Ok(())
    }

    pub fn finish(mut self) -> Result<Model, FitError> {
        let Some(open) = self.open.take() else {
            return Err(FitError::Empty);
        };
        self.segments.push(open.close());
        Ok(Model { page_count: self.page_count, epsilon: self.epsilon, segments: self.segments })
    }

    /// `finish` for a producer that learns the page count only at the end
    /// (variable-layout runs): the fitter was opened with a provisional
    /// upper bound, and the final count must not fall below any page a
    /// group was pushed on. The fit itself does not depend on `page_count`;
    /// it only clamps predictions, which is why the swap is sound.
    pub fn finish_with(mut self, page_count: u64) -> Result<Model, FitError> {
        assert!(page_count >= 1 && page_count <= self.page_count, "final page count outside the provisional bound");
        self.page_count = page_count;
        self.finish()
    }
}

/// Fit and verify over an in-memory group list. Producers with a streaming
/// source use [`Fitter`] and re-stream for verification.
pub fn fit(groups: &[Group], epsilon: u16, page_count: u64) -> Result<Model, FitError> {
    let mut f = Fitter::new(epsilon, page_count);
    for g in groups {
        f.push(*g)?;
    }
    let m = f.finish()?;
    verify(&m, groups.iter().copied())?;
    Ok(m)
}

/// Verify-on-build: every group within the bound.
pub fn verify(m: &Model, groups: impl IntoIterator<Item = Group>) -> Result<(), FitError> {
    for g in groups {
        m.check(&g).map_err(FitError::Bound)?;
    }
    Ok(())
}

/// Entries per page for the fixed layout: `floor(4030 / (33 + value_size))`.
pub fn entries_per_page(value_size: u32) -> u64 {
    PAGE_PAYLOAD / (33 + value_size as u64)
}

/// Pages needed for `n` entries at `epp` entries per page.
pub fn page_count(n: u64, epp: u64) -> u64 {
    n.div_ceil(epp)
}

/// Turns a sorted stream of `k64` prefixes into prefix groups with page
/// spans, assigning entry `i` (0-based) to page `i / epp + 1`.
pub struct Grouper {
    epp: u64,
    idx: u64,
    cur: Option<Group>,
}

impl Grouper {
    pub fn new(entries_per_page: u64) -> Self {
        Grouper { epp: entries_per_page, idx: 0, cur: None }
    }

    pub fn entries_seen(&self) -> u64 {
        self.idx
    }

    /// Push the next key in sorted order. Returns the completed group when
    /// the key changes. Panics on a decreasing key: that is a producer bug.
    #[inline]
    pub fn push(&mut self, k64: u64) -> Option<Group> {
        let page = self.idx / self.epp + 1;
        self.push_at(k64, page)
    }

    /// `push` for a producer that places entries on pages itself (the
    /// variable layout): `page` is the 1-based page the entry sits on and
    /// must not decrease between calls.
    #[inline]
    pub fn push_at(&mut self, k64: u64, page: u64) -> Option<Group> {
        self.idx += 1;
        match &mut self.cur {
            Some(g) if g.k64 == k64 => {
                g.p_max = page;
                None
            }
            Some(g) => {
                assert!(k64 > g.k64, "keys not sorted: {:#x} after {:#x}", k64, g.k64);
                let done = *g;
                *g = Group { k64, p_min: page, p_max: page };
                Some(done)
            }
            None => {
                self.cur = Some(Group { k64, p_min: page, p_max: page });
                None
            }
        }
    }

    pub fn finish(self) -> Option<Group> {
        self.cur
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaCha8Rng;

    fn groups_from_keys(keys: &[u64], epp: u64) -> Vec<Group> {
        let mut g = Grouper::new(epp);
        let mut out: Vec<Group> = keys.iter().filter_map(|&k| g.push(k)).collect();
        out.extend(g.finish());
        out
    }

    fn sorted_random_keys(n: usize, seed: u64) -> Vec<u64> {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let mut v: Vec<u64> = (0..n).map(|_| rng.random()).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    #[test]
    fn bound_holds_on_random_keys_every_epsilon() {
        for seed in 0..4 {
            let keys = sorted_random_keys(50_000, seed);
            for epp in [1u64, 7, 70] {
                let groups = groups_from_keys(&keys, epp);
                let pc = page_count(keys.len() as u64, epp);
                for eps in [0u16, 1, 2, 4, 8, 64] {
                    let m = fit(&groups, eps, pc).unwrap();
                    assert!(m.segments.len() <= groups.len());
                    for g in &groups {
                        m.check(g).unwrap();
                    }
                    // Decreasing ε never decreases segment count.
                }
            }
        }
    }

    #[test]
    fn epsilon_monotone() {
        let keys = sorted_random_keys(200_000, 9);
        let groups = groups_from_keys(&keys, 70);
        let pc = page_count(keys.len() as u64, 70);
        let mut prev = usize::MAX;
        for eps in [1u16, 2, 4, 8] {
            let n = fit(&groups, eps, pc).unwrap().segments.len();
            assert!(n <= prev, "eps {eps}: {n} > {prev}");
            prev = n;
        }
    }

    #[test]
    fn slope_bounds_are_tight() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let pred = |intercept: i128, dx: i128, s: i128| -> i128 {
            intercept + (((dx as u128) * (s as u128)) >> 64) as i128
        };
        for _ in 0..20_000 {
            let eps: i128 = rng.random_range(0..=8);
            let p_min: i128 = rng.random_range(1..=1_000_000);
            let p_max: i128 = p_min + rng.random_range(0..=2 * eps);
            let intercept: i128 = p_min + rng.random_range(-3 * eps - 5..=3 * eps + 5);
            // Mix of tiny and huge dx so both slope regimes are exercised.
            let dx: i128 = if rng.random_bool(0.5) {
                rng.random_range(1..=1_000_000)
            } else {
                rng.random_range(1..=(u64::MAX as i128))
            };
            let (lo, hi) = slope_bounds(eps, intercept, dx, p_min, p_max);
            let a = p_max - eps; // lower target
            let b = p_min + eps; // upper target
            let in_range = |s: i128| (0..=SLOPE_MAX).contains(&s);
            if in_range(lo) {
                assert!(pred(intercept, dx, lo) >= a, "lo not feasible");
            }
            if in_range(lo - 1) {
                assert!(pred(intercept, dx, lo - 1) < a, "lo not least");
            }
            if in_range(hi) {
                assert!(pred(intercept, dx, hi) <= b, "hi not feasible");
            }
            if in_range(hi + 1) {
                assert!(pred(intercept, dx, hi + 1) > b, "hi not greatest");
            }
        }
    }

    #[test]
    fn naive_hi_bound_would_lose_slopes() {
        // With intercept = p_min + ε exactly, the naive bound
        // floor((p_min + ε − intercept) << 64 / dx) is 0, forbidding every
        // positive slope, while the exact bound allows slopes up to the
        // point where the floor ticks over.
        let (eps, intercept, dx, p_min, p_max) = (1i128, 6i128, 1i128 << 40, 5i128, 5i128);
        let (_, hi) = slope_bounds(eps, intercept, dx, p_min, p_max);
        assert!(hi > 0);
        let naive = floor_div((p_min + eps - intercept) * Q64, dx);
        assert_eq!(naive, 0);
    }

    #[test]
    fn one_group_is_one_zero_slope_segment() {
        let m = fit(&[Group { k64: 77, p_min: 1, p_max: 1 }], 1, 1).unwrap();
        assert_eq!(m.segments, vec![Segment { key_start: 77, intercept: 1, slope: 0 }]);
        assert_eq!(m.predict(0), 1);
        assert_eq!(m.predict(u64::MAX), 1);
    }

    #[test]
    fn sequential_prefixes_fit_one_segment() {
        let keys: Vec<u64> = (1_000..1_000 + 70 * 1000).collect();
        let groups = groups_from_keys(&keys, 70);
        let pc = page_count(keys.len() as u64, 70);
        let m = fit(&groups, 1, pc).unwrap();
        assert_eq!(m.segments.len(), 1, "a perfect line needs one segment at ε = 1");
        let m0 = fit(&groups, 0, pc).unwrap();
        assert_eq!(m0.segments.len(), 1, "a perfect line needs one segment even at ε = 0");
    }

    #[test]
    fn shared_prefix_beyond_two_epsilon_aborts() {
        // Sequential full keys from zero: every k64 is 0.
        let keys = vec![0u64; 70 * 4];
        let groups = groups_from_keys(&keys, 70);
        assert_eq!(groups.len(), 1);
        assert!(matches!(fit(&groups, 1, 4), Err(FitError::Unrepresentable(_))));
        assert!(fit(&groups, 2, 4).is_ok(), "four pages is 2ε + 1 pages at ε = 2, minus one");
    }

    #[test]
    fn key_past_a_segments_last_prefix_is_capped_at_the_next_intercept() {
        // Segment A: a steep slope over three dense prefixes; segment B
        // starts far up the key space. Keys in the gap between A's last
        // prefix and B's key_start used to ride A's slope to page_count.
        let m = Model {
            page_count: 100,
            epsilon: 1,
            segments: vec![
                Segment { key_start: 0, intercept: 1, slope: u64::MAX / 4 },
                Segment { key_start: 1 << 62, intercept: 5, slope: 0 },
            ],
        };
        assert_eq!(m.predict(8), 2, "inside A: 8 × (2^64/4 − 1) >> 64 = 1");
        assert_eq!(m.predict((1 << 62) - 1), 6, "capped at B's intercept + ε, not 100");
        assert_eq!(m.predict(1 << 62), 5, "B itself");
        assert_eq!(m.predict(u64::MAX), 5, "the last segment is never capped");
    }

    #[test]
    fn key_before_first_segment_uses_intercept() {
        let groups = vec![
            Group { k64: 1 << 60, p_min: 1, p_max: 1 },
            Group { k64: 2 << 60, p_min: 2, p_max: 2 },
            Group { k64: 3 << 60, p_min: 3, p_max: 3 },
        ];
        let m = fit(&groups, 0, 3).unwrap();
        assert_eq!(m.segments.len(), 1);
        assert_eq!(m.predict(0), m.segments[0].intercept as u64);
        assert_eq!(m.predict(u64::MAX), 3, "clamped");
    }

    #[test]
    fn unsorted_groups_rejected() {
        let mut f = Fitter::new(1, 10);
        f.push(Group { k64: 5, p_min: 1, p_max: 1 }).unwrap();
        assert!(matches!(f.push(Group { k64: 5, p_min: 1, p_max: 1 }), Err(FitError::Unsorted { .. })));
        assert!(matches!(f.push(Group { k64: 4, p_min: 1, p_max: 1 }), Err(FitError::Unsorted { .. })));
    }

    #[test]
    fn empty_fit_is_an_error() {
        assert!(matches!(Fitter::new(1, 0).finish(), Err(FitError::Empty)));
    }

    #[test]
    fn encode_decode_roundtrip_and_root() {
        let keys = sorted_random_keys(10_000, 3);
        let groups = groups_from_keys(&keys, 70);
        let pc = page_count(keys.len() as u64, 70);
        let m = fit(&groups, 2, pc).unwrap();
        let bytes = m.encode();
        assert_eq!(bytes.len(), m.encoded_len());
        let d = Model::decode(&bytes, pc, 2).unwrap();
        assert_eq!(d, m);
        assert_eq!(d.model_root(), m.model_root());
        assert_eq!(Model::decode(&bytes[..bytes.len() - 1], pc, 2), Err(DecodeError::Length { expected: bytes.len(), got: bytes.len() - 1 }));
    }

    #[test]
    fn decode_rejects_bad_context_and_intercepts() {
        let keys = sorted_random_keys(5_000, 4);
        let groups = groups_from_keys(&keys, 70);
        let pc = page_count(keys.len() as u64, 70);
        let m = fit(&groups, 1, pc).unwrap();
        let bytes = m.encode();
        // No pages, or more than 2^31: rejected before anything is read.
        assert_eq!(Model::decode(&bytes, 0, 1), Err(DecodeError::PageCount(0)));
        assert_eq!(Model::decode(&bytes, MAX_PAGES + 1, 1), Err(DecodeError::PageCount(MAX_PAGES + 1)));
        assert!(Model::decode(&bytes, MAX_PAGES, 1).is_ok());
        // An intercept past the last page, or below page 1.
        let one = |intercept: i64| {
            Model { page_count: 4, epsilon: 1, segments: vec![Segment { key_start: 9, intercept, slope: 0 }] }.encode()
        };
        assert!(Model::decode(&one(4), 4, 1).is_ok());
        assert!(Model::decode(&one(1), 4, 1).is_ok());
        assert_eq!(Model::decode(&one(5), 4, 1), Err(DecodeError::Intercept { key_start: 9, intercept: 5 }));
        assert_eq!(Model::decode(&one(0), 4, 1), Err(DecodeError::Intercept { key_start: 9, intercept: 0 }));
        assert_eq!(Model::decode(&one(-3), 4, 1), Err(DecodeError::Intercept { key_start: 9, intercept: -3 }));
        // A segment count of u32::MAX with four bytes: a length error, no
        // overflow and no allocation.
        assert!(matches!(
            Model::decode(&u32::MAX.to_le_bytes(), 4, 1),
            Err(DecodeError::Length { .. } | DecodeError::Overflow)
        ));
    }

    #[test]
    fn predict_never_panics_on_a_hand_built_model() {
        let empty = Model { page_count: 0, epsilon: 1, segments: Vec::new() };
        assert_eq!(empty.predict(0), 1);
        assert_eq!(empty.predict(u64::MAX), 1);
        let zero_pages = Model {
            page_count: 0,
            epsilon: 1,
            segments: vec![Segment { key_start: 0, intercept: 7, slope: u64::MAX }],
        };
        assert_eq!(zero_pages.predict(u64::MAX), 1);
        let extreme = Model {
            page_count: MAX_PAGES,
            epsilon: 1,
            segments: vec![Segment { key_start: 0, intercept: i64::MIN, slope: u64::MAX }],
        };
        assert_eq!(extreme.predict(0), 1);
        let extreme = Model {
            page_count: MAX_PAGES,
            epsilon: 1,
            segments: vec![Segment { key_start: 0, intercept: i64::MAX, slope: u64::MAX }],
        };
        assert_eq!(extreme.predict(u64::MAX), MAX_PAGES);
    }

    #[test]
    fn grouper_pages_and_spans() {
        let mut g = Grouper::new(2);
        assert_eq!(g.push(1), None);
        assert_eq!(g.push(1), None);
        assert_eq!(g.push(1), None);
        assert_eq!(g.push(9), Some(Group { k64: 1, p_min: 1, p_max: 2 }));
        assert_eq!(g.finish(), Some(Group { k64: 9, p_min: 2, p_max: 2 }));
    }

    #[test]
    fn entries_per_page_matches_spec() {
        assert_eq!(entries_per_page(24), 70);
        assert_eq!(entries_per_page(0), 122);
        assert_eq!(page_count(1_000_000, 70), 14_286);
    }
}
