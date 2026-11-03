//! Seeded synthetic key workloads, streamed in sorted order so that 10^9 keys
//! never have to be held at once.
//!
//! Every workload is defined by `(kind, n, seed)` and produces the same
//! sorted `k64` stream on every run. Keys are generated per top-16-bit
//! bucket: bucket counts come from sequential conditional binomial draws
//! (an exact multinomial), the low 48 bits are drawn uniformly and sorted
//! within the bucket, so the overall stream is exactly `n` sorted uniform
//! prefixes without a global sort.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use rand_distr::{Binomial, Distribution};
use std::fmt;
use std::str::FromStr;

const BUCKETS: usize = 1 << 16;
const LOW_BITS: u32 = 48;
/// Number of distinct 16-bit vanity prefixes in the clustered workload.
pub const VANITY_PREFIXES: usize = 16;
/// Share of keys that land in vanity prefixes, as a divisor (1 percent).
pub const VANITY_DIVISOR: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Uniform 32-byte keys: hashed account ids, the common case.
    Uniform,
    /// Sequential 64-bit prefixes with random suffixes: an auto-increment id
    /// in the leading bytes. One group per key, a perfect line.
    SequentialPrefix,
    /// 99 percent uniform plus 1 percent of keys spread over 16 shared
    /// 16-bit prefixes: vanity addresses, a density cliff the model must
    /// break segments around.
    Vanity,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Uniform, Kind::SequentialPrefix, Kind::Vanity];
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Kind::Uniform => "uniform",
            Kind::SequentialPrefix => "seq-prefix",
            Kind::Vanity => "vanity",
        })
    }
}

impl FromStr for Kind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "uniform" => Ok(Kind::Uniform),
            "seq-prefix" | "seq" | "sequential" => Ok(Kind::SequentialPrefix),
            "vanity" => Ok(Kind::Vanity),
            other => Err(format!("unknown workload {other:?}; use uniform, seq-prefix, vanity")),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Spec {
    pub kind: Kind,
    pub n: u64,
    pub seed: u64,
}

impl Spec {
    /// Stream the workload's `k64` prefixes in sorted order.
    pub fn for_each(&self, mut f: impl FnMut(u64)) {
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed ^ (self.kind as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        match self.kind {
            Kind::Uniform => {
                let counts = multinomial(&mut rng, self.n, BUCKETS);
                emit_buckets(&mut rng, &counts, &mut f);
            }
            Kind::SequentialPrefix => {
                let start = rng.random_range(0..=u64::MAX - self.n);
                for i in 0..self.n {
                    f(start + i);
                }
            }
            Kind::Vanity => {
                let vanity_total = self.n / VANITY_DIVISOR;
                let uniform_total = self.n - vanity_total;
                let mut counts = multinomial(&mut rng, uniform_total, BUCKETS);
                let prefixes = distinct_prefixes(&mut rng, VANITY_PREFIXES);
                let vanity_counts = multinomial(&mut rng, vanity_total, VANITY_PREFIXES);
                for (p, c) in prefixes.iter().zip(vanity_counts) {
                    counts[*p as usize] += c;
                }
                emit_buckets(&mut rng, &counts, &mut f);
            }
        }
    }

    /// The vanity prefixes this spec uses (for reporting); empty otherwise.
    pub fn vanity_prefixes(&self) -> Vec<u16> {
        if self.kind != Kind::Vanity {
            return Vec::new();
        }
        let mut rng = ChaCha8Rng::seed_from_u64(self.seed ^ (self.kind as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let _ = multinomial(&mut rng, self.n - self.n / VANITY_DIVISOR, BUCKETS);
        distinct_prefixes(&mut rng, VANITY_PREFIXES)
    }
}

/// Exact multinomial `(n; 1/k, …, 1/k)` by sequential conditional binomials.
fn multinomial(rng: &mut ChaCha8Rng, n: u64, k: usize) -> Vec<u64> {
    let mut counts = vec![0u64; k];
    let mut remaining = n;
    for (i, c) in counts.iter_mut().enumerate() {
        let left = (k - i) as f64;
        if i + 1 == k {
            *c = remaining;
        } else if remaining > 0 {
            let draw = Binomial::new(remaining, 1.0 / left).expect("valid binomial").sample(rng);
            *c = draw;
            remaining -= draw;
        }
    }
    counts
}

fn distinct_prefixes(rng: &mut ChaCha8Rng, k: usize) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::with_capacity(k);
    while out.len() < k {
        let p: u16 = rng.random();
        if !out.contains(&p) {
            out.push(p);
        }
    }
    out.sort_unstable();
    out
}

fn emit_buckets(rng: &mut ChaCha8Rng, counts: &[u64], f: &mut impl FnMut(u64)) {
    let mask: u64 = (1 << LOW_BITS) - 1;
    let mut buf: Vec<u64> = Vec::new();
    for (b, &c) in counts.iter().enumerate() {
        buf.clear();
        buf.reserve(c as usize);
        let hi = (b as u64) << LOW_BITS;
        for _ in 0..c {
            buf.push(hi | (rng.random::<u64>() & mask));
        }
        buf.sort_unstable();
        for &k in &buf {
            f(k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(spec: Spec) -> Vec<u64> {
        let mut v = Vec::new();
        spec.for_each(|k| v.push(k));
        v
    }

    #[test]
    fn exact_count_sorted_deterministic() {
        for kind in Kind::ALL {
            let spec = Spec { kind, n: 100_000, seed: 42 };
            let a = collect(spec);
            let b = collect(spec);
            assert_eq!(a.len(), 100_000, "{kind}");
            assert_eq!(a, b, "{kind} not deterministic");
            assert!(a.windows(2).all(|w| w[0] <= w[1]), "{kind} not sorted");
        }
    }

    #[test]
    fn seeds_differ() {
        let a = collect(Spec { kind: Kind::Uniform, n: 1000, seed: 1 });
        let b = collect(Spec { kind: Kind::Uniform, n: 1000, seed: 2 });
        assert_ne!(a, b);
    }

    #[test]
    fn uniform_is_spread() {
        let keys = collect(Spec { kind: Kind::Uniform, n: 1 << 20, seed: 7 });
        // Each of 16 top-4-bit buckets holds about 1/16 of the keys.
        let mut c = [0u64; 16];
        for k in &keys {
            c[(k >> 60) as usize] += 1;
        }
        for x in c {
            assert!((x as f64 - 65536.0).abs() < 2500.0, "{c:?}");
        }
    }

    #[test]
    fn vanity_prefixes_are_dense() {
        let spec = Spec { kind: Kind::Vanity, n: 1_000_000, seed: 3 };
        let keys = collect(spec);
        let prefixes = spec.vanity_prefixes();
        assert_eq!(prefixes.len(), VANITY_PREFIXES);
        let in_vanity = keys.iter().filter(|k| prefixes.contains(&((*k >> 48) as u16))).count();
        // ~1 percent vanity plus the uniform share of 16/65536 buckets.
        assert!(in_vanity > 9_500 && in_vanity < 11_000, "{in_vanity}");
    }

    #[test]
    fn sequential_is_consecutive() {
        let keys = collect(Spec { kind: Kind::SequentialPrefix, n: 1000, seed: 5 });
        assert!(keys.windows(2).all(|w| w[1] == w[0] + 1));
    }
}
