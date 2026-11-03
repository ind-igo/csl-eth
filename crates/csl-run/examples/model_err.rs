//! Prediction error of a run's model: for every page `i`, the error on its
//! first key (stored) and on the key just below it (absent, covered by page
//! `i − 1`); for 10^6 uniform random keys; and for the key just below every
//! segment's `key_start`. Prints histograms of `predict − page`. Stored keys
//! must be within `ε`; everything else within `ε + 1` (core §4, §10).
//!
//! Usage: model_err <manifest file> <run file>   (the manifest names the run
//! as its base or delta).

use csl_run::{k64, Manifest, Reader, RunRef};
use std::collections::BTreeMap;
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let m = Manifest::decode(&fs::read(&args[1]).expect("manifest")).expect("decode manifest");
    let file = fs::File::open(&args[2]).expect("run");
    let name = std::path::Path::new(&args[2]).file_name().unwrap().to_string_lossy().to_string();
    let rref: RunRef = [m.base, m.delta]
        .into_iter()
        .flatten()
        .find(|r| hex::encode(r.root) == name)
        .expect("manifest does not name this run");
    let mut r = Reader::new(file, rref, 24);
    let pc = rref.page_count;
    let eps = rref.epsilon_pages as i64;
    let mut hist_in: BTreeMap<i64, u64> = BTreeMap::new();
    let mut hist_gap: BTreeMap<i64, u64> = BTreeMap::new();
    let mut prev_hi_k: Option<u64> = None;
    let mut lo_keys: Vec<u64> = Vec::with_capacity(pc as usize);
    for i in 1..=pc {
        let page = r.fetch_page(i).expect("page");
        let k = k64(&page.lo);
        lo_keys.push(k);
        let p = r.load_model().unwrap().predict(k) as i64;
        *hist_in.entry(p - i as i64).or_default() += 1;
        if i > 1 {
            // The absent key just below this page's lo fence belongs to page
            // i − 1. Skip when it would share k64 with the previous page's
            // last key (then it is the same group).
            let below = k.wrapping_sub(1);
            if prev_hi_k != Some(below) && k > 0 {
                let p = r.load_model().unwrap().predict(below) as i64;
                *hist_gap.entry(p - (i as i64 - 1)).or_default() += 1;
            }
        }
        prev_hi_k = page.entries.last().map(|e| k64(&e.key));
    }
    // Uniform random keys (almost all absent): the true page from the
    // in-memory fence list, the error from the model.
    let mut hist_rand: BTreeMap<i64, u64> = BTreeMap::new();
    let mut seg_boundary: BTreeMap<i64, u64> = BTreeMap::new();
    let model = r.load_model().unwrap().clone();
    let mut x = 0x9E3779B97F4A7C15u64;
    for _ in 0..1_000_000u32 {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        let truth = lo_keys.partition_point(|lo| *lo <= x) as i64; // pages are 1-based; page 1's lo is the minimum key
        let truth = truth.max(1);
        let p = model.predict(x) as i64;
        *hist_rand.entry(p - truth).or_default() += 1;
    }
    // Keys just below each segment's key_start: extrapolated by the previous segment.
    for s in model.segments.iter().skip(1) {
        let k = s.key_start - 1;
        let truth = (lo_keys.partition_point(|lo| *lo <= k) as i64).max(1);
        let p = model.predict(k) as i64;
        *seg_boundary.entry(p - truth).or_default() += 1;
    }
    println!("run {name}: pages {pc}, epsilon {eps}, segments {}", model.segments.len());
    println!("1e6 uniform random keys: predict − true page");
    for (d, n) in &hist_rand {
        println!("  {d:+3}  {n:9}{}", if d.abs() > eps + 1 { "  beyond the ε + 1 walk" } else { "" });
    }
    println!("keys just below each segment's key_start: predict − true page");
    for (d, n) in &seg_boundary {
        println!("  {d:+3}  {n:9}{}", if d.abs() > eps + 1 { "  beyond the ε + 1 walk" } else { "" });
    }
    println!("in-set first keys: predict − page");
    for (d, n) in &hist_in {
        println!("  {d:+3}  {n:9}{}", if d.abs() > eps { "  OUTSIDE ε" } else { "" });
    }
    println!("absent keys just below a page's lo (covered by the page before): predict − page");
    for (d, n) in &hist_gap {
        println!("  {d:+3}  {n:9}{}", if d.abs() > eps + 1 { "  beyond the ε + 1 walk" } else { "" });
    }
}
