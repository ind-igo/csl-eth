//! Milestone 2 exit measurement: build a run from a workload, then locate
//! every key (or a sample) and a matching number of absent keys, reporting
//! record requests by execution path.

use clap::Parser;
use csl_run::{Config, Entry, Lookup, Path as LPath, Reader, Writer, KEY};
use pgm::workload::{Kind, Spec};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::fs::{File, OpenOptions};
use std::time::Instant;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "vanity")]
    workload: String,
    #[arg(long, default_value = "1e6")]
    n: String,
    #[arg(long, default_value = "1,2,4", value_delimiter = ',')]
    eps: Vec<u16>,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Keys to look up per class (present, absent); 0 = all present keys.
    #[arg(long, default_value_t = 100_000)]
    sample: u64,
    /// Where to write the run files.
    #[arg(long, default_value = "/tmp")]
    dir: std::path::PathBuf,
}

fn full_key(k64: u64, seed: u64) -> [u8; KEY] {
    // Deterministic 32-byte key from the prefix: prefix, then blake3 of it.
    let mut k = [0u8; KEY];
    k[..8].copy_from_slice(&k64.to_be_bytes());
    let h = blake3::hash(&[k64.to_be_bytes(), seed.to_le_bytes()].concat());
    k[8..].copy_from_slice(&h.as_bytes()[..24]);
    k
}

fn value_for(key: &[u8; KEY]) -> Vec<u8> {
    blake3::hash(key).as_bytes()[..24].to_vec()
}

fn main() {
    let a = Args::parse();
    let kind: Kind = a.workload.parse().unwrap();
    let n = a.n.parse::<f64>().unwrap().round() as u64;
    let spec = Spec { kind, n, seed: a.seed };
    let cfg_base = Config { profile_id: [0x11; 32], table_id: 0, value_size: 24, epsilon: 1 };

    println!("| ε | pages | file | model | build s | class | lookups | direct | walk (pages) | fallback (pages) | max req | mean req | bytes/lookup |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|---|");
    for &eps in &a.eps {
        let path = a.dir.join(format!("csl-bench-{kind}-{n}-e{eps}.run"));
        let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
        let cfg = Config { epsilon: eps, ..cfg_base };
        let t0 = Instant::now();
        let mut w = Writer::new(f, cfg, n).unwrap();
        // The workload may repeat a k64 (rare); the full key still differs
        // only if we salt by position, so dedupe by skipping repeats and
        // declaring the count after a first pass.
        let mut last: Option<u64> = None;
        let mut count = 0u64;
        spec.for_each(|k| {
            if last != Some(k) {
                count += 1;
            }
            last = Some(k);
        });
        if count != n {
            // Recreate the writer with the deduplicated count.
            let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(&path).unwrap();
            w = Writer::new(f, cfg, count).unwrap();
        }
        let mut last: Option<u64> = None;
        spec.for_each(|k| {
            if last == Some(k) {
                return;
            }
            last = Some(k);
            let key = full_key(k, a.seed);
            w.push(Entry::value(key, value_for(&key))).unwrap();
        });
        let built = w.finish().unwrap();
        let build_s = t0.elapsed().as_secs_f64();
        let rref = built.run_ref(0, 0, eps);
        let file_len = std::fs::metadata(&path).unwrap().len();

        // Present keys: a strided sample over the sorted stream.
        let mut present: Vec<[u8; KEY]> = Vec::new();
        let stride = count.checked_div(a.sample).map_or(1, |s| s.max(1));
        let mut i = 0u64;
        let mut last: Option<u64> = None;
        spec.for_each(|k| {
            if last == Some(k) {
                return;
            }
            last = Some(k);
            if i.is_multiple_of(stride) {
                present.push(full_key(k, a.seed));
            }
            i += 1;
        });
        let mut rng = ChaCha8Rng::seed_from_u64(a.seed + 1000);
        let absent: Vec<[u8; KEY]> = (0..present.len()).map(|_| rng.random()).collect();

        for (class, keys, expect_found) in [("present", &present, true), ("absent", &absent, false)] {
            let mut r = Reader::new(File::open(&path).unwrap(), rref, 24);
            r.load_model().unwrap();
            let t1 = Instant::now();
            for k in keys {
                let (res, _path) = r.get(k).unwrap();
                match (&res, expect_found) {
                    (Lookup::Found(v), true) => assert_eq!(*v, value_for(k)),
                    (Lookup::Absent, false) => {}
                    (Lookup::Absent, true) => panic!("present key reported absent"),
                    (Lookup::Found(_), false) => panic!("random key found"),
                    (Lookup::Tombstone, _) => panic!("no tombstones here"),
                }
            }
            let s = &r.stats;
            let lookups = keys.len() as u64;
            println!(
                "| {} | {} | {:.1} MB | {} B | {:.1} | {} | {} | {} | {} ({}) | {} ({}) | {} | {:.3} | {:.0} |",
                eps,
                built.page_count,
                file_len as f64 / 1e6,
                built.layout.model_bytes,
                build_s,
                class,
                lookups,
                s.direct,
                s.walk,
                s.walk_pages,
                s.fallback,
                s.fallback_pages,
                s.max_requests_one_lookup,
                s.record_requests as f64 / lookups as f64,
                s.record_bytes as f64 / lookups as f64,
            );
            let _ = t1;
            let _ = LPath::Direct;
        }
        std::fs::remove_file(&path).ok();
    }
}
