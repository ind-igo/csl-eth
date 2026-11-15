//! Throughput of the streaming export on a synthetic state generated on the
//! fly (nothing held in memory but the trie builders and the sorters).
//!
//! ```text
//! cargo run --release -p csl-eth-store --example export_bench -- \
//!     --accounts 1000000 --slots 4000000 --big 1000000 --mem-mb 256 --out /path/to/dir \
//!     [--workers N] [--ranges N] [--latency-us U] [--no-by-hash]
//! ```
//!
//! `--latency-us` makes the source sleep that long when it opens a
//! contract's storage and every 64 slots, standing in for reth's page faults
//! (the first mainnet run read about 60,000 slots/s on one thread at 41% of
//! a core).
//!
//! A first pass builds the state root with nothing kept (the header's
//! `state_root` the export checks against); the second is the export.
//! Measure peak memory around it with `/usr/bin/time -l` (macOS) or `-v`.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::KECCAK_EMPTY;
use csl_eth_store::{export, AccountRange, ExportOptions, ExportStats, Head, SourceAccount, StateSource};
use csl_eth_trie::{encode_word, path_of, Account, Builder, Discard, EMPTY_ROOT};
use std::{
    collections::HashMap,
    convert::Infallible,
    path::PathBuf,
    time::{Duration, Instant},
};

fn mix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The `i`-th of `n` ascending 256-bit keys, spread evenly with jitter.
fn sorted_key(i: u64, n: u64, salt: u64) -> B256 {
    let step = U256::MAX / U256::from(n);
    let jitter = U256::from(mix(i ^ salt.rotate_left(17))) % (step / U256::from(2)).max(U256::from(1));
    B256::from(step * U256::from(i) + jitter)
}

struct Synth {
    accounts: u64,
    /// Every `contract_every`-th account has storage and code.
    contract_every: u64,
    slots_each: u64,
    /// Account 0 holds this many slots.
    big: u64,
    code: HashMap<B256, Vec<u8>>,
    pool: Vec<B256>,
    latency: Duration,
}

impl Synth {
    fn new(accounts: u64, slots: u64, big: u64) -> Synth {
        let contract_every = 10;
        let contracts = (accounts / contract_every).max(1);
        let slots_each = (slots.saturating_sub(big) / contracts).max(1);
        let mut code = HashMap::new();
        let mut pool = Vec::new();
        for i in 0..64u64 {
            let len = if i % 4 == 0 { 6000 + (i as usize) * 100 } else { 200 + (i as usize) * 30 };
            let c: Vec<u8> = (0..len).map(|j| mix(i * 1_000_003 + j as u64) as u8).collect();
            let h = keccak256(&c);
            code.insert(h, c);
            pool.push(h);
        }
        Synth { accounts, contract_every, slots_each, big, code, pool, latency: Duration::ZERO }
    }

    fn slot_count(&self, i: u64) -> u64 {
        if i == 0 {
            self.big
        } else if i.is_multiple_of(self.contract_every) {
            self.slots_each
        } else {
            0
        }
    }

    fn account(&self, i: u64) -> SourceAccount {
        let code_hash = if i.is_multiple_of(self.contract_every) { self.pool[(mix(i) % self.pool.len() as u64) as usize] } else { KECCAK_EMPTY };
        SourceAccount { hashed: sorted_key(i, self.accounts, 1), nonce: mix(i) % 1000, balance: U256::from(mix(i ^ 7)), code_hash }
    }

    fn index_of(&self, hashed: &B256) -> u64 {
        // Inverse of `sorted_key`: the jitter is below half a step.
        let step = U256::MAX / U256::from(self.accounts);
        (U256::from_be_bytes(hashed.0) / step).to::<u64>()
    }

    /// The first account at or above `k`.
    fn first_at(&self, k: &B256) -> u64 {
        let j = self.index_of(k).min(self.accounts);
        if j < self.accounts && sorted_key(j, self.accounts, 1) < *k {
            j + 1
        } else {
            j
        }
    }
}

type Slots<'a> = Box<dyn Iterator<Item = Result<(B256, U256), Infallible>> + 'a>;
type Accounts<'a> = Box<dyn Iterator<Item = Result<SourceAccount, Infallible>> + 'a>;

impl StateSource for Synth {
    type Error = Infallible;
    type Accounts<'a> = Accounts<'a>;
    type Storage<'a> = Slots<'a>;

    fn accounts(&self, range: &AccountRange) -> Result<Accounts<'_>, Infallible> {
        let lo = self.first_at(&range.start);
        let hi = range.end.map_or(self.accounts, |e| self.first_at(&e)).max(lo);
        Ok(Box::new((lo..hi).map(|i| Ok(self.account(i)))))
    }

    fn storage(&self, hashed: &B256) -> Result<Slots<'_>, Infallible> {
        let i = self.index_of(hashed);
        let n = self.slot_count(i);
        let salt = mix(i).wrapping_add(3);
        let latency = self.latency;
        if n > 0 && !latency.is_zero() {
            std::thread::sleep(latency);
        }
        Ok(Box::new((0..n).map(move |j| {
            if j % 64 == 63 && !latency.is_zero() {
                std::thread::sleep(latency);
            }
            Ok((sorted_key(j, n, salt), U256::from(mix(salt ^ j) | 1)))
        })))
    }

    fn code(&self, code_hash: &B256) -> Result<Option<Vec<u8>>, Infallible> {
        Ok(self.code.get(code_hash).cloned())
    }
}

/// This process's resident set, from `ps`.
fn rss_mib() -> f64 {
    let out = std::process::Command::new("ps").args(["-o", "rss=", "-p", &std::process::id().to_string()]).output().ok();
    out.and_then(|o| String::from_utf8(o.stdout).ok()).and_then(|s| s.trim().parse::<f64>().ok()).map_or(0.0, |kb| kb / 1024.0)
}

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1).cloned())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let num = |n: &str, d: u64| arg(&args, n).map_or(d, |v| v.parse().expect("a number"));
    let accounts = num("--accounts", 1_000_000);
    let slots = num("--slots", 4_000_000);
    let big = num("--big", 1_000_000);
    let mem = num("--mem-mb", 256) << 20;
    let out = PathBuf::from(arg(&args, "--out").expect("--out <dir>"));
    let by_hash = !args.iter().any(|a| a == "--no-by-hash");
    let mut src = Synth::new(accounts, slots, big);

    // The state root, nothing kept.
    let t = Instant::now();
    let mut b = Builder::new(Discard);
    for a in src.accounts(&AccountRange::ALL).unwrap() {
        let a = a.unwrap();
        let mut sb = Builder::new(Discard);
        let mut n = 0;
        for s in src.storage(&a.hashed).unwrap() {
            let (k, v) = s.unwrap();
            sb.push(path_of(&k), encode_word(&v)).unwrap();
            n += 1;
        }
        let storage_root = if n == 0 { EMPTY_ROOT } else { sb.finish().0.root };
        b.push(path_of(&a.hashed), Account { nonce: a.nonce, balance: a.balance, storage_root, code_hash: a.code_hash }.encode()).unwrap();
    }
    let state_root = b.finish().0.root;
    eprintln!("root pass: {state_root} in {:.1} s", t.elapsed().as_secs_f64());

    let head = Head { block_hash: B256::repeat_byte(0x42), block_number: 1, timestamp: 1, state_root };
    src.latency = Duration::from_micros(num("--latency-us", 0));
    let mut opts = ExportOptions::new(out.join("scratch"));
    opts.memory_bytes = mem;
    opts.workers = num("--workers", opts.workers as u64) as usize;
    opts.ranges = num("--ranges", opts.ranges as u64) as usize;
    opts.by_hash = by_hash;
    opts.progress_every = std::time::Duration::from_secs(5);
    let mut last = Instant::now();
    let mut phase = None;
    let r = export(&out.join("root"), &head, &src, &opts, &mut |s: &ExportStats| {
        if phase != Some(s.phase) {
            phase = Some(s.phase);
            eprintln!("{:?} at {:.1} s, rss {:.0} MiB", s.phase, s.elapsed.as_secs_f64(), rss_mib());
        }
        if last.elapsed().as_secs() >= 5 {
            last = Instant::now();
            eprintln!(
                "{:?} {:.0}s: {} accounts, {} slots, {} + {} nodes, {:.0} MB spilled, {} written",
                s.phase,
                s.elapsed.as_secs_f64(),
                s.accounts,
                s.storage_slots,
                s.account_nodes,
                s.storage_nodes,
                s.spill_bytes() as f64 / 1e6,
                s.written
            );
        }
    })
    .expect("export");
    let s = &r.stats;
    let nodes = s.account_nodes + s.storage_nodes;
    let secs = |d: std::time::Duration| d.as_secs_f64();
    let write: f64 = s.write.iter().map(|d| d.as_secs_f64()).sum();
    let file_bytes: u64 = s.tables.iter().flatten().map(|t| t.file_bytes).sum();
    println!("accounts {} slots {} storage tries {} largest {}", s.accounts, s.storage_slots, s.storage_tries, s.largest_storage.0);
    println!("nodes {} (account {}, storage {}), embedded {}", nodes, s.account_nodes, s.storage_nodes, s.embedded);
    println!("workers {}, budget {} MiB, peak chunk memory {:.1} MiB", s.workers, mem >> 20, s.peak_sort_bytes as f64 / (1 << 20) as f64);
    for (t, st) in s.sort.iter().enumerate() {
        println!("  table {t}: {st:?}");
    }
    println!(
        "build {:.1} s ({:.0} nodes/s incl. by-hash pushes, {:.0} slots/s; account trie waited {:.1} s), sort {:.1} s, code {:.2} s, write {:.1} s, total {:.1} s",
        secs(s.build),
        nodes as f64 / secs(s.build),
        s.storage_slots as f64 / secs(s.build),
        secs(s.build_wait),
        secs(s.sort_time),
        secs(s.check_code),
        write,
        secs(s.elapsed)
    );
    println!(
        "spilled {:.0} MB ({:.0} MB/s over build + sort), tables {:.0} MB written ({:.0} MB/s)",
        s.spill_bytes() as f64 / 1e6,
        s.spill_bytes() as f64 / 1e6 / (secs(s.build) + secs(s.sort_time)),
        file_bytes as f64 / 1e6,
        file_bytes as f64 / 1e6 / write
    );
}
