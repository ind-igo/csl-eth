//! Conformance vectors (v1-min §9). `make-inputs` writes deterministic input
//! JSON; `gen` writes the Rust encoder's output for every input plus an
//! expected-values file. A second writer consumes the same inputs and must
//! match the Rust output byte for byte.
//!
//! Every `u64` field is a decimal string in the JSON, so a reader whose
//! numbers are IEEE doubles (JavaScript's `JSON.parse`) never rounds one:
//! `manifest-large` carries values above 2^53 to catch that.

use clap::{Parser, Subcommand};
use csl_run::{write_all, ColdRoot, Config, Entry, Manifest, RunRef, KEY, KEY_MAX};
use ed25519_dalek::SigningKey;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "csl-vectors")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write vectors/inputs/*.json.
    MakeInputs { dir: PathBuf },
    /// Encode every input: vectors/rust/<name>.{run,bin} and vectors/expected/<name>.json.
    Gen { dir: PathBuf },
}

/// `u64` as a JSON decimal string (and only a string on input).
mod dec {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        let s = String::deserialize(d)?;
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || (s.len() > 1 && s.starts_with('0')) {
            return Err(D::Error::custom(format!("u64 field {s:?} is not a canonical decimal string")));
        }
        s.parse().map_err(D::Error::custom)
    }

    pub mod opt {
        use serde::Serializer;

        pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(v) => s.serialize_str(&v.to_string()),
                None => s.serialize_none(),
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct EntryJson {
    key: String,
    tag: u8,
    value: String,
}

#[derive(Serialize, Deserialize)]
struct RunRefJson {
    root: String,
    #[serde(with = "dec")]
    block_lo: u64,
    #[serde(with = "dec")]
    block_hi: u64,
    #[serde(with = "dec")]
    page_count: u64,
    #[serde(with = "dec")]
    entry_count: u64,
    epsilon_pages: u16,
    model_bytes: u32,
    model_root: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Input {
    Run {
        name: String,
        profile_id: String,
        table_id: u16,
        value_size: u32,
        epsilon: u16,
        entries: Vec<EntryJson>,
    },
    Manifest {
        name: String,
        #[serde(with = "dec")]
        chain_id: u64,
        profile_id: String,
        #[serde(with = "dec")]
        block_number: u64,
        block_hash: String,
        #[serde(with = "dec")]
        rebuild_block: u64,
        base: Option<RunRefJson>,
        delta: Option<RunRefJson>,
    },
    ColdRoot {
        name: String,
        signing_key: String,
        #[serde(with = "dec")]
        chain_id: u64,
        profile_id: String,
        #[serde(with = "dec")]
        height: u64,
        block_hash: String,
        manifest_root: String,
    },
}

#[derive(Serialize)]
struct Expected {
    name: String,
    file: String,
    #[serde(with = "dec")]
    bytes: u64,
    blake3: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", with = "dec::opt")]
    page_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    depth: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    segments: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_message: Option<String>,
}

fn h32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

fn key_with_prefix(rng: &mut ChaCha8Rng, prefix: &[u8]) -> [u8; KEY] {
    let mut k: [u8; KEY] = rng.random();
    k[..prefix.len()].copy_from_slice(prefix);
    k
}

fn entries(rng: &mut ChaCha8Rng, keys: BTreeSet<[u8; KEY]>, value_size: usize, tombstone_every: usize) -> Vec<EntryJson> {
    keys.into_iter()
        .enumerate()
        .map(|(i, k)| {
            let tomb = tombstone_every > 0 && i % tombstone_every == tombstone_every - 1;
            let value: Vec<u8> = if tomb { Vec::new() } else { (0..value_size).map(|_| rng.random()).collect() };
            EntryJson { key: hex::encode(k), tag: u8::from(tomb), value: hex::encode(value) }
        })
        .collect()
}

fn random_keys(rng: &mut ChaCha8Rng, n: usize) -> BTreeSet<[u8; KEY]> {
    let mut s = BTreeSet::new();
    while s.len() < n {
        s.insert(rng.random());
    }
    s
}

fn make_inputs(dir: &Path) {
    let inputs = dir.join("inputs");
    fs::create_dir_all(&inputs).unwrap();
    let mut rng = ChaCha8Rng::seed_from_u64(0xC5);
    let profile = hex::encode([0x11u8; 32]);
    let mut list: Vec<Input> = Vec::new();

    let run = |name: &str, epsilon: u16, entries: Vec<EntryJson>| Input::Run {
        name: name.into(),
        profile_id: profile.clone(),
        table_id: 0,
        value_size: 24,
        epsilon,
        entries,
    };

    // 1. one page, depth 0
    list.push(run("one-page", 1, { let ks = random_keys(&mut rng, 3); entries(&mut rng, ks, 24, 0) }));
    // 2. two pages, depth 1: 70 + 1
    list.push(run("two-pages", 1, { let ks = random_keys(&mut rng, 71); entries(&mut rng, ks, 24, 0) }));
    // 3. three pages with tombstones, depth 2, the odd-level duplication
    list.push(run("tombstones", 1, { let ks = random_keys(&mut rng, 150); entries(&mut rng, ks, 24, 3) }));
    // 4. prefix group spanning 2ε + 1 = 3 pages at ε = 1, pages 2..4 of 5
    {
        let mut keys = BTreeSet::new();
        while keys.len() < 70 {
            keys.insert(key_with_prefix(&mut rng, &[0x00, 0x01]));
        }
        let shared = [0x40u8, 0, 0, 0, 0, 0, 0, 0x01];
        while keys.len() < 280 {
            keys.insert(key_with_prefix(&mut rng, &shared));
        }
        while keys.len() < 310 {
            keys.insert(key_with_prefix(&mut rng, &[0xF0]));
        }
        list.push(run("prefix-group", 1, entries(&mut rng, keys, 24, 0)));
    }
    // 5. the maximum key present on the last page
    {
        let mut keys = random_keys(&mut rng, 99);
        keys.insert(KEY_MAX);
        list.push(run("max-key", 1, entries(&mut rng, keys, 24, 0)));
    }
    // 6. nine pages, depth 4, ε = 2, last page partial
    list.push(run("nine-pages", 2, { let ks = random_keys(&mut rng, 625); entries(&mut rng, ks, 24, 7) }));
    // 7. half the keys under one 16-bit prefix, ε = 4
    {
        let mut keys = random_keys(&mut rng, 500);
        while keys.len() < 1000 {
            keys.insert(key_with_prefix(&mut rng, &[0xDE, 0xAD]));
        }
        list.push(run("vanity-small", 4, entries(&mut rng, keys, 24, 0)));
    }
    // 8. a sixteen-page run, every proof slot filled, ε = 1
    list.push(run("sixteen-pages", 1, { let ks = random_keys(&mut rng, 1120); entries(&mut rng, ks, 24, 0) }));

    let rr = |x: u8| RunRefJson {
        root: hex::encode([x; 32]),
        block_lo: 1,
        block_hi: 200,
        page_count: 14_286,
        entry_count: 1_000_000,
        epsilon_pages: 1,
        model_bytes: 2_836,
        model_root: hex::encode([x + 1; 32]),
    };
    for (name, base, delta) in [
        ("manifest-empty", None, None),
        ("manifest-base", Some(rr(0xA0)), None),
        ("manifest-delta", None, Some(rr(0xB0))),
        ("manifest-both", Some(rr(0xA0)), Some(rr(0xB0))),
    ] {
        list.push(Input::Manifest {
            name: name.into(),
            chain_id: 0x1234,
            profile_id: profile.clone(),
            block_number: 200,
            block_hash: hex::encode([0x77u8; 32]),
            rebuild_block: if base.is_some() { 100 } else { 0 },
            base,
            delta,
        });
    }
    // Every u64 field above 2^53, so a second writer that parses them as
    // doubles encodes different bytes: block_number 2^53 + 1 is the first
    // integer a double cannot hold.
    list.push(Input::Manifest {
        name: "manifest-large".into(),
        chain_id: u64::MAX,
        profile_id: profile.clone(),
        block_number: 9_007_199_254_740_993,
        block_hash: hex::encode([0x78u8; 32]),
        rebuild_block: 9_007_199_254_740_992,
        base: Some(RunRefJson {
            root: hex::encode([0xC0u8; 32]),
            block_lo: 0,
            block_hi: 9_007_199_254_740_992,
            page_count: 1 << 31,
            entry_count: u64::MAX - 1,
            epsilon_pages: u16::MAX,
            model_bytes: u32::MAX,
            model_root: hex::encode([0xC1u8; 32]),
        }),
        delta: Some(RunRefJson {
            root: hex::encode([0xD0u8; 32]),
            block_lo: 9_007_199_254_740_993,
            block_hi: 9_007_199_254_740_993,
            page_count: 18_014_398_509_481_985,
            entry_count: 12_345_678_901_234_567_891,
            epsilon_pages: 1,
            model_bytes: 28,
            model_root: hex::encode([0xD1u8; 32]),
        }),
    });
    list.push(Input::ColdRoot {
        name: "cold-root".into(),
        signing_key: hex::encode([0x42u8; 32]),
        chain_id: 0x1234,
        profile_id: profile.clone(),
        height: 200,
        block_hash: hex::encode([0x77u8; 32]),
        manifest_root: hex::encode([0x99u8; 32]),
    });

    for input in &list {
        let name = match input {
            Input::Run { name, .. } | Input::Manifest { name, .. } | Input::ColdRoot { name, .. } => name.clone(),
        };
        fs::write(inputs.join(format!("{name}.json")), serde_json::to_string_pretty(input).unwrap()).unwrap();
    }
    eprintln!("wrote {} inputs to {}", list.len(), inputs.display());
}

fn to_run_ref(r: &RunRefJson) -> RunRef {
    RunRef {
        root: h32(&r.root),
        block_lo: r.block_lo,
        block_hi: r.block_hi,
        page_count: r.page_count,
        entry_count: r.entry_count,
        epsilon_pages: r.epsilon_pages,
        model_bytes: r.model_bytes,
        model_root: h32(&r.model_root),
    }
}

fn gen(dir: &Path) {
    let out = dir.join("rust");
    let exp = dir.join("expected");
    fs::create_dir_all(&out).unwrap();
    fs::create_dir_all(&exp).unwrap();
    let mut names: Vec<PathBuf> = fs::read_dir(dir.join("inputs")).unwrap().map(|e| e.unwrap().path()).collect();
    names.sort();
    for p in names {
        let input: Input = serde_json::from_str(&fs::read_to_string(&p).unwrap()).unwrap();
        let (name, file, bytes, mut e) = match input {
            Input::Run { name, profile_id, table_id, value_size, epsilon, entries } => {
                let cfg = Config { profile_id: h32(&profile_id), table_id, value_size, epsilon };
                let es: Vec<Entry> = entries
                    .iter()
                    .map(|e| Entry { key: h32(&e.key), tag: e.tag, value: hex::decode(&e.value).unwrap() })
                    .collect();
                let (bytes, built) = write_all(cfg, &es).unwrap_or_else(|err| panic!("{name}: {err}"));
                let e = Expected {
                    name: name.clone(),
                    file: format!("{name}.run"),
                    bytes: 0,
                    blake3: String::new(),
                    root: Some(hex::encode(built.root)),
                    model_root: Some(hex::encode(built.model_root)),
                    page_count: Some(built.page_count),
                    depth: Some(built.layout.depth),
                    segments: Some(built.model.segments.len()),
                    model_bytes: Some(built.layout.model_bytes as usize),
                    manifest_root: None,
                    signing_message: None,
                };
                (name.clone(), format!("{name}.run"), bytes, e)
            }
            Input::Manifest { name, chain_id, profile_id, block_number, block_hash, rebuild_block, base, delta } => {
                let m = Manifest {
                    format_version: 1,
                    chain_id,
                    profile_id: h32(&profile_id),
                    block_number,
                    block_hash: h32(&block_hash),
                    rebuild_block,
                    base: base.as_ref().map(to_run_ref),
                    delta: delta.as_ref().map(to_run_ref),
                };
                let bytes = m.encode();
                assert_eq!(Manifest::decode(&bytes).unwrap(), m);
                let e = Expected {
                    name: name.clone(),
                    file: format!("{name}.bin"),
                    bytes: 0,
                    blake3: String::new(),
                    root: None,
                    model_root: None,
                    page_count: None,
                    depth: None,
                    segments: None,
                    model_bytes: None,
                    manifest_root: Some(hex::encode(m.root())),
                    signing_message: None,
                };
                (name.clone(), format!("{name}.bin"), bytes, e)
            }
            Input::ColdRoot { name, signing_key, chain_id, profile_id, height, block_hash, manifest_root } => {
                let key = SigningKey::from_bytes(&h32(&signing_key));
                let c = ColdRoot {
                    chain_id,
                    profile_id: h32(&profile_id),
                    height,
                    block_hash: h32(&block_hash),
                    manifest_root: h32(&manifest_root),
                    signature: [0; 64],
                }
                .sign(&key);
                assert!(c.verify(&key.verifying_key()));
                let bytes = c.encode();
                let e = Expected {
                    name: name.clone(),
                    file: format!("{name}.bin"),
                    bytes: 0,
                    blake3: String::new(),
                    root: None,
                    model_root: None,
                    page_count: None,
                    depth: None,
                    segments: None,
                    model_bytes: None,
                    manifest_root: None,
                    signing_message: Some(hex::encode(c.signing_message())),
                };
                (name.clone(), format!("{name}.bin"), bytes, e)
            }
        };
        e.bytes = bytes.len() as u64;
        e.blake3 = hex::encode(blake3::hash(&bytes).as_bytes());
        fs::write(out.join(&file), &bytes).unwrap();
        fs::write(exp.join(format!("{name}.json")), serde_json::to_string_pretty(&e).unwrap()).unwrap();
        eprintln!("{name}: {} bytes, blake3 {}", e.bytes, &e.blake3[..16]);
    }
}

fn main() {
    match Args::parse().cmd {
        Cmd::MakeInputs { dir } => make_inputs(&dir),
        Cmd::Gen { dir } => gen(&dir),
    }
}
