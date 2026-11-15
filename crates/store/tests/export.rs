//! The streaming export against the in-memory producer: for the same state
//! every file and the manifest are byte for byte the same, whatever the
//! memory budget; every failure aborts before a manifest or `latest`.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{HashBuilder, KECCAK_EMPTY};
use csl_eth_store::{
    export, extsort, manifest_path, produce_with, AccountLeaf, CodeIter, ExportError, ExportOptions, ExportPhase, ExportStats, Head, ProduceOptions, SourceAccount, StateSource, VecSource,
    CODE_BLOB_THRESHOLD, LATEST_FILE, TABLE_ACCOUNT_NODES, TABLE_CODE, TABLE_FILES, TABLE_NODES_BY_HASH, TABLE_STORAGE_NODES,
};
use csl_eth_trie::{encode_word, path_of, Account};
use rand::{Rng, RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::{Path, PathBuf},
    time::Duration,
};

struct World {
    accounts: Vec<AccountLeaf>,
    code: HashMap<B256, Vec<u8>>,
    head: Head,
}

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

fn random_slots(rng: &mut ChaCha8Rng, n: usize) -> Vec<(B256, U256)> {
    let mut m = BTreeMap::new();
    while m.len() < n {
        let mut s = [0u8; 32];
        rng.fill_bytes(&mut s);
        // Small words too, so some leaves are short.
        let w = if rng.random_bool(0.3) { U256::from(rng.random_range(1u64..256)) } else { U256::from(rng.random::<u128>()) | U256::from(1) };
        m.insert(B256::from(s), w);
    }
    m.into_iter().collect()
}

fn with_roots(mut accounts: Vec<AccountLeaf>) -> Vec<AccountLeaf> {
    for a in &mut accounts {
        a.account.storage_root = storage_root(&a.storage);
    }
    accounts
}

fn head_for(accounts: &[AccountLeaf], tag: u8) -> Head {
    Head { block_hash: B256::repeat_byte(tag), block_number: 24_400_000 + tag as u64, timestamp: 1_761_800_000, state_root: state_root(accounts) }
}

/// `n` accounts: zero, one or many slots, one with `big` slots, a crafted
/// pair of slots under a long shared prefix (short, embedded leaves), code
/// shared between accounts, inline and above the blob threshold, and
/// accounts without code.
fn world(n: usize, big: usize, seed: u64) -> World {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut pool: Vec<B256> = Vec::new();
    let mut code = HashMap::new();
    for i in 0..12 {
        let len = if i % 3 == 0 { rng.random_range(CODE_BLOB_THRESHOLD + 1..=24_576) } else { rng.random_range(1..=3000) };
        let mut c = vec![0u8; len];
        rng.fill_bytes(&mut c);
        let h = keccak256(&c);
        code.insert(h, c);
        pool.push(h);
    }
    // A code at exactly the threshold stays inline.
    let c = vec![0x5Bu8; CODE_BLOB_THRESHOLD];
    let h = keccak256(&c);
    code.insert(h, c);
    pool.push(h);

    let mut by_key: BTreeMap<B256, AccountLeaf> = BTreeMap::new();
    let mut i = 0usize;
    while by_key.len() < n {
        let mut h = [0u8; 32];
        rng.fill_bytes(&mut h);
        let storage = match i {
            0 => random_slots(&mut rng, big),
            1 => {
                // Two slots sharing 60 nibbles.
                let mut a = [0x44u8; 32];
                let mut b = [0x44u8; 32];
                a[30] = 0x10;
                b[30] = 0x70;
                vec![(B256::from(a), U256::from(1)), (B256::from(b), U256::from(2))]
            }
            _ => match rng.random_range(0..10) {
                0..=3 => Vec::new(),
                4..=5 => random_slots(&mut rng, 1),
                6..=8 => {
                    let k = rng.random_range(2..60);
                    random_slots(&mut rng, k)
                }
                _ => {
                    let k = rng.random_range(60..400);
                    random_slots(&mut rng, k)
                }
            },
        };
        let code_hash = if rng.random_bool(0.4) { pool[rng.random_range(0..pool.len())] } else { KECCAK_EMPTY };
        let account = Account { nonce: rng.random_range(0..1000), balance: U256::from(rng.random::<u64>()), storage_root: B256::ZERO, code_hash };
        by_key.insert(B256::from(h), AccountLeaf { hashed: B256::from(h), account, storage });
        i += 1;
    }
    // A code no account references: the export must not write it.
    let c = vec![0xEEu8; 77];
    code.insert(keccak256(&c), c);
    let accounts = with_roots(by_key.into_values().collect());
    let head = head_for(&accounts, 0xAB);
    World { accounts, code, head }
}

fn scratch(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "csl-eth-export-{}-{}-{name}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Every regular file under `root`, by relative path.
fn files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let e = e.unwrap();
            let p = e.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.insert(p.strip_prefix(base).unwrap().to_string_lossy().into_owned(), std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        walk(root, root, &mut out);
    }
    out
}

fn assert_same_files(a: &BTreeMap<String, Vec<u8>>, b: &BTreeMap<String, Vec<u8>>) {
    let ka: Vec<&String> = a.keys().collect();
    let kb: Vec<&String> = b.keys().collect();
    assert_eq!(ka, kb, "the same files");
    for (k, v) in a {
        assert!(v == &b[k], "{k} differs ({} and {} bytes)", v.len(), b[k].len());
    }
}

fn opts(scratch: &Path, memory: u64) -> ExportOptions {
    let mut o = ExportOptions::new(scratch);
    o.memory_bytes = memory;
    o.progress_every = Duration::ZERO;
    o
}

fn no_scratch_left(parent: &Path) {
    let left: Vec<_> = std::fs::read_dir(parent).map(|rd| rd.flatten().map(|e| e.file_name()).filter(|n| n.to_string_lossy().starts_with(extsort::SCRATCH_PREFIX)).collect()).unwrap_or_default();
    assert!(left.is_empty(), "scratch left behind: {left:?}");
}

/// Export `w` from `src` and produce it the in-memory way; compare.
fn compare<S: StateSource>(w: &World, src: &S, memory: u64, by_hash: bool, name: &str) -> ExportStats {
    let base = scratch(name);
    let (a, b, tmp) = (base.join("produce"), base.join("export"), base.join("tmp"));
    let produced = produce_with(&a, &w.head, "", w.accounts.iter().cloned(), &w.code, ProduceOptions::default()).unwrap();
    let mut o = opts(&tmp, memory);
    o.by_hash = by_hash;
    let mut phases = Vec::new();
    let exported = export(&b, &w.head, src, &o, &mut |s: &ExportStats| {
        if phases.last() != Some(&s.phase) {
            phases.push(s.phase);
        }
    })
    .unwrap();
    no_scratch_left(&tmp);

    let st = &exported.stats;
    let ps = &produced.stats;
    assert_eq!((st.accounts, st.storage_slots, st.storage_tries), (ps.accounts, ps.storage_slots, ps.storage_tries));
    assert_eq!((st.account_nodes, st.storage_nodes, st.embedded), (ps.account_nodes, ps.storage_nodes, ps.embedded));
    assert_eq!((st.code_entries, st.code_blobs), (ps.code_entries, ps.code_blobs));
    let mut want = vec![ExportPhase::Build, ExportPhase::Sort, ExportPhase::CheckCode];
    for t in [TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES, TABLE_NODES_BY_HASH, TABLE_CODE] {
        if produced.manifest.table(t).is_some() && (by_hash || t != TABLE_NODES_BY_HASH) {
            want.push(ExportPhase::Write(t));
        }
    }
    want.push(ExportPhase::Done);
    assert_eq!(phases, want);

    let (fa, fb) = (files(&a), files(&b));
    if by_hash {
        assert_eq!(exported.manifest, produced.manifest);
        assert_same_files(&fa, &fb);
        assert_eq!(st.tables, ps.tables);
    } else {
        let mut m = produced.manifest.clone();
        m.tables.retain(|t| t.table_id != TABLE_NODES_BY_HASH);
        assert_eq!(exported.manifest, m);
        assert!(exported.manifest.table(TABLE_NODES_BY_HASH).is_none());
        let by_hash_file = format!("{}/{}", csl_eth_store::snapshot_dir(&w.head.block_hash), TABLE_FILES[TABLE_NODES_BY_HASH as usize]);
        let manifest_file = manifest_path(&w.head.block_hash);
        let strip = |f: &BTreeMap<String, Vec<u8>>| -> BTreeMap<String, Vec<u8>> { f.iter().filter(|(k, _)| **k != by_hash_file && **k != manifest_file).map(|(k, v)| (k.clone(), v.clone())).collect() };
        assert!(fa.contains_key(&by_hash_file) && !fb.contains_key(&by_hash_file));
        assert_same_files(&strip(&fa), &strip(&fb));
    }
    std::fs::remove_dir_all(&base).unwrap();
    exported.stats
}

#[test]
fn matches_produce_with_byte_for_byte() {
    for seed in 1..=3u64 {
        let w = world(400, 5000, seed);
        let st = compare(&w, &VecSource::new(&w.accounts, &w.code), 1 << 30, true, "same");
        assert_eq!(st.spill_bytes(), 0, "a large budget never spills");
        assert_eq!(st.largest_storage.0, 5000);
        assert!(st.code_blobs > 0 && st.code_entries > st.code_blobs);
    }
}

#[test]
fn matches_under_a_tiny_budget_with_multi_pass_merges() {
    let w = world(300, 6000, 9);
    let st = compare(&w, &VecSource::new(&w.accounts, &w.code), 48 << 10, true, "tiny");
    eprintln!("tiny budget: {:?}", st.sort);
    for t in [TABLE_ACCOUNT_NODES, TABLE_STORAGE_NODES, TABLE_NODES_BY_HASH] {
        let s = &st.sort[t as usize];
        assert!(s.spills > 2 && s.merge_passes > 0, "table {t}: {s:?}");
    }
    assert!(st.peak_sort_bytes <= 48 << 10, "the chunk within the budget: {}", st.peak_sort_bytes);
    // A middling budget: spills, one merge.
    let st = compare(&w, &VecSource::new(&w.accounts, &w.code), 1 << 20, true, "mid");
    assert!(st.spill_bytes() > 0);
}

#[test]
fn ordered_code_stream_gives_the_same_files() {
    let w = world(300, 2000, 5);
    let mut src = VecSource::new(&w.accounts, &w.code);
    src.ordered_code = true;
    compare(&w, &src, 1 << 30, true, "ordered");
    compare(&w, &src, 64 << 10, true, "ordered-tiny");
}

#[test]
fn without_by_hash_the_other_files_are_unchanged() {
    let w = world(300, 3000, 6);
    compare(&w, &VecSource::new(&w.accounts, &w.code), 1 << 30, false, "nobyhash");
    compare(&w, &VecSource::new(&w.accounts, &w.code), 48 << 10, false, "nobyhash-tiny");
}

#[test]
fn re_exporting_a_block_without_by_hash_removes_the_old_baseline() {
    let w = world(100, 500, 8);
    let base = scratch("reexport");
    let (root, tmp) = (base.join("root"), base.join("tmp"));
    let by_hash_file = root.join(csl_eth_store::table_path(&w.head.block_hash, TABLE_NODES_BY_HASH));
    let src = VecSource::new(&w.accounts, &w.code);
    let first = export(&root, &w.head, &src, &opts(&tmp, 1 << 20), &mut |_| {}).unwrap();
    assert!(first.manifest.table(TABLE_NODES_BY_HASH).is_some() && by_hash_file.exists());
    let mut o = opts(&tmp, 1 << 20);
    o.by_hash = false;
    let second = export(&root, &w.head, &src, &o, &mut |_| {}).unwrap();
    assert!(second.manifest.table(TABLE_NODES_BY_HASH).is_none() && !by_hash_file.exists());
    let on_disk = csl_eth_store::Manifest::from_json(&std::fs::read(root.join(manifest_path(&w.head.block_hash))).unwrap()).unwrap();
    assert_eq!(on_disk, second.manifest);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn edge_states_match() {
    // One account, no storage, no code: a single-leaf account trie, one table.
    let one = with_roots(vec![AccountLeaf {
        hashed: B256::repeat_byte(0x12),
        account: Account { nonce: 1, balance: U256::from(5), storage_root: B256::ZERO, code_hash: KECCAK_EMPTY },
        storage: Vec::new(),
    }]);
    let w = World { head: head_for(&one, 1), accounts: one, code: HashMap::new() };
    let st = compare(&w, &VecSource::new(&w.accounts, &w.code), 1 << 20, true, "one");
    assert_eq!(st.code_entries, 0);
    // A single account whose one slot makes a single-leaf storage trie.
    let mut one = w.accounts.clone();
    one[0].storage = vec![(B256::repeat_byte(3), U256::from(9))];
    let one = with_roots(one);
    let w = World { head: head_for(&one, 2), accounts: one, code: HashMap::new() };
    compare(&w, &VecSource::new(&w.accounts, &w.code), 1 << 20, true, "one-slot");
}

// --- aborts ---

#[derive(Debug)]
struct Boom(&'static str);

impl fmt::Display for Boom {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "boom: {}", self.0)
    }
}

impl std::error::Error for Boom {}

/// A source that fails where it is told to.
struct Faulty<'a> {
    inner: VecSource<'a>,
    /// Fail at this account index instead of yielding it.
    account_at: Option<usize>,
    /// Fail at this slot index of this account.
    slot_at: Option<(B256, usize)>,
    /// Fail opening this account's storage.
    storage_open: Option<B256>,
    /// Fail looking this code up.
    code: Option<B256>,
}

impl<'a> Faulty<'a> {
    fn new(inner: VecSource<'a>) -> Faulty<'a> {
        Faulty { inner, account_at: None, slot_at: None, storage_open: None, code: None }
    }
}

impl StateSource for Faulty<'_> {
    type Error = Boom;
    type Accounts<'b>
        = Box<dyn Iterator<Item = Result<SourceAccount, Boom>> + 'b>
    where
        Self: 'b;
    type Storage<'b>
        = Box<dyn Iterator<Item = Result<(B256, U256), Boom>> + 'b>
    where
        Self: 'b;

    fn accounts(&self) -> Result<Self::Accounts<'_>, Boom> {
        let at = self.account_at;
        Ok(Box::new(self.inner.accounts().unwrap().enumerate().map(move |(i, a)| if Some(i) == at { Err(Boom("accounts")) } else { Ok(a.unwrap()) })))
    }

    fn storage(&self, hashed: &B256) -> Result<Self::Storage<'_>, Boom> {
        if self.storage_open == Some(*hashed) {
            return Err(Boom("open storage"));
        }
        let at = self.slot_at.filter(|(h, _)| h == hashed).map(|(_, i)| i);
        Ok(Box::new(self.inner.storage(hashed).unwrap().enumerate().map(move |(i, s)| if Some(i) == at { Err(Boom("slots")) } else { Ok(s.unwrap()) })))
    }

    fn code(&self, code_hash: &B256) -> Result<Option<Vec<u8>>, Boom> {
        if self.code == Some(*code_hash) {
            return Err(Boom("code"));
        }
        Ok(self.inner.code(code_hash).unwrap())
    }

    fn codes(&self) -> Option<Result<CodeIter<'_, Boom>, Boom>> {
        None
    }
}

/// Export into a root that already holds a good snapshot; the failure must
/// leave it untouched: no manifest for the new block, `latest` unchanged,
/// no files of the new snapshot, no scratch.
fn assert_aborts<S: StateSource>(name: &str, head: &Head, src: &S, memory: u64, check: impl Fn(&ExportError) -> bool) {
    let base = scratch(name);
    let (root, tmp) = (base.join("root"), base.join("tmp"));
    let good = world(20, 10, 99);
    let good_head = Head { block_hash: B256::repeat_byte(0x99), ..good.head };
    export(&root, &good_head, &VecSource::new(&good.accounts, &good.code), &opts(&tmp, 1 << 20), &mut |_| {}).unwrap();
    let before = files(&root);
    assert!(before.contains_key(LATEST_FILE));
    assert_ne!(head.block_hash, good_head.block_hash);

    let r = export(&root, head, src, &opts(&tmp, memory), &mut |_| {});
    let e = r.err().unwrap_or_else(|| panic!("{name}: the export must fail"));
    assert!(check(&e), "{name}: unexpected error {e}");
    eprintln!("{name}: {e}");
    assert!(!root.join(manifest_path(&head.block_hash)).exists());
    assert_same_files(&before, &files(&root));
    no_scratch_left(&tmp);
    std::fs::remove_dir_all(&base).unwrap();
}

#[test]
fn aborts_write_no_manifest_and_leave_latest() {
    let w = world(200, 3000, 21);
    let head = w.head;
    let vs = || VecSource::new(&w.accounts, &w.code);
    for memory in [1 << 30, 32 << 10] {
        // Wrong state root.
        let mut bad = head;
        bad.state_root = B256::repeat_byte(7);
        assert_aborts("root", &bad, &vs(), memory, |e| matches!(e, ExportError::StateRoot { expected, got } if *expected == bad.state_root && *got == head.state_root));

        // A referenced code missing, and one hashing differently.
        let used = w.accounts.iter().find(|a| a.account.code_hash != KECCAK_EMPTY).unwrap().account.code_hash;
        let mut code = w.code.clone();
        code.remove(&used);
        assert_aborts("no-code", &head, &VecSource::new(&w.accounts, &code), memory, |e| matches!(e, ExportError::Code { hash, what: "no bytecode" } if *hash == used));
        let mut src = VecSource::new(&w.accounts, &code);
        src.ordered_code = true;
        assert_aborts("no-code-ordered", &head, &src, memory, |e| matches!(e, ExportError::Code { hash, .. } if *hash == used));
        let mut code = w.code.clone();
        code.get_mut(&used).unwrap()[0] ^= 1;
        assert_aborts("code-hash", &head, &VecSource::new(&w.accounts, &code), memory, |e| matches!(e, ExportError::Code { what: "bytecode hashes differently", .. }));

        // Accounts out of order, and a repeated account.
        let mut acc = w.accounts.clone();
        acc.swap(50, 51);
        assert_aborts("unsorted-accounts", &head, &VecSource::new(&acc, &w.code), memory, |e| matches!(e, ExportError::UnsortedAccounts { .. }));
        let mut acc = w.accounts.clone();
        acc.insert(60, acc[60].clone());
        assert_aborts("repeated-account", &head, &VecSource::new(&acc, &w.code), memory, |e| matches!(e, ExportError::UnsortedAccounts { prev, next } if prev == next));

        // Slots out of order, repeated, and a zero word.
        let big = w.accounts.iter().position(|a| a.storage.len() > 100).unwrap();
        let mut acc = w.accounts.clone();
        acc[big].storage.swap(70, 71);
        assert_aborts("unsorted-slots", &head, &VecSource::new(&acc, &w.code), memory, |e| matches!(e, ExportError::UnsortedSlots { owner, .. } if *owner == w.accounts[big].hashed));
        let mut acc = w.accounts.clone();
        let s = acc[big].storage[80];
        acc[big].storage.insert(80, s);
        assert_aborts("repeated-slot", &head, &VecSource::new(&acc, &w.code), memory, |e| matches!(e, ExportError::UnsortedSlots { .. }));
        let mut acc = w.accounts.clone();
        acc[big].storage[5].1 = U256::ZERO;
        assert_aborts("zero-slot", &head, &VecSource::new(&acc, &w.code), memory, |e| matches!(e, ExportError::ZeroSlot { .. }));

        // A truncated slot stream (the source lost the end of a trie
        // without saying so): only the state root can tell.
        let mut acc = w.accounts.clone();
        acc[big].storage.truncate(10);
        assert_aborts("truncated-slots", &head, &VecSource::new(&acc, &w.code), memory, |e| matches!(e, ExportError::StateRoot { .. }));

        // Source errors mid-stream: accounts, opening storage, within the
        // big trie, a code lookup.
        let source_err = |during: &'static str| move |e: &ExportError| matches!(e, ExportError::Source { during: d, .. } if d.starts_with(during));
        let mut f = Faulty::new(vs());
        f.account_at = Some(150);
        assert_aborts("err-accounts", &head, &f, memory, source_err("accounts"));
        let mut f = Faulty::new(vs());
        f.storage_open = Some(w.accounts[100].hashed);
        assert_aborts("err-open-storage", &head, &f, memory, source_err("storage of"));
        let mut f = Faulty::new(vs());
        f.slot_at = Some((w.accounts[big].hashed, 90));
        assert_aborts("err-slots", &head, &f, memory, source_err("storage of"));
        let mut f = Faulty::new(vs());
        f.code = Some(used);
        assert_aborts("err-code", &head, &f, memory, source_err("code"));
    }
}

#[test]
fn stale_scratch_is_cleared() {
    let parent = scratch("stale");
    std::fs::create_dir_all(parent.join(format!("{}123-456", extsort::SCRATCH_PREFIX))).unwrap();
    assert_eq!(extsort::remove_stale(&parent), 1);
    no_scratch_left(&parent);
    std::fs::remove_dir_all(&parent).unwrap();
}

#[test]
fn a_large_storage_trie_reports_progress_while_it_builds() {
    let mut rng = ChaCha8Rng::seed_from_u64(4);
    let accounts = with_roots(vec![AccountLeaf {
        hashed: B256::repeat_byte(0x77),
        account: Account { nonce: 1, balance: U256::from(1), storage_root: B256::ZERO, code_hash: KECCAK_EMPTY },
        storage: random_slots(&mut rng, 70_000),
    }]);
    let head = head_for(&accounts, 3);
    let base = scratch("progress");
    let code = HashMap::new();
    let mut seen = Vec::new();
    export(&base.join("root"), &head, &VecSource::new(&accounts, &code), &opts(&base.join("tmp"), 1 << 20), &mut |s: &ExportStats| {
        if s.building.1 > 0 {
            seen.push(s.building);
        }
    })
    .unwrap();
    assert_eq!(seen, vec![(accounts[0].hashed, 65_536)]);
    std::fs::remove_dir_all(&base).unwrap();
}
