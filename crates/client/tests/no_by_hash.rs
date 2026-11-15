//! A full-state export may omit the content-addressed baseline table
//! (`nodes_by_hash`). The client must open such a snapshot, serve every
//! path-keyed read as before, and answer the baseline's reads
//! `Insufficient(NoTable(3))` rather than fail or panic.

use alloy_primitives::{keccak256, B256, U256};
use alloy_trie::{HashBuilder, KECCAK_EMPTY};
use csl_eth_client::{DirDriver, Read, Reason, Snapshot};
use csl_eth_store::{export, AccountLeaf, ExportOptions, Head, VecSource, TABLE_NODES_BY_HASH};
use csl_eth_trie::{encode_word, path_of, Account};
use std::collections::HashMap;

#[test]
fn a_snapshot_without_nodes_by_hash_serves_path_reads_and_refuses_baseline_reads() {
    let mut accounts = Vec::new();
    let code = vec![0x60u8, 0x00, 0x56];
    let code_hash = keccak256(&code);
    for i in 0u8..60 {
        let mut h = [i.wrapping_mul(97); 32];
        h[0] = i.wrapping_mul(4);
        let storage: Vec<(B256, U256)> = if i % 3 == 0 { (1u8..=20).map(|j| (keccak256([i, j]), U256::from(j as u64 * 1000 + i as u64))).collect() } else { Vec::new() };
        let mut storage = storage;
        storage.sort();
        let mut hb = HashBuilder::default();
        for (k, v) in &storage {
            hb.add_leaf(path_of(k), &encode_word(v));
        }
        let account = Account { nonce: i as u64, balance: U256::from(i as u64 + 1), storage_root: hb.root(), code_hash: if i % 4 == 1 { code_hash } else { KECCAK_EMPTY } };
        accounts.push(AccountLeaf { hashed: B256::from(h), account, storage });
    }
    accounts.sort_by_key(|a| a.hashed);
    accounts.dedup_by_key(|a| a.hashed);
    let mut hb = HashBuilder::default();
    for a in &accounts {
        hb.add_leaf(path_of(&a.hashed), &a.account.encode());
    }
    let head = Head { block_hash: B256::repeat_byte(0xCD), block_number: 1, timestamp: 2, state_root: hb.root() };
    let codes: HashMap<B256, Vec<u8>> = [(code_hash, code.clone())].into();

    let base = std::env::temp_dir().join(format!("csl-eth-nobyhash-{}", std::process::id()));
    let mut opts = ExportOptions::new(base.join("tmp"));
    opts.by_hash = false;
    let out = export(&base.join("root"), &head, &VecSource::new(&accounts, &codes), &opts, &mut |_| {}).unwrap();
    assert!(out.manifest.table(TABLE_NODES_BY_HASH).is_none());

    let mut snap = Snapshot::open(DirDriver::new(base.join("root")), None, head.state_root).unwrap();
    for a in &accounts {
        assert_eq!(snap.account(&a.hashed).0, Read::Verified(a.account));
        for (k, v) in &a.storage {
            assert_eq!(snap.storage(&a.hashed, k).0, Read::Verified(*v));
        }
        let (r, _) = snap.account_by_hash(&a.hashed);
        assert_eq!(r, Read::Insufficient(Reason::NoTable(TABLE_NODES_BY_HASH)));
        if let Some((k, _)) = a.storage.first() {
            let (r, _) = snap.storage_by_hash(&a.hashed, k);
            assert_eq!(r, Read::Insufficient(Reason::NoTable(TABLE_NODES_BY_HASH)));
        }
    }
    assert_eq!(snap.code(&code_hash).0, Read::Verified(code));
    // Absence is still proven by path.
    assert!(matches!(snap.account(&B256::repeat_byte(0xFE)).0, Read::VerifiedAbsent(_)));
    // The table listing says why table 3 is missing.
    let t3 = snap.tables().into_iter().find(|t| t.table_id == TABLE_NODES_BY_HASH).unwrap();
    assert_eq!((t3.page_count, t3.error.as_deref()), (0, Some("snapshot has no table 3")));
    std::fs::remove_dir_all(&base).unwrap();
}
