//! The variable layout without inline proofs (core §3.2, Ethereum profile
//! §1): greedy packing, blob entries, blake3-of-file identity, and a reader
//! that parses pages for shape but verifies nothing.

use csl_run::{write_all_with, Config, Entry, EntryLayout, Error, Format, Lookup, Reader, RunHeader, KEY, KEY_MAX, MAX_INLINE_VALUE, PAGE};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::BTreeMap;

fn cfg(eps: u16) -> Config {
    Config { profile_id: [8; 32], table_id: 1, value_size: 0, epsilon: eps }
}

/// Values between 1 and `max` bytes, every tenth a tombstone, every
/// thirteenth a blob reference.
fn dataset(n: usize, seed: u64, max: usize) -> Vec<Entry> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut m: BTreeMap<[u8; KEY], Entry> = BTreeMap::new();
    while m.len() < n {
        let k: [u8; KEY] = rng.random();
        let i = m.len();
        let e = if i % 10 == 3 {
            Entry::tombstone(k)
        } else if i % 13 == 5 {
            Entry::blob(k, rng.random())
        } else {
            let len = rng.random_range(1..=max);
            Entry::value(k, (0..len).map(|_| rng.random()).collect())
        };
        m.insert(k, e);
    }
    m.into_values().collect()
}

fn check(es: &[Entry], eps: u16) -> (Vec<u8>, csl_run::Built) {
    let (bytes, built) = write_all_with(cfg(eps), Format::variable(), es).unwrap();
    assert_eq!(bytes.len() as u64, built.layout.total_len);
    assert_eq!(bytes.len() % PAGE, 0);
    assert_eq!(built.layout.depth, 0);
    assert_eq!(built.layout.record_bytes, PAGE as u64);
    assert!(!built.layout.inline_proofs);
    assert_eq!(built.root, *blake3::hash(&bytes).as_bytes(), "identity is blake3 of the file");
    let h = RunHeader::decode(&bytes).unwrap();
    assert_eq!((h.page_count, h.entry_count, h.epsilon_pages), (built.page_count, es.len() as u64, eps));

    let rref = built.run_ref(0, 0, eps);
    let mut r = Reader::with_format(bytes.clone(), rref, Format::variable());
    for e in es {
        let (got, _) = r.get_entry(&e.key).unwrap();
        assert_eq!(got.as_ref(), Some(e));
        let (res, _) = r.get(&e.key).unwrap();
        match e.tag {
            1 => assert_eq!(res, Lookup::Tombstone),
            _ => assert_eq!(res, Lookup::Found(e.value.clone())),
        }
    }
    let mut rng = ChaCha8Rng::seed_from_u64(99);
    for _ in 0..200 {
        let k: [u8; KEY] = rng.random();
        if es.iter().any(|e| e.key == k) {
            continue;
        }
        assert_eq!(r.get(&k).unwrap().0, Lookup::Absent);
    }
    assert_eq!(r.get(&[0u8; KEY]).unwrap().0, Lookup::Absent);
    if !es.iter().any(|e| e.key == KEY_MAX) {
        assert_eq!(r.get(&KEY_MAX).unwrap().0, Lookup::Absent);
    }

    // Packing is greedy: no page could take the first entry of the next.
    let mut total_entries = 0;
    for i in 1..=built.page_count {
        let p = r.fetch_page(i).unwrap();
        total_entries += p.entries.len();
        if i < built.page_count {
            let next = r.fetch_page(i + 1).unwrap();
            assert_eq!(p.hi, next.lo);
            assert_eq!(next.lo, next.entries[0].key, "fence is the next page's first key");
            let bytes: usize = p.entries.iter().chain(next.entries.first()).map(|e| e.encoded_len(EntryLayout::Variable)).sum();
            assert!(!csl_run::page::variable_fits(p.entries.len() + 1, bytes), "page {i} left room for the next entry");
        }
    }
    assert_eq!(total_entries, es.len());
    (bytes, built)
}

#[test]
fn write_read_every_key_at_several_sizes_and_shapes() {
    for (n, eps, max) in [(1usize, 1u16, 100usize), (2, 1, 1000), (100, 1, 1024), (1000, 1, 300), (1000, 4, 1024), (3000, 2, 64), (500, 1, MAX_INLINE_VALUE)] {
        let es = dataset(n, n as u64 + max as u64, max);
        check(&es, eps);
    }
}

#[test]
fn deterministic_bytes() {
    let es = dataset(400, 1, 500);
    let (a, _) = write_all_with(cfg(1), Format::variable(), &es).unwrap();
    let (b, _) = write_all_with(cfg(1), Format::variable(), &es).unwrap();
    assert_eq!(a, b);
}

#[test]
fn one_entry_per_page_when_values_are_maximal() {
    let mut es = dataset(5, 2, 1);
    for e in &mut es {
        *e = Entry::value(e.key, vec![3; MAX_INLINE_VALUE]);
    }
    let (_, built) = check(&es, 1);
    assert_eq!(built.page_count, 5);
}

#[test]
fn max_key_on_last_page() {
    let mut es = dataset(99, 5, 200);
    es.push(Entry::blob(KEY_MAX, [9; 32]));
    es.sort_by_key(|e| e.key);
    let (bytes, built) = check(&es, 1);
    let mut r = Reader::with_format(bytes, built.run_ref(0, 0, 1), Format::variable());
    let (e, _) = r.get_entry(&KEY_MAX).unwrap();
    assert_eq!(e, Some(Entry::blob(KEY_MAX, [9; 32])));
}

#[test]
fn writer_rejects_bad_input_and_proofs() {
    let es = dataset(10, 3, 50);
    let v = Format::variable();
    let mut big = es.clone();
    big[0] = Entry::value(big[0].key, vec![0; MAX_INLINE_VALUE + 1]);
    assert!(matches!(write_all_with(cfg(1), v, &big), Err(Error::BadValueLen { .. })));
    let mut hash = es.clone();
    hash[1] = Entry { key: hash[1].key, tag: 2, value: vec![0; 31] };
    assert!(matches!(write_all_with(cfg(1), v, &hash), Err(Error::BadValueLen { expected: 32, got: 31 })));
    let mut tag = es.clone();
    tag[2].tag = 3;
    assert!(matches!(write_all_with(cfg(1), v, &tag), Err(Error::BadTag(3))));
    // Variable with proofs is not a format the writer streams.
    let with_proofs = Format { layout: EntryLayout::Variable, inline_proofs: true, paged_model: false };
    assert!(matches!(write_all_with(cfg(1), with_proofs, &es), Err(Error::Layout(_))));
    // Blob entries have no place in the fixed layout.
    let (bytes, _) = write_all_with(cfg(1), v, &es).unwrap();
    assert!(bytes.len() > PAGE);
    assert!(matches!(csl_run::write_all(Config { value_size: 24, ..cfg(1) }, &[Entry::blob([1; 32], [0; 32])]), Err(Error::BadTag(2))));
}

#[test]
fn no_proofs_means_no_verification_but_shape_is_still_checked() {
    let es = dataset(300, 4, 400);
    let (bytes, built) = check(&es, 1);
    let rref = built.run_ref(0, 0, 1);
    let layout = built.layout;
    // A flipped value byte on page 2 is not caught: pages are routing data.
    let mut r = Reader::with_format(bytes.clone(), rref, Format::variable());
    let p2 = r.fetch_page(2).unwrap();
    let j = p2.entries.iter().position(|e| e.tag == 0).unwrap();
    let rec = layout.record_off(2) as usize;
    let entry_off = u16::from_le_bytes(bytes[rec + 66 + 2 * j..rec + 66 + 2 * j + 2].try_into().unwrap()) as usize;
    let mut b = bytes.clone();
    b[rec + entry_off + 32 + 1 + 2] ^= 1;
    let mut r = Reader::with_format(b, rref, Format::variable());
    let tampered = r.fetch_page(2).unwrap();
    assert_ne!(tampered.entries[j].value, p2.entries[j].value);
    // A broken offset table is.
    let mut b = bytes.clone();
    b[layout.record_off(2) as usize + 68] ^= 1;
    let mut r = Reader::with_format(b, rref, Format::variable());
    assert!(matches!(r.fetch_page(2), Err(Error::MalformedPage { page: 2, what: "offsets" })));
    // The model is still bound to its root.
    let mut b = bytes.clone();
    b[layout.model_off as usize + 4] ^= 1;
    let mut r = Reader::with_format(b, rref, Format::variable());
    assert!(matches!(r.load_model(), Err(Error::ModelMismatch)));
    // Reading a variable run as fixed fails on shape.
    let mut r = Reader::new(bytes, rref, 24);
    assert!(r.fetch_page(1).is_err());
}

#[test]
fn shared_prefix_group_within_bound_builds_and_beyond_aborts() {
    // Values of 500 bytes: 7 entries per page. 21 entries under one k64
    // prefix span 3 pages at ε = 1 (2ε + 1): fine. 22 span 4: abort.
    let mk = |n: usize| -> Vec<Entry> {
        let mut rng = ChaCha8Rng::seed_from_u64(8);
        let mut m: BTreeMap<[u8; KEY], Entry> = BTreeMap::new();
        while m.len() < n {
            let mut k: [u8; KEY] = rng.random();
            k[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            m.insert(k, Entry::value(k, vec![0; 500]));
        }
        m.into_values().collect()
    };
    assert!(write_all_with(cfg(1), Format::variable(), &mk(21)).is_ok());
    assert!(matches!(write_all_with(cfg(1), Format::variable(), &mk(22)), Err(Error::Fit(pgm::FitError::Unrepresentable(_)))));
    assert!(write_all_with(cfg(2), Format::variable(), &mk(22)).is_ok());
}
