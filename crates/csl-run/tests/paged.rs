//! The paged model section (core §4.1): page 0 carries the top model and
//! the tree root, model pages carry the segments under `bmt` proofs, and a
//! lookup routes through one model page. Both layouts, many model pages,
//! fences chained, requests counted, and every tamper rejected.

use csl_run::{tree::verify_inline, write_all_with, Config, Entry, Error, Format, Lookup, ModelPage, Path, Reader, Top, DIGEST, KEY, KEY_MAX, MODEL_PAGE_SEGMENTS, PAGE, TOP_MAX_SEGMENTS};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::BTreeMap;

fn cfg(eps: u16, value_size: u32) -> Config {
    Config {
        profile_id: [9; 32],
        table_id: 2,
        value_size,
        epsilon: eps,
    }
}

fn dataset(n: usize, seed: u64, value_len: usize) -> Vec<Entry> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut m: BTreeMap<[u8; KEY], Entry> = BTreeMap::new();
    while m.len() < n {
        let k: [u8; KEY] = rng.random();
        let v: Vec<u8> = (0..value_len).map(|_| rng.random()).collect();
        m.insert(k, Entry::value(k, v));
    }
    m.into_values().collect()
}

/// Model pages decoded straight from the file, proofs checked, fences
/// chained, segments equal to the whole model's.
fn model_pages_of(bytes: &[u8], built: &csl_run::Built) -> Vec<ModelPage> {
    let top = Top::decode(&bytes[..PAGE]).unwrap();
    assert_eq!(top.model_pages, built.model_pages);
    assert_eq!(Some(&top.model), built.top.as_ref());
    assert!(top.model.segments.len() <= TOP_MAX_SEGMENTS);
    let depth = csl_run::tree::depth(top.model_pages);
    let record = PAGE + DIGEST * depth;
    assert_eq!(built.layout.model_bytes, (top.model_pages as usize * record) as u64);
    let mut pages = Vec::new();
    let mut all = Vec::new();
    for m in 1..=top.model_pages {
        let off = built.layout.model_off as usize + (m as usize - 1) * record;
        let (page, proof) = bytes[off..off + record].split_at(PAGE);
        let digest = *blake3::hash(page).as_bytes();
        assert!(verify_inline(top.model_pages, (m - 1) as u32, &digest, proof, &top.tree_root), "model page {m} proof");
        let mp = ModelPage::decode(page, built.page_count, m, m == top.model_pages).unwrap();
        if m == 1 {
            assert_eq!(mp.lo, 0);
        } else {
            let prev: &ModelPage = pages.last().unwrap();
            assert_eq!(prev.hi, mp.lo, "fences chain");
            assert_eq!(mp.lo, mp.segments[0].key_start);
            assert_eq!(prev.next_intercept, mp.segments[0].intercept);
        }
        if m < top.model_pages {
            assert_eq!(mp.segments.len(), MODEL_PAGE_SEGMENTS, "every page but the last is full");
        } else {
            assert_eq!(mp.hi, u64::MAX);
            assert_eq!(mp.next_intercept, built.page_count as i64);
        }
        all.extend(mp.segments.iter().copied());
        pages.push(mp);
    }
    assert_eq!(all, built.model.segments, "the pages are the model");
    pages
}

fn check(es: &[Entry], format: Format, eps: u16) -> (Vec<u8>, csl_run::Built) {
    let vs = es[0].value.len() as u32;
    let (bytes, built) = write_all_with(cfg(eps, vs), format, es).unwrap();
    assert!(built.model_pages >= 1);
    assert_eq!(built.model_root, *blake3::hash(&bytes[..PAGE]).as_bytes(), "model_root is page 0");
    let pages = model_pages_of(&bytes, &built);
    assert_eq!(pages.len() as u64, built.model_pages);

    let rref = built.run_ref(0, 0, eps);
    let mut r = Reader::with_format(bytes.clone(), rref, format);
    assert!(matches!(r.load_model(), Err(Error::Layout(_))), "no whole model to load");
    r.prepare().unwrap();
    assert_eq!(r.stats.model_requests, 1, "prepare reads page 0");
    for e in es {
        let before = r.stats.model_requests;
        let (res, path) = r.get(&e.key).unwrap();
        assert_eq!(res, Lookup::Found(e.value.clone()));
        assert!(!matches!(path, Path::Fallback(_)), "fallback on honest data");
        assert!(r.stats.model_requests - before <= 1 + u64::from(built.top.as_ref().unwrap().epsilon) + 1, "model pages per lookup");
    }
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    for _ in 0..200 {
        let k: [u8; KEY] = rng.random();
        if es.iter().any(|e| e.key == k) {
            continue;
        }
        assert_eq!(r.get(&k).unwrap().0, Lookup::Absent);
    }
    assert_eq!(r.get(&[0u8; KEY]).unwrap().0, Lookup::Absent);
    assert_eq!(r.get(&KEY_MAX).unwrap().0, Lookup::Absent);
    // Every model page is kept once read: a second pass costs no model request.
    let after_first = r.stats.model_requests;
    for e in es {
        r.get(&e.key).unwrap();
    }
    assert_eq!(r.stats.model_requests, after_first, "model pages are cached");
    assert!(after_first <= 1 + built.model_pages, "no model page is read twice");
    (bytes, built)
}

#[test]
fn paged_variable_layout_reads_every_key() {
    for (n, eps) in [(1usize, 1u16), (2, 1), (300, 1), (3000, 1), (3000, 4)] {
        let es = dataset(n, n as u64, 40);
        let (_, built) = check(&es, Format::variable().paged(), eps);
        assert_eq!(built.model_pages, 1, "a small run has one model page");
    }
}

#[test]
fn many_model_pages_in_both_layouts() {
    // ε = 0 on random keys closes a segment every few dozen groups, so a
    // run of 150,000 small entries has a couple of thousand segments and
    // more than ten model pages.
    let es = dataset(150_000, 20, 8);
    let (_, built) = check(&es, Format::variable().paged(), 0);
    assert!(built.model_pages > 5, "variable: {} model pages", built.model_pages);
    let (_, built) = check(&es, Format::fixed(8).paged(), 0);
    assert!(built.model_pages > 5, "fixed: {} model pages", built.model_pages);
    assert!(built.layout.inline_proofs);
}

#[test]
fn deterministic_bytes() {
    let es = dataset(2000, 3, 16);
    let (a, _) = write_all_with(cfg(1, 16), Format::variable().paged(), &es).unwrap();
    let (b, _) = write_all_with(cfg(1, 16), Format::variable().paged(), &es).unwrap();
    assert_eq!(a, b);
    let (c, _) = write_all_with(cfg(1, 16), Format::variable(), &es).unwrap();
    assert_ne!(a, c, "paging changes the file");
}

#[test]
fn whole_and_paged_models_agree() {
    let es = dataset(5000, 5, 8);
    let (bytes, whole) = write_all_with(cfg(1, 8), Format::variable(), &es).unwrap();
    let (pbytes, paged) = write_all_with(cfg(1, 8), Format::variable().paged(), &es).unwrap();
    assert_eq!(whole.model, paged.model, "same fit");
    assert_eq!(whole.page_count, paged.page_count);
    assert_eq!(&bytes[PAGE..whole.layout.model_off as usize], &pbytes[PAGE..paged.layout.model_off as usize], "same pages");
    let mut rw = Reader::with_format(bytes, whole.run_ref(0, 0, 1), Format::variable());
    let mut rp = Reader::with_format(pbytes, paged.run_ref(0, 0, 1), Format::variable().paged());
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    for _ in 0..500 {
        let k: u64 = rng.random();
        assert_eq!(rw.predict_page(k).unwrap(), rp.predict_page(k).unwrap(), "same prediction for {k:#x}");
    }
}

#[test]
fn tampering_is_rejected_never_misrouted_silently() {
    let es = dataset(150_000, 21, 8);
    let (bytes, built) = write_all_with(cfg(0, 8), Format::variable().paged(), &es).unwrap();
    assert!(built.model_pages > 3);
    let format = Format::variable().paged();
    let rref = built.run_ref(0, 0, 0);
    let top = Top::decode(&bytes[..PAGE]).unwrap();
    let record = PAGE + DIGEST * csl_run::tree::depth(top.model_pages);

    // Page 0: any byte, header included, breaks model_root.
    for off in [0usize, 60, 100, PAGE - 1] {
        let mut b = bytes.clone();
        b[off] ^= 1;
        let mut r = Reader::with_format(b, rref, format);
        assert!(matches!(r.prepare(), Err(Error::ModelMismatch)), "page 0 byte {off}");
    }
    // A wrong model_root.
    let mut bad = rref;
    bad.model_root[0] ^= 1;
    let mut r = Reader::with_format(bytes.clone(), bad, format);
    assert!(matches!(r.prepare(), Err(Error::ModelMismatch)));
    // A model_bytes that is not the page count's.
    let mut bad = rref;
    bad.model_bytes -= 1;
    let mut r = Reader::with_format(bytes.clone(), bad, format);
    assert!(matches!(r.prepare(), Err(Error::ModelMismatch)));

    // A model page: a flipped segment byte fails its proof; a flipped
    // proof byte too. Every key that routes there is an error, not a page.
    let m = 3u64;
    let off = built.layout.model_off as usize + (m as usize - 1) * record;
    for delta in [40usize, PAGE + 5] {
        let mut b = bytes.clone();
        b[off + delta] ^= 0x10;
        let mut r = Reader::with_format(b, rref, format);
        r.prepare().unwrap();
        let mut hit = 0;
        for e in es.iter().step_by(7) {
            match r.get(&e.key) {
                Ok((Lookup::Found(v), _)) => assert_eq!(v, e.value),
                Ok(other) => panic!("{other:?}"),
                Err(Error::ModelMismatch) => hit += 1,
                Err(e) => panic!("{e}"),
            }
        }
        assert!(hit > 0, "some key routes through model page {m}");
    }
}

#[test]
fn model_page_shape_is_checked() {
    let page = ModelPage {
        lo: 0,
        hi: 100,
        next_intercept: 5,
        segments: vec![pgm::Segment {
            key_start: 10,
            intercept: 2,
            slope: 7,
        }],
    };
    let bytes = page.encode();
    assert_eq!(ModelPage::decode(&bytes, 10, 1, false).unwrap(), page);
    let bad = |f: &dyn Fn(&mut [u8])| {
        let mut b = bytes;
        f(&mut b);
        ModelPage::decode(&b, 10, 1, false).is_err()
    };
    assert!(bad(&|b| b[0] = 0), "zero segments");
    assert!(bad(&|b| b[0] = 200), "too many segments");
    assert!(bad(&|b| b[2] = 1), "first page not from zero");
    assert!(bad(&|b| b[10..18].copy_from_slice(&0u64.to_le_bytes())), "fences out of order");
    assert!(bad(&|b| b[18..26].copy_from_slice(&11i64.to_le_bytes())), "next intercept beyond the run");
    assert!(bad(&|b| b[26..34].copy_from_slice(&100u64.to_le_bytes())), "segment beyond hi");
    assert!(bad(&|b| b[34..42].copy_from_slice(&0i64.to_le_bytes())), "intercept 0");
    assert!(bad(&|b| b[PAGE - 1] = 1), "padding");
    assert!(ModelPage::decode(&bytes, 10, 1, true).is_err(), "last page must end at the maximum");
    let routing = page.routing(10, 1);
    assert_eq!(routing.segments.len(), 2);
    assert_eq!(routing.predict(0), 2);
    assert_eq!(routing.predict(99), 2);
}
