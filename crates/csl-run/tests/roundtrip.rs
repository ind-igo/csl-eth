use csl_run::{write_all, Config, Entry, Error, Lookup, Reader, RunHeader, KEY, KEY_MAX, PAGE};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::collections::BTreeMap;

fn cfg(eps: u16) -> Config {
    Config { profile_id: [7; 32], table_id: 0, value_size: 24, epsilon: eps }
}

fn dataset(n: usize, seed: u64, tomb_every: usize) -> Vec<Entry> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let mut m: BTreeMap<[u8; KEY], Entry> = BTreeMap::new();
    while m.len() < n {
        let k: [u8; KEY] = rng.random();
        let e = if tomb_every > 0 && m.len().is_multiple_of(tomb_every) { Entry::tombstone(k) } else { Entry::value(k, (0..24).map(|_| rng.random()).collect()) };
        m.insert(k, e);
    }
    m.into_values().collect()
}

#[test]
fn write_read_every_key_every_size() {
    for (n, eps) in [(1usize, 1u16), (70, 1), (71, 1), (210, 2), (1000, 1), (1000, 4), (5000, 1)] {
        let es = dataset(n, n as u64, 5);
        let (bytes, built) = write_all(cfg(eps), &es).unwrap();
        assert_eq!(bytes.len() as u64, built.layout.total_len);
        assert_eq!(bytes.len() % PAGE, 0);
        let h = RunHeader::decode(&bytes).unwrap();
        assert_eq!((h.page_count, h.entry_count, h.epsilon_pages), (built.page_count, n as u64, eps));

        let rref = built.run_ref(0, 10, eps);
        let mut r = Reader::new(bytes.clone(), rref, 24);
        for e in &es {
            let (res, _) = r.get(&e.key).unwrap();
            match e.tag {
                0 => assert_eq!(res, Lookup::Found(e.value.clone())),
                _ => assert_eq!(res, Lookup::Tombstone),
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
        // Boundaries of the key space.
        assert_eq!(r.get(&[0u8; KEY]).unwrap().0, Lookup::Absent);
        assert_eq!(r.get(&KEY_MAX).unwrap().0, Lookup::Absent);
        assert!(r.stats.max_requests_one_lookup <= 2 * eps as u64 + 2 + (64 - (built.page_count - 1).leading_zeros()) as u64 + 2);
    }
}

#[test]
fn deterministic_bytes() {
    let es = dataset(500, 1, 3);
    let (a, _) = write_all(cfg(1), &es).unwrap();
    let (b, _) = write_all(cfg(1), &es).unwrap();
    assert_eq!(a, b);
}

#[test]
fn max_key_on_last_page() {
    let mut es = dataset(99, 5, 0);
    es.push(Entry::value(KEY_MAX, vec![9; 24]));
    es.sort_by_key(|e| e.key);
    let (bytes, built) = write_all(cfg(1), &es).unwrap();
    let mut r = Reader::new(bytes, built.run_ref(0, 0, 1), 24);
    assert_eq!(r.get(&KEY_MAX).unwrap().0, Lookup::Found(vec![9; 24]));
}

#[test]
fn corruption_is_rejected() {
    let es = dataset(300, 2, 0);
    let (bytes, built) = write_all(cfg(1), &es).unwrap();
    let rref = built.run_ref(0, 0, 1);
    let layout = built.layout;

    // A flipped byte inside page 2.
    let mut b = bytes.clone();
    b[layout.record_off(2) as usize + 100] ^= 1;
    let mut r = Reader::new(b, rref, 24);
    assert!(matches!(r.fetch_page(2), Err(Error::ProofFailed { page: 2 })));
    assert!(r.fetch_page(1).is_ok());

    // A flipped byte inside page 3's proof.
    let mut b = bytes.clone();
    b[(layout.record_off(3) + PAGE as u64) as usize] ^= 1;
    let mut r = Reader::new(b, rref, 24);
    assert!(matches!(r.fetch_page(3), Err(Error::ProofFailed { page: 3 })));

    // Page 1's record served at page 2's offset (position binding).
    let mut b = bytes.clone();
    let rb = layout.record_bytes as usize;
    let p1 = b[layout.record_off(1) as usize..layout.record_off(1) as usize + rb].to_vec();
    b[layout.record_off(2) as usize..layout.record_off(2) as usize + rb].copy_from_slice(&p1);
    let mut r = Reader::new(b, rref, 24);
    assert!(matches!(r.fetch_page(2), Err(Error::ProofFailed { page: 2 })));

    // Model section altered.
    let mut b = bytes.clone();
    b[layout.model_off as usize + 4] ^= 1;
    let mut r = Reader::new(b, rref, 24);
    assert!(matches!(r.load_model(), Err(Error::ModelMismatch)));

    // Wrong root in the RunRef.
    let mut bad = rref;
    bad.root[0] ^= 1;
    let mut r = Reader::new(bytes.clone(), bad, 24);
    assert!(matches!(r.fetch_page(1), Err(Error::ProofFailed { page: 1 })));
}

#[test]
fn writer_rejects_bad_input() {
    let es = dataset(10, 3, 0);
    let mut rev = es.clone();
    rev.reverse();
    assert!(matches!(write_all(cfg(1), &rev), Err(Error::Unsorted { .. })));
    let mut dup = es.clone();
    dup.push(es[0].clone());
    dup.sort_by_key(|e| e.key);
    assert!(matches!(write_all(cfg(1), &dup), Err(Error::Unsorted { .. })));
    let mut short = es.clone();
    short[0].value.pop();
    assert!(matches!(write_all(cfg(1), &short), Err(Error::BadValueLen { .. })));
    let mut tag = es.clone();
    tag[0].tag = 2;
    assert!(matches!(write_all(cfg(1), &tag), Err(Error::BadTag(2))));
}

#[test]
fn shared_prefix_group_within_bound_builds_and_beyond_aborts() {
    // 3 pages under one prefix at ε = 1 is 2ε + 1: fine. 4 pages: abort.
    let mut rng = ChaCha8Rng::seed_from_u64(8);
    let mk = |n: usize, rng: &mut ChaCha8Rng| -> Vec<Entry> {
        let mut m: BTreeMap<[u8; KEY], Entry> = BTreeMap::new();
        while m.len() < n {
            let mut k: [u8; KEY] = rng.random();
            k[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
            m.insert(k, Entry::value(k, vec![0; 24]));
        }
        m.into_values().collect()
    };
    assert!(write_all(cfg(1), &mk(210, &mut rng)).is_ok());
    assert!(matches!(write_all(cfg(1), &mk(211, &mut rng)), Err(Error::Fit(pgm::FitError::Unrepresentable(_)))));
    assert!(write_all(cfg(2), &mk(211, &mut rng)).is_ok());
}

#[test]
fn unused_proof_slot_in_a_three_page_run_is_rejected() {
    // 150 entries at 70 per page: three pages, depth 2. Page 3 is the
    // unpaired last leaf at level 0, so its record uses one proof slot and
    // the second must be zero (v1-min §2).
    let es = dataset(150, 11, 0);
    let (bytes, built) = write_all(cfg(1), &es).unwrap();
    assert_eq!((built.page_count, built.layout.depth), (3, 2));
    let rref = built.run_ref(0, 0, 1);
    let layout = built.layout;
    let slot2 = (layout.record_off(3) + PAGE as u64 + 32) as usize;
    assert!(bytes[slot2..slot2 + 32].iter().all(|b| *b == 0), "the writer zeroes the unused slot");
    let mut b = bytes.clone();
    b[slot2 + 7] = 0x5a;
    let mut r = Reader::new(b, rref, 24);
    assert!(matches!(r.fetch_page(3), Err(Error::ProofFailed { page: 3 })));
    assert!(r.fetch_page(1).is_ok() && r.fetch_page(2).is_ok());
}

/// A source that returns fewer bytes than asked, as a misbehaving custom
/// `Source` might.
struct Short(Vec<u8>, usize);

impl csl_run::Source for Short {
    fn read_at(&self, off: u64, len: usize) -> Result<Vec<u8>, Error> {
        let start = off as usize;
        let end = (start + len).min(self.0.len());
        Ok(self.0[start..end.saturating_sub(self.1).max(start)].to_vec())
    }
}

#[test]
fn short_reads_are_errors_not_panics() {
    let es = dataset(300, 12, 0);
    let (bytes, built) = write_all(cfg(1), &es).unwrap();
    let rref = built.run_ref(0, 0, 1);
    // A custom source one byte short of every request.
    let mut r = Reader::new(Short(bytes.clone(), 1), rref, 24);
    assert!(matches!(r.fetch_page(1), Err(Error::ShortRead { .. })));
    assert!(matches!(r.load_model(), Err(Error::ShortRead { .. })));
    assert!(r.get(&[7u8; KEY]).is_err());
    // A source returning nothing at all.
    let mut r = Reader::new(Short(bytes.clone(), usize::MAX), rref, 24);
    assert!(matches!(r.fetch_page(2), Err(Error::ShortRead { got: 0, .. })));
    // The Vec source: a truncated file, and an offset past usize on any target.
    let mut r = Reader::new(bytes[..bytes.len() / 2].to_vec(), rref, 24);
    assert!(matches!(r.fetch_page(built.page_count), Err(Error::ShortRead { .. })));
    use csl_run::Source;
    assert!(matches!(bytes.read_at(u64::MAX, 1), Err(Error::ShortRead { .. })));
    assert!(matches!(bytes.read_at(u64::MAX - 1, 4096), Err(Error::ShortRead { .. })));
}

#[test]
fn bad_run_refs_and_page_indexes_are_errors_not_panics() {
    let es = dataset(300, 13, 0);
    let (bytes, built) = write_all(cfg(1), &es).unwrap();
    let rref = built.run_ref(0, 0, 1);
    let mut r = Reader::new(bytes.clone(), rref, 24);
    assert!(matches!(r.fetch_page(0), Err(Error::PageOutOfRange { page: 0, .. })));
    assert!(matches!(r.fetch_page(built.page_count + 1), Err(Error::PageOutOfRange { .. })));
    // Zero pages and more than 2^31 pages give no layout: try_new refuses,
    // new builds a reader whose every read is an error.
    for pc in [0u64, (1 << 31) + 1, u64::MAX] {
        let bad = csl_run::RunRef { page_count: pc, ..rref };
        assert!(matches!(Reader::try_new(bytes.clone(), bad, 24), Err(Error::Layout(_))), "{pc}");
        let mut r = Reader::new(bytes.clone(), bad, 24);
        assert!(r.layout().is_none());
        assert!(matches!(r.fetch_page(1), Err(Error::Layout(_))));
        assert!(matches!(r.load_model(), Err(Error::Layout(_))));
        assert!(r.get(&[1u8; KEY]).is_err());
    }
    // A model decoded for a different (valid) page count is rejected by its
    // root, never reaching predict.
    let bad = csl_run::RunRef { page_count: built.page_count + 1, ..rref };
    let mut r = Reader::new(bytes, bad, 24);
    assert!(r.get(&[1u8; KEY]).is_err());
}

#[test]
fn layout_arithmetic_is_checked() {
    use csl_run::Layout;
    assert!(matches!(Layout::try_new(0, 0), Err(Error::Layout(_))));
    assert!(matches!(Layout::try_new((1 << 31) + 1, 0), Err(Error::Layout(_))));
    assert!(matches!(Layout::try_new(1, u64::MAX), Err(Error::Layout(_))));
    assert!(matches!(Layout::try_new(1, u64::MAX - 4096), Err(Error::Layout(_))));
    // The largest run v1-min allows: 2^31 pages, depth 31, every offset in u64.
    let l = Layout::try_new(1 << 31, u64::from(u32::MAX)).unwrap();
    assert_eq!(l.depth, 31);
    assert_eq!(l.record_bytes, 4096 + 32 * 31);
    assert_eq!(l.model_off, 4096 + (1u64 << 31) * l.record_bytes);
    assert!(l.total_len >= l.model_off + u64::from(u32::MAX) && l.total_len % 4096 == 0);
    assert_eq!(l.checked_record_off(0), None);
    assert_eq!(l.checked_record_off((1 << 31) + 1), None);
    assert_eq!(l.checked_record_off(1 << 31), Some(4096 + ((1u64 << 31) - 1) * l.record_bytes));
    assert_eq!(Layout::try_new(3, 100).unwrap(), Layout::new(3, 100));
}
