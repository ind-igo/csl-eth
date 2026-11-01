//! The workload and the fault table on a prefix slice, as milestone 1
//! reads mainnet: the boundary proof supplies the branches above the
//! prefix (the shape model's `below`), keys outside it end at a sealed
//! subtree and must be `Insufficient`, and the shape model must still
//! predict every walk inside.

mod common;

use csl_eth_client::{DirDriver, Hint, Snapshot};
use csl_eth_snap::faults::{plan_for, run_table_plan, Fault, Mode, Options};
use csl_eth_snap::workload::{plan, run_mode, Expect, Sizes};

#[test]
fn the_workload_scores_a_prefix_slice_and_its_outside() {
    let w = common::prefix(4000, 11);
    assert!(w.slice.accounts.len() > 200, "{}", w.slice.accounts.len());
    assert!(!w.slice.boundary.is_empty());
    let dir = w.produce("workload");
    let sizes = Sizes {
        accounts: 150,
        absent: 150,
        slots: 150,
        absent_slots: 150,
        outside: 60,
        d_account: csl_eth_store::D_ACCOUNT,
        d_storage: csl_eth_store::D_STORAGE,
    };
    let p = plan(&w.slice, &sizes, 3).unwrap();
    eprintln!("plan: {}", p.meta);
    let outside = p
        .draws
        .iter()
        .filter(|d| matches!(d.expect, Expect::Insufficient))
        .count();
    assert_eq!(outside, 60, "outside keys drawn");
    assert_eq!(p.meta["drawn"]["outside"], outside);
    common::drawn_as_requested(&p.meta);
    for baseline in [false, true] {
        let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
        snap.hint = Hint::symmetric(1);
        snap.top_levels = 4;
        let sc = run_mode(&p, &w.slice, &mut snap, baseline);
        eprintln!(
            "{}: {} reads, series {:?}",
            sc.mode,
            sc.reads,
            sc.series_names()
        );
        assert!(!sc.failed(), "{}", sc.to_json());
        assert_eq!(sc.ok, sc.reads);
        assert_eq!(sc.shape_mismatch, 0, "{}", sc.to_json()["shape_mismatches"]);
        assert_eq!(
            sc.count("outside"),
            outside,
            "every outside key Insufficient(Missing)"
        );
        for name in [
            "account_present",
            "account_absent",
            "account_absent_empty_slot",
            "account_absent_leaf_mismatch",
            "storage_present",
            "storage_absent",
            "storage_empty_trie",
            "storage_absent_account",
            "code",
        ] {
            assert!(sc.count(name) > 0, "{}: shape {name} is empty", sc.mode);
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_fault_table_passes_on_a_prefix_slice_with_outside_keys() {
    let w = common::prefix(3000, 12);
    let dir = w.produce("faults");
    let o = Options {
        keys: 30,
        mode: Mode::Both,
        faults: Fault::ALL.to_vec(),
        ..Options::default()
    };
    let p = plan_for(&w.slice, o.keys, o.seed).unwrap();
    let blobs = p
        .draws
        .iter()
        .filter(|d| d.series.iter().any(|s| s == "code_blob"))
        .count();
    eprintln!("{blobs} blob-sized codes drawn");
    common::drawn_as_requested(&p.meta);
    let t = run_table_plan(&w.slice, &dir, &p, &o).unwrap();
    for f in &t.failures {
        eprintln!("failure: {f:?}");
    }
    assert!(t.safe && t.control_correct, "{:?}", t.failures);
    assert!(t.exercised, "not exercised: {:?}", t.not_exercised);
    assert!(t.pass);
    // `truncated_blob` cuts blob files: the baseline reads no code, and
    // neither mode fetches a blob when the plan drew no blob-sized code.
    // Those (fault, mode) pairs are not applicable, said so in the table;
    // every other pair applies and was exercised.
    let blob = t.row("truncated_blob").unwrap();
    let base = blob.mode("baseline").unwrap();
    assert!(base.not_applicable.is_some() && base.faulted == 0);
    let path = blob.mode("path").unwrap();
    if blobs == 0 {
        assert!(path.not_applicable.is_some() && path.faulted == 0);
    } else {
        assert!(path.not_applicable.is_none() && path.exercised && path.faulted > 0);
    }
    let n_a = if blobs == 0 { 2 } else { 1 };
    assert_eq!(
        t.not_applicable.len(),
        n_a,
        "{blobs} blobs: {:?}",
        t.not_applicable
    );
    assert!(t
        .not_applicable
        .iter()
        .all(|s| s.starts_with("truncated_blob ")));
    let n = t.shapes.get("outside").copied().unwrap_or(0);
    assert!(n > 0, "{:?}", t.shapes);
    let none = t.row("none").unwrap();
    for m in ["path", "baseline"] {
        let c = none.counts(m, "outside").unwrap();
        assert_eq!((c.reads, c.correct), (n as u64, n as u64), "{m}");
    }
    for r in &t.faults {
        assert_eq!(r.total.outside_answered, 0, "{}", r.name);
        assert_eq!(r.total.shape_mismatch, 0, "{}", r.name);
    }
    std::fs::remove_dir_all(&dir).ok();
}
