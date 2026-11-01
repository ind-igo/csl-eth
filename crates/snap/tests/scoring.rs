//! Controls for the scorers: shown a wrong expectation, the workload and
//! the fault table must count it as the failure it is. These fail if a
//! scorer accepted everything.

mod common;

use alloy_primitives::U256;
use csl_eth_client::{DirDriver, Hint, Snapshot};
use csl_eth_snap::faults::{self, run_table_plan, Fault, Mode, Options};
use csl_eth_snap::workload::{self, plan, run_mode, Expect, Plan, Sizes, Target};
use csl_eth_trie::AbsentBy;

fn sizes() -> Sizes {
    Sizes {
        accounts: 60,
        absent: 60,
        slots: 60,
        absent_slots: 60,
        outside: 0,
        d_account: csl_eth_store::D_ACCOUNT,
        d_storage: csl_eth_store::D_STORAGE,
    }
}

/// Indices of draws matching `f`, in plan order.
fn find(p: &Plan, f: impl Fn(&Target, &Expect) -> bool) -> Vec<usize> {
    (0..p.draws.len())
        .filter(|i| f(&p.draws[*i].target, &p.draws[*i].expect))
        .collect()
}

/// Six wrong expectations and two wrong shape predictions planted in a
/// clean plan: three wrong values (account, slot, code), a present key
/// expected absent, an absent key expected present, an inside key
/// expected outside, an absence of the wrong kind, a node count off by
/// one.
fn planted(p: &mut Plan) {
    let present = find(p, |t, e| {
        matches!(t, Target::Account(_)) && matches!(e, Expect::Account(_))
    });
    let absent = find(p, |t, e| {
        matches!(t, Target::Account(_)) && matches!(e, Expect::Absent(AbsentBy::EmptySlot))
    });
    let slot = find(p, |_, e| matches!(e, Expect::Slot(_)))[0];
    let code = find(p, |_, e| matches!(e, Expect::Code(_)))[0];
    assert!(present.len() >= 4 && absent.len() >= 2);

    let Expect::Account(mut a) = p.draws[present[0]].expect.clone() else {
        unreachable!()
    };
    let real = a;
    a.balance += U256::from(1);
    p.draws[present[0]].expect = Expect::Account(a);
    if let Expect::Slot(v) = &mut p.draws[slot].expect {
        *v += U256::from(1);
    }
    if let Expect::Code(len) = &mut p.draws[code].expect {
        *len += 1;
    }
    p.draws[present[1]].expect = Expect::Absent(AbsentBy::EmptySlot);
    p.draws[present[2]].expect = Expect::Insufficient;
    p.draws[absent[0]].expect = Expect::Account(real);
    p.draws[absent[1]].expect = Expect::Absent(AbsentBy::LeafMismatch);
    p.draws[present[3]].nodes += 1;
}

#[test]
fn the_workload_scorer_counts_every_planted_error() {
    let w = common::whole(800, 21);
    let dir = w.produce("workload");
    let mut p = plan(&w.slice, &sizes(), 5).unwrap();
    // The clean plan passes; the planted one fails by exactly the plants.
    for (planted_errors, baseline) in [(false, false), (true, false), (true, true)] {
        if planted_errors && !baseline {
            planted(&mut p);
        }
        let mut snap = Snapshot::open(DirDriver::new(&dir), None, w.head.state_root).unwrap();
        snap.hint = Hint::symmetric(1);
        let sc = run_mode(&p, &w.slice, &mut snap, baseline);
        if !planted_errors {
            assert!(!sc.failed(), "{}", sc.to_json());
            continue;
        }
        let j = sc.to_json();
        assert!(sc.failed());
        assert_eq!(sc.wrong_values, 3, "{j}");
        assert_eq!(sc.false_present, 1, "{j}");
        assert_eq!(sc.false_absent, 1, "{j}");
        assert_eq!(
            sc.unexpected, 1,
            "an inside key answered where Insufficient was due: {j}"
        );
        assert_eq!(sc.shape_mismatch, 2, "{j}");
        assert_eq!(sc.ok, sc.reads - 6);
    }
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn the_fault_table_scorer_counts_every_planted_error() {
    let w = common::whole(800, 22);
    let dir = w.produce("faults");
    let mut p = faults::plan_for(&w.slice, 40, 1).unwrap();
    planted(&mut p);
    let o = Options {
        mode: Mode::Both,
        faults: vec![Fault::None, Fault::NodeOmitted],
        ..Options::default()
    };
    let t = run_table_plan(&w.slice, &dir, &p, &o).unwrap();
    assert!(!t.pass);
    assert!(!t.control_correct);
    let none = t.row("none").unwrap();
    assert!(!none.pass());
    let path = none.mode("path").unwrap().total;
    assert_eq!(
        (
            path.wrong_value,
            path.false_present,
            path.false_absent,
            path.outside_answered,
            path.shape_mismatch
        ),
        (3, 1, 1, 1, 2),
        "{path:?}"
    );
    // The baseline reads no code (the read is the same in both modes).
    let base = none.mode("baseline").unwrap().total;
    assert_eq!(
        (
            base.wrong_value,
            base.false_present,
            base.false_absent,
            base.outside_answered,
            base.shape_mismatch
        ),
        (2, 1, 1, 1, 2),
        "{base:?}"
    );
    assert_eq!(
        t.failures.iter().filter(|f| f.fault == "none").count(),
        8 + 7
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// The commands fail (after writing their reports) when the slice does
/// not describe the bucket: here every account's balance is off by one.
#[test]
fn both_commands_fail_on_a_slice_that_disagrees_with_the_bucket() {
    let mut w = common::whole(400, 23);
    let dir = w.produce("bucket");
    for (_, a) in w.slice.accounts.iter_mut() {
        a.balance += U256::from(1);
    }
    let slice_dir = common::scratch("slice");
    w.slice.write(&slice_dir).unwrap();

    let out = slice_dir.join("faults.json");
    let r = faults::run(faults::Args {
        slice: slice_dir.clone(),
        bucket: dir.clone(),
        out: out.clone(),
        keys: 20,
        rate: 1.0,
        seed: 1,
        mode: Mode::Path,
        top_levels: 0,
        faults: vec!["node_omitted".into()],
    });
    assert!(r.is_err(), "{r:?}");
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(report["pass"], false);
    assert_eq!(report["control_correct"], false);

    let out = slice_dir.join("workload.json");
    let r = workload::run(workload::Args {
        slice: slice_dir.clone(),
        bucket: Some(dir.clone()),
        url: None,
        proxy: None,
        checkpoint: None,
        out: out.clone(),
        mode: Mode::Path,
        accounts: 20,
        absent: 20,
        slots: 20,
        absent_slots: 20,
        outside: 0,
        seed: 1,
        prefetch: 1,
        top_levels: 4,
        d_account: None,
        d_storage: None,
        oracle: None,
        oracle_samples: 0,
        oracle_blocks: 300,
    });
    assert!(r.is_err(), "{r:?}");
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(report["pass"], false);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&slice_dir).ok();
}
