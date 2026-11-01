//! The fault table over synthetic buckets: every named fault applied to
//! the responses, the workload's shapes read under it through both
//! clients, and the table passes (no wrong value, no false absence) with
//! each aimed fault caught in the table and trie it was aimed at.

mod common;

use csl_eth_snap::faults::{run_table, Fault, Mode, Options, Row, Table};

fn print(t: &Table) {
    for r in &t.faults {
        for (m, mr) in &r.modes {
            eprintln!(
                "{:<20} {m:<8} open_error={:?} faulted={} reads={} correct={} insufficient={} failures={} untargeted={} coverage={:?} reasons={:?}",
                r.name,
                mr.open_error,
                mr.faulted,
                mr.total.reads,
                mr.total.correct,
                mr.total.insufficient,
                mr.total.failures(),
                mr.untargeted,
                mr.coverage,
                mr.reasons
            );
        }
    }
    for f in &t.failures {
        eprintln!("failure: {f:?}");
    }
}

/// A reason containing `needle` was seen under `mode`.
fn caught(r: &Row, mode: &str, needle: &str) {
    let mr = r.mode(mode).unwrap();
    assert!(
        mr.total.insufficient > 0,
        "{} {mode}: nothing insufficient",
        r.name
    );
    assert!(
        mr.reasons.keys().any(|k| k.contains(needle)),
        "{} {mode}: expected a {needle} reason, saw {:?}",
        r.name,
        mr.reasons
    );
}

/// The aimed node's (table, trie, depth) labels seen under `mode`.
fn covered(r: &Row, mode: &str, prefix: &str) -> usize {
    r.mode(mode)
        .unwrap()
        .coverage
        .keys()
        .filter(|k| k.starts_with(prefix))
        .count()
}

#[test]
fn every_fault_is_caught_where_it_was_aimed_and_none_becomes_a_false_answer() {
    let w = common::whole(900, 2);
    let dir = w.produce("table");
    let o = Options {
        keys: 40,
        rate: 1.0,
        seed: 1,
        mode: Mode::Both,
        top_levels: 0,
        faults: Fault::ALL.to_vec(),
    };
    let t = run_table(&w.slice, &dir, &o).unwrap();
    print(&t);
    assert!(t.safe, "a fault produced a wrong value or a false absence");
    assert!(t.control_correct);
    assert!(t.failures.is_empty(), "{:?}", t.failures);
    assert!(t.exercised, "not exercised: {:?}", t.not_exercised);
    assert!(t.pass);
    // The one (fault, mode) that cannot apply: the baseline reads no code.
    assert_eq!(t.not_applicable.len(), 1, "{:?}", t.not_applicable);
    assert!(
        t.not_applicable[0].starts_with("truncated_blob baseline: "),
        "{:?}",
        t.not_applicable
    );
    assert_eq!(t.faults.len(), Fault::ALL.len());
    // Every kind is drawn to its size: forced picks never cost a draw.
    common::drawn_as_requested(&t.plan);
    for s in ["account_present", "account_absent", "storage_present"] {
        assert_eq!(t.shapes[s], 40, "{s}: {:?}", t.shapes);
    }
    for s in [
        "account_absent",
        "storage_absent",
        "storage_empty_trie",
        "storage_absent_account",
        "code",
    ] {
        assert!(
            t.shapes.get(s).is_some_and(|n| *n > 0),
            "no {s} reads: {:?}",
            t.shapes
        );
    }
    assert!(
        !t.shapes.contains_key("outside"),
        "a whole-trie slice has no outside"
    );

    // The control row: every read right, through both clients.
    let none = t.row("none").unwrap();
    assert_eq!(none.total.insufficient, 0);
    assert_eq!(none.total.correct, none.total.reads);
    assert_eq!(none.faulted, 0);
    assert_eq!(
        none.counts("baseline", "account_present").unwrap().correct as usize,
        t.shapes["account_present"]
    );

    // Every row that opened made the same reads.
    for r in &t.faults {
        for (m, mr) in &r.modes {
            if mr.open_error.is_none() {
                assert_eq!(
                    mr.total.reads,
                    none.mode(m).unwrap().total.reads,
                    "{} {m}",
                    r.name
                );
            }
        }
    }

    // Aimed faults: almost every read is aimed (`forged_fence` needs a
    // node the model mispredicts and `fence_gap` a page whose fences are
    // not already tight, and aim past nodes without), almost every aim
    // lands, the aims reach every storage depth in the path mode and the
    // hash-keyed table in the baseline, and the catch is in that table.
    for f in Fault::ALL.iter().filter(|f| f.aimed()) {
        let r = t.row(f.name()).unwrap();
        for m in ["path", "baseline"] {
            let mr = r.mode(m).unwrap();
            let landed: u64 = mr.coverage.values().sum();
            assert_eq!(landed + mr.untargeted, mr.total.reads, "{} {m}", r.name);
            assert_eq!(mr.untargeted, mr.no_aim + mr.missed, "{} {m}", r.name);
            let aimed: u64 = mr.aimed_at.values().sum();
            assert_eq!(aimed, landed + mr.missed, "{} {m}", r.name);
            assert!(mr.exercised, "{} {m}: {:?}", r.name, mr.not_exercised);
            assert!(
                mr.missed * 50 <= aimed,
                "{} {m}: {} of {aimed} aims missed",
                r.name,
                mr.missed
            );
            if !matches!(f, Fault::ForgedFence | Fault::FenceGap) {
                assert!(
                    mr.untargeted * 50 <= mr.total.reads,
                    "{} {m}: {} of {} reads untargeted",
                    r.name,
                    mr.untargeted,
                    mr.total.reads
                );
            }
        }
        assert!(
            covered(r, "path", "table 1 storage depth ") >= 3,
            "{}: {:?}",
            r.name,
            r.mode("path").unwrap().coverage
        );
        assert!(
            covered(r, "path", "table 0 account depth ") >= 3,
            "{}",
            r.name
        );
        assert!(
            covered(r, "baseline", "table 3 storage depth ") >= 3,
            "{}",
            r.name
        );
        assert!(
            covered(r, "baseline", "table 3 account depth ") >= 3,
            "{}",
            r.name
        );
        assert_eq!(covered(r, "baseline", "table 0"), 0, "{}", r.name);
        assert_eq!(covered(r, "baseline", "table 1"), 0, "{}", r.name);
    }
    // Every fault aimed at an entry or its page is caught in the storage
    // table in the path mode and in the hash-keyed table in the baseline.
    for (name, needle) in [
        ("node_omitted", "Missing"),
        ("page_malformed", "malformed: offsets"),
        ("forged_fence", "Missing"),
        ("fence_excludes", "malformed: key outside fences"),
        ("truncated_page", "short range"),
        ("wrong_run_page", "Run("),
        ("bit_flip_page", ""),
        ("missing_range", "io: not found"),
        ("http_error", "500"),
        ("stale_value", "HashMismatch"),
        ("stale_page", "HashMismatch"),
    ] {
        let r = t.row(name).unwrap();
        caught(r, "path", needle);
        let path = &r.mode("path").unwrap().reasons;
        let base = &r.mode("baseline").unwrap().reasons;
        assert!(
            path.keys()
                .any(|k| k.contains(needle) && k.contains("table 1")),
            "{name}: no storage-table catch in the path mode: {path:?}"
        );
        assert!(
            path.keys()
                .any(|k| k.contains(needle) && k.contains("table 0")),
            "{name}: no account-table catch in the path mode: {path:?}"
        );
        assert!(
            base.keys()
                .any(|k| k.contains(needle) && k.contains("table 3")),
            "{name}: no hash-table catch in the baseline: {base:?}"
        );
    }
    caught(
        t.row("stale_value").unwrap(),
        "path",
        "Code(bytecode does not hash",
    );
    // A page from the other run is one whole foreign page spliced into an
    // intact response: the client rejects the page itself, never sees a
    // short read or a refusal.
    for m in ["path", "baseline"] {
        let reasons = &t.row("wrong_run_page").unwrap().mode(m).unwrap().reasons;
        for k in reasons.keys() {
            assert!(
                !k.contains("ShortRead") && !k.contains("short range") && !k.contains("io:"),
                "wrong_run_page {m}: an I/O outcome, not a foreign page: {reasons:?}"
            );
        }
    }
    // A refusal aimed below the root lands mid-walk: most insufficient
    // reads decoded nodes before it.
    for name in ["missing_range", "http_error"] {
        for m in ["path", "baseline"] {
            let after = &t.row(name).unwrap().mode(m).unwrap().caught_after_nodes;
            let mid: u64 = after.iter().filter(|(n, _)| **n > 0).map(|(_, c)| c).sum();
            let all: u64 = after.values().sum();
            assert!(mid * 2 > all, "{name} {m}: {after:?}");
        }
    }
    // Narrowed fences still cover every entry, and every node a walk
    // needs is an entry: the row is all correct and that is the point.
    let gap = t.row("fence_gap").unwrap();
    assert_eq!(gap.total.correct, gap.total.reads);
    caught(t.row("wrong_range").unwrap(), "path", "Run(");
    caught(t.row("bit_flip").unwrap(), "path", "Run(");
    caught(t.row("bit_flip").unwrap(), "baseline", "table 3");
    caught(t.row("model_page_tamper").unwrap(), "path", "ModelMismatch");
    caught(t.row("page0_tamper").unwrap(), "path", "ModelMismatch");
    caught(t.row("page0_missing").unwrap(), "path", "io: not found");
    caught(
        t.row("truncated_blob").unwrap(),
        "path",
        "Blob(does not hash to its name",
    );

    // The manifest: a forged state_root refuses the open; forged model
    // roots open but every read is Insufficient; a forged file root is
    // not checked by anything (the trie proves values) so every read is
    // still right.
    let sr = t.row("manifest_state_root").unwrap();
    assert!(
        sr.open_error
            .as_deref()
            .is_some_and(|e| e.contains("state_root")),
        "{:?}",
        sr.open_error
    );
    assert_eq!(sr.total.reads, 0);
    assert!(
        sr.faulted > 0,
        "a refused open still counts what it changed"
    );
    let mr = t.row("manifest_model_root").unwrap();
    assert!(mr.open_error.is_none());
    assert_eq!(mr.total.insufficient, mr.total.reads);
    assert!(
        mr.reasons.keys().all(|k| k.contains("ModelMismatch")),
        "{:?}",
        mr.reasons
    );
    let tr = t.row("manifest_table_root").unwrap();
    assert_eq!(tr.total.correct, tr.total.reads);
    // Whole files cut in half: `latest` is no longer a block hash, the
    // manifest no longer JSON.
    for name in ["truncated_latest", "truncated_manifest"] {
        let r = t.row(name).unwrap();
        assert!(r.open_error.is_some(), "{name}");
        assert!(r.faulted > 0, "{name}");
    }
    assert!(t
        .row("truncated_manifest")
        .unwrap()
        .modes
        .values()
        .all(|m| m.faulted == 1));
    // Page 0 tampered or refused on every table: nothing can route.
    for name in ["page0_tamper", "page0_missing"] {
        let p0 = t.row(name).unwrap();
        assert_eq!(p0.total.insufficient, p0.total.reads, "{name}");
    }

    std::fs::remove_dir_all(&dir).ok();
}

/// One fault alone reproduces its row of the full table: seeds come from
/// the fault's name, not its place in the list.
#[test]
fn a_fault_alone_reproduces_its_row() {
    let w = common::whole(300, 3);
    let dir = w.produce("alone");
    let mut o = Options {
        keys: 20,
        mode: Mode::Path,
        faults: vec![Fault::NodeOmitted, Fault::BitFlip, Fault::BitFlipPage],
        ..Options::default()
    };
    let all = run_table(&w.slice, &dir, &o).unwrap();
    o.faults = vec![Fault::BitFlipPage];
    let one = run_table(&w.slice, &dir, &o).unwrap();
    assert_eq!(one.faults.len(), 2, "the control row always runs");
    let (a, b) = (
        all.row("bit_flip_page").unwrap(),
        one.row("bit_flip_page").unwrap(),
    );
    assert_eq!(a.total, b.total);
    assert_eq!(a.reasons, b.reasons);
    std::fs::remove_dir_all(&dir).ok();
}

/// At a partial rate the host is flaky rather than hostile: reads split
/// between right and Insufficient, still never wrong.
#[test]
fn a_flaky_host_splits_reads_between_right_and_insufficient() {
    let w = common::whole(300, 5);
    let dir = w.produce("flaky");
    let o = Options {
        keys: 30,
        rate: 0.3,
        seed: 9,
        mode: Mode::Path,
        top_levels: 0,
        faults: vec![
            Fault::MissingRange,
            Fault::HttpError,
            Fault::BitFlip,
            Fault::StalePage,
        ],
    };
    let t = run_table(&w.slice, &dir, &o).unwrap();
    assert!(t.pass, "{:?}", t.failures);
    for r in t.faults.iter().filter(|r| r.name != "none") {
        eprintln!("{} at 0.3: {:?} {:?}", r.name, r.total, r.reasons);
        assert!(
            r.total.correct > 0 && r.total.insufficient > 0,
            "{}: {:?}",
            r.name,
            r.total
        );
        if r.aimed {
            assert!(r.mode("path").unwrap().spared > 0);
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// A table that injects nothing is safe and does not pass: at rate 0
/// every read is right, and no firing fault is exercised. The command
/// fails on it, with the report saying which half held.
#[test]
fn a_table_that_injects_nothing_is_safe_but_fails() {
    let w = common::whole(300, 4);
    let dir = w.produce("rate0");
    let o = Options {
        keys: 20,
        rate: 0.0,
        mode: Mode::Both,
        ..Options::default()
    };
    let t = run_table(&w.slice, &dir, &o).unwrap();
    assert!(t.safe && t.control_correct, "{:?}", t.failures);
    assert!(!t.exercised);
    assert!(!t.pass);
    for r in t.faults.iter().filter(|r| r.name != "none") {
        assert!(!r.exercised, "{}", r.name);
        assert_eq!(r.faulted, 0, "{}", r.name);
        for (m, mr) in &r.modes {
            if mr.not_applicable.is_none() {
                assert!(!mr.exercised, "{} {m}", r.name);
                assert!(
                    t.not_exercised
                        .iter()
                        .any(|s| s.starts_with(&format!("{} {m}: ", r.name))),
                    "{} {m} not listed: {:?}",
                    r.name,
                    t.not_exercised
                );
            }
        }
    }

    let slice_dir = common::scratch("rate0-slice");
    w.slice.write(&slice_dir).unwrap();
    let out = slice_dir.join("faults.json");
    let r = csl_eth_snap::faults::run(csl_eth_snap::faults::Args {
        slice: slice_dir.clone(),
        bucket: dir.clone(),
        out: out.clone(),
        keys: 20,
        rate: 0.0,
        seed: 1,
        mode: Mode::Path,
        top_levels: 0,
        faults: vec!["node_omitted".into(), "bit_flip".into()],
    });
    assert!(r.is_err(), "{r:?}");
    let report: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
    assert_eq!(report["pass"], false);
    assert_eq!(report["safe"], true);
    assert_eq!(report["exercised"], false);
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&slice_dir).ok();
}

/// With the top levels kept across reads, a response holding a cached
/// node can change without the client consuming it, so no aim is at a
/// cached account depth and coverage counts only nodes the client
/// fetches; the aimed faults are still exercised and caught.
#[test]
fn with_top_levels_cached_no_aim_is_at_a_cached_depth() {
    let w = common::whole(900, 6);
    let dir = w.produce("top");
    let o = Options {
        keys: 30,
        mode: Mode::Both,
        top_levels: 2,
        faults: vec![Fault::NodeOmitted, Fault::MissingRange, Fault::StaleValue],
        ..Options::default()
    };
    let t = run_table(&w.slice, &dir, &o).unwrap();
    print(&t);
    assert!(t.pass, "{:?} {:?}", t.not_exercised, t.failures);
    for r in t.faults.iter().filter(|r| r.aimed) {
        for m in ["path", "baseline"] {
            let mr = r.mode(m).unwrap();
            for label in mr.aimed_at.keys().chain(mr.coverage.keys()) {
                for d in 0..o.top_levels {
                    assert!(
                        !label.ends_with(&format!("account depth {d}")),
                        "{} {m}: aimed at a cached depth: {label}",
                        r.name
                    );
                }
            }
            assert!(
                covered(
                    r,
                    m,
                    &format!("table {} account depth ", if m == "path" { 0 } else { 3 })
                ) > 0,
                "{} {m}: {:?}",
                r.name,
                mr.coverage
            );
        }
    }
    std::fs::remove_dir_all(&dir).ok();
}
