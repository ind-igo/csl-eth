//! Milestone 1 measurement: model bytes beside `8 × page_count`.
//!
//! One generation pass per (workload, n) feeds one fitter per ε; a second
//! pass verifies every model. Prints a markdown table and optionally a JSON
//! file with every number.

use clap::Parser;
use pgm::workload::{Kind, Spec};
use pgm::{entries_per_page, page_count, Fitter, Grouper, Model};
use serde::Serialize;
use std::time::Instant;

#[derive(Parser, Debug)]
#[command(name = "pgm-bench", about = "Learned-index size measurement for the cold state layer")]
struct Args {
    /// Workloads: uniform, seq-prefix, vanity, or all.
    #[arg(long, default_value = "all", value_delimiter = ',')]
    workload: Vec<String>,
    /// Key counts, e.g. 1e6,1e8,1e9 or plain integers.
    #[arg(long, default_value = "1e6", value_delimiter = ',')]
    n: Vec<String>,
    /// ε in pages.
    #[arg(long, default_value = "1,2,4,8", value_delimiter = ',')]
    eps: Vec<u16>,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    /// Fixed value size in bytes; cinder accounts are 24.
    #[arg(long, default_value_t = 24)]
    value_size: u32,
    /// Write every result as JSON here.
    #[arg(long)]
    json: Option<std::path::PathBuf>,
    /// Skip the verification pass (never for reported numbers).
    #[arg(long)]
    no_verify: bool,
}

#[derive(Serialize, Clone, Debug)]
struct Row {
    workload: String,
    n: u64,
    seed: u64,
    value_size: u32,
    entries_per_page: u64,
    page_count: u64,
    groups: u64,
    epsilon: u16,
    segments: usize,
    model_bytes: usize,
    fence_bytes: u64,
    fraction: f64,
    keys_per_segment: f64,
    verified: bool,
    max_abs_error: u64,
    fit_secs: f64,
    verify_secs: f64,
}

fn parse_n(s: &str) -> u64 {
    let s = s.replace('_', "");
    if let Ok(v) = s.parse::<u64>() {
        return v;
    }
    let f: f64 = s.parse().unwrap_or_else(|_| panic!("bad n {s:?}"));
    f.round() as u64
}

fn human(b: f64) -> String {
    if b >= 1e9 {
        format!("{:.2} GB", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.2} MB", b / 1e6)
    } else if b >= 1e3 {
        format!("{:.1} KB", b / 1e3)
    } else {
        format!("{b:.0} B")
    }
}

fn main() {
    let args = Args::parse();
    let kinds: Vec<Kind> = if args.workload.iter().any(|w| w == "all") {
        Kind::ALL.to_vec()
    } else {
        args.workload.iter().map(|w| w.parse().unwrap_or_else(|e| panic!("{e}"))).collect()
    };
    let ns: Vec<u64> = args.n.iter().map(|s| parse_n(s)).collect();
    let epp = entries_per_page(args.value_size);
    let mut rows: Vec<Row> = Vec::new();

    for kind in kinds {
        for &n in &ns {
            let spec = Spec { kind, n, seed: args.seed };
            let pc = page_count(n, epp);
            eprintln!("[{kind} n={n}] pages={pc} epp={epp} fitting ε={:?}", args.eps);

            let t0 = Instant::now();
            let mut fitters: Vec<Fitter> = args.eps.iter().map(|&e| Fitter::new(e, pc)).collect();
            let mut grouper = Grouper::new(epp);
            let mut failed: Vec<Option<pgm::FitError>> = vec![None; fitters.len()];
            let push_all = |g: pgm::Group, fitters: &mut Vec<Fitter>, failed: &mut Vec<Option<pgm::FitError>>| {
                for (f, fail) in fitters.iter_mut().zip(failed.iter_mut()) {
                    if fail.is_none() {
                        if let Err(e) = f.push(g) {
                            *fail = Some(e);
                        }
                    }
                }
            };
            spec.for_each(|k| {
                if let Some(g) = grouper.push(k) {
                    push_all(g, &mut fitters, &mut failed);
                }
            });
            let groups = grouper.entries_seen();
            if let Some(g) = grouper.finish() {
                push_all(g, &mut fitters, &mut failed);
            }
            let fit_secs = t0.elapsed().as_secs_f64();
            // groups counted by the first fitter (same for all)
            let group_count = fitters[0].groups_seen();
            let _ = groups;

            let mut models: Vec<Option<Model>> = Vec::new();
            for (f, fail) in fitters.into_iter().zip(failed.iter()) {
                if let Some(e) = fail {
                    eprintln!("  ε={} fit aborted: {e}", f.groups_seen());
                    models.push(None);
                } else {
                    models.push(f.finish().ok());
                }
            }

            // Verification pass: re-stream, check every group against every model.
            let t1 = Instant::now();
            let mut max_err: Vec<u64> = vec![0; models.len()];
            let mut ok: Vec<bool> = vec![true; models.len()];
            if !args.no_verify {
                let mut grouper = Grouper::new(epp);
                let check = |g: pgm::Group, models: &Vec<Option<Model>>, max_err: &mut Vec<u64>, ok: &mut Vec<bool>| {
                    for (i, m) in models.iter().enumerate() {
                        if let Some(m) = m {
                            let p = m.predict(g.k64);
                            let e = (p as i128 - g.p_min as i128).abs().max((p as i128 - g.p_max as i128).abs()) as u64;
                            if e > max_err[i] {
                                max_err[i] = e;
                            }
                            if m.check(&g).is_err() {
                                ok[i] = false;
                            }
                        }
                    }
                };
                spec.for_each(|k| {
                    if let Some(g) = grouper.push(k) {
                        check(g, &models, &mut max_err, &mut ok);
                    }
                });
                if let Some(g) = grouper.finish() {
                    check(g, &models, &mut max_err, &mut ok);
                }
            }
            let verify_secs = t1.elapsed().as_secs_f64();

            for (i, m) in models.iter().enumerate() {
                let eps = args.eps[i];
                let fence_bytes = 8 * pc;
                let (segments, model_bytes) = match m {
                    Some(m) => (m.segments.len(), m.encoded_len()),
                    None => (0, 0),
                };
                let row = Row {
                    workload: kind.to_string(),
                    n,
                    seed: args.seed,
                    value_size: args.value_size,
                    entries_per_page: epp,
                    page_count: pc,
                    groups: group_count,
                    epsilon: eps,
                    segments,
                    model_bytes,
                    fence_bytes,
                    fraction: if m.is_some() { model_bytes as f64 / fence_bytes as f64 } else { f64::NAN },
                    keys_per_segment: if segments > 0 { n as f64 / segments as f64 } else { f64::NAN },
                    verified: m.is_some() && ok[i] && !args.no_verify,
                    max_abs_error: max_err[i],
                    fit_secs,
                    verify_secs,
                };
                eprintln!(
                    "  ε={eps}: segments={segments} model={} fences={} fraction={:.5} verified={} max|err|={}",
                    human(model_bytes as f64),
                    human(fence_bytes as f64),
                    row.fraction,
                    row.verified,
                    row.max_abs_error
                );
                rows.push(row);
            }
            eprintln!("  fit {fit_secs:.1}s, verify {verify_secs:.1}s");
        }
    }

    println!("| workload | n | pages | groups | ε | segments | keys/segment | model bytes | 8 × page_count | fraction | verified | max abs err |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");
    for r in &rows {
        println!(
            "| {} | {:.0e} | {} | {} | {} | {} | {:.0} | {} | {} | {:.5} | {} | {} |",
            r.workload,
            r.n as f64,
            r.page_count,
            r.groups,
            r.epsilon,
            r.segments,
            r.keys_per_segment,
            human(r.model_bytes as f64),
            human(r.fence_bytes as f64),
            r.fraction,
            if r.verified { "yes" } else { "NO" },
            r.max_abs_error
        );
    }

    // Growth ratios between consecutive n for the same workload and ε.
    let mut printed = false;
    for kind in Kind::ALL {
        for &eps in &args.eps {
            let mut series: Vec<&Row> = rows.iter().filter(|r| r.workload == kind.to_string() && r.epsilon == eps && r.segments > 0).collect();
            series.sort_by_key(|r| r.n);
            for w in series.windows(2) {
                if !printed {
                    println!("\n| workload | ε | n_lo → n_hi | n ratio | model bytes ratio |");
                    println!("|---|---|---|---|---|");
                    printed = true;
                }
                println!(
                    "| {} | {} | {:.0e} → {:.0e} | {:.0} | {:.2} |",
                    kind,
                    eps,
                    w[0].n as f64,
                    w[1].n as f64,
                    w[1].n as f64 / w[0].n as f64,
                    w[1].model_bytes as f64 / w[0].model_bytes as f64
                );
            }
        }
    }

    if let Some(p) = &args.json {
        std::fs::write(p, serde_json::to_string_pretty(&rows).unwrap()).unwrap();
        eprintln!("wrote {}", p.display());
    }
}
