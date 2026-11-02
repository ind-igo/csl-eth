//! `csl-eth produce`: the producer loop. A snapshot is only a head while
//! the bucket's head files can be followed to it: its finality update is
//! signed in some period P, and a client refuses a head signed two periods
//! before its clock as stale, so a frozen snapshot stops opening once
//! period P+2 begins. This loop keeps the bucket current by doing, at each chosen
//! epoch boundary, what was done by hand once:
//!
//! 1. fetch the slice over snap with the pivot at the boundary (the block
//!    finality will name 13 to 19 minutes later), dialing `--lead-secs`
//!    before it;
//! 2. build the snapshot into the local mirror of the bucket;
//! 3. wait for the beacon node's finality update to name that block, and
//!    keep its exact bytes (a watcher polls from the start of the cycle,
//!    since the node serves only its newest update and the one naming our
//!    block exists for one epoch);
//! 4. lay out the head files: the bootstrap once, the period updates from
//!    the checkpoint's period through the current one (fetching what is
//!    missing, the current period's again, and a period's once more after
//!    it closes), and `head/finality`;
//! 5. verify the mirror as a client would: the head reaches exactly this
//!    block and the manifest's state root, and sampled accounts, slots and
//!    code from the slice read back verified through it. Head files count
//!    only from here, and only those the head's verification read: the
//!    bootstrap and the updates for periods `b..s` (`s` the finality
//!    update's signing period). If verification fails, what was fetched
//!    is discarded and the next cycle fetches it again; if it passes,
//!    updates fetched for `s` or later, which it did not read, are dropped
//!    from the mirror and not published;
//! 6. publish so that a reader never sees a pointer to something not yet
//!    there: run files, manifest, new blobs, changed head updates of
//!    `b..s`, `snapshots/latest`, and `head/finality` last;
//! 7. delete snapshots beyond `--keep` from the bucket and the mirror, and
//!    old slices; never the newest, the one `head/finality` or `latest`
//!    names, or one a pointer write may have named (a write that failed is
//!    not known not to have landed, nor to be over). Blobs are
//!    content-addressed and shared, and are never deleted.
//!
//! A failed cycle is logged and the loop goes on to the next boundary.
//! Pointer writes that keep failing are bounded: with more than three
//! snapshots waiting on them (pending, and newer than the confirmed head),
//! a cycle fetches nothing and writes the newest one's pointers again,
//! while its head still verifies; once it cannot, one new snapshot is let
//! in, so they grow by one per head lifetime (27 to 55 hours), not per
//! cycle.
//! What has been published is recorded in `<work>/state.json` as each
//! file goes up, so a restart re-uploads neither blobs nor closed updates.
//! Each publisher call has a deadline (`--publish-timeout-secs`) that
//! covers the program and anything it leaves holding its output: past it
//! the process group is killed and the call is a failure.

use crate::{fetch, FetchConfig, Slice};
use alloy_primitives::{keccak256, B256};
use clap::Args as ClapArgs;
use csl_eth_client::{open_at_head, DirDriver, Read};
use csl_eth_head::{
    fetch::{finalized_of, Beacon, FinalityWatch},
    paths, Chain, DirSource,
};
use csl_eth_store::{produce_with, ProduceOptions, LATEST_FILE, MANIFEST_FILE};
use csl_eth_trie::{Nibbles, KECCAK_EMPTY};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

/// Seconds in an epoch: 32 slots of 12 seconds.
const EPOCH_SECS: u64 = 32 * 12;

/// `produce.log` is rotated to `produce.log.1` above this size.
const LOG_MAX: u64 = 10 << 20;

#[derive(ClapArgs, Debug, Clone)]
pub struct Args {
    /// Hex nibbles of the slice, e.g. `1a7` for 1/4096 of state.
    #[arg(long)]
    pub prefix: String,
    /// Local state: `bucket/` (the mirror of what is published),
    /// `slices/`, `state.json` and `produce.log`.
    #[arg(long)]
    pub work: PathBuf,
    /// The weak-subjectivity checkpoint root the bucket's head starts at.
    #[arg(long)]
    pub checkpoint: B256,
    /// Beacon node with the light-client endpoints.
    #[arg(long, default_value = "https://lodestar-mainnet.chainsafe.io")]
    pub beacon: String,
    /// Invoked as `<program> put <key> <file>` and `<program> delete
    /// <key>`; a nonzero exit is a failure.
    #[arg(long)]
    pub publish: String,
    /// Snapshots kept in the bucket.
    #[arg(long, default_value_t = 3)]
    pub keep: usize,
    /// Minimum spacing between published snapshots, in minutes; the next
    /// boundary is the first epoch boundary past it.
    #[arg(long, default_value_t = 60)]
    pub every_mins: u64,
    /// Run one cycle and exit with its status.
    #[arg(long)]
    pub once: bool,
    /// Start dialing this long before the boundary.
    #[arg(long, default_value_t = 120)]
    pub lead_secs: u64,
    /// Give up on the fetch this long after the boundary (peers serve a
    /// root for about 128 blocks, 25 minutes).
    #[arg(long, default_value_t = 1200)]
    pub max_fetch_secs: u64,
    /// Give up waiting for finality to name the block this long after the
    /// boundary (it normally does after 13 to 19 minutes).
    #[arg(long, default_value_t = 2400)]
    pub finality_wait_secs: u64,
    /// How often to poll the beacon node's finality update.
    #[arg(long, default_value_t = 16)]
    pub poll_secs: u64,
    #[arg(long, default_value_t = 8)]
    pub peers: usize,
    /// Per request to a peer.
    #[arg(long, default_value_t = 20)]
    pub timeout_secs: u64,
    #[arg(long, default_value_t = 30399)]
    pub udp_port: u16,
    /// Learned-index error bound in pages.
    #[arg(long, default_value_t = 1)]
    pub epsilon: u16,
    /// Accounts read back through the head before publishing.
    #[arg(long, default_value_t = 16)]
    pub samples: usize,
    /// Uploads in flight.
    #[arg(long, default_value_t = 8)]
    pub publish_parallel: usize,
    /// Deadline for each publisher call; past it the program and its
    /// process group are killed and the call is a failure.
    #[arg(long, default_value_t = 300)]
    pub publish_timeout_secs: u64,
}

/// What has been published, kept across restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct State {
    pub checkpoint: B256,
    pub bootstrap_published: bool,
    /// Head updates in the bucket: the blake3 of the bytes, and whether
    /// they were fetched after their period closed (then final: never
    /// fetched or published again).
    pub updates: BTreeMap<u64, PubUpdate>,
    /// Local update files fetched after their period closed.
    pub updates_final_local: BTreeSet<u64>,
    /// Blob keys in the bucket.
    pub blobs: BTreeSet<String>,
    /// Snapshots with files in the bucket, oldest first.
    pub snapshots: Vec<SnapRec>,
    /// The block the bucket's `head/finality` names.
    pub finality: Option<B256>,
    /// The block the bucket's `snapshots/latest` names.
    pub latest: Option<B256>,
    /// Snapshots a pointer write (`latest` or `head/finality`) was started
    /// for, with when (unix seconds; the latest attempt's). A write that
    /// failed or timed out may have landed, or may still land: killing the
    /// publisher does not cancel a request the store is already serving.
    /// So the bucket may name any of them, and they are protected from
    /// collection until both pointers have been written and confirmed by a
    /// write that began at least the grace after (see [`release_pending`]).
    /// A `state.json` from before the times were kept lists bare hashes;
    /// they load as started now.
    #[serde(default, deserialize_with = "pending_compat")]
    pub pending: BTreeMap<B256, u64>,
}

fn pending_compat<'de, D>(d: D) -> Result<BTreeMap<B256, u64>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Pending {
        Since(BTreeMap<B256, u64>),
        Bare(BTreeSet<B256>),
    }
    Ok(match Pending::deserialize(d)? {
        Pending::Since(m) => m,
        Pending::Bare(s) => {
            let now = now_secs();
            s.into_iter().map(|h| (h, now)).collect()
        }
    })
}

/// How long a pointer write that was not confirmed is assumed able to
/// land: an hour, or four publisher deadlines if that is longer, well past
/// any request's lifetime (the publisher is killed at its deadline, and the
/// R2 publisher's curl gives up at 240 s a try).
pub fn pending_grace(publish_timeout: Duration) -> u64 {
    (4 * publish_timeout.as_secs()).max(3600)
}

/// Both pointers were written and confirmed by writes that began at
/// `started`. An entry is released only if its own writes began at least
/// `grace` before that: by then none of them can still land, so the
/// confirmed writes are the bucket's last word. An entry younger than that
/// stays, since a write of it landing after `started` would name it again;
/// a later cycle releases it.
pub fn release_pending(state: &mut State, started: u64, grace: u64) {
    state
        .pending
        .retain(|_, since| since.saturating_add(grace) > started);
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PubUpdate {
    pub blake3: String,
    #[serde(rename = "final")]
    pub is_final: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SnapRec {
    pub block_hash: B256,
    pub block_number: u64,
    /// The epoch boundary it was fetched at (unix seconds).
    pub boundary: u64,
    /// Its keys in the bucket.
    pub keys: Vec<String>,
    /// `head/finality` has named it: published whole.
    pub complete: bool,
    /// Its slice under `<work>/slices/`.
    pub slice: String,
}

impl State {
    fn path(work: &Path) -> PathBuf {
        work.join("state.json")
    }

    pub fn load(work: &Path, checkpoint: B256) -> Result<State, String> {
        match fs::read(State::path(work)) {
            Ok(b) => {
                let s: State =
                    serde_json::from_slice(&b).map_err(|e| format!("state.json: {e}"))?;
                if s.checkpoint != checkpoint {
                    return Err(format!(
                        "state.json is for checkpoint {}, not {checkpoint}; use another --work",
                        s.checkpoint
                    ));
                }
                Ok(s)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State {
                checkpoint,
                ..Default::default()
            }),
            Err(e) => Err(format!("state.json: {e}")),
        }
    }

    pub fn save(&self, work: &Path) -> Result<(), String> {
        write_atomic(
            &State::path(work),
            &serde_json::to_vec_pretty(self).expect("state serializes"),
        )
    }

    /// The boundary of the newest snapshot `head/finality` has named.
    fn last_boundary(&self) -> Option<u64> {
        self.snapshots
            .iter()
            .filter(|s| s.complete)
            .map(|s| s.boundary)
            .max()
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(d) = path.parent() {
        fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("{}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The first epoch boundary at or after `t` (unix seconds).
pub fn boundary_at_or_after(genesis: u64, t: u64) -> u64 {
    if t <= genesis {
        return genesis;
    }
    genesis + (t - genesis).div_ceil(EPOCH_SECS) * EPOCH_SECS
}

/// The boundary the next cycle fetches at: at least `lead` from now, and
/// at least `every` after the last published snapshot's boundary.
pub fn next_target(genesis: u64, now: u64, lead: u64, last: Option<u64>, every: u64) -> u64 {
    let earliest = (now + lead).max(last.map_or(0, |b| b + every));
    boundary_at_or_after(genesis, earliest)
}

/// Snapshots to delete: incomplete ones (a cycle that failed while
/// publishing), and complete ones beyond the newest `keep`; never the
/// ones `head/finality` or `latest` name, any a pointer write is pending
/// for, or the newest by block number.
pub fn gc_plan(state: &State, keep: usize) -> Vec<B256> {
    let newest = state
        .snapshots
        .iter()
        .max_by_key(|s| s.block_number)
        .map(|s| s.block_hash);
    let protected = |h: &B256| {
        state.finality == Some(*h)
            || state.latest == Some(*h)
            || state.pending.contains_key(h)
            || newest == Some(*h)
    };
    let mut complete: Vec<&SnapRec> = state.snapshots.iter().filter(|s| s.complete).collect();
    complete.sort_by_key(|s| s.block_number);
    let excess = complete.len().saturating_sub(keep);
    let mut out: Vec<(u64, B256)> = complete[..excess]
        .iter()
        .map(|s| (s.block_number, s.block_hash))
        .collect();
    out.extend(
        state
            .snapshots
            .iter()
            .filter(|s| !s.complete)
            .map(|s| (s.block_number, s.block_hash)),
    );
    out.sort();
    out.into_iter()
        .map(|(_, h)| h)
        .filter(|h| !protected(h))
        .collect()
}

/// Where uploads go: `put` a key from a local file, `delete` a key.
pub trait Publish: Sync {
    fn put(&self, key: &str, file: &Path) -> Result<(), String>;
    fn delete(&self, key: &str) -> Result<(), String>;
}

/// An external program, `<program> put <key> <file>` / `<program> delete
/// <key>`, each call with a deadline.
pub struct Program {
    pub program: String,
    pub timeout: Duration,
}

/// After a kill, how long to wait for the output pipes to close.
const PIPE_GRACE: Duration = Duration::from_secs(2);

impl Program {
    /// The deadline bounds the whole call: the program's exit, then the
    /// end of its stdout and stderr, which a process it started can hold
    /// open after it exits (`cmd &`). Past it, the process group is killed;
    /// a reader still blocked after a short grace (a descendant that left
    /// the group) is abandoned, not joined. The program's exit status
    /// decides the call: one that exited 0 but left something holding its
    /// output has done its work, and that straggler is killed and logged.
    fn run(&self, args: &[&std::ffi::OsStr]) -> Result<(), String> {
        use std::{
            io::Read as _,
            sync::{Arc, Mutex},
            thread::JoinHandle,
        };
        let shown = || {
            format!(
                "{} {}",
                self.program,
                args.iter()
                    .map(|a| a.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" ")
            )
        };
        let mut cmd = Command::new(&self.program);
        cmd.args(args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // Its own process group, so a timeout kills what it started too
        // (a shell script's `cf` or `curl`), and the pipes close.
        #[cfg(unix)]
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        let mut child = cmd.spawn().map_err(|e| format!("{}: {e}", self.program))?;
        let pid = child.id();
        let kill_group = || {
            #[cfg(unix)]
            let _ = Command::new("kill")
                .args(["-KILL", &format!("-{pid}")])
                .status();
        };
        // Read into shared buffers, so what arrived is there even if a
        // reader is abandoned.
        let drain = |r: Option<Box<dyn std::io::Read + Send>>| {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let b = buf.clone();
            let t = std::thread::spawn(move || {
                let Some(mut r) = r else { return };
                let mut chunk = [0u8; 8192];
                loop {
                    match r.read(&mut chunk) {
                        Ok(0) => return,
                        Ok(n) => b.lock().unwrap().extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => return,
                    }
                }
            });
            (t, buf)
        };
        let (out_t, out) = drain(child.stdout.take().map(|x| Box::new(x) as _));
        let (err_t, err) = drain(child.stderr.take().map(|x| Box::new(x) as _));
        let readers = [out_t, err_t];
        let drained_by = |readers: &[JoinHandle<()>], until: Instant| loop {
            if readers.iter().all(|t| t.is_finished()) {
                return true;
            }
            if Instant::now() >= until {
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(st)) => break Some(st),
                Ok(None) if Instant::now() >= deadline => break None,
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => return Err(format!("{}: {e}", shown())),
            }
        };
        let Some(status) = status else {
            kill_group();
            let _ = child.kill();
            let _ = child.wait();
            drained_by(&readers, Instant::now() + PIPE_GRACE);
            return Err(format!(
                "{}: no answer in {} s; killed",
                shown(),
                self.timeout.as_secs()
            ));
        };
        if !drained_by(&readers, deadline) {
            kill_group();
            let closed = drained_by(&readers, Instant::now() + PIPE_GRACE);
            tracing::warn!(
                call = %shown(),
                %status,
                closed,
                "the publisher exited; its output was held open past the deadline; group killed"
            );
        }
        // Finished readers are joined; one still blocked is left detached.
        for t in readers {
            if t.is_finished() {
                let _ = t.join();
            }
        }
        if status.success() {
            return Ok(());
        }
        let (se, so) = (err.lock().unwrap().clone(), out.lock().unwrap().clone());
        let (se, so) = (String::from_utf8_lossy(&se), String::from_utf8_lossy(&so));
        Err(format!(
            "{}: {}: {}{}",
            shown(),
            status,
            se.trim(),
            if so.trim().is_empty() {
                String::new()
            } else {
                format!(" / {}", so.trim())
            }
        ))
    }
}

impl Publish for Program {
    fn put(&self, key: &str, file: &Path) -> Result<(), String> {
        self.run(&["put".as_ref(), key.as_ref(), file.as_os_str()])
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.run(&["delete".as_ref(), key.as_ref()])
    }
}

/// Counts what a cycle sent.
struct Sent {
    files: u64,
    bytes: u64,
}

/// Upload `items` with up to `parallel` in flight. Returns the keys that
/// went up and the first error, if any.
fn put_many(
    p: &dyn Publish,
    items: &[(String, PathBuf)],
    parallel: usize,
    sent: &mut Sent,
) -> (Vec<String>, Option<String>) {
    let next = std::sync::atomic::AtomicUsize::new(0);
    let done = std::sync::Mutex::new(Vec::new());
    let err = std::sync::Mutex::new(None::<String>);
    std::thread::scope(|s| {
        for _ in 0..parallel.max(1).min(items.len().max(1)) {
            s.spawn(|| loop {
                if err.lock().unwrap().is_some() {
                    return;
                }
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some((key, file)) = items.get(i) else {
                    return;
                };
                match p.put(key, file) {
                    Ok(()) => done.lock().unwrap().push(i),
                    Err(e) => {
                        err.lock().unwrap().get_or_insert(e);
                        return;
                    }
                }
            });
        }
    });
    let mut idx = done.into_inner().unwrap();
    idx.sort();
    for &i in &idx {
        sent.files += 1;
        sent.bytes += fs::metadata(&items[i].1).map(|m| m.len()).unwrap_or(0);
    }
    (
        idx.into_iter().map(|i| items[i].0.clone()).collect(),
        err.into_inner().unwrap(),
    )
}

fn put_one(p: &dyn Publish, key: &str, file: &Path, sent: &mut Sent) -> Result<(), String> {
    p.put(key, file)?;
    sent.files += 1;
    sent.bytes += fs::metadata(file).map(|m| m.len()).unwrap_or(0);
    Ok(())
}

/// A failed step: which, and why.
struct Failed {
    step: &'static str,
    error: String,
}

fn at(step: &'static str) -> impl FnOnce(String) -> Failed {
    move |error| Failed { step, error }
}

/// The local layout under `--work`.
struct Work {
    root: PathBuf,
    bucket: PathBuf,
    slices: PathBuf,
}

impl Work {
    fn new(root: &Path) -> Result<Work, String> {
        let w = Work {
            root: root.to_path_buf(),
            bucket: root.join("bucket"),
            slices: root.join("slices"),
        };
        for d in [&w.root, &w.bucket, &w.slices] {
            fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        Ok(w)
    }

    fn log(&self, line: &Value) {
        let s = line.to_string();
        println!("{s}");
        let _ = std::io::stdout().flush();
        let path = self.root.join("produce.log");
        // One generation kept: above the cap the log becomes produce.log.1.
        if fs::metadata(&path).is_ok_and(|m| m.len() > LOG_MAX) {
            let _ = fs::rename(&path, self.root.join("produce.log.1"));
        }
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(f, "{s}");
        }
    }
}

/// Run the loop (or one cycle with `--once`).
pub fn run(args: Args) -> Result<(), String> {
    parse_prefix(&args.prefix)?;
    let work = Work::new(&args.work)?;
    let mut state = State::load(&work.root, args.checkpoint)?;
    let publisher = Program {
        program: args.publish.clone(),
        timeout: Duration::from_secs(args.publish_timeout_secs),
    };
    let chain = Chain::mainnet();
    loop {
        let target = next_target(
            chain.genesis_time,
            now_secs(),
            args.lead_secs,
            state.last_boundary(),
            args.every_mins * 60,
        );
        let start = target.saturating_sub(args.lead_secs);
        let wait = start.saturating_sub(now_secs());
        tracing::info!(target, wait_secs = wait, "next cycle at the epoch boundary");
        if wait > 0 {
            std::thread::sleep(Duration::from_secs(wait));
        }
        let mut line = Map::new();
        let r = cycle(&args, &work, &mut state, &publisher, target, &mut line);
        // Garbage is collected after every cycle: a failed one leaves a
        // built snapshot and a slice behind, and may have published part
        // of a snapshot.
        let gc = collect(&work, &mut state, &publisher, args.keep);
        line.insert("deleted".into(), json!(gc.deleted));
        if let Some(e) = &gc.error {
            line.insert("gc_error".into(), json!(e));
        }
        let ok = r.is_ok();
        match r {
            Ok(()) => {
                line.insert("ok".into(), json!(true));
            }
            Err(f) => {
                line.insert("ok".into(), json!(false));
                line.insert("step".into(), json!(f.step));
                line.insert("error".into(), json!(f.error));
            }
        }
        let mut out = Map::new();
        out.insert("ok".into(), line["ok"].clone());
        for (k, v) in line {
            out.entry(k).or_insert(v);
        }
        work.log(&Value::Object(out));
        if args.once {
            return if ok {
                Ok(())
            } else {
                Err("the cycle failed (see the log line)".into())
            };
        }
    }
}

fn parse_prefix(s: &str) -> Result<Nibbles, String> {
    let s = s.trim_start_matches("0x");
    if s.is_empty() || s.len() > 62 {
        return Err("prefix must be 1 to 62 hex nibbles".into());
    }
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        out.push(
            c.to_digit(16)
                .ok_or_else(|| format!("not a hex nibble: {c}"))? as u8,
        );
    }
    Ok(Nibbles::from_nibbles(out))
}

/// The fetch in a runtime of its own, dropped when it returns, so its
/// discovery sockets and peer tasks do not outlive the cycle.
fn fetch_blocking(cfg: FetchConfig) -> Result<Slice, String> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let r = rt.block_on(fetch(cfg)).map_err(|e| e.to_string());
        rt.shutdown_timeout(Duration::from_secs(2));
        r
    })
    .join()
    .map_err(|_| "the fetch thread panicked".to_string())?
}

fn secs(d: Duration) -> f64 {
    (d.as_secs_f64() * 10.0).round() / 10.0
}

fn utc(t: u64) -> String {
    // Civil date from unix seconds (Howard Hinnant's algorithm), to keep
    // the log readable without a date crate.
    let days = (t / 86_400) as i64;
    let rem = t % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn cycle(
    args: &Args,
    work: &Work,
    state: &mut State,
    publisher: &dyn Publish,
    target: u64,
    line: &mut Map<String, Value>,
) -> Result<(), Failed> {
    let chain = Chain::mainnet();
    let boundary_slot = (target - chain.genesis_time) / 12;
    line.insert("boundary".into(), json!(utc(target)));
    line.insert("boundary_slot".into(), json!(boundary_slot));

    // 0. Pointer writes that keep failing would leave one more protected
    // snapshot every cycle. Past a bound, no new one is fetched while the
    // newest of those waiting can still be made the head: its pointers are
    // written again instead.
    let stuck = unresolved_pending(state);
    if stuck.len() > MAX_UNRESOLVED {
        let msg = format!(
            "{} snapshots wait on pointer writes (bound {MAX_UNRESOLVED})",
            stuck.len()
        );
        tracing::error!("{msg}");
        line.insert("pending_error".into(), json!(msg));
        let mut sent = Sent { files: 0, bytes: 0 };
        let r = retry_pointers(
            work,
            state,
            publisher,
            stuck[0],
            args.checkpoint,
            pending_grace(Duration::from_secs(args.publish_timeout_secs)),
            SystemTime::now(),
            &mut sent,
        );
        line.insert("published_files".into(), json!(sent.files));
        match r.map_err(at("pointers"))? {
            Retry::Confirmed => {
                line.insert("retried".into(), json!(stuck[0]));
                return Ok(());
            }
            // It cannot be made the head (stale, or the mirror's head
            // reaches another block): one new snapshot is let in, so a
            // producer whose pointer writes failed for a day or two
            // recovers on its own once they work again.
            Retry::Skipped(why) => {
                line.insert("retry_skipped".into(), json!(why));
            }
        }
    }

    // The finality update naming our block is served for one epoch only;
    // watch from now so a slow fetch cannot miss it.
    let watch = FinalityWatch::start(&args.beacon, Duration::from_secs(args.poll_secs));

    // 1. Fetch at the boundary.
    let t = Instant::now();
    let cfg = FetchConfig {
        prefix: parse_prefix(&args.prefix).map_err(at("fetch"))?,
        peers: args.peers,
        timeout: Duration::from_secs(args.timeout_secs),
        udp_port: args.udp_port,
        pivot_at: Some(target),
        max_wall: Duration::from_secs(target.saturating_sub(now_secs()) + args.max_fetch_secs),
        ..Default::default()
    };
    let slice = fetch_blocking(cfg).map_err(at("fetch"))?;
    let h = &slice.head;
    let fetch_done_ms = now_ms();
    line.insert("block_number".into(), json!(h.block_number));
    line.insert("block_hash".into(), json!(h.block_hash));
    line.insert("block_timestamp".into(), json!(h.timestamp));
    if h.pivot_set_ms > 0 {
        line.insert(
            "pivot_latency_secs".into(),
            json!(secs(Duration::from_millis(
                h.pivot_set_ms.saturating_sub(target * 1000)
            ))),
        );
        line.insert(
            "transfer_secs".into(),
            json!(secs(Duration::from_millis(
                fetch_done_ms.saturating_sub(h.pivot_set_ms)
            ))),
        );
    }
    line.insert("fetch_secs".into(), json!(secs(t.elapsed())));
    line.insert("peers".into(), json!(h.peers_used));
    line.insert("repivots".into(), json!(h.repivots));
    line.insert("requests".into(), json!(h.requests));
    line.insert("bytes_in".into(), json!(h.bytes_in));
    line.insert("accounts".into(), json!(h.accounts));
    line.insert("slots".into(), json!(h.storage_slots));
    line.insert("codes".into(), json!(h.codes));
    let slice_name = format!("{}-{}", h.block_number, &hex::encode(h.block_hash)[..8]);
    slice
        .write(&work.slices.join(&slice_name))
        .map_err(|e| Failed {
            step: "fetch",
            error: format!("writing the slice: {e}"),
        })?;

    // 2. Build into the mirror.
    let t = Instant::now();
    let produced = produce_with(
        &work.bucket,
        &slice.produce_head(),
        &slice.head.prefix,
        slice.leaves(),
        &slice.code,
        ProduceOptions {
            epsilon: args.epsilon,
            boundary: slice.boundary.clone(),
        },
    )
    .map_err(|e| Failed {
        step: "build",
        error: e.to_string(),
    })?;
    line.insert("build_secs".into(), json!(secs(t.elapsed())));

    // 3. Finality names our block.
    let t = Instant::now();
    let deadline = Instant::now()
        + Duration::from_secs((target + args.finality_wait_secs).saturating_sub(now_secs()));
    let finality = watch
        .wait_for(h.block_hash, h.block_number, deadline)
        .map_err(at("finality"))?;
    drop(watch);
    let fin = finalized_of(&finality).map_err(at("finality"))?;
    line.insert("finality_wait_secs".into(), json!(secs(t.elapsed())));
    line.insert(
        "finalized_after_boundary_secs".into(),
        json!(now_secs().saturating_sub(target)),
    );
    line.insert("finalized_slot".into(), json!(fin.slot));

    // 4. Head files in the mirror.
    let t = Instant::now();
    let mut head = head_files(args, work, state, &finality).map_err(at("head"))?;
    line.insert("head_secs".into(), json!(secs(t.elapsed())));
    line.insert("updates_fetched".into(), json!(head.fetched));

    // 5. Verify as a client would. The head files fetched this cycle are
    // kept (and an update marked final) only if it passes, and only those
    // it read.
    let (v, read) = match verify(args, work, &slice, &produced.manifest) {
        Ok(v) => v,
        Err(e) => {
            head.discard(work, state);
            return Err(Failed {
                step: "verify",
                error: e,
            });
        }
    };
    head.commit(work, state, read).map_err(at("verify"))?;
    line.insert("verify".into(), v);

    // 6. Publish in order.
    let t = Instant::now();
    let mut sent = Sent { files: 0, bytes: 0 };
    let r = publish(
        work,
        state,
        publisher,
        &slice,
        target,
        &slice_name,
        &head,
        args.publish_parallel,
        pending_grace(Duration::from_secs(args.publish_timeout_secs)),
        &mut sent,
    );
    line.insert("publish_secs".into(), json!(secs(t.elapsed())));
    line.insert("published_files".into(), json!(sent.files));
    line.insert("published_bytes".into(), json!(sent.bytes));
    r.map_err(at("publish"))
}

/// What step 4 laid out, not yet trusted: until the cycle's verification
/// passes, nothing fetched is marked final, and on failure it is removed.
struct HeadFiles {
    /// Periods fetched from the beacon node this cycle.
    fetched: Vec<u64>,
    /// The update periods laid out: the checkpoint's through current.
    first: u64,
    current: u64,
    /// The update periods verification read and checked, `b..s`; empty
    /// until it passes. Only these are kept, marked final and published.
    verified: std::ops::Range<u64>,
    /// The mirror's bootstrap is not yet trusted: fetched this cycle, or
    /// left by a cycle that never published it (one that failed, or
    /// crashed between fetching and verifying). Removed on failure.
    untrusted_bootstrap: bool,
    /// The mirror's `head/finality` before this cycle, restored on failure.
    old_finality: Option<Vec<u8>>,
}

impl HeadFiles {
    /// Verification passed, having read and checked the updates for
    /// `verified` (`b..s`): one of those fetched this cycle is final from
    /// now on (its period closed before `s` was signed). One fetched for
    /// `s` or later was not read, so nothing vouches for it: it is removed
    /// from the mirror, not marked final, and the next cycle fetches it
    /// again, until a head signed after its period reads it.
    fn commit(
        &mut self,
        work: &Work,
        state: &mut State,
        verified: std::ops::Range<u64>,
    ) -> Result<(), String> {
        for &p in &self.fetched {
            if verified.contains(&p) {
                state.updates_final_local.insert(p);
            } else {
                let _ = fs::remove_file(work.bucket.join(paths::update(p)));
                state.updates_final_local.remove(&p);
            }
        }
        self.verified = verified;
        state.save(&work.root)
    }

    /// Verification failed (or step 4 did): remove what this cycle fetched,
    /// so the next one fetches it again, and put the mirror's
    /// `head/finality` back.
    fn discard(&self, work: &Work, state: &mut State) {
        for &p in &self.fetched {
            let _ = fs::remove_file(work.bucket.join(paths::update(p)));
            state.updates_final_local.remove(&p);
        }
        if self.untrusted_bootstrap {
            let _ = fs::remove_file(work.bucket.join(paths::bootstrap(&state.checkpoint)));
        }
        let fin = work.bucket.join(paths::FINALITY);
        let _ = match &self.old_finality {
            Some(b) => write_atomic(&fin, b),
            None => fs::remove_file(&fin).map_err(|e| e.to_string()),
        };
        let _ = state.save(&work.root);
    }
}

fn head_files(
    args: &Args,
    work: &Work,
    state: &mut State,
    finality: &[u8],
) -> Result<HeadFiles, String> {
    let mut h = HeadFiles {
        fetched: Vec::new(),
        first: 0,
        current: 0,
        verified: 0..0,
        untrusted_bootstrap: false,
        old_finality: fs::read(work.bucket.join(paths::FINALITY)).ok(),
    };
    match lay_out_head(args, work, state, finality, &mut h) {
        Ok(()) => Ok(h),
        Err(e) => {
            h.discard(work, state);
            Err(e)
        }
    }
}

fn lay_out_head(
    args: &Args,
    work: &Work,
    state: &State,
    finality: &[u8],
    h: &mut HeadFiles,
) -> Result<(), String> {
    let chain = Chain::mainnet();
    let beacon = Beacon::new(&args.beacon);
    let bpath = work.bucket.join(paths::bootstrap(&args.checkpoint));
    // A bootstrap is published only after a cycle verified with it, so
    // one in the mirror but not published is on probation like a fresh one.
    let boot = match fs::read(&bpath) {
        Ok(b) => {
            h.untrusted_bootstrap = !state.bootstrap_published;
            b
        }
        Err(_) => {
            let (b, _) = beacon.bootstrap(args.checkpoint)?;
            write_atomic(&bpath, &b)?;
            h.untrusted_bootstrap = true;
            b
        }
    };
    let slot = serde_json::from_slice::<Value>(&boot)
        .ok()
        .and_then(|v| {
            v["data"]["header"]["beacon"]["slot"]
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
        })
        .ok_or("bootstrap without a slot")?;
    h.first = csl_eth_head::period_of(slot);
    h.current = csl_eth_head::period_of(csl_eth_head::current_slot(&chain, SystemTime::now()));
    let need = updates_to_fetch(state, h.first, h.current, |p| {
        work.bucket.join(paths::update(p)).exists()
    });
    if let (Some(&lo), Some(&hi)) = (need.first(), need.last()) {
        for u in beacon.updates(lo, hi)? {
            if !need.contains(&u.period) {
                continue;
            }
            h.fetched.push(u.period);
            write_atomic(&work.bucket.join(paths::update(u.period)), &u.bytes)?;
        }
    }
    write_atomic(&work.bucket.join(paths::FINALITY), finality)
}

/// The period updates to fetch: every period from `first` through
/// `current` whose local copy is missing, is the current period's (the
/// node improves it until the period ends), or was fetched before its
/// period closed; never one published final.
pub fn updates_to_fetch(
    state: &State,
    first: u64,
    current: u64,
    have: impl Fn(u64) -> bool,
) -> Vec<u64> {
    (first..=current)
        .filter(|p| {
            if state.updates.get(p).is_some_and(|u| u.is_final) && have(*p) {
                return false;
            }
            *p == current || !have(*p) || !state.updates_final_local.contains(p)
        })
        .collect()
}

/// The update periods `csl_eth_head::verify` reads from the mirror as of
/// `now`, `b..s`: the same files and clock give the same range it walked.
fn head_reads(
    work: &Work,
    checkpoint: B256,
    chain: &Chain,
    now: SystemTime,
) -> Result<std::ops::Range<u64>, String> {
    let file = |k: &str| fs::read(work.bucket.join(k)).map_err(|e| format!("{k}: {e}"));
    csl_eth_head::update_periods(
        &file(&paths::bootstrap(&checkpoint))?,
        &file(paths::FINALITY)?,
        checkpoint,
        chain,
        now,
    )
    .map_err(|e| e.to_string())
}

/// Step 5: the mirror verified as a client would see it once published.
/// Also returns the update periods the head's verification read, `b..s`.
fn verify(
    args: &Args,
    work: &Work,
    slice: &Slice,
    manifest: &csl_eth_store::Manifest,
) -> Result<(Value, std::ops::Range<u64>), String> {
    let now = SystemTime::now();
    let chain = Chain::mainnet();
    let head = csl_eth_head::verify(
        &DirSource(work.bucket.clone()),
        &chain,
        args.checkpoint,
        now,
    )
    .map_err(|e| e.to_string())?;
    let read = head_reads(work, args.checkpoint, &chain, now)?;
    if head.execution.block_hash != slice.head.block_hash {
        return Err(format!(
            "the head reaches block {} ({}), not ours ({})",
            head.execution.block_number, head.execution.block_hash, slice.head.block_hash
        ));
    }
    if head.execution.state_root != manifest.state_root {
        return Err(format!(
            "the head's state root {} is not the manifest's {}",
            head.execution.state_root, manifest.state_root
        ));
    }
    let (mut snap, _) = open_at_head(DirDriver::new(&work.bucket), args.checkpoint, now)
        .map_err(|e| e.to_string())?;
    let stride = (slice.accounts.len() / args.samples.max(1)).max(1);
    let (mut accounts, mut slots, mut codes) = (0u64, 0u64, 0u64);
    for (i, (h, a)) in slice.accounts.iter().enumerate().step_by(stride) {
        match snap.account(h).0 {
            Read::Verified(got) if got == *a => accounts += 1,
            other => return Err(format!("account {h}: {other:?}, expected {a:?}")),
        }
        if let Some((k, v)) = slice
            .storage
            .get(&a.storage_root)
            .and_then(|s| s.get(i % s.len().max(1)))
        {
            match snap.storage(h, k).0 {
                Read::Verified(got) if got == *v => slots += 1,
                other => return Err(format!("slot {h}/{k}: {other:?}, expected {v}")),
            }
        }
        if a.code_hash != KECCAK_EMPTY {
            match snap.code(&a.code_hash).0 {
                Read::Verified(c) if keccak256(&c) == a.code_hash => codes += 1,
                other => {
                    return Err(format!(
                        "code {}: {}",
                        a.code_hash,
                        match other {
                            Read::Verified(_) => "wrong bytes".to_string(),
                            o => format!("{o:?}"),
                        }
                    ))
                }
            }
        }
    }
    Ok((
        json!({
            "ok": true,
            "head_block": head.execution.block_number,
            "period": head.period,
            "participants": head.participants,
            "updates_applied": head.updates_applied,
            "finality_lag_secs": head.finality_lag_secs,
            "accounts": accounts,
            "slots": slots,
            "codes": codes,
        }),
        read,
    ))
}

/// Step 6. Each group goes up only after the one before it is all there,
/// and the state records each as it lands.
#[allow(clippy::too_many_arguments)]
fn publish(
    work: &Work,
    state: &mut State,
    p: &dyn Publish,
    slice: &Slice,
    boundary: u64,
    slice_name: &str,
    head: &HeadFiles,
    parallel: usize,
    pending_grace: u64,
    sent: &mut Sent,
) -> Result<(), String> {
    let hash = slice.head.block_hash;
    let dir = csl_eth_store::snapshot_dir(&hash);
    let mut runs: Vec<(String, PathBuf)> = Vec::new();
    for e in fs::read_dir(work.bucket.join(&dir)).map_err(|e| format!("{dir}: {e}"))? {
        let e = e.map_err(|e| e.to_string())?;
        let name = e.file_name().to_string_lossy().to_string();
        if name != MANIFEST_FILE && !name.ends_with(".tmp") {
            runs.push((format!("{dir}/{name}"), e.path()));
        }
    }
    runs.sort();
    let manifest_key = format!("{dir}/{MANIFEST_FILE}");
    let mut keys: Vec<String> = runs.iter().map(|(k, _)| k.clone()).collect();
    keys.push(manifest_key.clone());
    // Recorded before the first upload, so a failure part way leaves a
    // record for the collector.
    if !state.snapshots.iter().any(|s| s.block_hash == hash) {
        state.snapshots.push(SnapRec {
            block_hash: hash,
            block_number: slice.head.block_number,
            boundary,
            keys,
            complete: false,
            slice: slice_name.to_string(),
        });
        state.save(&work.root)?;
    }

    // The snapshot's run files, then its manifest.
    let (_, err) = put_many(p, &runs, parallel, sent);
    if let Some(e) = err {
        return Err(e);
    }
    put_one(p, &manifest_key, &work.bucket.join(&manifest_key), sent)?;

    // Blobs not yet in the bucket.
    let mut blobs: Vec<(String, PathBuf)> = Vec::new();
    if let Ok(rd) = fs::read_dir(work.bucket.join("blobs")) {
        for e in rd.flatten() {
            let key = format!("blobs/{}", e.file_name().to_string_lossy());
            if !key.ends_with(".tmp") && !state.blobs.contains(&key) {
                blobs.push((key, e.path()));
            }
        }
    }
    blobs.sort();
    let (up, err) = put_many(p, &blobs, parallel, sent);
    state.blobs.extend(up);
    state.save(&work.root)?;
    if let Some(e) = err {
        return Err(e);
    }

    // Head: the bootstrap once, then the updates verification read whose
    // bytes changed (all closed and final; later ones are not published).
    if !state.bootstrap_published {
        let key = paths::bootstrap(&state.checkpoint);
        put_one(p, &key, &work.bucket.join(&key), sent)?;
        state.bootstrap_published = true;
        state.save(&work.root)?;
    }
    publish_updates(work, state, p, head.verified.clone(), sent)?;
    publish_pointers(work, state, p, hash, pending_grace, sent)
}

/// The head updates of `periods` whose bytes are not yet in the bucket;
/// never one published final.
fn publish_updates(
    work: &Work,
    state: &mut State,
    p: &dyn Publish,
    periods: std::ops::Range<u64>,
    sent: &mut Sent,
) -> Result<(), String> {
    for period in periods {
        let key = paths::update(period);
        let file = work.bucket.join(&key);
        let Ok(bytes) = fs::read(&file) else {
            continue;
        };
        if state.updates.get(&period).is_some_and(|u| u.is_final) {
            continue;
        }
        let b3 = blake3::hash(&bytes).to_hex().to_string();
        let is_final = state.updates_final_local.contains(&period);
        if state.updates.get(&period).map(|u| &u.blake3) != Some(&b3) {
            put_one(p, &key, &file, sent)?;
        }
        state.updates.insert(
            period,
            PubUpdate {
                blake3: b3,
                is_final,
            },
        );
        state.save(&work.root)?;
    }
    Ok(())
}

/// `latest`, then the finality update that makes snapshot `hash` the head,
/// both from the mirror. The intent is journaled first: a write that fails
/// (or times out) may have landed, or land later, so the bucket may name
/// this snapshot, and collection must not delete it.
fn publish_pointers(
    work: &Work,
    state: &mut State,
    p: &dyn Publish,
    hash: B256,
    pending_grace: u64,
    sent: &mut Sent,
) -> Result<(), String> {
    let started = now_secs();
    state.pending.insert(hash, started);
    state.save(&work.root)?;
    put_one(p, LATEST_FILE, &work.bucket.join(LATEST_FILE), sent)?;
    state.latest = Some(hash);
    state.save(&work.root)?;
    put_one(p, paths::FINALITY, &work.bucket.join(paths::FINALITY), sent)?;
    state.finality = Some(hash);
    if let Some(s) = state.snapshots.iter_mut().find(|s| s.block_hash == hash) {
        s.complete = true;
    }
    state.save(&work.root)?;
    // Both pointers name this snapshot now, by writes that began at
    // `started`. An earlier pending write is overridden only if it could
    // no longer land after them; one that still could stays pending (this
    // cycle's own, too, until a later cycle confirms past its grace).
    release_pending(state, started, pending_grace);
    state.save(&work.root)
}

/// Snapshots waiting on pointer writes beyond which a cycle fetches none.
const MAX_UNRESOLVED: usize = 3;

/// Pending snapshots newer than the one `head/finality` is confirmed to
/// name, newest first: their pointer writes failed and no confirmed pair
/// has gone past them. (Pending ones older than it only wait out their
/// grace; the next confirmed pair releases them, and no more are added.)
pub fn unresolved_pending(state: &State) -> Vec<B256> {
    let confirmed = state
        .finality
        .and_then(|h| state.snapshots.iter().find(|s| s.block_hash == h))
        .map(|s| s.block_number);
    let mut out: Vec<(u64, B256)> = state
        .snapshots
        .iter()
        .filter(|s| state.pending.contains_key(&s.block_hash))
        .filter(|s| confirmed.is_none_or(|c| s.block_number > c))
        .map(|s| (s.block_number, s.block_hash))
        .collect();
    out.sort_by(|a, b| b.cmp(a));
    out.into_iter().map(|(_, h)| h).collect()
}

enum Retry {
    Confirmed,
    Skipped(String),
}

/// Write the pointers for pending snapshot `hash` again, as of `now`, if
/// the mirror's head still verifies to it. Everything else of it is in the
/// bucket already (a snapshot becomes pending only after the rest of its
/// cycle went up), and the mirror's head files are the ones its cycle
/// verified unless a later cycle replaced them, in which case the head no
/// longer reaches it. A head gone stale cannot be made the head at all.
#[allow(clippy::too_many_arguments)]
fn retry_pointers(
    work: &Work,
    state: &mut State,
    p: &dyn Publish,
    hash: B256,
    checkpoint: B256,
    pending_grace: u64,
    now: SystemTime,
    sent: &mut Sent,
) -> Result<Retry, String> {
    let chain = Chain::mainnet();
    let head = match csl_eth_head::verify(&DirSource(work.bucket.clone()), &chain, checkpoint, now)
    {
        Ok(h) => h,
        Err(e) => return Ok(Retry::Skipped(format!("the mirror's head: {e}"))),
    };
    if head.execution.block_hash != hash {
        return Ok(Retry::Skipped(format!(
            "the mirror's head is block {}, not the newest waiting, {hash}",
            head.execution.block_hash
        )));
    }
    let read = match head_reads(work, checkpoint, &chain, now) {
        Ok(r) => r,
        Err(e) => return Ok(Retry::Skipped(format!("the mirror's head: {e}"))),
    };
    publish_updates(work, state, p, read, sent)?;
    write_atomic(&work.bucket.join(LATEST_FILE), hex::encode(hash).as_bytes())?;
    publish_pointers(work, state, p, hash, pending_grace, sent)?;
    Ok(Retry::Confirmed)
}

struct Collected {
    deleted: Vec<String>,
    error: Option<String>,
}

/// Step 7: snapshots beyond `keep` and failed ones, from the bucket and the
/// mirror; built-but-unpublished snapshots and slices not kept, locally.
fn collect(work: &Work, state: &mut State, p: &dyn Publish, keep: usize) -> Collected {
    let mut out = Collected {
        deleted: Vec::new(),
        error: None,
    };
    for hash in gc_plan(state, keep) {
        let Some(i) = state.snapshots.iter().position(|s| s.block_hash == hash) else {
            continue;
        };
        let rec = state.snapshots[i].clone();
        // The manifest first, so a half-deleted snapshot is not one a
        // reader would try to open.
        let mut keys = rec.keys.clone();
        keys.sort_by_key(|k| !k.ends_with(MANIFEST_FILE));
        let mut failed = None;
        for k in &keys {
            match p.delete(k) {
                Ok(()) => out.deleted.push(k.clone()),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = failed {
            out.error = Some(e);
            break;
        }
        state.snapshots.remove(i);
        if let Err(e) = state.save(&work.root) {
            out.error = Some(e);
            break;
        }
    }
    // Locally: snapshot directories and slices nothing in the state keeps.
    let kept_dirs: BTreeSet<String> = state
        .snapshots
        .iter()
        .map(|s| hex::encode(s.block_hash))
        .collect();
    if let Ok(rd) = fs::read_dir(work.bucket.join("snapshots")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if e.path().is_dir() && !kept_dirs.contains(&name) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
    let kept_slices: BTreeSet<&str> = state.snapshots.iter().map(|s| s.slice.as_str()).collect();
    if let Ok(rd) = fs::read_dir(&work.slices) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if !kept_slices.contains(name.as_str()) {
                let _ = fs::remove_dir_all(e.path());
            }
        }
    }
    // The mirror's `latest` follows the bucket's.
    if let Some(h) = state.latest {
        let _ = write_atomic(&work.bucket.join(LATEST_FILE), hex::encode(h).as_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const G: u64 = 1_606_824_023;

    #[test]
    fn boundaries_are_epochs_from_genesis() {
        assert_eq!(boundary_at_or_after(G, G), G);
        assert_eq!(boundary_at_or_after(G, G + 1), G + EPOCH_SECS);
        assert_eq!(boundary_at_or_after(G, G + EPOCH_SECS), G + EPOCH_SECS);
        // Block 26,311,778's epoch boundary (2026-10-31).
        let b = boundary_at_or_after(G, 1_793_438_000);
        assert_eq!((b - G) % EPOCH_SECS, 0);
        assert!(b >= 1_793_438_000 && b < 1_793_438_000 + EPOCH_SECS);
    }

    #[test]
    fn the_next_target_leaves_lead_and_spacing() {
        let now = G + 1000 * EPOCH_SECS + 10;
        // Lead only: the next boundary at least 120 s away.
        let t = next_target(G, now, 120, None, 3600);
        assert_eq!(t, G + 1001 * EPOCH_SECS);
        let t = next_target(G, now, 380, None, 3600);
        assert_eq!(t, G + 1002 * EPOCH_SECS);
        // Spacing: an hour after the last published boundary.
        let last = G + 1000 * EPOCH_SECS;
        let t = next_target(G, now, 120, Some(last), 3600);
        assert_eq!(t, boundary_at_or_after(G, last + 3600));
        assert!(t - last >= 3600 && t - last < 3600 + EPOCH_SECS);
    }

    fn rec(n: u64, complete: bool) -> SnapRec {
        SnapRec {
            block_hash: B256::with_last_byte(n as u8),
            block_number: n,
            boundary: n,
            keys: vec![],
            complete,
            slice: format!("{n}"),
        }
    }

    #[test]
    fn gc_keeps_the_newest_and_never_the_head() {
        let mut s = State {
            snapshots: vec![
                rec(3, true),
                rec(1, true),
                rec(2, true),
                rec(4, true),
                rec(5, false),
            ],
            finality: Some(B256::with_last_byte(4)),
            latest: Some(B256::with_last_byte(4)),
            ..Default::default()
        };
        // Keep 2: delete 1 and 2 (oldest first). The failed 5 is the
        // newest, and stays until a newer one exists.
        assert_eq!(
            gc_plan(&s, 2),
            vec![B256::with_last_byte(1), B256::with_last_byte(2)]
        );
        // Keep 0 still never deletes what finality names.
        s.snapshots.retain(|r| r.complete);
        assert_eq!(
            gc_plan(&s, 0),
            vec![
                B256::with_last_byte(1),
                B256::with_last_byte(2),
                B256::with_last_byte(3)
            ]
        );
        // An incomplete snapshot `latest` names (a cycle that failed
        // between `latest` and `head/finality`) stays.
        s.snapshots.push(rec(6, false));
        s.latest = Some(B256::with_last_byte(6));
        assert!(!gc_plan(&s, 3).contains(&B256::with_last_byte(6)));
    }

    #[test]
    fn updates_fetched_are_the_missing_the_current_and_the_unclosed() {
        let mut s = State::default();
        let have = |p: u64| p != 1899;
        // 1898 local but fetched while open, 1899 missing, 1900 current.
        assert_eq!(
            updates_to_fetch(&s, 1898, 1900, have),
            vec![1898, 1899, 1900]
        );
        s.updates_final_local.insert(1898);
        assert_eq!(updates_to_fetch(&s, 1898, 1900, have), vec![1899, 1900]);
        // Published final: never again, even if the local copy were not.
        s.updates_final_local.clear();
        s.updates.insert(
            1898,
            PubUpdate {
                blake3: "x".into(),
                is_final: true,
            },
        );
        assert_eq!(updates_to_fetch(&s, 1898, 1900, have), vec![1899, 1900]);
        // The current period always.
        assert_eq!(
            updates_to_fetch(&s, 1898, 1898, |_| true),
            Vec::<u64>::new()
        );
        s.updates.clear();
        assert_eq!(updates_to_fetch(&s, 1898, 1898, |_| true), vec![1898]);
    }

    /// Records calls in order.
    struct Rec(std::sync::Mutex<Vec<String>>);

    impl Publish for Rec {
        fn put(&self, key: &str, _: &Path) -> Result<(), String> {
            self.0.lock().unwrap().push(format!("put {key}"));
            Ok(())
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            self.0.lock().unwrap().push(format!("delete {key}"));
            Ok(())
        }
    }

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "csl-eth-produce-{name}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn touch(root: &Path, rel: &str, body: &[u8]) {
        let p = root.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, body).unwrap();
    }

    fn fake_slice(n: u64) -> Slice {
        Slice {
            head: crate::SliceHead {
                block_hash: B256::with_last_byte(n as u8),
                block_number: n,
                timestamp: 0,
                state_root: B256::ZERO,
                prefix: "1".into(),
                fetched_at: 0,
                accounts: 0,
                storage_tries: 0,
                storage_slots: 0,
                codes: 0,
                peers_used: 0,
                bytes_in: 0,
                requests: 0,
                wall_ms: 0,
                repivots: 0,
                pivot_set_ms: 0,
            },
            accounts: vec![],
            storage: Default::default(),
            code: Default::default(),
            boundary: vec![],
        }
    }

    /// Lay out a built snapshot `n` and head files in the mirror.
    fn lay_out(w: &Work, n: u64, blobs: &[&str], updates: &[(u64, &[u8])]) {
        let h = B256::with_last_byte(n as u8);
        let dir = csl_eth_store::snapshot_dir(&h);
        for f in ["account_nodes.run", "code.run", MANIFEST_FILE] {
            touch(&w.bucket, &format!("{dir}/{f}"), f.as_bytes());
        }
        for b in blobs {
            touch(&w.bucket, &format!("blobs/{b}"), b.as_bytes());
        }
        for (p, body) in updates {
            touch(&w.bucket, &paths::update(*p), body);
        }
        touch(&w.bucket, LATEST_FILE, hex::encode(h).as_bytes());
        touch(&w.bucket, paths::FINALITY, b"fin");
        fs::create_dir_all(w.slices.join(format!("{n}"))).unwrap();
    }

    #[test]
    fn publish_order_and_what_a_restart_skips() {
        let root = tmp("order");
        let w = Work::new(&root).unwrap();
        let mut s = State {
            checkpoint: B256::repeat_byte(9),
            ..Default::default()
        };
        touch(&w.bucket, &paths::bootstrap(&s.checkpoint), b"boot");
        lay_out(&w, 1, &["aa", "bb"], &[(1898, b"u1898"), (1899, b"u1899")]);
        s.updates_final_local.insert(1898);
        let head = HeadFiles {
            fetched: vec![],
            first: 1898,
            current: 1899,
            verified: 1898..1900,
            untrusted_bootstrap: false,
            old_finality: None,
        };
        let rec = Rec(Default::default());
        let mut sent = Sent { files: 0, bytes: 0 };
        publish(
            &w,
            &mut s,
            &rec,
            &fake_slice(1),
            100,
            "1",
            &head,
            1,
            0,
            &mut sent,
        )
        .unwrap();
        let d = csl_eth_store::snapshot_dir(&B256::with_last_byte(1));
        let calls = rec.0.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                format!("put {d}/account_nodes.run"),
                format!("put {d}/code.run"),
                format!("put {d}/{MANIFEST_FILE}"),
                "put blobs/aa".into(),
                "put blobs/bb".into(),
                format!("put {}", paths::bootstrap(&s.checkpoint)),
                "put head/updates/1898".into(),
                "put head/updates/1899".into(),
                format!("put {LATEST_FILE}"),
                format!("put {}", paths::FINALITY),
            ]
        );
        assert_eq!(sent.files, 10);
        assert!(s.snapshots[0].complete);
        assert_eq!(s.finality, Some(B256::with_last_byte(1)));
        assert!(s.pending.is_empty(), "both pointers confirmed");
        // Reloaded from disk, as after a restart.
        let mut s = State::load(&root, B256::repeat_byte(9)).unwrap();
        assert!(s.updates[&1898].is_final && !s.updates[&1899].is_final);

        // The next cycle: one new blob, 1899 improved, 1898 final and
        // untouched, the bootstrap not again.
        lay_out(
            &w,
            2,
            &["cc"],
            &[(1898, b"u1898-changed"), (1899, b"u1899-better")],
        );
        let rec = Rec(Default::default());
        publish(
            &w,
            &mut s,
            &rec,
            &fake_slice(2),
            200,
            "2",
            &head,
            1,
            0,
            &mut sent,
        )
        .unwrap();
        let calls = rec.0.lock().unwrap().clone();
        let d2 = csl_eth_store::snapshot_dir(&B256::with_last_byte(2));
        assert_eq!(
            calls,
            vec![
                format!("put {d2}/account_nodes.run"),
                format!("put {d2}/code.run"),
                format!("put {d2}/{MANIFEST_FILE}"),
                "put blobs/cc".into(),
                "put head/updates/1899".into(),
                format!("put {LATEST_FILE}"),
                format!("put {}", paths::FINALITY),
            ]
        );

        // Keep 1: snapshot 1 goes, manifest first, from the bucket and the
        // mirror, with its slice; blobs stay.
        let rec = Rec(Default::default());
        let c = collect(&w, &mut s, &rec, 1);
        assert!(c.error.is_none());
        let calls = rec.0.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec![
                format!("delete {d}/{MANIFEST_FILE}"),
                format!("delete {d}/account_nodes.run"),
                format!("delete {d}/code.run"),
            ]
        );
        assert!(!w.bucket.join(&d).exists());
        assert!(w.bucket.join(&d2).exists());
        assert!(!w.slices.join("1").exists() && w.slices.join("2").exists());
        assert!(w.bucket.join("blobs/aa").exists());
        assert_eq!(s.snapshots.len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn gc_spares_pending_pointers_and_the_newest() {
        let mut s = State {
            snapshots: vec![rec(1, true), rec(2, true), rec(3, false), rec(4, false)],
            finality: Some(B256::with_last_byte(2)),
            latest: Some(B256::with_last_byte(2)),
            ..Default::default()
        };
        // 4 is the newest: kept even though incomplete; 3 goes.
        assert_eq!(
            gc_plan(&s, 0),
            vec![B256::with_last_byte(1), B256::with_last_byte(3)]
        );
        // A pointer write for 3 failed: it may be what the bucket names.
        s.pending.insert(B256::with_last_byte(3), 0);
        assert_eq!(gc_plan(&s, 0), vec![B256::with_last_byte(1)]);
    }

    #[test]
    fn pending_is_released_only_past_its_grace() {
        let (b, c, d) = (
            B256::with_last_byte(2),
            B256::with_last_byte(3),
            B256::with_last_byte(4),
        );
        // B's finality write timed out at t=0 and may still be in flight.
        let mut s = State {
            pending: [(b, 0)].into(),
            ..Default::default()
        };
        // C's pointers are confirmed by writes begun at t=600; B's request
        // could land after them, so B stays, and so does C.
        s.pending.insert(c, 600);
        release_pending(&mut s, 600, 3600);
        assert_eq!(s.pending.keys().collect::<Vec<_>>(), vec![&b, &c]);
        // D's, begun at t=3700, are past B's grace and not C's.
        s.pending.insert(d, 3700);
        release_pending(&mut s, 3700, 3600);
        assert_eq!(s.pending.keys().collect::<Vec<_>>(), vec![&c, &d]);
        assert_eq!(pending_grace(Duration::from_secs(300)), 3600);
        assert_eq!(pending_grace(Duration::from_secs(1800)), 7200);
    }

    #[test]
    fn a_state_file_with_bare_pending_hashes_loads() {
        let root = tmp("compat");
        fs::create_dir_all(&root).unwrap();
        let ck = B256::repeat_byte(9);
        let h = B256::with_last_byte(2);
        let mut v = serde_json::to_value(State {
            checkpoint: ck,
            ..Default::default()
        })
        .unwrap();
        // As written before the times were kept, and before `pending`.
        v["pending"] = json!([h]);
        fs::write(root.join("state.json"), v.to_string()).unwrap();
        let before = now_secs();
        let s = State::load(&root, ck).unwrap();
        assert!(s.pending[&h] >= before && s.pending[&h] <= now_secs());
        v.as_object_mut().unwrap().remove("pending");
        fs::write(root.join("state.json"), v.to_string()).unwrap();
        assert!(State::load(&root, ck).unwrap().pending.is_empty());
        // And the new form round-trips.
        let mut s = s;
        s.pending.insert(h, 7);
        s.save(&root).unwrap();
        assert_eq!(State::load(&root, ck).unwrap().pending[&h], 7);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unresolved_are_the_pending_past_the_confirmed_head() {
        let mut s = State {
            snapshots: (1..=7).map(|n| rec(n, n <= 3)).collect(),
            finality: Some(B256::with_last_byte(3)),
            ..Default::default()
        };
        // 2 waits out its grace behind the confirmed 3; 4 to 7 failed.
        for n in [2, 3, 4, 5, 6, 7] {
            s.pending.insert(B256::with_last_byte(n), 0);
        }
        let h = |n: u8| B256::with_last_byte(n);
        assert_eq!(unresolved_pending(&s), vec![h(7), h(6), h(5), h(4)]);
        s.finality = None;
        assert_eq!(unresolved_pending(&s).len(), 6);
    }

    /// The head crate's p1900 set: the producer's first published head.
    fn p1900(w: &Work) -> (B256, B256, u64, SystemTime) {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../head/tests/fixtures/p1900");
        let read = |f: &str| fs::read(format!("{dir}/{f}")).unwrap();
        let meta: Value = serde_json::from_slice(&read("meta.json")).unwrap();
        let checkpoint: B256 = meta["checkpoint"].as_str().unwrap().parse().unwrap();
        let now = UNIX_EPOCH + Duration::from_secs(meta["now"].as_u64().unwrap());
        touch(
            &w.bucket,
            &paths::bootstrap(&checkpoint),
            &read("bootstrap.json"),
        );
        for p in [1898, 1899, 1900] {
            touch(
                &w.bucket,
                &paths::update(p),
                &read(&format!("update-{p}.json")),
            );
        }
        let fin = read("finality.json");
        touch(&w.bucket, paths::FINALITY, &fin);
        let v: Value = serde_json::from_slice(&fin).unwrap();
        let ex = &v["data"]["finalized_header"]["execution"];
        let hash: B256 = ex["block_hash"].as_str().unwrap().parse().unwrap();
        let number: u64 = ex["block_number"].as_str().unwrap().parse().unwrap();
        (checkpoint, hash, number, now)
    }

    #[test]
    fn stuck_pointers_are_retried_for_the_newest_while_its_head_verifies() {
        let root = tmp("retry");
        let w = Work::new(&root).unwrap();
        let (checkpoint, hash, number, now) = p1900(&w);
        let rec_of = |h: B256, n: u64, complete: bool| SnapRec {
            block_hash: h,
            block_number: n,
            boundary: n,
            keys: vec![],
            complete,
            slice: format!("{n}"),
        };
        // Confirmed head 1; 2, 3 and 4 and then ours failed at a pointer.
        let mut s = State {
            checkpoint,
            bootstrap_published: true,
            snapshots: vec![
                rec_of(B256::with_last_byte(1), number - 40, true),
                rec_of(B256::with_last_byte(2), number - 30, false),
                rec_of(B256::with_last_byte(3), number - 20, false),
                rec_of(B256::with_last_byte(4), number - 10, false),
                rec_of(hash, number, false),
            ],
            finality: Some(B256::with_last_byte(1)),
            latest: Some(B256::with_last_byte(1)),
            ..Default::default()
        };
        for h in [2, 3, 4]
            .map(B256::with_last_byte)
            .into_iter()
            .chain([hash])
        {
            s.pending.insert(h, 0);
        }
        assert_eq!(unresolved_pending(&s).len(), 4);
        let rec = Rec(Default::default());
        let mut sent = Sent { files: 0, bytes: 0 };
        // Two periods on, the head is stale: nothing is written.
        let late = now + Duration::from_secs(2 * 8192 * 12);
        let r = retry_pointers(&w, &mut s, &rec, hash, checkpoint, 3600, late, &mut sent).unwrap();
        assert!(matches!(r, Retry::Skipped(ref e) if e.contains("stale")));
        assert!(rec.0.lock().unwrap().is_empty());
        // Still fresh: the updates it reads, then both pointers.
        let r = retry_pointers(&w, &mut s, &rec, hash, checkpoint, 3600, now, &mut sent).unwrap();
        assert!(matches!(r, Retry::Confirmed));
        assert_eq!(
            rec.0.lock().unwrap().clone(),
            vec![
                "put head/updates/1898".to_string(),
                "put head/updates/1899".into(),
                format!("put {LATEST_FILE}"),
                format!("put {}", paths::FINALITY),
            ]
        );
        assert_eq!(
            fs::read_to_string(w.bucket.join(LATEST_FILE)).unwrap(),
            hex::encode(hash)
        );
        assert_eq!((s.finality, s.latest), (Some(hash), Some(hash)));
        // The others' writes began long before: released, and no longer
        // stuck; ours stays pending until a later cycle confirms.
        assert_eq!(s.pending.keys().collect::<Vec<_>>(), vec![&hash]);
        assert!(unresolved_pending(&s).is_empty());
        // A head that reaches another block is not retried for this one.
        let r = retry_pointers(
            &w,
            &mut s,
            &rec,
            B256::with_last_byte(4),
            checkpoint,
            3600,
            now,
            &mut sent,
        )
        .unwrap();
        assert!(matches!(r, Retry::Skipped(ref e) if e.contains("not the newest")));
        let _ = fs::remove_dir_all(&root);
    }

    /// Fails `put` for one key.
    struct FailOn(&'static str, Rec);

    impl Publish for FailOn {
        fn put(&self, key: &str, file: &Path) -> Result<(), String> {
            if key == self.0 {
                return Err(format!("{key}: timed out"));
            }
            self.1.put(key, file)
        }
        fn delete(&self, key: &str) -> Result<(), String> {
            self.1.delete(key)
        }
    }

    #[test]
    fn a_failed_pointer_write_stays_protected_until_a_later_commit() {
        let root = tmp("pending");
        let w = Work::new(&root).unwrap();
        let mut s = State {
            checkpoint: B256::repeat_byte(9),
            ..Default::default()
        };
        touch(&w.bucket, &paths::bootstrap(&s.checkpoint), b"boot");
        let head = HeadFiles {
            fetched: vec![],
            first: 1898,
            current: 1898,
            verified: 1898..1899,
            untrusted_bootstrap: false,
            old_finality: None,
        };
        let mut sent = Sent { files: 0, bytes: 0 };
        let ok = Rec(Default::default());
        lay_out(&w, 1, &[], &[(1898, b"u")]);
        publish(
            &w,
            &mut s,
            &ok,
            &fake_slice(1),
            100,
            "1",
            &head,
            1,
            0,
            &mut sent,
        )
        .unwrap();
        // Cycle 2's finality write fails: it may or may not have landed.
        lay_out(&w, 2, &[], &[(1898, b"u")]);
        let fail = FailOn(paths::FINALITY, Rec(Default::default()));
        assert!(publish(
            &w,
            &mut s,
            &fail,
            &fake_slice(2),
            200,
            "2",
            &head,
            1,
            0,
            &mut sent
        )
        .is_err());
        let h2 = B256::with_last_byte(2);
        assert!(s.pending.contains_key(&h2));
        // Cycle 3 fails at `latest`: 2 and 3 both pending, across a restart.
        lay_out(&w, 3, &[], &[(1898, b"u")]);
        let fail = FailOn(LATEST_FILE, Rec(Default::default()));
        assert!(publish(
            &w,
            &mut s,
            &fail,
            &fake_slice(3),
            300,
            "3",
            &head,
            1,
            0,
            &mut sent
        )
        .is_err());
        let mut s = State::load(&root, B256::repeat_byte(9)).unwrap();
        let h3 = B256::with_last_byte(3);
        assert!(s.pending.contains_key(&h2) && s.pending.contains_key(&h3));
        // Collection with keep 0 deletes nothing a pointer may name.
        let c = collect(&w, &mut s, &Rec(Default::default()), 0);
        assert!(c.deleted.is_empty(), "{:?}", c.deleted);
        // Cycle 4 commits both pointers: 2 and 3 are fair game again.
        lay_out(&w, 4, &[], &[(1898, b"u")]);
        publish(
            &w,
            &mut s,
            &ok,
            &fake_slice(4),
            400,
            "4",
            &head,
            1,
            0,
            &mut sent,
        )
        .unwrap();
        assert!(s.pending.is_empty());
        assert_eq!(
            gc_plan(&s, 1),
            vec![
                B256::with_last_byte(1),
                B256::with_last_byte(2),
                B256::with_last_byte(3)
            ]
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn head_files_of_a_failed_cycle_are_discarded() {
        let root = tmp("discard");
        let w = Work::new(&root).unwrap();
        let mut s = State {
            checkpoint: B256::repeat_byte(9),
            ..Default::default()
        };
        touch(&w.bucket, &paths::bootstrap(&s.checkpoint), b"boot");
        touch(&w.bucket, &paths::update(1898), b"u1898 kept");
        touch(&w.bucket, &paths::update(1899), b"u1899 fetched");
        touch(&w.bucket, &paths::update(1900), b"u1900 fetched");
        touch(&w.bucket, paths::FINALITY, b"new");
        s.updates_final_local.insert(1898);
        let head = HeadFiles {
            fetched: vec![1899, 1900],
            first: 1898,
            current: 1900,
            verified: 0..0,
            untrusted_bootstrap: true,
            old_finality: Some(b"old".to_vec()),
        };
        head.discard(&w, &mut s);
        assert!(!w.bucket.join(paths::update(1899)).exists());
        assert!(!w.bucket.join(paths::update(1900)).exists());
        assert!(w.bucket.join(paths::update(1898)).exists());
        assert!(!w.bucket.join(paths::bootstrap(&s.checkpoint)).exists());
        assert_eq!(fs::read(w.bucket.join(paths::FINALITY)).unwrap(), b"old");
        // The next cycle fetches them again; 1899 was never marked final.
        let have = |p: u64| w.bucket.join(paths::update(p)).exists();
        assert_eq!(updates_to_fetch(&s, 1898, 1900, have), vec![1899, 1900]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn only_updates_the_head_read_are_kept_and_final() {
        let root = tmp("commit");
        let w = Work::new(&root).unwrap();
        let s = State {
            checkpoint: B256::repeat_byte(9),
            updates_final_local: [1898].into(),
            ..Default::default()
        };
        let fetched = |w: &Work| {
            touch(&w.bucket, &paths::update(1898), b"u1898 kept");
            touch(&w.bucket, &paths::update(1899), b"u1899 fetched");
            touch(&w.bucket, &paths::update(1900), b"u1900 fetched");
            HeadFiles {
                fetched: vec![1899, 1900],
                first: 1898,
                current: 1900,
                verified: 0..0,
                untrusted_bootstrap: false,
                old_finality: None,
            }
        };
        let have = |p: u64| w.bucket.join(paths::update(p)).exists();
        // Signed in 1900: verification read 1898 and 1899. 1899 is final;
        // 1900 was not read, so it is dropped and fetched again.
        let (mut s1, mut head) = (s.clone(), fetched(&w));
        head.commit(&w, &mut s1, 1898..1900).unwrap();
        assert_eq!(head.verified, 1898..1900);
        assert_eq!(s1.updates_final_local, [1898, 1899].into());
        assert!(!have(1900));
        assert_eq!(updates_to_fetch(&s1, 1898, 1900, have), vec![1900]);
        // The rollover: signed in 1899, prepared once 1900 began. 1899 is
        // closed and was fetched, but verification never read it: not
        // final, not kept, and fetched again until a head signed in 1900
        // reads it.
        let (mut s2, mut head) = (s.clone(), fetched(&w));
        head.commit(&w, &mut s2, 1898..1899).unwrap();
        assert_eq!(s2.updates_final_local, [1898].into());
        assert!(have(1898) && !have(1899) && !have(1900));
        assert_eq!(updates_to_fetch(&s2, 1898, 1900, have), vec![1899, 1900]);
        // Nor is it published.
        lay_out(&w, 1, &[], &[]);
        touch(&w.bucket, &paths::bootstrap(&s2.checkpoint), b"boot");
        let rec = Rec(Default::default());
        let mut sent = Sent { files: 0, bytes: 0 };
        publish(
            &w,
            &mut s2,
            &rec,
            &fake_slice(1),
            100,
            "1",
            &head,
            1,
            0,
            &mut sent,
        )
        .unwrap();
        let calls = rec.0.lock().unwrap().clone();
        assert!(calls.contains(&"put head/updates/1898".to_string()));
        assert!(!calls.iter().any(|c| c.contains("head/updates/1899")));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_publisher_past_its_deadline_is_killed() {
        let root = tmp("timeout");
        fs::create_dir_all(&root).unwrap();
        let script = root.join("slow.sh");
        // The child it starts holds stdout open: the group kill closes it.
        fs::write(&script, "#!/bin/sh\nsleep 30 &\nsleep 30\n").unwrap();
        fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let p = Program {
            program: script.to_string_lossy().into(),
            timeout: Duration::from_secs(1),
        };
        let t = Instant::now();
        let e = p.delete("k").unwrap_err();
        assert!(e.contains("killed"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        let ok = root.join("ok.sh");
        fs::write(&ok, "#!/bin/sh\necho fine\n").unwrap();
        fs::set_permissions(&ok, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let p = Program {
            program: ok.to_string_lossy().into(),
            timeout: Duration::from_secs(5),
        };
        p.delete("k").unwrap();
        let bad = root.join("bad.sh");
        fs::write(&bad, "#!/bin/sh\necho nope >&2\nexit 3\n").unwrap();
        fs::set_permissions(&bad, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let p = Program {
            program: bad.to_string_lossy().into(),
            timeout: Duration::from_secs(5),
        };
        let e = p.delete("k").unwrap_err();
        assert!(e.contains("nope"), "{e}");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_publisher_that_leaves_its_output_open_is_bounded() {
        let root = tmp("straggler");
        fs::create_dir_all(&root).unwrap();
        let pid = root.join("pid");
        // Exits at once, successfully, but its child holds stdout and
        // stderr for a day: the readers never see EOF on their own.
        let script = root.join("straggler.sh");
        fs::write(
            &script,
            format!(
                "#!/bin/sh\nsleep 86400 &\necho $! > {}\nexit 0\n",
                pid.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755)).unwrap();
        let p = Program {
            program: script.to_string_lossy().into(),
            timeout: Duration::from_secs(1),
        };
        let t = Instant::now();
        p.put("k", &script).unwrap();
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        // The straggler was killed with the group.
        let pid = fs::read_to_string(&pid).unwrap().trim().to_string();
        let gone = (0..100).any(|_| {
            let alive = Command::new("kill")
                .args(["-0", &pid])
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if alive {
                std::thread::sleep(Duration::from_millis(50));
            }
            !alive
        });
        assert!(gone, "sleep {pid} still running");
        // The same shape exiting nonzero is a failure, also bounded.
        fs::write(&script, "#!/bin/sh\nsleep 86400 &\necho nope >&2\nexit 4\n").unwrap();
        let t = Instant::now();
        let e = p.delete("k").unwrap_err();
        assert!(e.contains("nope"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn the_log_rotates_above_its_cap() {
        let root = tmp("log");
        let w = Work::new(&root).unwrap();
        fs::write(root.join("produce.log"), vec![b'x'; LOG_MAX as usize + 1]).unwrap();
        w.log(&json!({"ok": true}));
        assert_eq!(
            fs::metadata(root.join("produce.log.1")).unwrap().len(),
            LOG_MAX + 1
        );
        assert_eq!(
            fs::read_to_string(root.join("produce.log")).unwrap(),
            "{\"ok\":true}\n"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
