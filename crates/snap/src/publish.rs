//! Where uploads go: the [`Publish`] trait the tracker writes through, and
//! [`Program`], an external publisher (`scripts/gcs-publish.sh`) called
//! once per file with a deadline.

use std::{
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

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
    fn run(&self, args: &[&std::ffi::OsStr], timeout: Duration) -> Result<(), String> {
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
        let deadline = Instant::now() + timeout;
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
                timeout.as_secs()
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

/// The slowest upload rate a put is allowed, bytes a second: about five
/// times under the 40 to 80 MB/s one stream gets from the VM to the bucket.
/// `scripts/gcs-publish.sh` gives each try the same allowance.
pub const PUT_FLOOR_RATE: u64 = 10_000_000;

/// How long a put of `bytes` may take: the fixed deadline plus three tries'
/// worth of transfer at [`PUT_FLOOR_RATE`] (the script retries twice). The
/// fixed deadline alone capped a file at about 12 GB.
pub fn put_timeout(base: Duration, bytes: u64) -> Duration {
    base + Duration::from_secs(3 * (bytes / PUT_FLOOR_RATE))
}

impl Publish for Program {
    fn put(&self, key: &str, file: &Path) -> Result<(), String> {
        let bytes = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
        self.run(
            &["put".as_ref(), key.as_ref(), file.as_os_str()],
            put_timeout(self.timeout, bytes),
        )
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        self.run(&["delete".as_ref(), key.as_ref()], self.timeout)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    fn tmp(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "csl-eth-publish-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn a_put_deadline_grows_with_the_file() {
        let base = Duration::from_secs(300);
        assert_eq!(put_timeout(base, 0), base);
        assert_eq!(put_timeout(base, 9_999_999), base);
        // 12 GB, the old cap at 50 MB/s: 3 tries of 1,200 s each on top.
        assert_eq!(
            put_timeout(base, 12_000_000_000),
            Duration::from_secs(300 + 3_600)
        );
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
}
