//! Per-launch lifetime boundary — a private cgroup v2 subtree every
//! launch descendant is pinned into.
//!
//! cgroup membership is inherited across `fork`/`exec`/`setsid` and
//! survives reparenting: a detached daemon or orphaned worker cannot
//! leave the subtree from inside the sandbox (migrating out requires
//! write access to a *different* cgroup's `cgroup.procs`, which the
//! Landlock fs boundary and the `cgroup_write_grant_conflict` launch
//! check withhold). Teardown SIGKILLs every member — `cgroup.kill`
//! (kernel ≥ 5.14) atomically, else a freeze + per-pid sweep — so no
//! descendant can outlive the session the way a group-escaped process
//! escapes `kill(-pgid)`.
//!
//! Creating the subtree needs write access to the v2 hierarchy (a
//! delegated subtree or privilege); [`LifetimeCgroup::try_adopt`]
//! returns `None` when the hierarchy is absent or unwritable, and the
//! caller falls back to the process-group + `/proc` sweep. That
//! fallback cannot reach a descendant that already left the group and
//! reparented — the residual is recorded on the launch report's
//! `process_lifetime` grant entry.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// cgroup v2 root the private cgroup is created under.
pub(crate) const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// A shareable view onto the cgroup directory — cloneable (the sweep
/// needs only the path), so a blocking wait thread and the async
/// teardown can both sweep the same subtree while the owner keeps the
/// dir fd and the drop-side rmdir.
#[derive(Clone)]
pub(crate) struct CgroupView {
    pub(crate) dir: PathBuf,
}

/// The private cgroup — removed on drop. Members still alive at
/// teardown are SIGKILLed by the caller before the rmdir (see
/// [`CgroupView::kill_members`]); the directory only outlives the
/// workload when a member's reaping outruns the rmdir window or the
/// supervisor itself dies abruptly — a documented residue, not a leak.
pub(crate) struct LifetimeCgroup {
    pub(crate) dir: PathBuf,
    /// Open dir fd — the eBPF route attaches its programs to it; kept
    /// open by every holder so the object stays addressable.
    pub(crate) fd: File,
}

/// `true` when a `/proc/<pid>/cgroup` body places the pid inside
/// `dir`'s subtree. The file names cgroups by their path from the
/// reader's v2 root — `0::/mcp-writ-…` — so `dir`'s filesystem
/// spelling under `root` is re-rooted (a leading `/`) before
/// comparing; a cgroup-namespace view that does not match simply
/// reports non-membership — the pid is never signaled.
pub(crate) fn cgroup_body_covers(dir: &Path, root: &str, body: &str) -> bool {
    let rooted = match dir.strip_prefix(root) {
        Ok(rel) => format!("/{}", rel.to_string_lossy()),
        Err(_) => dir.to_string_lossy().into_owned(),
    };
    body.lines().any(|line| {
        line.strip_prefix("0::")
            .map(|p| p == rooted || p.starts_with(&format!("{rooted}/")))
            .unwrap_or(false)
    })
}

fn mono_nanos() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

impl LifetimeCgroup {
    /// Create `/sys/fs/cgroup/mcp-writ-<tag>-<pid>-<nonce>` and open it.
    pub(crate) fn create(tag: &str) -> io::Result<Self> {
        let nonce = format!("mcp-writ-{tag}-{}-{}", std::process::id(), mono_nanos());
        let dir = Path::new(CGROUP_ROOT).join(nonce);
        std::fs::create_dir(&dir)?;
        match File::open(&dir) {
            Ok(fd) => Ok(Self { dir, fd }),
            Err(e) => {
                let _ = std::fs::remove_dir(&dir);
                Err(e)
            }
        }
    }

    /// Move `pid` into this cgroup via a parent-side `cgroup.procs`
    /// write. Membership then covers the whole descendant tree — no
    /// pre_exec cooperation needed.
    pub(crate) fn adopt(&self, pid: u32) -> io::Result<()> {
        std::fs::write(self.dir.join("cgroup.procs"), pid.to_string())
    }

    /// Create a private cgroup and move `pid` into it, or `None` when
    /// the v2 hierarchy is absent, unwritable, or rejects the join —
    /// the caller falls back to the process-group sweep and reports
    /// the lifetime boundary as unarmed rather than pretending it
    /// exists.
    pub(crate) fn try_adopt(tag: &str, pid: u32) -> Option<Self> {
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            return None;
        }
        let cg = Self::create(tag).ok()?;
        if cg.adopt(pid).is_ok() {
            Some(cg)
        } else {
            // Nothing joined — the drop-side rmdir removes the dir.
            None
        }
    }

    /// A cloneable sweep handle for the same subtree.
    pub(crate) fn view(&self) -> CgroupView {
        CgroupView {
            dir: self.dir.clone(),
        }
    }

    pub(crate) fn member_pids(&self) -> Vec<i32> {
        self.view().member_pids()
    }

    /// See [`CgroupView::kill_members`].
    pub(crate) fn kill_members(&self) -> usize {
        self.view().kill_members()
    }
}

impl CgroupView {
    /// Every pid listed by `cgroup.procs` under `dir`, recursing into
    /// descendant cgroups (a workload with write access could have
    /// created sub-cgroups and moved into one — enforcement applies
    /// to the subtree, so the sweep must too).
    fn collect_pids(dir: &Path, out: &mut Vec<i32>, depth: usize) {
        if depth > 16 {
            return;
        }
        if let Ok(body) = std::fs::read_to_string(dir.join("cgroup.procs")) {
            out.extend(body.lines().filter_map(|l| l.trim().parse::<i32>().ok()));
        }
        if let Ok(rd) = std::fs::read_dir(dir) {
            for e in rd.flatten() {
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    Self::collect_pids(&e.path(), out, depth + 1);
                }
            }
        }
    }

    pub(crate) fn member_pids(&self) -> Vec<i32> {
        let mut v = Vec::new();
        Self::collect_pids(&self.dir, &mut v, 0);
        v
    }

    /// Whether `pid` still sits inside this cgroup subtree — checked
    /// right before each per-pid kill in the `cgroup.kill`-less
    /// fallback. The roster read and the signal are two syscalls, so
    /// a member can exit and its pid be recycled mid-sweep; without
    /// the re-check a recycled pid could deliver SIGKILL to an
    /// unrelated process. A pid reused *by another member* still
    /// matches and is correctly killed.
    fn pid_is_member(&self, pid: i32) -> bool {
        let Ok(body) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
            return false;
        };
        cgroup_body_covers(&self.dir, CGROUP_ROOT, &body)
    }

    /// SIGKILL every still-live member, returning how many *remain*
    /// listed after the bounded sweep (0 = clean).
    ///
    /// A descendant that outlived the supervised child (a setsid'd
    /// daemon, an orphaned worker) is still a cgroup member and still
    /// owned — the group kill cannot reach it but this sweep does.
    ///
    /// `cgroup.kill` (kernel ≥ 5.14) kills the whole subtree
    /// atomically; kernels without it take the freeze + per-pid
    /// fallback — freeze so the roster cannot grow mid-sweep, SIGKILL
    /// the members in one pass, then thaw immediately (a SIGKILLed
    /// member stays dead; holding the freeze would only delay the
    /// reap). The roster is then polled briefly — a just-killed
    /// member stays listed until its parent or init reaps it — and a
    /// non-empty roster triggers one more pass: a member whose kill
    /// raced a roster read, or a pid the first pass skipped, is
    /// caught by the second. Members still listed after that are
    /// either alive or zombies mid-reap; the caller must not detach
    /// beneath either.
    pub(crate) fn kill_members(&self) -> usize {
        if self.member_pids().is_empty() {
            return 0;
        }
        let cgroup_kill = std::fs::write(self.dir.join("cgroup.kill"), b"1").is_ok();
        for _ in 0..2 {
            if !cgroup_kill {
                // No cgroup.kill (kernel < 5.14): freeze so the
                // roster cannot grow mid-sweep, SIGKILL the members
                // in one pass, and thaw right away — the wait loop
                // below lets the roster drain.
                let freeze = self.dir.join("cgroup.freeze");
                let frozen = std::fs::write(&freeze, b"1").is_ok();
                for pid in self.member_pids() {
                    // Safety: signal by pid; membership is re-verified
                    // so a recycled pid cannot hit an unrelated
                    // process, and ESRCH on an exited member is the
                    // normal race here.
                    if self.pid_is_member(pid) {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                }
                if frozen {
                    let _ = std::fs::write(&freeze, b"0");
                }
            }
            // Wait (bounded) for the killed members to leave the
            // roster so the rmdir below does not lose to a reaping
            // delay.
            for _ in 0..100 {
                if self.member_pids().is_empty() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if self.member_pids().is_empty() {
                break;
            }
        }
        self.member_pids().len()
    }
}

impl Drop for LifetimeCgroup {
    fn drop(&mut self) {
        // Just-killed members can take a moment to be reaped out of
        // the roster — retry briefly before leaving a residue dir.
        // Members still listed make every rmdir an EBUSY, so the
        // retry stops early rather than spinning the full window.
        for _ in 0..50 {
            if std::fs::remove_dir(&self.dir).is_ok() {
                return;
            }
            if !self.member_pids().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}
