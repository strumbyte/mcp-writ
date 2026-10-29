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
//! delegated subtree or privilege); [`LifetimeCgroup::create_with_writer`]
//! returns `None` when the hierarchy is absent or unwritable, and the
//! caller falls back to the process-group + `/proc` sweep. Adoption
//! happens *in the child*: a `pre_exec` hook writes the child's own
//! pid into `cgroup.procs` before `execve` — membership can never be
//! outrun by an early `fork`, which the post-spawn `try_adopt` write
//! allowed. The parent verifies the join via `/proc/<pid>/cgroup`
//! ([`LifetimeCgroup::member`]); a failed best-effort join degrades to
//! the fallback with an honest `skipped` grant, while
//! `sandbox.require_lifetime_boundary` makes a failed or impossible
//! join refuse the launch. The fallback still names a reparented
//! descendant while it carries the launch's lineage marker; the
//! descendant that escapes it must leave the group, rewrite the
//! marker, and reparent — the residual is recorded on the launch
//! report's `process_lifetime` grant entry.

use std::fs::File;
use std::io;
use std::os::unix::io::AsRawFd;
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

/// Fail-closed overlap check between the policy's effective fs write
/// grants and the cgroup v2 hierarchy the private cgroup lives under.
///
/// A workload that can write `cgroup.procs` of a cgroup outside its
/// private subtree (`/sys/fs/cgroup` or an ancestor — `/sys`, `/`, or
/// any covering glob) migrates itself or a child out of the armed
/// boundary entirely. Any grant spelling covering the v2 root — or
/// inside it, where it could still name `cgroup.procs` or
/// `cgroup.subtree_control` of a sibling branch — conflicts. A
/// root-glob spelling (`/*`, `/**`) reduces to an empty base every
/// grant builder skips — it grants nothing and is skipped here too.
/// Any other unresolvable spelling conflicts: "cannot prove disjoint"
/// stays on the refuse side.
///
/// `write_grants` is the workload's effective write-grant spellings
/// (`Policy::write_grant_spellings`), enumerated by the caller so this
/// leaf does not depend on `policy` — the same leaf shape
/// `audit_log::sink_guard` uses. `escape_effect` names what the
/// boundary migration would break on the caller's route (e.g. "shed
/// the connect hooks" on `ebpf-run`, "escape the descendant-lifetime
/// boundary" on ordinary launches).
pub fn cgroup_write_grant_conflict(
    write_grants: impl IntoIterator<Item = String>,
    escape_effect: &str,
) -> Option<String> {
    let root = match crate::fsoverlap::resolve_grant_spelling(CGROUP_ROOT) {
        Some(r) => r,
        None => {
            return Some(format!("cannot resolve the cgroup v2 root '{CGROUP_ROOT}'"));
        }
    };
    for grant in write_grants {
        match crate::fsoverlap::resolve_grant_spelling(&grant) {
            Some(g) => {
                if crate::fsoverlap::path_covers(&g, &root)
                    || crate::fsoverlap::path_covers(&root, &g)
                {
                    return Some(format!(
                        "fs write grant '{grant}' (resolves to '{}') overlaps the cgroup v2 \
                         hierarchy at '{}' — a workload could move itself out of the \
                         enforced cgroup and {escape_effect}",
                        g.display(),
                        root.display()
                    ));
                }
            }
            None => {
                if crate::fsoverlap::reduces_to_empty_base(&grant) {
                    continue;
                }
                return Some(format!(
                    "fs write grant '{grant}' cannot be resolved against the cgroup v2 \
                     hierarchy — refusing rather than assuming disjoint"
                ));
            }
        }
    }
    None
}

fn mono_nanos() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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

    /// Create the private cgroup *before* spawn and return it with a
    /// pre-opened `cgroup.procs` write fd — the hand-off for in-child
    /// adoption (see [`Self::attach_join`] / `cgroup_procs` in
    /// `linux_spawn`). `None` when the v2 hierarchy is absent or
    /// unwritable: the caller falls back to the best-effort sweep.
    ///
    /// This closes the window the parent-side [`Self::try_adopt`]
    /// leaves open: a child writes its own pid in `pre_exec`, before
    /// `execve` runs the workload's first instruction, so no descendant
    /// can ever exist outside the subtree.
    pub(crate) fn create_with_writer(tag: &str) -> Option<(Self, File)> {
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            return None;
        }
        let cg = Self::create(tag).ok()?;
        match std::fs::OpenOptions::new()
            .write(true)
            .open(cg.dir.join("cgroup.procs"))
        {
            Ok(w) => Some((cg, w)),
            Err(_) => {
                // The drop-side rmdir removes the unused dir.
                None
            }
        }
    }

    /// Whether `pid` currently sits inside this cgroup subtree —
    /// the post-spawn verification that the child's pre-exec join
    /// write actually landed. Reads `/proc/<pid>/cgroup`, same shape
    /// as [`CgroupView::pid_is_member`].
    pub(crate) fn member(&self, pid: u32) -> bool {
        let Ok(body) = std::fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
            return false;
        };
        cgroup_body_covers(&self.dir, CGROUP_ROOT, &body)
    }

    /// Attach a `pre_exec` hook that moves the child into this cgroup
    /// before `execve` — the unsandboxed-route counterpart of the
    /// sandbox bits' `cgroup_procs` stage. `writer` is the
    /// [`Self::create_with_writer`] fd; `required` selects the failure
    /// contract: a failed join aborts the spawn under a policy that
    /// requires the boundary, and otherwise yields to the post-spawn
    /// [`Self::member`] check, which reports the unadopted launch
    /// honestly (`skipped` grant + fallback sweep).
    ///
    /// The `writer` fd must already exist when the arm's fd-hygiene
    /// snapshot runs so the child copy is CLOEXEC-sealed — it stays
    /// writable for the join and dies at `execve` (the workload must
    /// never inherit a `cgroup.procs` write fd).
    #[cfg(target_os = "linux")]
    pub(crate) fn attach_join(
        &self,
        cmd: &mut std::process::Command,
        writer: File,
        required: bool,
    ) {
        use std::os::unix::process::CommandExt;
        // Safety: the closure performs a single `write(2)` on a live
        // fd and returns a Result — async-signal-safe, no heap.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            cmd.pre_exec(
                move || match super::linux_spawn::write_self_pid(writer.as_raw_fd()) {
                    Err(e) if required => Err(e),
                    _ => Ok(()),
                },
            );
        }
    }

    /// Tokio variant of [`Self::attach_join`].
    #[cfg(target_os = "linux")]
    pub(crate) fn attach_join_tokio(
        &self,
        cmd: &mut tokio::process::Command,
        writer: File,
        required: bool,
    ) {
        // Safety: same contract as `attach_join`.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            cmd.pre_exec(
                move || match super::linux_spawn::write_self_pid(writer.as_raw_fd()) {
                    Err(e) if required => Err(e),
                    _ => Ok(()),
                },
            );
        }
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
                        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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

#[cfg(test)]
mod tests {
    use super::*;

    fn grants(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn grant_covering_the_hierarchy_root_conflicts() {
        // Write access to the v2 root itself names every
        // `cgroup.procs` — including a parent's — so the workload can
        // migrate itself out of its private subtree.
        for spelling in ["/sys/fs/cgroup", "/sys", "/"] {
            let conflict = cgroup_write_grant_conflict(grants(&[spelling]), "test escape");
            assert!(
                conflict.is_some(),
                "grant '{spelling}' covering the hierarchy must conflict"
            );
        }
    }

    #[test]
    fn grant_inside_the_hierarchy_conflicts() {
        // A grant *under* the root reaches a sibling branch's
        // `cgroup.procs` / `cgroup.subtree_control` just as surely as
        // a covering grant does.
        for spelling in [
            "/sys/fs/cgroup/user.slice",
            "/sys/fs/cgroup/mcp-writ-other-1",
        ] {
            let conflict = cgroup_write_grant_conflict(grants(&[spelling]), "test escape");
            assert!(
                conflict.is_some(),
                "grant '{spelling}' inside the hierarchy must conflict"
            );
        }
    }

    #[test]
    fn disjoint_grant_is_clean() {
        let conflict = cgroup_write_grant_conflict(
            grants(&["/nonexistent-mcp-writ-test-workdir"]),
            "test escape",
        );
        assert!(conflict.is_none());
    }

    #[test]
    fn root_glob_grants_nothing_and_stays_clean() {
        // `/*`, `/**` reduce to an empty base every grant builder
        // skips — they must not trip the conflict check.
        for spelling in ["/*", "/**", "/*/*"] {
            let conflict = cgroup_write_grant_conflict(grants(&[spelling]), "test escape");
            assert!(
                conflict.is_none(),
                "root glob '{spelling}' grants nothing and must not conflict"
            );
        }
    }

    #[test]
    fn unresolvable_spelling_stays_on_the_refuse_side() {
        // A mid-path wildcard cannot be proven disjoint from the
        // hierarchy — the conflict check refuses rather than assume.
        let conflict = cgroup_write_grant_conflict(grants(&["/sys/*/grant"]), "test escape");
        assert!(conflict.is_some());
    }

    #[test]
    fn empty_grant_list_never_conflicts() {
        assert!(cgroup_write_grant_conflict(Vec::new(), "test escape").is_none());
    }

    #[test]
    fn conflict_message_names_the_escape_effect() {
        let conflict = cgroup_write_grant_conflict(grants(&["/sys"]), "shed the connect hooks")
            .expect("a covering grant must conflict");
        assert!(conflict.contains("shed the connect hooks"));
    }
}
