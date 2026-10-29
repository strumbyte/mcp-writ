//! Process-tree teardown primitives behind the child lifecycle: the
//! group SIGKILL and the descendant sweep that reaches processes which
//! escaped the launch's process group (`setpgid`/`setsid`/reparenting).

/// Lineage marker stamped into every unix launch's environment
/// (`apply_unix_process_group*`): workload descendants inherit it, so
/// an orphaned process reparented onto this guard can be attributed to
/// *a* launch tree even after escaping its process group (`setsid`) —
/// the signal `pgid` alone cannot give for an escapee whose group is
/// itself. The value is the launch's unique tag (see [`launch_tag`]),
/// registered beside the leader pid, so attribution names *this*
/// teardown's session exactly — a sibling session's tagged children
/// never match. Deliberately absent from `GUARD_ENV_VARS`: the marker
/// must survive into workload children — its value is the attribution.
#[cfg(target_os = "linux")]
pub(super) const SPAWN_TAG: &str = "MCP_WRIT_SPAWN_TAG";

/// Unique-per-launch lineage tag stamped into the workload environment
/// and registered beside the leader pid. Uniqueness within this guard
/// process is all the attribution needs — a workload that copies its
/// own tag onto a daemon only keeps that daemon attributable (killed
/// by its own session's teardown), and it cannot learn another
/// session's value from anything this code publishes. A counter is
/// therefore sufficient; guesses and forgeries cannot spare or doom
/// anything.
#[cfg(target_os = "linux")]
pub(super) fn launch_tag() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[cfg(unix)]
pub(super) fn kill_unix_process_group(pgid: u32) {
    // `kill(0)` signals *this* process's own group — a pgid that never
    // materialized must not reach the call.
    if pgid == 0 {
        return;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let _ = unsafe { libc::kill(-(pgid as i32), libc::SIGKILL) };
}

/// Arm `PR_SET_CHILD_SUBREAPER` on this guard process: a workload
/// descendant orphaned after its launch leader died reparents to *us*
/// instead of init — the scoped sweep under [`kill_orphan_descendants`]
/// can then still name it. (Orphans created *while the leader lives*
/// reparent to the leader instead, which is armed as a subreaper in
/// `pre_exec`, keeping them inside that launch's own tree.) Without
/// either arm — and without a lifetime cgroup — a `setsid`'d survivor
/// is parented to init and unreachable. Idempotent; armed at each unix
/// workload spawn. The closest userspace equivalent does not exist on
/// macOS — that platform keeps the reparented-orphan residual the
/// group kill alone cannot cover.
#[cfg(target_os = "linux")]
pub(super) fn arm_child_subreaper() {
    // Safety: prctl with these args takes no pointers and cannot fail
    // in a harmful way — the return is ignored deliberately.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let _ = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
}

/// Live descendants of `root_pid` by ppid links — a snapshot the
/// caller signals itself. Taken while the leader is still up, a
/// `setsid`/`setpgid` escapee is still parent-linked and reachable:
/// the group kill cannot name it and a post-mortem walk finds it
/// already reparented. Descendants forked *after* this snapshot are
/// outside the set — `kill_orphan_descendants` is the Linux follow-up
/// for them.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn collect_proc_descendants(root_pid: u32) -> Vec<u32> {
    let children_of = children_of_all(root_pid);
    let mut out = Vec::new();
    let mut pending = vec![root_pid];
    while let Some(parent) = pending.pop() {
        let Some(kids) = children_of.get(&parent) else {
            continue;
        };
        for &kid in kids {
            out.push(kid);
            pending.push(kid);
        }
    }
    out
}

/// Best-effort SIGKILL of each pid in `pids`. Pids that exited between
/// the snapshot and this call simply fail `ESRCH`.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn kill_pids(pids: &[u32]) {
    for &pid in pids {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
    }
}

/// Best-effort SIGKILL of every live descendant of `root_pid` —
/// snapshot + signal in one, for callers running when the leader may
/// already be gone (processes that escaped the child's process group
/// via `setpgid`/`setsid` while still parent-linked). On Linux,
/// descendants orphaned *before* this runs are picked up by the
/// `kill_orphan_descendants` follow-up; on macOS they remain a
/// documented residual the group kill is the only reach for.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn kill_proc_descendants(root_pid: u32) {
    kill_pids(&collect_proc_descendants(root_pid));
}

/// Live launch leaders this guard still supervises, each with the
/// lineage [`launch_tag`] stamped into its workload environment. A pid
/// enters at spawn and leaves at teardown, so the orphan sweep can
/// tell "another session's leader" apart from a workload process that
/// reparented onto us via `PR_SET_CHILD_SUBREAPER` — and can attribute
/// a tagged orphan to *this* session by comparing the marker value,
/// not merely its presence.
#[cfg(target_os = "linux")]
static LIVE_LAUNCH_ROOTS: std::sync::LazyLock<
    std::sync::Mutex<std::collections::HashMap<u32, u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Register a leader already spawned outside [`spawn_and_register`]
/// (test helpers, `StdChild::spawned`'s redundant re-register). An
/// existing entry keeps its real tag — a `0` re-registration never
/// erases attribution, it only marks "registered, tag unknown" for a
/// leader that genuinely lacks one.
#[cfg(target_os = "linux")]
pub(super) fn register_launch_root(pid: u32, tag: u64) {
    let _ = LIVE_LAUNCH_ROOTS.lock().map(|mut s| {
        s.entry(pid).or_insert(tag);
    });
}

#[cfg(target_os = "linux")]
pub(super) fn unregister_launch_root(pid: u32) {
    let _ = LIVE_LAUNCH_ROOTS.lock().map(|mut s| s.remove(&pid));
}

/// `Command::spawn` + launch-root registration under the sweep lock.
/// The orphan sweep holds the same mutex across its `/proc` walk and
/// kill phase, so a concurrent teardown either sees the child before
/// it exists or only after registration — never the unprotected
/// window in between. `launch_tag` is the value `apply_unix_process_*`
/// stamped into the environment — descendants inherit it, so the sweep
/// can name this session's escapees exactly. On non-Linux unix there
/// is no orphan sweep; the helper passes the spawn through untouched.
#[cfg(unix)]
pub(crate) fn spawn_and_register<T>(
    spawn: impl FnOnce() -> std::io::Result<T>,
    pid: impl FnOnce(&T) -> u32,
    launch_tag: u64,
) -> std::io::Result<T> {
    #[cfg(target_os = "linux")]
    {
        let mut live = LIVE_LAUNCH_ROOTS.lock().unwrap_or_else(|e| e.into_inner());
        let spawned = spawn()?;
        live.insert(pid(&spawned), launch_tag);
        Ok(spawned)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, launch_tag);
        spawn()
    }
}

/// Kill workload descendants orphaned onto *this* guard process. With
/// `PR_SET_CHILD_SUBREAPER` armed on the guard, a workload process
/// orphaned after its leader died — the case `kill(-pgid)` and a
/// `root_pid`-rooted walk both miss once the leader exited — reparents
/// here, so a scoped sweep over our own children still reaches it.
///
/// The sweep is scoped by *lineage attribution*, not by "every
/// unregistered child". A direct child counts as this teardown's
/// residue only when one of these holds:
/// - it still sits in the torn-down launch's own group
///   (`pgid == root_pgid`) — an orphan that never escaped; or
/// - it sits in a *foreign* group and its [`SPAWN_TAG`] value equals
///   the torn-down root's registered launch tag — a descendant that
///   escaped via `setpgid`/`setsid` and still bears *this* session's
///   lineage marker.
///
/// Everything else is spared by construction: plainly spawned children
/// of this process share our own group; foreign-group children whose
/// marker names a *different* launch tag (a live sibling session's
/// workload, helper-spawned children stamped by `apply_unix_process_*`
/// without registration) belong to that tag's owner, not to this
/// teardown; and marker-less foreign children (a host embedder's
/// deliberately regrouped child) are not ours to kill. A child whose
/// group is another *live* registered leader is likewise left for that
/// session's teardown — with launch leaders themselves armed as
/// subreapers (`pre_exec`), another session's orphans reparent under
/// *its* leader while it lives and never reach this list mid-session.
/// The torn-down leader itself is never a seed (`kid != root_pgid`):
/// its own wait owns the reap, whether or not the caller registered
/// it. A torn-down root that was never registered resolves to no tag,
/// so its foreign-group escapees are spared rather than attributed by
/// guesswork — the safe side.
///
/// The remaining residue is a hard indistinguishability, not a
/// coverage gap: an orphan that both escaped its group *and* scrubbed
/// or rewrote the marker in its environment is identical to a foreign
/// host child and is spared. The marker lives in the workload's own
/// environment, so a *deliberately* evading workload can remove or
/// randomize it — but it cannot make the sweep kill a sibling: the
/// per-launch tag value of another session is not knowable from the
/// evading workload's own environ. On a non-cgroup host no userspace
/// mechanism can attribute the reparented process once the marker is
/// gone; the `LifetimeCgroup` boundary (`cgroup.kill`) is the complete
/// answer for that threat model, and this sweep is the best-effort
/// fallback for hosts where the v2 hierarchy is absent or unwritable.
#[cfg(target_os = "linux")]
pub(super) fn kill_orphan_descendants(root_pgid: u32) {
    let own = std::process::id();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let self_pgid = unsafe { libc::getpgrp() } as u32;
    // Hold the live-root lock across the whole map+kill: a spawn
    // registering under `spawn_and_register` then either precedes the
    // map (pid present *and* protected) or follows it (pid absent) —
    // the unprotected mid-window cannot occur.
    let live = LIVE_LAUNCH_ROOTS.lock().unwrap_or_else(|e| e.into_inner());
    // This session's lineage nonce — an unregistered torn-down root
    // resolves to `None`, which disables the marker-based foreign-group
    // seed below (an untagged `spawn_tag_of` must never equal it).
    let root_tag = live.get(&root_pgid).copied();
    let children_of = children_of_all(own);
    let seeds: Vec<u32> = children_of
        .get(&own)
        .into_iter()
        .flatten()
        .copied()
        .filter(|kid| !live.contains_key(kid) && *kid != root_pgid)
        .filter(|&kid| {
            let Some(group) = pgrp_of(kid) else {
                // Already gone between the map and the read — nothing
                // to attribute, nothing to kill.
                return false;
            };
            // Still in the torn-down launch's own group — residue of
            // this session regardless of marker state.
            if group == root_pgid {
                return true;
            }
            // Foreign group: launch residue only when its marker names
            // *this* session's tag — and never when the group it hides
            // in is a *live* registered leader's (that session's
            // teardown owns it).
            group != self_pgid
                && !live.contains_key(&group)
                && root_tag.is_some()
                && spawn_tag_of(kid) == root_tag
        })
        .collect();
    // Seeds are attributed residue — kill them plus every descendant
    // the snapshot still links under them (their own group state no
    // longer matters once the root of that subtree matched).
    let mut killed = seeds.clone();
    let mut pending = seeds.clone();
    while let Some(parent) = pending.pop() {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let _ = unsafe { libc::kill(parent as i32, libc::SIGKILL) };
        if let Some(kids) = children_of.get(&parent) {
            for &kid in kids {
                killed.push(kid);
                pending.push(kid);
            }
        }
    }
    drop(live);
    // Reap what we killed — only pids this sweep signaled, never a
    // registered leader or a live host child. Seeds are already our
    // children and were just SIGKILL'd, so a bounded reap collects
    // them near-instantly; the retry bound keeps a credential-shifted
    // (setuid → EPERM) or uninterruptible-sleep seed from hanging
    // teardown — a leftover zombie is reaped by the next sweep.
    for &pid in &seeds {
        for _ in 0..64 {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let reaped =
                unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) };
            if reaped != 0 {
                break;
            }
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::sched_yield() };
        }
    }
    // With seeds collected, their dead descendants reparent to this
    // (subreaper) process — the nonblocking pass reaps those instead
    // of leaving zombies behind. A still-dying descendant is left for
    // the next teardown sweep.
    for &pid in &killed {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let _ = unsafe { libc::waitpid(pid as libc::pid_t, std::ptr::null_mut(), libc::WNOHANG) };
    }
}

/// `pgrp` out of `/proc/<pid>/stat` — one field past `ppid`, with the
/// same `comm`-safe tail parse as [`stat_ppid`]. The orphan sweep uses
/// it to tell a reparented workload process (foreign group) apart from
/// a plainly spawned child of this process (our own group).
#[cfg(target_os = "linux")]
fn pgrp_of(pid: u32) -> Option<u32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let tail = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = tail.split_whitespace();
    fields.next()?; // state
    fields.next()?; // ppid
    fields.next()?.parse().ok()
}

/// The lineage tag in `pid`'s `/proc/<pid>/environ`, if any — the
/// value `apply_unix_process_group*` stamped at launch, inherited by
/// workload descendants. `None` means unreadable, absent, cleared, or
/// non-numeric — the safe side: a `None` answer can only spare
/// residue, never doom a bystander, because the sweep compares it
/// against the torn-down root's *known* tag.
#[cfg(target_os = "linux")]
fn spawn_tag_of(pid: u32) -> Option<u64> {
    let env = std::fs::read(format!("/proc/{pid}/environ")).ok()?;
    const KEY: &[u8] = b"MCP_WRIT_SPAWN_TAG=";
    for entry in env.split(|&b| b == 0) {
        if let Some(value) = entry.strip_prefix(KEY) {
            return std::str::from_utf8(value).ok()?.parse().ok();
        }
    }
    None
}

/// ppid → children map of every live process, via `/proc/*/stat`
/// (skipping `root_pid`'s own entry). The snapshot is taken before any
/// kill, so mid-sweep reparenting cannot hide a descendant.
#[cfg(target_os = "linux")]
fn children_of_all(root_pid: u32) -> std::collections::HashMap<u32, Vec<u32>> {
    use std::collections::HashMap;
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return children_of;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == root_pid {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(ppid) = stat_ppid(&stat) else {
            continue;
        };
        children_of.entry(ppid).or_default().push(pid);
    }
    children_of
}

/// macOS counterpart of the `/proc` walk: `proc_listpids` +
/// `PROC_PIDTBSDINFO` yields every live pid's ppid. Orphans already
/// reparented to launchd are missed — the residual the group kill is
/// the only reach for on this platform.
#[cfg(target_os = "macos")]
fn children_of_all(root_pid: u32) -> std::collections::HashMap<u32, Vec<u32>> {
    use std::collections::HashMap;
    let mut children_of = HashMap::new();
    // One bounded listing — the buffer caps the pid count examined;
    // a truncated listing sweeps less of the tree, never more.
    const MAX_PIDS: usize = 8192;
    // Darwin's PROC_ALL_PIDS listing kind — not exported by this libc.
    const PROC_ALL_PIDS: u32 = 1;
    let mut pids = vec![0i32; MAX_PIDS];
    // Safety: `pids` is a live, correctly-sized buffer; the return is
    // a byte count.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe {
        libc::proc_listpids(
            PROC_ALL_PIDS,
            0,
            pids.as_mut_ptr() as *mut libc::c_void,
            (MAX_PIDS * std::mem::size_of::<i32>()) as i32,
        )
    };
    if n <= 0 {
        return children_of;
    }
    let count = (n as usize / std::mem::size_of::<i32>()).min(MAX_PIDS);
    for &raw in &pids[..count] {
        let pid = raw as u32;
        if pid == 0 || pid == root_pid {
            continue;
        }
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
        // Safety: `info` is a live, correctly-sized out-buffer.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let sz = unsafe {
            libc::proc_pidinfo(
                raw,
                libc::PROC_PIDTBSDINFO,
                0,
                &mut info as *mut libc::proc_bsdinfo as *mut libc::c_void,
                std::mem::size_of::<libc::proc_bsdinfo>() as i32,
            )
        };
        if sz != std::mem::size_of::<libc::proc_bsdinfo>() as i32 {
            continue;
        }
        children_of.entry(info.pbi_ppid).or_default().push(pid);
    }
    children_of
}

/// `ppid` out of `/proc/<pid>/stat`. The real end of `comm` is the last
/// `)` on the line — no field after `comm` can contain one — so a
/// crafted `comm` value cannot hide the ancestry fields from this parse.
#[cfg(target_os = "linux")]
fn stat_ppid(stat: &str) -> Option<u32> {
    let tail = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = tail.split_whitespace();
    fields.next()?; // state
    fields.next()?.parse().ok()
}
