//! Process-tree teardown primitives behind the child lifecycle: the
//! group SIGKILL and the descendant sweep that reaches processes which
//! escaped the launch's process group (`setpgid`/`setsid`/reparenting).

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
/// descendant whose intermediate parent dies then reparents to *us*
/// instead of init — the post-exit sweep can still find it by ppid
/// under [`kill_orphan_descendants`]. Without it (and without a
/// lifetime cgroup) a `setsid`'d process whose leader already exited
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

/// Kill every remaining descendant of *this* guard process. With
/// `PR_SET_CHILD_SUBREAPER` armed, a workload process orphaned before
/// or during teardown — the case `kill(-pgid)` and a `root_pid`-rooted
/// walk both miss once the leader exited — reparents here, so a BFS
/// from our own pid still reaches its whole subtree. Everything still
/// alive beneath us at teardown is session machinery or workload
/// residue; the sweep is teardown-scoped by contract and must leave
/// nothing running.
#[cfg(target_os = "linux")]
pub(super) fn kill_orphan_descendants() {
    kill_pids(&collect_proc_descendants(std::process::id()));
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
