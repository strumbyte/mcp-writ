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

/// Best-effort SIGKILL of every descendant of `root_pid`, including
/// processes that escaped the child's process group via `setpgid` or
/// `setsid` (which `kill(-pgid)` cannot reach). Walks `/proc/*/stat`
/// ppid links once, then signals by pid — the parentage snapshot is
/// taken before any kill, so mid-sweep reparenting cannot hide a
/// descendant. Post-exit, a dead leader's children are reparented away
/// before this runs; the group kill above is what must catch those.
#[cfg(target_os = "linux")]
pub(super) fn kill_proc_descendants(root_pid: u32) {
    use std::collections::HashMap;

    let Ok(entries) = std::fs::read_dir("/proc") else {
        return;
    };
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
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

    let mut pending = vec![root_pid];
    while let Some(parent) = pending.pop() {
        let Some(kids) = children_of.get(&parent) else {
            continue;
        };
        for &kid in kids {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let _ = unsafe { libc::kill(kid as i32, libc::SIGKILL) };
            pending.push(kid);
        }
    }
}

/// macOS counterpart of the `/proc` walk: `proc_listpids` +
/// `PROC_PIDTBSDINFO` yields every live pid's ppid; the BFS from
/// `root_pid` reaches descendants that escaped the process group
/// while still parent-linked. Orphans already reparented to launchd
/// are missed — the same residual the Linux walk carries; the group
/// kill above catches them while they kept the launch pgid.
#[cfg(target_os = "macos")]
pub(super) fn kill_proc_descendants(root_pid: u32) {
    use std::collections::HashMap;
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
        return;
    }
    let count = (n as usize / std::mem::size_of::<i32>()).min(MAX_PIDS);
    let mut children_of: HashMap<u32, Vec<u32>> = HashMap::new();
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

    let mut pending = vec![root_pid];
    while let Some(parent) = pending.pop() {
        let Some(kids) = children_of.get(&parent) else {
            continue;
        };
        for &kid in kids {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let _ = unsafe { libc::kill(kid as i32, libc::SIGKILL) };
            pending.push(kid);
        }
    }
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
