//! Capability probe for the namespaced path. Runs inside the
//! `namespaced-probe` helper — a fresh exec'd process, so it can
//! actually `unshare` without contaminating the parent — and reports
//! each setup stage the way init would hit it. The parent refuses the
//! launch when a required stage is absent (there is no degraded
//! namespace to fall back to), so the probe doubles as the honest
//! `unsupported` detector for the report.

use std::io::Write;
use std::os::unix::io::FromRawFd;

/// Serialized probe result — the `--report` payload's `capabilities`
/// section and the launch-refusal detail. Wire format to the parent
/// is `key=value` lines (no JSON parser dependency).
#[derive(Debug, Clone)]
pub struct ProbeReport {
    pub userns: bool,
    pub netns: bool,
    pub mountns: bool,
    pub id_map: bool,
    /// The `/proc` remount init's pidns-init child performs succeeded
    /// from a fresh pidns under this mountns (PR-35 / D-10). `false`
    /// reports the masked-`/proc` environment constraint (container,
    /// nested userns) the launch would otherwise hit as a bare
    /// `ERR proc-mount errno=1` — `capable()` refuses it the same way.
    pub proc_mount: bool,
    pub tun: bool,
    pub loopback_up: bool,
    pub route: bool,
    /// `AF_INET6` socket creation did not fail `EAFNOSUPPORT`
    /// (PR-26a) — the probe measures socket availability, not kernel
    /// provenance. `false` records that the probe could not create a
    /// v6 socket that way (typically a kernel without IPv6 —
    /// `ipv6.disable=1`, no `CONFIG_IPV6`); other socket errors such
    /// as `EPERM`/`EMFILE` count as *present* rather than proving v6
    /// absent. `false` routes the namespace v4-only *by environment* —
    /// `missing()` must not name `ipv6_route_via_tun`, since
    /// v6-requiring policies are refused separately by the host-side
    /// reachability check.
    pub ipv6_stack: bool,
    /// In-netns IPv6 configured (v6 addr + v6 default route — PR-26a):
    /// the route is dual-stack when a v6 socket could be created.
    /// `ipv6=false` with `ipv6_stack=true` is a genuine setup failure
    /// and lands in `missing()`; `ipv6=false` with `ipv6_stack=false`
    /// is an unavailable socket, not a failure.
    pub ipv6: bool,
    /// Stage that failed, when one did — matches init's `ERR` stages.
    pub failed_stage: Option<String>,
    pub detail: Option<String>,
}

impl ProbeReport {
    /// Every stage the launch depends on succeeded.
    pub fn capable(&self) -> bool {
        self.missing().is_empty()
    }

    /// The `linux-namespaced` catalog `requires` ids whose stage
    /// failed — the same tokens the `--report` `missing` member lists
    /// and a mechanism selector would refuse on
    /// ([`crate::enforcement::capability::LINUX_NAMESPACED`]).
    /// `capable()` ⇔ `missing().is_empty()`: one judgment, both
    /// consumers.
    pub fn missing(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.userns {
            v.push("userns");
        }
        if !self.netns {
            v.push("netns");
        }
        if !self.mountns {
            v.push("mountns");
        }
        if !self.id_map {
            v.push("uid_gid_map");
        }
        if !self.proc_mount {
            v.push("proc_mount");
        }
        if !self.tun {
            v.push("tun");
        }
        if !self.loopback_up {
            v.push("loopback_up");
        }
        if !self.route {
            v.push("default_route_via_tun");
        }
        if self.ipv6_stack && !self.ipv6 {
            v.push("ipv6_route_via_tun");
        }
        v
    }

    /// One-line refusal reason for diagnostics/report `reason`.
    pub fn reason(&self) -> Option<String> {
        self.failed_stage.as_ref().map(|s| {
            format!(
                "namespaced setup stage '{s}' failed: {}",
                self.detail.as_deref().unwrap_or("no detail")
            )
        })
    }
}

fn report_text(r: &ProbeReport) -> String {
    format!(
        "userns={}\nnetns={}\nmountns={}\nid_map={}\nproc_mount={}\ntun={}\nloopback_up={}\nroute={}\nipv6_stack={}\nipv6={}\nfailed_stage={}\ndetail={}\n",
        r.userns,
        r.netns,
        r.mountns,
        r.id_map,
        r.proc_mount,
        r.tun,
        r.loopback_up,
        r.route,
        r.ipv6_stack,
        r.ipv6,
        r.failed_stage.as_deref().unwrap_or(""),
        r.detail.as_deref().unwrap_or("").replace('\n', " "),
    )
}

fn parse_report(body: &str) -> Option<ProbeReport> {
    let mut report = ProbeReport {
        userns: false,
        netns: false,
        mountns: false,
        id_map: false,
        proc_mount: false,
        tun: false,
        loopback_up: false,
        route: false,
        ipv6_stack: false,
        ipv6: false,
        failed_stage: None,
        detail: None,
    };
    let mut saw_any = false;
    for line in body.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        saw_any = true;
        let truthy = v == "true";
        match k {
            "userns" => report.userns = truthy,
            "netns" => report.netns = truthy,
            "mountns" => report.mountns = truthy,
            "id_map" => report.id_map = truthy,
            "proc_mount" => report.proc_mount = truthy,
            "tun" => report.tun = truthy,
            "loopback_up" => report.loopback_up = truthy,
            "route" => report.route = truthy,
            "ipv6_stack" => report.ipv6_stack = truthy,
            "ipv6" => report.ipv6 = truthy,
            "failed_stage" if !v.is_empty() => report.failed_stage = Some(v.to_string()),
            "detail" if !v.is_empty() => report.detail = Some(v.to_string()),
            _ => {}
        }
    }
    if !saw_any {
        return None;
    }
    Some(report)
}

/// Grandchild side of the probe: unshare, wait for its map, run the
/// in-namespace checks, write the report to `report_fd`, `_exit` so
/// the fresh namespaces die with it.
fn probe_grandchild(sync_r: i32, sync_w: i32, report_fd: i32) -> ! {
    let mut r = ProbeReport {
        userns: false,
        netns: false,
        mountns: false,
        // Set by the parent side of the report merge — the grandchild
        // only knows the namespaces half.
        id_map: true,
        proc_mount: false,
        tun: false,
        loopback_up: false,
        route: false,
        ipv6_stack: false,
        ipv6: false,
        failed_stage: None,
        detail: None,
    };
    macro_rules! fail {
        ($stage:literal, $e:expr) => {{
            r.failed_stage = Some($stage.to_string());
            r.detail = Some($e.to_string());
            let body = report_text(&r);
            // SAFETY: `body`'s as_ptr()/len() describe a readable String
            // buffer that outlives the call; `report_fd` is the live
            // write end handed in by the caller. `_exit` never returns.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe {
                libc::write(report_fd, body.as_ptr() as *const _, body.len());
                libc::_exit(0);
            }
        }};
    }

    // Same single unshare call init's grandchild makes — success
    // implies all four namespaces were granted together, so the pidns
    // half init relies on is measured here too (a CLONE_NEWPID refusal
    // reports `unshare`, never a launch-time surprise).
    // SAFETY: scalar flag bitmask, no pointers; a refused combination
    // returns EINVAL rather than producing UB.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe {
        libc::unshare(
            libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWPID,
        )
    } < 0
    {
        fail!("unshare", std::io::Error::last_os_error());
    }
    r.userns = true;
    r.netns = true;
    r.mountns = true;

    // Tell the parent "unshared" and wait for the map write.
    // SAFETY: the 1-byte literal is a readable buffer; a bad `sync_w`
    // fails EBADF without touching memory.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::write(sync_w, b"1".as_ptr() as *const _, 1) } != 1 {
        fail!("fork", std::io::Error::last_os_error());
    }
    let mut b = [0u8; 1];
    // SAFETY: `b` is a writable 1-byte buffer that outlives the call; a
    // bad `sync_r` fails EBADF without touching memory.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::read(sync_r, b.as_mut_ptr() as *mut _, 1) } != 1 {
        fail!("idmap", "parent map-write never arrived".to_string());
    }

    // TUN inside the fresh netns.
    // SAFETY: `c"/dev/net/tun"` is a NUL-terminated static C string;
    // open(2) takes no other pointers.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let tun = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if tun < 0 {
        fail!("tun", std::io::Error::last_os_error());
    }
    // SAFETY: `ifreq` is a POD union, so the all-zero bit pattern is a
    // valid value; the flag and name fields are filled before use.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
    for (slot, &b) in ifr.ifr_name.iter_mut().zip(b"egress0".iter()) {
        *slot = b as libc::c_char;
    }
    // SAFETY: `tun` is the live `/dev/net/tun` descriptor opened above
    // and `&ifr` points at an initialized `ifreq` — the request-argument
    // layout TUNSETIFF requires.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::ioctl(tun, libc::TUNSETIFF, &ifr) } < 0 {
        let e = std::io::Error::last_os_error();
        // SAFETY: `tun` is still owned — the failed ioctl transfers
        // nothing — so it is closed exactly once on this error path.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(tun) };
        fail!("tun", e);
    }
    r.tun = true;

    if let Err(e) = super::netlink::bring_loopback_up() {
        fail!("loopback", e);
    }
    r.loopback_up = true;
    if let Err(e) = (|| -> std::io::Result<()> {
        super::netlink::addr_add("egress0", super::WORKLOAD_V4, 24)?;
        super::netlink::default_route_dev("egress0")?;
        Ok(())
    })() {
        fail!("route", e);
    }
    r.route = true;
    // Dual-stack net config — the same v6 address + default route init
    // installs. Only a kernel that HAS a v6 stack is measured: absent
    // (`ipv6.disable=1`, no CONFIG_IPV6) the route is v4-only by
    // environment — `ipv6` stays false but nothing goes missing, and a
    // v6-needing policy is refused separately by the host-side
    // reachability check in `select`. A present stack whose setup
    // fails is a real requirement failure.
    r.ipv6_stack = super::init::ipv6_stack_present();
    if r.ipv6_stack {
        if let Err(e) = (|| -> std::io::Result<()> {
            let _ = super::init::enable_ipv6();
            super::netlink::addr_add_v6("egress0", super::WORKLOAD_V6, 64)?;
            super::netlink::default_route_dev_v6("egress0")?;
            Ok(())
        })() {
            fail!("ipv6", e);
        }
        r.ipv6 = true;
    }
    // PR-35 / D-10: measure the `/proc` remount init's pidns-init child
    // performs. Every stage above can pass while this still refuses —
    // the mount requires CAP_SYS_ADMIN over the *pidns's* owner userns
    // (so it must be attempted inside the fresh pidns) and a
    // fully-visible `/proc` in the inherited mount namespace (a
    // container or nested userns that masks parts of `/proc` answers
    // EPERM). Testing after the network stages keeps a refusal honest:
    // `missing` then names `proc_mount` alone instead of every stage
    // the early exit would have left untested.
    match probe_proc_mount() {
        Ok(()) => r.proc_mount = true,
        Err(e) => fail!("proc_mount", e),
    }
    // SAFETY: `tun` is still owned by this process — it was opened above
    // and never wrapped — so it is closed exactly once here.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { libc::close(tun) };
    let body = report_text(&r);
    // SAFETY: `body`'s as_ptr()/len() describe a readable String buffer
    // that outlives the call; `report_fd` is the live write end handed
    // in by the caller. `_exit` never returns.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::write(report_fd, body.as_ptr() as *const _, body.len());
        libc::_exit(0);
    }
}

/// Attempt init's `/proc` remount the way init performs it: a child
/// forked *after* the `CLONE_NEWPID` unshare lands as pid 1 of the
/// fresh pid namespace — the position a procfs mount actually needs
/// CAP_SYS_ADMIN over — replays init's `MS_PRIVATE|MS_REC` detach on
/// the inherited mountns, then tries `mount("proc", "/proc")`. The
/// outcome returns through the child's exit status (`errno` on
/// failure, 0 on success); the mount itself lives in this probe's
/// private mountns, so the host's `/proc` is untouched, and a
/// successful attempt umounts right back so no later stage sees the
/// over-mounted view.
fn probe_proc_mount() -> std::io::Result<()> {
    // SAFETY: the probe helper is single-threaded here — the child
    // inherits no foreign-held lock, and it `_exit`s without unwinding.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if pid == 0 {
        let code: i32 = (|| {
            // SAFETY: every pointer is a NUL-terminated static C
            // string; MS_PRIVATE|MS_REC takes null source/fstype/data.
            // The call lands in the mountns shared with the probe
            // grandchild — the same detach init performs.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe {
                libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_PRIVATE | libc::MS_REC,
                    std::ptr::null(),
                )
            } < 0
            {
                return errno_code();
            }
            // SAFETY: static C strings; proc takes no mount data.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            if unsafe {
                libc::mount(
                    c"proc".as_ptr(),
                    c"/proc".as_ptr(),
                    c"proc".as_ptr(),
                    0,
                    std::ptr::null(),
                )
            } < 0
            {
                return errno_code();
            }
            // Restore the inherited /proc view for the remaining
            // stages — MNT_DETACH drops the over-mount immediately.
            // SAFETY: static C string; umount2 takes no mount data.
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::umount2(c"/proc".as_ptr(), libc::MNT_DETACH) };
            0
        })();
        // SAFETY: terminates the forked child — `_exit` never returns.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::_exit(code.clamp(0, 255)) };
    }
    let mut status = 0i32;
    loop {
        // SAFETY: `&mut status` is a valid, writable c_int and `pid`
        // is this process's unreaped child.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            break;
        }
        // A wait error must not read the zero-initialized `status` —
        // an unreported child is a failed measurement, not a success.
        if r < 0 && errno_code() != libc::EINTR {
            return Err(std::io::Error::last_os_error());
        }
    }
    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == 0 {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(code))
        }
    } else {
        Err(std::io::Error::other(
            "proc-mount probe child died before reporting",
        ))
    }
}

fn errno_code() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// Uniform report for a setup stage that failed before any namespace
/// work ran — pipe creation or the fork itself.
fn failed_probe(stage: &str, detail: String) -> ProbeReport {
    ProbeReport {
        userns: false,
        netns: false,
        mountns: false,
        id_map: false,
        proc_mount: false,
        tun: false,
        loopback_up: false,
        route: false,
        ipv6_stack: false,
        ipv6: false,
        failed_stage: Some(stage.to_string()),
        detail: Some(detail),
    }
}

/// Run the probe in-process. Same fork topology as init: the
/// grandchild unshares, the parent writes its map (self-map after
/// `unshare(CLONE_NEWUSER)` is EPERM on this kernel), the grandchild
/// reports the namespace-side checks over a pipe. Callers must only
/// use this inside the dedicated `namespaced-probe` exec.
fn probe_in_place() -> ProbeReport {
    let mut sync_a = [0i32; 2]; // grandchild → parent: "unshared"
    let mut sync_b = [0i32; 2]; // parent → grandchild: "mapped"
    let mut report_p = [0i32; 2];
    // A failed pipe() leaves its slots at the zero initializer — fd 0 —
    // so every call is checked before the fork and the failure path
    // closes only the ends a successful call actually wrote.
    let mut created = 0usize;
    let mut pipe_err = None;
    for pair in [&mut sync_a, &mut sync_b, &mut report_p] {
        // SAFETY: `pair` is a valid, writable `[c_int; 2]` — exactly the
        // two-fd output pipe(2) writes; the result is checked here, so a
        // failed call's placeholder slots are never used.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        if unsafe { libc::pipe(pair.as_mut_ptr()) } < 0 {
            pipe_err = Some(std::io::Error::last_os_error());
            break;
        }
        created += 1;
    }
    if let Some(e) = pipe_err {
        // SAFETY: `take(created)` reaches only the ends a successful
        // pipe() wrote — open descriptors owned by this process, each
        // closed once. Uncreated slots still hold fd-0 placeholders and
        // are never closed.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            for pair in [&sync_a, &sync_b, &report_p].iter().take(created) {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
        }
        return failed_probe("pipe", e.to_string());
    }
    // SAFETY: the probe helper runs before the tokio runtime starts, so
    // the process is single-threaded and the child inherits no
    // foreign-held lock — post-fork Rust allocation stays sound.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: the three pipe ends are open descriptors owned by this
        // (grandchild) process, each closed exactly once.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::close(sync_a[0]);
            libc::close(sync_b[1]);
            libc::close(report_p[0]);
        }
        probe_grandchild(sync_b[0], sync_a[1], report_p[1]);
    }
    if pid < 0 {
        // Capture the fork errno before the closes — a failed close
        // could overwrite it.
        let fork_err = std::io::Error::last_os_error();
        // SAFETY: all six ends are open descriptors owned by this
        // process — the three pipes verified above — each closed once.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            for pair in [&sync_a, &sync_b, &report_p] {
                libc::close(pair[0]);
                libc::close(pair[1]);
            }
        }
        return failed_probe("fork", fork_err.to_string());
    }
    // SAFETY: the three pipe ends are open descriptors owned by this
    // (probe parent) process, each closed exactly once.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::close(sync_a[1]);
        libc::close(sync_b[0]);
        libc::close(report_p[1]);
    }

    // Wait for "unshared", then write the grandchild's maps.
    let mut b = [0u8; 1];
    // SAFETY: `b` is a writable 1-byte buffer that outlives the call;
    // `sync_a[0]` is this process's open read end.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let got = unsafe { libc::read(sync_a[0], b.as_mut_ptr() as *mut _, 1) } == 1;
    let mut id_map = false;
    let mut map_err = None;
    if got {
        // SAFETY: argument-free queries — no pointers, no writable
        // state.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let euid = unsafe { libc::geteuid() };
        // SAFETY: argument-free query — no pointers, no writable state.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let egid = unsafe { libc::getegid() };
        match (|| -> std::io::Result<()> {
            std::fs::write(format!("/proc/{pid}/setgroups"), "deny")?;
            std::fs::write(format!("/proc/{pid}/uid_map"), format!("0 {euid} 1"))?;
            std::fs::write(format!("/proc/{pid}/gid_map"), format!("0 {egid} 1"))?;
            Ok(())
        })() {
            Ok(()) => id_map = true,
            Err(e) => map_err = Some(e.to_string()),
        }
    }
    // SAFETY: the 1-byte literal is a readable buffer and both pipe ends
    // are open descriptors owned by this process, each closed once.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::write(sync_b[1], b"1".as_ptr() as *const _, 1);
        libc::close(sync_a[0]);
        libc::close(sync_b[1]);
    }

    // Collect the grandchild's namespace-side report.
    let mut body = String::new();
    {
        use std::io::Read;
        // SAFETY: `report_p[0]` is a descriptor the pipe() above
        // verifiably created — an open fd owned by this process and not
        // yet wrapped — `File` takes ownership once and its drop
        // performs the only close.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let mut f = unsafe { std::fs::File::from_raw_fd(report_p[0]) };
        let _ = f.read_to_string(&mut body);
    }
    let mut r = parse_report(&body).unwrap_or_else(|| ProbeReport {
        userns: false,
        netns: false,
        mountns: false,
        id_map: false,
        proc_mount: false,
        tun: false,
        loopback_up: false,
        route: false,
        ipv6_stack: false,
        ipv6: false,
        failed_stage: Some("probe".to_string()),
        detail: Some(format!("grandchild report missing (raw: {body})")),
    });
    r.id_map = id_map;
    if got && !id_map && r.failed_stage.is_none() {
        r.failed_stage = Some("idmap".to_string());
        r.detail = Some(map_err.unwrap_or_else(|| "map write failed".to_string()));
    }
    let mut status = 0i32;
    // SAFETY: `&mut status` is a valid, writable c_int and `pid` is this
    // process's unreaped child.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        libc::waitpid(pid, &mut status, 0);
    }
    r
}

/// `namespaced-probe` entry: print the report as `key=value` lines,
/// exit 0 when the host is fully capable, 1 otherwise.
pub(crate) fn probe_main() -> i32 {
    let report = probe_in_place();
    let body = report_text(&report);
    let _ = std::io::stdout().lock().write_all(body.as_bytes());
    if report.capable() { 0 } else { 1 }
}

/// Parent-side probe: exec `namespaced-probe`, parse its report.
/// Spawning itself never blocks long — the helper does a handful of
/// syscalls and exits.
pub fn run_probe() -> Result<ProbeReport, String> {
    let out = std::process::Command::new("/proc/self/exe")
        .arg(super::PROBE_SUBCOMMAND)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("probe spawn failed: {e}"))?;
    let body = String::from_utf8_lossy(&out.stdout);
    parse_report(body.trim()).ok_or_else(|| format!("probe output parse failed (raw: {body})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(all_ok: bool) -> ProbeReport {
        ProbeReport {
            userns: all_ok,
            netns: all_ok,
            mountns: all_ok,
            id_map: all_ok,
            proc_mount: all_ok,
            tun: all_ok,
            loopback_up: all_ok,
            route: all_ok,
            ipv6_stack: all_ok,
            ipv6: all_ok,
            failed_stage: None,
            detail: None,
        }
    }

    #[test]
    fn missing_tokens_are_catalog_requires_ids() {
        // The stage -> requirement-id mapping is bound to the
        // `linux-namespaced` catalog row: a token the catalog does not
        // name can never reach a report `missing` member.
        let catalog_ids: Vec<&str> = crate::enforcement::capability::LINUX_NAMESPACED
            .requires
            .iter()
            .map(|r| r.id)
            .collect();
        for stage in [
            "userns",
            "netns",
            "mountns",
            "id_map",
            "proc_mount",
            "tun",
            "loopback_up",
            "route",
            "ipv6",
        ] {
            let mut r = report(true);
            match stage {
                "userns" => r.userns = false,
                "netns" => r.netns = false,
                "mountns" => r.mountns = false,
                "id_map" => r.id_map = false,
                "proc_mount" => r.proc_mount = false,
                "tun" => r.tun = false,
                "loopback_up" => r.loopback_up = false,
                "route" => r.route = false,
                "ipv6" => r.ipv6 = false,
                _ => unreachable!(),
            }
            for token in r.missing() {
                assert!(
                    catalog_ids.contains(&token),
                    "missing() token '{token}' is not a linux-namespaced requires id"
                );
            }
        }
        // A fully-failed probe names every stage it measures — the
        // coverage is complete, not a subset, and adds nothing the
        // catalog does not require. (`pidns` folds into the single
        // `unshare` stage — the probe and init both create it in the
        // same call, so a refusal reports `unshare`, never a separate
        // pidns token.) `ipv6_route_via_tun` is measured only when the
        // kernel exposes a v6 stack — pin it separately since a
        // stack-absent host must not report it.
        let mut all = report(false);
        all.ipv6_stack = true;
        let mut all = all.missing();
        all.sort_unstable();
        assert_eq!(
            all,
            [
                "default_route_via_tun",
                "ipv6_route_via_tun",
                "loopback_up",
                "mountns",
                "netns",
                "proc_mount",
                "tun",
                "uid_gid_map",
                "userns"
            ],
            "a fully-failed probe on a v6-capable kernel must name \
             every measured stage id"
        );
        // An absent v6 stack is not a capability failure: `ipv6` stays
        // false but `ipv6_route_via_tun` is not missing and the route
        // stays capable — selection's host-side reachability check is
        // the layer that refuses v6-needing policies there.
        let mut no_stack = report(true);
        no_stack.ipv6_stack = false;
        no_stack.ipv6 = false;
        assert!(
            !no_stack.missing().contains(&"ipv6_route_via_tun"),
            "an absent IPv6 stack is v4-only by environment, not a \
             failed stage"
        );
        assert!(no_stack.capable());
        assert!(report(true).capable());
        assert!(!report(false).capable());
    }
}
