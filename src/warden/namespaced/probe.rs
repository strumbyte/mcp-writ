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
#[derive(Debug)]
pub struct ProbeReport {
    pub userns: bool,
    pub netns: bool,
    pub mountns: bool,
    pub id_map: bool,
    pub tun: bool,
    pub loopback_up: bool,
    pub route: bool,
    /// Stage that failed, when one did — matches init's `ERR` stages.
    pub failed_stage: Option<String>,
    pub detail: Option<String>,
}

impl ProbeReport {
    /// Every stage the launch depends on succeeded.
    pub fn capable(&self) -> bool {
        self.userns
            && self.netns
            && self.mountns
            && self.id_map
            && self.tun
            && self.loopback_up
            && self.route
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
        "userns={}\nnetns={}\nmountns={}\nid_map={}\ntun={}\nloopback_up={}\nroute={}\nfailed_stage={}\ndetail={}\n",
        r.userns,
        r.netns,
        r.mountns,
        r.id_map,
        r.tun,
        r.loopback_up,
        r.route,
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
        tun: false,
        loopback_up: false,
        route: false,
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
            "tun" => report.tun = truthy,
            "loopback_up" => report.loopback_up = truthy,
            "route" => report.route = truthy,
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
        tun: false,
        loopback_up: false,
        route: false,
        failed_stage: None,
        detail: None,
    };
    macro_rules! fail {
        ($stage:literal, $e:expr) => {{
            r.failed_stage = Some($stage.to_string());
            r.detail = Some($e.to_string());
            let body = report_text(&r);
            unsafe {
                libc::write(report_fd, body.as_ptr() as *const _, body.len());
                libc::_exit(0);
            }
        }};
    }

    // Same single unshare call init's grandchild makes — success
    // implies all three namespaces were granted together.
    if unsafe { libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNET | libc::CLONE_NEWNS) } < 0 {
        fail!("unshare", std::io::Error::last_os_error());
    }
    r.userns = true;
    r.netns = true;
    r.mountns = true;

    // Tell the parent "unshared" and wait for the map write.
    if unsafe { libc::write(sync_w, b"1".as_ptr() as *const _, 1) } != 1 {
        fail!("fork", std::io::Error::last_os_error());
    }
    let mut b = [0u8; 1];
    if unsafe { libc::read(sync_r, b.as_mut_ptr() as *mut _, 1) } != 1 {
        fail!("idmap", "parent map-write never arrived".to_string());
    }

    // TUN inside the fresh netns.
    let tun = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR) };
    if tun < 0 {
        fail!("tun", std::io::Error::last_os_error());
    }
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as i16;
    for (slot, &b) in ifr.ifr_name.iter_mut().zip(b"egress0".iter()) {
        *slot = b as libc::c_char;
    }
    if unsafe { libc::ioctl(tun, libc::TUNSETIFF, &ifr) } < 0 {
        let e = std::io::Error::last_os_error();
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
    unsafe { libc::close(tun) };
    let body = report_text(&r);
    unsafe {
        libc::write(report_fd, body.as_ptr() as *const _, body.len());
        libc::_exit(0);
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
    unsafe {
        libc::pipe(sync_a.as_mut_ptr());
        libc::pipe(sync_b.as_mut_ptr());
        libc::pipe(report_p.as_mut_ptr());
    }
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::close(sync_a[0]);
            libc::close(sync_b[1]);
            libc::close(report_p[0]);
        }
        probe_grandchild(sync_b[0], sync_a[1], report_p[1]);
    }
    if pid < 0 {
        return ProbeReport {
            userns: false,
            netns: false,
            mountns: false,
            id_map: false,
            tun: false,
            loopback_up: false,
            route: false,
            failed_stage: Some("fork".to_string()),
            detail: Some(std::io::Error::last_os_error().to_string()),
        };
    }
    unsafe {
        libc::close(sync_a[1]);
        libc::close(sync_b[0]);
        libc::close(report_p[1]);
    }

    // Wait for "unshared", then write the grandchild's maps.
    let mut b = [0u8; 1];
    let got = unsafe { libc::read(sync_a[0], b.as_mut_ptr() as *mut _, 1) } == 1;
    let mut id_map = false;
    let mut map_err = None;
    if got {
        let euid = unsafe { libc::geteuid() };
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
    unsafe {
        libc::write(sync_b[1], b"1".as_ptr() as *const _, 1);
        libc::close(sync_a[0]);
        libc::close(sync_b[1]);
    }

    // Collect the grandchild's namespace-side report.
    let mut body = String::new();
    {
        use std::io::Read;
        let mut f = unsafe { std::fs::File::from_raw_fd(report_p[0]) };
        let _ = f.read_to_string(&mut body);
    }
    let mut r = parse_report(&body).unwrap_or_else(|| ProbeReport {
        userns: false,
        netns: false,
        mountns: false,
        id_map: false,
        tun: false,
        loopback_up: false,
        route: false,
        failed_stage: Some("probe".to_string()),
        detail: Some(format!("grandchild report missing (raw: {body})")),
    });
    r.id_map = id_map;
    if got && !id_map && r.failed_stage.is_none() {
        r.failed_stage = Some("idmap".to_string());
        r.detail = Some(map_err.unwrap_or_else(|| "map write failed".to_string()));
    }
    let mut status = 0i32;
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
