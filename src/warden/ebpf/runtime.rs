//! The prepared cgroup-eBPF runtime: a private cgroup v2 directory,
//! the rule/grant/stats/event maps, and the two loaded+attached
//! connect programs. [`Runtime::prepare`] is also the capability
//! diagnostic path — every failed setup step surfaces as a named,
//! remediable error instead of an opaque `EINVAL`.

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::{Path, PathBuf};

use super::prog::{self, ProgKind, ProgMaps};
use super::rules::{GRANT_SLOTS, RuleEntry, RuleTable, grant_sentinel};
use super::sys;

/// Ring-buffer data size (bytes) — sized for a burst of denied
/// connects, not for sustained auditing of allowed traffic.
pub const RINGBUF_DATA_SIZE: usize = 256 * 1024;

/// cgroup v2 root the private cgroup is created under.
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// An owned bpf map/prog fd — closes on drop.
struct Fd(i32);
impl Fd {
    fn raw(&self) -> i32 {
        self.0
    }
}
impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // Safety: `self.0` is an owned open fd.
            unsafe { libc::close(self.0) };
        }
    }
}

/// The private cgroup — removed on drop. Members still alive at
/// teardown are SIGKILLed by `Runtime::drop` before the programs
/// detach (see [`PrivateCgroup::kill_members`]); the directory only
/// outlives the workload when a member's reaping outruns the rmdir
/// window or the supervisor itself dies abruptly — a documented
/// residue, not a leak.
struct PrivateCgroup {
    dir: PathBuf,
    fd: File,
}
impl PrivateCgroup {
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

    fn member_pids(&self) -> Vec<i32> {
        let mut v = Vec::new();
        Self::collect_pids(&self.dir, &mut v, 0);
        v
    }

    /// SIGKILL every still-live member, returning how many were found.
    ///
    /// A descendant that outlived the supervised child (a setsid'd
    /// daemon, an orphaned worker) is still a cgroup member and still
    /// enforced — detaching beneath it would silently strip the IP
    /// layer from a running process (and block the rmdir with
    /// `EBUSY`), so teardown kills the remainder first.
    ///
    /// `cgroup.kill` (kernel ≥ 5.14) kills the whole subtree
    /// atomically; kernels without it take the freeze + per-pid
    /// fallback — freeze so the roster cannot grow mid-sweep, SIGKILL
    /// the members in one pass, then thaw immediately (a SIGKILLed
    /// member stays dead; holding the freeze would only delay the
    /// reap). The roster is then polled briefly in both paths — a
    /// just-killed member stays listed until its parent or init
    /// reaps it.
    fn kill_members(&self) -> usize {
        let found = self.member_pids().len();
        if found == 0 {
            return 0;
        }
        if std::fs::write(self.dir.join("cgroup.kill"), b"1").is_err() {
            // No cgroup.kill (kernel < 5.14): freeze so the roster
            // cannot grow mid-sweep, SIGKILL the members in one pass,
            // and thaw right away — the wait loop below lets the
            // roster drain.
            let freeze = self.dir.join("cgroup.freeze");
            let frozen = std::fs::write(&freeze, b"1").is_ok();
            for pid in self.member_pids() {
                // Safety: signal by pid; ESRCH on an exited member is
                // the normal race here.
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            if frozen {
                let _ = std::fs::write(&freeze, b"0");
            }
        }
        // Wait (bounded) for the killed members to leave the roster so
        // the rmdir below does not lose to a reaping delay.
        for _ in 0..100 {
            if self.member_pids().is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        found
    }
}
impl Drop for PrivateCgroup {
    fn drop(&mut self) {
        // Just-killed members can take a moment to be reaped out of
        // the roster — retry briefly before leaving a residue dir.
        for _ in 0..50 {
            if std::fs::remove_dir(&self.dir).is_ok() {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// Everything the launch needs before the child exists: the cgroup it
/// will join, the attached enforcement, and the event channel.
pub struct Runtime {
    cgroup: PrivateCgroup,
    /// Pre-opened `cgroup.procs` write fd — the child writes its own
    /// pid into it during `pre_exec` (an open fd needs no path lookup
    /// and nothing the sandbox could deny).
    procs_w: File,
    _rules4: Fd,
    _rules6: Fd,
    grants4: Fd,
    grants6: Fd,
    events: Fd,
    stats: Fd,
    prog4: Fd,
    prog6: Fd,
    attached4: bool,
    attached6: bool,
    /// Rule-entry audit metadata parallel to each map (idx → rule).
    pub meta4: Vec<super::rules::RuleMeta>,
    pub meta6: Vec<super::rules::RuleMeta>,
}

/// Which preparation step a [`PrepareError`] names.
pub struct PrepareError {
    pub step: &'static str,
    pub source: io::Error,
    /// An actionable hint (e.g. which capability a `-EPERM` wants).
    pub hint: Option<String>,
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.step, self.source)?;
        if let Some(h) = &self.hint {
            write!(f, " ({h})")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

fn err(step: &'static str, source: io::Error) -> PrepareError {
    PrepareError {
        step,
        hint: hint_for(&source),
        source,
    }
}

/// Map an errno to the most likely missing requirement.
fn hint_for(e: &io::Error) -> Option<String> {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => Some(
            "permission denied — cgroup eBPF needs CAP_BPF + CAP_SYS_ADMIN \
             (or an unprivileged-BPF kernel) and write access to the cgroup \
             v2 hierarchy"
                .to_string(),
        ),
        Some(libc::EINVAL) => Some(
            "the kernel rejected a required cgroup-BPF feature — this route \
             needs CONFIG_CGROUP_BPF and CGROUP_SOCK_ADDR program support"
                .to_string(),
        ),
        Some(libc::ENOENT) => Some(
            "cgroup v2 is not mounted at /sys/fs/cgroup — a cgroup2 \
             hierarchy is required"
                .to_string(),
        ),
        _ => None,
    }
}

/// `unix_now_ns - ktime_boot_ns` — the offset the program adds to
/// `ktime_get_boot_ns` so grant expiry compares in unix seconds.
fn boot_epoch_ns() -> u64 {
    let rt = || {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // Safety: `t` is a live out-param.
        unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut t) };
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    };
    let bt = || {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) };
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    };
    rt().saturating_sub(bt())
}

/// Create `/sys/fs/cgroup/mcp-writ-ebpf-<pid>-<nonce>` and open it plus
/// a `cgroup.procs` write fd for the child.
fn create_private_cgroup() -> Result<(PrivateCgroup, File), PrepareError> {
    let nonce = format!("mcp-writ-ebpf-{}-{}", std::process::id(), mono_nanos());
    let dir = Path::new(CGROUP_ROOT).join(nonce);
    std::fs::create_dir(&dir).map_err(|e| err("private cgroup mkdir", e))?;
    let fd = match File::open(&dir) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_dir(&dir);
            return Err(err("private cgroup open", e));
        }
    };
    let procs_w = match std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("cgroup.procs"))
    {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_dir(&dir);
            return Err(err("private cgroup.procs open", e));
        }
    };
    Ok((PrivateCgroup { dir, fd }, procs_w))
}

fn mono_nanos() -> u64 {
    let mut t = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
}

/// How many leading entries of a table are deny entries.
fn deny_counts(t: &RuleTable) -> (usize, usize) {
    (
        t.v4.iter()
            .take_while(|e| e.action == super::rules::ACTION_DENY)
            .count(),
        t.v6.iter()
            .take_while(|e| e.action == super::rules::ACTION_DENY)
            .count(),
    )
}

fn entry_bytes(e: &RuleEntry) -> &[u8] {
    // Safety: RuleEntry is a repr(C) POD of exactly RULE_ENTRY_SIZE.
    unsafe {
        std::slice::from_raw_parts(
            e as *const RuleEntry as *const u8,
            super::rules::RULE_ENTRY_SIZE,
        )
    }
}

impl Runtime {
    /// Full pre-spawn setup — the real capability probe. Any failure
    /// returns a [`PrepareError`] naming the step, errno, and the
    /// likely missing capability/feature.
    pub fn prepare(table: &RuleTable) -> Result<Self, PrepareError> {
        if !Path::new(CGROUP_ROOT).join("cgroup.controllers").exists() {
            let e = io::Error::from_raw_os_error(libc::ENOENT);
            return Err(PrepareError {
                step: "cgroup-v2 check",
                hint: hint_for(&e),
                source: e,
            });
        }
        let (cgroup, procs_w) = create_private_cgroup()?;
        let mk = |step: &'static str, ty, ks, vs, max| {
            sys::map_create(ty, ks, vs, max)
                .map(Fd)
                .map_err(|e| err(step, e))
        };
        // RAII: any `?` below drops what came before, incl. the cgroup.
        let rules4 = mk(
            "rules4 map create",
            sys::BPF_MAP_TYPE_ARRAY,
            4,
            super::rules::RULE_ENTRY_SIZE as u32,
            table.v4.len().max(1) as u32,
        )?;
        let rules6 = mk(
            "rules6 map create",
            sys::BPF_MAP_TYPE_ARRAY,
            4,
            super::rules::RULE_ENTRY_SIZE as u32,
            table.v6.len().max(1) as u32,
        )?;
        let grants4 = mk(
            "grants4 map create",
            sys::BPF_MAP_TYPE_ARRAY,
            4,
            super::rules::RULE_ENTRY_SIZE as u32,
            GRANT_SLOTS as u32,
        )?;
        let grants6 = mk(
            "grants6 map create",
            sys::BPF_MAP_TYPE_ARRAY,
            4,
            super::rules::RULE_ENTRY_SIZE as u32,
            GRANT_SLOTS as u32,
        )?;
        let events = mk(
            "events ringbuf create",
            sys::BPF_MAP_TYPE_RINGBUF,
            0,
            0,
            RINGBUF_DATA_SIZE as u32,
        )?;
        let stats = mk("stats map create", sys::BPF_MAP_TYPE_ARRAY, 4, 16, 1)?;

        // Populate static rules + sentinel grant slots.
        let fill = |map: &Fd, entries: &[RuleEntry]| -> Result<(), PrepareError> {
            for (i, e) in entries.iter().enumerate() {
                sys::map_update(map.raw(), &(i as u32).to_ne_bytes(), entry_bytes(e))
                    .map_err(|e2| err("rule map populate", e2))?;
            }
            Ok(())
        };
        fill(&rules4, &table.v4)?;
        fill(&rules6, &table.v6)?;
        let sentinel = grant_sentinel();
        for map in [&grants4, &grants6] {
            for i in 0..GRANT_SLOTS {
                sys::map_update(map.raw(), &(i as u32).to_ne_bytes(), entry_bytes(&sentinel))
                    .map_err(|e| err("grant map init", e))?;
            }
        }
        sys::map_update(stats.raw(), &0u32.to_ne_bytes(), &[0u8; 16])
            .map_err(|e| err("stats map init", e))?;

        let (n_deny4, n_deny6) = deny_counts(table);
        let boot_ns = boot_epoch_ns();
        let maps4 = ProgMaps {
            rules: rules4.raw(),
            grants: grants4.raw(),
            events: events.raw(),
            stats: stats.raw(),
        };
        let maps6 = ProgMaps {
            rules: rules6.raw(),
            grants: grants6.raw(),
            events: events.raw(),
            stats: stats.raw(),
        };
        let mut vlog = Vec::new();
        let ins4 = prog::build(
            ProgKind::V4Connect,
            maps4,
            table.v4.len(),
            n_deny4,
            GRANT_SLOTS,
            table.default_allow,
            boot_ns,
        );
        let prog4 = Fd(
            sys::prog_load(&ins4, sys::BPF_CGROUP_INET4_CONNECT, &mut vlog)
                .map_err(|e| err("INET4_CONNECT prog load", e))?,
        );
        sys::prog_attach(
            cgroup.fd.as_raw_fd(),
            prog4.raw(),
            sys::BPF_CGROUP_INET4_CONNECT,
        )
        .map_err(|e| err("INET4_CONNECT attach", e))?;
        let attached4 = true;

        let ins6 = prog::build(
            ProgKind::V6Connect,
            maps6,
            table.v6.len(),
            n_deny6,
            GRANT_SLOTS,
            table.default_allow,
            boot_ns,
        );
        let prog6 = Fd(
            sys::prog_load(&ins6, sys::BPF_CGROUP_INET6_CONNECT, &mut vlog)
                .map_err(|e| err("INET6_CONNECT prog load", e))?,
        );
        sys::prog_attach(
            cgroup.fd.as_raw_fd(),
            prog6.raw(),
            sys::BPF_CGROUP_INET6_CONNECT,
        )
        .map_err(|e| err("INET6_CONNECT attach", e))?;
        let attached6 = true;

        Ok(Runtime {
            cgroup,
            procs_w,
            _rules4: rules4,
            _rules6: rules6,
            grants4,
            grants6,
            events,
            stats,
            prog4,
            prog6,
            attached4,
            attached6,
            meta4: table.meta_v4.clone(),
            meta6: table.meta_v6.clone(),
        })
    }

    /// The `cgroup.procs` write fd — handed to the child's pre-exec so
    /// it joins before exec.
    pub fn procs_writer(&self) -> &File {
        &self.procs_w
    }

    /// Events map fd — the supervisor mmaps the ring buffer over it.
    pub fn events_fd(&self) -> RawFd {
        self.events.raw()
    }
    /// Grant maps for dynamic-allowlist resync.
    pub fn grant_map(&self, fam: super::rules::Family) -> RawFd {
        match fam {
            super::rules::Family::V4 => self.grants4.raw(),
            super::rules::Family::V6 => self.grants6.raw(),
        }
    }
    /// Stats map fd — the drain thread reads the drop counter.
    pub fn stats_fd(&self) -> RawFd {
        self.stats.raw()
    }
    /// Read `[denied, denied_dropped]` from the stats map.
    pub fn stats(&self) -> [u64; 2] {
        let mut buf = [0u8; 16];
        if sys::map_lookup(self.stats.raw(), &0u32.to_ne_bytes(), &mut buf).is_ok() {
            [
                u64::from_ne_bytes(buf[0..8].try_into().unwrap()),
                u64::from_ne_bytes(buf[8..16].try_into().unwrap()),
            ]
        } else {
            [0, 0]
        }
    }
    /// The private cgroup path (diagnostics only).
    pub fn cgroup_path(&self) -> &Path {
        &self.cgroup.dir
    }
    /// The procs-writer fd for spawn wiring.
    pub fn procs_fd(&self) -> RawFd {
        self.procs_w.as_raw_fd()
    }

    /// SIGKILL any still-live cgroup members — descendants that
    /// escaped the workload's process group (setsid'd daemons,
    /// orphaned workers). Idempotent; safe to call at child exit and
    /// again from `Drop`. Returns the member count found (0 = clean).
    pub fn kill_members(&self) -> usize {
        let n = self.cgroup.kill_members();
        if n > 0 {
            tracing::warn!(
                members = n,
                "cgroup still held workload members at teardown — \
                 killed before the connect programs detach"
            );
        }
        n
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // Kill leftover members *before* detaching: enforcement must
        // never be silently detached from a live process — a dead
        // member cannot connect. Detach first would leave a still-
        // running member unsupervised.
        let _ = self.kill_members();
        // Detach so a racing connect in a still-dying child can't
        // hit a closed program fd's slot.
        for (attached, prog, ty) in [
            (self.attached4, &self.prog4, sys::BPF_CGROUP_INET4_CONNECT),
            (self.attached6, &self.prog6, sys::BPF_CGROUP_INET6_CONNECT),
        ] {
            if attached {
                let _ = sys::prog_detach(self.cgroup.fd.as_raw_fd(), prog.raw(), ty);
            }
        }
    }
}
