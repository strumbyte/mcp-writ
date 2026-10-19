//! The prepared cgroup-eBPF runtime: a private cgroup v2 directory,
//! the rule/grant/stats/event maps, and the two loaded+attached
//! connect programs. [`Runtime::prepare`] is also the capability
//! diagnostic path — every failed setup step surfaces as a named,
//! remediable error instead of an opaque `EINVAL`.

use std::fs::File;
use std::io;
use std::os::unix::io::{AsRawFd, RawFd};
use std::path::Path;

use super::prog::{self, ProgKind, ProgMaps};
use super::rules::{GRANT_SLOTS, RuleEntry, RuleTable, grant_sentinel};
use super::sys;
use crate::warden::cgroup::CGROUP_ROOT;
use crate::warden::cgroup::LifetimeCgroup as PrivateCgroup;

// Re-exported for `tests.rs`.
#[cfg(test)]
pub(super) use crate::warden::cgroup::cgroup_body_covers;

/// Ring-buffer data size (bytes) — sized for a burst of denied
/// connects, not for sustained auditing of allowed traffic.
pub const RINGBUF_DATA_SIZE: usize = 256 * 1024;

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
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(self.0) };
        }
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
    /// One-slot u64 wall-clock epoch — the program adds it to
    /// `ktime_get_boot_ns`; the drain rewrites it each resync tick so
    /// a post-load realtime step cannot skew grant expiry.
    clock: Fd,
    /// One-slot u64 grant-map write seqlock — odd while
    /// `write_grant_maps` rewrites slots, the next even value when
    /// done. A dedicated map so a seqlock publish can never clobber
    /// the XADD-updated stats counters.
    seq: Fd,
    /// Loaded+attached programs as `(fd, attach_type)` pairs — the
    /// INET4/6_CONNECT hooks and the UDP4/6_SENDMSG hooks; `Drop`
    /// detaches each while members still live (see `kill_members`).
    progs: Vec<(Fd, u32)>,
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

/// Map an errno to the most likely missing requirement. `sys::prog_load`
/// folds the verifier log into a *new* `io::Error` that keeps `kind()`
/// but drops the errno — so the `kind()` fallbacks below carry the
/// prog-load path, the raw errno the direct-syscall path.
fn hint_for(e: &io::Error) -> Option<String> {
    let errno = e.raw_os_error();
    if matches!(errno, Some(n) if n == libc::EPERM || n == libc::EACCES)
        || e.kind() == io::ErrorKind::PermissionDenied
    {
        return Some(
            "permission denied — cgroup eBPF needs CAP_BPF or CAP_SYS_ADMIN \
             (program/map ops) plus CAP_NET_ADMIN (cgroup attach), and write \
             access to the cgroup v2 hierarchy"
                .to_string(),
        );
    }
    if errno == Some(libc::EINVAL) || e.kind() == io::ErrorKind::InvalidInput {
        return Some(
            "the kernel rejected a required cgroup-BPF feature — this route \
             needs CONFIG_CGROUP_BPF and CGROUP_SOCK_ADDR program support"
                .to_string(),
        );
    }
    if errno == Some(libc::E2BIG) || e.kind() == io::ErrorKind::ArgumentListTooLong {
        return Some(
            "the generated program exceeds the kernel's bpf instruction \
             limit — kernels before 5.2 cap programs at 4096 insns; reduce \
             the rule set or run on a newer kernel"
                .to_string(),
        );
    }
    if errno == Some(libc::ENOENT) {
        return Some(
            "cgroup v2 is not mounted at /sys/fs/cgroup — a cgroup2 \
             hierarchy is required"
                .to_string(),
        );
    }
    None
}

/// `unix_now_ns - ktime_boot_ns` — the offset stored in the clock
/// map; the program adds it to `ktime_get_boot_ns` so grant expiry
/// compares in unix seconds. Recomputed each drain tick so a realtime
/// step propagates within that interval.
///
/// Known skew: inside a Linux *time namespace*,
/// `clock_gettime(CLOCK_BOOTTIME)` carries the namespace offset while
/// the kernel-side `ktime_get_boot_ns` does not — the computed epoch
/// then misses by that offset and grant expiry is persistently
/// skewed (each tick recomputes the same skew). Docker/Kubernetes do
/// not enable timens by default; a launcher unsharing one should not
/// rely on grant TTLs.
pub(super) fn boot_epoch_ns() -> u64 {
    let rt = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    };
    let bt = || {
        let mut t = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t) };
        t.tv_sec as u64 * 1_000_000_000 + t.tv_nsec as u64
    };
    rt().saturating_sub(bt())
}

/// Create `/sys/fs/cgroup/mcp-writ-ebpf-<pid>-<nonce>` and open it plus
/// a `cgroup.procs` write fd for the child.
fn create_private_cgroup() -> Result<(PrivateCgroup, File), PrepareError> {
    let cgroup = PrivateCgroup::create("ebpf").map_err(|e| err("private cgroup create", e))?;
    let procs_w = match std::fs::OpenOptions::new()
        .write(true)
        .open(cgroup.dir.join("cgroup.procs"))
    {
        Ok(f) => f,
        Err(e) => {
            // The cgroup dir is removed by `PrivateCgroup`'s drop.
            return Err(err("private cgroup.procs open", e));
        }
    };
    Ok((cgroup, procs_w))
}

fn entry_bytes(e: &RuleEntry) -> &[u8] {
    // Safety: RuleEntry is a repr(C) POD of exactly RULE_ENTRY_SIZE.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        std::slice::from_raw_parts(
            e as *const RuleEntry as *const u8,
            super::rules::RULE_ENTRY_SIZE,
        )
    }
}

/// Fail-closed overlap check between the policy's effective fs write
/// grants and the cgroup v2 hierarchy the private cgroup lives under.
///
/// cgroup-BPF attach enforces on the cgroup *subtree*: a workload that
/// can write `cgroup.procs` of a cgroup outside the private subtree
/// (`/sys/fs/cgroup` or an ancestor — `/sys`, `/`, or any covering glob)
/// migrates itself or a child out from under the attached programs and
/// sheds connect enforcement entirely. Any grant spelling covering the
/// v2 root — or inside it, where it could still name `cgroup.procs` or
/// `cgroup.subtree_control` of a sibling branch — refuses the launch.
/// A root-glob spelling (`/*`, `/**`) reduces to an empty base every
/// grant builder skips — it grants nothing and is skipped here too.
/// Any other unresolvable spelling refuses: "cannot prove disjoint"
/// stays on the refuse side.
pub fn cgroup_write_grant_conflict(policy: &crate::policy::Policy) -> Option<String> {
    let root = match crate::fsoverlap::resolve_grant_spelling(CGROUP_ROOT) {
        Some(r) => r,
        None => {
            return Some(format!("cannot resolve the cgroup v2 root '{CGROUP_ROOT}'"));
        }
    };
    for grant in policy.write_grant_spellings() {
        match crate::fsoverlap::resolve_grant_spelling(&grant) {
            Some(g) => {
                if crate::fsoverlap::path_covers(&g, &root)
                    || crate::fsoverlap::path_covers(&root, &g)
                {
                    return Some(format!(
                        "fs write grant '{grant}' (resolves to '{}') overlaps the cgroup v2 \
                         hierarchy at '{}' — a workload could move itself out of the \
                         enforced cgroup and shed the connect hooks",
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
        let stats = mk(
            "stats map create",
            sys::BPF_MAP_TYPE_ARRAY,
            4,
            prog::STATS_VALUE_SIZE as u32,
            1,
        )?;
        let clock = mk("clock map create", sys::BPF_MAP_TYPE_ARRAY, 4, 8, 1)?;
        let seq = mk("seq map create", sys::BPF_MAP_TYPE_ARRAY, 4, 8, 1)?;

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
        sys::map_update(
            stats.raw(),
            &0u32.to_ne_bytes(),
            &[0u8; prog::STATS_VALUE_SIZE],
        )
        .map_err(|e| err("stats map init", e))?;
        // Rests even — `write_grant_maps` raises it odd across a
        // slot rewrite and lands it on the next even value.
        sys::map_update(seq.raw(), &0u32.to_ne_bytes(), &0u64.to_ne_bytes())
            .map_err(|e| err("seq map init", e))?;
        // Written before either program attaches, so no connect can
        // read a zero epoch (which would dead-check every grant).
        sys::map_update(
            clock.raw(),
            &0u32.to_ne_bytes(),
            &boot_epoch_ns().to_ne_bytes(),
        )
        .map_err(|e| err("clock map init", e))?;

        let maps4 = ProgMaps {
            rules: rules4.raw(),
            grants: grants4.raw(),
            events: events.raw(),
            stats: stats.raw(),
            seq: seq.raw(),
            clock: clock.raw(),
        };
        let maps6 = ProgMaps {
            rules: rules6.raw(),
            grants: grants6.raw(),
            events: events.raw(),
            stats: stats.raw(),
            seq: seq.raw(),
            clock: clock.raw(),
        };
        let mut vlog = Vec::new();
        // Load + attach per hook: a program's `expected_attach_type`
        // must match the attach call, so each hook needs its own load
        // even though the connect and sendmsg programs share their
        // rule tables (the sendmsg variant additionally allows the
        // nameless/connected-socket send the connect hook already
        // gated). Any failed step unwinds the whole prepare —
        // enforcement never runs partially attached.
        let mut progs: Vec<(Fd, u32)> = Vec::new();
        for (kind, maps, load_step, attach_step) in [
            (
                ProgKind::V4Connect,
                maps4,
                "INET4_CONNECT prog load",
                "INET4_CONNECT attach",
            ),
            (
                ProgKind::V4Sendmsg,
                maps4,
                "UDP4_SENDMSG prog load",
                "UDP4_SENDMSG attach",
            ),
            (
                ProgKind::V6Connect,
                maps6,
                "INET6_CONNECT prog load",
                "INET6_CONNECT attach",
            ),
            (
                ProgKind::V6Sendmsg,
                maps6,
                "UDP6_SENDMSG prog load",
                "UDP6_SENDMSG attach",
            ),
        ] {
            let insns = prog::build(
                kind,
                maps,
                if kind.is_v6() { &table.v6 } else { &table.v4 },
                GRANT_SLOTS,
                table.default_allow,
            );
            let fd = Fd(sys::prog_load(&insns, kind.attach_type(), &mut vlog)
                .map_err(|e| err(load_step, e))?);
            if let Err(e) = sys::prog_attach(cgroup.fd.as_raw_fd(), fd.raw(), kind.attach_type()) {
                // No `Runtime` exists to `Drop` — detach every program
                // already attached so the cgroup is not left holding
                // hooks whose fds are about to close.
                for (fd, ty) in progs.drain(..) {
                    let _ = sys::prog_detach(cgroup.fd.as_raw_fd(), fd.raw(), ty);
                }
                return Err(err(attach_step, e));
            }
            progs.push((fd, kind.attach_type()));
        }

        Ok(Runtime {
            cgroup,
            procs_w,
            _rules4: rules4,
            _rules6: rules6,
            grants4,
            grants6,
            events,
            stats,
            clock,
            seq,
            progs,
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
    /// Clock-epoch map fd — the drain rewrites it each resync tick so
    /// a post-load realtime step propagates to grant expiry within
    /// that interval rather than staying skewed for the launch's
    /// lifetime.
    pub fn clock_fd(&self) -> RawFd {
        self.clock.raw()
    }
    /// Grant maps for dynamic-allowlist resync.
    pub fn grant_map(&self, fam: super::rules::Family) -> RawFd {
        match fam {
            super::rules::Family::V4 => self.grants4.raw(),
            super::rules::Family::V6 => self.grants6.raw(),
        }
    }
    /// Stats map fd — the drain thread reads the counters.
    pub fn stats_fd(&self) -> RawFd {
        self.stats.raw()
    }
    /// Grant-seqlock map fd — `write_grant_maps` brackets every slot
    /// rewrite in its counter.
    pub fn seq_fd(&self) -> RawFd {
        self.seq.raw()
    }
    /// Read `[denied, denied_dropped]` from the stats map.
    pub fn stats(&self) -> [u64; 2] {
        let mut buf = [0u8; prog::STATS_VALUE_SIZE];
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
    /// again from `Drop`. Returns the member count still listed
    /// after the bounded sweep (0 = clean).
    pub fn kill_members(&self) -> usize {
        let n = self.cgroup.kill_members();
        if n > 0 {
            tracing::warn!(
                members = n,
                "private cgroup still lists workload members after the \
                 kill sweep — the connect programs stay attached so the \
                 IP hooks keep covering them"
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
        if self.kill_members() > 0 {
            // Members outlived the bounded sweep (alive, or zombies
            // mid-reap): keep the programs attached — the IP hooks
            // stay enforced on them and the residue cgroup the rmdir
            // EBUSYs on outlives this Runtime. Detaching here would
            // strip enforcement from processes that can still run.
            tracing::warn!(
                "private cgroup still holds workload members at drop — \
                 leaving the connect programs attached"
            );
            return;
        }
        // Detach so a racing connect/sendmsg in a still-dying child
        // can't hit a closed program fd's slot.
        for (prog, ty) in &self.progs {
            let _ = sys::prog_detach(self.cgroup.fd.as_raw_fd(), prog.raw(), *ty);
        }
    }
}
