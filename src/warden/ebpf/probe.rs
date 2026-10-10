//! Capability probe — startup refusal diagnostics for the opt-in
//! cgroup-eBPF route. Mirrors `unotify::probe::check_support`: refuses
//! with a named diagnostic when a required piece is missing — never
//! silently degrades, and `sandbox.allow_degraded` does not cover this
//! check.
//!
//! Cheap static checks run here (cgroup v2 mount, capability bits, a
//! minimal `CGROUP_SOCK_ADDR` program load); the authoritative probe
//! is [`Runtime::prepare`](super::runtime::Runtime::prepare) itself —
//! it builds and attaches the real programs before any child exists.

use std::io;

use super::prog;
use super::sys;

/// `/proc/self/status` `CapEff` bit names we report on.
const CAP_NET_ADMIN: u64 = 12;
const CAP_SYS_ADMIN: u64 = 21;
const CAP_BPF: u64 = 39;
/// `CAP_PERFMON` — newer kernels split map-create checks this way.
const CAP_PERFMON: u64 = 38;

fn cap_eff() -> Option<u64> {
    let body = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = body.lines().find(|l| l.starts_with("CapEff:"))?;
    u64::from_str_radix(line.strip_prefix("CapEff:")?.trim(), 16).ok()
}

fn has_cap(eff: u64, cap: u64) -> bool {
    eff & (1 << cap) != 0
}

/// Verify the environment supports what the route needs. Refuses with
/// a stage-named diagnostic when any piece is missing.
///
/// Checks, in order:
/// 1. cgroup v2 mounted at `/sys/fs/cgroup` (`cgroup.controllers`).
/// 2. Effective capabilities — `CAP_BPF`/`CAP_SYS_ADMIN` for bpf()
///    program+map ops, `CAP_NET_ADMIN` for cgroup attach — plus write
///    access to the hierarchy.
/// 3. `bpf(BPF_MAP_CREATE)` — syscall reachable, features present.
/// 4. A minimal `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` /
///    `BPF_CGROUP_INET4_CONNECT` program load — proves
///    `CONFIG_CGROUP_BPF` and the attach type exist (some kernels, e.g.
///    WSL2, compile them out).
pub fn check_support() -> Result<(), String> {
    // 1. cgroup v2 hierarchy.
    if !std::path::Path::new("/sys/fs/cgroup/cgroup.controllers").exists() {
        return Err(
            "cgroup v2 is not mounted at /sys/fs/cgroup — a unified cgroup2 \
             hierarchy is required for cgroup eBPF enforcement"
                .into(),
        );
    }

    // 2. Capabilities — name what's missing rather than letting a raw
    //    EPERM surface from the first bpf() call.
    let eff = cap_eff().unwrap_or(0);
    let can_bpf = has_cap(eff, CAP_BPF) || has_cap(eff, CAP_SYS_ADMIN);
    let missing: Vec<&str> = [
        (!can_bpf).then_some("CAP_BPF or CAP_SYS_ADMIN (bpf program/map ops)"),
        (!has_cap(eff, CAP_NET_ADMIN)).then_some("CAP_NET_ADMIN (cgroup attach)"),
        (!has_cap(eff, CAP_PERFMON) && !has_cap(eff, CAP_SYS_ADMIN))
            .then_some("CAP_PERFMON or CAP_SYS_ADMIN (ring buffer map)"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !missing.is_empty() {
        return Err(format!(
            "missing required capabilities: {}",
            missing.join(", ")
        ));
    }
    // The private cgroup is created under the hierarchy root — without
    // write access there is nowhere to attach.
    // Safety: plain access(2) on a literal path.
    if unsafe { libc::access(c"/sys/fs/cgroup".as_ptr(), libc::W_OK) } != 0 {
        return Err(format!(
            "/sys/fs/cgroup is not writable: {} — the route needs to create \
             a private cgroup (delegated subtree or run privileged)",
            io::Error::last_os_error()
        ));
    }

    // 3. bpf() syscall reachable — a 1-entry ARRAY is the cheapest op.
    match sys::map_create(sys::BPF_MAP_TYPE_ARRAY, 4, 8, 1) {
        Ok(fd) => unsafe {
            libc::close(fd);
        },
        Err(e) => {
            return Err(format!(
                "bpf(BPF_MAP_CREATE) failed: {e} — {}",
                match e.raw_os_error() {
                    Some(libc::EPERM) | Some(libc::EACCES) =>
                        "the kernel refused despite reported capabilities \
                         (unprivileged_bpf_disabled=2 or LSM policy)",
                    Some(libc::ENOSYS) => "the kernel lacks bpf() entirely",
                    _ => "unexpected bpf() failure",
                }
            ));
        }
    }

    // 4. A minimal CGROUP_SOCK_ADDR/INET4_CONNECT load — the real
    //    CONFIG_CGROUP_BPF probe (two instructions: r0=1 (allow), exit).
    let insns = [
        // mov64 r0, 1
        prog::ins(0xb7, 0, 0, 0, 1),
        // exit
        prog::ins(0x95, 0, 0, 0, 0),
    ];
    let mut vlog = Vec::new();
    match sys::prog_load(&insns, sys::BPF_CGROUP_INET4_CONNECT, &mut vlog) {
        Ok(fd) => unsafe {
            libc::close(fd);
        },
        Err(e) => {
            return Err(format!(
                "CGROUP_SOCK_ADDR/INET4_CONNECT program load failed: {e} — {}",
                match e.raw_os_error() {
                    Some(libc::EINVAL) =>
                        "kernel lacks CONFIG_CGROUP_BPF or the cgroup socket-addr \
                         attach type (e.g. a WSL2 kernel built without it)",
                    Some(libc::EPERM) | Some(libc::EACCES) =>
                        "permission denied loading a cgroup program",
                    _ => "unexpected bpf(PROG_LOAD) failure",
                }
            ));
        }
    }
    Ok(())
}
