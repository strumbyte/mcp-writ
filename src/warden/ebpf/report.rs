//! Capability report — the cgroup-eBPF route's honest enforcement
//! statement, parallel to `unotify::report`.

use std::path::Path;

use crate::audit_log::PolicyAuditContext;
use crate::warden::plan;

use super::supervisor::DrainStats;

/// Fixed limitations of the cgroup-eBPF route — surfaced in `--report`
/// output and the docs. Keep in sync with `docs/guide*.md` and the PR
/// guide.
pub const LIMITATIONS: &[&str] = &[
    "connect(2) only — UDP send paths that never call connect \
     (sendto/sendmsg on an unconnected datagram socket), TCP \
     MSG_FASTOPEN setup, io_uring IORING_OP_CONNECT, proxy-style fd \
     passing (SCM_RIGHTS of an already-connected socket into the \
     cgroup), and non-socket channels are outside this layer",
    "IPv4/IPv6 only — AF_UNIX, AF_PACKET, and other families do not \
     reach the INET4/6_CONNECT hooks",
    "enforcement is cgroup-scoped: the workload tree joins a private \
     cgroup in pre_exec; a process moved elsewhere escapes the hooks \
     (only a privileged outside process can do that)",
    "kernel-enforced denies are observed through a ring buffer — a full \
     buffer cannot weaken the verdict but loses the audit record (the \
     denied_dropped counter reports it)",
    "requires CAP_BPF/CAP_SYS_ADMIN + CAP_NET_ADMIN and a writable \
     cgroup v2 hierarchy (checked at startup — never silently \
     degraded); kernels without CONFIG_CGROUP_BPF or the cgroup \
     socket-addr hooks (e.g. WSL2 builds lacking it) refuse",
    "the in-kernel wall clock for grant expiry is ktime_get_boot_ns + \
     a wall-clock epoch the drain refreshes each resync tick — \
     clock-domain drift stays sub-second, and a post-load realtime \
     step (NTP sync, a manual clock change) skews grant expiry by at \
     most ~500ms before the next refresh corrects it",
    "teardown SIGKILLs workload members still in the private cgroup \
     (a setsid'd daemon or orphaned worker would otherwise outlive \
     the supervised child with the cgroup — and rmdir-blocking \
     membership — left behind): cgroup.kill where the kernel has it, \
     else a freeze + per-pid sweep",
    "if the supervisor itself dies abruptly (SIGKILL on the launcher) \
     the private cgroup and its attached programs can be left behind \
     — leftover members stay kernel-denied (fail-closed) until the \
     residue is removed with rmdir + bpftool detach",
    "no fallback: if this route cannot start it refuses the launch — \
     it never silently substitutes unotify or the ordinary pipeline",
];

/// JSON literal `null` for optional report fields.
struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

fn layer_status_json(
    lo: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    l: &crate::enforcement::EgressLayerStatus,
) -> std::fmt::Result {
    lo.member("layer", l.layer)?;
    lo.member("rpc", l.rpc)?;
    match &l.os {
        Some(os) => lo.member("os", os.as_str())?,
        None => lo.member("os", &JsonNull)?,
    }
    match &l.note {
        Some(n) => lo.member("note", n.as_str())?,
        None => lo.member("note", &JsonNull)?,
    }
    Ok(())
}

/// The `layer=ip` egress status under this route — the real mechanism
/// plus its honest ceiling.
pub fn ip_layer_status() -> crate::enforcement::EgressLayerStatus {
    crate::enforcement::EgressLayerStatus {
        layer: "ip",
        rpc: "auditor",
        os: Some("cgroup-ebpf INET4/6_CONNECT".to_string()),
        note: Some(
            "connect(2) destinations enforced in-kernel against cidr rules, \
             IP-literal host rules, and dynamic grants with proto/port scope; \
             connect-only scope + UDP-sendto gap + cgroup-scoped coverage \
             apply (see report limitations)"
                .to_string(),
        ),
    }
}

/// Machine-readable report for `ebpf-run --report`: capability state,
/// the two-layer egress disposition, limitations, and (after exit)
/// drain counters. `policy` is `None` when the launch refused before
/// one loaded.
pub fn report_json(
    launch_id: uuid::Uuid,
    state: &str,
    reason: Option<&str>,
    policy: Option<&crate::policy::Policy>,
    policy_ctx: Option<&PolicyAuditContext>,
    allowlist: Option<&Path>,
    stats: Option<&DrainStats>,
) -> String {
    let mut uname_buf: libc::utsname = unsafe { std::mem::zeroed() };
    // Safety: `uname_buf` is a live, correctly-sized out buffer.
    let kernel = if unsafe { libc::uname(&mut uname_buf) } == 0 {
        unsafe {
            std::ffi::CStr::from_ptr(uname_buf.release.as_ptr())
                .to_string_lossy()
                .into_owned()
        }
    } else {
        "unknown".to_string()
    };
    let name_status = crate::enforcement::EgressLayerStatus {
        layer: "name",
        rpc: "auditor",
        os: Some("dns-gate (optional, external)".to_string()),
        note: Some(
            "host rules are name-layer; the dns-gate resolver enforces them for \
             workloads pointed at it, and its allowlist export feeds this \
             route's grant maps"
                .to_string(),
        ),
    };
    nojson::object(|o| -> std::fmt::Result {
        o.member("schema_version", "1.0")?;
        o.member("component", "ebpf-run")?;
        o.member("launch_id", launch_id.to_string().as_str())?;
        o.member(
            "capability",
            nojson::object(|c| -> std::fmt::Result {
                c.member("mechanism", "cgroup-ebpf")?;
                c.member("hooks", "BPF_CGROUP_INET4_CONNECT+INET6_CONNECT")?;
                c.member("kernel_release", kernel.as_str())?;
                c.member("state", state)?;
                if let Some(r) = reason {
                    c.member("reason", r)?;
                }
                c.member(
                    "allowlist_source",
                    allowlist
                        .map(|p| p.display().to_string())
                        .as_deref()
                        .unwrap_or("none"),
                )?;
                Ok(())
            }),
        )?;
        if let Some(policy) = policy {
            let out = &policy.network.outbound;
            o.member(
                "egress_layers",
                nojson::object(|e| -> std::fmt::Result {
                    e.member(
                        "default_action",
                        if out.deny_all_others {
                            "deny_all"
                        } else {
                            "allow_all"
                        },
                    )?;
                    e.member(
                        "layers",
                        nojson::array(|a| {
                            for l in [&name_status, &ip_layer_status()] {
                                a.element(nojson::object(|lo| layer_status_json(lo, l)))?;
                            }
                            Ok(())
                        }),
                    )?;
                    e.member(
                        "rules",
                        nojson::array(|a| {
                            for r in plan::egress_rule_table(policy) {
                                a.element(nojson::object(|ro| {
                                    ro.member("effect", r.effect)?;
                                    ro.member("kind", r.kind)?;
                                    ro.member("rule", r.rule.as_str())?;
                                    ro.member("proto", r.proto)?;
                                    ro.member("port", r.port)?;
                                    ro.member("name_layer", r.name_layer)?;
                                    ro.member("ip_layer", r.ip_layer)?;
                                    Ok(())
                                }))?;
                            }
                            Ok(())
                        }),
                    )?;
                    Ok(())
                }),
            )?;
        }
        if let Some(ctx) = policy_ctx {
            o.member(
                "policy",
                nojson::object(|p| -> std::fmt::Result {
                    p.member("id", ctx.id.as_str())?;
                    p.member("version", ctx.version.as_str())?;
                    p.member("hash", ctx.hash.as_str())?;
                    Ok(())
                }),
            )?;
        }
        o.member(
            "limitations",
            nojson::array(|a| {
                for l in LIMITATIONS {
                    a.element(*l)?;
                }
                Ok(())
            }),
        )?;
        o.member(
            "drain_stats",
            nojson::object(|s| -> std::fmt::Result {
                let st = stats.cloned().unwrap_or_default();
                s.member("denied", st.denied)?;
                s.member("denied_dropped", st.dropped)?;
                s.member("malformed_records", st.malformed)?;
                s.member("busy_records", st.busy)?;
                s.member("grant_syncs", st.grant_syncs)?;
                s.member("grant_entries", st.grant_entries)?;
                s.member("grants_dropped", st.grants_dropped)?;
                s.member("audit_errors", st.audit_errors)?;
                Ok(())
            }),
        )?;
        Ok(())
    })
    .to_string()
}
