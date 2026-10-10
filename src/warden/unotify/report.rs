//! Capability report — the opt-in path's honest enforcement statement.

use std::path::Path;

use crate::audit_log::PolicyAuditContext;
use crate::warden::plan;

use super::supervisor::SupervisorStats;

/// Fixed limitations of the PoC — surfaced in `--report` output and the
/// docs. Keep this list in sync with `docs/guide*.md` and the PR guide.
pub const LIMITATIONS: &[&str] = &[
    "connect(2) only — sendto/sendmsg datagram egress (including TCP \
     setup via MSG_FASTOPEN, which never calls connect), io_uring \
     IORING_OP_CONNECT, proxy-style fd passing, and non-socket \
     channels are outside this layer",
    "TOCTOU: the supervisor reads the child's sockaddr with \
     process_vm_readv; a hostile workload may rewrite the buffer \
     between inspection and the kernel's use of it",
    "non-AF_INET/AF_INET6 families (AF_UNIX, AF_PACKET, ...) are \
     continued unsupervised",
    "the socket's protocol is read via pidfd_getfd+getsockopt(SO_TYPE); \
     when that fails proto reports 'unknown' (the IP/port verdict is \
     unaffected)",
    "supervisor death fails closed: the kernel returns ENOSYS to pending \
     and future connects; the command also kills the supervised child",
    "requires SECCOMP_USER_NOTIF_FLAG_CONTINUE (Linux ≥ 5.5); checked at \
     startup, never silently degraded",
    "foreign-architecture (compat) tasks are killed rather than \
     supervised — their syscall table is not this filter's table",
    "port-qualified allow rules refuse at startup — widening them to \
     every port would be silent",
    "the notification fires only when the policy's own seccomp filter \
     allows connect — a syscall-level connect deny stays denied but is \
     not audited at this layer",
    "the supervised tree is the child's process group; a workload that \
     escapes via setsid loses tree-kill coverage (its own connects stay \
     filtered — the filter is per-task, inherited at clone)",
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

/// The `layer=ip` egress status under this PoC — the real mechanism
/// plus its honest ceiling, parallel to the Auditor-only note the
/// ordinary Linux path reports.
pub fn ip_layer_status() -> crate::enforcement::EgressLayerStatus {
    crate::enforcement::EgressLayerStatus {
        layer: "ip",
        rpc: "auditor",
        os: Some("seccomp-user-notif (PoC)".to_string()),
        note: Some(
            "connect(2) destinations evaluated against cidr rules, IP-literal \
             host rules, and live DNS-grant entries; TOCTOU + connect-only \
             scope + supervisor-lifetime limits apply (see report limitations)"
                .to_string(),
        ),
    }
}

/// Machine-readable PoC report for `unotify-run --report`: capability
/// state, the two-layer egress disposition, limitations, and (after
/// exit) supervisor counters. `policy` is `None` when the launch
/// refused before one loaded — the report then omits `egress_layers`.
pub fn report_json(
    launch_id: uuid::Uuid,
    state: &str,
    reason: Option<&str>,
    policy: Option<&crate::policy::Policy>,
    policy_ctx: Option<&PolicyAuditContext>,
    allowlist: Option<&Path>,
    stats: Option<&SupervisorStats>,
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
             supervisor's grant source"
                .to_string(),
        ),
    };
    nojson::object(|o| -> std::fmt::Result {
        o.member("schema_version", "1.0")?;
        o.member("component", "unotify-run")?;
        o.member("launch_id", launch_id.to_string().as_str())?;
        o.member(
            "capability",
            nojson::object(|c| -> std::fmt::Result {
                c.member("mechanism", "seccomp-user-notif")?;
                c.member("syscall", "connect")?;
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
            "supervisor_stats",
            nojson::object(|s| -> std::fmt::Result {
                let st = stats.cloned().unwrap_or_default();
                s.member("notifications", st.notifications)?;
                s.member("continued", st.continued)?;
                s.member("denied", st.denied)?;
                s.member("noninet_skipped", st.noninet_skipped)?;
                s.member("unreadable_denied", st.unreadable_denied)?;
                s.member("expired", st.expired)?;
                s.member("audit_unavailable_denied", st.audit_unavailable_denied)?;
                s.member("send_errors", st.send_errors)?;
                s.member("audit_errors", st.audit_errors)?;
                Ok(())
            }),
        )?;
        Ok(())
    })
    .to_string()
}
