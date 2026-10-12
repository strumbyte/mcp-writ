//! Capability report for the CONNECT-proxy route — the honest
//! statement of what this mechanism enforces, parallel to
//! `namespaced::report` / `ebpf::report`.

use std::net::SocketAddr;

use crate::audit_log::PolicyAuditContext;
use crate::warden::plan;

use super::ProxyStats;

/// Fixed limitations of the CONNECT-proxy route — surfaced in
/// `--report` output and the docs. Keep in sync with `docs/guide*.md`
/// and the PR guide.
pub const LIMITATIONS: &[&str] = &[
    "TCP only — the CONNECT protocol has no UDP equivalent, so the \
     SBPL profile denies all UDP egress outright (a UDP-capable allow \
     rule is unenforced on this path, warned at startup)",
    "the workload must use the injected proxy env (or connect to the \
     listener explicitly): a client that ignores proxy env vars has no \
     egress at all — that is fail-closed, but it means applications \
     without proxy support cannot egress",
    "enforcement relies on the sandbox pinning every outbound TCP \
     connect to loopback — a sibling process on the host that learns \
     the per-launch credential could use the proxy, and a workload \
     that escapes sandbox-exec escapes the pin entirely (the \
     sandbox-exec boundary itself is the OS limit, not this proxy)",
    "kernel-level SBPL denies are unobservable — only proxy-evaluated \
     refusals emit sandbox.network_denied; a direct connect the \
     profile refuses leaves no audit record (documented observation \
     gap, same as the native path)",
    "name→IP grants minted by the proxy use a fixed 5-minute cap — \
     getaddrinfo exposes no TTL, so a name's addresses stay \
     authorized up to the cap even if DNS re-points them (the DNS \
     gate's answer-accurate TTLs are the stronger mechanism where it \
     runs)",
    "CONNECT to loopback/link-local/multicast/unspecified is refused \
     regardless of policy — the proxy runs on the host network where \
     those addresses name host services (SSRF guard); workloads that \
     legitimately need loopback services reach them only via \
     policy-declared localhost:port rules",
    "sandbox-exec itself is deprecated (no kernel acceptance signal; \
     its own limits apply — see the native path's limitations); this \
     route adds a proxy, it does not strengthen the boundary",
    "the proxy task is trusted code in the launcher process — a \
     launcher compromise voids the mechanism; for a boundary that does \
     not trust the supervisor, Apple Container's VM/NAT isolation is \
     the documented stronger route (tracked separately, not \
     implemented here)",
    "no fallback: if the proxy route cannot start it refuses the \
     launch — it never silently substitutes the native \
     sandbox-exec-only path",
];

/// The `layer=name`/`layer=ip` egress status under this route.
fn name_layer_status() -> crate::enforcement::EgressLayerStatus {
    crate::enforcement::EgressLayerStatus {
        layer: "name",
        rpc: "auditor",
        os: Some("connect-proxy".to_string()),
        note: Some(
            "CONNECT authority names evaluated by the proxy against allow/deny \
             host rules (deny wins, deny_all_others applies); allowed names are \
             resolved outside the sandbox and mint fixed-cap grants into the IP \
             layer under the covering rules' proto/port qualifiers"
                .to_string(),
        ),
    }
}

fn ip_layer_status() -> crate::enforcement::EgressLayerStatus {
    crate::enforcement::EgressLayerStatus {
        layer: "ip",
        rpc: "auditor",
        os: Some("connect-proxy + sbpl loopback pin".to_string()),
        note: Some(
            "SBPL pins every outbound TCP connect to the loopback proxy; the \
             proxy enforces cidr/IP-literal rules, deny rules, and minted \
             grants per flow before dialing outward"
                .to_string(),
        ),
    }
}

fn layer_status_json(
    lo: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    l: &crate::enforcement::EgressLayerStatus,
) -> std::fmt::Result {
    struct JsonNull;
    impl nojson::DisplayJson for JsonNull {
        fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
            write!(f.inner_mut(), "null")
        }
    }
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

/// Machine-readable report for `macos-proxy-run --report`: capability
/// state, the two-layer egress disposition, the proxy endpoint shape
/// (never the credential), limitations, and live stats.
/// `policy`/`endpoint` are `None` when the launch refused before the
/// corresponding stage.
pub fn report_json(
    launch_id: uuid::Uuid,
    state: &str,
    reason: Option<&str>,
    policy: Option<&crate::policy::Policy>,
    policy_ctx: Option<&PolicyAuditContext>,
    endpoint: Option<SocketAddr>,
    stats: Option<&ProxyStats>,
) -> String {
    nojson::object(|o| -> std::fmt::Result {
        o.member("schema_version", "1.0")?;
        o.member("component", "macos-proxy-run")?;
        o.member("launch_id", launch_id.to_string().as_str())?;
        o.member(
            "capability",
            nojson::object(|c| -> std::fmt::Result {
                c.member("mechanism", "sbpl-loopback-connect-proxy")?;
                c.member("state", state)?;
                if let Some(r) = reason {
                    c.member("reason", r)?;
                }
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
                            for l in [&name_layer_status(), &ip_layer_status()] {
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
            "proxy",
            nojson::object(|p| -> std::fmt::Result {
                p.member(
                    "listen",
                    endpoint
                        .map(|a| a.to_string())
                        .as_deref()
                        .unwrap_or("not-bound"),
                )?;
                p.member("credential", "per-launch bearer (redacted)")?;
                p.member(
                    "env_vars",
                    nojson::array(|a| {
                        for k in super::PROXY_ENV_VARS {
                            a.element(*k)?;
                        }
                        Ok(())
                    }),
                )?;
                p.member("protocol", "CONNECT host:port (RFC 7231), Basic proxy-auth")?;
                Ok(())
            }),
        )?;
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
            "proxy_stats",
            nojson::object(|s| -> std::fmt::Result {
                use std::sync::atomic::Ordering::Relaxed;
                let zero = ProxyStats::default();
                let st = stats.unwrap_or(&zero);
                s.member("accepted", st.accepted.load(Relaxed))?;
                s.member("denied_name", st.denied_name.load(Relaxed))?;
                s.member("denied_ip", st.denied_ip.load(Relaxed))?;
                s.member("denied_protected", st.denied_protected.load(Relaxed))?;
                s.member("denied_auth", st.denied_auth.load(Relaxed))?;
                s.member("rejected_method", st.rejected_method.load(Relaxed))?;
                s.member("rejected_head", st.rejected_head.load(Relaxed))?;
                s.member("resolve_failed", st.resolve_failed.load(Relaxed))?;
                s.member("dial_failed", st.dial_failed.load(Relaxed))?;
                s.member("bytes_to_workload", st.bytes_to_workload.load(Relaxed))?;
                s.member("bytes_from_workload", st.bytes_from_workload.load(Relaxed))?;
                Ok(())
            }),
        )?;
        Ok(())
    })
    .to_string()
}
