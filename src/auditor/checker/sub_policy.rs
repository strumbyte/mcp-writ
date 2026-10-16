//! Per-tool sub-policy enforcement: fs path and network host allow/deny
//! lists, the `read_only` side-effect guard, and the secret-path overlay
//! applied to extracted argument targets.

use crate::policy::host::extract_host_from_url;
use crate::policy::{EgressDest, EgressProto, Policy, ToolPolicy};

use super::PolicyViolation;
use super::targets::{ExtractedTargets, collect_argument_targets};

/// A request-side network destination: the canonical host plus the
/// `port=`/`proto=` qualifiers the argument spelling pinned. Bare host
/// and unknown-scheme values inherit the pre-schema convention — an
/// `allow` rule only ever described TCP reachability — so they carry
/// `proto=Tcp` with no port.
struct NetTarget {
    host: String,
    port: Option<u16>,
    proto: EgressProto,
}

/// URL scheme → transport. Everything not recognizably datagram-based
/// is TCP — the pre-schema `allow` contract described TCP reachability.
fn scheme_proto(scheme: &str) -> EgressProto {
    match scheme.to_ascii_lowercase().as_str() {
        "udp" | "dns" | "ntp" | "quic" | "stun" | "stuns" | "dtls" | "sip" | "sips" | "mdns"
        | "tftp" | "snmp" => EgressProto::Udp,
        _ => EgressProto::Tcp,
    }
}

/// Default destination port for a known URL scheme — the port an
/// unqualified `https://host` call actually dials, so a `port=443`
/// qualifier can be verified without an explicit `:443`.
fn scheme_default_port(scheme: &str) -> Option<u16> {
    match scheme.to_ascii_lowercase().as_str() {
        "http" | "ws" => Some(80),
        "https" | "wss" => Some(443),
        "ftp" => Some(21),
        "ssh" => Some(22),
        "telnet" => Some(23),
        "smtp" => Some(25),
        "dns" => Some(53),
        "pop3" => Some(110),
        "pop3s" => Some(995),
        "ntp" => Some(123),
        "imap" => Some(143),
        "imaps" => Some(993),
        "ldap" => Some(389),
        "ldaps" => Some(636),
        "smtps" => Some(465),
        _ => None,
    }
}

fn egress_dest_matches(dest: &EgressDest, target: &NetTarget) -> bool {
    match dest {
        EgressDest::Host(h) => host_matches(&target.host, h),
        EgressDest::Cidr(c) => crate::policy::host::normalize_policy_host(&target.host)
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| crate::policy::host::cidr_contains(c, &ip)),
        // An AF_UNIX opt-in never matches a host/IP egress target — it
        // binds a socket path, not a network flow.
        EgressDest::Unix(_) => false,
    }
}

fn reject_if_secret_overlay(tool: &ToolPolicy, path: &str) -> Result<(), PolicyViolation> {
    match crate::secret_paths::overlay_denies(path) {
        Ok(()) => Ok(()),
        Err(reason) => Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason,
        }),
    }
}

fn apply_secret_overlay(
    tool: &ToolPolicy,
    extracted: &ExtractedTargets,
) -> Result<(), PolicyViolation> {
    for path in &extracted.paths {
        reject_if_secret_overlay(tool, path)?;
    }
    for url in &extracted.urls {
        if secret_overlay_applies_to_url(url) {
            reject_if_secret_overlay(tool, url)?;
        }
    }
    Ok(())
}

/// Overlay is for filesystem arguments (`file:`, opaque `file:`, dirty
/// schemes, non-network strings). Ordinary `http(s):` URLs stay on the
/// network policy path.
fn secret_overlay_applies_to_url(url: &str) -> bool {
    crate::pathutil::starts_with_file_scheme(url)
        || crate::pathutil::is_opaque_file_uri(url)
        || crate::pathutil::uri_scheme_slot_is_dirty(url)
        || !crate::pathutil::looks_like_network_target(url)
}

/// Check tool-specific sub-policies (fs paths, network hosts) against request arguments,
/// and enforce global network denials.
/// Returns `true` if any sub-policy was evaluated.
pub(super) fn check_tool_sub_policy(
    json: &nojson::RawJson<'_>,
    tool: &ToolPolicy,
    policy: &Policy,
) -> Result<bool, PolicyViolation> {
    let mut has_sub = false;
    let extracted = collect_argument_targets(json);
    let fs_restricted = tool.fs.as_ref().is_some_and(|fs_policy| {
        fs_policy.allow_specified
            || fs_policy.require_path.is_some()
            || !fs_policy.allowed_paths.is_empty()
            || !fs_policy.denied_paths.is_empty()
    });

    let read_only = crate::policy::SideEffect::parse(tool.side_effect.as_deref().unwrap_or(""))
        .ok()
        == Some(crate::policy::SideEffect::ReadOnly);
    if read_only && (!extracted.hosts.is_empty() || !extracted.urls.is_empty()) {
        return Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason: "side_effect=\"read_only\" forbids host/URL arguments".to_string(),
        });
    }

    // The decoy-argument hole (F66/F11/F12): a string under a key
    // outside both the selector vocabularies and the declared payload
    // fields cannot be proven a non-selector. Under any restricted
    // contract — an fs allow/deny/require rule, a tool network block,
    // `read_only`, or a global outbound rule — such a string is
    // refused rather than forwarded unchecked next to an allowed decoy.
    let net_contract = tool.network.as_ref().is_some_and(|net| {
        net.allow_specified
            || !net.allowed_hosts.is_empty()
            || !net.allowed_cidrs.is_empty()
            || !net.denied_hosts.is_empty()
            || !net.denied_cidrs.is_empty()
            || !net.egress_rules.is_empty()
    }) || read_only
        || !policy.network.outbound.denied_hosts.is_empty()
        || !policy.network.outbound.denied_cidrs.is_empty()
        || policy.network.outbound.deny_all_others
        || !policy.network.outbound.allowed.is_empty()
        || !policy.network.outbound.allowed_cidrs.is_empty();
    // An over-budget walk is unknowable the same way an unrecognized
    // selector is: the retained targets are a strict prefix, so a
    // restricted contract denies rather than authorize a partial set.
    if (fs_restricted || net_contract) && extracted.truncated {
        return Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason: "argument target extraction exceeded the work budget".to_string(),
        });
    }
    if (fs_restricted || net_contract)
        && let Some(bad) = extracted
            .unclassified
            .iter()
            .find(|v| crate::pathutil::selector_plausible(v))
    {
        return Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!(
                "unrecognized argument '{bad}' may carry an undeclared resource \
                 selector — restricted tools accept only declared fields"
            ),
        });
    }

    if let Some(ref fs_policy) = tool.fs {
        has_sub = true;
        if fs_restricted {
            if extracted.paths.is_empty() && !fs_policy.allows_pathless_call() {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: "filesystem-restricted tool is missing a path target \
                             (checked path/file/uri and nested string fields)"
                        .to_string(),
                });
            }
            // The policy side is fixed for the whole request — resolve
            // its patterns once instead of canonicalizing per target.
            if !extracted.paths.is_empty() {
                let patterns = resolve_fs_patterns(tool, fs_policy)?;
                for path in &extracted.paths {
                    authorize_one_path_prepared(tool, fs_policy, &patterns, path)?;
                }
            }
        }
    }
    // Overlay beats explicit allow. Also inspect URL-classified values:
    // percent-encoded `file:` (`%66ile://…`) must not skip path extraction.
    if policy.fs.secret_overlay {
        apply_secret_overlay(tool, &extracted)?;
        if !extracted.paths.is_empty() || !extracted.urls.is_empty() {
            has_sub = true;
        }
    }

    // Authorization ran on the normalized spelling, but the forwarded
    // request carries the raw one. When they differ (NFKC-equivalent
    // names, percent-encoded bytes, `file:` spellings) the checked path
    // and the opened path are different filesystem objects — on a
    // byte-preserving filesystem they are distinct directory entries.
    // The rule applies where an allow decision was just spent (the
    // overlay is a deny-list on the normalized form, which spelling
    // tricks cannot slip past); a restricted call must carry the
    // canonical spelling itself.
    if !extracted.noncanonical.is_empty() && fs_restricted {
        let nc = &extracted.noncanonical[0];
        return Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!(
                "path argument '{}' is not in canonical form; resend the canonical spelling '{}'",
                nc.raw, nc.normalized
            ),
        });
    }

    // Build qualified destinations: bare host/socket arguments carry the
    // pre-schema `tcp` convention with whatever `:port` they spelled;
    // URLs add their scheme's transport and default port so a `port=443`
    // qualifier verifies `https://` even without an explicit `:443`.
    let mut targets: Vec<NetTarget> = Vec::new();
    for raw in &extracted.hosts {
        let (host, port, _) = crate::policy::host::analyze_policy_host(raw);
        targets.push(NetTarget {
            host,
            port,
            proto: EgressProto::Tcp,
        });
    }
    for url in &extracted.urls {
        match extract_host_from_url(url) {
            Some(h) => {
                let (_, port, _) = crate::policy::host::analyze_policy_host(url);
                let scheme = url.split("://").next().unwrap_or_default();
                targets.push(NetTarget {
                    host: h,
                    port: port.or_else(|| scheme_default_port(scheme)),
                    proto: scheme_proto(scheme),
                });
            }
            None => {
                if tool.network.is_some()
                    || !policy.network.outbound.denied_hosts.is_empty()
                    || !policy.network.outbound.denied_cidrs.is_empty()
                    || policy.network.outbound.deny_all_others
                    || !policy.network.outbound.allowed.is_empty()
                    || !policy.network.outbound.allowed_cidrs.is_empty()
                {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "invalid or unparseable URL '{url}' in network-restricted tool"
                        ),
                    });
                }
            }
        }
    }
    let hosts: Vec<String> = targets.iter().map(|t| t.host.clone()).collect();

    for target in &targets {
        let host = &target.host;
        for denied in &policy.network.outbound.denied_hosts {
            if host_matches(host, denied) {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' denied by global network policy"),
                });
            }
        }
        // IP layer: a literal-IP argument is also evaluated against the
        // `cidr` rules — `denied_hosts` IP literals already match
        // exactly via `host_matches` above. The argument is normalized
        // first so a bracketed `[v6]` spelling reaches the same check.
        let ip = crate::policy::host::normalize_policy_host(host)
            .parse::<std::net::IpAddr>()
            .ok();
        if let Some(ip) = ip {
            for denied in &policy.network.outbound.denied_cidrs {
                if crate::policy::host::cidr_contains(denied, &ip) {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "host '{host}' denied by global network cidr rule '{denied}'"
                        ),
                    });
                }
            }
        }
        // `deny_all_others` is a closed posture, not an allow-list gate:
        // with no allow rules at all it still denies every extracted
        // host — an empty allow-list is the default deny, not the
        // absence of one.
        if policy.network.outbound.deny_all_others {
            let allowed = policy
                .network
                .outbound
                .allowed
                .iter()
                .any(|a| host_matches(host, a))
                || ip.is_some_and(|ip| {
                    policy
                        .network
                        .outbound
                        .allowed_cidrs
                        .iter()
                        .any(|c| crate::policy::host::cidr_contains(c, &ip))
                });
            if !allowed {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' not in global outbound allow list"),
                });
            }
        }
    }

    if let Some(ref net_policy) = tool.network {
        has_sub = true;
        // A closed inherited allow-list (deny_all_others, empty allowed) must
        // reject hosts that appear, but must not demand a host on FS-only
        // calls. `allow none` is not listed here on purpose: it governs
        // destinations that appear, it does not require the call to name
        // one — the unclassified-argument deny above is what refuses a
        // hidden selector under it.
        let requires_host_target = !net_policy.allowed_hosts.is_empty()
            || !net_policy.denied_hosts.is_empty()
            || !net_policy.allowed_cidrs.is_empty()
            || !net_policy.denied_cidrs.is_empty()
            || !net_policy.egress_rules.is_empty();
        if requires_host_target && targets.is_empty() {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: "network-restricted tool is missing a url/host target \
                         (checked url/host/uri and nested string fields)"
                    .to_string(),
            });
        }
        // Declared `proto=`/`port=` qualifiers are part of the contract:
        // when the block carried structured egress rules, destination
        // authorization runs against the qualified rule set, deny-first —
        // a `port=443` allow must not authorize `host:444`, and a target
        // whose qualifiers cannot be determined is not covered.
        let qualified = net_policy.egress_rule_set();
        let has_qualified = !net_policy.egress_rules.is_empty();
        for target in &targets {
            let host = &target.host;
            for denied in &net_policy.denied_hosts {
                if host_matches(host, denied) {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!("host '{host}' denied by tool network sub-policy"),
                    });
                }
            }
            let ip = crate::policy::host::normalize_policy_host(host)
                .parse::<std::net::IpAddr>()
                .ok();
            if let Some(ip) = ip {
                for denied in &net_policy.denied_cidrs {
                    if crate::policy::host::cidr_contains(denied, &ip) {
                        return Err(PolicyViolation {
                            tool_name: tool.name.clone(),
                            reason: format!(
                                "host '{host}' denied by tool network cidr rule '{denied}'"
                            ),
                        });
                    }
                }
            }
            if has_qualified {
                // Deny rules overlap a flow whose qualifiers are unknown —
                // an unpinned port cannot prove it is not the denied one.
                let denied_qualified = qualified.iter().filter(|r| !r.allow).any(|rule| {
                    egress_dest_matches(&rule.dest, target)
                        && rule.proto.covers(target.proto)
                        && (rule.port.is_none()
                            || target.port.is_none()
                            || rule.port == target.port)
                });
                if denied_qualified {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "destination '{host}' denied by qualified tool egress rule"
                        ),
                    });
                }
                let allowed_qualified = qualified.iter().filter(|r| r.allow).any(|rule| {
                    egress_dest_matches(&rule.dest, target)
                        && rule.proto.covers(target.proto)
                        && rule.port.is_none_or(|p| target.port == Some(p))
                });
                if !allowed_qualified {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "destination '{host}' not covered by tool egress rules \
                             (proto/port qualifiers apply)"
                        ),
                    });
                }
            } else if net_policy.allow_specified
                || !net_policy.allowed_hosts.is_empty()
                || !net_policy.allowed_cidrs.is_empty()
            {
                let allowed = net_policy
                    .allowed_hosts
                    .iter()
                    .any(|a| host_matches(host, a))
                    || ip.is_some_and(|ip| {
                        net_policy
                            .allowed_cidrs
                            .iter()
                            .any(|c| crate::policy::host::cidr_contains(c, &ip))
                    });
                if !allowed {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!("host '{host}' not in tool network allowed hosts"),
                    });
                }
            }
        }
    } else if !hosts.is_empty()
        && (!policy.network.outbound.denied_hosts.is_empty()
            || !policy.network.outbound.denied_cidrs.is_empty())
    {
        has_sub = true;
    }

    if tool.syscalls.is_some() {
        has_sub = true;
    }

    Ok(has_sub)
}

/// Tool fs allow/deny patterns resolved once per request — the policy
/// side is fixed, so canonicalizing it inside the per-target loop would
/// multiply filesystem work by the extracted target count.
pub(super) struct ResolvedFsPatterns {
    denied: Vec<String>,
    allowed: Vec<String>,
}

fn resolve_fs_patterns(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
) -> Result<ResolvedFsPatterns, PolicyViolation> {
    let resolve = |pattern: &String| -> Result<String, PolicyViolation> {
        crate::pathutil::resolve_policy_pattern(pattern).map_err(|e| PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!("policy path '{pattern}' could not be resolved: {e}"),
        })
    };
    Ok(ResolvedFsPatterns {
        denied: fs_policy
            .denied_paths
            .iter()
            .map(resolve)
            .collect::<Result<_, _>>()?,
        allowed: fs_policy
            .allowed_paths
            .iter()
            .map(resolve)
            .collect::<Result<_, _>>()?,
    })
}

fn authorize_one_path_prepared(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
    patterns: &ResolvedFsPatterns,
    path: &str,
) -> Result<(), PolicyViolation> {
    let effective = match crate::pathutil::normalize_fs_argument(path) {
        Ok(normalized) => normalized,
        Err(e) => {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!("path '{path}' could not be normalized: {e}"),
            });
        }
    };
    let resolved =
        crate::pathutil::resolve_for_authorization(&effective).map_err(|e| PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!("path '{path}' could not be resolved: {e}"),
        })?;

    let matches_pattern = |pattern: &str| crate::pathutil::path_matches_lexical(&resolved, pattern);

    for denied in &patterns.denied {
        if matches_pattern(denied) {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!(
                    "path '{path}' (resolved '{resolved}') denied by tool fs sub-policy"
                ),
            });
        }
    }
    if fs_policy.allow_specified || !fs_policy.allowed_paths.is_empty() {
        let mut allowed = false;
        for pattern in &patterns.allowed {
            if matches_pattern(pattern) {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!(
                    "path '{path}' (resolved '{resolved}') not in tool fs allowed paths"
                ),
            });
        }
    }
    Ok(())
}

/// Test-only convenience — the sole caller is a unix-only symlink
/// regression test.
#[cfg(all(test, unix))]
pub(super) fn authorize_one_path(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
    path: &str,
) -> Result<(), PolicyViolation> {
    let patterns = resolve_fs_patterns(tool, fs_policy)?;
    authorize_one_path_prepared(tool, fs_policy, &patterns, path)
}

/// Normalize a path string by resolving `.` and `..` segments.
#[cfg(test)]
pub(super) fn normalize_path(path: &str) -> String {
    crate::pathutil::lexical_normalize_str(path)
}

/// Check if a file path matches a policy path pattern.
#[cfg(test)]
pub(super) fn path_matches(path: &str, pattern: &str) -> bool {
    crate::pathutil::path_matches(path, pattern)
}

/// Check if a hostname matches a policy host pattern — delegates to the
/// shared name-layer matcher in `policy::host` so the Auditor's RPC
/// argument checks and the DNS gate's query-name evaluation decide the
/// same way for the same spelling.
pub(super) fn host_matches(host: &str, pattern: &str) -> bool {
    crate::policy::host::host_matches(host, pattern)
}
