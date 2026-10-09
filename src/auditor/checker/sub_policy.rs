//! Per-tool sub-policy enforcement: fs path and network host allow/deny
//! lists, the `read_only` side-effect guard, and the secret-path overlay
//! applied to extracted argument targets.

use crate::policy::host::extract_host_from_url;
use crate::policy::{Policy, ToolPolicy};

use super::PolicyViolation;
use super::targets::{ExtractedTargets, collect_argument_targets};

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

    if crate::policy::SideEffect::parse(tool.side_effect.as_deref().unwrap_or("")).ok()
        == Some(crate::policy::SideEffect::ReadOnly)
        && (!extracted.hosts.is_empty() || !extracted.urls.is_empty())
    {
        return Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason: "side_effect=\"read_only\" forbids host/URL arguments".to_string(),
        });
    }

    if let Some(ref fs_policy) = tool.fs {
        has_sub = true;
        let fs_restricted = fs_policy.allow_specified
            || fs_policy.require_path.is_some()
            || !fs_policy.allowed_paths.is_empty()
            || !fs_policy.denied_paths.is_empty();
        if fs_restricted {
            if extracted.paths.is_empty() && !fs_policy.allows_pathless_call() {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: "filesystem-restricted tool is missing a path target \
                             (checked path/file/uri and nested string fields)"
                        .to_string(),
                });
            }
            for path in &extracted.paths {
                authorize_one_path(tool, fs_policy, path)?;
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

    let mut hosts: Vec<String> = extracted.hosts.clone();
    for url in &extracted.urls {
        match extract_host_from_url(url) {
            Some(h) => hosts.push(h),
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

    for host in &hosts {
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
        if policy.network.outbound.deny_all_others
            && !(policy.network.outbound.allowed.is_empty()
                && policy.network.outbound.allowed_cidrs.is_empty())
        {
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
        // reject hosts that appear, but must not demand a host on FS-only calls.
        let requires_host_target = !net_policy.allowed_hosts.is_empty()
            || !net_policy.denied_hosts.is_empty()
            || !net_policy.allowed_cidrs.is_empty()
            || !net_policy.denied_cidrs.is_empty();
        if requires_host_target && hosts.is_empty() {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: "network-restricted tool is missing a url/host target \
                         (checked url/host/uri and nested string fields)"
                    .to_string(),
            });
        }
        for host in &hosts {
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
            if net_policy.allow_specified
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

pub(super) fn authorize_one_path(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
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

    let matches_pattern = |pattern: &str| -> Result<bool, PolicyViolation> {
        let pattern =
            crate::pathutil::resolve_policy_pattern(pattern).map_err(|e| PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!("policy path '{pattern}' could not be resolved: {e}"),
            })?;
        Ok(crate::pathutil::path_matches_lexical(&resolved, &pattern))
    };

    for denied in &fs_policy.denied_paths {
        if matches_pattern(denied)? {
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
        for pattern in &fs_policy.allowed_paths {
            if matches_pattern(pattern)? {
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
