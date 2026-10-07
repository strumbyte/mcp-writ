use kdl::KdlDocument;

use super::unique_child;
use crate::error::PolicyError;
use crate::policy::{
    FsPolicy, FsToolPolicy, NetworkPolicy, OutboundPolicy, SyscallPolicy, ToolNetworkPolicy,
    ToolSyscallPolicy,
};

/// `process deny-all=#true` means no exec grant. `#false` or `allow` grants exec.
pub(crate) fn parse_process_exec_allowed(node: &kdl::KdlNode) -> Result<bool, PolicyError> {
    let deny_all_prop = node.get("deny-all");
    let mut allow_child = false;
    let mut deny_all_child = None;
    if let Some(children) = node.children() {
        allow_child = children.get("allow").is_some();
        deny_all_child = unique_child(children, "deny-all", "'process'")?;
    }
    if deny_all_prop.is_some() && (allow_child || deny_all_child.is_some()) {
        return Err(PolicyError::KdlParse(
            "'process' cannot combine a 'deny-all' property with 'allow' or 'deny-all' child nodes"
                .into(),
        ));
    }
    if allow_child && deny_all_child.is_some() {
        return Err(PolicyError::KdlParse(
            "'process' cannot combine 'allow' and 'deny-all' child nodes".into(),
        ));
    }
    if let Some(val) = deny_all_prop {
        let deny_all = val
            .as_bool()
            .ok_or_else(|| PolicyError::KdlParse("'process.deny-all' must be a boolean".into()))?;
        return Ok(!deny_all);
    }
    if allow_child {
        return Ok(true);
    }
    if let Some(deny_all_node) = deny_all_child {
        let deny_all = deny_all_node
            .get(0)
            .and_then(|v| v.as_bool())
            .ok_or_else(|| PolicyError::KdlParse("'process.deny-all' must be a boolean".into()))?;
        return Ok(!deny_all);
    }
    Ok(false)
}

/// Parse filesystem allow/deny nodes into FsPolicy (for defaults).
pub(crate) fn parse_fs_allows(doc: &KdlDocument) -> Result<FsPolicy, PolicyError> {
    let mut read_only = Vec::new();
    let mut read_write = Vec::new();
    let mut denied_paths = Vec::new();
    let mut secret_overlay = true;
    let mut secret_overlay_seen = false;

    for node in doc.nodes() {
        let name = node.name().to_string();
        match name.as_str() {
            "secret-overlay" => {
                if secret_overlay_seen {
                    return Err(PolicyError::KdlParse(
                        "duplicate 'secret-overlay' in filesystem".into(),
                    ));
                }
                let val = node.get(0).ok_or_else(|| {
                    PolicyError::KdlParse("'secret-overlay' must be a boolean (e.g. #true)".into())
                })?;
                secret_overlay = val.as_bool().ok_or_else(|| {
                    PolicyError::KdlParse("'secret-overlay' must be a boolean (e.g. #true)".into())
                })?;
                secret_overlay_seen = true;
            }
            "allow" => {
                let entry0 = node.get(0).ok_or_else(|| {
                    PolicyError::KdlParse(
                        "missing path argument on 'allow' node in filesystem".into(),
                    )
                })?;
                let path = entry0.as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "path argument on 'allow' node in filesystem must be a string, got {:?}",
                        entry0
                    ))
                })?;
                if node.entries().iter().filter(|e| e.name().is_none()).count() > 1 {
                    return Err(PolicyError::KdlParse(
                        "unexpected extra arguments on 'allow' node in filesystem".into(),
                    ));
                }
                for entry in node.entries() {
                    if let Some(prop_name) = entry.name()
                        && prop_name.value() != "mode"
                    {
                        return Err(PolicyError::KdlParse(format!(
                            "unknown property '{}' on 'allow' node in filesystem",
                            prop_name.value()
                        )));
                    }
                }
                let mode = if let Some(m_val) = node.get("mode") {
                    let m_str = m_val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(
                            "'mode' property on 'allow' node in filesystem must be a string".into(),
                        )
                    })?;
                    match m_str {
                        "read" | "write" => m_str,
                        _ => {
                            return Err(PolicyError::KdlParse(format!(
                                "invalid mode '{m_str}' on 'allow' node in filesystem; must be 'read' or 'write'"
                            )));
                        }
                    }
                } else {
                    "read"
                };

                match mode {
                    "write" => read_write.push(path.to_string()),
                    _ => read_only.push(path.to_string()),
                }
            }
            "deny" => {
                let entry0 = node.get(0).ok_or_else(|| {
                    PolicyError::KdlParse(
                        "missing path argument on 'deny' node in filesystem".into(),
                    )
                })?;
                let path = entry0.as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "path argument on 'deny' node in filesystem must be a string, got {:?}",
                        entry0
                    ))
                })?;
                if node.entries().iter().filter(|e| e.name().is_none()).count() > 1 {
                    return Err(PolicyError::KdlParse(
                        "unexpected extra arguments on 'deny' node in filesystem".into(),
                    ));
                }
                for entry in node.entries() {
                    if let Some(prop_name) = entry.name() {
                        return Err(PolicyError::KdlParse(format!(
                            "unexpected property '{}' on 'deny' node in filesystem",
                            prop_name.value()
                        )));
                    }
                }
                denied_paths.push(path.to_string());
            }
            _ => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected node '{name}' in filesystem block; expected 'allow', 'deny', or 'secret-overlay'"
                )));
            }
        }
    }

    let allow_specified = !read_only.is_empty() || !read_write.is_empty();
    Ok(FsPolicy {
        read_only,
        read_write,
        denied_paths,
        allow_specified,
        secret_overlay,
    })
}

/// Parse filesystem allow/deny nodes into FsToolPolicy (for tools).
pub(crate) fn parse_tool_fs(doc: &KdlDocument) -> Result<FsToolPolicy, PolicyError> {
    let mut allowed_paths = Vec::new();
    let mut read_only_paths = Vec::new();
    let mut read_write_paths = Vec::new();
    let mut denied_paths = Vec::new();
    let mut allow_specified = false;
    let mut require_path = None;

    for node in doc.nodes() {
        let name = node.name().to_string();
        match name.as_str() {
            "require-path" => {
                if require_path.is_some()
                    || node.entries().len() != 1
                    || node.entries()[0].name().is_some()
                    || node.children().is_some()
                {
                    return Err(PolicyError::KdlParse(
                        "require-path must appear once with exactly one boolean argument".into(),
                    ));
                }
                require_path = Some(node.get(0).and_then(|v| v.as_bool()).ok_or_else(|| {
                    PolicyError::KdlParse("require-path must be a boolean (#true or #false)".into())
                })?);
            }
            "allow" => {
                allow_specified = true;
                if node.get("none").and_then(|v| v.as_bool()) == Some(true) {
                    continue;
                }
                let entry0 = node.get(0).ok_or_else(|| {
                    PolicyError::KdlParse(
                        "missing path argument on 'allow' node in filesystem".into(),
                    )
                })?;
                let path = entry0.as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "path argument on 'allow' node in filesystem must be a string, got {:?}",
                        entry0
                    ))
                })?;
                if node.entries().iter().filter(|e| e.name().is_none()).count() > 1 {
                    return Err(PolicyError::KdlParse(
                        "unexpected extra arguments on 'allow' node in filesystem".into(),
                    ));
                }
                for entry in node.entries() {
                    if let Some(prop_name) = entry.name()
                        && prop_name.value() != "mode"
                    {
                        return Err(PolicyError::KdlParse(format!(
                            "unknown property '{}' on 'allow' node in filesystem",
                            prop_name.value()
                        )));
                    }
                }
                let mode = if let Some(m_val) = node.get("mode") {
                    let m_str = m_val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(
                            "'mode' property on 'allow' node in filesystem must be a string".into(),
                        )
                    })?;
                    match m_str {
                        "read" | "write" => m_str,
                        _ => {
                            return Err(PolicyError::KdlParse(format!(
                                "invalid mode '{m_str}' on 'allow' node in filesystem; must be 'read' or 'write'"
                            )));
                        }
                    }
                } else {
                    "read"
                };

                allowed_paths.push(path.to_string());
                if mode == "write" {
                    read_write_paths.push(path.to_string());
                } else {
                    read_only_paths.push(path.to_string());
                }
            }
            "deny" => {
                let entry0 = node.get(0).ok_or_else(|| {
                    PolicyError::KdlParse(
                        "missing path argument on 'deny' node in filesystem".into(),
                    )
                })?;
                let path = entry0.as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "path argument on 'deny' node in filesystem must be a string, got {:?}",
                        entry0
                    ))
                })?;
                if node.entries().iter().filter(|e| e.name().is_none()).count() > 1 {
                    return Err(PolicyError::KdlParse(
                        "unexpected extra arguments on 'deny' node in filesystem".into(),
                    ));
                }
                for entry in node.entries() {
                    if let Some(prop_name) = entry.name() {
                        return Err(PolicyError::KdlParse(format!(
                            "unexpected property '{}' on 'deny' node in filesystem",
                            prop_name.value()
                        )));
                    }
                }
                denied_paths.push(path.to_string());
            }
            _ => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected node '{name}' in filesystem block; expected 'allow', 'deny', or 'require-path'"
                )));
            }
        }
    }

    Ok(FsToolPolicy {
        allowed_paths,
        read_only_paths,
        read_write_paths,
        denied_paths,
        allow_specified,
        require_path,
    })
}

/// Parse tool-level syscalls sub-policy (allow/deny).
pub(crate) fn parse_tool_syscalls(doc: &KdlDocument) -> Result<ToolSyscallPolicy, PolicyError> {
    let mut allowed = Vec::new();
    let mut denied = Vec::new();

    for node in doc.nodes() {
        let name = node.name().to_string();
        let target = match name.as_str() {
            "allow" => &mut allowed,
            "deny" => &mut denied,
            _ => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected node '{name}' in syscalls block; expected 'allow' or 'deny'"
                )));
            }
        };
        for entry in node.entries() {
            if let Some(prop_name) = entry.name() {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected property '{}' on '{name}' node in syscalls",
                    prop_name.value()
                )));
            }
            let s = entry.value().as_string().ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "syscall entry in '{name}' must be a string, got {:?}",
                    entry.value()
                ))
            })?;
            target.push(s.to_string());
        }
    }

    Ok(ToolSyscallPolicy { allowed, denied })
}

/// Parse tool-level network sub-policy (allow/deny with host attribute).
pub(crate) fn parse_tool_network(doc: &KdlDocument) -> Result<ToolNetworkPolicy, PolicyError> {
    let mut allowed_hosts = Vec::new();
    let mut denied_hosts = Vec::new();
    let mut allow_specified = false;

    for node in doc.nodes() {
        let name = node.name().to_string();
        let target = match name.as_str() {
            "allow" => {
                allow_specified = true;
                if node.get("none").and_then(|v| v.as_bool()) == Some(true) {
                    continue;
                }
                &mut allowed_hosts
            }
            "deny" => &mut denied_hosts,
            _ => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected node '{name}' in network block; expected 'allow' or 'deny'"
                )));
            }
        };

        let host_val = node.get("host").ok_or_else(|| {
            PolicyError::KdlParse(format!(
                "'{name}' node in network must have a 'host' property"
            ))
        })?;
        let host = host_val.as_string().ok_or_else(|| {
            PolicyError::KdlParse(format!(
                "'host' property on '{name}' node in network must be a string, got {:?}",
                host_val
            ))
        })?;

        for entry in node.entries() {
            if let Some(prop_name) = entry.name() {
                if prop_name.value() != "host" {
                    return Err(PolicyError::KdlParse(format!(
                        "unexpected property '{}' on '{name}' node in network",
                        prop_name.value()
                    )));
                }
            } else {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected positional argument on '{name}' node in network",
                )));
            }
        }

        let normalized = crate::policy::host::normalize_policy_host(host);
        target.push(normalized);
    }

    Ok(ToolNetworkPolicy {
        allowed_hosts,
        denied_hosts,
        allow_specified,
    })
}

/// Parse syscall allow nodes into SyscallPolicy.
pub(crate) fn parse_syscall_allows(doc: &KdlDocument) -> Result<SyscallPolicy, PolicyError> {
    let mut allowed = Vec::new();

    for node in doc.nodes() {
        let name = node.name().to_string();
        if name != "allow" {
            return Err(PolicyError::KdlParse(format!(
                "unexpected node '{name}' in syscalls block; expected 'allow'"
            )));
        }
        for entry in node.entries() {
            if let Some(prop_name) = entry.name() {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected property '{}' on 'allow' node in syscalls",
                    prop_name.value()
                )));
            }
            let s = entry.value().as_string().ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "syscall entry in 'allow' must be a string, got {:?}",
                    entry.value()
                ))
            })?;
            allowed.push(s.to_string());
        }
    }

    Ok(SyscallPolicy { allowed })
}

/// Parse network allow/deny nodes into NetworkPolicy.
pub(crate) fn parse_network_rules(doc: &KdlDocument) -> Result<NetworkPolicy, PolicyError> {
    let mut allowed = Vec::new();
    let mut allowed_port_qualified = Vec::new();
    let mut denied_hosts = Vec::new();
    // Secure by default: deny all others unless explicitly opened with `allow host="*"`.
    let mut deny_all = true;
    let mut inbound = crate::policy::InboundPolicy::default();
    let mut inbound_seen = false;

    for node in doc.nodes() {
        let name = node.name().to_string();
        match name.as_str() {
            "allow" => {
                let host_val = node.get("host").ok_or_else(|| {
                    PolicyError::KdlParse(
                        "'allow' node in network must have a 'host' property".into(),
                    )
                })?;
                let host = host_val.as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "'host' property on 'allow' node in network must be a string, got {:?}",
                        host_val
                    ))
                })?;
                for entry in node.entries() {
                    if let Some(prop_name) = entry.name() {
                        if prop_name.value() != "host" {
                            return Err(PolicyError::KdlParse(format!(
                                "unexpected property '{}' on 'allow' node in network",
                                prop_name.value()
                            )));
                        }
                    } else {
                        return Err(PolicyError::KdlParse(
                            "unexpected positional argument on 'allow' node in network".into(),
                        ));
                    }
                }
                if host == "*" {
                    deny_all = false;
                } else {
                    let (normalized, port_qualified) =
                        crate::policy::host::analyze_policy_host(host);
                    // The port folds into the stored host identity; the
                    // qualifier's source spelling is recorded so a
                    // mechanism that emits real destination rules
                    // (PSEC) can refuse it rather than widen the entry
                    // to every port.
                    if port_qualified && !allowed_port_qualified.contains(&host.to_string()) {
                        allowed_port_qualified.push(host.to_string());
                    }
                    allowed.push(normalized);
                }
            }
            "deny" => {
                let host_val = node.get("host").ok_or_else(|| {
                    PolicyError::KdlParse(
                        "'deny' node in network must have a 'host' property".into(),
                    )
                })?;
                let host = host_val.as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "'host' property on 'deny' node in network must be a string, got {:?}",
                        host_val
                    ))
                })?;
                for entry in node.entries() {
                    if let Some(prop_name) = entry.name() {
                        if prop_name.value() != "host" {
                            return Err(PolicyError::KdlParse(format!(
                                "unexpected property '{}' on 'deny' node in network",
                                prop_name.value()
                            )));
                        }
                    } else {
                        return Err(PolicyError::KdlParse(
                            "unexpected positional argument on 'deny' node in network".into(),
                        ));
                    }
                }
                if host == "*" {
                    deny_all = true;
                } else {
                    denied_hosts.push(crate::policy::host::normalize_policy_host(host));
                }
            }
            "inbound" => {
                if inbound_seen {
                    return Err(PolicyError::KdlParse(
                        "duplicate 'inbound' in network".into(),
                    ));
                }
                inbound_seen = true;
                let allow = node.get("allow").and_then(|v| v.as_bool()).ok_or_else(|| {
                    PolicyError::KdlParse(
                        "'inbound' node in network must have allow=#true or allow=#false".into(),
                    )
                })?;
                inbound.allow_listen = allow;
            }
            _ => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected node '{name}' in network block; expected 'allow', 'deny', or 'inbound'"
                )));
            }
        }
    }

    Ok(NetworkPolicy {
        outbound: OutboundPolicy {
            allowed,
            allowed_port_qualified,
            denied_hosts,
            deny_all_others: deny_all,
        },
        inbound,
    })
}
