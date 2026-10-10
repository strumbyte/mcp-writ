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
                    // `none` is the whole declaration — a path, a
                    // `mode`, or a children block beside it would be
                    // silently dropped, so refuse anything but the
                    // marker itself.
                    if node.children().is_some() {
                        return Err(PolicyError::KdlParse(
                            "'allow none=#true' node in filesystem takes no children".into(),
                        ));
                    }
                    for entry in node.entries() {
                        match entry.name() {
                            Some(prop) if prop.value() == "none" => {}
                            Some(prop) => {
                                return Err(PolicyError::KdlParse(format!(
                                    "unexpected property '{}' on 'allow none=#true' node in filesystem",
                                    prop.value()
                                )));
                            }
                            None => {
                                return Err(PolicyError::KdlParse(
                                    "unexpected positional argument on 'allow none=#true' node in filesystem"
                                        .into(),
                                ));
                            }
                        }
                    }
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

/// One `allow`/`deny` network node after parsing — the flat-list
/// projections every existing consumer reads plus the structured rule
/// carrying `proto=`/`port=` qualifiers.
struct NetNodeParse {
    /// `Some(deny)` — a bare `host="*"` posture node. Only produced when
    /// the caller's level has postures (defaults); the tool level treats
    /// `host="*"` as an ordinary wildcard rule.
    posture: Option<bool>,
    /// Normalized host for the flat allow/deny list — `None` for
    /// bare-port rules and `*`-with-qualifiers rules (they carry no
    /// name-layer identity; the rule-aware evaluation still sees them).
    host: Option<String>,
    /// Canonical cidr for the flat allow/deny list.
    cidr: Option<String>,
    /// Source spelling for `*_port_qualified` provenance (allow side).
    port_qualified_spelling: Option<String>,
    /// The structured rule — `None` for posture nodes.
    rule: Option<crate::policy::EgressRule>,
}

/// Parse one `allow`/`deny` network node shared by the defaults-level
/// and tool-level parsers. `posture_aware` is `true` only at defaults
/// level, where a bare `host="*"` node flips the default action instead
/// of declaring a rule.
fn parse_network_rule_node(
    node: &kdl::KdlNode,
    is_allow: bool,
    posture_aware: bool,
) -> Result<NetNodeParse, PolicyError> {
    let name = node.name().to_string();
    let host_prop = node.get("host");
    let cidr_prop = node.get("cidr");
    if host_prop.is_some() == cidr_prop.is_some() {
        return Err(PolicyError::KdlParse(format!(
            "'{name}' node in network requires exactly one of 'host' or 'cidr'"
        )));
    }
    for entry in node.entries() {
        if let Some(prop_name) = entry.name() {
            if !matches!(prop_name.value(), "host" | "cidr" | "proto" | "port") {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected property '{}' on '{name}' node in network",
                    prop_name.value()
                )));
            }
        } else {
            return Err(PolicyError::KdlParse(format!(
                "unexpected positional argument on '{name}' node in network"
            )));
        }
    }
    // `deny` takes no qualifiers — checked before any posture handling
    // so `deny host="*" proto=…` is a load error rather than a scoped
    // wildcard denial.
    let props_were_present = node.get("proto").is_some() || node.get("port").is_some();

    if let Some(host_val) = host_prop {
        let host = host_val.as_string().ok_or_else(|| {
            PolicyError::KdlParse(format!(
                "'host' property on '{name}' node in network must be a string, got {:?}",
                host_val
            ))
        })?;
        if host == "*" && posture_aware && !props_were_present {
            // Bare `allow host="*"` / `deny host="*"` are postures, not
            // rules — they set the default action. A `*` carrying
            // `proto=`/`port=` is a scoped rule instead
            // (`allow host="*" proto="udp"` opens UDP without lifting
            // the deny-all posture on TCP).
            return Ok(NetNodeParse {
                posture: Some(!is_allow),
                host: None,
                cidr: None,
                port_qualified_spelling: None,
                rule: None,
            });
        }
        if host == "*" && posture_aware {
            // A scoped wildcard rule — it enters `egress_rules` only:
            // the name layer reads it through the rule-aware evaluation
            // (resolving names for a proto/port-scoped grant), never
            // through the flat `allowed` list the auditor reads.
            let (proto, port) = parse_rule_quals(node, &name, is_allow, None)?;
            return Ok(NetNodeParse {
                posture: None,
                host: None,
                cidr: None,
                port_qualified_spelling: None,
                rule: Some(crate::policy::EgressRule {
                    allow: is_allow,
                    dest: crate::policy::EgressDest::Host("*".to_string()),
                    proto,
                    port,
                }),
            });
        }
        if let Some(port) = crate::policy::host::bare_port_spelling(host) {
            if !is_allow {
                return Err(PolicyError::KdlParse(
                    "a 'deny' node does not take a bare-port 'host' — deny rules are \
                     protocol/port-blind"
                        .into(),
                ));
            }
            let (proto, port_prop) = parse_rule_quals(node, &name, true, None)?;
            if port_prop.is_some() {
                return Err(PolicyError::KdlParse(format!(
                    "'{name}' node is already a bare-port rule ('{host}') — drop the \
                     'port' property"
                )));
            }
            return Ok(NetNodeParse {
                posture: None,
                host: None,
                cidr: None,
                port_qualified_spelling: None,
                rule: Some(crate::policy::EgressRule {
                    allow: true,
                    dest: crate::policy::EgressDest::Host("*".to_string()),
                    proto,
                    port: Some(port),
                }),
            });
        }
        if crate::policy::host::all_digits_host(host) {
            return Err(PolicyError::KdlParse(format!(
                "numeric 'host' value '{host}' on '{name}' is not a valid bare-port \
                 rule (1-65535, no leading zeros) — write an IP literal like \
                 '192.0.2.1' or a valid port"
            )));
        }
        let (normalized, spelled_port, port_qualified) =
            crate::policy::host::analyze_policy_host(host);
        if !is_allow && port_qualified {
            return Err(PolicyError::KdlParse(
                "a 'deny' 'host' rule does not take a port qualifier — it would \
                 silently widen to every port"
                    .into(),
            ));
        }
        if port_qualified && spelled_port.is_none() {
            return Err(PolicyError::KdlParse(format!(
                "the port qualifier in 'host' value '{host}' on '{name}' is empty \
                 or out of range (1-65535) — it cannot be widened to every port"
            )));
        }
        let (proto, port) = parse_rule_quals(node, &name, is_allow, spelled_port)?;
        return Ok(NetNodeParse {
            posture: None,
            host: Some(normalized.clone()),
            cidr: None,
            port_qualified_spelling: (is_allow && port_qualified).then(|| host.to_string()),
            rule: Some(crate::policy::EgressRule {
                allow: is_allow,
                dest: crate::policy::EgressDest::Host(normalized),
                proto: if is_allow {
                    proto
                } else {
                    crate::policy::EgressProto::Any
                },
                port: if is_allow { port } else { None },
            }),
        });
    }

    let cidr_val = cidr_prop.unwrap();
    let cidr_str = cidr_val.as_string().ok_or_else(|| {
        PolicyError::KdlParse(format!(
            "'cidr' property on '{name}' node in network must be a string, got {:?}",
            cidr_val
        ))
    })?;
    let (normalized, spelled_port, port_qualified) =
        crate::policy::host::analyze_policy_cidr(cidr_str).map_err(|e| {
            PolicyError::KdlParse(format!("invalid 'cidr' on '{name}' node in network: {e}"))
        })?;
    if !is_allow && port_qualified {
        return Err(PolicyError::KdlParse(
            "a 'deny' 'cidr' rule does not take a port qualifier — it would \
             silently widen to every port"
                .into(),
        ));
    }
    if port_qualified && spelled_port.is_none() {
        return Err(PolicyError::KdlParse(format!(
            "the port qualifier in 'cidr' value '{cidr_str}' on '{name}' is empty \
             or out of range (1-65535) — it cannot be widened to every port"
        )));
    }
    let (proto, port) = parse_rule_quals(node, &name, is_allow, spelled_port)?;
    Ok(NetNodeParse {
        posture: None,
        host: None,
        cidr: Some(normalized.clone()),
        port_qualified_spelling: (is_allow && port_qualified).then(|| cidr_str.to_string()),
        rule: Some(crate::policy::EgressRule {
            allow: is_allow,
            dest: crate::policy::EgressDest::Cidr(normalized),
            proto: if is_allow {
                proto
            } else {
                crate::policy::EgressProto::Any
            },
            port: if is_allow { port } else { None },
        }),
    })
}

/// Parse tool-level network sub-policy (allow/deny with `host`/`cidr`
/// attributes). `host=` entries are name-layer rules; `cidr=` entries
/// are IP-layer rules — the two never fold into one another. The
/// `proto=`/`port=` grammar is the defaults-level one; qualifiers ride
/// in `egress_rules` so a tool block round-trips through emit intact.
pub(crate) fn parse_tool_network(doc: &KdlDocument) -> Result<ToolNetworkPolicy, PolicyError> {
    let mut allowed_hosts = Vec::new();
    let mut allowed_cidrs = Vec::new();
    let mut denied_hosts = Vec::new();
    let mut denied_cidrs = Vec::new();
    let mut egress_rules = Vec::new();
    let mut allow_specified = false;

    for node in doc.nodes() {
        let name = node.name().to_string();
        let is_allow = match name.as_str() {
            "allow" => {
                allow_specified = true;
                if node.get("none").and_then(|v| v.as_bool()) == Some(true) {
                    // `none` is the whole declaration — a `host=`/`cidr=`,
                    // an argument, or a children block beside it would be
                    // silently dropped, so refuse anything but the marker
                    // itself.
                    if node.children().is_some() {
                        return Err(PolicyError::KdlParse(
                            "'allow none=#true' node in network takes no children".into(),
                        ));
                    }
                    for entry in node.entries() {
                        match entry.name() {
                            Some(prop) if prop.value() == "none" => {}
                            Some(prop) => {
                                return Err(PolicyError::KdlParse(format!(
                                    "unexpected property '{}' on 'allow none=#true' node in network",
                                    prop.value()
                                )));
                            }
                            None => {
                                return Err(PolicyError::KdlParse(
                                    "unexpected positional argument on 'allow none=#true' node in network"
                                        .into(),
                                ));
                            }
                        }
                    }
                    continue;
                }
                true
            }
            "deny" => false,
            _ => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected node '{name}' in network block; expected 'allow' or 'deny'"
                )));
            }
        };

        let parsed = parse_network_rule_node(node, is_allow, false)?;
        // The tool level has no posture — `host="*"` is an ordinary
        // wildcard rule here (`parse_network_rule_node` with
        // `posture_aware=false` returns it through `host`/`rule`).
        debug_assert!(parsed.posture.is_none());
        let _ = parsed.posture;
        if let Some(h) = parsed.host {
            if is_allow {
                allowed_hosts.push(h);
            } else {
                denied_hosts.push(h);
            }
        }
        if let Some(c) = parsed.cidr {
            let target = if is_allow {
                &mut allowed_cidrs
            } else {
                &mut denied_cidrs
            };
            if !target.contains(&c) {
                target.push(c);
            }
        }
        if let Some(rule) = parsed.rule
            && !egress_rules.contains(&rule)
        {
            egress_rules.push(rule);
        }
    }

    crate::policy::sort_egress_rules(&mut egress_rules);
    Ok(ToolNetworkPolicy {
        allowed_hosts,
        allowed_cidrs,
        denied_hosts,
        denied_cidrs,
        egress_rules,
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

/// The `proto=`/`port=` qualifiers on an `allow`/`deny` network node.
/// `deny` takes neither — deny rules are protocol/port-blind at every
/// layer (a `deny host=` is also a name-layer deny, where ports do not
/// exist), so an attribute would silently mis-scope the denial.
///
/// The port may come from the destination spelling (`host:443`,
/// `cidr:53`) or the `port=` property — never both differently.
fn parse_rule_quals(
    node: &kdl::KdlNode,
    node_name: &str,
    is_allow: bool,
    spelled_port: Option<u16>,
) -> Result<(crate::policy::EgressProto, Option<u16>), PolicyError> {
    let proto_prop = node.get("proto");
    let port_prop = node.get("port");
    if !is_allow && (proto_prop.is_some() || port_prop.is_some()) {
        return Err(PolicyError::KdlParse(format!(
            "a '{node_name}' node does not take 'proto' or 'port' — deny \
             rules are protocol/port-blind at every layer"
        )));
    }
    let proto = match proto_prop {
        Some(v) => {
            let s = v.as_string().ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "'proto' on '{node_name}' must be a string (tcp|udp|any), got {v:?}"
                ))
            })?;
            crate::policy::EgressProto::parse(s)
                .map_err(|e| PolicyError::KdlParse(format!("'proto' on '{node_name}': {e}")))?
        }
        None => crate::policy::EgressProto::Tcp,
    };
    let prop_port = match port_prop {
        Some(v) => {
            let n = v.as_integer().ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "'port' on '{node_name}' must be an integer (1-65535), got {v:?}"
                ))
            })?;
            Some(u16::try_from(n).ok().filter(|p| *p > 0).ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "'port' on '{node_name}' must be in 1-65535, got {n}"
                ))
            })?)
        }
        None => None,
    };
    let port = match (spelled_port, prop_port) {
        (Some(a), Some(b)) if a != b => {
            return Err(PolicyError::KdlParse(format!(
                "'{node_name}' spells port {a} in the destination but port={b} — \
                 write the port once"
            )));
        }
        (Some(a), _) => Some(a),
        (None, b) => b,
    };
    Ok((proto, port))
}

/// Parse network allow/deny nodes into NetworkPolicy.
///
/// `host=` entries are name-layer rules (evaluated on names — Auditor
/// argument checks, and a DNS-gate name policy where the execution
/// path provides one); `cidr=` entries are IP-layer rules (static
/// `addr/prefix` evaluated on connection destinations). The two are
/// stored in separate fields and never fold into one another. Every
/// declared rule also lands in `egress_rules` with its `proto=`/`port=`
/// qualifiers preserved for mechanisms that can express them.
pub(crate) fn parse_network_rules(doc: &KdlDocument) -> Result<NetworkPolicy, PolicyError> {
    let mut allowed = Vec::new();
    let mut allowed_port_qualified = Vec::new();
    let mut allowed_cidrs = Vec::new();
    let mut allowed_cidrs_port_qualified = Vec::new();
    let mut denied_hosts = Vec::new();
    let mut denied_cidrs = Vec::new();
    let mut egress_rules = Vec::new();
    // Secure by default: deny all others unless explicitly opened with `allow host="*"`.
    let mut deny_all = true;
    let mut inbound = crate::policy::InboundPolicy::default();
    let mut inbound_seen = false;

    for node in doc.nodes() {
        let name = node.name().to_string();
        match name.as_str() {
            "allow" | "deny" => {
                let is_allow = name == "allow";
                let parsed = parse_network_rule_node(node, is_allow, true)?;
                if let Some(deny) = parsed.posture {
                    deny_all = deny;
                    continue;
                }
                if let Some(spelling) = parsed.port_qualified_spelling {
                    // The port folds into the stored rule identity; the
                    // qualifier's source spelling is recorded so a
                    // mechanism that emits real destination rules
                    // (PSEC) can refuse it rather than widen the entry
                    // to every port.
                    let provenance = if parsed.cidr.is_some() {
                        &mut allowed_cidrs_port_qualified
                    } else {
                        &mut allowed_port_qualified
                    };
                    if !provenance.contains(&spelling) {
                        provenance.push(spelling);
                    }
                }
                if let Some(h) = parsed.host {
                    if is_allow {
                        allowed.push(h);
                    } else {
                        denied_hosts.push(h);
                    }
                }
                if let Some(c) = parsed.cidr {
                    let target = if is_allow {
                        &mut allowed_cidrs
                    } else {
                        &mut denied_cidrs
                    };
                    if !target.contains(&c) {
                        target.push(c);
                    }
                }
                if let Some(rule) = parsed.rule
                    && !egress_rules.contains(&rule)
                {
                    egress_rules.push(rule);
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

    crate::policy::sort_egress_rules(&mut egress_rules);
    Ok(NetworkPolicy {
        outbound: OutboundPolicy {
            allowed,
            allowed_port_qualified,
            allowed_cidrs,
            allowed_cidrs_port_qualified,
            denied_hosts,
            denied_cidrs,
            deny_all_others: deny_all,
            egress_rules,
        },
        inbound,
    })
}
