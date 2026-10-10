use std::collections::HashMap;
use std::path::{Path, PathBuf};

use kdl::KdlDocument;

use super::kdl_inherit::rematerialize_inherited_defaults;
use super::merge::PolicyLayer;
use super::{
    EnvironmentPolicy, FsPolicy, FsToolPolicy, LoggingPolicy, NetworkPolicy, Policy, SideEffect,
    SyscallPolicy, ToolNetworkPolicy, ToolSyscallPolicy, TrajectoryRule, TransportConfig,
    TransportType,
};
use crate::error::PolicyError;

mod deputy;
mod leaves;
mod mcp_rules;
mod servers;

pub(crate) use deputy::{parse_deputy_node, reject_misplaced_deputy};
pub(crate) use leaves::{
    parse_fs_allows, parse_network_rules, parse_process_exec_allowed, parse_syscall_allows,
    parse_tool_fs, parse_tool_network, parse_tool_syscalls,
};
pub(crate) use mcp_rules::parse_server_mcp_rules;
pub(crate) use servers::{parse_server_hashes, parse_servers, parse_tools_list_hashes};

/// Parse KDL content string into a Policy struct.
pub fn parse_kdl_policy(content: &str) -> Result<Policy, PolicyError> {
    let doc: KdlDocument = content
        .parse()
        .map_err(|e: kdl::KdlError| PolicyError::KdlParse(e.to_string()))?;
    let profiles = parse_profiles(&doc)?;
    parse_kdl_policy_with_profiles(content, &profiles, None)
}

/// Parse KDL content string with existing profiles and base directory.
pub fn parse_kdl_policy_with_profiles(
    content: &str,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
) -> Result<Policy, PolicyError> {
    let doc: KdlDocument = content
        .parse()
        .map_err(|e: kdl::KdlError| PolicyError::KdlParse(e.to_string()))?;

    let version = parse_version(&doc)?;
    let transport = parse_transport(&doc);
    let defaults = parse_defaults(&doc)?;
    let logging = parse_logging(&doc)?;
    let sandbox = parse_sandbox(&doc)?;
    let defaults_layer = defaults_to_layer(&defaults);
    let tools = parse_servers(&doc, &defaults_layer, profiles, base_dir, version)?;
    let mcp_rules = parse_server_mcp_rules(&doc, version, false)?;
    reject_misplaced_deputy(&doc, false)?;
    let hash_entries = parse_server_hashes(&doc)?;
    let tools_list_hashes = parse_tools_list_hashes(&doc)?;

    let confused_deputy_protection = if let Some(cdp_node) = doc.get("confused_deputy_protection") {
        if let Some(arg) = cdp_node.get(0) {
            arg.as_bool().ok_or_else(|| {
                PolicyError::KdlParse("'confused_deputy_protection' must be a boolean".into())
            })?
        } else {
            false
        }
    } else {
        false
    };

    let (trajectory, trajectory_rules) = parse_trajectory(&doc)?;

    let mut policy = Policy {
        version,
        transport,
        tools,
        fs: defaults.fs,
        syscalls: defaults.syscalls,
        network: defaults.network,
        environment: defaults.environment,
        logging,
        sandbox,
        confused_deputy_protection,
        trajectory,
        trajectory_rules,
        hash_entries,
        tools_list_hashes,
        mcp_rules,
    };
    crate::policy::apply_outbound_deny_precedence(&mut policy.network.outbound);
    rematerialize_inherited_defaults(&mut policy);
    Ok(policy)
}

/// Parsed default policies from the `defaults` node.
#[derive(Default)]
pub(crate) struct Defaults {
    pub(crate) fs: FsPolicy,
    pub(crate) syscalls: SyscallPolicy,
    pub(crate) network: NetworkPolicy,
    pub(crate) environment: EnvironmentPolicy,
}

fn parse_version(doc: &KdlDocument) -> Result<u32, PolicyError> {
    let node = doc
        .get("policy")
        .ok_or_else(|| PolicyError::KdlParse("missing 'policy' node".into()))?;

    let version_val = node.get("version").ok_or_else(|| {
        PolicyError::KdlParse("missing 'version' property on 'policy' node".into())
    })?;

    let v = version_val
        .as_integer()
        .ok_or_else(|| PolicyError::KdlParse("'version' must be an integer".into()))?;

    u32::try_from(v).map_err(|_| PolicyError::KdlParse("'version' out of range".into()))
}

fn parse_transport(doc: &KdlDocument) -> TransportConfig {
    // KDL policies default to stdio transport.
    // A `transport` node can override this.
    let Some(node) = doc.get("transport") else {
        return TransportConfig {
            type_: TransportType::Stdio,
            listen_addr: None,
        };
    };

    let type_str = node
        .get("type")
        .and_then(|v| v.as_string())
        .unwrap_or("stdio");

    let type_ = match type_str {
        "http" => TransportType::Http,
        _ => TransportType::Stdio,
    };

    let listen_addr = node
        .get("listen_addr")
        .and_then(|v| v.as_string())
        .map(String::from);

    TransportConfig { type_, listen_addr }
}

fn parse_defaults(doc: &KdlDocument) -> Result<Defaults, PolicyError> {
    let Some(node) = unique_child(doc, "defaults", "the policy document")? else {
        return Ok(Defaults::default());
    };

    let children = match node.children() {
        Some(c) => c,
        None => {
            return Ok(Defaults::default());
        }
    };

    let fs = if let Some(n) = unique_child(children, "filesystem", "'defaults'")? {
        if let Some(c) = n.children() {
            parse_fs_allows(c)?
        } else {
            FsPolicy::default()
        }
    } else {
        FsPolicy::default()
    };

    let syscalls = if let Some(n) = unique_child(children, "syscalls", "'defaults'")? {
        if let Some(c) = n.children() {
            parse_syscall_allows(c)?
        } else {
            SyscallPolicy::default()
        }
    } else {
        SyscallPolicy::default()
    };

    let network = if let Some(n) = unique_child(children, "network", "'defaults'")? {
        if let Some(c) = n.children() {
            parse_network_rules(c)?
        } else {
            NetworkPolicy::default()
        }
    } else {
        NetworkPolicy::default()
    };

    let environment = if let Some(n) = unique_child(children, "environment", "'defaults'")? {
        EnvironmentPolicy {
            restrict: true,
            allowed: parse_environment_node(n)?,
            declared: true,
        }
    } else {
        EnvironmentPolicy::default()
    };

    Ok(Defaults {
        fs,
        syscalls,
        network,
        environment,
    })
}

/// `KdlDocument::get` returns the first of several same-named children
/// and silently drops the rest — for nodes that must be unique, reject
/// the extras instead of selecting one.
pub(crate) fn unique_child<'a>(
    children: &'a KdlDocument,
    name: &str,
    context: &str,
) -> Result<Option<&'a kdl::KdlNode>, PolicyError> {
    let mut matches = children.nodes().iter().filter(|n| n.name().value() == name);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(PolicyError::KdlParse(format!(
            "duplicate '{name}' in {context}"
        )));
    }
    Ok(first)
}

/// Parse a `defaults { environment { allow "NAME" ... } }` node.
///
/// Returns the positional `allow` arguments. Only `allow` child nodes are
/// permitted; the `environment` node itself must carry no arguments or
/// properties. Node presence alone enables restriction, so an empty
/// `environment {}` yields an empty list.
pub(crate) fn parse_environment_node(node: &kdl::KdlNode) -> Result<Vec<String>, PolicyError> {
    if !node.entries().is_empty() {
        return Err(PolicyError::KdlParse(
            "'environment' node takes no arguments or properties; use 'allow \"NAME\"' children"
                .into(),
        ));
    }
    let mut allowed = Vec::new();
    let Some(children) = node.children() else {
        return Ok(allowed);
    };
    for child in children.nodes() {
        if child.name().to_string() != "allow" {
            return Err(PolicyError::KdlParse(format!(
                "unexpected node '{}' in environment block; only 'allow' is supported",
                child.name()
            )));
        }
        if child.children().is_some() {
            return Err(PolicyError::KdlParse(
                "'allow' node in environment takes no children".into(),
            ));
        }
        for entry in child.entries() {
            if let Some(prop) = entry.name() {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected property '{}' on 'allow' node in environment",
                    prop.value()
                )));
            }
            let name = entry.value().as_string().ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "environment variable name in 'allow' must be a string, got {:?}",
                    entry.value()
                ))
            })?;
            allowed.push(name.to_string());
        }
    }
    Ok(allowed)
}

pub(crate) fn validate_logging_level(level: &str) -> Result<(), PolicyError> {
    match level {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(PolicyError::KdlParse(format!(
            "invalid logging level '{level}'; must be one of: trace, debug, info, warn, error"
        ))),
    }
}

fn parse_logging(doc: &KdlDocument) -> Result<LoggingPolicy, PolicyError> {
    let Some(node) = doc.get("logging") else {
        return Ok(LoggingPolicy::default());
    };
    let mut logging = LoggingPolicy::default();
    if let Some(val) = node.get("level") {
        let level = val
            .as_string()
            .ok_or_else(|| PolicyError::KdlParse("'logging.level' must be a string".into()))?;
        validate_logging_level(level)?;
        logging.level = level.to_string();
    }
    logging.fail_closed = parse_logging_fail_closed(node)?;
    Ok(logging)
}

pub(crate) fn parse_logging_fail_closed(node: &kdl::KdlNode) -> Result<bool, PolicyError> {
    if let Some(val) = node.get("fail_closed") {
        return val.as_bool().ok_or_else(|| {
            PolicyError::KdlParse("'logging.fail_closed' must be a boolean".into())
        });
    }
    Ok(true)
}

fn parse_sandbox(doc: &KdlDocument) -> Result<crate::policy::SandboxPolicy, PolicyError> {
    let mut policy = crate::policy::SandboxPolicy::default();
    if let Some(node) = doc.get("sandbox")
        && let Some(val) = node.get("allow_degraded")
    {
        policy.allow_degraded = val.as_bool().ok_or_else(|| {
            PolicyError::KdlParse("'sandbox.allow_degraded' must be a boolean".into())
        })?;
    }
    Ok(policy)
}

/// Parse the opt-in `trajectory` flag and ordered `after` children.
///
/// Omitted node → disabled (current behavior). Properties are name-keyed;
/// child node order is preserved. Unknown children or values fail closed.
pub(crate) fn parse_trajectory(
    doc: &KdlDocument,
) -> Result<(bool, Vec<TrajectoryRule>), PolicyError> {
    let Some(node) = doc.get("trajectory") else {
        return Ok((false, Vec::new()));
    };

    let enabled = if let Some(arg) = node.get(0) {
        arg.as_bool()
            .ok_or_else(|| PolicyError::KdlParse("'trajectory' must be a boolean".into()))?
    } else {
        false
    };

    let mut rules = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            let name = child.name().to_string();
            if name != "after" {
                return Err(PolicyError::KdlParse(format!(
                    "unknown trajectory child '{name}', expected 'after'"
                )));
            }
            let after_raw = child
                .get("side_effect")
                .ok_or_else(|| {
                    PolicyError::KdlParse("'after' requires a side_effect property".into())
                })?
                .as_string()
                .ok_or_else(|| {
                    PolicyError::KdlParse("'after.side_effect' must be a string".into())
                })?;
            let deny_raw = child
                .get("deny-next")
                .ok_or_else(|| {
                    PolicyError::KdlParse("'after' requires a deny-next property".into())
                })?
                .as_string()
                .ok_or_else(|| {
                    PolicyError::KdlParse("'after.deny-next' must be a string".into())
                })?;
            let after_side_effect = SideEffect::parse(after_raw).map_err(PolicyError::KdlParse)?;
            let deny_next = SideEffect::parse(deny_raw)
                .map_err(|e| PolicyError::KdlParse(e.replace("side_effect", "deny-next")))?;
            rules.push(TrajectoryRule {
                after_side_effect,
                deny_next,
            });
        }
    }

    Ok((enabled, rules))
}

pub(crate) fn defaults_to_layer(defaults: &Defaults) -> PolicyLayer {
    let mut allowed_paths = Vec::new();
    let mut read_only_paths = Vec::new();
    let mut read_write_paths = Vec::new();

    for path in &defaults.fs.read_only {
        read_only_paths.push(path.clone());
        allowed_paths.push(path.clone());
    }
    for path in &defaults.fs.read_write {
        read_write_paths.push(path.clone());
        allowed_paths.push(path.clone());
    }

    let allow_specified = !allowed_paths.is_empty();
    let fs = if !allowed_paths.is_empty() || !defaults.fs.denied_paths.is_empty() {
        Some(FsToolPolicy {
            allowed_paths,
            read_only_paths,
            read_write_paths,
            denied_paths: defaults.fs.denied_paths.clone(),
            allow_specified,
            require_path: None,
        })
    } else {
        None
    };

    let syscalls = if !defaults.syscalls.allowed.is_empty() {
        Some(ToolSyscallPolicy {
            allowed: defaults.syscalls.allowed.clone(),
            denied: Vec::new(),
        })
    } else {
        None
    };

    let allowed_hosts: Vec<String> = defaults
        .network
        .outbound
        .allowed
        .iter()
        .map(|h| crate::policy::host::normalize_policy_host(h))
        .collect();
    let denied_hosts: Vec<String> = defaults
        .network
        .outbound
        .denied_hosts
        .iter()
        .map(|h| crate::policy::host::normalize_policy_host(h))
        .collect();

    // `cidr` rules are already canonical `addr/prefix` strings.
    let allowed_cidrs = defaults.network.outbound.allowed_cidrs.clone();
    let denied_cidrs = defaults.network.outbound.denied_cidrs.clone();

    let net_allow_specified = !allowed_hosts.is_empty() || !allowed_cidrs.is_empty();
    let network = if !allowed_hosts.is_empty()
        || !denied_hosts.is_empty()
        || !allowed_cidrs.is_empty()
        || !denied_cidrs.is_empty()
        || !defaults.network.outbound.egress_rules.is_empty()
    {
        Some(ToolNetworkPolicy {
            allowed_hosts,
            allowed_cidrs,
            denied_hosts,
            denied_cidrs,
            // Qualified rules inherit wholesale — proto/port travel with
            // the destination rules they qualify.
            egress_rules: defaults.network.outbound.egress_rules(),
            allow_specified: net_allow_specified,
        })
    } else {
        None
    };

    PolicyLayer {
        allowed: Some(true),
        fs,
        syscalls,
        network,
        environment_explicit: false,
    }
}

fn parse_layer_children(children: &KdlDocument, context: &str) -> Result<PolicyLayer, PolicyError> {
    // `environment` is a launch-level contract (`defaults.environment`) —
    // inside a profile or server-defaults layer it has no effect, so it is
    // rejected here instead of drifting to a tool-level check later.
    if children.get("environment").is_some() {
        return Err(PolicyError::KdlParse(
            "'environment' is only allowed under 'defaults' — it cannot appear in a profile or server-defaults block".into(),
        ));
    }

    let fs = if let Some(n) = unique_child(children, "filesystem", context)? {
        if let Some(c) = n.children() {
            Some(parse_tool_fs(c)?)
        } else {
            None
        }
    } else {
        None
    };

    let syscalls = if let Some(n) = unique_child(children, "syscalls", context)? {
        if let Some(c) = n.children() {
            Some(parse_tool_syscalls(c)?)
        } else {
            None
        }
    } else {
        None
    };

    let network = if let Some(n) = unique_child(children, "network", context)? {
        if let Some(c) = n.children() {
            Some(parse_tool_network(c)?)
        } else {
            None
        }
    } else {
        None
    };

    Ok(PolicyLayer {
        allowed: None,
        fs,
        syscalls,
        network,
        // Rejected above — `environment` cannot appear in a layer block.
        environment_explicit: false,
    })
}

pub(crate) fn parse_profiles(
    doc: &KdlDocument,
) -> Result<HashMap<String, PolicyLayer>, PolicyError> {
    let mut profiles = HashMap::new();

    for node in doc.nodes() {
        if node.name().to_string() != "profile" {
            continue;
        }

        let name = node
            .get(0)
            .and_then(|v| v.as_string())
            .ok_or_else(|| {
                PolicyError::KdlParse("profile node must have a name as first argument".into())
            })?
            .to_string();

        let layer = if let Some(children) = node.children() {
            parse_layer_children(children, &format!("profile '{name}'"))?
        } else {
            PolicyLayer::default()
        };

        profiles.insert(name, layer);
    }

    Ok(profiles)
}

pub(crate) fn resolve_tool_args_schema(
    schema_ref: &str,
    base_dir: Option<&Path>,
) -> Result<String, PolicyError> {
    if let Some(file_path) = schema_ref.strip_prefix('@') {
        let file_path = file_path.trim();
        if let Some(base) = base_dir {
            let resolved = if Path::new(file_path).is_absolute() {
                PathBuf::from(file_path)
            } else {
                base.join(file_path)
            };
            let content = std::fs::read_to_string(&resolved).map_err(|e| {
                PolicyError::FileRead(std::io::Error::new(
                    e.kind(),
                    format!("failed to read schema file '{}': {e}", resolved.display()),
                ))
            })?;
            // Validate JSON syntax (or boolean as per JSON schema 2020-12)
            if let Err(e) = nojson::RawJson::parse(&content) {
                return Err(PolicyError::KdlParse(format!(
                    "schema file '{}' contains invalid JSON: {e}",
                    resolved.display()
                )));
            }
            Ok(content)
        } else {
            Ok(schema_ref.to_string())
        }
    } else {
        Ok(schema_ref.to_string())
    }
}

/// Strict `tool` node shape required by `policy version=2` (KDL schema v2).
///
/// v2 is a closed schema: a `tool` entry accepts exactly one positional
/// name argument, only the documented properties, and only the documented
/// child nodes. Unknown members are load errors — unknown methods
/// (`mcp`), unknown fields, and malformed shapes never pass silently.
/// `environment` stays accepted here so `environment_explicit` can flag
/// it and the validator reject it like an inline v1 declaration.
pub(crate) fn validate_tool_shape_v2(
    node: &kdl::KdlNode,
    tool_name: &str,
) -> Result<(), PolicyError> {
    if node.entries().iter().filter(|e| e.name().is_none()).count() > 1 {
        return Err(PolicyError::KdlParse(format!(
            "tool '{tool_name}' takes exactly one name argument in policy version 2"
        )));
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name() {
            match prop.value() {
                "deny" | "args_schema" | "side_effect" | "input_responses" | "profile" => {}
                other => {
                    return Err(PolicyError::KdlParse(format!(
                        "unknown property '{other}' on tool '{tool_name}'; version 2 tool entries \
                         accept only deny, args_schema, side_effect, input_responses, profile"
                    )));
                }
            }
        }
    }
    if let Some(children) = node.children() {
        let mut deputy_seen = false;
        for child in children.nodes() {
            match child.name().value() {
                "deputy" => {
                    if std::mem::replace(&mut deputy_seen, true) {
                        return Err(PolicyError::KdlParse(format!(
                            "duplicate 'deputy' in tool '{tool_name}'"
                        )));
                    }
                }
                "filesystem" | "syscalls" | "network" | "process" | "environment" | "profile"
                | "profiles" => {}
                other => {
                    return Err(PolicyError::KdlParse(format!(
                        "unexpected node '{other}' in tool '{tool_name}'; version 2 tool entries \
                         accept only filesystem, syscalls, network, process, environment, \
                         profile, profiles, deputy"
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
