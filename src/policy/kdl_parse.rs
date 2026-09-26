use std::collections::HashMap;
use std::path::{Path, PathBuf};

use kdl::KdlDocument;

use super::kdl_inherit::rematerialize_inherited_defaults;
use super::mcp::{McpRule, RuleEffect, ServerMcpRules, method_slots};
use super::merge::{PolicyLayer, merge_policy, validate_merged};
use super::{
    EnvironmentPolicy, FsPolicy, FsToolPolicy, HashEntry, HashType, InputResponsesMode,
    LoggingPolicy, NetworkPolicy, OutboundPolicy, Policy, SideEffect, SyscallPolicy,
    ToolNetworkPolicy, ToolPolicy, ToolSyscallPolicy, ToolsListHashEntry, TrajectoryRule,
    TransportConfig, TransportType,
};
use crate::error::PolicyError;
use crate::protocol::MessageDirection;
use crate::protocol::SupportedProtocolVersion;
use crate::protocol::fields::SubscriptionFilter;

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
    let Some(node) = doc.get("defaults") else {
        return Ok(Defaults::default());
    };

    let children = match node.children() {
        Some(c) => c,
        None => {
            return Ok(Defaults::default());
        }
    };

    let fs = if let Some(n) = children.get("filesystem") {
        if let Some(c) = n.children() {
            parse_fs_allows(c)?
        } else {
            FsPolicy::default()
        }
    } else {
        FsPolicy::default()
    };

    let syscalls = if let Some(n) = children.get("syscalls") {
        if let Some(c) = n.children() {
            parse_syscall_allows(c)?
        } else {
            SyscallPolicy::default()
        }
    } else {
        SyscallPolicy::default()
    };

    let network = if let Some(n) = children.get("network") {
        if let Some(c) = n.children() {
            parse_network_rules(c)?
        } else {
            NetworkPolicy::default()
        }
    } else {
        NetworkPolicy::default()
    };

    let environment = if let Some(n) = children.get("environment") {
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

    let net_allow_specified = !allowed_hosts.is_empty();
    let network = if !allowed_hosts.is_empty() || !denied_hosts.is_empty() {
        Some(ToolNetworkPolicy {
            allowed_hosts,
            denied_hosts,
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

fn parse_layer_children(children: &KdlDocument) -> Result<PolicyLayer, PolicyError> {
    // `environment` is a launch-level contract (`defaults.environment`) —
    // inside a profile or server-defaults layer it has no effect, so it is
    // rejected here instead of drifting to a tool-level check later.
    if children.get("environment").is_some() {
        return Err(PolicyError::KdlParse(
            "'environment' is only allowed under 'defaults' — it cannot appear in a profile or server-defaults block".into(),
        ));
    }

    let fs = if let Some(n) = children.get("filesystem") {
        if let Some(c) = n.children() {
            Some(parse_tool_fs(c)?)
        } else {
            None
        }
    } else {
        None
    };

    let syscalls = if let Some(n) = children.get("syscalls") {
        if let Some(c) = n.children() {
            Some(parse_tool_syscalls(c)?)
        } else {
            None
        }
    } else {
        None
    };

    let network = if let Some(n) = children.get("network") {
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
            parse_layer_children(children)?
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
fn validate_tool_shape_v2(node: &kdl::KdlNode, tool_name: &str) -> Result<(), PolicyError> {
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
        for child in children.nodes() {
            match child.name().value() {
                "filesystem" | "syscalls" | "network" | "process" | "environment" | "profile"
                | "profiles" => {}
                other => {
                    return Err(PolicyError::KdlParse(format!(
                        "unexpected node '{other}' in tool '{tool_name}'; version 2 tool entries \
                         accept only filesystem, syscalls, network, process, environment, \
                         profile, profiles"
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Parse `mcp { allow ... / deny ... }` blocks under each `server` node.
///
/// Schema v2 only — an `mcp` child under `policy version < 2` is a load
/// error. Each rule expands over the method's own rule-key slots
/// (revision × direction × kind from the method ledger); `protocol=` and
/// `direction=` properties only restrict that expansion, never extend it.
/// Two rules covering the same atom — even with the same effect — are a
/// load error; restate them as one rule.
pub(crate) fn parse_server_mcp_rules(
    doc: &KdlDocument,
    version: u32,
    in_when_body: bool,
) -> Result<Vec<ServerMcpRules>, PolicyError> {
    reject_misplaced_mcp(doc, in_when_body)?;
    let mut out: Vec<ServerMcpRules> = Vec::new();
    for node in doc.nodes() {
        if node.name().to_string() != "server" {
            continue;
        }
        let server_name = node.get(0).and_then(|v| v.as_string()).map(String::from);
        let Some(children) = node.children() else {
            continue;
        };
        let mut rules = Vec::new();
        for child in children.nodes() {
            if child.name().to_string() != "mcp" {
                continue;
            }
            if version < 2 {
                return Err(PolicyError::KdlParse(format!(
                    "'mcp' rules in server '{}' require 'policy version=2'",
                    server_name.as_deref().unwrap_or("<unnamed>")
                )));
            }
            if !child.entries().is_empty() {
                return Err(PolicyError::KdlParse(format!(
                    "'mcp' node in server '{}' takes no arguments or properties",
                    server_name.as_deref().unwrap_or("<unnamed>")
                )));
            }
            let Some(mcp_children) = child.children() else {
                continue;
            };
            for rule_node in mcp_children.nodes() {
                rules.push(parse_mcp_rule_node(rule_node)?);
            }
        }
        if rules.is_empty() {
            continue;
        }
        if let Some(existing) = out.iter_mut().find(|s| s.server_name == server_name) {
            existing.extend_rules(rules);
        } else {
            out.push(ServerMcpRules::new(server_name, rules));
        }
    }
    for entry in &out {
        super::mcp::validate_rule_set(entry.server_name.as_deref(), entry.rules())
            .map_err(PolicyError::KdlParse)?;
    }
    Ok(out)
}

/// `mcp` blocks only take effect as direct children of a `server` node
/// this scan actually reads: a top-level `server`, or a `server`
/// directly inside a top-level `when` block (whose body merges when the
/// environment matches). An `mcp` anywhere else — document root,
/// `defaults`, `profile`, `server-defaults`, `tool`, a `when` node's own
/// children, or inside a nested `when` that is never evaluated — would
/// be silently ignored, so it is a load error instead.
fn reject_misplaced_mcp(doc: &KdlDocument, in_when_body: bool) -> Result<(), PolicyError> {
    fn misplaced() -> PolicyError {
        PolicyError::KdlParse("'mcp' is only valid as a direct child of a 'server' node".into())
    }
    /// No `mcp` anywhere in this subtree.
    fn no_mcp(node: &kdl::KdlNode) -> Result<(), PolicyError> {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                if child.name().value() == "mcp" {
                    return Err(misplaced());
                }
                no_mcp(child)?;
            }
        }
        Ok(())
    }
    /// One level of nodes that may legitimately hold `mcp` blocks.
    /// `when` children form another such level only at document root —
    /// inside a `when` body a nested `when` is never evaluated.
    fn level(doc: &KdlDocument, in_when: bool) -> Result<(), PolicyError> {
        for node in doc.nodes() {
            match node.name().value() {
                "mcp" => return Err(misplaced()),
                // `mcp` is legal directly under `server`; deeper is not.
                "server" => {
                    if let Some(children) = node.children() {
                        for child in children.nodes() {
                            if child.name().value() != "mcp" {
                                no_mcp(child)?;
                            }
                        }
                    }
                }
                "when" if !in_when => {
                    if let Some(children) = node.children() {
                        level(children, true)?;
                    }
                }
                _ => no_mcp(node)?,
            }
        }
        Ok(())
    }
    level(doc, in_when_body)
}

/// Strict `uri`/`filter` child shape: exactly one positional argument —
/// extra entries, named properties, or child blocks are load errors
/// rather than silently ignored.
fn takes_single_positional_arg(child: &kdl::KdlNode) -> bool {
    child.entries().len() == 1 && child.entries()[0].name().is_none() && child.children().is_none()
}

/// Parse one `allow "method"` / `deny "method"` node inside an `mcp` block.
fn parse_mcp_rule_node(node: &kdl::KdlNode) -> Result<McpRule, PolicyError> {
    let effect = match node.name().value() {
        "allow" => RuleEffect::Allow,
        "deny" => RuleEffect::Deny,
        other => {
            return Err(PolicyError::KdlParse(format!(
                "unexpected node '{other}' in mcp block; expected 'allow' or 'deny'"
            )));
        }
    };
    let method = node
        .get(0)
        .and_then(|v| v.as_string())
        .ok_or_else(|| {
            PolicyError::KdlParse("mcp rule requires a method string as first argument".into())
        })?
        .to_string();
    if node.entries().iter().filter(|e| e.name().is_none()).count() > 1 {
        return Err(PolicyError::KdlParse(format!(
            "mcp rule for method \"{method}\" takes exactly one method argument"
        )));
    }

    let mut versions = Vec::new();
    let mut direction = None;
    for entry in node.entries() {
        let Some(prop) = entry.name() else {
            continue;
        };
        match prop.value() {
            "protocol" => {
                let raw = entry.value().as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "'protocol' property on mcp rule for method \"{method}\" must be a string"
                    ))
                })?;
                let parsed = SupportedProtocolVersion::parse(raw).ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "unknown protocol revision '{raw}' on mcp rule for method \"{method}\"; \
                         supported: 2025-11-25, 2026-07-28"
                    ))
                })?;
                if !versions.contains(&parsed) {
                    versions.push(parsed);
                }
            }
            "direction" => {
                let raw = entry.value().as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "'direction' property on mcp rule for method \"{method}\" must be a string"
                    ))
                })?;
                direction = Some(MessageDirection::parse(raw).ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "unknown direction '{raw}' on mcp rule for method \"{method}\"; \
                         expected c2s or s2c"
                    ))
                })?);
            }
            other => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected property '{other}' on mcp rule for method \"{method}\"; \
                     expected protocol= or direction="
                )));
            }
        }
    }

    let mut uris = Vec::new();
    let mut filters = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "uri" => {
                    if !takes_single_positional_arg(child) {
                        return Err(PolicyError::KdlParse(format!(
                            "'uri' child of an mcp rule for method \"{method}\" takes exactly one argument"
                        )));
                    }
                    let uri = child.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
                        PolicyError::KdlParse(
                            "'uri' child of an mcp rule requires a string argument".into(),
                        )
                    })?;
                    if uri.trim().is_empty() {
                        return Err(PolicyError::KdlParse(
                            "'uri' child of an mcp rule must not be empty".into(),
                        ));
                    }
                    if uris.iter().any(|u: &String| u == uri) {
                        return Err(PolicyError::KdlParse(format!(
                            "duplicate uri '{uri}' in mcp rule for method \"{method}\""
                        )));
                    }
                    uris.push(uri.to_string());
                }
                "filter" => {
                    if !takes_single_positional_arg(child) {
                        return Err(PolicyError::KdlParse(format!(
                            "'filter' child of an mcp rule for method \"{method}\" takes exactly one argument"
                        )));
                    }
                    let raw = child.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
                        PolicyError::KdlParse(
                            "'filter' child of an mcp rule requires a string argument".into(),
                        )
                    })?;
                    let parsed = SubscriptionFilter::parse(raw).ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "unknown filter '{raw}' in mcp rule for method \"{method}\"; \
                             expected toolsListChanged, promptsListChanged, \
                             resourcesListChanged, or resourceSubscriptions"
                        ))
                    })?;
                    if filters.contains(&parsed) {
                        return Err(PolicyError::KdlParse(format!(
                            "duplicate filter '{raw}' in mcp rule for method \"{method}\""
                        )));
                    }
                    filters.push(parsed);
                }
                other => {
                    return Err(PolicyError::KdlParse(format!(
                        "unexpected node '{other}' in mcp rule for method \"{method}\"; \
                         expected 'uri' or 'filter'"
                    )));
                }
            }
        }
    }

    let rule = McpRule {
        effect,
        method,
        versions,
        direction,
        uris,
        filters,
    };
    validate_mcp_rule(&rule)?;
    Ok(rule)
}

/// Shape + reachability checks for one parsed `mcp` rule.
fn validate_mcp_rule(rule: &McpRule) -> Result<(), PolicyError> {
    if method_slots(&rule.method).is_empty() {
        return Err(PolicyError::KdlParse(format!(
            "unknown MCP method \"{}\" in mcp rule — the rule ledger is closed; \
             MCP extensions cannot be targeted until registered",
            rule.method
        )));
    }
    if rule.atoms().is_empty() {
        let slots: Vec<String> = method_slots(&rule.method)
            .iter()
            .map(|s| {
                format!(
                    "{}/{}/{}",
                    s.version.as_str(),
                    s.direction.as_str(),
                    s.kind.as_str()
                )
            })
            .collect();
        return Err(PolicyError::KdlParse(format!(
            "mcp rule for method \"{}\" targets no valid rule-key combination \
             after protocol=/direction= filtering — the method only travels as: {}",
            rule.method,
            slots.join(", ")
        )));
    }
    if rule.effect == RuleEffect::Deny && (!rule.uris.is_empty() || !rule.filters.is_empty()) {
        return Err(PolicyError::KdlParse(format!(
            "deny rule for method \"{}\" cannot carry uri/filter children",
            rule.method
        )));
    }
    if !rule.filters.is_empty() && rule.method != "subscriptions/listen" {
        return Err(PolicyError::KdlParse(format!(
            "filter children are only valid on subscriptions/listen rules, not \"{}\"",
            rule.method
        )));
    }
    if !rule.uris.is_empty()
        && !matches!(
            rule.method.as_str(),
            "resources/read"
                | "resources/subscribe"
                | "resources/unsubscribe"
                | "subscriptions/listen"
        )
    {
        return Err(PolicyError::KdlParse(format!(
            "uri children are only valid on resources/read, resources/subscribe, \
             resources/unsubscribe, and subscriptions/listen rules, not \"{}\"",
            rule.method
        )));
    }
    if rule.method == "subscriptions/listen"
        && !rule.uris.is_empty()
        && !rule
            .filters
            .contains(&SubscriptionFilter::ResourceSubscriptions)
    {
        return Err(PolicyError::KdlParse(
            "uri children on a subscriptions/listen rule require \
             filter \"resourceSubscriptions\""
                .into(),
        ));
    }
    Ok(())
}

pub(crate) fn parse_servers(
    doc: &KdlDocument,
    defaults_layer: &PolicyLayer,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
    version: u32,
) -> Result<Vec<ToolPolicy>, PolicyError> {
    let mut tools = Vec::new();

    for node in doc.nodes() {
        if node.name().to_string() != "server" {
            continue;
        }

        let server_name = node.get(0).and_then(|v| v.as_string()).map(String::from);

        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

        // Parse server-defaults if present
        let server_defaults_layer = if let Some(sd_node) = children.get("server-defaults") {
            if let Some(sd_children) = sd_node.children() {
                parse_layer_children(sd_children)?
            } else {
                PolicyLayer::default()
            }
        } else {
            PolicyLayer::default()
        };

        // `environment` is a launch-level contract (`defaults.environment`);
        // an `environment` node directly under `server` is rejected by
        // `parse_server_hashes` below, which scans every server child.
        for child in children.nodes() {
            if child.name().to_string() != "tool" {
                continue;
            }

            let tool_name = child
                .get(0)
                .and_then(|v| v.as_string())
                .ok_or_else(|| {
                    PolicyError::KdlParse("tool node must have a name as first argument".into())
                })?
                .to_string();

            if version >= 2 {
                validate_tool_shape_v2(child, &tool_name)?;
            }

            let tool_children = child.children();

            // Check if tool is explicitly denied (strict type check)
            let explicit_deny = if let Some(val) = child.get("deny") {
                match val.as_bool() {
                    Some(b) => Some(b),
                    None => {
                        return Err(PolicyError::KdlParse(format!(
                            "'deny' property on tool '{}' must be a boolean (e.g. deny=#true), got {:?}",
                            tool_name, val
                        )));
                    }
                }
            } else {
                None
            };

            // Parse args_schema if present (strict type check, resolve relative to base_dir)
            let args_schema = if let Some(val) = child.get("args_schema") {
                match val.as_string() {
                    Some(s) => Some(resolve_tool_args_schema(s, base_dir)?),
                    None => {
                        return Err(PolicyError::KdlParse(format!(
                            "'args_schema' property on tool '{}' must be a string",
                            tool_name
                        )));
                    }
                }
            } else {
                None
            };

            // Parse side_effect if present (strict type check)
            let side_effect = if let Some(val) = child.get("side_effect") {
                match val.as_string() {
                    Some(s) => {
                        crate::policy::SideEffect::parse(s).map_err(PolicyError::KdlParse)?;
                        Some(s.to_string())
                    }
                    None => {
                        return Err(PolicyError::KdlParse(format!(
                            "'side_effect' property on tool '{}' must be a string",
                            tool_name
                        )));
                    }
                }
            } else {
                None
            };

            // Parse input_responses if present (strict type check)
            let (input_responses, input_responses_specified) =
                if let Some(val) = child.get("input_responses") {
                    match val.as_string() {
                        Some(raw) => (
                            InputResponsesMode::parse_kdl(raw).map_err(PolicyError::KdlParse)?,
                            true,
                        ),
                        None => {
                            return Err(PolicyError::KdlParse(format!(
                                "'input_responses' property on tool '{}' must be a string",
                                tool_name
                            )));
                        }
                    }
                } else {
                    (InputResponsesMode::Auto, false)
                };

            // Profile reference: either property `profile="name"` or child `profile "name"` / `profiles "name"`
            let profile_name = if let Some(val) = child.get("profile") {
                match val.as_string() {
                    Some(s) => Some(s.to_string()),
                    None => {
                        return Err(PolicyError::KdlParse(format!(
                            "'profile' property on tool '{}' must be a string",
                            tool_name
                        )));
                    }
                }
            } else if let Some(tc) = tool_children {
                tc.get("profile")
                    .or_else(|| tc.get("profiles"))
                    .and_then(|n| n.get(0))
                    .and_then(|v| v.as_string())
                    .map(|s| s.to_string())
            } else {
                None
            };

            let profile_layer = if let Some(ref pname) = profile_name {
                profiles
                    .get(pname)
                    .ok_or_else(|| {
                        PolicyError::Validation(format!(
                            "unknown profile '{}' referenced by tool '{}'",
                            pname, tool_name
                        ))
                    })?
                    .clone()
            } else {
                PolicyLayer::default()
            };

            // Parse tool-level rules
            let tool_fs = if let Some(tc) = tool_children {
                if let Some(fs_node) = tc.get("filesystem") {
                    if let Some(c) = fs_node.children() {
                        Some(parse_tool_fs(c)?)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let tool_syscalls = if let Some(tc) = tool_children {
                if let Some(sc_node) = tc.get("syscalls") {
                    if let Some(c) = sc_node.children() {
                        Some(parse_tool_syscalls(c)?)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let tool_network = if let Some(tc) = tool_children {
                if let Some(net_node) = tc.get("network") {
                    if let Some(c) = net_node.children() {
                        Some(parse_tool_network(c)?)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let has_tool_fs = tool_fs.is_some();
            let has_tool_syscalls = tool_syscalls.is_some();
            let has_tool_network = tool_network.is_some();
            let has_tool_environment =
                tool_children.is_some_and(|tc| tc.get("environment").is_some());

            let (process_exec_allowed, process_explicit) = if let Some(tc) = tool_children {
                if let Some(proc_node) = tc.get("process") {
                    (parse_process_exec_allowed(proc_node)?, true)
                } else {
                    (false, false)
                }
            } else {
                (false, false)
            };

            let tool_layer = PolicyLayer {
                allowed: explicit_deny.map(|d| !d),
                fs: tool_fs,
                syscalls: tool_syscalls,
                network: tool_network,
                environment_explicit: has_tool_environment,
            };

            // 4-stage merge: defaults → profile → server-defaults → tool
            let merged = merge_policy(&[
                defaults_layer,
                &profile_layer,
                &server_defaults_layer,
                &tool_layer,
            ]);

            validate_merged(&merged)?;

            let has_fs = has_tool_fs
                || profile_layer.fs.is_some()
                || server_defaults_layer.fs.is_some()
                || defaults_layer.fs.is_some()
                || !merged.fs.allowed_paths.is_empty()
                || !merged.fs.read_only_paths.is_empty()
                || !merged.fs.read_write_paths.is_empty()
                || !merged.fs.denied_paths.is_empty();

            let fs = if has_fs { Some(merged.fs) } else { None };

            let has_syscalls = has_tool_syscalls
                || profile_layer.syscalls.is_some()
                || server_defaults_layer.syscalls.is_some()
                || defaults_layer.syscalls.is_some()
                || !merged.syscalls.allowed.is_empty()
                || !merged.syscalls.denied.is_empty();

            let syscalls = if has_syscalls {
                Some(merged.syscalls)
            } else {
                None
            };

            let has_network = has_tool_network
                || profile_layer.network.is_some()
                || server_defaults_layer.network.is_some()
                || defaults_layer.network.is_some()
                || !merged.network.allowed_hosts.is_empty()
                || !merged.network.denied_hosts.is_empty();

            let network = if has_network {
                Some(merged.network)
            } else {
                None
            };

            tools.push(ToolPolicy {
                name: tool_name,
                allowed: merged.allowed,
                args_schema,
                side_effect,
                server: server_name.clone(),
                fs,
                syscalls,
                network,
                input_responses,
                input_responses_specified,
                fs_explicit: has_tool_fs
                    || profile_layer.fs.is_some()
                    || server_defaults_layer.fs.is_some(),
                network_explicit: has_tool_network
                    || profile_layer.network.is_some()
                    || server_defaults_layer.network.is_some(),
                syscalls_explicit: has_tool_syscalls
                    || profile_layer.syscalls.is_some()
                    || server_defaults_layer.syscalls.is_some(),
                environment_explicit: has_tool_environment
                    || profile_layer.environment_explicit
                    || server_defaults_layer.environment_explicit,
                process_exec_allowed,
                process_explicit,
            });
        }
    }

    Ok(tools)
}

/// `process deny-all=#true` means no exec grant. `#false` or `allow` grants exec.
pub(crate) fn parse_process_exec_allowed(node: &kdl::KdlNode) -> Result<bool, PolicyError> {
    if let Some(val) = node.get("deny-all") {
        let deny_all = val
            .as_bool()
            .ok_or_else(|| PolicyError::KdlParse("'process.deny-all' must be a boolean".into()))?;
        return Ok(!deny_all);
    }
    if let Some(children) = node.children() {
        if children.get("allow").is_some() {
            return Ok(true);
        }
        if let Some(deny_all_node) = children.get("deny-all") {
            let deny_all = deny_all_node
                .get(0)
                .and_then(|v| v.as_bool())
                .ok_or_else(|| {
                    PolicyError::KdlParse("'process.deny-all' must be a boolean".into())
                })?;
            return Ok(!deny_all);
        }
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

/// Parse hash entries (binary-hash, lockfile-hash, entrypoint-hash) from server blocks.
pub(crate) fn parse_server_hashes(doc: &KdlDocument) -> Result<Vec<HashEntry>, PolicyError> {
    let mut entries = Vec::new();

    for node in doc.nodes() {
        if node.name().to_string() != "server" {
            continue;
        }

        let server_name = match node.get(0).and_then(|v| v.as_string()) {
            Some(name) => name.to_string(),
            None => {
                return Err(PolicyError::KdlParse(
                    "server node must have a name argument".into(),
                ));
            }
        };

        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

        for child in children.nodes() {
            let name = child.name().to_string();
            let hash_type = match name.as_str() {
                "binary-hash" => HashType::Binary,
                "lockfile-hash" => HashType::Lockfile,
                "entrypoint-hash" => HashType::Entrypoint,
                "docker-manifest-hash" => HashType::DockerManifest,
                "tools-list-hash" | "tool" | "server-defaults" | "defaults" | "filesystem"
                | "syscalls" | "network" | "profile" | "profiles" | "mcp" => continue,
                "environment" => {
                    return Err(PolicyError::KdlParse(format!(
                        "'environment' in server '{server_name}' is not supported; \
                         environment is a launch-level contract — declare it under \
                         top-level 'defaults'"
                    )));
                }
                other if other.contains("hash") => {
                    return Err(PolicyError::KdlParse(format!(
                        "unknown hash node '{other}' in server '{server_name}'; \
                         expected binary-hash, lockfile-hash, entrypoint-hash, \
                         docker-manifest-hash, or tools-list-hash"
                    )));
                }
                other => {
                    return Err(PolicyError::KdlParse(format!(
                        "unknown node '{other}' in server '{server_name}'"
                    )));
                }
            };

            let hash_value = child.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "{} in server '{server_name}' requires a string digest argument",
                    name
                ))
            })?;
            validate_sha256_digest(hash_value)?;

            let target = child
                .get("target")
                .and_then(|v| v.as_string())
                .map(String::from)
                .or_else(|| {
                    child.children().and_then(|c| {
                        c.get("target")
                            .and_then(|n| n.get(0))
                            .and_then(|v| v.as_string())
                            .map(String::from)
                    })
                })
                .unwrap_or_default();
            if target.trim().is_empty() {
                return Err(PolicyError::KdlParse(format!(
                    "{} in server '{server_name}' requires a non-empty target",
                    name
                )));
            }

            let approved = child
                .get("approved")
                .and_then(|v| v.as_string())
                .map(String::from)
                .or_else(|| {
                    child.children().and_then(|c| {
                        c.get("approved")
                            .and_then(|n| n.get(0))
                            .and_then(|v| v.as_string())
                            .map(String::from)
                    })
                });

            entries.push(HashEntry {
                server_name: server_name.clone(),
                hash_type,
                hash_value: hash_value.to_string(),
                target,
                approved,
            });
        }
    }

    Ok(entries)
}

fn validate_sha256_digest(digest: &str) -> Result<(), PolicyError> {
    let hex = digest.strip_prefix("sha256:").ok_or_else(|| {
        PolicyError::KdlParse(format!("digest '{digest}' must be sha256:<64 hex chars>"))
    })?;
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(PolicyError::KdlParse(format!(
            "digest '{digest}' must be sha256:<64 hex chars>"
        )));
    }
    Ok(())
}

/// Parse `tools-list-hash` entries from server blocks.
pub(crate) fn parse_tools_list_hashes(
    doc: &KdlDocument,
) -> Result<Vec<ToolsListHashEntry>, PolicyError> {
    let mut entries = Vec::new();

    for node in doc.nodes() {
        if node.name().to_string() != "server" {
            continue;
        }

        let server_name = match node.get(0).and_then(|v| v.as_string()) {
            Some(name) => name.to_string(),
            None => {
                return Err(PolicyError::KdlParse(
                    "server node must have a name argument".into(),
                ));
            }
        };

        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

        for child in children.nodes() {
            if child.name().to_string() != "tools-list-hash" {
                continue;
            }

            let hash_value = child.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
                PolicyError::KdlParse(format!(
                    "tools-list-hash in server '{server_name}' requires a string digest argument"
                ))
            })?;
            validate_sha256_digest(hash_value)?;

            let approved = child
                .get("approved")
                .and_then(|v| v.as_string())
                .map(String::from)
                .or_else(|| {
                    child.children().and_then(|c| {
                        c.get("approved")
                            .and_then(|n| n.get(0))
                            .and_then(|v| v.as_string())
                            .map(String::from)
                    })
                });

            entries.push(ToolsListHashEntry {
                server_name: server_name.clone(),
                hash_value: hash_value.to_string(),
                approved,
            });
        }
    }

    Ok(entries)
}

/// Parse network allow/deny nodes into NetworkPolicy.
pub(crate) fn parse_network_rules(doc: &KdlDocument) -> Result<NetworkPolicy, PolicyError> {
    let mut allowed = Vec::new();
    let mut denied_hosts = Vec::new();
    // Secure by default: deny all others unless explicitly opened with `allow host="*"`.
    let mut deny_all = true;
    let mut inbound = crate::policy::InboundPolicy::default();

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
                    allowed.push(crate::policy::host::normalize_policy_host(host));
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
            denied_hosts,
            deny_all_others: deny_all,
        },
        inbound,
    })
}
