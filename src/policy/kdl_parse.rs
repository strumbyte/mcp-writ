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
pub(crate) use servers::{
    parse_server_hashes, parse_servers, parse_tools_list_hashes, resolve_tool_profile_names,
};

/// Parse KDL content string into a Policy struct.
pub fn parse_kdl_policy(content: &str) -> Result<Policy, PolicyError> {
    let doc: KdlDocument = content
        .parse()
        .map_err(|e: kdl::KdlError| PolicyError::KdlParse(e.to_string()))?;
    let version = parse_version(&doc)?;
    let profiles = parse_profiles(&doc, version)?;
    // No `base_dir` means `@file` references stay unresolved — nothing
    // is read, nothing to record.
    let mut schema_sources = Vec::new();
    parse_kdl_policy_with_profiles(content, &profiles, None, &mut schema_sources, None)
}

/// Parse KDL content string with existing profiles and base directory.
/// `schema_sources` collects every `@file` document the parse read —
/// the caller records them as protected policy sources. `rules`
/// overrides the composition-semantics version the layer merges run
/// under (`None` = the document's declared version); the declaration
/// grammar always follows the declared version.
pub fn parse_kdl_policy_with_profiles(
    content: &str,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
    schema_sources: &mut Vec<std::path::PathBuf>,
    rules: Option<u32>,
) -> Result<Policy, PolicyError> {
    let doc: KdlDocument = content
        .parse()
        .map_err(|e: kdl::KdlError| PolicyError::KdlParse(e.to_string()))?;

    let version = parse_version(&doc)?;
    let transport = parse_transport(&doc);
    let defaults = parse_defaults(&doc, version)?;
    let logging = parse_logging(&doc)?;
    let sandbox = parse_sandbox(&doc)?;
    let defaults_layer = defaults_to_layer(&defaults);
    let rules = rules.unwrap_or(version);
    let tools = parse_servers(
        &doc,
        &defaults_layer,
        profiles,
        base_dir,
        version,
        rules,
        schema_sources,
    )?;
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
        provenance: None,
    };
    crate::policy::apply_outbound_deny_precedence(&mut policy.network.outbound);
    // A bare parse keeps no provenance log — the rematerialization's
    // re-attribution records are dropped with the scratch sink.
    rematerialize_inherited_defaults(
        &mut policy,
        &mut super::provenance::Provenance::default(),
        Path::new(""),
    );
    Ok(policy)
}

/// Parsed default policies from the `defaults` node.
#[derive(Default)]
pub(crate) struct Defaults {
    pub(crate) fs: FsPolicy,
    pub(crate) syscalls: SyscallPolicy,
    pub(crate) network: NetworkPolicy,
    pub(crate) environment: EnvironmentPolicy,
    /// `policy version=3`: `replace=#true` on the `defaults` sub-blocks —
    /// the same flag an inner layer can carry, so a composed document's
    /// defaults layer composes with the same rules a profile does.
    pub(crate) fs_replace: bool,
    pub(crate) syscalls_replace: bool,
    pub(crate) network_replace: bool,
}

/// `replace=#true` on a `filesystem`/`syscalls`/`network` block is a
/// `policy version=3` declaration. Under v2 the strict schema rejects
/// the property before parsing; under v1 permissive parsing ignores it.
/// This check is the fallback for paths that skip the schema pass.
pub(crate) fn parse_replace_flag(
    node: &kdl::KdlNode,
    context: &str,
    version: u32,
) -> Result<bool, PolicyError> {
    let Some(val) = node.get("replace") else {
        return Ok(false);
    };
    if version == 2 {
        return Err(PolicyError::KdlParse(format!(
            "'replace' on '{context}' requires 'policy version=3'"
        )));
    }
    if version < 2 {
        // v1 is permissive — an unrecognized property is ignored.
        return Ok(false);
    }
    val.as_bool().ok_or_else(|| {
        PolicyError::KdlParse(format!(
            "'replace' on '{context}' must be a boolean (#true or #false)"
        ))
    })
}

/// An `allow none=#true` declaration parses as `allow_specified` with
/// empty allow lists. Under v3 union semantics that spelling would merge
/// as a no-op — the narrowed scope the author asked for silently widens
/// back to the inherited grants — so it must opt into replacement
/// explicitly with `replace=#true` on the block.
pub(crate) fn check_none_needs_replace(
    allow_specified: bool,
    has_allow_values: bool,
    replace: bool,
    context: &str,
    version: u32,
) -> Result<(), PolicyError> {
    if version >= 3 && allow_specified && !has_allow_values && !replace {
        return Err(PolicyError::KdlParse(format!(
            "'allow none=#true' in '{context}' requires 'replace=#true' under policy version 3 — \
             without it the narrowed allow list would union with the inherited grants"
        )));
    }
    Ok(())
}

pub(crate) fn parse_version(doc: &KdlDocument) -> Result<u32, PolicyError> {
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

fn parse_defaults(doc: &KdlDocument, version: u32) -> Result<Defaults, PolicyError> {
    let Some(node) = unique_child(doc, "defaults", "the policy document")? else {
        return Ok(Defaults::default());
    };

    let children = match node.children() {
        Some(c) => c,
        None => {
            return Ok(Defaults::default());
        }
    };

    let mut fs_replace = false;
    let fs = if let Some(n) = unique_child(children, "filesystem", "'defaults'")? {
        fs_replace = parse_replace_flag(n, "defaults.filesystem", version)?;
        if let Some(c) = n.children() {
            parse_fs_allows(c)?
        } else {
            FsPolicy::default()
        }
    } else {
        FsPolicy::default()
    };

    let mut syscalls_replace = false;
    let syscalls = if let Some(n) = unique_child(children, "syscalls", "'defaults'")? {
        syscalls_replace = parse_replace_flag(n, "defaults.syscalls", version)?;
        if let Some(c) = n.children() {
            parse_syscall_allows(c, version)?
        } else {
            SyscallPolicy::default()
        }
    } else {
        SyscallPolicy::default()
    };

    let mut network_replace = false;
    let network = if let Some(n) = unique_child(children, "network", "'defaults'")? {
        network_replace = parse_replace_flag(n, "defaults.network", version)?;
        if let Some(c) = n.children() {
            parse_network_rules(c)?
        } else {
            NetworkPolicy::default()
        }
    } else {
        NetworkPolicy::default()
    };

    let environment = if let Some(n) = unique_child(children, "environment", "'defaults'")? {
        let env = parse_environment_node(n)?;
        EnvironmentPolicy {
            restrict: !env.inherit_parent,
            allowed: env.allowed,
            declared: true,
            inherit_parent: env.inherit_parent,
        }
    } else {
        EnvironmentPolicy::default()
    };

    Ok(Defaults {
        fs,
        syscalls,
        network,
        environment,
        fs_replace,
        syscalls_replace,
        network_replace,
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

/// The parsed contents of a `defaults { environment { ... } }` node.
pub(crate) struct ParsedEnvironment {
    /// Positional `allow "NAME"` arguments.
    pub(crate) allowed: Vec<String>,
    /// `inherit-parent #true` — ambient parent-environment inheritance,
    /// an explicit downgrade opt-in.
    pub(crate) inherit_parent: bool,
}

/// Parse a `defaults { environment { ... } }` node.
///
/// Permitted children: `allow "NAME"` nodes (names copied from the
/// parent environment into the restricted child environment) and a
/// single `inherit-parent #true` node (opt back into ambient
/// inheritance — a downgrade). The `environment` node itself must carry
/// no arguments or properties. Node presence alone marks the contract
/// declared, so an empty `environment {}` yields an empty allow list
/// with restriction kept — restriction is now the default, so the node
/// only documents intent or carries `inherit-parent`.
/// `inherit-parent #true` combined with `allow` entries is refused:
/// inheritance makes an allow list dead configuration.
pub(crate) fn parse_environment_node(
    node: &kdl::KdlNode,
) -> Result<ParsedEnvironment, PolicyError> {
    if !node.entries().is_empty() {
        return Err(PolicyError::KdlParse(
            "'environment' node takes no arguments or properties; use 'allow \"NAME\"' or \
             'inherit-parent #true' children"
                .into(),
        ));
    }
    let mut allowed = Vec::new();
    let mut inherit_parent = false;
    let Some(children) = node.children() else {
        return Ok(ParsedEnvironment {
            allowed,
            inherit_parent,
        });
    };
    for child in children.nodes() {
        let name = child.name().to_string();
        match name.as_str() {
            "allow" => {
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
            "inherit-parent" => {
                if child.children().is_some() {
                    return Err(PolicyError::KdlParse(
                        "'inherit-parent' node in environment takes no children".into(),
                    ));
                }
                let mut entries = child.entries().iter();
                let (Some(entry), None) = (entries.next(), entries.next()) else {
                    return Err(PolicyError::KdlParse(
                        "'inherit-parent' node takes exactly one boolean argument".into(),
                    ));
                };
                if entry.name().is_some() {
                    return Err(PolicyError::KdlParse(
                        "'inherit-parent' takes a positional boolean, not a property".into(),
                    ));
                }
                let flag = entry.value().as_bool().ok_or_else(|| {
                    PolicyError::KdlParse(
                        "'inherit-parent' argument must be a boolean (#true/#false)".into(),
                    )
                })?;
                if inherit_parent && flag {
                    return Err(PolicyError::KdlParse(
                        "duplicate 'inherit-parent #true' in environment block".into(),
                    ));
                }
                if flag {
                    inherit_parent = true;
                }
            }
            other => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected node '{other}' in environment block; only 'allow' and \
                     'inherit-parent' are supported"
                )));
            }
        }
    }
    if inherit_parent && !allowed.is_empty() {
        return Err(PolicyError::KdlParse(
            "'inherit-parent #true' cannot be combined with 'allow' entries — inheritance \
             already delivers every parent variable"
                .into(),
        ));
    }
    Ok(ParsedEnvironment {
        allowed,
        inherit_parent,
    })
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
    if let Some(node) = doc.get("sandbox") {
        if let Some(val) = node.get("allow_degraded") {
            policy.allow_degraded = val.as_bool().ok_or_else(|| {
                PolicyError::KdlParse("'sandbox.allow_degraded' must be a boolean".into())
            })?;
        }
        if let Some(val) = node.get("require_lifetime_boundary") {
            policy.require_lifetime_boundary = val.as_bool().ok_or_else(|| {
                PolicyError::KdlParse(
                    "'sandbox.require_lifetime_boundary' must be a boolean".into(),
                )
            })?;
        }
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

    let syscalls = if !defaults.syscalls.allowed.is_empty() || !defaults.syscalls.denied.is_empty()
    {
        Some(ToolSyscallPolicy {
            allowed: defaults.syscalls.allowed.clone(),
            denied: defaults.syscalls.denied.clone(),
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
        fs_replace: defaults.fs_replace,
        syscalls_replace: defaults.syscalls_replace,
        network_replace: defaults.network_replace,
    }
}

fn parse_layer_children(
    children: &KdlDocument,
    context: &str,
    version: u32,
) -> Result<PolicyLayer, PolicyError> {
    // `environment` is a launch-level contract (`defaults.environment`) —
    // inside a profile or server-defaults layer it has no effect, so it is
    // rejected here instead of drifting to a tool-level check later.
    if children.get("environment").is_some() {
        return Err(PolicyError::KdlParse(
            "'environment' is only allowed under 'defaults' — it cannot appear in a profile or server-defaults block".into(),
        ));
    }

    let mut fs_replace = false;
    let fs = if let Some(n) = unique_child(children, "filesystem", context)? {
        fs_replace = parse_replace_flag(n, &format!("{context}.filesystem"), version)?;
        if let Some(c) = n.children() {
            let policy = parse_tool_fs(c)?;
            check_none_needs_replace(
                policy.allow_specified,
                !policy.allowed_paths.is_empty(),
                fs_replace,
                &format!("{context}.filesystem"),
                version,
            )?;
            Some(policy)
        } else {
            None
        }
    } else {
        None
    };

    let mut syscalls_replace = false;
    let syscalls = if let Some(n) = unique_child(children, "syscalls", context)? {
        syscalls_replace = parse_replace_flag(n, &format!("{context}.syscalls"), version)?;
        if let Some(c) = n.children() {
            Some(parse_tool_syscalls(c)?)
        } else {
            None
        }
    } else {
        None
    };

    let mut network_replace = false;
    let network = if let Some(n) = unique_child(children, "network", context)? {
        network_replace = parse_replace_flag(n, &format!("{context}.network"), version)?;
        if let Some(c) = n.children() {
            let policy = parse_tool_network(c)?;
            check_none_needs_replace(
                policy.allow_specified,
                !policy.allowed_hosts.is_empty()
                    || !policy.allowed_cidrs.is_empty()
                    || policy.egress_rules.iter().any(|r| r.allow),
                network_replace,
                &format!("{context}.network"),
                version,
            )?;
            Some(policy)
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
        fs_replace,
        syscalls_replace,
        network_replace,
    })
}

pub(crate) fn parse_profiles(
    doc: &KdlDocument,
    version: u32,
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
            parse_layer_children(children, &format!("profile '{name}'"), version)?
        } else {
            PolicyLayer::default()
        };

        profiles.insert(name, layer);
    }

    Ok(profiles)
}

/// Resolve an `args_schema` spelling: `@file` reads the document
/// relative to `base_dir` (or absolutely); anything else is returned
/// verbatim. The second tuple element is the file actually read, when
/// one was, as `(spelled, canonical)`: the absolute path exactly as
/// spelled — symlinks left unresolved — plus the opened file's real
/// path, captured from the same handle the content streamed from so a
/// repointed link cannot split the recorded source from the bytes.
/// Callers record both as policy sources so a workload write grant
/// covering either refuses the launch.
pub(crate) fn resolve_tool_args_schema(
    schema_ref: &str,
    base_dir: Option<&Path>,
) -> Result<(String, Option<(PathBuf, PathBuf)>), PolicyError> {
    if let Some(file_path) = schema_ref.strip_prefix('@') {
        let file_path = file_path.trim();
        if let Some(base) = base_dir {
            let resolved = if Path::new(file_path).is_absolute() {
                PathBuf::from(file_path)
            } else {
                base.join(file_path)
            };
            let (content, canonical) = crate::fspriv::read_text_bounded_follow_links_resolved(
                &resolved,
                super::MAX_SCHEMA_FILE_BYTES,
            )
            .map_err(|e| {
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
            let spelled = crate::fsoverlap::absolutize_lexical(&resolved);
            Ok((content, Some((spelled, canonical))))
        } else {
            Ok((schema_ref.to_string(), None))
        }
    } else {
        Ok((schema_ref.to_string(), None))
    }
}

/// Strict `tool` node shape required by `policy version>=2` (KDL schema
/// v2/v3 share the closed grammar).
///
/// A `tool` entry accepts exactly one positional name argument, only the
/// documented properties, and only the documented child nodes. Unknown
/// members are load errors — unknown methods (`mcp`), unknown fields,
/// and malformed shapes never pass silently. `environment` stays
/// accepted here so `environment_explicit` can flag it and the validator
/// reject it like an inline v1 declaration.
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
