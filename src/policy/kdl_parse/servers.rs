use std::collections::HashMap;
use std::path::Path;

use kdl::KdlDocument;

use super::{
    parse_deputy_node, parse_layer_children, parse_process_exec_allowed, parse_tool_fs,
    parse_tool_network, parse_tool_syscalls, resolve_tool_args_schema, unique_child,
    validate_tool_shape_v2,
};
use crate::error::PolicyError;
use crate::policy::merge::{PolicyLayer, merge_policy, validate_merged};
use crate::policy::{HashEntry, HashType, InputResponsesMode, ToolPolicy, ToolsListHashEntry};

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
        let server_ctx = format!("server '{}'", server_name.as_deref().unwrap_or("<unnamed>"));
        let server_defaults_layer =
            if let Some(sd_node) = unique_child(children, "server-defaults", &server_ctx)? {
                if let Some(sd_children) = sd_node.children() {
                    parse_layer_children(sd_children, &server_ctx)?
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
            let tool_ctx = format!("tool '{tool_name}'");

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
                    Some(s) => {
                        // The property and a child node together are
                        // ambiguous about which profile applies.
                        if let Some(tc) = tool_children {
                            let prof = unique_child(tc, "profile", &tool_ctx)?;
                            let profs = unique_child(tc, "profiles", &tool_ctx)?;
                            if prof.is_some() || profs.is_some() {
                                return Err(PolicyError::KdlParse(format!(
                                    "tool '{tool_name}' sets 'profile' both as a property \
                                     and as a profile/profiles child node"
                                )));
                            }
                        }
                        Some(s.to_string())
                    }
                    None => {
                        return Err(PolicyError::KdlParse(format!(
                            "'profile' property on tool '{}' must be a string",
                            tool_name
                        )));
                    }
                }
            } else if let Some(tc) = tool_children {
                let prof = unique_child(tc, "profile", &tool_ctx)?;
                let profs = unique_child(tc, "profiles", &tool_ctx)?;
                if prof.is_some() && profs.is_some() {
                    // `profile "a"` and `profiles "b"` siblings pick one
                    // silently otherwise — either could be meant.
                    return Err(PolicyError::KdlParse(format!(
                        "tool '{tool_name}' declares both 'profile' and 'profiles' child nodes"
                    )));
                }
                prof.or(profs)
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

            // Parse tool-level rules. Same-named policy blocks are
            // unique per tool — `get` would take the first and silently
            // drop the rest.
            let tool_fs = if let Some(tc) = tool_children {
                if let Some(fs_node) = unique_child(tc, "filesystem", &tool_ctx)? {
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
                if let Some(sc_node) = unique_child(tc, "syscalls", &tool_ctx)? {
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
                if let Some(net_node) = unique_child(tc, "network", &tool_ctx)? {
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

            // `deputy` declares a Confused Deputy role + extraction rules.
            // Under v1 it would be silently ignored (there is no closed
            // tool schema), so it is rejected outright rather than
            // dropped — the same reasoning as `mcp` rules.
            let deputy = match tool_children
                .map(|tc| unique_child(tc, "deputy", &format!("tool '{tool_name}'")))
                .transpose()?
                .flatten()
            {
                Some(node) => {
                    if version < 2 {
                        return Err(PolicyError::KdlParse(format!(
                            "'deputy' on tool '{tool_name}' requires 'policy version=2'"
                        )));
                    }
                    Some(parse_deputy_node(node, &tool_name)?)
                }
                None => None,
            };

            let has_tool_fs = tool_fs.is_some();
            let has_tool_syscalls = tool_syscalls.is_some();
            let has_tool_network = tool_network.is_some();
            let has_tool_environment = tool_children
                .map(|tc| unique_child(tc, "environment", &tool_ctx))
                .transpose()?
                .flatten()
                .is_some();

            let (process_exec_allowed, process_explicit) = if let Some(tc) = tool_children {
                if let Some(proc_node) = unique_child(tc, "process", &tool_ctx)? {
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
                deputy,
            });
        }
    }

    Ok(tools)
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
