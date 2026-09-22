use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kdl::KdlDocument;

use super::kdl_parse::{
    Defaults, defaults_to_layer, parse_environment_node, parse_fs_allows,
    parse_kdl_policy_with_profiles, parse_logging_fail_closed, parse_network_rules,
    parse_process_exec_allowed, parse_profiles, parse_server_hashes, parse_servers,
    parse_syscall_allows, parse_tool_fs, parse_tool_network, parse_tool_syscalls,
    parse_tools_list_hashes, parse_trajectory, resolve_tool_args_schema, validate_logging_level,
};
use super::merge::PolicyLayer;
use super::{EnvironmentPolicy, InputResponsesMode, Policy};
use crate::error::PolicyError;

/// Internal recursive loader that handles extends, include, and when directives
/// with circular-reference detection via a visited set.
pub(crate) fn load_kdl_policy_internal(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
) -> Result<Policy, PolicyError> {
    let mut profiles = HashMap::new();
    load_kdl_policy_recursive(path, visited, env, &mut profiles)
}

fn load_kdl_policy_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
    profiles: &mut HashMap<String, PolicyLayer>,
) -> Result<Policy, PolicyError> {
    Ok(load_kdl_policy_recursive_with_doc(path, visited, env, profiles)?.0)
}

fn load_kdl_policy_recursive_with_doc(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
    profiles: &mut HashMap<String, PolicyLayer>,
) -> Result<(Policy, KdlDocument), PolicyError> {
    let canonical = path.canonicalize().map_err(PolicyError::FileRead)?;
    if !visited.insert(canonical.clone()) {
        return Err(PolicyError::Validation(format!(
            "circular reference detected: '{}'",
            path.display(),
        )));
    }

    let content = std::fs::read_to_string(path).map_err(PolicyError::FileRead)?;
    let doc: KdlDocument = content
        .parse()
        .map_err(|e: kdl::KdlError| PolicyError::KdlParse(e.to_string()))?;

    let base_dir = path.parent().unwrap_or(Path::new("."));

    // ── Step 1: Process `extends "base.kdl"` ──────────────────────
    let mut policy = if let Some(extends_node) = doc.get("extends") {
        let base_name = extends_node
            .get(0)
            .and_then(|v| v.as_string())
            .ok_or_else(|| {
                PolicyError::KdlParse("extends node must have a file path argument".into())
            })?;
        let base_path = base_dir.join(base_name);
        load_kdl_policy_recursive(&base_path, visited, env, profiles)?
    } else {
        Policy::default()
    };

    // ── Step 2: Process `include "extra.kdl"` ─────────────────────
    for node in doc.nodes() {
        if node.name().to_string() != "include" {
            continue;
        }
        let inc_name = node.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
            PolicyError::KdlParse("include node must have a file path argument".into())
        })?;
        let inc_path = base_dir.join(inc_name);
        let (included, inc_doc) =
            load_kdl_policy_recursive_with_doc(&inc_path, visited, env, profiles)?;
        merge_into_policy(&mut policy, &included, &inc_doc);
        if included.confused_deputy_protection {
            policy.confused_deputy_protection = true;
        }
        if included.trajectory {
            policy.trajectory = true;
        }
        if included.logging.level != "info" && policy.logging.level == "info" {
            policy.logging.level = included.logging.level;
        }
    }

    // ── Step 3: Parse current document ────────────────────────────
    let doc_profiles = parse_profiles(&doc)?;
    profiles.extend(doc_profiles);

    let this_policy = parse_kdl_policy_with_profiles(&content, profiles, Some(base_dir))?;

    // If this file has an extends, merge current on top of base+includes.
    // Otherwise, current IS the base.
    if doc.get("extends").is_some()
        || doc
            .nodes()
            .iter()
            .any(|n| n.name().to_string() == "include")
    {
        merge_into_policy(&mut policy, &this_policy, &doc);
    } else {
        policy = this_policy;
    }

    // ── Step 4: Process `when environment="xxx" { ... }` ──────────
    apply_when_overrides(&doc, &mut policy, env, profiles, Some(base_dir))?;
    rematerialize_inherited_defaults(&mut policy);

    // Remove from visited so sibling includes from a parent don't false-trigger
    visited.remove(&canonical);

    Ok((policy, doc))
}

/// Merge `overlay` policy on top of `base` (in place).
///
/// - Scalar fields: overlay wins only if explicitly defined in doc
/// - Allow lists: overlay replaces if non-empty, else base is kept
/// - Deny lists: accumulated (union, sticky)
/// - Tools: overlay tool overrides specified fields; unspecified fields inherited; deny is sticky
fn merge_into_policy(base: &mut Policy, overlay: &Policy, doc: &KdlDocument) {
    // version: overlay wins
    base.version = overlay.version;

    // transport: overlay wins if explicitly set in doc
    if doc.get("transport").is_some() {
        base.transport = overlay.transport.clone();
    }

    // fs: extends/include union allow lists; denies stay sticky.
    if overlay.fs.allow_specified {
        for p in &overlay.fs.read_only {
            if !base.fs.read_only.contains(p) {
                base.fs.read_only.push(p.clone());
            }
        }
        for p in &overlay.fs.read_write {
            if !base.fs.read_write.contains(p) {
                base.fs.read_write.push(p.clone());
            }
        }
        base.fs.allow_specified = true;
    }
    for denied in &overlay.fs.denied_paths {
        if !base.fs.denied_paths.contains(denied) {
            base.fs.denied_paths.push(denied.clone());
        }
    }
    base.fs
        .read_only
        .retain(|p| !base.fs.denied_paths.contains(p));
    base.fs
        .read_write
        .retain(|p| !base.fs.denied_paths.contains(p));
    base.fs
        .read_write
        .retain(|p| !base.fs.read_only.contains(p));

    // syscalls: overlay replaces if non-empty
    if !overlay.syscalls.allowed.is_empty() {
        base.syscalls.allowed = overlay.syscalls.allowed.clone();
    }

    // environment: an `environment` node in the overlay turns restriction on;
    // its allow list replaces the base's only when non-empty (same rule as
    // syscalls). There is no way to un-restrict through an overlay.
    if overlay.environment.restrict {
        base.environment.restrict = true;
        if !overlay.environment.allowed.is_empty() {
            base.environment.allowed = overlay.environment.allowed.clone();
        }
    }

    // network: overlay replaces if non-empty
    if !overlay.network.outbound.allowed.is_empty() {
        base.network.outbound.allowed = overlay.network.outbound.allowed.clone();
    }
    for host in &overlay.network.outbound.denied_hosts {
        if !base.network.outbound.denied_hosts.contains(host) {
            base.network.outbound.denied_hosts.push(host.clone());
        }
    }
    if doc
        .get("defaults")
        .and_then(|d| d.children())
        .and_then(|c| c.get("network"))
        .is_some()
    {
        base.network.outbound.deny_all_others = overlay.network.outbound.deny_all_others;
        base.network.inbound.allow_listen = overlay.network.inbound.allow_listen;
    }
    crate::policy::apply_outbound_deny_precedence(&mut base.network.outbound);

    if doc
        .get("defaults")
        .and_then(|d| d.children())
        .and_then(|c| c.get("filesystem"))
        .is_some()
    {
        // Omitted secret-overlay stays default-on (fail-secure).
        base.fs.secret_overlay = overlay.fs.secret_overlay;
    }

    // logging: overlay level wins only if explicitly configured in doc
    if doc.get("logging").is_some() {
        base.logging = overlay.logging.clone();
    }

    if doc.get("sandbox").is_some() {
        base.sandbox = overlay.sandbox.clone();
    }

    // confused_deputy_protection: overlay wins only if explicitly configured in doc
    if doc.get("confused_deputy_protection").is_some() {
        base.confused_deputy_protection = overlay.confused_deputy_protection;
    }

    // trajectory: overlay wins only if explicitly configured in doc
    if doc.get("trajectory").is_some() {
        base.trajectory = overlay.trajectory;
        base.trajectory_rules = overlay.trajectory_rules.clone();
    }

    // tools: merge only within the same server identity
    for tool in &overlay.tools {
        if let Some(existing) = base
            .tools
            .iter_mut()
            .find(|t| t.name == tool.name && t.server == tool.server)
        {
            // Deny is sticky: if base denied the tool, it stays denied
            if !existing.allowed || !tool.allowed {
                existing.allowed = false;
            }

            // FS merge
            match (&mut existing.fs, &tool.fs) {
                (Some(base_fs), Some(over_fs)) => {
                    if over_fs.require_path.is_some() {
                        base_fs.require_path = over_fs.require_path;
                    }
                    if over_fs.allow_specified {
                        base_fs.allowed_paths = over_fs.allowed_paths.clone();
                        base_fs.read_only_paths = over_fs.read_only_paths.clone();
                        base_fs.read_write_paths = over_fs.read_write_paths.clone();
                        base_fs.allow_specified = true;
                    }
                    for denied in &over_fs.denied_paths {
                        if !base_fs.denied_paths.contains(denied) {
                            base_fs.denied_paths.push(denied.clone());
                        }
                    }
                    base_fs
                        .allowed_paths
                        .retain(|p| !base_fs.denied_paths.contains(p));
                    base_fs
                        .read_only_paths
                        .retain(|p| !base_fs.denied_paths.contains(p));
                    base_fs
                        .read_write_paths
                        .retain(|p| !base_fs.denied_paths.contains(p));
                }
                (None, Some(over_fs)) => {
                    existing.fs = Some(over_fs.clone());
                }
                _ => {}
            }

            // Syscalls merge
            match (&mut existing.syscalls, &tool.syscalls) {
                (Some(base_sc), Some(over_sc)) => {
                    if !over_sc.allowed.is_empty() {
                        base_sc.allowed = over_sc.allowed.clone();
                    }
                    for denied in &over_sc.denied {
                        if !base_sc.denied.contains(denied) {
                            base_sc.denied.push(denied.clone());
                        }
                    }
                    base_sc.allowed.retain(|s| !base_sc.denied.contains(s));
                }
                (None, Some(over_sc)) => {
                    existing.syscalls = Some(over_sc.clone());
                }
                _ => {}
            }

            // Network merge
            match (&mut existing.network, &tool.network) {
                (Some(base_net), Some(over_net)) => {
                    if over_net.allow_specified {
                        base_net.allowed_hosts = over_net.allowed_hosts.clone();
                        base_net.allow_specified = true;
                    }
                    for denied in &over_net.denied_hosts {
                        if !base_net.denied_hosts.contains(denied) {
                            base_net.denied_hosts.push(denied.clone());
                        }
                    }
                    base_net
                        .allowed_hosts
                        .retain(|h| !base_net.denied_hosts.contains(h));
                }
                (None, Some(over_net)) => {
                    existing.network = Some(over_net.clone());
                }
                _ => {}
            }

            if tool.args_schema.is_some() {
                existing.args_schema = tool.args_schema.clone();
            }
            if tool.side_effect.is_some() {
                existing.side_effect = tool.side_effect.clone();
            }
            if tool.input_responses_specified {
                existing.input_responses = tool.input_responses;
                existing.input_responses_specified = true;
            }
            existing.fs_explicit |= tool.fs_explicit;
            existing.network_explicit |= tool.network_explicit;
            existing.syscalls_explicit |= tool.syscalls_explicit;
            existing.environment_explicit |= tool.environment_explicit;
            if tool.process_explicit {
                existing.process_exec_allowed = tool.process_exec_allowed;
                existing.process_explicit = true;
            }
        } else {
            base.tools.push(tool.clone());
        }
    }

    // hash_entries: overlay replaces by (server_name, hash_type, target); new entries appended
    for entry in &overlay.hash_entries {
        if let Some(existing) = base.hash_entries.iter_mut().find(|e| {
            e.server_name == entry.server_name
                && e.hash_type == entry.hash_type
                && e.target == entry.target
        }) {
            *existing = entry.clone();
        } else {
            base.hash_entries.push(entry.clone());
        }
    }

    // tools_list_hashes: overlay replaces by server_name; new entries appended
    for entry in &overlay.tools_list_hashes {
        if let Some(existing) = base
            .tools_list_hashes
            .iter_mut()
            .find(|e| e.server_name == entry.server_name)
        {
            *existing = entry.clone();
        } else {
            base.tools_list_hashes.push(entry.clone());
        }
    }
}

/// Evaluate `when environment="xxx" { ... }` blocks and apply matching overrides.
fn apply_when_overrides(
    doc: &KdlDocument,
    policy: &mut Policy,
    env_value: &str,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
) -> Result<(), PolicyError> {
    for node in doc.nodes() {
        if node.name().to_string() != "when" {
            continue;
        }

        let expected_env = match node.get("environment").and_then(|v| v.as_string()) {
            Some(v) => v,
            None => continue, // unknown condition type, skip
        };

        if expected_env != env_value {
            continue; // condition doesn't match
        }

        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

        // Apply overrides from the when block
        apply_overrides_from_doc(children, policy, profiles, base_dir)?;
    }

    Ok(())
}

/// Apply override fields parsed from a KdlDocument (used by `when` blocks).
fn apply_overrides_from_doc(
    doc: &KdlDocument,
    policy: &mut Policy,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
) -> Result<(), PolicyError> {
    // defaults overrides
    if let Some(defaults_node) = doc.get("defaults")
        && let Some(children) = defaults_node.children()
    {
        if let Some(fs_node) = children.get("filesystem")
            && let Some(fs_children) = fs_node.children()
        {
            let fs = parse_fs_allows(fs_children)?;
            if fs.allow_specified {
                policy.fs.read_only = fs.read_only;
                policy.fs.read_write = fs.read_write;
                policy.fs.allow_specified = true;
            }
            for denied in &fs.denied_paths {
                if !policy.fs.denied_paths.contains(denied) {
                    policy.fs.denied_paths.push(denied.clone());
                }
            }
            policy
                .fs
                .read_only
                .retain(|p| !policy.fs.denied_paths.contains(p));
            policy
                .fs
                .read_write
                .retain(|p| !policy.fs.denied_paths.contains(p));
            policy
                .fs
                .read_write
                .retain(|p| !policy.fs.read_only.contains(p));
        }
        if let Some(sc_node) = children.get("syscalls")
            && let Some(sc_children) = sc_node.children()
        {
            let sc = parse_syscall_allows(sc_children)?;
            if !sc.allowed.is_empty() {
                policy.syscalls.allowed = sc.allowed;
            }
        }
        // Same rule as syscalls: node presence enables restriction; a
        // non-empty `allow` list replaces the base's.
        if let Some(env_node) = children.get("environment") {
            let allowed = parse_environment_node(env_node)?;
            policy.environment.restrict = true;
            if !allowed.is_empty() {
                policy.environment.allowed = allowed;
            }
        }
        if let Some(net_node) = children.get("network")
            && let Some(net_children) = net_node.children()
        {
            let net = parse_network_rules(net_children)?;
            if !net.outbound.allowed.is_empty() || !net.outbound.deny_all_others {
                policy.network.outbound.allowed = net.outbound.allowed;
            }
            for host in &net.outbound.denied_hosts {
                if !policy.network.outbound.denied_hosts.contains(host) {
                    policy.network.outbound.denied_hosts.push(host.clone());
                }
            }
            policy.network.outbound.deny_all_others = net.outbound.deny_all_others;
            if net_children.get("inbound").is_some() {
                policy.network.inbound.allow_listen = net.inbound.allow_listen;
            }
            crate::policy::apply_outbound_deny_precedence(&mut policy.network.outbound);
        }
    }

    // logging override (level and fail_closed are independent)
    if let Some(logging_node) = doc.get("logging") {
        if let Some(level_prop) = logging_node.get("level") {
            let level = level_prop
                .as_string()
                .ok_or_else(|| PolicyError::KdlParse("'logging.level' must be a string".into()))?;
            validate_logging_level(level)?;
            policy.logging.level = level.to_string();
        }
        if logging_node.get("fail_closed").is_some() {
            policy.logging.fail_closed = parse_logging_fail_closed(logging_node)?;
        }
    }

    // sandbox override
    if let Some(sandbox_node) = doc.get("sandbox")
        && let Some(val) = sandbox_node.get("allow_degraded")
    {
        policy.sandbox.allow_degraded = val.as_bool().ok_or_else(|| {
            PolicyError::KdlParse("'sandbox.allow_degraded' must be a boolean".into())
        })?;
    }

    // confused_deputy_protection override
    if let Some(cdp_node) = doc.get("confused_deputy_protection")
        && let Some(arg) = cdp_node.get(0)
    {
        let cdp = arg.as_bool().ok_or_else(|| {
            PolicyError::KdlParse("'confused_deputy_protection' must be a boolean".into())
        })?;
        policy.confused_deputy_protection = cdp;
    }

    // trajectory override (flag + ordered after children)
    if doc.get("trajectory").is_some() {
        let (enabled, rules) = parse_trajectory(doc)?;
        policy.trajectory = enabled;
        policy.trajectory_rules = rules;
    }

    // server/tool overrides
    for node in doc.nodes() {
        if node.name().to_string() != "server" {
            continue;
        }
        let server_name = node.get(0).and_then(|v| v.as_string()).map(String::from);
        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

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

            if let Some(existing) = policy
                .tools
                .iter_mut()
                .find(|t| t.name == tool_name && t.server == server_name)
            {
                if let Some(val) = child.get("deny") {
                    let d = val.as_bool().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'deny' property on tool '{}' must be a boolean",
                            tool_name
                        ))
                    })?;
                    // Sticky deny: if already denied, cannot be reversed to allowed
                    if d {
                        existing.allowed = false;
                    }
                }
                if let Some(val) = child.get("side_effect") {
                    let se = val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'side_effect' property on tool '{}' must be a string",
                            tool_name
                        ))
                    })?;
                    crate::policy::SideEffect::parse(se).map_err(PolicyError::KdlParse)?;
                    existing.side_effect = Some(se.to_string());
                }
                if let Some(val) = child.get("args_schema") {
                    let s = val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'args_schema' property on tool '{}' must be a string",
                            tool_name
                        ))
                    })?;
                    let resolved = resolve_tool_args_schema(s, base_dir)?;
                    existing.args_schema = Some(resolved);
                }
                if let Some(val) = child.get("input_responses") {
                    let raw = val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'input_responses' property on tool '{}' must be a string",
                            tool_name
                        ))
                    })?;
                    existing.input_responses =
                        InputResponsesMode::parse_kdl(raw).map_err(PolicyError::KdlParse)?;
                    existing.input_responses_specified = true;
                }
                if let Some(tc) = child.children() {
                    if let Some(fs_node) = tc.get("filesystem")
                        && let Some(fs_children) = fs_node.children()
                    {
                        let over_fs = parse_tool_fs(fs_children)?;
                        if !existing.fs_explicit {
                            // Re-base inherited grants on the current
                            // (post-`when`) defaults so the override folds the
                            // same way as an inline tool block.
                            existing.fs = Some(tool_fs_base(&policy.fs, existing.fs.as_ref()));
                        }
                        existing.fs_explicit = true;
                        match &mut existing.fs {
                            Some(base_fs) => {
                                if over_fs.require_path.is_some() {
                                    base_fs.require_path = over_fs.require_path;
                                }
                                if over_fs.allow_specified {
                                    base_fs.allowed_paths = over_fs.allowed_paths.clone();
                                    base_fs.read_only_paths = over_fs.read_only_paths.clone();
                                    base_fs.read_write_paths = over_fs.read_write_paths.clone();
                                    base_fs.allow_specified = true;
                                }
                                for denied in &over_fs.denied_paths {
                                    if !base_fs.denied_paths.contains(denied) {
                                        base_fs.denied_paths.push(denied.clone());
                                    }
                                }
                                base_fs
                                    .allowed_paths
                                    .retain(|p| !base_fs.denied_paths.contains(p));
                                base_fs
                                    .read_only_paths
                                    .retain(|p| !base_fs.denied_paths.contains(p));
                                base_fs
                                    .read_write_paths
                                    .retain(|p| !base_fs.denied_paths.contains(p));
                            }
                            None => existing.fs = Some(over_fs),
                        }
                    }
                    if let Some(sc_node) = tc.get("syscalls")
                        && let Some(sc_children) = sc_node.children()
                    {
                        let over_sc = parse_tool_syscalls(sc_children)?;
                        // Per-tool syscalls are not enforced; mark explicit so
                        // rematerialize keeps them and load-time validation
                        // rejects the policy like an inline declaration.
                        existing.syscalls_explicit = true;
                        match &mut existing.syscalls {
                            Some(base_sc) => {
                                if !over_sc.allowed.is_empty() {
                                    base_sc.allowed = over_sc.allowed.clone();
                                }
                                for denied in &over_sc.denied {
                                    if !base_sc.denied.contains(denied) {
                                        base_sc.denied.push(denied.clone());
                                    }
                                }
                                base_sc.allowed.retain(|s| !base_sc.denied.contains(s));
                            }
                            None => existing.syscalls = Some(over_sc),
                        }
                    }
                    if let Some(net_node) = tc.get("network")
                        && let Some(net_children) = net_node.children()
                    {
                        let over_net = parse_tool_network(net_children)?;
                        if !existing.network_explicit {
                            existing.network = Some(tool_network_base(
                                &policy.network,
                                existing.network.as_ref(),
                            ));
                        }
                        existing.network_explicit = true;
                        match &mut existing.network {
                            Some(base_net) => {
                                if over_net.allow_specified {
                                    base_net.allowed_hosts = over_net.allowed_hosts.clone();
                                    base_net.allow_specified = true;
                                }
                                for denied in &over_net.denied_hosts {
                                    if !base_net.denied_hosts.contains(denied) {
                                        base_net.denied_hosts.push(denied.clone());
                                    }
                                }
                                base_net
                                    .allowed_hosts
                                    .retain(|h| !base_net.denied_hosts.contains(h));
                            }
                            None => existing.network = Some(over_net),
                        }
                    }
                    if let Some(proc_node) = tc.get("process") {
                        existing.process_exec_allowed = parse_process_exec_allowed(proc_node)?;
                        existing.process_explicit = true;
                    }
                    // Per-tool environment is not enforced; flag it so
                    // load-time validation rejects the policy like an
                    // inline declaration.
                    if tc.get("environment").is_some() {
                        existing.environment_explicit = true;
                    }
                }
            } else {
                let defaults_layer = defaults_to_layer(&Defaults {
                    fs: policy.fs.clone(),
                    syscalls: policy.syscalls.clone(),
                    network: policy.network.clone(),
                    environment: EnvironmentPolicy::default(),
                });
                let mut dummy_doc = KdlDocument::new();
                let mut s_node = kdl::KdlNode::new("server");
                if let Some(ref s) = server_name {
                    s_node.push(kdl::KdlValue::String(s.clone()));
                }
                let mut s_children = KdlDocument::new();
                if let Some(server_defaults) = children.get("server-defaults") {
                    s_children.nodes_mut().push(server_defaults.clone());
                }
                s_children.nodes_mut().push(child.clone());
                s_node.set_children(s_children);
                dummy_doc.nodes_mut().push(s_node);
                let new_tools = parse_servers(&dummy_doc, &defaults_layer, profiles, base_dir)?;
                for t in new_tools {
                    policy.tools.push(t);
                }
            }
        }
    }

    // hash_entries overrides
    let hash_overrides = parse_server_hashes(doc)?;
    for entry in hash_overrides {
        if let Some(existing) = policy.hash_entries.iter_mut().find(|e| {
            e.server_name == entry.server_name
                && e.hash_type == entry.hash_type
                && e.target == entry.target
        }) {
            *existing = entry;
        } else {
            policy.hash_entries.push(entry);
        }
    }

    // tools_list_hashes overrides
    let tl_overrides = parse_tools_list_hashes(doc)?;
    for entry in tl_overrides {
        if let Some(existing) = policy
            .tools_list_hashes
            .iter_mut()
            .find(|e| e.server_name == entry.server_name)
        {
            *existing = entry;
        } else {
            policy.tools_list_hashes.push(entry);
        }
    }

    Ok(())
}

/// Build a tool's filesystem policy from the current global defaults,
/// preserving denied paths already accumulated on the tool.
pub(crate) fn tool_fs_base(
    global_fs: &super::FsPolicy,
    existing: Option<&super::FsToolPolicy>,
) -> super::FsToolPolicy {
    let mut denied = global_fs.denied_paths.clone();
    if let Some(cur) = existing {
        for d in &cur.denied_paths {
            if !denied.contains(d) {
                denied.push(d.clone());
            }
        }
    }
    let mut fs = super::FsToolPolicy {
        allowed_paths: global_fs
            .read_only
            .iter()
            .chain(global_fs.read_write.iter())
            .cloned()
            .collect(),
        read_only_paths: global_fs.read_only.clone(),
        read_write_paths: global_fs.read_write.clone(),
        denied_paths: denied,
        allow_specified: global_fs.allow_specified,
        require_path: None,
    };
    fs.allowed_paths.retain(|p| !fs.denied_paths.contains(p));
    fs.read_only_paths.retain(|p| !fs.denied_paths.contains(p));
    fs.read_write_paths.retain(|p| !fs.denied_paths.contains(p));
    fs
}

/// Build a tool's network policy from the current global defaults using flat
/// layer-merge semantics (`allow_specified` only when defaults declared allow
/// rules), preserving denied hosts already accumulated on the tool.
pub(crate) fn tool_network_base(
    global_net: &super::NetworkPolicy,
    existing: Option<&super::ToolNetworkPolicy>,
) -> super::ToolNetworkPolicy {
    let mut denied = global_net.outbound.denied_hosts.clone();
    if let Some(cur) = existing {
        for d in &cur.denied_hosts {
            if !denied.contains(d) {
                denied.push(d.clone());
            }
        }
    }
    let mut network = super::ToolNetworkPolicy {
        allowed_hosts: global_net.outbound.allowed.clone(),
        denied_hosts: denied,
        allow_specified: !global_net.outbound.allowed.is_empty(),
    };
    crate::policy::apply_tool_network_deny_precedence(&mut network);
    network
}

/// Rebuild per-tool grants from the final global defaults unless the tool
/// declared its own filesystem/network/syscall block.
pub(crate) fn rematerialize_inherited_defaults(policy: &mut Policy) {
    crate::policy::apply_outbound_deny_precedence(&mut policy.network.outbound);
    let global_fs = policy.fs.clone();
    let global_net = policy.network.clone();
    let global_sc = policy.syscalls.clone();

    for tool in &mut policy.tools {
        if !tool.fs_explicit {
            let fs = tool_fs_base(&global_fs, tool.fs.as_ref());
            let keep = fs.allow_specified
                || !fs.allowed_paths.is_empty()
                || !fs.denied_paths.is_empty()
                || !fs.read_only_paths.is_empty()
                || !fs.read_write_paths.is_empty();
            tool.fs = keep.then_some(fs);
        } else if let Some(ref mut fs) = tool.fs {
            for d in &global_fs.denied_paths {
                if !fs.denied_paths.contains(d) {
                    fs.denied_paths.push(d.clone());
                }
            }
            fs.allowed_paths.retain(|p| !fs.denied_paths.contains(p));
            fs.read_only_paths.retain(|p| !fs.denied_paths.contains(p));
            fs.read_write_paths.retain(|p| !fs.denied_paths.contains(p));
        }

        if !tool.network_explicit {
            let mut network = tool_network_base(&global_net, tool.network.as_ref());
            // deny_all_others with an empty allow list is still a closed
            // allow-list: every host must be rejected.
            network.allow_specified |= global_net.outbound.deny_all_others;
            let keep = network.allow_specified
                || !network.allowed_hosts.is_empty()
                || !network.denied_hosts.is_empty();
            tool.network = keep.then_some(network);
        } else if let Some(ref mut network) = tool.network {
            for d in &global_net.outbound.denied_hosts {
                if !network.denied_hosts.contains(d) {
                    network.denied_hosts.push(d.clone());
                }
            }
            crate::policy::apply_tool_network_deny_precedence(network);
        }

        if !tool.syscalls_explicit {
            let mut denied = Vec::new();
            if let Some(ref existing) = tool.syscalls {
                denied = existing.denied.clone();
            }
            let allowed: Vec<String> = global_sc
                .allowed
                .iter()
                .filter(|s| !denied.contains(s))
                .cloned()
                .collect();
            let keep = !allowed.is_empty() || !denied.is_empty();
            tool.syscalls = keep.then_some(super::ToolSyscallPolicy { allowed, denied });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::kdl_loader::{load_kdl_policy, load_kdl_policy_with_env, parse_kdl_policy};

    #[test]
    fn test_load_example_kdl_file() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        let policy = load_kdl_policy(&path).expect("Failed to load policy.example.kdl");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.tools.len(), 3);
        assert!(policy.tools[0].allowed);
        assert_eq!(policy.tools[0].name, "read_file");
        assert_eq!(policy.tools[0].side_effect.as_deref(), Some("read_only"));
        assert!(!policy.tools[2].allowed);
        assert_eq!(policy.tools[2].name, "exec_shell");
        assert!(policy.network.outbound.deny_all_others);
        assert_eq!(policy.fs.read_only.len(), 2); // /usr/lib/** and /etc/ssl/certs/**
        assert_eq!(policy.fs.read_write.len(), 1); // /workspace/**
        assert_eq!(policy.syscalls.allowed.len(), 20);
        assert!(policy.syscalls.allowed.iter().any(|s| s == "execve"));
        assert!(policy.syscalls.allowed.iter().any(|s| s == "execveat"));
    }

    // ================================================================
    // extends / include / when / circular-reference tests
    // ================================================================

    /// Helper: create a temp directory with a unique name for test isolation.
    fn make_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("mcp_writ_test").join(format!(
            "{}_{}",
            label,
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_load_rejects_per_tool_syscalls() {
        let dir = make_test_dir("tool_syscalls_rejected");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "svc" {
                    tool "x" {
                        syscalls {
                            allow "read"
                        }
                    }
                }
            "#,
        )
        .unwrap();
        let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
        assert!(err.to_string().contains("per-tool syscalls"), "got: {err}");
    }

    // ── extends ─────────────────────────────────────────────────

    #[test]
    fn test_extends_basic_inheritance() {
        let dir = make_test_dir("extends_basic");
        // base policy
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                defaults {
                    filesystem {
                        allow "/base/ro"
                    }
                }
            "#,
        )
        .unwrap();
        // child policy
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
                defaults {
                    filesystem {
                        allow "/child/rw" mode="write"
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        // child inherits base read-only
        assert!(policy.fs.read_only.contains(&"/base/ro".to_string()));
        // child has its own read-write
        assert!(policy.fs.read_write.contains(&"/child/rw".to_string()));
    }

    #[test]
    fn test_extends_child_overrides_parent() {
        let dir = make_test_dir("extends_override");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                logging level="debug"
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
                logging level="warn"
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        assert_eq!(policy.logging.level, "warn");
    }

    #[test]
    fn test_extends_process_exec_merges_and_conflicts_with_side_effect() {
        let dir = make_test_dir("extends_process");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                server "s" {
                    tool "t" side_effect="read_only"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
                server "s" {
                    tool "t" {
                        process {
                            allow "echo"
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let combined = parse_kdl_policy(
            r#"
                policy version=1
                server "s" {
                    tool "t" side_effect="read_only" {
                        process {
                            allow "echo"
                        }
                    }
                }
            "#,
        )
        .unwrap();
        assert!(
            super::super::validator::validate_policy(&combined).is_err(),
            "same-file read_only + process allow must fail"
        );
        let err = load_kdl_policy(&dir.join("child.kdl")).unwrap_err();
        assert!(
            err.to_string().contains("process execution")
                || err.to_string().contains("side_effect"),
            "extends must preserve process grant and fail the same check, got {err}"
        );
    }

    #[test]
    fn test_include_process_exec_merges_and_conflicts_with_side_effect() {
        let dir = make_test_dir("include_process");
        std::fs::write(
            dir.join("extra.kdl"),
            r#"
                policy version=1
                server "s" {
                    tool "t" {
                        process {
                            allow "echo"
                        }
                    }
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("main.kdl"),
            r#"
                include "extra.kdl"
                policy version=1
                server "s" {
                    tool "t" side_effect="read_only"
                }
            "#,
        )
        .unwrap();
        let err = load_kdl_policy(&dir.join("main.kdl")).unwrap_err();
        assert!(
            err.to_string().contains("process execution")
                || err.to_string().contains("side_effect"),
            "include must preserve process grant and fail the same check, got {err}"
        );
    }

    #[test]
    fn test_extends_multi_level() {
        let dir = make_test_dir("extends_multi");
        // grandparent
        std::fs::write(
            dir.join("grandparent.kdl"),
            r#"
                policy version=1
                defaults {
                    filesystem {
                        allow "/gp"
                    }
                }
            "#,
        )
        .unwrap();
        // parent extends grandparent
        std::fs::write(
            dir.join("parent.kdl"),
            r#"
                extends "grandparent.kdl"
                policy version=1
                defaults {
                    filesystem {
                        allow "/parent" mode="write"
                    }
                }
            "#,
        )
        .unwrap();
        // child extends parent
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "parent.kdl"
                policy version=1
                logging level="error"
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        // grandparent's read-only inherited through parent
        assert!(policy.fs.read_only.contains(&"/gp".to_string()));
        // parent's read-write inherited
        assert!(policy.fs.read_write.contains(&"/parent".to_string()));
        assert_eq!(policy.logging.level, "error");
    }

    #[test]
    fn test_extends_tools_merged() {
        let dir = make_test_dir("extends_tools");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "read_file"
                    tool "exec" deny=#true
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
                server "s1" {
                    tool "exec"
                    tool "write_file"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        // read_file from base preserved
        let rf = policy.tools.iter().find(|t| t.name == "read_file").unwrap();
        assert!(rf.allowed);
        // exec in base had deny=#true; child specified tool "exec" without deny
        // Deny is sticky across extends: exec remains denied!
        let exec = policy.tools.iter().find(|t| t.name == "exec").unwrap();
        assert!(!exec.allowed);
        // write_file added by child
        let wf = policy
            .tools
            .iter()
            .find(|t| t.name == "write_file")
            .unwrap();
        assert!(wf.allowed);
    }

    // ── include ─────────────────────────────────────────────────

    #[test]
    fn test_include_basic() {
        let dir = make_test_dir("include_basic");
        std::fs::write(
            dir.join("extra.kdl"),
            r#"
                policy version=1
                server "extra" {
                    tool "extra_tool"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("main.kdl"),
            r#"
                include "extra.kdl"
                policy version=1
                server "main" {
                    tool "main_tool"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
        assert!(policy.tools.iter().any(|t| t.name == "extra_tool"));
        assert!(policy.tools.iter().any(|t| t.name == "main_tool"));
    }

    #[test]
    fn test_include_multiple_files() {
        let dir = make_test_dir("include_multi");
        std::fs::write(
            dir.join("a.kdl"),
            r#"
                policy version=1
                server "sa" {
                    tool "tool_a"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("b.kdl"),
            r#"
                policy version=1
                server "sb" {
                    tool "tool_b"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("main.kdl"),
            r#"
                include "a.kdl"
                include "b.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
        assert!(policy.tools.iter().any(|t| t.name == "tool_a"));
        assert!(policy.tools.iter().any(|t| t.name == "tool_b"));
    }

    #[test]
    fn test_include_subdirectory_relative_path() {
        let dir = make_test_dir("include_subdir");
        let sub = dir.join("rules");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(
            sub.join("extra.kdl"),
            r#"
                policy version=1
                server "sub" {
                    tool "sub_tool"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("main.kdl"),
            r#"
                include "rules/extra.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
        assert!(policy.tools.iter().any(|t| t.name == "sub_tool"));
    }

    // ── when (conditional overrides) ────────────────────────────

    #[test]
    fn test_when_matching_env() {
        let dir = make_test_dir("when_match");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                logging level="info"
                when environment="production" {
                    logging level="error"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        assert_eq!(policy.logging.level, "error");
    }

    #[test]
    fn test_when_non_matching_env() {
        let dir = make_test_dir("when_nomatch");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                logging level="info"
                when environment="production" {
                    logging level="error"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
        assert_eq!(policy.logging.level, "info");
    }

    #[test]
    fn test_when_unset_env_does_not_match() {
        let dir = make_test_dir("when_unset");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                logging level="info"
                when environment="production" {
                    logging level="error"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "").unwrap();
        assert_eq!(policy.logging.level, "info");
    }

    #[test]
    fn test_when_overrides_tools() {
        let dir = make_test_dir("when_tools");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "exec"
                }
                when environment="production" {
                    server "s1" {
                        tool "exec" deny=#true
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        let exec = policy.tools.iter().find(|t| t.name == "exec").unwrap();
        assert!(!exec.allowed);
    }

    #[test]
    fn test_when_overrides_tool_process() {
        let dir = make_test_dir("when_tool_process");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "exec" side_effect="execute" {
                        process {
                            deny-all #true
                        }
                    }
                }
                when environment="production" {
                    server "s1" {
                        tool "exec" {
                            process {
                                deny-all #false
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        let exec = policy.tools.iter().find(|t| t.name == "exec").unwrap();
        assert!(exec.process_explicit);
        assert!(exec.process_exec_allowed);
    }

    #[test]
    fn test_when_process_deny_all_revokes_exec() {
        let dir = make_test_dir("when_process_revoke");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "exec" side_effect="execute" {
                        process {
                            deny-all #false
                        }
                    }
                }
                when environment="production" {
                    server "s1" {
                        tool "exec" {
                            process {
                                deny-all #true
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        let exec = policy.tools.iter().find(|t| t.name == "exec").unwrap();
        assert!(exec.process_explicit);
        assert!(!exec.process_exec_allowed);
    }

    #[test]
    fn test_when_process_allow_conflicts_with_read_only() {
        let dir = make_test_dir("when_process_conflict");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "read" side_effect="read_only"
                }
                when environment="production" {
                    server "s1" {
                        tool "read" {
                            process {
                                deny-all #false
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
        assert!(
            err.to_string().contains("process execution"),
            "expected side_effect conflict, got: {err}"
        );
    }

    #[test]
    fn test_when_overrides_defaults() {
        let dir = make_test_dir("when_defaults");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                defaults {
                    filesystem {
                        allow "/dev/data" mode="write"
                    }
                }
                when environment="lockdown" {
                    defaults {
                        filesystem {
                            allow "/dev/data"
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "lockdown").unwrap();
        assert!(policy.fs.read_only.contains(&"/dev/data".to_string()));
    }

    #[test]
    fn test_when_rematerializes_inherited_tool_fs() {
        let dir = make_test_dir("when_remat_fs");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                defaults {
                    filesystem {
                        allow "/dev/data" mode="write"
                    }
                }
                server "svc" {
                    tool "fetch"
                }
                when environment="prod" {
                    defaults {
                        filesystem {
                            allow "/prod/data" mode="write"
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "prod").unwrap();
        let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
        let fs = fetch.fs.as_ref().unwrap();
        assert!(fs.read_write_paths.contains(&"/prod/data".to_string()));
        assert!(!fs.read_write_paths.iter().any(|p| p == "/dev/data"));
    }

    #[test]
    fn test_rematerialize_deny_all_sets_allow_specified() {
        let dir = make_test_dir("remat_deny_all_net");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                defaults {
                    network {
                        deny host="*"
                    }
                }
                server "svc" {
                    tool "fetch"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
        let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
        let net = fetch.network.as_ref().unwrap();
        assert!(net.allow_specified);
        assert!(net.allowed_hosts.is_empty());
    }

    #[test]
    fn test_when_network_deny_preserves_inbound() {
        let dir = make_test_dir("when_inbound_keep");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                defaults {
                    network {
                        inbound allow=#true
                    }
                }
                when environment="prod" {
                    defaults {
                        network {
                            deny host="evil.example.com"
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "prod").unwrap();
        assert!(policy.network.inbound.allow_listen);
        assert!(
            policy
                .network
                .outbound
                .denied_hosts
                .contains(&"evil.example.com".to_string())
        );
    }

    #[test]
    fn test_when_tool_network_allow_is_preserved() {
        let dir = make_test_dir("when_tool_net_allow");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "fetch"
                }
                when environment="production" {
                    server "s1" {
                        tool "fetch" {
                            network {
                                allow host="prod.example.com"
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
        assert!(fetch.network_explicit);
        let net = fetch.network.as_ref().unwrap();
        assert_eq!(net.allowed_hosts, vec!["prod.example.com"]);
        assert!(net.allow_specified);
    }

    #[test]
    fn test_when_tool_network_rebases_on_updated_defaults() {
        // Same as writing the tool block inline against the post-`when`
        // defaults: a deny-only override declares no allow list, so the tool
        // must not inherit the closed allow-list rematerialized earlier.
        let dir = make_test_dir("when_tool_net_rebase");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                defaults {
                    network {
                        deny host="g1.example.com"
                    }
                }
                server "s1" {
                    tool "fetch"
                }
                when environment="production" {
                    defaults {
                        network {
                            deny host="g2.example.com"
                        }
                    }
                    server "s1" {
                        tool "fetch" {
                            network {
                                deny host="tool.example.com"
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
        let net = fetch.network.as_ref().unwrap();
        assert!(!net.allow_specified);
        assert!(net.allowed_hosts.is_empty());
        for host in ["g1.example.com", "g2.example.com", "tool.example.com"] {
            assert!(
                net.denied_hosts.contains(&host.to_string()),
                "missing {host}"
            );
        }
    }

    #[test]
    fn test_when_tool_network_deny_only_matches_inline_semantics() {
        // A deny-only tool network block declares no allow list — same result
        // as writing the block inline (open except denied hosts).
        let dir = make_test_dir("when_tool_net_deny_only");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "fetch"
                }
                when environment="production" {
                    server "s1" {
                        tool "fetch" {
                            network {
                                deny host="evil.example.com"
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
        let net = fetch.network.as_ref().unwrap();
        assert!(!net.allow_specified);
        assert!(net.allowed_hosts.is_empty());
        assert_eq!(net.denied_hosts, vec!["evil.example.com"]);
    }

    #[test]
    fn test_when_tool_fs_rebases_on_updated_defaults() {
        let dir = make_test_dir("when_tool_fs_rebase");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                defaults {
                    filesystem {
                        allow "/a/data"
                    }
                }
                server "s1" {
                    tool "fetch"
                }
                when environment="production" {
                    defaults {
                        filesystem {
                            allow "/b/data"
                        }
                    }
                    server "s1" {
                        tool "fetch" {
                            filesystem {
                                deny "/b/secret"
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
        let fs = fetch.fs.as_ref().unwrap();
        assert_eq!(fs.read_only_paths, vec!["/b/data"]);
        assert!(fs.denied_paths.contains(&"/b/secret".to_string()));
    }

    #[test]
    fn test_when_tool_syscalls_is_validation_error() {
        // Per-tool syscalls are unenforceable; inside `when` they must surface
        // the same load error as an inline declaration, not be dropped silently.
        let dir = make_test_dir("when_tool_syscalls");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "fetch"
                }
                when environment="production" {
                    server "s1" {
                        tool "fetch" {
                            syscalls {
                                allow "read"
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
        assert!(err.to_string().contains("per-tool syscalls"), "got: {err}");

        // A non-matching environment never applies the block.
        load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    }

    #[test]
    fn test_when_multiple_blocks_only_matching_applied() {
        let dir = make_test_dir("when_multi");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                logging level="info"
                when environment="staging" {
                    logging level="debug"
                }
                when environment="production" {
                    logging level="error"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "staging").unwrap();
        assert_eq!(policy.logging.level, "debug");
    }

    // ── environment (defaults.environment) ─────────────────────

    #[test]
    fn test_environment_absent_everywhere_stays_unrestricted() {
        let dir = make_test_dir("env_absent");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
            "#,
        )
        .unwrap();
        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        assert!(!policy.environment.restrict);
        assert!(policy.environment.allowed.is_empty());
    }

    #[test]
    fn test_extends_inherits_base_environment() {
        let dir = make_test_dir("extends_env_inherit");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                defaults {
                    environment {
                        allow "MEMORY_FILE_PATH"
                    }
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
            "#,
        )
        .unwrap();
        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        assert!(policy.environment.restrict);
        assert_eq!(policy.environment.allowed, vec!["MEMORY_FILE_PATH"]);
    }

    #[test]
    fn test_extends_environment_overlay_replaces_nonempty() {
        let dir = make_test_dir("extends_env_replace");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                defaults {
                    environment {
                        allow "A" "B"
                    }
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
                defaults {
                    environment {
                        allow "C"
                    }
                }
            "#,
        )
        .unwrap();
        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        assert!(policy.environment.restrict);
        assert_eq!(policy.environment.allowed, vec!["C"]);
    }

    #[test]
    fn test_extends_environment_empty_overlay_keeps_base_list() {
        // Same rule as syscalls: an empty overlay does not replace the
        // base's allow list — there is no way to un-restrict via extends.
        let dir = make_test_dir("extends_env_empty");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                defaults {
                    environment {
                        allow "A"
                    }
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
                defaults {
                    environment {
                    }
                }
            "#,
        )
        .unwrap();
        let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
        assert!(policy.environment.restrict);
        assert_eq!(policy.environment.allowed, vec!["A"]);
    }

    #[test]
    fn test_include_environment_merges() {
        let dir = make_test_dir("include_env");
        std::fs::write(
            dir.join("extra.kdl"),
            r#"
                policy version=1
                defaults {
                    environment {
                        allow "INCLUDED_VAR"
                    }
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                include "extra.kdl"
                policy version=1
            "#,
        )
        .unwrap();
        let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
        assert!(policy.environment.restrict);
        assert_eq!(policy.environment.allowed, vec!["INCLUDED_VAR"]);
    }

    #[test]
    fn test_when_environment_replaces_allow_list() {
        let dir = make_test_dir("when_env_replace");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                defaults {
                    environment {
                        allow "A" "B"
                    }
                }
                when environment="production" {
                    defaults {
                        environment {
                            allow "C"
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        assert!(policy.environment.restrict);
        assert_eq!(policy.environment.allowed, vec!["C"]);

        // A non-matching environment never applies the block.
        let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
        assert_eq!(dev.environment.allowed, vec!["A", "B"]);
    }

    #[test]
    fn test_when_environment_enables_restriction() {
        let dir = make_test_dir("when_env_enable");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                when environment="production" {
                    defaults {
                        environment {
                            allow "A"
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let prod = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
        assert!(prod.environment.restrict);
        assert_eq!(prod.environment.allowed, vec!["A"]);

        let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
        assert!(!dev.environment.restrict);
    }

    #[test]
    fn test_when_tool_environment_is_validation_error() {
        // Same fail-closed rule as per-tool syscalls: `environment` under a
        // tool inside `when` must surface the load error, not be dropped.
        let dir = make_test_dir("when_tool_env");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "fetch"
                }
                when environment="production" {
                    server "s1" {
                        tool "fetch" {
                            environment {
                                allow "SECRET"
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();

        let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
        assert!(
            err.to_string().contains("per-tool environment"),
            "got: {err}"
        );

        load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    }

    #[test]
    fn test_profile_environment_is_rejected() {
        let dir = make_test_dir("profile_env");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                profile "p" {
                    environment {
                        allow "SECRET"
                    }
                }
                server "s1" {
                    tool "fetch" profile="p"
                }
            "#,
        )
        .unwrap();
        let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
        assert!(
            err.to_string().contains("per-tool environment"),
            "got: {err}"
        );
    }

    #[test]
    fn test_server_defaults_environment_is_rejected() {
        let dir = make_test_dir("server_defaults_env");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    server-defaults {
                        environment {
                            allow "SECRET"
                        }
                    }
                    tool "fetch"
                }
            "#,
        )
        .unwrap();
        let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
        assert!(
            err.to_string().contains("per-tool environment"),
            "got: {err}"
        );
    }

    #[test]
    fn test_when_server_environment_is_rejected() {
        // `environment` directly under a `server` node inside `when` fails to
        // load: `parse_server_hashes` scans the `when` doc's server children
        // and rejects `environment` outright before validation runs.
        let dir = make_test_dir("when_server_env");
        std::fs::write(
            dir.join("policy.kdl"),
            r#"
                policy version=1
                server "s1" {
                    tool "fetch"
                }
                when environment="production" {
                    server "s1" {
                        environment {
                            allow "SECRET"
                        }
                        tool "fetch" {
                            filesystem {
                                allow none=#true
                                require-path #false
                            }
                        }
                    }
                }
            "#,
        )
        .unwrap();
        let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
        assert!(
            err.to_string().contains("environment"),
            "server-level environment in when must fail to load: {err}"
        );
        load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    }

    // ── circular reference detection ────────────────────────────

    #[test]
    fn test_circular_extends_detected() {
        let dir = make_test_dir("circ_extends");
        std::fs::write(
            dir.join("a.kdl"),
            r#"
                extends "b.kdl"
                policy version=1
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("b.kdl"),
            r#"
                extends "a.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let err = load_kdl_policy(&dir.join("a.kdl")).unwrap_err();
        assert!(err.to_string().contains("circular reference"));
    }

    #[test]
    fn test_circular_include_detected() {
        let dir = make_test_dir("circ_include");
        std::fs::write(
            dir.join("a.kdl"),
            r#"
                include "b.kdl"
                policy version=1
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("b.kdl"),
            r#"
                include "a.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let err = load_kdl_policy(&dir.join("a.kdl")).unwrap_err();
        assert!(err.to_string().contains("circular reference"));
    }

    #[test]
    fn test_self_extends_detected() {
        let dir = make_test_dir("self_extends");
        std::fs::write(
            dir.join("self.kdl"),
            r#"
                extends "self.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let err = load_kdl_policy(&dir.join("self.kdl")).unwrap_err();
        assert!(err.to_string().contains("circular reference"));
    }

    #[test]
    fn test_three_way_circular_extends() {
        let dir = make_test_dir("circ3");
        std::fs::write(
            dir.join("a.kdl"),
            r#"
                extends "b.kdl"
                policy version=1
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("b.kdl"),
            r#"
                extends "c.kdl"
                policy version=1
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("c.kdl"),
            r#"
                extends "a.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let err = load_kdl_policy(&dir.join("a.kdl")).unwrap_err();
        assert!(err.to_string().contains("circular reference"));
    }

    // ── combined extends + include ──────────────────────────────

    #[test]
    fn test_extends_with_include() {
        let dir = make_test_dir("extends_include");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                defaults {
                    filesystem {
                        allow "/base"
                    }
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("extra.kdl"),
            r#"
                policy version=1
                server "extra" {
                    tool "extra_tool"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("main.kdl"),
            r#"
                extends "base.kdl"
                include "extra.kdl"
                policy version=1
                server "main" {
                    tool "main_tool"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
        assert!(policy.fs.read_only.contains(&"/base".to_string()));
        assert!(policy.tools.iter().any(|t| t.name == "extra_tool"));
        assert!(policy.tools.iter().any(|t| t.name == "main_tool"));
    }

    // ── extends + when combined ─────────────────────────────────

    #[test]
    fn test_extends_plus_when() {
        let dir = make_test_dir("extends_when");
        std::fs::write(
            dir.join("base.kdl"),
            r#"
                policy version=1
                logging level="info"
                server "s1" {
                    tool "exec"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "base.kdl"
                policy version=1
                when environment="production" {
                    logging level="error"
                    server "s1" {
                        tool "exec" deny=#true
                    }
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&dir.join("child.kdl"), "production").unwrap();
        assert_eq!(policy.logging.level, "error");
        let exec = policy.tools.iter().find(|t| t.name == "exec").unwrap();
        assert!(!exec.allowed);
    }

    // ── edge: missing extends file ──────────────────────────────

    #[test]
    fn test_extends_missing_file_error() {
        let dir = make_test_dir("extends_missing");
        std::fs::write(
            dir.join("child.kdl"),
            r#"
                extends "nonexistent.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let err = load_kdl_policy(&dir.join("child.kdl")).unwrap_err();
        assert!(matches!(err, PolicyError::FileRead(_)));
    }

    // ── edge: sibling includes should not false-trigger cycle ───

    #[test]
    fn test_sibling_includes_no_false_cycle() {
        let dir = make_test_dir("sibling_inc");
        // shared.kdl is included by both a.kdl and b.kdl
        std::fs::write(
            dir.join("shared.kdl"),
            r#"
                policy version=1
                server "shared" {
                    tool "shared_tool"
                }
            "#,
        )
        .unwrap();
        std::fs::write(
            dir.join("a.kdl"),
            r#"
                include "shared.kdl"
                policy version=1
                server "a" {
                    tool "tool_a"
                }
            "#,
        )
        .unwrap();
        // main includes both a.kdl; a.kdl includes shared.kdl
        // This should NOT trigger a cycle because we remove from visited after processing
        std::fs::write(
            dir.join("main.kdl"),
            r#"
                include "a.kdl"
                include "shared.kdl"
                policy version=1
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
        assert!(policy.tools.iter().any(|t| t.name == "shared_tool"));
        assert!(policy.tools.iter().any(|t| t.name == "tool_a"));
    }

    // ── edge: no extends/include is just normal parse ───────────

    #[test]
    fn test_no_extends_no_include_normal_parse() {
        let dir = make_test_dir("no_ext_inc");
        std::fs::write(
            dir.join("simple.kdl"),
            r#"
                policy version=1
                logging level="debug"
                server "s1" {
                    tool "read"
                }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&dir.join("simple.kdl")).unwrap();
        assert_eq!(policy.logging.level, "debug");
        assert_eq!(policy.tools.len(), 1);
        assert_eq!(policy.tools[0].name, "read");
    }

    #[test]
    fn test_r04_when_does_not_un_deny_tool() {
        let tmp = std::env::temp_dir().join("test_r04_when");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let kdl_file = tmp.join("policy.kdl");
        std::fs::write(
            &kdl_file,
            r#"
            policy version=1
            server "test" {
                tool "exec" deny=#true args_schema="{}"
            }
            when environment="prod" {
                server "test" {
                    tool "exec" side_effect="read_only"
                }
            }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy_with_env(&kdl_file, "prod").unwrap();
        let exec_tool = policy.tools.iter().find(|t| t.name == "exec").unwrap();
        // deny must remain sticky (allowed must stay false)
        assert!(!exec_tool.allowed);
        // args_schema must not be wiped out
        assert_eq!(exec_tool.args_schema.as_deref(), Some("{}"));
        // side_effect was updated
        assert_eq!(exec_tool.side_effect.as_deref(), Some("read_only"));

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_r04_include_retains_logging_and_deputy() {
        let tmp = std::env::temp_dir().join("test_r04_inc");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let inc_file = tmp.join("extra.kdl");
        std::fs::write(
            &inc_file,
            r#"
            policy version=1
            logging level="error"
            confused_deputy_protection #true
            "#,
        )
        .unwrap();

        let main_file = tmp.join("main.kdl");
        std::fs::write(
            &main_file,
            r#"
            policy version=1
            include "extra.kdl"
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&main_file).unwrap();
        assert_eq!(policy.logging.level, "error");
        assert!(policy.confused_deputy_protection);

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_include_retains_trajectory() {
        let tmp = std::env::temp_dir().join("test_r04_inc_traj");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let inc_file = tmp.join("extra.kdl");
        std::fs::write(
            &inc_file,
            r#"
            policy version=1
            trajectory #true {
                after side_effect="read_only" deny-next="network"
            }
            "#,
        )
        .unwrap();

        let main_file = tmp.join("main.kdl");
        std::fs::write(
            &main_file,
            r#"
            policy version=1
            include "extra.kdl"
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&main_file).unwrap();
        assert!(policy.trajectory);
        assert_eq!(policy.trajectory_rules.len(), 1);
        assert_eq!(
            policy.trajectory_rules[0].after_side_effect,
            crate::policy::SideEffect::ReadOnly
        );

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_cross_file_profile_inheritance() {
        let tmp = std::env::temp_dir().join("test_profile_sharing");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();

        let base_file = tmp.join("base.kdl");
        std::fs::write(
            &base_file,
            r#"
            policy version=1
            profile "web" {
                network {
                    allow host="api.example.com"
                }
            }
            "#,
        )
        .unwrap();

        let child_file = tmp.join("child.kdl");
        std::fs::write(
            &child_file,
            r#"
            policy version=1
            extends "base.kdl"
            server "test" {
                tool "fetch" profile="web"
            }
            "#,
        )
        .unwrap();

        let policy = load_kdl_policy(&child_file).unwrap();
        let tool = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
        let net = tool.network.as_ref().unwrap();
        assert_eq!(net.allowed_hosts, vec!["api.example.com"]);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
