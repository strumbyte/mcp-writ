//! Overlay-merge semantics for extends/include/when: how an overlay document
//! field set merges onto a base Policy, and how the final per-tool grants are
//! rematerialized from the merged defaults.

use std::collections::HashMap;
use std::path::Path;

use kdl::KdlDocument;

use crate::error::PolicyError;
use crate::policy::kdl_parse::{
    Defaults, defaults_to_layer, parse_deputy_node, parse_environment_node, parse_fs_allows,
    parse_logging_fail_closed, parse_network_rules, parse_process_exec_allowed,
    parse_server_hashes, parse_server_mcp_rules, parse_servers, parse_syscall_allows,
    parse_tool_fs, parse_tool_network, parse_tool_syscalls, parse_tools_list_hashes,
    parse_trajectory, resolve_tool_args_schema, unique_child, validate_logging_level,
    validate_tool_shape_v2,
};
use crate::policy::merge::PolicyLayer;
use crate::policy::{
    EnvironmentPolicy, FsPolicy, FsToolPolicy, InputResponsesMode, NetworkPolicy, Policy,
    ToolNetworkPolicy, ToolSyscallPolicy,
};

/// Merge `overlay` policy on top of `base` (in place).
///
/// - Scalar fields: overlay wins only if explicitly defined in doc
/// - Allow lists: overlay replaces if non-empty, else base is kept
///   (environment replaces whenever the overlay document declares the node,
///   even with an empty list)
/// - Deny lists: accumulated (union, sticky)
/// - Tools: overlay tool overrides specified fields; unspecified fields inherited; deny is sticky
pub(super) fn merge_into_policy(base: &mut Policy, overlay: &Policy, doc: &KdlDocument) {
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

    // environment: an `environment` node declared on the overlay's side —
    // in this document's `defaults` or resolved from one of its `when`
    // blocks — is authoritative: the allow list replaces the base's even
    // when empty. A restriction the overlay only inherited (restrict on,
    // nothing declared) still turns restriction on but follows the usual
    // non-empty-replaces rule. There is no way to un-restrict through an
    // overlay.
    if overlay.environment.restrict {
        base.environment.restrict = true;
    }
    if overlay.environment.declared || !overlay.environment.allowed.is_empty() {
        base.environment.allowed = overlay.environment.allowed.clone();
        base.environment.declared = true;
    }

    // network: overlay replaces if non-empty
    if !overlay.network.outbound.allowed.is_empty() {
        base.network.outbound.allowed = overlay.network.outbound.allowed.clone();
        base.network.outbound.allowed_port_qualified =
            overlay.network.outbound.allowed_port_qualified.clone();
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
            // `deputy` replaces whole — an overlay that omits it inherits
            // the base's block; `role="none"` is the explicit opt-out.
            if tool.deputy.is_some() {
                existing.deputy = tool.deputy.clone();
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

    // mcp rules: union per server. Atom-level overlaps across documents
    // resolve deny-first when the rules are normalised (`resolve_atoms`).
    for server_rules in &overlay.mcp_rules {
        if let Some(existing) = base
            .mcp_rules
            .iter_mut()
            .find(|s| s.server_name == server_rules.server_name)
        {
            existing.extend_rules(server_rules.rules().iter().cloned());
        } else {
            base.mcp_rules.push(server_rules.clone());
        }
    }
}

/// Evaluate `when environment="xxx" { ... }` blocks and apply matching overrides.
pub(super) fn apply_when_overrides(
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
    if let Some(defaults_node) = unique_child(doc, "defaults", "the override document")?
        && let Some(children) = defaults_node.children()
    {
        if let Some(fs_node) = unique_child(children, "filesystem", "'defaults'")?
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
        if let Some(sc_node) = unique_child(children, "syscalls", "'defaults'")?
            && let Some(sc_children) = sc_node.children()
        {
            let sc = parse_syscall_allows(sc_children)?;
            if !sc.allowed.is_empty() {
                policy.syscalls.allowed = sc.allowed;
            }
        }
        // Node presence in a matching `when` block enables restriction; the
        // declared `allow` list replaces the base's — including an empty one.
        if let Some(env_node) = unique_child(children, "environment", "'defaults'")? {
            policy.environment.restrict = true;
            policy.environment.declared = true;
            policy.environment.allowed = parse_environment_node(env_node)?;
        }
        if let Some(net_node) = unique_child(children, "network", "'defaults'")?
            && let Some(net_children) = net_node.children()
        {
            let net = parse_network_rules(net_children)?;
            if !net.outbound.allowed.is_empty() || !net.outbound.deny_all_others {
                policy.network.outbound.allowed = net.outbound.allowed;
                policy.network.outbound.allowed_port_qualified =
                    net.outbound.allowed_port_qualified;
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
        let server_ctx = format!("server '{}'", server_name.as_deref().unwrap_or("<unnamed>"));
        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

        // `environment` is launch-level (`defaults.environment`): inside a
        // `when` block's server-defaults it is only parsed for *new* tools —
        // for existing tools it would be silently dropped, so reject it.
        if unique_child(children, "server-defaults", &server_ctx)?
            .and_then(|sd| sd.children())
            .is_some_and(|sdc| sdc.get("environment").is_some())
        {
            return Err(PolicyError::KdlParse(
                "'environment' is only allowed under 'defaults' — it cannot appear in a server-defaults block inside 'when'".into(),
            ));
        }

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
            let tool_ctx = format!("tool '{tool_name}'");

            // `when` tool overrides obey the same closed v2 tool shape as
            // inline declarations; unknown members must not pass silently
            // here either (a misspelt `deputy` included).
            if policy.version >= 2 {
                validate_tool_shape_v2(child, &tool_name)?;
            }

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
                    if let Some(fs_node) = unique_child(tc, "filesystem", &tool_ctx)?
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
                    if let Some(sc_node) = unique_child(tc, "syscalls", &tool_ctx)?
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
                    if let Some(net_node) = unique_child(tc, "network", &tool_ctx)?
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
                    if let Some(proc_node) = unique_child(tc, "process", &tool_ctx)? {
                        existing.process_exec_allowed = parse_process_exec_allowed(proc_node)?;
                        existing.process_explicit = true;
                    }
                    // Per-tool environment is not enforced; flag it so
                    // load-time validation rejects the policy like an
                    // inline declaration.
                    if unique_child(tc, "environment", &tool_ctx)?.is_some() {
                        existing.environment_explicit = true;
                    }
                    // `deputy` replaces whole, same as include/extends —
                    // `role="none"` is the opt-out. Under v1 it would be
                    // dropped silently, so it is rejected outright.
                    if let Some(dep_node) = unique_child(tc, "deputy", &tool_ctx)? {
                        if policy.version < 2 {
                            return Err(PolicyError::KdlParse(format!(
                                "'deputy' on tool '{tool_name}' requires 'policy version=2'"
                            )));
                        }
                        existing.deputy = Some(parse_deputy_node(dep_node, &tool_name)?);
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
                if let Some(server_defaults) =
                    unique_child(children, "server-defaults", &server_ctx)?
                {
                    s_children.nodes_mut().push(server_defaults.clone());
                }
                s_children.nodes_mut().push(child.clone());
                s_node.set_children(s_children);
                dummy_doc.nodes_mut().push(s_node);
                let new_tools = parse_servers(
                    &dummy_doc,
                    &defaults_layer,
                    profiles,
                    base_dir,
                    policy.version,
                )?;
                for t in new_tools {
                    policy.tools.push(t);
                }
            }
        }
    }

    // mcp rules inside matching `when` blocks union per server, with the
    // same deny-first atom resolution as include/extends.
    let mcp_overrides = parse_server_mcp_rules(doc, policy.version, true)?;
    for server_rules in mcp_overrides {
        if let Some(existing) = policy
            .mcp_rules
            .iter_mut()
            .find(|s| s.server_name == server_rules.server_name)
        {
            existing.extend_rules(server_rules.into_rules());
        } else {
            policy.mcp_rules.push(server_rules);
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
pub(crate) fn tool_fs_base(global_fs: &FsPolicy, existing: Option<&FsToolPolicy>) -> FsToolPolicy {
    let mut denied = global_fs.denied_paths.clone();
    if let Some(cur) = existing {
        for d in &cur.denied_paths {
            if !denied.contains(d) {
                denied.push(d.clone());
            }
        }
    }
    let mut fs = FsToolPolicy {
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
    global_net: &NetworkPolicy,
    existing: Option<&ToolNetworkPolicy>,
) -> ToolNetworkPolicy {
    let mut denied = global_net.outbound.denied_hosts.clone();
    if let Some(cur) = existing {
        for d in &cur.denied_hosts {
            if !denied.contains(d) {
                denied.push(d.clone());
            }
        }
    }
    let mut network = ToolNetworkPolicy {
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
            tool.syscalls = keep.then_some(ToolSyscallPolicy { allowed, denied });
        }
    }
}
