use std::collections::HashMap;
use std::path::Path;

use kdl::KdlDocument;

use crate::error::PolicyError;
use crate::policy::kdl_parse::{
    Defaults, check_none_needs_replace, defaults_to_layer, parse_deputy_node,
    parse_environment_node, parse_fs_allows, parse_logging_fail_closed, parse_network_rules,
    parse_process_exec_allowed, parse_replace_flag, parse_server_hashes, parse_server_mcp_rules,
    parse_servers, parse_syscall_allows, parse_tool_fs, parse_tool_network, parse_tool_syscalls,
    parse_tools_list_hashes, parse_trajectory, resolve_tool_args_schema,
    resolve_tool_profile_names, unique_child, validate_logging_level, validate_tool_shape_v2,
};
use crate::policy::merge::PolicyLayer;
use crate::policy::provenance::Provenance;
use crate::policy::{EnvironmentPolicy, FsPolicy, InputResponsesMode, Policy, SyscallPolicy};

use super::tool::{
    merge_tool_fs, merge_tool_network, merge_tool_syscalls, seed_tool_fields, tool_fs_base,
    tool_network_base,
};
use super::{
    OverlayDecl, PendingWarnings, declares_network_posture, fs_deny_covers, node_line,
    prune_covered, tool_key,
};

/// The line the `server "name"` node starts on — attribution for the
/// entries `parse_server_*` collect from inside it (`mcp` rules,
/// hash entries, tools-list pins).
fn server_node_line(doc: &KdlDocument, content: &str, server_name: Option<&str>) -> Option<u32> {
    doc.nodes()
        .iter()
        .find(|n| {
            n.name().value() == "server" && n.get(0).and_then(|v| v.as_string()) == server_name
        })
        .and_then(|n| node_line(content, n))
}

/// Evaluate `when environment="xxx" { ... }` blocks and apply matching
/// overrides. Returns the declarations matching blocks made — an
/// `include` consumer merges on them, so a value set through a `when`
/// propagates like one the file declared outright. Network
/// re-declarations that skip `inbound` while a listener grant is live
/// are recorded on `pending`, not warned immediately: they are
/// evaluated against the load's final merged policy.
#[expect(clippy::too_many_arguments)]
pub(in crate::policy::kdl_inherit) fn apply_when_overrides(
    doc: &KdlDocument,
    policy: &mut Policy,
    env_value: &str,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
    path: &Path,
    content: &str,
    pending: &mut PendingWarnings,
    prov: &mut Provenance,
    rules: u32,
) -> Result<OverlayDecl, PolicyError> {
    let mut decl = OverlayDecl::default();
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
        apply_overrides_from_doc(
            children, policy, profiles, base_dir, path, content, pending, prov, rules,
        )?;
        decl.merge(&OverlayDecl::for_when_children(
            children,
            path,
            content,
            policy.version,
        ));
    }

    Ok(decl)
}

/// Apply override fields parsed from a KdlDocument (used by `when` blocks).
/// `rules` is the composition-semantics version — under v3 the allow
/// sides below union unless the block declared `replace=#true`.
#[expect(clippy::too_many_arguments)]
fn apply_overrides_from_doc(
    doc: &KdlDocument,
    policy: &mut Policy,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
    path: &Path,
    content: &str,
    pending: &mut PendingWarnings,
    prov: &mut Provenance,
    rules: u32,
) -> Result<(), PolicyError> {
    // defaults overrides
    if let Some(defaults_node) = unique_child(doc, "defaults", "the override document")?
        && let Some(children) = defaults_node.children()
    {
        if let Some(fs_node) = unique_child(children, "filesystem", "'defaults'")? {
            let line = node_line(content, fs_node);
            // `secret-overlay` rides the declared block; omitted stays
            // default-on (fail-secure), same as the inheritance merge.
            let fs_replace = parse_replace_flag(fs_node, "defaults.filesystem", policy.version)?;
            let fs = match fs_node.children() {
                Some(fs_children) => parse_fs_allows(fs_children)?,
                None => FsPolicy::default(),
            };
            policy.fs.secret_overlay = fs.secret_overlay;
            prov.set("defaults.filesystem.secret-overlay", path, line);
            if fs.allow_specified || (rules >= 3 && fs_replace) {
                if rules >= 3 && !fs_replace {
                    // Under v3 the allow lists union by default — a
                    // matching `when` adds to what the doc built.
                    prov.union(
                        "defaults.filesystem.read_only",
                        path,
                        line,
                        fs.read_only.iter().cloned(),
                    );
                    prov.union(
                        "defaults.filesystem.read_write",
                        path,
                        line,
                        fs.read_write.iter().cloned(),
                    );
                    prov.union(
                        "defaults.filesystem.executable",
                        path,
                        line,
                        fs.executable.iter().cloned(),
                    );
                    for p in &fs.read_only {
                        if !policy.fs.read_only.contains(p) {
                            policy.fs.read_only.push(p.clone());
                        }
                    }
                    for p in &fs.read_write {
                        if !policy.fs.read_write.contains(p) {
                            policy.fs.read_write.push(p.clone());
                        }
                    }
                    for p in &fs.executable {
                        if !policy.fs.executable.contains(p) {
                            policy.fs.executable.push(p.clone());
                        }
                    }
                } else {
                    // A matching `when` block replaces the allow lists
                    // wholesale under v1/v2 — and under v3 only on an
                    // explicit `replace=#true`.
                    prov.replace(
                        "defaults.filesystem.read_only",
                        path,
                        line,
                        fs.read_only.clone(),
                    );
                    prov.replace(
                        "defaults.filesystem.read_write",
                        path,
                        line,
                        fs.read_write.clone(),
                    );
                    prov.replace(
                        "defaults.filesystem.executable",
                        path,
                        line,
                        fs.executable.clone(),
                    );
                    policy.fs.read_only = fs.read_only;
                    policy.fs.read_write = fs.read_write;
                    policy.fs.executable = fs.executable;
                }
                policy.fs.allow_specified = true;
            }
            prov.union(
                "defaults.filesystem.denied",
                path,
                line,
                fs.denied_paths.iter().cloned(),
            );
            for denied in &fs.denied_paths {
                if !policy.fs.denied_paths.contains(denied) {
                    policy.fs.denied_paths.push(denied.clone());
                }
            }
            let denied_now = policy.fs.denied_paths.clone();
            for (field, list) in [
                ("defaults.filesystem.read_only", &mut policy.fs.read_only),
                ("defaults.filesystem.read_write", &mut policy.fs.read_write),
                ("defaults.filesystem.executable", &mut policy.fs.executable),
            ] {
                prune_covered(
                    list,
                    |p| fs_deny_covers(&denied_now, p),
                    prov,
                    field,
                    path,
                    line,
                );
            }
            let read_now = policy.fs.read_only.clone();
            for (field, list) in [
                ("defaults.filesystem.read_write", &mut policy.fs.read_write),
                ("defaults.filesystem.executable", &mut policy.fs.executable),
            ] {
                prune_covered(list, |p| read_now.contains(p), prov, field, path, line);
            }
        }
        if let Some(sc_node) = unique_child(children, "syscalls", "'defaults'")? {
            let line = node_line(content, sc_node);
            let sc_replace = parse_replace_flag(sc_node, "defaults.syscalls", policy.version)?;
            let sc = match sc_node.children() {
                Some(sc_children) => parse_syscall_allows(sc_children, policy.version)?,
                None => SyscallPolicy::default(),
            };
            if !sc.allowed.is_empty() || (rules >= 3 && sc_replace) {
                if rules >= 3 && !sc_replace {
                    prov.union("defaults.syscalls", path, line, sc.allowed.iter().cloned());
                    for s in &sc.allowed {
                        if !policy.syscalls.allowed.contains(s) {
                            policy.syscalls.allowed.push(s.clone());
                        }
                    }
                } else {
                    prov.replace("defaults.syscalls", path, line, sc.allowed.clone());
                    policy.syscalls.allowed = sc.allowed;
                }
            }
            if !sc.denied.is_empty() {
                prov.union(
                    "defaults.syscalls.denied",
                    path,
                    line,
                    sc.denied.iter().cloned(),
                );
                for s in &sc.denied {
                    if !policy.syscalls.denied.contains(s) {
                        policy.syscalls.denied.push(s.clone());
                    }
                }
            }
            // Deny-wins against the accumulated deny list even when
            // this block added no `deny` itself — an `allow` here can
            // re-declare a name an earlier layer already denies.
            let denied_now = policy.syscalls.denied.clone();
            prune_covered(
                &mut policy.syscalls.allowed,
                |s| denied_now.contains(s),
                prov,
                "defaults.syscalls",
                path,
                line,
            );
        }
        // Node presence in a matching `when` block marks the contract
        // declared; the declared contents — restriction posture, the
        // `inherit-parent` opt-in, and the `allow` list — replace the
        // base's (including an empty list).
        if let Some(env_node) = unique_child(children, "environment", "'defaults'")? {
            let env = parse_environment_node(env_node)?;
            let line = node_line(content, env_node);
            prov.replace(
                "defaults.environment.allowed",
                path,
                line,
                env.allowed.clone(),
            );
            prov.set("defaults.environment.restrict", path, line);
            prov.set("defaults.environment.inherit-parent", path, line);
            policy.environment.restrict = !env.inherit_parent;
            policy.environment.inherit_parent = env.inherit_parent;
            policy.environment.declared = true;
            policy.environment.allowed = env.allowed;
        }
        if let Some(net_node) = unique_child(children, "network", "'defaults'")?
            && let Some(net_children) = net_node.children()
        {
            let net_replace = parse_replace_flag(net_node, "defaults.network", policy.version)?;
            let net = parse_network_rules(net_children)?;
            let line = node_line(content, net_node);
            // Same allow-replaces / deny-accumulates semantics as the
            // inheritance merge — including the qualified `egress_rules`
            // entries the flat lists cannot carry. Under v3 the allow
            // side unions unless the block carried `replace=#true`.
            // Materialize the stored rule set so composition sees the
            // effective rules.
            policy.network.outbound.egress_rules = policy.network.outbound.egress_rules();
            let net_rules = net.outbound.egress_rules();
            let net_has_allow = !net.outbound.allowed.is_empty()
                || !net.outbound.allowed_cidrs.is_empty()
                || !net.outbound.deny_all_others
                || net_rules.iter().any(|r| r.allow);
            if net_has_allow || (rules >= 3 && net_replace) {
                // One `describe`d spelling per declared allow rule —
                // the flat lists are the same rules' projections, so
                // chaining them would double-count and lose the
                // proto/port/`unix=` qualifiers.
                let allow_items: Vec<String> = net_rules
                    .iter()
                    .filter(|r| r.allow)
                    .map(|r| r.describe())
                    .collect();
                if rules >= 3 && !net_replace {
                    prov.union("defaults.network.allow", path, line, allow_items);
                    for h in &net.outbound.allowed {
                        if !policy.network.outbound.allowed.contains(h) {
                            policy.network.outbound.allowed.push(h.clone());
                        }
                    }
                    for s in &net.outbound.allowed_port_qualified {
                        if !policy.network.outbound.allowed_port_qualified.contains(s) {
                            policy
                                .network
                                .outbound
                                .allowed_port_qualified
                                .push(s.clone());
                        }
                    }
                    for c in &net.outbound.allowed_cidrs {
                        if !policy.network.outbound.allowed_cidrs.contains(c) {
                            policy.network.outbound.allowed_cidrs.push(c.clone());
                        }
                    }
                    for s in &net.outbound.allowed_cidrs_port_qualified {
                        if !policy
                            .network
                            .outbound
                            .allowed_cidrs_port_qualified
                            .contains(s)
                        {
                            policy
                                .network
                                .outbound
                                .allowed_cidrs_port_qualified
                                .push(s.clone());
                        }
                    }
                    for r in &net_rules {
                        if r.allow && !policy.network.outbound.egress_rules.contains(r) {
                            policy.network.outbound.egress_rules.push(r.clone());
                        }
                    }
                } else {
                    prov.replace("defaults.network.allow", path, line, allow_items);
                    policy.network.outbound.allowed = net.outbound.allowed;
                    policy.network.outbound.allowed_port_qualified =
                        net.outbound.allowed_port_qualified;
                    policy.network.outbound.allowed_cidrs = net.outbound.allowed_cidrs;
                    policy.network.outbound.allowed_cidrs_port_qualified =
                        net.outbound.allowed_cidrs_port_qualified;
                    policy.network.outbound.egress_rules.retain(|r| !r.allow);
                    for r in &net_rules {
                        if r.allow && !policy.network.outbound.egress_rules.contains(r) {
                            policy.network.outbound.egress_rules.push(r.clone());
                        }
                    }
                }
            }
            let deny_items: Vec<String> = net_rules
                .iter()
                .filter(|r| !r.allow)
                .map(|r| r.describe())
                .collect();
            prov.union("defaults.network.deny", path, line, deny_items);
            for host in &net.outbound.denied_hosts {
                if !policy.network.outbound.denied_hosts.contains(host) {
                    policy.network.outbound.denied_hosts.push(host.clone());
                }
            }
            for cidr in &net.outbound.denied_cidrs {
                if !policy.network.outbound.denied_cidrs.contains(cidr) {
                    policy.network.outbound.denied_cidrs.push(cidr.clone());
                }
            }
            for r in &net_rules {
                if !r.allow && !policy.network.outbound.egress_rules.contains(r) {
                    policy.network.outbound.egress_rules.push(r.clone());
                }
            }
            // Posture moves only on a bare `host="*"` posture node — a
            // block that merely adds rules must not reset an inherited
            // open posture. `inbound` likewise moves only when declared.
            if declares_network_posture(net_children) {
                policy.network.outbound.deny_all_others = net.outbound.deny_all_others;
                prov.set("defaults.network.posture", path, line);
            }
            if net_children.get("inbound").is_some() {
                policy.network.inbound.allow_listen = net.inbound.allow_listen;
                prov.set("defaults.network.inbound", path, line);
            } else if policy.network.inbound.allow_listen {
                // Deferred: a later declaration may still close the
                // grant — the warning is evaluated on the load's
                // final merged state.
                pending.push_inbound(path);
            }
            crate::policy::sort_egress_rules(&mut policy.network.outbound.egress_rules);
            {
                // A flat entry and its rule projection drop together —
                // record the rule spelling the writers track.
                let before_rules = policy.network.outbound.egress_rules.clone();
                crate::policy::apply_outbound_deny_precedence(&mut policy.network.outbound);
                let mut dropped: Vec<String> = before_rules
                    .iter()
                    .filter(|r| r.allow && !policy.network.outbound.egress_rules.contains(r))
                    .map(|r| r.describe())
                    .collect();
                dropped.dedup();
                if !dropped.is_empty() {
                    prov.prune("defaults.network.allow", path, line, dropped);
                }
            }
        }
    }

    // logging override (level and fail_closed are independent)
    if let Some(logging_node) = doc.get("logging") {
        let line = node_line(content, logging_node);
        let mut wrote = false;
        if let Some(level_prop) = logging_node.get("level") {
            let level = level_prop
                .as_string()
                .ok_or_else(|| PolicyError::KdlParse("'logging.level' must be a string".into()))?;
            validate_logging_level(level)?;
            policy.logging.level = level.to_string();
            wrote = true;
        }
        if logging_node.get("fail_closed").is_some() {
            policy.logging.fail_closed = parse_logging_fail_closed(logging_node)?;
            wrote = true;
        }
        if wrote {
            prov.set("logging", path, line);
        }
    }

    // sandbox override
    if let Some(sandbox_node) = doc.get("sandbox") {
        let mut wrote = false;
        if let Some(val) = sandbox_node.get("allow_degraded") {
            policy.sandbox.allow_degraded = val.as_bool().ok_or_else(|| {
                PolicyError::KdlParse("'sandbox.allow_degraded' must be a boolean".into())
            })?;
            wrote = true;
        }
        if let Some(val) = sandbox_node.get("require_lifetime_boundary") {
            policy.sandbox.require_lifetime_boundary = val.as_bool().ok_or_else(|| {
                PolicyError::KdlParse(
                    "'sandbox.require_lifetime_boundary' must be a boolean".into(),
                )
            })?;
            wrote = true;
        }
        if wrote {
            prov.set("sandbox", path, node_line(content, sandbox_node));
        }
    }

    // confused_deputy_protection override
    if let Some(cdp_node) = doc.get("confused_deputy_protection")
        && let Some(arg) = cdp_node.get(0)
    {
        let cdp = arg.as_bool().ok_or_else(|| {
            PolicyError::KdlParse("'confused_deputy_protection' must be a boolean".into())
        })?;
        policy.confused_deputy_protection = cdp;
        prov.set(
            "confused_deputy_protection",
            path,
            node_line(content, cdp_node),
        );
    }

    // trajectory override (flag + ordered after children)
    if doc.get("trajectory").is_some() {
        let line = doc.get("trajectory").and_then(|n| node_line(content, n));
        let (enabled, rules) = parse_trajectory(doc)?;
        policy.trajectory = enabled;
        policy.trajectory_rules = rules;
        prov.set("trajectory", path, line);
        prov.replace(
            "trajectory.after",
            path,
            line,
            policy
                .trajectory_rules
                .iter()
                .map(|r| format!("{:?}->{:?}", r.after_side_effect, r.deny_next))
                .collect(),
        );
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
            let tkey = tool_key(server_name.as_deref(), &tool_name);
            let tline = node_line(content, child);

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
                        prov.set(format!("{tkey}.deny"), path, tline);
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
                    prov.set(format!("{tkey}.side_effect"), path, tline);
                }
                if let Some(val) = child.get("args_schema") {
                    let s = val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'args_schema' property on tool '{}' must be a string",
                            tool_name
                        ))
                    })?;
                    let (resolved, source) = resolve_tool_args_schema(s, base_dir)?;
                    existing.args_schema = Some(resolved);
                    if let Some((spelled, canonical)) = source {
                        prov.record_source(canonical);
                        prov.record_source_spelling(spelled);
                    }
                    prov.set(format!("{tkey}.args_schema"), path, tline);
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
                    prov.set(format!("{tkey}.input_responses"), path, tline);
                }
                // A `when` override that names profiles must apply them
                // to an existing tool too — the inline parse resolves
                // the same spellings, so an unresolvable name is a
                // load error, not a silently dropped restriction. Each
                // layer merges onto the tool's effective state in
                // declaration order — under v3 they union, under v2 a
                // later layer replaces the earlier allow side.
                let when_tool_profiles =
                    resolve_tool_profile_names(child, child.children(), &tool_ctx, policy.version)?;
                for pname in &when_tool_profiles {
                    let profile_layer = profiles.get(pname).ok_or_else(|| {
                        PolicyError::Validation(format!(
                            "unknown profile '{pname}' referenced by tool '{tool_name}'"
                        ))
                    })?;
                    prov.set(format!("{tkey}.profile"), path, tline);
                    if profile_layer.fs.is_some() {
                        if !existing.fs_explicit {
                            existing.fs = Some(tool_fs_base(&policy.fs, existing.fs.as_ref()));
                        }
                        existing.fs_explicit = true;
                        merge_tool_fs(
                            &mut existing.fs,
                            profile_layer.fs.as_ref(),
                            prov,
                            &tkey,
                            path,
                            tline,
                            rules >= 3,
                            profile_layer.fs_replace,
                        );
                    }
                    if profile_layer.syscalls.is_some() {
                        existing.syscalls_explicit = true;
                        merge_tool_syscalls(
                            &mut existing.syscalls,
                            profile_layer.syscalls.as_ref(),
                            prov,
                            &tkey,
                            path,
                            tline,
                            rules >= 3,
                            profile_layer.syscalls_replace,
                        );
                    }
                    if profile_layer.network.is_some() {
                        if !existing.network_explicit {
                            existing.network = Some(tool_network_base(
                                &policy.network,
                                existing.network.as_ref(),
                            ));
                        }
                        existing.network_explicit = true;
                        merge_tool_network(
                            &mut existing.network,
                            profile_layer.network.as_ref(),
                            prov,
                            &tkey,
                            path,
                            tline,
                            rules >= 3,
                            profile_layer.network_replace,
                        );
                    }
                }
                if let Some(tc) = child.children() {
                    if let Some(fs_node) = unique_child(tc, "filesystem", &tool_ctx)?
                        && let Some(fs_children) = fs_node.children()
                    {
                        let fs_replace = parse_replace_flag(
                            fs_node,
                            &format!("{tool_ctx}.filesystem"),
                            policy.version,
                        )?;
                        let over_fs = parse_tool_fs(fs_children)?;
                        check_none_needs_replace(
                            over_fs.allow_specified,
                            !over_fs.allowed_paths.is_empty(),
                            fs_replace,
                            &format!("{tool_ctx}.filesystem"),
                            policy.version,
                        )?;
                        if !existing.fs_explicit {
                            // Re-base inherited grants on the current
                            // (post-`when`) defaults so the override folds the
                            // same way as an inline tool block.
                            existing.fs = Some(tool_fs_base(&policy.fs, existing.fs.as_ref()));
                        }
                        existing.fs_explicit = true;
                        existing.fs_replace |= fs_replace;
                        merge_tool_fs(
                            &mut existing.fs,
                            Some(&over_fs),
                            prov,
                            &tkey,
                            path,
                            tline,
                            rules >= 3,
                            fs_replace,
                        );
                    }
                    if let Some(sc_node) = unique_child(tc, "syscalls", &tool_ctx)?
                        && let Some(sc_children) = sc_node.children()
                    {
                        let sc_replace = parse_replace_flag(
                            sc_node,
                            &format!("{tool_ctx}.syscalls"),
                            policy.version,
                        )?;
                        let over_sc = parse_tool_syscalls(sc_children)?;
                        // Per-tool syscalls are not enforced; mark explicit so
                        // rematerialize keeps them and load-time validation
                        // rejects the policy like an inline declaration.
                        existing.syscalls_explicit = true;
                        existing.syscalls_replace |= sc_replace;
                        merge_tool_syscalls(
                            &mut existing.syscalls,
                            Some(&over_sc),
                            prov,
                            &tkey,
                            path,
                            tline,
                            rules >= 3,
                            sc_replace,
                        );
                    }
                    if let Some(net_node) = unique_child(tc, "network", &tool_ctx)?
                        && let Some(net_children) = net_node.children()
                    {
                        let net_replace = parse_replace_flag(
                            net_node,
                            &format!("{tool_ctx}.network"),
                            policy.version,
                        )?;
                        let over_net = parse_tool_network(net_children)?;
                        check_none_needs_replace(
                            over_net.allow_specified,
                            !over_net.allowed_hosts.is_empty()
                                || !over_net.allowed_cidrs.is_empty()
                                || over_net.egress_rules.iter().any(|r| r.allow),
                            net_replace,
                            &format!("{tool_ctx}.network"),
                            policy.version,
                        )?;
                        if !existing.network_explicit {
                            existing.network = Some(tool_network_base(
                                &policy.network,
                                existing.network.as_ref(),
                            ));
                        }
                        existing.network_explicit = true;
                        existing.network_replace |= net_replace;
                        merge_tool_network(
                            &mut existing.network,
                            Some(&over_net),
                            prov,
                            &tkey,
                            path,
                            tline,
                            rules >= 3,
                            net_replace,
                        );
                    }
                    if let Some(proc_node) = unique_child(tc, "process", &tool_ctx)? {
                        existing.process_exec_allowed = parse_process_exec_allowed(proc_node)?;
                        existing.process_explicit = true;
                        prov.set(format!("{tkey}.process"), path, tline);
                    }
                    // Per-tool environment is not enforced; flag it so
                    // load-time validation rejects the policy like an
                    // inline declaration.
                    if unique_child(tc, "environment", &tool_ctx)?.is_some() {
                        existing.environment_explicit = true;
                        prov.set(format!("{tkey}.environment"), path, tline);
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
                        prov.set(format!("{tkey}.deputy"), path, tline);
                    }
                }
            } else {
                let defaults_layer = defaults_to_layer(&Defaults {
                    fs: policy.fs.clone(),
                    syscalls: policy.syscalls.clone(),
                    network: policy.network.clone(),
                    environment: EnvironmentPolicy::default(),
                    ..Defaults::default()
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
                let mut schema_sources = Vec::new();
                let new_tools = parse_servers(
                    &dummy_doc,
                    &defaults_layer,
                    profiles,
                    base_dir,
                    policy.version,
                    rules,
                    &mut schema_sources,
                )?;
                for source in schema_sources {
                    prov.record_source(source);
                }
                for t in new_tools {
                    prov.set(tkey.clone(), path, tline);
                    seed_tool_fields(prov, &tkey, &t, (path, tline));
                    policy.tools.push(t);
                }
            }
        }
    }

    // mcp rules inside matching `when` blocks union per server, with the
    // same deny-first atom resolution as include/extends.
    let mcp_overrides = parse_server_mcp_rules(doc, policy.version, true)?;
    for server_rules in mcp_overrides {
        // The `server` node's own line is the closest attribution the
        // overrides have (rules carry no per-node spans).
        let line = server_node_line(doc, content, server_rules.server_name.as_deref());
        prov.union(
            "mcp.rules",
            path,
            line,
            server_rules
                .rules()
                .iter()
                .map(|r| format!("{:?} {}", r.effect, r.method)),
        );
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
        // The `server` node's line is the closest attribution a hash
        // entry has — the override record sits inside it.
        let line = server_node_line(doc, content, Some(entry.server_name.as_str()));
        prov.union(
            "integrity.hash",
            path,
            line,
            [format!(
                "{}/{:?}:{}",
                entry.server_name, entry.hash_type, entry.target
            )],
        );
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
        let line = server_node_line(doc, content, Some(entry.server_name.as_str()));
        prov.union(
            "integrity.tools-list",
            path,
            line,
            [format!("{}/tools-list-hash", entry.server_name)],
        );
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
