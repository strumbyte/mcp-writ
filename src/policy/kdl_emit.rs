use crate::policy::{InputResponsesMode, Policy, ToolPolicy, TransportType};

/// Serialize the effective policy into a self-contained KDL string.
///
/// The resulting KDL has all inheritance (extends), includes, profiles,
/// and server-defaults already merged into concrete rules, suitable for
/// embedding into container images or environments without external files.
pub(crate) fn to_kdl(policy: &Policy) -> String {
    fn escape_kdl(s: &str) -> String {
        crate::termutil::escape_kdl_string(s)
    }

    fn sorted_kdl_properties(mut props: Vec<(&str, String)>) -> String {
        props.sort_by(|a, b| a.0.cmp(b.0));
        props
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    let mut out = String::new();
    out.push_str(&format!("policy version={}\n\n", policy.version));

    // Transport
    match policy.transport.type_ {
        TransportType::Stdio => {
            out.push_str("transport type=\"stdio\"\n\n");
        }
        TransportType::Http => {
            if let Some(ref addr) = policy.transport.listen_addr {
                out.push_str(&format!(
                    "transport type=\"http\" listen_addr=\"{}\"\n\n",
                    escape_kdl(addr)
                ));
            } else {
                out.push_str("transport type=\"http\"\n\n");
            }
        }
    }

    // Defaults
    out.push_str("defaults {\n");
    let has_fs = !policy.fs.read_only.is_empty()
        || !policy.fs.read_write.is_empty()
        || !policy.fs.denied_paths.is_empty();
    if has_fs || !policy.fs.secret_overlay {
        out.push_str("    filesystem {\n");
        // Overlay beats explicit allow. TOCTOU after this check is Warden's job.
        if policy.fs.secret_overlay {
            out.push_str("        secret-overlay #true\n");
        } else {
            out.push_str("        secret-overlay #false\n");
        }
        for p in &policy.fs.read_only {
            out.push_str(&format!(
                "        allow \"{}\" mode=\"read\"\n",
                escape_kdl(p)
            ));
        }
        for p in &policy.fs.read_write {
            out.push_str(&format!(
                "        allow \"{}\" mode=\"write\"\n",
                escape_kdl(p)
            ));
        }
        for p in &policy.fs.denied_paths {
            out.push_str(&format!("        deny \"{}\"\n", escape_kdl(p)));
        }
        out.push_str("    }\n");
    }

    if !policy.syscalls.allowed.is_empty() {
        out.push_str("    syscalls {\n");
        out.push_str("        allow");
        for sc in &policy.syscalls.allowed {
            out.push_str(&format!(" \"{}\"", escape_kdl(sc)));
        }
        out.push_str("\n    }\n");
    }

    let has_net = !policy.network.outbound.allowed.is_empty()
        || !policy.network.outbound.denied_hosts.is_empty()
        || !policy.network.outbound.deny_all_others
        || policy.network.inbound.allow_listen;
    if has_net {
        out.push_str("    network {\n");
        for h in &policy.network.outbound.allowed {
            out.push_str(&format!("        allow host=\"{}\"\n", escape_kdl(h)));
        }
        for h in &policy.network.outbound.denied_hosts {
            out.push_str(&format!("        deny host=\"{}\"\n", escape_kdl(h)));
        }
        if policy.network.outbound.deny_all_others {
            out.push_str("        deny host=\"*\"\n");
        } else {
            out.push_str("        allow host=\"*\"\n");
        }
        if policy.network.inbound.allow_listen {
            out.push_str("        inbound allow=#true\n");
        }
        out.push_str("    }\n");
    }
    out.push_str("}\n\n");

    // Confused deputy
    if policy.confused_deputy_protection {
        out.push_str("confused_deputy_protection #true\n\n");
    } else {
        out.push_str("confused_deputy_protection #false\n\n");
    }

    if policy.trajectory || !policy.trajectory_rules.is_empty() {
        if policy.trajectory_rules.is_empty() {
            out.push_str(&format!(
                "trajectory #{}\n\n",
                if policy.trajectory { "true" } else { "false" }
            ));
        } else {
            out.push_str(&format!(
                "trajectory #{} {{\n",
                if policy.trajectory { "true" } else { "false" }
            ));
            for rule in &policy.trajectory_rules {
                let props = sorted_kdl_properties(vec![
                    ("deny-next", format!("\"{}\"", rule.deny_next.as_str())),
                    (
                        "side_effect",
                        format!("\"{}\"", rule.after_side_effect.as_str()),
                    ),
                ]);
                out.push_str(&format!("    after {props}\n"));
            }
            out.push_str("}\n\n");
        }
    }

    // Logging
    out.push_str(&format!(
        "logging level=\"{}\" fail_closed=#{}\n\n",
        policy.logging.level,
        if policy.logging.fail_closed {
            "true"
        } else {
            "false"
        }
    ));

    if policy.sandbox.allow_degraded {
        out.push_str("sandbox allow_degraded=#true\n\n");
    }

    // Tools grouped by server
    let mut server_tools: std::collections::BTreeMap<String, Vec<&ToolPolicy>> =
        std::collections::BTreeMap::new();
    for tool in &policy.tools {
        let server = tool.server.clone().unwrap_or_else(|| "default".into());
        server_tools.entry(server).or_default().push(tool);
    }

    // If no tools but there are hashes, make sure servers are written
    for h in &policy.hash_entries {
        server_tools.entry(h.server_name.clone()).or_default();
    }
    for th in &policy.tools_list_hashes {
        server_tools.entry(th.server_name.clone()).or_default();
    }

    for (sname, tools) in server_tools {
        out.push_str(&format!("server \"{}\" {{\n", escape_kdl(&sname)));

        // Hashes for this server
        for h in &policy.hash_entries {
            if h.server_name == sname {
                let mut line = format!(
                    "    {} \"{}\" target=\"{}\"",
                    h.hash_type.as_str(),
                    escape_kdl(&h.hash_value),
                    escape_kdl(&h.target)
                );
                if let Some(ref app) = h.approved {
                    line.push_str(&format!(" approved=\"{}\"", escape_kdl(app)));
                }
                line.push('\n');
                out.push_str(&line);
            }
        }
        for th in &policy.tools_list_hashes {
            if th.server_name == sname {
                let mut line = format!("    tools-list-hash \"{}\"", escape_kdl(&th.hash_value));
                if let Some(ref app) = th.approved {
                    line.push_str(&format!(" approved=\"{}\"", escape_kdl(app)));
                }
                line.push('\n');
                out.push_str(&line);
            }
        }

        for tool in tools {
            let mut tool_line = format!("    tool \"{}\"", escape_kdl(&tool.name));
            if !tool.allowed {
                tool_line.push_str(" deny=#true");
            }
            if let Some(ref se) = tool.side_effect {
                tool_line.push_str(&format!(" side_effect=\"{}\"", escape_kdl(se)));
            }
            if let Some(ref schema) = tool.args_schema {
                tool_line.push_str(&format!(" args_schema=\"{}\"", escape_kdl(schema)));
            }
            if tool.input_responses_specified || tool.input_responses != InputResponsesMode::Auto {
                tool_line.push_str(&format!(
                    " input_responses=\"{}\"",
                    tool.input_responses.as_str()
                ));
            }

            // Per-tool syscalls are emitted only when the tool declared its
            // own block (syscalls_explicit). Values inherited from global
            // defaults are re-materialized on load and must not be written
            // back per-tool.
            let emit_syscalls = tool.syscalls_explicit
                && tool
                    .syscalls
                    .as_ref()
                    .is_some_and(|sc| !sc.allowed.is_empty() || !sc.denied.is_empty());
            let has_children = tool.fs.is_some()
                || emit_syscalls
                || tool.network.is_some()
                || tool.process_explicit;
            if has_children {
                tool_line.push_str(" {\n");
                if let Some(ref fs) = tool.fs {
                    let has_tool_fs = !fs.read_only_paths.is_empty()
                        || !fs.read_write_paths.is_empty()
                        || !fs.denied_paths.is_empty()
                        || fs.allow_specified
                        || fs.require_path.is_some();
                    if has_tool_fs {
                        tool_line.push_str("        filesystem {\n");
                        if let Some(required) = fs.require_path {
                            tool_line.push_str(&format!("            require-path #{required}\n"));
                        }
                        if fs.allow_specified
                            && fs.read_only_paths.is_empty()
                            && fs.read_write_paths.is_empty()
                        {
                            tool_line.push_str("            allow none=#true\n");
                        }
                        for p in &fs.read_only_paths {
                            tool_line.push_str(&format!(
                                "            allow \"{}\" mode=\"read\"\n",
                                escape_kdl(p)
                            ));
                        }
                        for p in &fs.read_write_paths {
                            tool_line.push_str(&format!(
                                "            allow \"{}\" mode=\"write\"\n",
                                escape_kdl(p)
                            ));
                        }
                        for p in &fs.denied_paths {
                            tool_line
                                .push_str(&format!("            deny \"{}\"\n", escape_kdl(p)));
                        }
                        tool_line.push_str("        }\n");
                    }
                }
                if emit_syscalls && let Some(ref sc) = tool.syscalls {
                    tool_line.push_str("        syscalls {\n");
                    if !sc.allowed.is_empty() {
                        tool_line.push_str("            allow");
                        for s in &sc.allowed {
                            tool_line.push_str(&format!(" \"{}\"", escape_kdl(s)));
                        }
                        tool_line.push('\n');
                    }
                    if !sc.denied.is_empty() {
                        tool_line.push_str("            deny");
                        for s in &sc.denied {
                            tool_line.push_str(&format!(" \"{}\"", escape_kdl(s)));
                        }
                        tool_line.push('\n');
                    }
                    tool_line.push_str("        }\n");
                }
                if let Some(ref net) = tool.network {
                    let has_tool_net = !net.allowed_hosts.is_empty()
                        || !net.denied_hosts.is_empty()
                        || net.allow_specified;
                    if has_tool_net {
                        tool_line.push_str("        network {\n");
                        if net.allow_specified && net.allowed_hosts.is_empty() {
                            tool_line.push_str("            allow none=#true\n");
                        }
                        for h in &net.allowed_hosts {
                            tool_line.push_str(&format!(
                                "            allow host=\"{}\"\n",
                                escape_kdl(h)
                            ));
                        }
                        for h in &net.denied_hosts {
                            tool_line.push_str(&format!(
                                "            deny host=\"{}\"\n",
                                escape_kdl(h)
                            ));
                        }
                        tool_line.push_str("        }\n");
                    }
                }
                if tool.process_explicit {
                    tool_line.push_str("        process {\n");
                    if tool.process_exec_allowed {
                        tool_line.push_str("            deny-all #false\n");
                    } else {
                        tool_line.push_str("            deny-all #true\n");
                    }
                    tool_line.push_str("        }\n");
                }
                tool_line.push_str("    }\n");
            } else {
                tool_line.push('\n');
            }
            out.push_str(&tool_line);
        }
        out.push_str("}\n\n");
    }
    out
}

#[cfg(test)]
mod to_kdl_tests {
    use super::*;
    use crate::policy::{SideEffect, TrajectoryRule, default_policy};

    #[test]
    fn inbound_listen_emits_network_block() {
        let mut policy = default_policy();
        policy.network.inbound.allow_listen = true;
        let kdl = policy.to_kdl();
        assert!(kdl.contains("inbound allow=#true"), "got:\n{kdl}");
    }

    #[test]
    fn omitted_trajectory_is_not_emitted() {
        let policy = default_policy();
        let kdl = policy.to_kdl();
        assert!(!kdl.contains("trajectory"), "got:\n{kdl}");
    }

    #[test]
    fn enabled_trajectory_emits_after_children() {
        let mut policy = default_policy();
        policy.trajectory = true;
        policy.trajectory_rules.push(TrajectoryRule {
            after_side_effect: SideEffect::ReadOnly,
            deny_next: SideEffect::Network,
        });
        let kdl = policy.to_kdl();
        assert!(kdl.contains("trajectory #true"), "got:\n{kdl}");
        assert!(
            kdl.contains("after deny-next=\"network\" side_effect=\"read_only\""),
            "got:\n{kdl}"
        );
    }

    #[test]
    fn process_deny_all_emits_positional_child_and_round_trips() {
        let mut policy = default_policy();
        let mut denied = ToolPolicy::named("denied_exec", true);
        denied.process_explicit = true;
        denied.process_exec_allowed = false;
        let mut allowed = ToolPolicy::named("allowed_exec", true);
        allowed.process_explicit = true;
        allowed.process_exec_allowed = true;
        policy.tools.push(denied);
        policy.tools.push(allowed);

        let kdl = policy.to_kdl();
        assert!(kdl.contains("deny-all #true"), "got:\n{kdl}");
        assert!(kdl.contains("deny-all #false"), "got:\n{kdl}");
        assert!(
            !kdl.contains("deny-all=#true") && !kdl.contains("deny-all=#false"),
            "assignment syntax must not be used, got:\n{kdl}"
        );

        let parsed = crate::policy::kdl_loader::parse_kdl_policy(&kdl).expect("to_kdl round-trip");
        let denied = parsed
            .tools
            .iter()
            .find(|t| t.name == "denied_exec")
            .expect("denied_exec");
        assert!(denied.process_explicit);
        assert!(!denied.process_exec_allowed);
        let allowed = parsed
            .tools
            .iter()
            .find(|t| t.name == "allowed_exec")
            .expect("allowed_exec");
        assert!(allowed.process_explicit);
        assert!(allowed.process_exec_allowed);
    }

    #[test]
    fn inherited_syscalls_are_not_emitted_and_output_validates() {
        let kdl = r#"
            policy version=1
            defaults {
                syscalls {
                    allow "read" "write"
                }
            }
            server "svc" {
                tool "read_file"
            }
        "#;
        let policy = crate::policy::kdl_loader::parse_kdl_policy(kdl).unwrap();
        let tool = &policy.tools[0];
        // The tool inherits global syscall defaults without declaring its own.
        assert!(tool.syscalls.is_some());
        assert!(!tool.syscalls_explicit);

        let emitted = policy.to_kdl();
        // Only the defaults-level syscalls block may appear; a per-tool
        // syscalls block would fail validation on reload.
        assert_eq!(emitted.matches("syscalls").count(), 1, "got:\n{emitted}");

        let reparsed =
            crate::policy::kdl_loader::parse_kdl_policy(&emitted).expect("to_kdl re-parse");
        assert!(!reparsed.tools[0].syscalls_explicit);
        crate::policy::validator::validate_policy(&reparsed).expect("to_kdl output validates");
    }
}
