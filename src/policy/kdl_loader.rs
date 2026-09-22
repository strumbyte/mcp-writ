use std::collections::HashSet;
use std::path::Path;

use super::Policy;
use crate::error::PolicyError;
use crate::execution::ExecutionTarget;

pub use super::kdl_parse::{parse_kdl_policy, parse_kdl_policy_with_profiles};

/// Load a KDL policy file from disk, process extends/include/when directives,
/// and validate for the OS this process runs on.
///
/// This is the native-compatibility entry point: it validates against the OS
/// this process runs on. The in-guest runner goes through
/// [`super::loader::load_policy_for_target`] with `ExecutionTarget::native()`,
/// which lands here — so a host-supplied target name can never stand in for
/// guest-side checking. Use [`load_kdl_policy_for_target`] when the workload
/// runs under another OS.
pub fn load_kdl_policy(path: &Path) -> Result<Policy, PolicyError> {
    let env = std::env::var("MCP_WRIT_ENV").unwrap_or_default();
    load_kdl_policy_for_target(path, &env, &ExecutionTarget::native())
}

/// Load a KDL policy file with an explicit environment value for `when` evaluation.
/// This avoids reading MCP_WRIT_ENV from the process environment, making it
/// safe for concurrent test execution. Validates for the host OS.
pub fn load_kdl_policy_with_env(path: &Path, env: &str) -> Result<Policy, PolicyError> {
    load_kdl_policy_for_target(path, env, &ExecutionTarget::native())
}

/// Load a KDL policy file, process extends/include/when directives, and
/// validate against an explicit execution target.
///
/// Inheritance and `when` resolution are target-independent; validation
/// runs once on the fully merged policy, so inherited constraints are
/// checked under `target.workload_os` — never the build host's OS unless
/// the target says so.
pub fn load_kdl_policy_for_target(
    path: &Path,
    env: &str,
    target: &ExecutionTarget,
) -> Result<Policy, PolicyError> {
    let mut visited = HashSet::new();
    let policy = super::kdl_inherit::load_kdl_policy_internal(path, &mut visited, env)?;
    super::validator::validate_policy_for_target(&policy, target)?;
    Ok(policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{InputResponsesMode, TransportType};

    #[test]
    fn test_minimal_kdl_policy() {
        let kdl = r#"
            policy version=1
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.tools.is_empty());
        assert!(matches!(policy.transport.type_, TransportType::Stdio));
    }

    #[test]
    fn test_missing_policy_node() {
        let kdl = "// empty document\n";
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("missing 'policy' node"));
    }

    #[test]
    fn test_missing_version() {
        let kdl = r#"policy"#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn test_invalid_kdl_syntax() {
        let kdl = "{{invalid";
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(matches!(err, PolicyError::KdlParse(_)));
    }

    #[test]
    fn test_defaults_section() {
        let kdl = r#"
            policy version=1

            defaults {
                filesystem {
                    allow "/usr/lib/**" mode="read"
                    allow "/workspace/**" mode="write"
                }
                syscalls {
                    allow "read" "write" "openat" "close"
                }
                network {
                    allow host="api.example.com"
                    deny host="*"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.fs.read_only, vec!["/usr/lib/**"]);
        assert_eq!(policy.fs.read_write, vec!["/workspace/**"]);
        assert_eq!(
            policy.syscalls.allowed,
            vec!["read", "write", "openat", "close"]
        );
        assert_eq!(policy.network.outbound.allowed, vec!["api.example.com"]);
        assert!(policy.network.outbound.deny_all_others);
    }

    #[test]
    fn test_defaults_network_specific_denied_hosts() {
        let kdl = r#"
            policy version=1

            defaults {
                network {
                    allow host="api.example.com"
                    deny host="malicious.com"
                    deny host="evil.org"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.network.outbound.allowed, vec!["api.example.com"]);
        assert_eq!(
            policy.network.outbound.denied_hosts,
            vec!["malicious.com", "evil.org"]
        );
        // Secure by default: deny_all_others is true even without explicit `deny host="*"`
        assert!(policy.network.outbound.deny_all_others);
    }

    #[test]
    fn test_server_with_tools() {
        let kdl = r#"
            policy version=1

            server "mcp-filesystem" {
                tool "read_file" {
                    filesystem {
                        allow "/workspace/**"
                        deny "/home/*/.ssh/**"
                    }
                }
                tool "write_file" {
                    filesystem {
                        allow "/workspace/output/**"
                    }
                }
                tool "exec_shell" deny=#true
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 3);

        assert_eq!(policy.tools[0].name, "read_file");
        assert!(policy.tools[0].allowed);
        let fs = policy.tools[0].fs.as_ref().unwrap();
        assert_eq!(fs.allowed_paths, vec!["/workspace/**"]);
        assert_eq!(fs.denied_paths, vec!["/home/*/.ssh/**"]);

        assert_eq!(policy.tools[1].name, "write_file");
        assert!(policy.tools[1].allowed);

        assert_eq!(policy.tools[2].name, "exec_shell");
        assert!(!policy.tools[2].allowed);
    }

    #[test]
    fn test_multiple_servers() {
        let kdl = r#"
            policy version=1

            server "mcp-filesystem" {
                tool "read_file" {
                    filesystem {
                        allow "/workspace/**"
                    }
                }
            }

            server "mcp-github" {
                tool "search_repositories"
                tool "create_issue"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 3);
        assert_eq!(policy.tools[0].name, "read_file");
        assert_eq!(policy.tools[1].name, "search_repositories");
        assert_eq!(policy.tools[2].name, "create_issue");
    }

    #[test]
    fn test_version_out_of_range() {
        let kdl = "policy version=-1\n";
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("out of range"));
    }

    #[test]
    fn test_tool_without_children_is_allowed() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "simple_tool"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 1);
        assert!(policy.tools[0].allowed);
        assert!(policy.tools[0].fs.is_none());
    }

    #[test]
    fn test_no_defaults_gives_empty() {
        let kdl = "policy version=1\n";
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.fs.read_only.is_empty());
        assert!(policy.fs.read_write.is_empty());
        assert!(policy.syscalls.allowed.is_empty());
        assert!(policy.network.outbound.allowed.is_empty());
        assert!(policy.network.outbound.denied_hosts.is_empty());
    }

    #[test]
    fn test_confused_deputy_protection() {
        let kdl = r#"
            policy version=1
            confused_deputy_protection #true
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.confused_deputy_protection);
    }

    #[test]
    fn test_trajectory_omitted_defaults_off() {
        let kdl = r#"
            policy version=1
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(!policy.trajectory);
        assert!(policy.trajectory_rules.is_empty());
    }

    #[test]
    fn test_trajectory_true_parses_after_rules() {
        let kdl = r#"
            policy version=1
            trajectory #true {
                after side_effect="read_only" deny-next="network"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.trajectory);
        assert_eq!(policy.trajectory_rules.len(), 1);
        assert_eq!(
            policy.trajectory_rules[0].after_side_effect,
            crate::policy::SideEffect::ReadOnly
        );
        assert_eq!(
            policy.trajectory_rules[0].deny_next,
            crate::policy::SideEffect::Network
        );
    }

    #[test]
    fn test_trajectory_property_order_does_not_change_parsed_rules() {
        let a = r#"
            policy version=1
            trajectory #true {
                after side_effect="read_only" deny-next="network"
            }
        "#;
        let b = r#"
            policy version=1
            trajectory #true {
                after deny-next="network" side_effect="read_only"
            }
        "#;
        let pa = parse_kdl_policy(a).unwrap();
        let pb = parse_kdl_policy(b).unwrap();
        assert_eq!(pa.trajectory, pb.trajectory);
        assert_eq!(pa.trajectory_rules, pb.trajectory_rules);
    }

    #[test]
    fn test_trajectory_unknown_child_is_load_error() {
        let kdl = r#"
            policy version=1
            trajectory #true {
                maybe side_effect="read_only" deny-next="network"
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(
            err.to_string().contains("unknown trajectory child"),
            "got: {err}"
        );
    }

    #[test]
    fn test_trajectory_unknown_deny_next_is_load_error() {
        let kdl = r#"
            policy version=1
            trajectory #true {
                after side_effect="read_only" deny-next="exfiltrate"
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("deny-next"), "got: {err}");
    }

    #[test]
    fn test_tool_syscalls_subpolicy() {
        let kdl = r#"
            policy version=1
            server "test-server" {
                tool "read_file" side_effect="read_only" {
                    syscalls {
                        allow "read" "openat" "fstat"
                        deny "execve" "fork"
                    }
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 1);
        let sc = policy.tools[0].syscalls.as_ref().unwrap();
        assert_eq!(sc.allowed, vec!["read", "openat", "fstat"]);
        assert_eq!(sc.denied, vec!["execve", "fork"]);
    }

    #[test]
    fn test_tool_network_subpolicy() {
        let kdl = r#"
            policy version=1
            server "test-server" {
                tool "fetch_url" {
                    network {
                        allow host="api.example.com"
                        allow host="cdn.example.com"
                        deny host="*.internal.corp"
                    }
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 1);
        let net = policy.tools[0].network.as_ref().unwrap();
        assert_eq!(
            net.allowed_hosts,
            vec!["api.example.com", "cdn.example.com"]
        );
        assert_eq!(net.denied_hosts, vec!["*.internal.corp"]);
    }

    #[test]
    fn test_tool_all_subpolicies_combined() {
        let kdl = r##"
            policy version=1
            server "mcp-filesystem" {
                tool "read_file" side_effect="read_only" {
                    filesystem {
                        allow "/workspace/**"
                        deny "/home/*/.ssh/**"
                    }
                    syscalls {
                        allow "read" "openat" "fstat"
                    }
                    network {
                        deny host="*"
                    }
                }
            }
        "##;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 1);
        let tool = &policy.tools[0];

        // filesystem
        let fs = tool.fs.as_ref().unwrap();
        assert_eq!(fs.allowed_paths, vec!["/workspace/**"]);
        assert_eq!(fs.denied_paths, vec!["/home/*/.ssh/**"]);

        // syscalls
        let sc = tool.syscalls.as_ref().unwrap();
        assert_eq!(sc.allowed, vec!["read", "openat", "fstat"]);
        assert!(sc.denied.is_empty());

        // network
        let net = tool.network.as_ref().unwrap();
        assert!(net.allowed_hosts.is_empty());
        assert_eq!(net.denied_hosts, vec!["*"]);

        // side_effect
        assert_eq!(tool.side_effect.as_deref(), Some("read_only"));
    }

    #[test]
    fn test_tool_input_responses_modes() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "auto_tool"
                tool "deny_tool" input_responses="deny"
                tool "allow_tool" input_responses="allow"
                tool "inspect_tool" input_responses="inspect"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 4);
        assert_eq!(policy.tools[0].input_responses, InputResponsesMode::Auto);
        assert_eq!(policy.tools[0].input_responses.as_str(), "auto");
        assert_eq!(policy.tools[1].input_responses, InputResponsesMode::Deny);
        assert_eq!(policy.tools[1].input_responses.as_str(), "deny");
        assert_eq!(policy.tools[2].input_responses, InputResponsesMode::Allow);
        assert_eq!(policy.tools[2].input_responses.as_str(), "allow");
        assert_eq!(policy.tools[3].input_responses, InputResponsesMode::Inspect);
        assert_eq!(policy.tools[3].input_responses.as_str(), "inspect");
    }

    #[test]
    fn test_tool_input_responses_invalid_rejected() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "bad" input_responses="maybe"
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("input_responses"), "got: {err}");
    }

    #[test]
    fn test_tool_without_subpolicies_has_none() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "simple_tool"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 1);
        assert!(policy.tools[0].syscalls.is_none());
        let net = policy.tools[0].network.as_ref().unwrap();
        assert!(net.allow_specified);
        assert!(net.allowed_hosts.is_empty());
    }

    #[test]
    fn test_empty_subpolicy_blocks() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "some_tool" {
                    syscalls {}
                    network {}
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        let tool = &policy.tools[0];
        let sc = tool.syscalls.as_ref().unwrap();
        assert!(sc.allowed.is_empty());
        assert!(sc.denied.is_empty());
        let net = tool.network.as_ref().unwrap();
        assert!(net.allowed_hosts.is_empty());
        assert!(net.denied_hosts.is_empty());
    }

    #[test]
    fn test_partial_subpolicy_only_syscalls() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "restricted_tool" {
                    syscalls {
                        allow "read" "write"
                    }
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        let tool = &policy.tools[0];
        assert!(tool.syscalls.is_some());
        assert_eq!(
            tool.syscalls.as_ref().unwrap().allowed,
            vec!["read", "write"]
        );
        let net = tool.network.as_ref().unwrap();
        assert!(net.allow_specified);
        assert!(net.allowed_hosts.is_empty());
        assert!(tool.fs.is_none());
    }

    #[test]
    fn test_load_kdl_via_generic_loader() {
        // Verify that load_policy() auto-detects .kdl extension
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        let policy = crate::policy::loader::load_policy(&path)
            .expect("generic loader should handle .kdl files");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.tools.len(), 3);
    }

    #[test]
    fn test_full_policy_roundtrip() {
        let kdl = r##"
            policy version=1

            defaults {
                filesystem {
                    allow "/usr/lib/**" mode="read"
                }
                syscalls {
                    allow "read" "write" "openat" "close" "fstat" "stat"
                }
                network {
                    allow host="api.openai.com"
                    deny host="*"
                }
                environment {
                    allow "MEMORY_FILE_PATH" "API_KEY"
                }
            }

            server "mcp-filesystem" {
                tool "read_file" {
                    filesystem {
                        allow "/workspace/**"
                        deny "/home/*/.ssh/**"
                    }
                }
                tool "write_file" {
                    filesystem {
                        allow "/workspace/output/**"
                    }
                }
                tool "exec_shell" deny=#true
            }
        "##;
        let policy = parse_kdl_policy(kdl).unwrap();

        // Version
        assert_eq!(policy.version, 1);

        // Defaults
        assert_eq!(policy.fs.read_only, vec!["/usr/lib/**"]);
        assert_eq!(policy.syscalls.allowed.len(), 6);
        assert!(policy.network.outbound.deny_all_others);
        assert!(policy.environment.restrict);
        assert_eq!(
            policy.environment.allowed,
            vec!["MEMORY_FILE_PATH", "API_KEY"]
        );

        // Tools
        assert_eq!(policy.tools.len(), 3);
        assert!(policy.tools[0].allowed);
        assert!(!policy.tools[2].allowed);

        // Emit → re-parse must preserve the environment restriction.
        let reparsed = parse_kdl_policy(&policy.to_kdl()).expect("to_kdl output re-parses");
        assert_eq!(reparsed.environment, policy.environment);
    }

    // ── defaults.environment ──

    #[test]
    fn test_environment_node_enables_restriction() {
        let kdl = r#"
            policy version=1
            defaults {
                environment {
                    allow "MEMORY_FILE_PATH" "MY_FLAG"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.environment.restrict);
        assert_eq!(
            policy.environment.allowed,
            vec!["MEMORY_FILE_PATH", "MY_FLAG"]
        );
    }

    #[test]
    fn test_environment_absent_means_inherit() {
        let kdl = "policy version=1";
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(!policy.environment.restrict);
        assert!(policy.environment.allowed.is_empty());
    }

    #[test]
    fn test_environment_empty_block_still_restricts() {
        let kdl = r#"
            policy version=1
            defaults {
                environment {
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.environment.restrict);
        assert!(policy.environment.allowed.is_empty());
    }

    #[test]
    fn test_environment_rejects_non_allow_children() {
        let kdl = r#"
            policy version=1
            defaults {
                environment {
                    deny "SECRET"
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("environment"), "got: {err}");
    }

    #[test]
    fn test_environment_rejects_named_property() {
        let kdl = r#"
            policy version=1
            defaults {
                environment {
                    allow name="FOO"
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("property"), "got: {err}");
    }

    #[test]
    fn test_environment_rejects_allow_children() {
        let kdl = r#"
            policy version=1
            defaults {
                environment {
                    allow "FOO" {
                        nested "x"
                    }
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("children"), "got: {err}");
    }

    #[test]
    fn test_environment_rejects_empty_allow_children() {
        let kdl = r#"
            policy version=1
            defaults {
                environment {
                    allow "FOO" {}
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("children"), "got: {err}");
    }

    #[test]
    fn test_server_level_environment_is_rejected() {
        let kdl = r#"
            policy version=1
            server "s" {
                environment {
                    allow "SECRET"
                }
                tool "fetch"
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(
            err.to_string().contains("environment") && err.to_string().contains("defaults"),
            "got: {err}"
        );
    }

    // ── Problem 1 tests: deny_all_others secure default ──

    #[test]
    fn test_empty_network_block_denies_all() {
        let kdl = r#"
            policy version=1
            defaults {
                network {}
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        // Empty network block must still deny all (secure by default)
        assert!(policy.network.outbound.deny_all_others);
        assert!(policy.network.outbound.allowed.is_empty());
        assert!(policy.network.outbound.denied_hosts.is_empty());
    }

    #[test]
    fn test_explicit_deny_wildcard_still_denies_all() {
        let kdl = r#"
            policy version=1
            defaults {
                network {
                    allow host="api.example.com"
                    deny host="*"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        // Explicit deny host="*" is redundant but keeps deny_all_others: true
        assert!(policy.network.outbound.deny_all_others);
        assert_eq!(policy.network.outbound.allowed, vec!["api.example.com"]);
    }

    #[test]
    fn test_allow_wildcard_opens_network() {
        let kdl = r#"
            policy version=1
            defaults {
                network {
                    allow host="*"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        // allow host="*" explicitly opens network access
        assert!(!policy.network.outbound.deny_all_others);
        // Wildcard is not added to the allowed list (it controls deny_all flag)
        assert!(policy.network.outbound.allowed.is_empty());
    }

    // ── Problem 2 tests: server name preservation ──

    #[test]
    fn test_server_name_preserved_on_tools() {
        let kdl = r#"
            policy version=1
            server "mcp-filesystem" {
                tool "read_file"
                tool "write_file"
            }
            server "mcp-github" {
                tool "search_repos"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 3);

        assert_eq!(policy.tools[0].server.as_deref(), Some("mcp-filesystem"));
        assert_eq!(policy.tools[1].server.as_deref(), Some("mcp-filesystem"));
        assert_eq!(policy.tools[2].server.as_deref(), Some("mcp-github"));
    }

    #[test]
    fn test_same_tool_name_different_servers_are_distinct() {
        let kdl = r#"
            policy version=1
            server "server-a" {
                tool "read_file" {
                    filesystem {
                        allow "/a/**"
                    }
                }
            }
            server "server-b" {
                tool "read_file" {
                    filesystem {
                        allow "/b/**"
                    }
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 2);
        super::super::validator::validate_policy(&policy)
            .expect("distinct (server, name) identities");
        assert_eq!(policy.tools[0].server.as_deref(), Some("server-a"));
        assert_eq!(policy.tools[1].server.as_deref(), Some("server-b"));
    }

    // ── Problem 3 tests: logging level from KDL ──

    #[test]
    fn test_logging_level_from_kdl() {
        let kdl = r#"
            policy version=1
            logging level="debug"
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.logging.level, "debug");
    }

    #[test]
    fn test_logging_level_default_when_absent() {
        let kdl = r#"
            policy version=1
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.logging.level, "info");
    }

    #[test]
    fn test_logging_fail_closed_only() {
        let kdl = r#"
            policy version=1
            logging fail_closed=#false
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.logging.level, "info");
        assert!(!policy.logging.fail_closed);
    }

    #[test]
    fn test_tool_fs_allow_replaces_defaults() {
        let kdl = r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/tmp/**" mode="write"
                }
            }
            server "svc" {
                tool "write" {
                    filesystem {
                        allow "/workspace/**" mode="write"
                    }
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        let fs = policy.tools[0].fs.as_ref().unwrap();
        assert_eq!(fs.read_write_paths, vec!["/workspace/**"]);
        assert!(!fs.allowed_paths.iter().any(|p| p.contains("/tmp")));
    }

    #[test]
    fn test_wildcard_deny_removes_matching_allow() {
        let kdl = r#"
            policy version=1
            defaults {
                network {
                    allow host="api.example.com"
                    deny host="*.example.com"
                    deny host="*"
                }
            }
            server "svc" {
                tool "fetch"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        let net = policy.tools[0].network.as_ref().unwrap();
        assert!(
            !net.allowed_hosts.iter().any(|h| h == "api.example.com"),
            "wildcard deny must drop api.example.com, got {:?}",
            net.allowed_hosts
        );
    }

    // ════════════════════════════════════════════════════════════
    // hash entry parsing tests
    // ════════════════════════════════════════════════════════════

    const H64A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_binary_hash_parsed() {
        let kdl = format!(
            r#"
            policy version=1
            server "my-server" {{
                tool "read_file"
                binary-hash "{H64A}" {{
                    target "/usr/local/bin/mcp-server"
                    approved "2026-02-20"
                }}
            }}
        "#
        );
        let policy = parse_kdl_policy(&kdl).unwrap();
        assert_eq!(policy.hash_entries.len(), 1);
        let entry = &policy.hash_entries[0];
        assert_eq!(entry.server_name, "my-server");
        assert_eq!(entry.hash_type, super::super::HashType::Binary);
        assert_eq!(entry.hash_value, H64A);
        assert_eq!(entry.target, "/usr/local/bin/mcp-server");
        assert_eq!(entry.approved.as_deref(), Some("2026-02-20"));
    }

    #[test]
    fn test_lockfile_and_entrypoint_hash_parsed() {
        let kdl = r#"
            policy version=1
            server "node-server" {
                tool "run"
                lockfile-hash "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" {
                    target "package-lock.json"
                }
                entrypoint-hash "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" {
                    target "dist/index.js"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.hash_entries.len(), 2);

        let lf = policy
            .hash_entries
            .iter()
            .find(|e| e.hash_type == super::super::HashType::Lockfile)
            .unwrap();
        assert_eq!(
            lf.hash_value,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        );
        assert_eq!(lf.target, "package-lock.json");
        assert!(lf.approved.is_none());

        let ep = policy
            .hash_entries
            .iter()
            .find(|e| e.hash_type == super::super::HashType::Entrypoint)
            .unwrap();
        assert_eq!(
            ep.hash_value,
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        );
        assert_eq!(ep.target, "dist/index.js");
    }

    #[test]
    fn test_no_hash_entries_when_absent() {
        let kdl = r#"
            policy version=1
            server "simple" {
                tool "read_file"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.hash_entries.is_empty());
    }

    #[test]
    fn test_multiple_servers_with_hashes() {
        let kdl = r#"
            policy version=1
            server "server-a" {
                tool "tool_a"
                binary-hash "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
                    target "/bin/a"
                }
            }
            server "server-b" {
                tool "tool_b"
                binary-hash "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
                    target "/bin/b"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.hash_entries.len(), 2);
        assert_eq!(policy.hash_entries[0].server_name, "server-a");
        assert_eq!(policy.hash_entries[1].server_name, "server-b");
    }

    #[test]
    fn test_hash_entry_without_target_children() {
        let kdl = r#"
            policy version=1
            server "compact" {
                tool "run"
                binary-hash "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(
            err.to_string().contains("requires a non-empty target"),
            "got {err}"
        );
    }

    #[test]
    fn test_unknown_hash_node_is_rejected() {
        let kdl = r#"
            policy version=1
            server "s" {
                tool "run"
                binry-hash "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
                    target "/bin/s"
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(
            err.to_string().contains("unknown hash node 'binry-hash'"),
            "got {err}"
        );
    }

    #[test]
    fn test_hash_entries_default_empty() {
        let kdl = "policy version=1\n";
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.hash_entries.is_empty());
    }

    // ─── tools-list-hash tests ──────────────────────────────────────────────

    #[test]
    fn test_tools_list_hash_parsed() {
        let kdl = r#"
            policy version=1
            server "my-server" {
                tool "read_file"
                tools-list-hash "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" approved="2026-02-20T10:30:00Z"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools_list_hashes.len(), 1);
        let entry = &policy.tools_list_hashes[0];
        assert_eq!(entry.server_name, "my-server");
        assert_eq!(
            entry.hash_value,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
    }

    #[test]
    fn test_tools_list_hash_without_approved() {
        let kdl = r#"
            policy version=1
            server "my-server" {
                tool "read_file"
                tools-list-hash "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools_list_hashes.len(), 1);
        let entry = &policy.tools_list_hashes[0];
        assert_eq!(
            entry.hash_value,
            "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert!(entry.approved.is_none());
    }

    #[test]
    fn test_tools_list_hash_multiple_servers() {
        let kdl = r#"
            policy version=1
            server "server-a" {
                tool "tool_a"
                tools-list-hash "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
            server "server-b" {
                tool "tool_b"
                tools-list-hash "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools_list_hashes.len(), 2);
        assert_eq!(policy.tools_list_hashes[0].server_name, "server-a");
        assert_eq!(policy.tools_list_hashes[1].server_name, "server-b");
    }

    #[test]
    fn test_tools_list_hash_default_empty() {
        let kdl = "policy version=1\n";
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.tools_list_hashes.is_empty());
    }

    #[test]
    fn test_tools_list_hash_absent_in_server() {
        let kdl = r#"
            policy version=1
            server "simple" {
                tool "read_file"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.tools_list_hashes.is_empty());
    }

    // ─── 4-stage merge & profile resolution tests ───────────────────────

    #[test]
    fn test_f02_four_stage_merge_via_loader() {
        let kdl = r#"
            policy version=1

            defaults {
                filesystem {
                    allow "/usr/lib/**" mode="read"
                }
                syscalls {
                    allow "read" "write" "openat"
                }
            }

            profile "restricted" {
                filesystem {
                    allow "/workspace/**" mode="write"
                    deny "/secret/**"
                }
            }

            server "test-server" {
                server-defaults {
                    network {
                        allow host="api.example.com"
                        deny host="evil.com"
                    }
                }

                tool "read_file" profile="restricted" {
                    filesystem {
                        allow "/workspace/docs/**" mode="read"
                    }
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.tools.len(), 1);
        let tool = &policy.tools[0];
        assert_eq!(tool.name, "read_file");
        assert!(tool.allowed);

        let fs = tool
            .fs
            .as_ref()
            .expect("fs sub-policy must be populated from 4-stage merge");
        // Tool overrode allowed_paths with "/workspace/docs/**"
        assert_eq!(fs.allowed_paths, vec!["/workspace/docs/**"]);
        // Denied accumulated from profile: "/secret/**"
        assert_eq!(fs.denied_paths, vec!["/secret/**"]);

        let sc = tool
            .syscalls
            .as_ref()
            .expect("syscalls must inherit from defaults");
        assert_eq!(sc.allowed, vec!["read", "write", "openat"]);

        let net = tool
            .network
            .as_ref()
            .expect("network must inherit from server-defaults");
        assert_eq!(net.allowed_hosts, vec!["api.example.com"]);
        assert_eq!(net.denied_hosts, vec!["evil.com"]);
    }

    #[test]
    fn test_f02_unknown_profile_rejected() {
        let kdl = r#"
            policy version=1
            server "test-server" {
                tool "read_file" profile="nonexistent"
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("unknown profile 'nonexistent'"));
    }

    // ─── Strict type validation tests ───────────────────────────────────

    #[test]
    fn test_f16_deny_string_rejected() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "exec" deny="true"
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(
            err.to_string()
                .contains("'deny' property on tool 'exec' must be a boolean")
        );
    }

    #[test]
    fn test_f16_args_schema_non_string_rejected() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "exec" args_schema=123
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(
            err.to_string()
                .contains("'args_schema' property on tool 'exec' must be a string")
        );
    }

    #[test]
    fn test_r14_fs_allow_non_string_rejected() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "read_file" {
                    filesystem {
                        allow 123
                    }
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("must be a string"));
    }

    #[test]
    fn test_r14_fs_allow_invalid_mode_rejected() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "read_file" {
                    filesystem {
                        allow "/workspace/**" mode="execute"
                    }
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("invalid mode 'execute'"));
    }

    #[test]
    fn test_r14_network_host_non_string_rejected() {
        let kdl = r#"
            policy version=1
            server "test" {
                tool "fetch" {
                    network {
                        allow host=123
                    }
                }
            }
        "#;
        let err = parse_kdl_policy(kdl).unwrap_err();
        assert!(err.to_string().contains("must be a string"));
    }

    #[test]
    fn test_r11_property_style_hashes_parsed() {
        let kdl = r#"
            policy version=1
            server "test" {
                binary-hash "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" target="/app/binary" approved="security-lead"
                tools-list-hash "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" approved="audit-team"
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(policy.hash_entries.len(), 1);
        assert_eq!(
            policy.hash_entries[0].hash_value,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert_eq!(policy.hash_entries[0].target, "/app/binary");
        assert_eq!(
            policy.hash_entries[0].approved.as_deref(),
            Some("security-lead")
        );

        assert_eq!(policy.tools_list_hashes.len(), 1);
        assert_eq!(
            policy.tools_list_hashes[0].hash_value,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_eq!(
            policy.tools_list_hashes[0].approved.as_deref(),
            Some("audit-team")
        );
    }

    #[test]
    fn test_secret_overlay_defaults_on() {
        let kdl = r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/workspace/**" mode="write"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(policy.fs.secret_overlay);
    }

    #[test]
    fn test_secret_overlay_can_be_disabled() {
        let kdl = r#"
            policy version=1
            defaults {
                filesystem {
                    secret-overlay #false
                    allow "/workspace/**" mode="write"
                }
            }
        "#;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert!(!policy.fs.secret_overlay);
    }
}
