use super::*;
use crate::policy::kdl_loader::{load_kdl_policy, load_kdl_policy_with_env, parse_kdl_policy};

#[test]
fn test_load_example_kdl_file() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
    let policy = load_kdl_policy(&path).expect("Failed to load policy.example.kdl");
    assert_eq!(policy.version, 2);
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
        err.to_string().contains("process execution") || err.to_string().contains("side_effect"),
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
        err.to_string().contains("process execution") || err.to_string().contains("side_effect"),
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
fn test_extends_environment_empty_overlay_replaces_base_list() {
    // A declared `environment {}` is authoritative: the base's allow
    // list is replaced even by an empty one. Restriction itself can
    // still not be removed via extends.
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
    assert!(policy.environment.allowed.is_empty());
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
fn test_include_when_environment_empty_overlay_replaces() {
    // `environment {}` declared via a matching `when` inside an
    // included file stays authoritative across the merge — the empty
    // allow list replaces the inherited one instead of being read as
    // "nothing declared" and silently widened back to the base's list.
    let dir = make_test_dir("inc_when_env_empty");
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
        dir.join("layer.kdl"),
        r#"
            policy version=1
            when environment="production" {
                defaults {
                    environment {
                    }
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            extends "base.kdl"
            include "layer.kdl"
        "#,
    )
    .unwrap();

    let prod = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
    assert!(prod.environment.restrict);
    assert!(
        prod.environment.allowed.is_empty(),
        "empty environment from an included when must replace: {:?}",
        prod.environment.allowed
    );

    // The `when` never matched here — the inherited list survives.
    let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    assert_eq!(dev.environment.allowed, vec!["A", "B"]);
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
        err.to_string().contains("only allowed under 'defaults'"),
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
        err.to_string().contains("only allowed under 'defaults'"),
        "got: {err}"
    );
}

#[test]
fn test_when_server_defaults_environment_is_rejected() {
    // `environment` inside a `when` block's server-defaults must fail to
    // load instead of being silently ignored.
    let dir = make_test_dir("when_sd_env");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "s1" {
                tool "fetch"
            }
            when environment="production" {
                server "s1" {
                    server-defaults {
                        environment {
                            allow "SECRET"
                        }
                    }
                    tool "fetch"
                }
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
    assert!(
        err.to_string().contains("environment"),
        "server-defaults environment in when must fail to load: {err}"
    );
    load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
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

// ── mcp passage rules (schema v2) ─────────────────────────────

use crate::policy::mcp::{RuleEffect, RuleKind};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

const V25: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2025November25;
const V26: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2026July28;
const C2S: MessageDirection = MessageDirection::ClientToServer;
const S2C: MessageDirection = MessageDirection::ServerToClient;

fn mcp_atom<'a>(
    atoms: &'a std::collections::BTreeMap<
        crate::policy::mcp::RuleKey,
        crate::policy::mcp::ResolvedRule,
    >,
    version: SupportedProtocolVersion,
    direction: MessageDirection,
    kind: RuleKind,
    method: &str,
) -> &'a crate::policy::mcp::ResolvedRule {
    atoms
        .iter()
        .find(|(k, _)| {
            k.version == version && k.direction == direction && k.kind == kind && k.method == method
        })
        .map(|(_, r)| r)
        .unwrap_or_else(|| panic!("missing atom {version:?}/{direction:?}/{kind:?}/{method}"))
}

#[test]
fn test_v2_mcp_block_parses_into_rule_atoms() {
    let policy = parse_kdl_policy(
        r#"
            policy version=2
            server "s1" {
                tool "t"
                mcp {
                    allow "resources/read" {
                        uri "file:///docs/a.txt"
                    }
                    deny "sampling/createMessage"
                }
            }
        "#,
    )
    .unwrap();

    assert_eq!(policy.mcp_rules.len(), 1);
    let entry = &policy.mcp_rules[0];
    assert_eq!(entry.server_name.as_deref(), Some("s1"));

    let atoms = entry.resolved();
    // resources/read: C2S request in both revisions.
    for v in [V25, V26] {
        let r = mcp_atom(atoms, v, C2S, RuleKind::Request, "resources/read");
        assert_eq!(r.effect, RuleEffect::Allow);
        assert_eq!(r.uris, vec!["file:///docs/a.txt".to_string()]);
    }
    // sampling/createMessage: 2025 S2C request, 2026 additional request.
    let r = mcp_atom(atoms, V25, S2C, RuleKind::Request, "sampling/createMessage");
    assert_eq!(r.effect, RuleEffect::Deny);
    let r = mcp_atom(
        atoms,
        V26,
        S2C,
        RuleKind::AdditionalRequest,
        "sampling/createMessage",
    );
    assert_eq!(r.effect, RuleEffect::Deny);
    assert!(r.uris.is_empty() && r.filters.is_empty());
}

#[test]
fn test_mcp_protocol_and_direction_restrictions() {
    let policy = parse_kdl_policy(
        r#"
            policy version=2
            server "s1" {
                tool "t"
                mcp {
                    allow "resources/read" protocol="2026-07-28"
                    deny "ping" direction="s2c"
                }
            }
        "#,
    )
    .unwrap();
    let atoms = policy.mcp_rules[0].resolved();
    // protocol= restricted expansion to the 2026 slot only.
    assert_eq!(atoms.len(), 2);
    mcp_atom(atoms, V26, C2S, RuleKind::Request, "resources/read");
    mcp_atom(atoms, V25, S2C, RuleKind::Request, "ping");
}

#[test]
fn test_v1_server_mcp_block_is_rejected() {
    let err = parse_kdl_policy(
        r#"
            policy version=1
            server "s1" {
                tool "t"
                mcp {
                    allow "resources/read"
                }
            }
        "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("version=2"), "got: {err}");
}

#[test]
fn test_misplaced_mcp_block_is_rejected() {
    // `mcp` only takes effect directly under `server`; anywhere else
    // it would be silently ignored, so placement is a load error in
    // either schema version.
    let docs = [
        // document root
        "policy version=2\nmcp { allow \"ping\" }",
        // under defaults / profile / server-defaults
        "policy version=2\ndefaults { mcp { allow \"ping\" } }",
        "policy version=2\nprofile \"p\" { mcp { allow \"ping\" } }",
        "policy version=2\nserver \"s\" {\n  server-defaults { mcp { allow \"ping\" } }\n}",
        // v1 tolerates unknown tool children, but `mcp` is reserved.
        "policy version=1\nserver \"s\" {\n  tool \"t\" { mcp { allow \"ping\" } }\n}",
        // a `server` not at document root is never read
        "policy version=2\nserver \"s\" {\n  server \"x\" { mcp { allow \"ping\" } }\n}",
        // directly under `when` — only `server` there may hold `mcp`
        "policy version=2\nwhen environment=\"prod\" {\n  mcp { allow \"ping\" }\n}",
        // inside a nested `when`, which is never evaluated
        "policy version=2\nwhen environment=\"prod\" {\n  when environment=\"prod\" {\n    server \"s\" { mcp { allow \"ping\" } }\n  }\n}",
        // under `defaults` inside `when`
        "policy version=2\nwhen environment=\"prod\" {\n  defaults { mcp { allow \"ping\" } }\n}",
    ];
    for doc in docs {
        let err = parse_kdl_policy(doc).unwrap_err();
        assert!(
            err.to_string()
                .contains("only valid as a direct child of a 'server' node"),
            "doc `{doc}`: got: {err}"
        );
    }

    // Same rule through the file-loading `when` path (env matched).
    let dir = make_test_dir("mcp_when_misplaced");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            when environment="prod" {
                mcp {
                    allow "ping"
                }
            }
        "#,
    )
    .unwrap();
    let err =
        load_kdl_policy_internal(&dir.join("policy.kdl"), &mut HashSet::new(), "prod").unwrap_err();
    assert!(
        err.to_string()
            .contains("only valid as a direct child of a 'server' node"),
        "got: {err}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_v2_tool_unknown_members_are_load_errors() {
    // Unknown property: rejected in v2, silently ignored in v1.
    let err = parse_kdl_policy(
        r#"
            policy version=2
            server "s1" {
                tool "t" bogus="x"
            }
        "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unknown property"), "got: {err}");
    parse_kdl_policy(
        r#"
            policy version=1
            server "s1" {
                tool "t" bogus="x"
            }
        "#,
    )
    .expect("v1 tolerates unknown tool properties");

    // Unknown child node: rejected in v2.
    let err = parse_kdl_policy(
        r#"
            policy version=2
            server "s1" {
                tool "t" {
                    telemetry {}
                }
            }
        "#,
    )
    .unwrap_err();
    assert!(err.to_string().contains("unexpected node"), "got: {err}");
}

#[test]
fn test_mcp_rule_load_errors() {
    let cases: &[(&str, &str)] = &[
        // Unknown method — the ledger is closed.
        (r#"allow "experimental/tasks""#, "unknown MCP method"),
        // Unknown protocol revision.
        (
            r#"allow "tools/list" protocol="2030-01-01""#,
            "unknown protocol revision",
        ),
        // Unknown direction.
        (
            r#"allow "tools/list" direction="north""#,
            "unknown direction",
        ),
        // protocol= filtering leaves no valid atom.
        (
            r#"allow "initialize" protocol="2026-07-28""#,
            "no valid rule-key combination",
        ),
        // Unexpected property.
        (r#"allow "tools/list" scope="wide""#, "unexpected property"),
        // uri on a deny rule.
        (r#"deny "resources/read" { uri "file:///x" }"#, "deny rule"),
        // uri on a method that takes none.
        (r#"allow "tools/list" { uri "file:///x" }"#, "only valid on"),
        // filter on a method that takes none.
        (
            r#"allow "tools/list" { filter "toolsListChanged" }"#,
            "only valid on subscriptions/listen",
        ),
        // Unknown filter name.
        (
            r#"allow "subscriptions/listen" { filter "bogus" }"#,
            "unknown filter",
        ),
        // uri on subscriptions/listen requires the resourceSubscriptions filter.
        (
            r#"allow "subscriptions/listen" { uri "file:///x" }"#,
            "resourceSubscriptions",
        ),
    ];
    for (rule, needle) in cases {
        let doc = format!(
            "policy version=2\nserver \"s1\" {{\n  tool \"t\"\n  mcp {{\n    {rule}\n  }}\n}}\n"
        );
        let err = parse_kdl_policy(&doc).unwrap_err();
        assert!(
            err.to_string().contains(needle),
            "rule `{rule}`: expected '{needle}', got: {err}"
        );
    }

    // Two rules covering the same atom in one document.
    let err = parse_kdl_policy(
        r#"
            policy version=2
            server "s1" {
                tool "t"
                mcp {
                    allow "resources/read"
                    deny "resources/read" protocol="2025-11-25"
                }
            }
        "#,
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("conflicting mcp rules"),
        "got: {err}"
    );
}

#[test]
fn test_mcp_rules_include_union_and_deny_precedence() {
    let dir = make_test_dir("mcp_include");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=2
            server "s1" {
                mcp {
                    deny "resources/read" protocol="2026-07-28"
                    allow "prompts/list"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            include "extra.kdl"
            server "s1" {
                tool "t"
                mcp {
                    allow "resources/read"
                }
            }
        "#,
    )
    .unwrap();

    // The internal loader parses+merges without the post-merge
    // validation gate, so the raw `mcp_rules` atoms stay inspectable.
    let policy =
        load_kdl_policy_internal(&dir.join("policy.kdl"), &mut HashSet::new(), "").unwrap();
    let atoms = policy.mcp_rules[0].resolved();
    // Cross-document atom overlap resolves deny-first; disjoint atoms union.
    assert_eq!(
        mcp_atom(atoms, V26, C2S, RuleKind::Request, "resources/read").effect,
        RuleEffect::Deny
    );
    assert_eq!(
        mcp_atom(atoms, V25, C2S, RuleKind::Request, "resources/read").effect,
        RuleEffect::Allow
    );
    mcp_atom(atoms, V25, C2S, RuleKind::Request, "prompts/list");
    mcp_atom(atoms, V26, C2S, RuleKind::Request, "prompts/list");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_mcp_rules_when_block_unions_per_server() {
    let dir = make_test_dir("mcp_when");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            server "s1" {
                tool "t"
                mcp {
                    allow "resources/read"
                }
            }
            when environment="prod" {
                server "s1" {
                    mcp {
                        deny "resources/read" protocol="2026-07-28"
                    }
                }
            }
        "#,
    )
    .unwrap();

    // Matching env: the when-block rules merge in, deny wins on overlap.
    let policy =
        load_kdl_policy_internal(&dir.join("policy.kdl"), &mut HashSet::new(), "prod").unwrap();
    let atoms = policy.mcp_rules[0].resolved();
    assert_eq!(
        mcp_atom(atoms, V26, C2S, RuleKind::Request, "resources/read").effect,
        RuleEffect::Deny
    );
    assert_eq!(
        mcp_atom(atoms, V25, C2S, RuleKind::Request, "resources/read").effect,
        RuleEffect::Allow
    );

    // Non-matching env: only the base rules.
    let policy =
        load_kdl_policy_internal(&dir.join("policy.kdl"), &mut HashSet::new(), "dev").unwrap();
    let atoms = policy.mcp_rules[0].resolved();
    assert_eq!(
        mcp_atom(atoms, V26, C2S, RuleKind::Request, "resources/read").effect,
        RuleEffect::Allow
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_mcp_rules_bind_to_server() {
    let policy = parse_kdl_policy(
        r#"
            policy version=2
            server "s1" {
                tool "a"
                mcp {
                    allow "resources/read"
                }
            }
            server "s2" {
                tool "b"
                mcp {
                    deny "resources/read"
                }
            }
        "#,
    )
    .unwrap();
    assert_eq!(
        policy.declared_servers(),
        vec!["s1".to_string(), "s2".to_string()]
    );

    let bound = policy.bind_to_server(Some("s1")).unwrap();
    assert_eq!(bound.mcp_rules.len(), 1);
    assert_eq!(bound.mcp_rules[0].server_name.as_deref(), Some("s1"));
    assert_eq!(
        mcp_atom(
            bound.mcp_rules[0].resolved(),
            V25,
            C2S,
            RuleKind::Request,
            "resources/read"
        )
        .effect,
        RuleEffect::Allow
    );

    // The other server's rules are gone; its methods get no atoms.
    assert!(bound.bind_to_server(Some("s2")).is_err());
}

#[test]
fn test_v1_policy_rejects_mcp_rules_via_validator() {
    // A programmatically-built v1 policy carrying mcp rules must be
    // refused even though the KDL path can never produce it.
    let mut policy = parse_kdl_policy("policy version=1").unwrap();
    policy
        .mcp_rules
        .push(crate::policy::mcp::ServerMcpRules::new(
            Some("s1".into()),
            vec![],
        ));
    let err = crate::policy::validator::validate_policy(&policy).unwrap_err();
    assert!(err.to_string().contains("version=2"), "got: {err}");
}

// ── deputy roles & extraction rules (v2) ─────────────────────

use crate::policy::deputy::{DeputyRole, DeputyRule, KnownShape};

const DEPUTY_DOC: &str = r#"
    policy version=2
    confused_deputy_protection #true
    server "s" {
        tool "ls" {
            deputy role="discover" {
                shape "mcp_list_result"
                extract "/result/files/*/path"
            }
        }
        tool "cat" {
            deputy role="use" {
                shape "fs_targets"
                extract "/params/arguments/path"
            }
        }
    }
"#;

#[test]
fn test_deputy_block_parses_roles_and_rules() {
    let policy = parse_kdl_policy(DEPUTY_DOC).unwrap();
    let ls = &policy.tools[0];
    let dep = ls.deputy.as_ref().expect("ls has a deputy block");
    assert_eq!(dep.role, DeputyRole::Discover);
    assert_eq!(dep.rules.len(), 2);
    assert!(matches!(
        dep.rules[0],
        DeputyRule::Shape(KnownShape::McpListResult)
    ));
    match &dep.rules[1] {
        DeputyRule::Pointer(p) => {
            assert_eq!(p.source, "/result/files/*/path");
            assert_eq!(p.root_segment(), "result");
            assert!(!p.split_lines);
        }
        other => panic!("expected extract pointer, got {other:?}"),
    }

    let cat = &policy.tools[1];
    let dep = cat.deputy.as_ref().expect("cat has a deputy block");
    assert_eq!(dep.role, DeputyRole::Use);
    assert_eq!(dep.rules.len(), 2);
    assert!(matches!(
        dep.rules[0],
        DeputyRule::Shape(KnownShape::FsTargets)
    ));
    // The use-role contract counts the tool as security-contracted.
    assert!(cat.has_security_contract());
}

#[test]
fn test_deputy_full_doc_loads_and_validates() {
    let dir = make_test_dir("deputy_load_ok");
    std::fs::write(dir.join("policy.kdl"), DEPUTY_DOC).unwrap();
    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    assert!(policy.tools.iter().all(|t| t.deputy.is_some()));
}

#[test]
fn test_deputy_requires_confused_deputy_flag() {
    let dir = make_test_dir("deputy_no_flag");
    std::fs::write(
        dir.join("policy.kdl"),
        DEPUTY_DOC.replace("confused_deputy_protection #true", ""),
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("confused_deputy_protection"),
        "got: {err}"
    );
}

#[test]
fn test_deputy_requires_version_2() {
    let dir = make_test_dir("deputy_v1");
    std::fs::write(
        dir.join("policy.kdl"),
        DEPUTY_DOC.replace("version=2", "version=1"),
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(err.to_string().contains("version=2"), "got: {err}");
}

/// The v1+include mix: the include contributes `deputy`, the main file
/// stays version=1. The merge must not silently carry the new setting
/// into a v1 policy — load fails instead.
#[test]
fn test_deputy_include_into_v1_main_fails() {
    let dir = make_test_dir("deputy_inc_v1");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=2
            confused_deputy_protection #true
            server "s" {
                tool "cat" {
                    deputy role="use" {
                        shape "fs_targets"
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
                tool "cat"
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("main.kdl")).unwrap_err();
    assert!(err.to_string().contains("version=2"), "got: {err}");
}

#[test]
fn test_deputy_rule_validation() {
    // (snippet, needle) — every malformed block is a load error.
    let cases: &[(&str, &str)] = &[
        ("deputy", "role"),
        ("deputy role=\"peek\"", "role"),
        ("deputy role=\"use\" mode=\"x\" {}", "unknown property"),
        ("deputy role=\"use\" role=\"use\" {}", "duplicate 'role'"),
        ("deputy \"x\" {}", "positional arguments"),
        ("deputy role=\"use\" { pointer \"/x\" }", "unexpected node"),
        (
            "deputy role=\"use\" { shape \"mcp_list_result\" }",
            "not valid for deputy role",
        ),
        (
            "deputy role=\"discover\" { shape \"fs_targets\" }",
            "not valid for deputy role",
        ),
        (
            "deputy role=\"discover\" { extract \"/params/a\" }",
            "/result/",
        ),
        ("deputy role=\"use\" { extract \"/result/a\" }", "/params/"),
        (
            "deputy role=\"use\" { extract \"params/a\" }",
            "must start with '/'",
        ),
        (
            "deputy role=\"use\" { extract \"/params\" }",
            "below the frame root",
        ),
        (
            "deputy role=\"use\" { extract \"/params/a\" split=\"words\" }",
            "split",
        ),
        (
            "deputy role=\"use\" { extract \"/params/a\" { x } }",
            "child nodes",
        ),
        // no rules under a binding role
        ("deputy role=\"use\" {}", "requires at least one"),
        ("deputy role=\"discover\"", "requires at least one"),
        // rules under the opt-out role
        (
            "deputy role=\"none\" { shape \"fs_targets\" }",
            "cannot declare extraction rules",
        ),
        // duplicate rules (separate `shape` nodes on their own lines)
        (
            "deputy role=\"discover\" {\n  shape \"mcp_list_result\"\n  shape \"mcp_list_result\"\n}",
            "duplicate",
        ),
    ];
    for (block, needle) in cases {
        let doc = format!(
            "policy version=2\nconfused_deputy_protection #true\nserver \"s\" {{\n  tool \"t\" {{\n    {block}\n  }}\n}}\n"
        );
        let err = parse_kdl_policy(&doc)
            .err()
            .or_else(|| {
                let p = parse_kdl_policy(&doc).unwrap();
                crate::policy::validator::validate_policy(&p).err()
            })
            .unwrap_or_else(|| panic!("`{block}` unexpectedly accepted"));
        assert!(
            err.to_string().contains(needle),
            "`{block}`: expected `{needle}` in `{err}`"
        );
    }

    // `role="none"` alone is legal — it opts a fixed-name tool out.
    let doc = r#"
        policy version=2
        confused_deputy_protection #true
        server "s" {
            tool "read_file" {
                deputy role="none"
            }
        }
    "#;
    let policy = parse_kdl_policy(doc).unwrap();
    let dep = policy.tools[0].deputy.as_ref().unwrap();
    assert_eq!(dep.role, DeputyRole::None);
    assert!(dep.rules.is_empty());
    crate::policy::validator::validate_policy(&policy).unwrap();
}

#[test]
fn test_deputy_extraction_bounds_enforced() {
    // >16 rules, >256-byte pointer, >16-segment pointer — all rejected.
    let many = (0..17)
        .map(|i| format!("extract \"/result/f{i}\""))
        .collect::<Vec<_>>()
        .join(" ");
    let long_ptr = format!("/result/{}", "a".repeat(300));
    let deep_ptr = format!("/result{}", "/x".repeat(17));
    for block in [
        format!("deputy role=\"discover\" {{ {many} }}"),
        format!("deputy role=\"discover\" {{ extract \"{long_ptr}\" }}"),
        format!("deputy role=\"discover\" {{ extract \"{deep_ptr}\" }}"),
    ] {
        let doc = format!(
            "policy version=2\nconfused_deputy_protection #true\nserver \"s\" {{\n  tool \"t\" {{\n    {block}\n  }}\n}}\n"
        );
        assert!(
            parse_kdl_policy(&doc).is_err(),
            "expected bound rejection: {block}"
        );
    }
}

#[test]
fn test_deputy_misplaced_is_rejected() {
    // `deputy` only takes effect directly under `tool`; anywhere else
    // it would be silently ignored, so placement is a load error.
    let inner = "deputy role=\"use\" { shape \"fs_targets\" }";
    // Lenient positions (unknown children would be skipped) — caught
    // by the dedicated misplaced-`deputy` sweep.
    let docs = [
        format!("policy version=2\n{inner}"),
        format!("policy version=2\ndefaults {{ {inner} }}"),
        format!("policy version=2\nprofile \"p\" {{ {inner} }}"),
        format!("policy version=2\nserver \"s\" {{\n  {inner}\n}}"),
        format!("policy version=2\nserver \"s\" {{\n  server-defaults {{ {inner} }}\n}}"),
        format!(
            "policy version=2\nserver \"s\" {{\n  server \"x\" {{\n    tool \"t\" {{\n      {inner}\n    }}\n  }}\n}}"
        ),
        format!("policy version=2\nwhen environment=\"prod\" {{\n  {inner}\n}}"),
        format!(
            "policy version=2\nwhen environment=\"prod\" {{\n  defaults {{\n    {inner}\n  }}\n}}"
        ),
        format!(
            "policy version=2\nwhen environment=\"prod\" {{\n  server \"s\" {{\n    {inner}\n  }}\n}}"
        ),
    ];
    for doc in &docs {
        let err = parse_kdl_policy(doc).unwrap_err();
        assert!(
            err.to_string()
                .contains("only valid as a direct child of a 'tool' node"),
            "doc `{doc}`: got: {err}"
        );
    }
    // Strict sub-parsers run before the sweep and reject the node
    // with their own shape error — still a load failure.
    for doc in [
        format!(
            "policy version=2\nserver \"s\" {{\n  tool \"t\" {{\n    filesystem {{\n      {inner}\n    }}\n  }}\n}}"
        ),
        format!(
            "policy version=2\nserver \"s\" {{\n  tool \"t\" {{\n    network {{\n      {inner}\n    }}\n  }}\n}}"
        ),
    ] {
        let err = parse_kdl_policy(&doc).unwrap_err();
        assert!(
            err.to_string().contains("deputy"),
            "doc `{doc}`: got: {err}"
        );
    }
}

#[test]
fn test_deputy_extends_inherits_block() {
    let dir = make_test_dir("deputy_extends");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=2
            confused_deputy_protection #true
            server "s" {
                tool "cat" {
                    deputy role="use" {
                        extract "/params/arguments/path"
                    }
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=2
            logging level="warn"
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    let dep = policy.tools[0].deputy.as_ref().expect("deputy inherited");
    assert_eq!(dep.role, DeputyRole::Use);
    assert_eq!(dep.rules.len(), 1);
}

#[test]
fn test_deputy_extends_child_replaces_block() {
    let dir = make_test_dir("deputy_extends_replace");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=2
            confused_deputy_protection #true
            server "s" {
                tool "cat" {
                    deputy role="use" {
                        extract "/params/arguments/path"
                    }
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=2
            server "s" {
                tool "cat" {
                    deputy role="none"
                }
            }
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    let dep = policy.tools[0].deputy.as_ref().unwrap();
    assert_eq!(dep.role, DeputyRole::None);
}

#[test]
fn test_deputy_when_override_applies() {
    let dir = make_test_dir("deputy_when");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            confused_deputy_protection #true
            server "s" {
                tool "cat"
            }
            when environment="prod" {
                server "s" {
                    tool "cat" {
                        deputy role="use" {
                            extract "/params/arguments/path"
                        }
                    }
                }
            }
        "#,
    )
    .unwrap();
    let prod = load_kdl_policy_with_env(&dir.join("policy.kdl"), "prod").unwrap();
    assert_eq!(
        prod.tools[0].deputy.as_ref().unwrap().role,
        DeputyRole::Use,
        "matching when must attach the deputy block"
    );
    let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "dev").unwrap();
    assert!(dev.tools[0].deputy.is_none(), "unmatched when must not");
}

#[test]
fn test_deputy_profile_preserves_block() {
    // `deputy` cannot live inside `profile` (misplaced sweep), but a
    // tool that references a profile keeps its own block.
    let dir = make_test_dir("deputy_profile");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            confused_deputy_protection #true
            profile "ro" {
                filesystem {
                    allow "/workspace/**"
                }
            }
            server "s" {
                tool "cat" profile="ro" {
                    deputy role="use" {
                        shape "fs_targets"
                    }
                }
            }
        "#,
    )
    .unwrap();
    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    let tool = &policy.tools[0];
    assert!(tool.fs.is_some(), "profile fields still merge");
    assert_eq!(tool.deputy.as_ref().unwrap().role, DeputyRole::Use);
}

#[test]
fn test_deputy_emit_roundtrip() {
    let policy = parse_kdl_policy(DEPUTY_DOC).unwrap();
    let emitted = policy.to_kdl();
    let reparsed = parse_kdl_policy(&emitted).expect("emitted deputy KDL re-parses");
    for (a, b) in policy.tools.iter().zip(reparsed.tools.iter()) {
        assert_eq!(a.deputy, b.deputy, "tool {} round-trip", a.name);
    }
}
