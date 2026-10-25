use super::*;

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
fn test_extends_cidr_rules_inherit_and_merge() {
    // `cidr` fields ride the same defaults overlay as `host` rules:
    // a child's allow list replaces the parent's for that layer, while
    // deny rules accumulate (sticky deny).
    let dir = make_test_dir("extends_cidr");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow host="base.example.com"
                    allow cidr="10.0.0.0/8"
                    deny cidr="169.254.0.0/16"
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
                network {
                    allow host="child.example.com"
                    allow cidr="192.168.0.0/16"
                    deny cidr="100.64.0.0/10"
                }
            }
        "#,
    )
    .unwrap();

    // Load against a Linux workload — a nonempty allow list under the
    // default deny-all is not expressible by the Windows AppContainer
    // the host target would validate against.
    let target = crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    };
    let policy =
        crate::policy::kdl_loader::load_kdl_policy_for_target(&dir.join("child.kdl"), "", &target)
            .unwrap();
    let out = &policy.network.outbound;
    assert_eq!(out.allowed, vec!["child.example.com"]);
    assert_eq!(out.allowed_cidrs, vec!["192.168.0.0/16"]);
    for cidr in ["169.254.0.0/16", "100.64.0.0/10"] {
        assert!(
            out.denied_cidrs.contains(&cidr.to_string()),
            "missing {cidr}"
        );
    }
}

#[test]
fn test_when_defaults_cidr_merge() {
    let dir = make_test_dir("when_cidr");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow cidr="10.0.0.0/8"
                }
            }
            when environment="prod" {
                defaults {
                    network {
                        deny cidr="10.9.0.0/16"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let target = crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    };
    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("policy.kdl"),
        "prod",
        &target,
    )
    .unwrap();
    let out = &policy.network.outbound;
    // A deny-only override leaves the declared allow list in place...
    assert_eq!(out.allowed_cidrs, vec!["10.0.0.0/8"]);
    // ...while the deny accumulates — it overlaps but does not cover the
    // allow, so the allow survives (per-destination check decides).
    assert_eq!(out.denied_cidrs, vec!["10.9.0.0/16"]);
}

#[test]
fn test_when_tool_network_cidr_rules() {
    let dir = make_test_dir("when_tool_cidr");
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
                            allow cidr="10.2.0.0/16"
                            deny cidr="10.2.9.0/24"
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
    assert_eq!(net.allowed_hosts, vec!["prod.example.com"]);
    assert_eq!(net.allowed_cidrs, vec!["10.2.0.0/16"]);
    // The deny overlaps the allow partially — it stays (allow not covered).
    assert_eq!(net.denied_cidrs, vec!["10.2.9.0/24"]);
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
fn test_when_network_replace_keeps_qualified_rules() {
    // Regression: a matching `when` replaces the flat allow lists, and the
    // structured `egress_rules` carrying `proto=`/`port=` qualifiers must
    // be replaced with them — the IP layer reads `egress_rules()`, so a
    // stale unqualified rule would keep the old grant alive.
    let dir = make_test_dir("when_net_qual");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow cidr="192.0.2.0/24"
                }
            }
            when environment="prod" {
                defaults {
                    network {
                        allow cidr="192.0.2.0/24" port=443
                    }
                }
            }
        "#,
    )
    .unwrap();

    // A nonempty defaults allow list needs a Linux workload target — the
    // Windows AppContainer validation cannot express it.
    let target = crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    };
    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("policy.kdl"),
        "prod",
        &target,
    )
    .unwrap();
    let rules = policy.network.outbound.egress_rules();
    let allows: Vec<_> = rules.iter().filter(|r| r.allow).collect();
    assert_eq!(
        allows.len(),
        1,
        "the old unqualified rule must be replaced, not kept: {allows:?}"
    );
    assert_eq!(allows[0].port, Some(443));
    assert_eq!(allows[0].proto, crate::policy::EgressProto::Tcp);
}

#[test]
fn test_extends_network_replace_keeps_qualified_rules() {
    // Same regression through `extends`: the child's allow rules replace
    // the parent's qualified rule set, proto/port included.
    let dir = make_test_dir("extends_net_qual");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow cidr="192.0.2.0/24" proto="udp"
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
                network {
                    allow cidr="192.0.2.0/24" port=443
                }
            }
        "#,
    )
    .unwrap();

    let target = crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    };
    let policy =
        crate::policy::kdl_loader::load_kdl_policy_for_target(&dir.join("child.kdl"), "", &target)
            .unwrap();
    let rules = policy.network.outbound.egress_rules();
    let allows: Vec<_> = rules.iter().filter(|r| r.allow).collect();
    assert_eq!(allows.len(), 1, "stale udp rule must be gone: {allows:?}");
    assert_eq!(allows[0].proto, crate::policy::EgressProto::Tcp);
    assert_eq!(allows[0].port, Some(443));
}

#[test]
fn test_when_network_scoped_rules_merge() {
    // Structured rules merge like their flat projections: the allow side
    // is replaced (a scoped-wildcard-only rule must not survive), deny
    // rules accumulate.
    let dir = make_test_dir("when_net_scoped");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow host="*" proto="udp" port=53
                    deny cidr="169.254.0.0/16"
                }
            }
            when environment="prod" {
                defaults {
                    network {
                        allow host="svc.example.com" port=443
                        deny cidr="100.64.0.0/10"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let target = crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    };
    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("policy.kdl"),
        "prod",
        &target,
    )
    .unwrap();
    let rules = policy.network.outbound.egress_rules();
    let allows: Vec<_> = rules.iter().filter(|r| r.allow).collect();
    assert_eq!(
        allows.len(),
        1,
        "scoped wildcard must be replaced, not kept: {allows:?}"
    );
    assert_eq!(allows[0].port, Some(443));
    let denies: Vec<_> = rules.iter().filter(|r| !r.allow).collect();
    assert_eq!(denies.len(), 2, "deny rules must accumulate: {denies:?}");
}

#[test]
fn test_when_tool_network_qualified_rules() {
    // A tool-level `network` inside `when` replaces the allow side of the
    // tool's qualified rule set the same way its flat lists are replaced.
    let dir = make_test_dir("when_tool_net_qual");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "s1" {
                tool "fetch" {
                    network {
                        allow host="dev.example.com"
                    }
                }
            }
            when environment="production" {
                server "s1" {
                    tool "fetch" {
                        network {
                            allow host="prod.example.com" port=443
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
    assert_eq!(net.allowed_hosts, vec!["prod.example.com"]);
    let rules = net.egress_rule_set();
    let allows: Vec<_> = rules.iter().filter(|r| r.allow).collect();
    assert_eq!(
        allows.len(),
        1,
        "stale tool rule must be replaced: {allows:?}"
    );
    assert_eq!(allows[0].port, Some(443));
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

// A matching `when` `allow` cannot re-grant a syscall the accumulated
// deny side already covers — the deny-wins prune runs even when the
// block declares no `deny` of its own.
#[test]
fn test_when_syscall_allow_cannot_revive_denied() {
    let dir = make_test_dir("when_sc_allow_vs_deny");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=3
            defaults {
                syscalls {
                    allow "read"
                    deny "ptrace"
                }
            }
            when environment="production" {
                defaults {
                    syscalls {
                        allow "ptrace"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
    assert_eq!(policy.syscalls.denied, vec!["ptrace"]);
    assert!(
        !policy.syscalls.allowed.contains(&"ptrace".to_string()),
        "the when-allow must not re-grant a denied syscall: {:?}",
        policy.syscalls.allowed
    );
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

#[test]
fn test_when_tool_profile_applies_to_existing_tool() {
    // Regression: a  override naming  on an *existing*
    // tool must apply the profile layer — the reference was previously
    // dropped silently, so conditional restrictions never landed.
    let dir = make_test_dir("when_tool_profile");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            profile "restricted" {
                filesystem {
                    deny "/srv/secrets"
                }
                network {
                    deny host="exfil.example.com"
                }
            }
            server "s1" {
                tool "fetch"
            }
            when environment="production" {
                server "s1" {
                    tool "fetch" profile="restricted"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap();
    let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
    assert!(fetch.fs_explicit);
    let fs = fetch.fs.as_ref().unwrap();
    assert!(
        fs.denied_paths.contains(&"/srv/secrets".to_string()),
        "profile deny must reach the existing tool: {fs:?}"
    );
    assert!(fetch.network_explicit);
    let net = fetch.network.as_ref().unwrap();
    assert!(
        net.denied_hosts.contains(&"exfil.example.com".to_string()),
        "profile deny must reach the existing tool: {net:?}"
    );

    // A non-matching environment never applies the block — the tool
    // keeps its un-profiled state.
    let dev = load_kdl_policy_with_env(&dir.join("policy.kdl"), "development").unwrap();
    let fetch = dev.tools.iter().find(|t| t.name == "fetch").unwrap();
    assert!(!fetch.fs_explicit);
    assert!(
        fetch
            .fs
            .as_ref()
            .is_none_or(|fs| fs.denied_paths.is_empty())
    );
}

#[test]
fn test_when_tool_profile_deny_sticks_against_own_allow() {
    // Deny entries from the profile accumulate under the override's own
    // field blocks and re-prune their allow side — the tool's inline
    // allow cannot carve the profile's deny back out.
    let dir = make_test_dir("when_tool_profile_deny");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            profile "restricted" {
                filesystem {
                    deny "/srv/secrets"
                }
            }
            server "s1" {
                tool "fetch"
            }
            when environment="production" {
                server "s1" {
                    tool "fetch" profile="restricted" {
                        filesystem {
                            allow "/srv/secrets"
                            allow "/work"
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
    assert_eq!(fs.denied_paths, vec!["/srv/secrets".to_string()]);
    assert_eq!(fs.read_only_paths, vec!["/work".to_string()]);
}

#[test]
fn test_when_tool_unknown_profile_fails_closed() {
    // An unresolvable profile name on an existing tool is a load error,
    // the same as the inline parse — never a silently ignored reference.
    let dir = make_test_dir("when_tool_bad_profile");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "s1" {
                tool "fetch"
            }
            when environment="production" {
                server "s1" {
                    tool "fetch" profile="missing"
                }
            }
        "#,
    )
    .unwrap();

    let err = load_kdl_policy_with_env(&dir.join("policy.kdl"), "production").unwrap_err();
    assert!(
        err.to_string().contains("unknown profile 'missing'"),
        "expected fail-closed unknown-profile error, got: {err}"
    );
}
