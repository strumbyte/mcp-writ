use super::*;

// ── PR-19 merge regressions (F-02/F-03/F-04) ─────────────────────
//
// The overlay merge must not widen a tool beyond what the parent
// declared (`fs_explicit`/`network_explicit` gates), and must not drop
// fields the merged subtree declared through an ancestor or a matching
// `when` block.

/// Network allow lists under the default deny-all posture need a Linux
/// workload target — the host-native AppContainer check cannot express
/// them.
fn linux_target() -> crate::execution::ExecutionTarget {
    crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    }
}

// (a) A child that re-declares a tool only to set `side_effect` must
// leave the parent's explicit tool `network` scope in place — the
// child's `defaults.network` is not the tool's declaration.
#[test]
fn test_extends_redecl_keeps_tool_network_allowlist() {
    let dir = make_test_dir("redecl_tool_net");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            server "s" {
                tool "fetch" {
                    network {
                        allow host="a.example.com"
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
            policy version=1
            defaults {
                network {
                    allow host="b.example.com"
                }
            }
            server "s" {
                tool "fetch" side_effect="network"
            }
        "#,
    )
    .unwrap();

    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("child.kdl"),
        "",
        &linux_target(),
    )
    .unwrap();
    let fetch = policy.tools.iter().find(|t| t.name == "fetch").unwrap();
    assert!(fetch.network_explicit);
    let net = fetch.network.as_ref().unwrap();
    assert_eq!(
        net.allowed_hosts,
        vec!["a.example.com"],
        "the parent's explicit tool allow list must survive a side_effect-only re-declaration"
    );
    // The child's defaults still land at the global layer.
    assert_eq!(policy.network.outbound.allowed, vec!["b.example.com"]);
}

// (b) Re-declaring an `allow none=#true` tool under a child that adds
// `defaults.filesystem` must not broaden the tool to the defaults paths.
#[test]
fn test_extends_redecl_keeps_tool_fs_none() {
    let dir = make_test_dir("redecl_tool_fs");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            server "s" {
                tool "w" {
                    filesystem {
                        allow none=#true
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
            policy version=1
            defaults {
                filesystem {
                    allow "/child/data"
                }
            }
            server "s" {
                tool "w" side_effect="write"
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    let w = policy.tools.iter().find(|t| t.name == "w").unwrap();
    assert!(w.fs_explicit);
    assert_eq!(w.side_effect.as_deref(), Some("write"));
    let fs = w.fs.as_ref().unwrap();
    assert!(fs.allow_specified);
    assert!(
        fs.allowed_paths.is_empty()
            && fs.read_only_paths.is_empty()
            && fs.read_write_paths.is_empty(),
        "the child's defaults must not widen an explicit allow-none tool: {fs:?}"
    );
    // Non-explicit sibling tools do pick up the merged defaults.
    assert!(policy.fs.read_only.contains(&"/child/data".to_string()));
}

// (c) Pin the README quickstart merge: extending
// `examples/policies/filesystem.kdl`, adding host `defaults`, and
// re-declaring `read_file` gives that tool the data root while every
// other tool keeps the inherited `allow none=#true` deny-all-paths
// scope.
#[test]
fn test_readme_quickstart_merge_result() {
    let dir = make_test_dir("readme_quickstart");
    let base = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/policies/filesystem.kdl");
    let base_ref = base.display().to_string().replace('\\', "/");
    std::fs::write(
        dir.join("policy.kdl"),
        format!(
            r#"
            extends "{base_ref}"
            policy version=1
            defaults {{
                filesystem {{
                    allow "/opt/node/bin" mode="read"
                    allow "/opt/node" mode="read"
                    allow "/srv/mcp-data" mode="read"
                    secret-overlay #true
                }}
                environment {{
                }}
            }}
            server "filesystem" {{
                tool "read_file" {{ filesystem {{ allow "/srv/mcp-data/**" }} }}
            }}
        "#
        ),
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();

    // The overridden tool carries exactly its declared scope.
    let read_file = policy.tools.iter().find(|t| t.name == "read_file").unwrap();
    let fs = read_file.fs.as_ref().unwrap();
    assert_eq!(fs.allowed_paths, vec!["/srv/mcp-data/**"]);
    assert_eq!(fs.read_only_paths, vec!["/srv/mcp-data/**"]);

    // Every sibling tool keeps the inherited empty allow-list — the
    // child's `defaults.filesystem` must not reach them.
    for t in &policy.tools {
        if t.name == "read_file" {
            continue;
        }
        let fs = t.fs.as_ref().expect("tool fs");
        assert!(
            fs.allow_specified && fs.allowed_paths.is_empty(),
            "tool '{}' must keep the inherited allow-none scope: {fs:?}",
            t.name
        );
    }
    // The pathless-call opt-in on list_allowed_directories survives.
    let lad = policy
        .tools
        .iter()
        .find(|t| t.name == "list_allowed_directories")
        .unwrap();
    assert_eq!(lad.fs.as_ref().unwrap().require_path, Some(false));

    // The child's own defaults still land at the global layer.
    assert!(policy.fs.read_only.contains(&"/srv/mcp-data".to_string()));
    assert!(policy.fs.secret_overlay);
    assert!(policy.environment.declared);
    assert!(policy.environment.restrict);
    assert!(policy.environment.allowed.is_empty());
}

// A child that declares `defaults.network` only to add rules inherits
// the parent's `allow host="*"` posture and `inbound` grant — both move
// only on their own declaration.
#[test]
fn test_extends_network_posture_and_inbound_inherit() {
    let dir = make_test_dir("posture_inbound_inherit");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow host="*"
                    inbound allow=#true
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
                    allow host="svc.example.com"
                }
            }
        "#,
    )
    .unwrap();

    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("child.kdl"),
        "",
        &linux_target(),
    )
    .unwrap();
    assert!(
        !policy.network.outbound.deny_all_others,
        "the parent's open posture must survive a rules-only child network block"
    );
    assert!(policy.network.inbound.allow_listen);
    assert_eq!(policy.network.outbound.allowed, vec!["svc.example.com"]);
}

// The same child's own posture/inbound declarations do override.
#[test]
fn test_extends_network_posture_and_inbound_override() {
    let dir = make_test_dir("posture_inbound_override");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow host="*"
                    inbound allow=#true
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
                    deny host="*"
                    inbound allow=#false
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert!(policy.network.outbound.deny_all_others);
    assert!(!policy.network.inbound.allow_listen);
}

// `when` must apply `secret-overlay` like the extends/include merge
// does — a matching block that re-enables the overlay (or turns it
// off) is not dropped.
#[test]
fn test_when_secret_overlay_applies() {
    let dir = make_test_dir("when_secret_overlay");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    secret-overlay #false
                }
            }
            when environment="prod" {
                defaults {
                    filesystem {
                        secret-overlay #true
                    }
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "prod").unwrap();
    assert!(policy.fs.secret_overlay);

    let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "dev").unwrap();
    assert!(!policy.fs.secret_overlay);
}

// The matching `when` block's `deny host="*"` posture applies — and a
// `defaults.network` that only adds a deny rule leaves an inherited
// open posture alone.
#[test]
fn test_when_network_posture_only_moves_when_declared() {
    let dir = make_test_dir("when_posture");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow host="*"
                }
            }
            when environment="prod" {
                defaults {
                    network {
                        deny host="bad.example.com"
                    }
                }
            }
            when environment="lockdown" {
                defaults {
                    network {
                        deny host="*"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let target = linux_target();
    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("policy.kdl"),
        "prod",
        &target,
    )
    .unwrap();
    assert!(
        !policy.network.outbound.deny_all_others,
        "a deny-only when block must not reset the open posture"
    );

    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("policy.kdl"),
        "lockdown",
        &target,
    )
    .unwrap();
    assert!(policy.network.outbound.deny_all_others);
}

// include must propagate fields the included file's ancestors declared:
// transport, sandbox, logging.fail_closed, network posture/inbound,
// secret-overlay, and trajectory rules all ride the merged policy.
#[test]
fn test_include_propagates_ancestor_declared_fields() {
    let dir = make_test_dir("include_ancestor_fields");
    std::fs::write(
        dir.join("grandparent.kdl"),
        r#"
            policy version=1
            transport type="http" listen_addr="127.0.0.1:18080"
            logging level="warn" fail_closed=#false
            sandbox allow_degraded=#true
            confused_deputy_protection #true
            trajectory #true {
                after side_effect="read_only" deny-next="network"
            }
            defaults {
                network {
                    allow host="*"
                    inbound allow=#true
                }
                filesystem {
                    secret-overlay #false
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            extends "grandparent.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "base.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let policy = crate::policy::kdl_loader::load_kdl_policy_for_target(
        &dir.join("main.kdl"),
        "",
        &linux_target(),
    )
    .unwrap();
    assert_eq!(policy.transport.type_, crate::policy::TransportType::Http);
    assert_eq!(
        policy.transport.listen_addr.as_deref(),
        Some("127.0.0.1:18080")
    );
    assert_eq!(policy.logging.level, "warn");
    assert!(!policy.logging.fail_closed);
    assert!(policy.sandbox.allow_degraded);
    assert!(policy.confused_deputy_protection);
    assert!(policy.trajectory);
    assert_eq!(policy.trajectory_rules.len(), 1);
    assert!(!policy.network.outbound.deny_all_others);
    assert!(policy.network.inbound.allow_listen);
    assert!(!policy.fs.secret_overlay);
}

// Fields an included file set through a matching `when` block are
// merged values, not nodes in the including file — they must propagate
// the same way.
#[test]
fn test_include_propagates_when_derived_fields() {
    let dir = make_test_dir("include_when_fields");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=1
            server "s" {
                tool "t" side_effect="read_only"
            }
            when environment="prod" {
                logging level="error"
                trajectory #true {
                    after side_effect="read_only" deny-next="network"
                }
                defaults {
                    filesystem {
                        secret-overlay #false
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
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy_with_env(&dir.join("main.kdl"), "prod").unwrap();
    assert_eq!(policy.logging.level, "error");
    assert!(policy.trajectory);
    assert_eq!(
        policy.trajectory_rules.len(),
        1,
        "a matching when's trajectory rules must not drop across include"
    );
    assert!(!policy.fs.secret_overlay);
}

// Every file in an extends/include chain declares a supported
// `policy version` — an ancestor's unknown version must not ride the
// child's accepted one.
#[test]
fn test_extends_rejects_unknown_ancestor_version() {
    let dir = make_test_dir("extends_bad_version");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=99
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

    let err = load_kdl_policy(&dir.join("child.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("unsupported policy version 99"),
        "got: {err}"
    );
    assert!(
        err.to_string().contains("base.kdl"),
        "the refusal names the offending file: {err}"
    );
}

#[test]
fn test_include_rejects_unknown_included_version() {
    let dir = make_test_dir("include_bad_version");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=42
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "extra.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let err = load_kdl_policy(&dir.join("main.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("unsupported policy version 42"),
        "got: {err}"
    );
}
