use super::*;
use crate::policy::kdl_inherit::overlay::{PendingWarnings, WeakenedPosture};
use crate::policy::{ToolPolicy, ToolSyscallPolicy};
use std::path::Path;

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

// (d) Re-declaring a tool without its own `syscalls` block must not
// replace the base tool's explicit scope with the parser-materialized
// defaults a non-declaring tool carries — the merge gates on
// `syscalls_explicit`, the same gate fs/network use.
#[test]
fn test_merge_tool_syscalls_gated_on_explicit() {
    let mut base = Policy::default();
    let mut base_tool = ToolPolicy::named("t", true);
    base_tool.server = Some("s".to_string());
    base_tool.syscalls = Some(ToolSyscallPolicy {
        allowed: vec!["read".to_string()],
        denied: vec!["write".to_string()],
    });
    base_tool.syscalls_explicit = true;
    base.tools.push(base_tool);

    // The overlay tool re-declares only `side_effect`; the `syscalls`
    // value it carries is materialized defaults, not a declaration.
    let mut overlay = Policy::default();
    let mut over_tool = ToolPolicy::named("t", true);
    over_tool.server = Some("s".to_string());
    over_tool.side_effect = Some("network".to_string());
    over_tool.syscalls = Some(ToolSyscallPolicy {
        allowed: vec!["execve".to_string()],
        denied: vec![],
    });
    overlay.tools.push(over_tool);

    merge_into_policy(
        &mut base,
        &overlay,
        &OverlayDecl::default(),
        std::path::Path::new("overlay.kdl"),
        &mut crate::policy::provenance::Provenance::default(),
        2,
    );
    let tool = base.tools.iter().find(|t| t.name == "t").unwrap();
    let sc = tool.syscalls.as_ref().unwrap();
    assert_eq!(
        sc.allowed,
        vec!["read"],
        "a non-declaring overlay tool must not replace the base's explicit syscalls"
    );
    assert_eq!(sc.denied, vec!["write"]);

    // An explicit `syscalls` declaration on the overlay tool does merge.
    let mut overlay = Policy::default();
    let mut over_tool = ToolPolicy::named("t", true);
    over_tool.server = Some("s".to_string());
    over_tool.syscalls = Some(ToolSyscallPolicy {
        allowed: vec!["openat".to_string()],
        denied: vec![],
    });
    over_tool.syscalls_explicit = true;
    overlay.tools.push(over_tool);

    merge_into_policy(
        &mut base,
        &overlay,
        &OverlayDecl::default(),
        std::path::Path::new("overlay.kdl"),
        &mut crate::policy::provenance::Provenance::default(),
        2,
    );
    let sc = base
        .tools
        .iter()
        .find(|t| t.name == "t")
        .unwrap()
        .syscalls
        .as_ref()
        .unwrap();
    assert_eq!(sc.allowed, vec!["openat"]);
    assert_eq!(sc.denied, vec!["write"], "deny stays sticky");
}

// The weakening detector reports every fail-secure posture an overlay
// moved down, and re-validates each against the final merged policy so
// a later declaration that restored it does not leave a stale warning.
#[test]
fn test_security_posture_weakened_and_message() {
    let base = Policy {
        confused_deputy_protection: true,
        trajectory: true,
        trajectory_rules: vec![crate::policy::TrajectoryRule {
            after_side_effect: crate::policy::SideEffect::ReadOnly,
            deny_next: crate::policy::SideEffect::Network,
        }],
        sandbox: crate::policy::SandboxPolicy {
            require_lifetime_boundary: true,
            ..Default::default()
        },
        logging: crate::policy::LoggingPolicy {
            level: "warn".to_string(),
            ..Default::default()
        },
        environment: crate::policy::EnvironmentPolicy {
            allowed: vec!["HOME".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let before = SecurityPosture::capture(&base);
    assert!(
        before.weakened(&base).is_empty(),
        "a no-op merge weakens nothing"
    );

    let mut after = base.clone();
    after.confused_deputy_protection = false;
    after.trajectory_rules.clear();
    after.logging.level = "info".to_string();
    after.logging.fail_closed = false;
    after.sandbox.allow_degraded = true;
    after.sandbox.require_lifetime_boundary = false;
    after.fs.secret_overlay = false;
    after.network.outbound.deny_all_others = false;
    after.network.inbound.allow_listen = true;
    after.environment.restrict = false;
    let weakened = before.weakened(&after);
    let kinds = [
        WeakenedPosture::ConfusedDeputyProtection,
        WeakenedPosture::TrajectoryRules(vec![]),
        WeakenedPosture::LoggingLevel(String::new()),
        WeakenedPosture::LoggingFailClosed,
        WeakenedPosture::SandboxAllowDegraded,
        WeakenedPosture::SandboxRequireLifetimeBoundary,
        WeakenedPosture::SecretOverlay,
        WeakenedPosture::OutboundPosture,
        WeakenedPosture::InboundListen,
        WeakenedPosture::EnvironmentRestrict,
    ];
    for kind in &kinds {
        assert!(
            weakened.iter().any(|w| w.same_kind(kind)),
            "expected a {kind:?} weakening, got {weakened:?}"
        );
        assert!(
            weakened
                .iter()
                .find(|w| w.same_kind(kind))
                .unwrap()
                .message(&after)
                .is_some(),
            "{kind:?} must still warn while weakened"
        );
    }
    // A posture restored by a later declaration stops warning.
    let mut restored = after.clone();
    restored.confused_deputy_protection = true;
    restored.network.inbound.allow_listen = false;
    restored.logging.fail_closed = true;
    restored.trajectory_rules = base.trajectory_rules.clone();
    assert_eq!(
        weakened
            .iter()
            .filter(|w| w.message(&restored).is_some())
            .count(),
        kinds.len() - 4,
        "restored postures must not warn"
    );
}

// `"info"` is the unconfigured level — a file that never chose one has
// no level posture to weaken (the same floor the pre-decl include
// clamp used).
#[test]
fn test_security_posture_default_level_not_weakened() {
    let mut policy = Policy::default();
    let before = SecurityPosture::capture(&policy);
    policy.logging.level = "error".to_string();
    assert!(
        before.weakened(&policy).is_empty(),
        "moving off the default 'info' level is not a weakening"
    );

    // ...but an explicitly chosen level being moved is.
    let before = SecurityPosture::capture(&policy);
    policy.logging.level = "warn".to_string();
    let weakened = before.weakened(&policy);
    assert!(
        weakened
            .iter()
            .any(|w| matches!(w, WeakenedPosture::LoggingLevel(_)))
    );
}

// An `environment` allow list that gains names is a weakening; a
// dropped posture flag is a different, stronger one.
#[test]
fn test_security_posture_environment_widening() {
    let mut policy = Policy {
        environment: crate::policy::EnvironmentPolicy {
            allowed: vec!["HOME".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let before = SecurityPosture::capture(&policy);
    policy.environment.allowed.push("API_TOKEN".to_string());
    let weakened = before.weakened(&policy);
    let [w] = weakened.as_slice() else {
        panic!("expected exactly one weakening, got {weakened:?}")
    };
    assert!(matches!(w, WeakenedPosture::EnvironmentAllowed(_)));
    let message = w.message(&policy).unwrap();
    assert!(message.contains("'API_TOKEN'"), "got: {message}");

    // `inherit-parent` lifts the restriction outright — reported as
    // the stronger EnvironmentRestrict, not as list growth.
    let mut policy = Policy {
        environment: crate::policy::EnvironmentPolicy {
            allowed: vec!["HOME".to_string()],
            ..Default::default()
        },
        ..Default::default()
    };
    let before = SecurityPosture::capture(&policy);
    policy.environment.restrict = false;
    policy.environment.inherit_parent = true;
    let weakened = before.weakened(&policy);
    assert!(
        weakened
            .iter()
            .any(|w| matches!(w, WeakenedPosture::EnvironmentRestrict))
    );
    assert!(
        !weakened
            .iter()
            .any(|w| matches!(w, WeakenedPosture::EnvironmentAllowed(_)))
    );

    // Re-imposing the restriction on an unrestricted base is a
    // strengthening — its allow list is not reported as growth.
    let mut policy = Policy {
        environment: crate::policy::EnvironmentPolicy {
            restrict: false,
            inherit_parent: true,
            ..Default::default()
        },
        ..Default::default()
    };
    let before = SecurityPosture::capture(&policy);
    policy.environment.restrict = true;
    policy.environment.inherit_parent = false;
    policy.environment.allowed = vec!["HOME".to_string()];
    assert!(
        before.weakened(&policy).is_empty(),
        "restoring restriction must not report the allow list as a weakening"
    );
}

// A file can lose the same kind of posture twice with different
// payloads — the doc merge and a matching `when` block each widening
// the allow list differently. Both losses must reach the final
// evaluation: dropping the second entry on (path, kind) alone would
// suppress a warning whenever the first entry's loss was restored.
#[test]
fn test_pending_weakened_keeps_distinct_payloads() {
    let path = Path::new("child.kdl");
    let mut pending = PendingWarnings::default();
    // First merge widened {A} → {A,B}; a later merge went {A,B} →
    // {A,B,C}. Two losses of the same kind, different payloads.
    pending.push_weakened(path, WeakenedPosture::EnvironmentAllowed(vec!["A".into()]));
    pending.push_weakened(
        path,
        WeakenedPosture::EnvironmentAllowed(vec!["A".into(), "B".into()]),
    );
    // An exact repeat is still a duplicate.
    pending.push_weakened(path, WeakenedPosture::EnvironmentAllowed(vec!["A".into()]));

    let policy = Policy {
        environment: crate::policy::EnvironmentPolicy {
            allowed: vec!["A".into(), "B".into(), "C".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let lines = pending.warning_lines(&policy);
    assert_eq!(
        lines.len(),
        2,
        "both distinct losses must warn, got {lines:?}"
    );

    // When the later declaration reverts the widened tail, the second
    // entry's loss is restored — but the first one still warns.
    let policy = Policy {
        environment: crate::policy::EnvironmentPolicy {
            allowed: vec!["A".into(), "B".into()],
            ..Default::default()
        },
        ..Default::default()
    };
    let lines = pending.warning_lines(&policy);
    assert_eq!(lines.len(), 1, "got {lines:?}");
    assert!(lines[0].contains("'B'"), "got: {}", lines[0]);
}

// `Policy::default()` is the loader's seed, not an established base:
// a file with no `extends` that includes an open-posture document
// declares that posture — there is nothing it could weaken yet, so
// no weakening may be recorded for the merge.
#[test]
fn test_include_onto_default_base_records_no_weakening() {
    let dir = make_test_dir("include_default_base");
    std::fs::write(
        dir.join("open.kdl"),
        r#"
            policy version=1
            defaults {
                network {
                    allow host="*"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "open.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let mut visited = std::collections::HashSet::new();
    let mut profiles = std::collections::HashMap::new();
    let mut budget = InheritBudget::default();
    let mut markers = Vec::new();
    let mut warnings = Vec::new();
    let mut prov = crate::policy::provenance::Provenance::default();
    let mut profile_files = std::collections::HashMap::new();
    let (policy, _decl, pending) = {
        let mut cx = super::LoadCx {
            profiles: &mut profiles,
            markers: &mut markers,
            warnings: &mut warnings,
            prov: &mut prov,
            profile_files: &mut profile_files,
            rules: None,
        };
        load_kdl_policy_recursive_with_decl(
            &dir.join("main.kdl"),
            &mut visited,
            "",
            &mut cx,
            &mut budget,
            0,
        )
        .unwrap()
    };
    assert!(
        !policy.network.outbound.deny_all_others,
        "the include's open posture still merges"
    );
    assert!(
        pending.warning_lines(&policy).is_empty(),
        "an unestablished base has nothing to weaken: {:?}",
        pending.warning_lines(&policy)
    );
}
