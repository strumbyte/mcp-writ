//! PR-28 `policy version=3` semantics: allow lists compose additively
//! by default, `replace=#true` opts back into replacement, multiple
//! `profile` references union in declaration order, and a
//! defaults-level `syscalls { deny ... }` narrows the inherited grant
//! (deny-wins prunes the allow side). v1/v2 keep their replacement
//! semantics — the version-pinned regressions sit beside each case so
//! a slip that widens v2 into v3 (or v3 into v2) fails here, not in
//! production.

use super::*;

/// Network allow lists under the default deny-all posture need a Linux
/// workload target — the host-native AppContainer check cannot express
/// them.
fn linux_target() -> crate::execution::ExecutionTarget {
    crate::execution::ExecutionTarget {
        workload_os: crate::execution::TargetOs::Linux,
        ..crate::execution::ExecutionTarget::native()
    }
}

fn load_for_target(path: &std::path::Path) -> Policy {
    crate::policy::kdl_loader::load_kdl_policy_for_target(path, "", &linux_target())
        .expect("policy must load")
}

// ── defaults: union by default ──────────────────────────────────────

// A v3 child's `defaults.filesystem` adds to the inherited allow list;
// under v2 the same document shape replaces it.
#[test]
fn test_v3_defaults_filesystem_unions_across_extends() {
    let dir = make_test_dir("v3_fs_union");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=3
            defaults {
                filesystem {
                    allow "/base/**"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=3
            defaults {
                filesystem {
                    allow "/child/**"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert!(
        policy.fs.read_only.contains(&"/base/**".to_string())
            && policy.fs.read_only.contains(&"/child/**".to_string()),
        "v3 defaults must union: {:?}",
        policy.fs.read_only
    );
}

#[test]
fn test_v3_defaults_filesystem_replace_flag() {
    let dir = make_test_dir("v3_fs_replace");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=3
            defaults {
                filesystem {
                    allow "/base/**"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=3
            defaults {
                filesystem replace=#true {
                    allow "/child/**"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert_eq!(
        policy.fs.read_only,
        vec!["/child/**"],
        "replace=#true drops the inherited allow list"
    );
}

// Defaults filesystem was already union-based before v3 (the F-02
// narrowing fix): the rules-version difference lives in the layered
// composition — under v2 a tool-local `filesystem` block replaces the
// inherited grants, under v3 it adds to them.
#[test]
fn test_v2_tool_filesystem_still_replaces() {
    let dir = make_test_dir("v2_tool_fs_replace");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            defaults {
                filesystem {
                    allow "/global/**"
                }
            }
            profile "p" {
                filesystem {
                    allow "/profile/**"
                }
            }
            server "s" {
                tool "t" {
                    profile "p"
                    filesystem {
                        allow "/tool/**"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    let t = policy.tools.iter().find(|t| t.name == "t").unwrap();
    let fs = t.fs.as_ref().unwrap();
    assert_eq!(
        fs.allowed_paths,
        vec!["/tool/**"],
        "v2 tool-local declarations replace the inherited layers: {fs:?}"
    );
}

#[test]
fn test_v3_defaults_network_unions_across_extends() {
    let dir = make_test_dir("v3_net_union");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=3
            defaults {
                network {
                    allow host="a.example.com"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=3
            defaults {
                network {
                    allow host="b.example.com"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_for_target(&dir.join("child.kdl"));
    assert!(
        policy
            .network
            .outbound
            .allowed
            .contains(&"a.example.com".to_string())
            && policy
                .network
                .outbound
                .allowed
                .contains(&"b.example.com".to_string()),
        "v3 network allows must union: {:?}",
        policy.network.outbound.allowed
    );
    assert!(policy.network.outbound.deny_all_others);
}

// ── defaults-level syscall deny ─────────────────────────────────────

// `deny` under `defaults.syscalls` is the v3 narrowing spelling: the
// allow side unions upward, so removing a syscall needs a deny. The
// effective allow list is pruned at the merge.
#[test]
fn test_v3_syscall_deny_prunes_inherited_allow() {
    let dir = make_test_dir("v3_sc_deny");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=3
            defaults {
                syscalls {
                    allow "read"
                    allow "write"
                    allow "execve"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=3
            defaults {
                syscalls {
                    allow "openat"
                    deny "execve"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert_eq!(policy.syscalls.denied, vec!["execve"]);
    assert!(
        policy.syscalls.allowed.contains(&"read".to_string())
            && policy.syscalls.allowed.contains(&"openat".to_string())
            && !policy.syscalls.allowed.contains(&"execve".to_string()),
        "deny-wins prunes the unioned allow list: {:?}",
        policy.syscalls.allowed
    );
}

// The emitted document carries the deny entries — a resolve → reload
// round trip must not widen the policy.
#[test]
fn test_v3_syscall_deny_emit_round_trip() {
    let policy = parse_kdl_policy(
        r#"
            policy version=3
            defaults {
                syscalls {
                    allow "read"
                    deny "execve"
                }
            }
        "#,
    )
    .unwrap();
    assert_eq!(policy.syscalls.denied, vec!["execve"]);
    assert!(!policy.syscalls.allowed.contains(&"execve".to_string()));

    let emitted = policy.to_kdl();
    let reparsed = parse_kdl_policy(&emitted)
        .unwrap_or_else(|e| panic!("emitted policy must re-parse: {e}\n{emitted}"));
    assert_eq!(reparsed.syscalls.denied, vec!["execve"]);
    assert!(!reparsed.syscalls.allowed.contains(&"execve".to_string()));
}

// ── multiple profiles ───────────────────────────────────────────────

#[test]
fn test_v3_multiple_profiles_union_in_order() {
    let dir = make_test_dir("v3_multi_profile");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=3
            profile "p1" {
                filesystem {
                    allow "/one/**"
                }
            }
            profile "p2" {
                filesystem {
                    allow "/two/**"
                }
            }
            server "s" {
                tool "t" {
                    profile "p1" "p2"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    let t = policy.tools.iter().find(|t| t.name == "t").unwrap();
    let fs = t.fs.as_ref().unwrap();
    assert!(
        fs.allowed_paths.contains(&"/one/**".to_string())
            && fs.allowed_paths.contains(&"/two/**".to_string()),
        "both profiles must compose: {fs:?}"
    );
}

#[test]
fn test_v2_multiple_profiles_rejected() {
    let dir = make_test_dir("v2_multi_profile");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            profile "p1" {
                filesystem {
                    allow "/one/**"
                }
            }
            profile "p2" {
                filesystem {
                    allow "/two/**"
                }
            }
            server "s" {
                tool "t" {
                    profile "p1" "p2"
                }
            }
        "#,
    )
    .unwrap();

    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("version=3"),
        "v2 must refuse multiple profile names: {err}"
    );
}

// The full chain — defaults → profile → server-defaults → tool — is
// additive under v3.
#[test]
fn test_v3_profile_server_defaults_tool_compose_additively() {
    let dir = make_test_dir("v3_layer_chain");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=3
            defaults {
                filesystem {
                    allow "/global/**"
                }
            }
            profile "p" {
                filesystem {
                    allow "/profile/**"
                }
            }
            server "s" {
                server-defaults {
                    filesystem {
                        allow "/server/**"
                    }
                }
                tool "t" {
                    profile "p"
                    filesystem {
                        allow "/tool/**"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    let t = policy.tools.iter().find(|t| t.name == "t").unwrap();
    let fs = t.fs.as_ref().unwrap();
    for path in ["/global/**", "/profile/**", "/server/**", "/tool/**"] {
        assert!(
            fs.allowed_paths.contains(&path.to_string()),
            "tool fs must contain {path} from every layer: {fs:?}"
        );
    }
}

// `replace=#true` on the tool's own block drops every inherited
// layer's allow side, leaving exactly what the tool declared.
#[test]
fn test_v3_tool_replace_clears_inherited_layers() {
    let dir = make_test_dir("v3_tool_replace");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=3
            defaults {
                filesystem {
                    allow "/global/**"
                }
            }
            profile "p" {
                filesystem {
                    allow "/profile/**"
                }
            }
            server "s" {
                tool "t" {
                    profile "p"
                    filesystem replace=#true {
                        allow "/only/**"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    let t = policy.tools.iter().find(|t| t.name == "t").unwrap();
    let fs = t.fs.as_ref().unwrap();
    assert_eq!(
        fs.allowed_paths,
        vec!["/only/**"],
        "tool replace=#true narrows to exactly the declared list: {fs:?}"
    );
}

// deny-wins spans composition layers: a defaults-level deny prunes a
// profile's covered allow even though the deny landed first.
#[test]
fn test_v3_deny_wins_across_layers() {
    let dir = make_test_dir("v3_deny_wins");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=3
            defaults {
                filesystem {
                    deny "/secret/**"
                }
            }
            profile "p" {
                filesystem {
                    allow "/data/**"
                    allow "/secret/keys"
                }
            }
            server "s" {
                tool "t" {
                    profile "p"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("policy.kdl")).unwrap();
    let t = policy.tools.iter().find(|t| t.name == "t").unwrap();
    let fs = t.fs.as_ref().unwrap();
    assert!(
        fs.allowed_paths.contains(&"/data/**".to_string())
            && !fs.allowed_paths.iter().any(|p| p == "/secret/keys"),
        "the defaults deny must prune the profile's covered allow: {fs:?}"
    );
}

// ── declaration rules ───────────────────────────────────────────────

// Under v3 `allow none=#true` on a union layer would silently widen —
// the narrowed scope unions back with the inherited grants — so the
// spelling must pair with `replace=#true`.
#[test]
fn test_v3_allow_none_requires_replace() {
    let dir = make_test_dir("v3_none_replace");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=3
            defaults {
                filesystem {
                    allow "/global/**"
                }
            }
            server "s" {
                tool "t" {
                    filesystem {
                        allow none=#true
                    }
                }
            }
        "#,
    )
    .unwrap();

    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("replace=#true"),
        "allow none without replace must refuse under v3: {err}"
    );
}

// `replace` on a block is a v3 declaration; v2 refuses it, v1 ignores
// it (permissive grammar).
#[test]
fn test_replace_flag_requires_v3() {
    let dir = make_test_dir("replace_flag_v2");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=2
            defaults {
                filesystem replace=#true {
                    allow "/x/**"
                }
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("version=3"),
        "v2 must refuse 'replace': {err}"
    );
}

// ── ancestor version validation ─────────────────────────────────────

// Every file in a composition validates its own version: a v3 entry
// with a v3 ancestor loads; a v4 ancestor is refused with the same
// "unsupported policy version" surface a v1/v2-only binary gives a v3
// document.
#[test]
fn test_v3_ancestor_version_still_validated() {
    let dir = make_test_dir("v3_ancestor");
    std::fs::write(dir.join("base.kdl"), "policy version=3\n").unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=3
        "#,
    )
    .unwrap();
    load_kdl_policy(&dir.join("child.kdl")).unwrap();

    std::fs::write(dir.join("future.kdl"), "policy version=4\n").unwrap();
    std::fs::write(
        dir.join("from_future.kdl"),
        r#"
            extends "future.kdl"
            policy version=3
        "#,
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("from_future.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("unsupported policy version 4"),
        "a version newer than supported must refuse, in any position: {err}"
    );
    assert!(
        err.to_string().contains("future.kdl"),
        "the refusal names the offending file: {err}"
    );
}

// ── when / include composition keeps v3 semantics ───────────────────

#[test]
fn test_v3_when_block_defaults_union() {
    let dir = make_test_dir("v3_when_union");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=3
            defaults {
                filesystem {
                    allow "/base/**"
                }
            }
            when environment="prod" {
                defaults {
                    filesystem {
                        allow "/prod/**"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy_with_env(&dir.join("policy.kdl"), "prod").unwrap();
    assert!(
        policy.fs.read_only.contains(&"/base/**".to_string())
            && policy.fs.read_only.contains(&"/prod/**".to_string()),
        "a matching when block unions under v3: {:?}",
        policy.fs.read_only
    );
}

#[test]
fn test_v3_include_unions_allow_lists() {
    let dir = make_test_dir("v3_include_union");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=3
            defaults {
                syscalls {
                    allow "read"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "extra.kdl"
            policy version=3
            defaults {
                syscalls {
                    allow "execve"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
    assert!(
        policy.syscalls.allowed.contains(&"read".to_string())
            && policy.syscalls.allowed.contains(&"execve".to_string()),
        "include unions the syscall allow lists under v3: {:?}",
        policy.syscalls.allowed
    );
}

#[test]
fn test_v2_include_still_replaces_syscalls() {
    let dir = make_test_dir("v2_include_syscalls");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=2
            defaults {
                syscalls {
                    allow "read"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "extra.kdl"
            policy version=2
            defaults {
                syscalls {
                    allow "execve"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
    assert_eq!(
        policy.syscalls.allowed,
        vec!["execve"],
        "v2 keeps replacement semantics"
    );
}
