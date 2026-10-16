use super::*;

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
    let tmp = make_test_dir("test_r04_when");

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
}

#[test]
fn test_r04_include_retains_logging_and_deputy() {
    let tmp = make_test_dir("test_r04_inc");

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
}

#[test]
fn test_include_retains_trajectory() {
    let tmp = make_test_dir("test_r04_inc_traj");

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
}

#[test]
fn test_cross_file_profile_inheritance() {
    let tmp = make_test_dir("test_profile_sharing");

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
}
