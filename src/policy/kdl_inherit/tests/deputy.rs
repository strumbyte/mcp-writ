use super::*;

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
