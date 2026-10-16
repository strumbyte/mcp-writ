use super::*;

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
    let err = load_kdl_policy_internal(
        &dir.join("policy.kdl"),
        &mut HashSet::new(),
        "prod",
        &mut Vec::new(),
    )
    .unwrap_err();
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
    let policy = load_kdl_policy_internal(
        &dir.join("policy.kdl"),
        &mut HashSet::new(),
        "",
        &mut Vec::new(),
    )
    .unwrap();
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
    let policy = load_kdl_policy_internal(
        &dir.join("policy.kdl"),
        &mut HashSet::new(),
        "prod",
        &mut Vec::new(),
    )
    .unwrap();
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
    let policy = load_kdl_policy_internal(
        &dir.join("policy.kdl"),
        &mut HashSet::new(),
        "dev",
        &mut Vec::new(),
    )
    .unwrap();
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
