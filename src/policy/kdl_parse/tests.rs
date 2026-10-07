use super::*;

fn parse_err(src: &str) -> PolicyError {
    parse_kdl_policy(src).expect_err("policy must fail to load")
}

#[test]
fn mcp_rule_rejects_duplicate_direction() {
    // A second `direction` on one rule is ambiguous — the load must
    // fail closed (whether the KDL document layer or the rule
    // parser reports it).
    let err = parse_err(
        r#"policy version=2
server "s" {
mcp {
    allow "tools/call" direction="c2s" direction="s2c"
}
}"#,
    );
    assert!(matches!(err, PolicyError::KdlParse(_)), "{err:?}");

    // A single direction still parses.
    assert!(
        parse_kdl_policy(
            r#"policy version=2
server "s" {
mcp {
    allow "tools/call" direction="c2s"
}
}"#
        )
        .is_ok()
    );
}

#[test]
fn tool_rejects_conflicting_profile_declarations() {
    // `profile` and `profiles` siblings are two competing spellings
    // for one reference — declaring both is a load error, not a
    // first-found pick.
    let err = parse_err(
        r#"policy version=2
profile "p" {}
server "s" {
tool "t" {
    profile "p"
    profiles "p"
}
}"#,
    );
    assert!(
        matches!(&err, PolicyError::KdlParse(m) if m.contains("both 'profile' and 'profiles'")),
        "{err:?}"
    );

    // The property form plus any child form is equally ambiguous.
    for child in ["profile", "profiles"] {
        let err = parse_err(&format!(
            r#"policy version=2
profile "p" {{}}
server "s" {{
tool "t" profile="p" {{
    {child} "p"
}}
}}"#
        ));
        assert!(
            matches!(&err, PolicyError::KdlParse(m) if m.contains("property")),
            "{child}: {err:?}"
        );
    }
}

#[test]
fn tool_accepts_single_profile_declaration_forms() {
    for decl in [
        r#"tool "t" profile="p""#,
        "tool \"t\" {\n        profile \"p\"\n    }",
        "tool \"t\" {\n        profiles \"p\"\n    }",
    ] {
        let src = format!("policy version=2\nprofile \"p\" {{}}\nserver \"s\" {{\n    {decl}\n}}");
        assert!(parse_kdl_policy(&src).is_ok(), "{decl}");
    }
}
