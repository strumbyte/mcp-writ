//! RPC contracts for path-free MCP tools sharing runtime/bootstrap OS grants.
use mcp_writ::auditor::checker::check_request;
use mcp_writ::policy::Policy;
use mcp_writ::policy::kdl_loader::{load_kdl_policy_with_env, parse_kdl_policy};
use mcp_writ::policy::validator::validate_policy;

fn policy_text(fs_rules: &str) -> String {
    format!(
        r#"
policy version=1
defaults {{
    filesystem {{
        allow "/fixture/runtime" mode="read"
    }}
}}
server "fixture" {{
    tool "runtime_info" {{
        filesystem {{
            {fs_rules}
        }}
    }}
    tool "read_file"
    tool "blocked_echo" deny=#true
}}
"#
    )
}

fn pathless_policy() -> Policy {
    let policy = parse_kdl_policy(&policy_text("allow none=#true; require-path #false")).unwrap();
    validate_policy(&policy).unwrap();
    policy
}

fn request(name: &str, arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
    )
}

#[test]
fn pathless_tools_preserve_bootstrap_grants_and_require_explicit_opt_in() {
    let policy = pathless_policy();
    assert_eq!(policy.fs.read_only, ["/fixture/runtime"]);
    let fs = policy.tools[0].fs.as_ref().unwrap();
    assert!(fs.allows_pathless_call());
    assert!(fs.allowed_paths.is_empty());
    for args in ["{}", r#"{"workers":8,"rounds":8,"message":"hello"}"#] {
        check_request(&request("runtime_info", args), &policy).unwrap();
    }
    // The earlier fail-closed default is unchanged for a file-using tool.
    let error = check_request(&request("read_file", "{}"), &policy).unwrap_err();
    assert!(error.reason.contains("missing a path target"));
    assert!(check_request(&request("blocked_echo", "{}"), &policy).is_err());

    for rules in ["allow none=#true", "allow none=#true; require-path #true"] {
        let strict = parse_kdl_policy(&policy_text(rules)).unwrap();
        assert!(check_request(&request("runtime_info", "{}"), &strict).is_err());
    }
}

#[test]
fn explicit_require_path_is_enforced_without_other_fs_rules() {
    let policy = parse_kdl_policy(
        "policy version=1\nserver \"fixture\" { tool \"runtime_info\" { filesystem { require-path #true; }; }; }",
    ).unwrap();
    validate_policy(&policy).unwrap();
    assert!(policy.tools[0].has_security_contract());
    let error = check_request(&request("runtime_info", "{}"), &policy).unwrap_err();
    assert!(error.reason.contains("missing a path target"));
}

#[test]
fn pathless_tools_still_reject_paths_network_and_mrtr_inputs() {
    let policy = pathless_policy();
    for args in [
        r#"{"path":"/fixture/runtime/data"}"#,
        r#"{"path":"/etc/passwd"}"#,
        r#"{"file":"C:\\secret.txt"}"#,
        r#"{"nested":[{"value":"/outside/file"}]}"#,
        r#"{"uri":"file:///etc/passwd"}"#,
        r#"{"path":"/etc/\u0070asswd"}"#,
        r#"{"url":"https://example.com/"}"#,
        r#"{"host":"example.com"}"#,
    ] {
        assert!(
            check_request(&request("runtime_info", args), &policy).is_err(),
            "unexpectedly allowed {args}"
        );
    }
    let mrtr = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"runtime_info","arguments":{},"inputResponses":[]}}"#;
    let error = check_request(mrtr, &policy).unwrap_err();
    assert!(error.reason.contains("inputResponses denied"));
}

#[test]
fn pathless_contract_rejects_ambiguous_or_permissive_configuration() {
    for rules in [
        "require-path #false",
        "allow \"/data/**\"; require-path #false",
        "allow none=#true; allow \"/data/**\" mode=\"write\"; require-path #false",
        "allow none=#true; require-path \"false\"",
        "allow none=#true; require-path #false #true",
        "allow none=#true; require-path #false extra=#true",
        "allow none=#true; require-path #false { ignored; }",
        "allow none=#true; require-path #false; require-path #true",
    ] {
        assert!(
            parse_kdl_policy(&policy_text(rules)).is_err(),
            "accepted {rules}"
        );
    }
    assert!(
        parse_kdl_policy("policy version=1\ndefaults { filesystem { require-path #false; }; }")
            .is_err(),
        "the option is not a process/global filesystem setting"
    );

    // A caller constructing structs directly must not bypass the closed-list rule.
    let mut invalid = pathless_policy();
    invalid.tools[0]
        .fs
        .as_mut()
        .unwrap()
        .allowed_paths
        .push("/data/**".into());
    assert!(validate_policy(&invalid).is_err());
    assert!(check_request(&request("runtime_info", "{}"), &invalid).is_err());
}

#[test]
fn pathless_contract_survives_profiles_and_serialization() {
    let text = r#"
policy version=1
defaults {
    filesystem { allow "/fixture/runtime"; }
}
profile "pathless" {
    filesystem { allow none=#true; require-path #false; }
}
server "fixture" {
    tool "runtime_info" profile="pathless"
}
"#;
    let policy = parse_kdl_policy(text).unwrap();
    validate_policy(&policy).unwrap();
    let serialized = policy.to_kdl();
    assert!(serialized.contains("require-path #false"));
    let reloaded = parse_kdl_policy(&serialized).unwrap();
    validate_policy(&reloaded).unwrap();
    assert_eq!(policy.tools[0].fs, reloaded.tools[0].fs);
    check_request(&request("runtime_info", "{}"), &reloaded).unwrap();
    assert!(
        check_request(
            &request("runtime_info", r#"{"path":"/fixture/runtime/data"}"#),
            &reloaded
        )
        .is_err()
    );
}

#[test]
fn pathless_contract_survives_extends_and_can_be_tightened() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("base.kdl"),
        policy_text("allow none=#true; require-path #false"),
    )
    .unwrap();
    let path = dir.path().join("child.kdl");
    std::fs::write(
        &path,
        "extends \"base.kdl\"\npolicy version=1\nserver \"fixture\" { tool \"runtime_info\"; }",
    )
    .unwrap();
    let inherited = load_kdl_policy_with_env(&path, "").unwrap();
    check_request(&request("runtime_info", "{}"), &inherited).unwrap();

    std::fs::write(&path, "extends \"base.kdl\"\npolicy version=1\nserver \"fixture\" { tool \"runtime_info\" { filesystem { require-path #true; }; }; }").unwrap();
    let tightened = load_kdl_policy_with_env(&path, "").unwrap();
    assert_eq!(
        tightened.tools[0].fs.as_ref().unwrap().require_path,
        Some(true)
    );
    assert!(check_request(&request("runtime_info", "{}"), &tightened).is_err());
}

#[test]
fn pathless_when_override_is_not_replaced_by_runtime_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.kdl");
    let text = r#"
policy version=1
defaults { filesystem { allow "/fixture/runtime"; }; }
server "fixture" { tool "runtime_info"; }
when environment="pathless" {
    server "fixture" {
        tool "runtime_info" {
            filesystem { allow none=#true; require-path #false; }
        }
    }
}
"#;
    std::fs::write(&path, text).unwrap();
    let strict = load_kdl_policy_with_env(&path, "").unwrap();
    assert!(check_request(&request("runtime_info", "{}"), &strict).is_err());
    let opted_in = load_kdl_policy_with_env(&path, "pathless").unwrap();
    assert!(opted_in.tools[0].fs_explicit);
    check_request(&request("runtime_info", "{}"), &opted_in).unwrap();
    assert!(
        check_request(
            &request("runtime_info", r#"{"path":"/fixture/runtime/data"}"#),
            &opted_in
        )
        .is_err()
    );
}
