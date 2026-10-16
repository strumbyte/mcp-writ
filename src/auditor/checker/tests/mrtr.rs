use super::*;

// --- MCP 2026-07-28 + 2025-11-25 / MRTR ---

fn fixture(name: &str) -> String {
    let path = format!("{}/tests/fixtures/mrtr/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

#[test]
fn test_input_responses_mode_resolve_exhaustive() {
    for mode in [
        InputResponsesMode::Auto,
        InputResponsesMode::Deny,
        InputResponsesMode::Allow,
        InputResponsesMode::Inspect,
    ] {
        let with_schema = mode.resolve(true);
        let without_schema = mode.resolve(false);
        match mode {
            InputResponsesMode::Auto => {
                assert_eq!(with_schema, ResolvedInputResponses::Deny);
                assert_eq!(without_schema, ResolvedInputResponses::Allow);
            }
            InputResponsesMode::Deny => {
                assert_eq!(with_schema, ResolvedInputResponses::Deny);
                assert_eq!(without_schema, ResolvedInputResponses::Deny);
            }
            InputResponsesMode::Allow => {
                assert_eq!(with_schema, ResolvedInputResponses::Allow);
                assert_eq!(without_schema, ResolvedInputResponses::Allow);
            }
            InputResponsesMode::Inspect => {
                assert_eq!(with_schema, ResolvedInputResponses::Inspect);
                assert_eq!(without_schema, ResolvedInputResponses::Inspect);
            }
        }
    }
}

#[test]
fn test_mrtr_retry_denied_tool_still_denied() {
    let policy = test_policy();
    let line = fixture("retry_denied_tool.json");
    let err = check_request(&line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "exec_shell");
    assert!(err.reason.contains("not allowed"), "got: {}", err.reason);
}

#[test]
fn test_mrtr_retry_unknown_tool_still_denied() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"not_listed","arguments":{},"inputResponses":{"e":{"action":"accept"}},"requestState":"opaque"}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(err.reason.contains("default deny"), "got: {}", err.reason);
}

#[test]
fn test_mrtr_retry_allowed_tool_without_schema_passes() {
    let policy = test_policy();
    let line = fixture("mcp_2026_07_28_tools_call_retry.json");
    let pass = check_request(&line, &policy).unwrap();
    assert!(
        pass.audit_notes
            .iter()
            .any(|n| n.contains("requestState present")),
        "notes: {:?}",
        pass.audit_notes
    );
    assert!(
        pass.audit_notes
            .iter()
            .any(|n| n.contains("protocolVersion=2026-07-28")),
        "notes: {:?}",
        pass.audit_notes
    );
}

#[test]
fn test_input_responses_denied_when_args_schema_auto() {
    let policy = schema_policy();
    let line = fixture("mcp_2026_07_28_tools_call_with_input_responses.json");
    let err = check_request(&line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    assert!(err.reason.contains("secure default"), "got: {}", err.reason);
}

#[test]
fn test_input_responses_opt_in_allow_with_schema() {
    let mut policy = schema_policy();
    policy.tools[0].input_responses = InputResponsesMode::Allow;
    let line = fixture("mcp_2026_07_28_tools_call_with_input_responses.json");
    assert!(check_request(&line, &policy).is_ok());
}

#[test]
fn test_input_responses_inspect_with_schema() {
    let mut policy = schema_policy();
    policy.tools[0].input_responses = InputResponsesMode::Inspect;
    let line = fixture("mcp_2026_07_28_tools_call_with_input_responses.json");
    let pass = check_request(&line, &policy).unwrap();
    assert!(
        pass.audit_notes
            .iter()
            .any(|n| n.contains("inputResponses present (inspect)")),
        "notes: {:?}",
        pass.audit_notes
    );
}

#[test]
fn test_input_responses_explicit_deny_without_schema() {
    let mut policy = test_policy();
    policy.tools[0].input_responses = InputResponsesMode::Deny;
    let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{},"inputResponses":{"e":{"action":"accept"}}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(err.reason.contains("tool policy"), "got: {}", err.reason);
}

#[test]
fn test_use_role_deputy_counts_as_security_contract() {
    // A `deputy role="use"` tool is a security contract like an
    // args_schema: `inputResponses` (the MRTR retry channel) denies
    // under the secure default until the policy opts in.
    use crate::policy::deputy::{DeputyPolicy, DeputyRole, DeputyRule, KnownShape};
    let mut policy = test_policy();
    policy.tools[0].deputy = Some(DeputyPolicy {
        role: DeputyRole::Use,
        rules: vec![DeputyRule::Shape(KnownShape::FsTargets)],
    });
    let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{},"inputResponses":{"e":{"action":"accept"}}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(err.reason.contains("secure default"), "got: {}", err.reason);
}

#[test]
fn test_extract_deputy_use_targets_pointer_shape_and_truncate() {
    use crate::policy::deputy::{DeputyRule, ExtractPointer, KnownShape};

    let line = r#"{"params":{"arguments":{"path":"/workspace/a.txt","note":"hi"}}}"#;
    let p = ExtractPointer::parse("/params/arguments/path", "params").unwrap();
    let out = extract_deputy_use_targets(line, &[DeputyRule::Pointer(p)]).unwrap();
    assert_eq!(out, vec!["/workspace/a.txt".to_string()]);

    // A `file:` URI normalizes to the fs path, but the use side refuses
    // the non-canonical spelling: the discovery check ran on the
    // normalized form while the server consumes the forwarded raw one.
    let line = r#"{"params":{"arguments":{"path":"file:///workspace/a.txt"}}}"#;
    let p = ExtractPointer::parse("/params/arguments/path", "params").unwrap();
    let err = extract_deputy_use_targets(line, &[DeputyRule::Pointer(p)]).unwrap_err();
    assert!(err.contains("canonical form"), "got: {err}");

    // `shape "fs_targets"` reads the well-known path argument keys.
    let line = r#"{"params":{"arguments":{"path":"/workspace/a.txt"}}}"#;
    let out =
        extract_deputy_use_targets(line, &[DeputyRule::Shape(KnownShape::FsTargets)]).unwrap();
    assert!(
        out.contains(&"/workspace/a.txt".to_string()),
        "got: {out:?}"
    );

    // Extraction that would overflow the value bound fails closed —
    // the unchecked tail can never be waived through.
    let big = (0..(crate::policy::deputy::MAX_EXTRACT_VALUES + 1))
        .map(|i| format!("\"/p{i}\""))
        .collect::<Vec<_>>()
        .join(",");
    let line = format!(r#"{{"params":{{"arguments":{{"files":[{big}]}}}}}}"#);
    let p = ExtractPointer::parse("/params/arguments/files/*", "params").unwrap();
    let err = extract_deputy_use_targets(&line, &[DeputyRule::Pointer(p)]).unwrap_err();
    assert!(err.contains("value bound"), "got: {err}");
}

#[test]
fn test_extract_deputy_use_targets_covers_input_responses() {
    use crate::policy::deputy::{DeputyRule, ExtractPointer};

    // A pointer naming only the arguments location must still vet
    // paths inside `params.inputResponses` — an opted-in MRTR retry
    // carries request-side input the tool may consume as a path.
    let line = r#"{"params":{"arguments":{"path":"/workspace/a.txt"},"inputResponses":{"e":{"action":"accept","content":{"path":"/workspace/sneaky.txt"}}}}}"#;
    let p = ExtractPointer::parse("/params/arguments/path", "params").unwrap();
    let out = extract_deputy_use_targets(line, &[DeputyRule::Pointer(p.clone())]).unwrap();
    assert!(
        out.contains(&"/workspace/a.txt".to_string())
            && out.contains(&"/workspace/sneaky.txt".to_string()),
        "got: {out:?}"
    );

    // Non-path answers are not extracted — the walk is classified,
    // not "every string".
    let line = r#"{"params":{"arguments":{"path":"/workspace/a.txt"},"inputResponses":{"e":{"action":"accept","content":{"name":"octocat"}}}}}"#;
    let out = extract_deputy_use_targets(line, &[DeputyRule::Pointer(p.clone())]).unwrap();
    assert_eq!(out, vec!["/workspace/a.txt".to_string()]);
}

#[test]
fn test_request_state_opaque_passthrough_under_cap() {
    let policy = test_policy();
    let line = fixture("mcp_2026_07_28_tools_call_with_request_state.json");
    let pass = check_request(&line, &policy).unwrap();
    assert!(
        pass.audit_notes
            .iter()
            .any(|n| n.contains("requestState present")),
        "notes: {:?}",
        pass.audit_notes
    );
    // Contents must not be treated as a filesystem path / structured input.
    assert!(pass.sub_policy.is_none());
}

#[test]
fn test_request_state_over_size_cap_rejected() {
    let policy = test_policy();
    let huge = "x".repeat(REQUEST_STATE_MAX_BYTES + 1);
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{{"name":"read_file","arguments":{{}},"requestState":"{huge}"}}}}"#
    );
    let err = check_request(&line, &policy).unwrap_err();
    assert!(err.reason.contains("size cap"), "got: {}", err.reason);
}

#[test]
fn test_request_state_over_cap_generic_path() {
    // The generic-path cap sees any method, not just tools/call.
    let huge = "x".repeat(REQUEST_STATE_MAX_BYTES + 1);
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":8,"method":"resources/read","params":{{"uri":"file:///a","requestState":"{huge}"}}}}"#
    );
    assert_eq!(
        request_state_over_cap(&line),
        Some(REQUEST_STATE_MAX_BYTES + 1)
    );
    // Absent member, under-cap value, non-request line, and invalid
    // JSON are all `None` (never rejected here).
    assert_eq!(
        request_state_over_cap(
            r#"{"jsonrpc":"2.0","id":8,"method":"resources/read","params":{"uri":"file:///a"}}"#
        ),
        None
    );
    assert_eq!(
        request_state_over_cap(
            r#"{"jsonrpc":"2.0","id":8,"method":"ping","params":{"requestState":"small"}}"#
        ),
        None
    );
    assert_eq!(request_state_over_cap("not json"), None);
    // A non-string member is measured on its raw text — still opaque.
    let big_object = format!(
        r#"{{"jsonrpc":"2.0","id":8,"method":"ping","params":{{"requestState":{{"blob":"{huge}"}}}}}}"#
    );
    assert!(request_state_over_cap(&big_object).is_some());
}

#[test]
fn test_request_state_does_not_bypass_fs_sub_policy() {
    let policy = sub_policy_policy();
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}},"requestState":"eyJwYXRoIjoiL3dvcmtzcGFjZS9va2F5In0"}}}}"#,
        ws_at("secrets/key.pem")
    );
    let err = check_request(&line, &policy).unwrap_err();
    assert!(
        err.reason.contains("denied by tool fs sub-policy"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_classify_request_protocol_version() {
    let mcp_2026_07_28 = fixture("mcp_2026_07_28_tools_call_retry.json");
    assert_eq!(
        classify_request_protocol_version(&mcp_2026_07_28),
        RequestProtocolVersion::Mcp2026July28
    );
    assert_eq!(
        classify_request_protocol_version(
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#
        ),
        RequestProtocolVersion::Mcp2025November25
    );
    assert_eq!(
        classify_request_protocol_version(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
        RequestProtocolVersion::Unspecified
    );
    assert_eq!(
        classify_request_protocol_version(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-08-01"}}}"#
        ),
        RequestProtocolVersion::Other
    );
}

#[test]
fn test_2025_11_25_initialize_and_2026_07_28_meta_passthrough() {
    let policy = test_policy();
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#;
    let init_pass = check_request(init, &policy).unwrap();
    assert!(
        init_pass
            .audit_notes
            .iter()
            .any(|n| n.contains("protocolVersion=2025-11-25")),
        "notes: {:?}",
        init_pass.audit_notes
    );
    let mcp_2026_07_28_list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
    let pass = check_request(mcp_2026_07_28_list, &policy).unwrap();
    assert!(
        pass.audit_notes
            .iter()
            .any(|n| n.contains("protocolVersion=2026-07-28")),
        "notes: {:?}",
        pass.audit_notes
    );
}

#[test]
fn test_request_protocol_version_exhaustive() {
    for version in [
        RequestProtocolVersion::Mcp2026July28,
        RequestProtocolVersion::Mcp2025November25,
        RequestProtocolVersion::Other,
        RequestProtocolVersion::Unspecified,
    ] {
        match version {
            RequestProtocolVersion::Mcp2026July28 => {
                assert_eq!(version, RequestProtocolVersion::Mcp2026July28);
            }
            RequestProtocolVersion::Mcp2025November25 => {
                assert_eq!(version, RequestProtocolVersion::Mcp2025November25);
            }
            RequestProtocolVersion::Other => {
                assert_eq!(version, RequestProtocolVersion::Other);
            }
            RequestProtocolVersion::Unspecified => {
                assert_eq!(version, RequestProtocolVersion::Unspecified);
            }
        }
    }
}

#[test]
fn test_escaped_tools_call_caught() {
    let mut policy = Policy::default();
    policy.tools.push(ToolPolicy::named("exec_shell", false));

    // Unescaped denied method
    let r1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_shell","arguments":{}}}"#;
    assert!(check_request(r1, &policy).is_err());

    // Escaped slash
    let r2 = r#"{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"exec_shell","arguments":{}}}"#;
    assert!(check_request(r2, &policy).is_err());

    // Unicode escaped slash
    let r3 = r#"{"jsonrpc":"2.0","id":1,"method":"tools\u002fcall","params":{"name":"exec_shell","arguments":{}}}"#;
    assert!(check_request(r3, &policy).is_err());
}

#[test]
fn test_batch_request_rejected() {
    let policy = test_policy();
    let batch = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}]"#;
    let err = check_request(batch, &policy).unwrap_err();
    assert!(
        err.reason.contains("batch requests are not supported"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_duplicate_key_rejected() {
    let policy = test_policy();
    let dup = r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let err = check_request(dup, &policy).unwrap_err();
    assert!(err.reason.contains("duplicate key"), "got: {}", err.reason);
}

#[test]
fn test_escaped_arguments_path() {
    let mut policy = Policy::default();
    let mut read = ToolPolicy::named("read_file", true);
    read.fs = Some(FsToolPolicy::new(
        // Narrower than cwd so a Windows drive path joined to cwd cannot
        // accidentally match when the suite is run from `/workspace`.
        vec!["/workspace/src/**".into()],
        vec![],
    ));
    policy.tools = vec![read];

    // Escaped outside path: /etc/\u0070asswd -> /etc/passwd (should be denied)
    let r1 = r#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/\u0070asswd"}}}"#;
    assert!(check_request(r1, &policy).is_err());

    // Escaped windows outside path: C:\\secret.txt (should be denied)
    let r2 = r#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"C:\\secret.txt"}}}"#;
    assert!(check_request(r2, &policy).is_err());
}

#[test]
fn test_url_userinfo_and_wildcards() {
    let mut policy = Policy::default();
    policy.network.outbound.deny_all_others = false;
    let mut fetch = ToolPolicy::named("fetch", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec!["api.example.com".into()],
        allowed_cidrs: Vec::new(),
        denied_hosts: vec![],
        denied_cidrs: Vec::new(),
        egress_rules: Vec::new(),
        allow_specified: true,
    });
    policy.tools = vec![fetch];

    // Userinfo spoofing: destination is evil.test, should be denied
    let r1 = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://api.example.com:password@evil.test/file"}}}"#;
    assert!(check_request(r1, &policy).is_err());

    // Protocol-relative outside host: evil.test, should be denied
    let r2 = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"//evil.test/file"}}}"#;
    assert!(check_request(r2, &policy).is_err());

    // Single wildcard deny="*"
    policy.tools[0].network = Some(ToolNetworkPolicy {
        allowed_hosts: vec![],
        allowed_cidrs: Vec::new(),
        denied_hosts: vec!["*".into()],
        denied_cidrs: Vec::new(),
        egress_rules: Vec::new(),
        allow_specified: false,
    });
    let r3 = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://evil.test/file"}}}"#;
    assert!(check_request(r3, &policy).is_err());
}

#[test]
fn test_nested_duplicate_key_rejected() {
    let policy = test_policy();
    // duplicate name in params
    let dup1 = r#"{"method":"tools/call","params":{"name":"read_file","name":"exec_shell","arguments":{}}}"#;
    let err1 = check_request(dup1, &policy).unwrap_err();
    assert!(
        err1.reason.contains("duplicate key 'name'"),
        "got: {}",
        err1.reason
    );

    // duplicate path in arguments
    let dup2 = r#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/file","path":"/etc/passwd"}}}"#;
    let err2 = check_request(dup2, &policy).unwrap_err();
    assert!(
        err2.reason.contains("duplicate key 'path'"),
        "got: {}",
        err2.reason
    );
}
