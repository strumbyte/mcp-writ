use super::*;

// --- F66/F11/F12: decoy arguments and unrecognized fields cannot smuggle
//     an unchecked selector past a restricted contract ---

fn decoy_policy() -> Policy {
    let mut read = ToolPolicy::named("read_file", true);
    read.fs = Some(FsToolPolicy::new(vec![ws()], Vec::new()));
    let mut fetch = ToolPolicy::named("fetch_url", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec!["api.example.com".to_string()],
        allowed_cidrs: Vec::new(),
        denied_hosts: vec!["evil.com".to_string()],
        denied_cidrs: Vec::new(),
        egress_rules: Vec::new(),
        allow_specified: true,
    });
    let mut policy = Policy {
        tools: vec![read, fetch],
        ..Default::default()
    };
    policy.network.outbound.deny_all_others = false;
    policy
}

#[test]
fn test_unclassified_plausible_arg_denied_beside_fs_decoy() {
    // The allowed `path` must not license an unchecked selector under an
    // unrecognized key — the forwarded request carries both fields.
    let policy = decoy_policy();
    for mystery in ["u@h", "sneaky.example", "~/loot", "report.txt", "../win"] {
        let args = format!(r#"{{"path":"{}","mystery":"{mystery}"}}"#, ws_at("a.txt"));
        let err = check_request(&tools_call(1, "read_file", &args), &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("unrecognized argument")
                || err.reason.contains("not in tool fs allowed paths")
                || err.reason.contains("denied by tool fs sub-policy")
                || err.reason.contains("could not be resolved"),
            "mystery={mystery} must be refused, got: {}",
            err.reason
        );
    }
    // A bare word is ordinary payload — not a selector — and still passes.
    let ok = tools_call(
        2,
        "read_file",
        &format!(r#"{{"path":"{}","mystery":"hello"}}"#, ws_at("a.txt")),
    );
    assert!(
        check_request(&ok, &policy).is_ok(),
        "bare word must stay forwardable"
    );
    // Declared payload fields keep carrying resource-shaped free text.
    let ok = tools_call(
        3,
        "read_file",
        &format!(
            r#"{{"path":"{}","note":"see ./report.txt for details"}}"#,
            ws_at("a.txt")
        ),
    );
    assert!(
        check_request(&ok, &policy).is_ok(),
        "payload field text must stay forwardable"
    );
}

#[test]
fn test_unclassified_destination_denied_beside_net_decoy() {
    let policy = decoy_policy();
    // A bare dotted name under an unknown key is a plausible selector and
    // is refused outright — the allowed `url` does not cover it.
    let err = check_request(
        &tools_call(
            1,
            "fetch_url",
            r#"{"url":"https://api.example.com","mystery":"sneaky.example"}"#,
        ),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("unrecognized argument"),
        "got: {}",
        err.reason
    );
    // IP/socket spellings classify as hosts under any key and hit the
    // tool allow-list instead of falling through unrecognized.
    for mystery in ["10.9.9.9", "10.9.9.9:4444", "[2001:db8::9]:443"] {
        let args = format!(r#"{{"url":"https://api.example.com","mystery":"{mystery}"}}"#);
        let err = check_request(&tools_call(2, "fetch_url", &args), &policy).unwrap_err();
        assert!(
            err.reason.contains("not in tool network allowed hosts"),
            "mystery={mystery} must reach the allow-list check, got: {}",
            err.reason
        );
    }
}

#[test]
fn test_network_alias_fields_reach_the_policy() {
    // F12: selector aliases carry network destinations even when the
    // value is a bare host, IP, or host:port rather than a URL.
    let policy = decoy_policy();
    for (key, val) in [
        ("proxy", "evil.com:8080"),
        ("upstream", "evil.com"),
        ("server", "evil.com"),
        ("address", "evil.com"),
        ("relay", "evil.com"),
        ("peer", "evil.com"),
        ("addr", "evil.com:443"),
        ("destinationIp", "10.9.9.9"),
        ("remoteAddr", "evil.com"),
        ("endpoint", "evil.com"),
    ] {
        let args = format!(r#"{{"{key}":"{val}"}}"#);
        let err = check_request(&tools_call(1, "fetch_url", &args), &policy).unwrap_err();
        assert!(
            err.reason.contains("denied by tool network sub-policy")
                || err.reason.contains("not in tool network allowed hosts"),
            "{key}={val} must reach the network policy, got: {}",
            err.reason
        );
    }
    // A bare allowed name under an alias key checks as a host — not a
    // malformed URL — so the allow-list still admits it.
    let ok = tools_call(2, "fetch_url", r#"{"server":"api.example.com"}"#);
    assert!(
        check_request(&ok, &policy).is_ok(),
        "allowed bare name under alias key must pass"
    );
    let ok = tools_call(3, "fetch_url", r#"{"peer":"api.example.com:8443"}"#);
    assert!(
        check_request(&ok, &policy).is_ok(),
        "allowed host:port under alias key must pass"
    );
}

#[test]
fn test_secret_literals_under_arbitrary_keys_denied() {
    // F11: reserved secret spellings are filesystem targets under any
    // key — the overlay does not depend on field-name recognition.
    let policy = overlay_on_no_fs_policy();
    for lit in [
        ".env",
        ".ssh/id_rsa",
        ".gnupg/secring.gpg",
        ".aws/credentials",
    ] {
        let args = format!(r#"{{"mystery":"{lit}"}}"#);
        let err = check_request(&tools_call(1, "read_file", &args), &policy).unwrap_err();
        assert!(
            err.reason.contains("secret") || err.reason.contains("overlay"),
            "literal {lit} under an arbitrary key must hit the overlay, got: {}",
            err.reason
        );
    }
    // The same literals under a restricted fs tool are still refused even
    // with the overlay off — they evaluate as ordinary path targets.
    let mut policy = decoy_policy();
    policy.fs.secret_overlay = false;
    for lit in [".env", ".ssh/id_rsa", ".aws/credentials"] {
        let args = format!(r#"{{"path":"{}","mystery":"{lit}"}}"#, ws_at("a.txt"));
        assert!(
            check_request(&tools_call(2, "read_file", &args), &policy).is_err(),
            "literal {lit} must be refused under the fs allow contract"
        );
    }
}

#[test]
fn test_explicit_empty_allowlists_do_not_pass_on_empty_targets() {
    // `allow none` must not pass when nothing was extracted — an
    // unextractable selector is the hidden target itself.
    let mut fetch = ToolPolicy::named("fetch_url", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: Vec::new(),
        allowed_cidrs: Vec::new(),
        denied_hosts: Vec::new(),
        denied_cidrs: Vec::new(),
        egress_rules: Vec::new(),
        allow_specified: true,
    });
    let mut read = ToolPolicy::named("read_file", true);
    let mut fs_none = FsToolPolicy::new(Vec::new(), Vec::new());
    fs_none.allow_specified = true;
    read.fs = Some(fs_none);
    let mut policy = Policy {
        tools: vec![fetch, read],
        ..Default::default()
    };
    policy.network.outbound.deny_all_others = false;

    // `allow none` governs destinations that appear — it does not demand
    // a dial. A call with no network argument is legal under it.
    let ok = tools_call(1, "fetch_url", r#"{"format":"json"}"#);
    assert!(
        check_request(&ok, &policy).is_ok(),
        "allow-none call with no network arg must pass"
    );
    // But a plausible selector it cannot extract is still refused.
    let err = check_request(
        &tools_call(1, "fetch_url", r#"{"mystery":"sneaky.example"}"#),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("unrecognized argument"),
        "got: {}",
        err.reason
    );
    let err =
        check_request(&tools_call(2, "read_file", r#"{"format":"json"}"#), &policy).unwrap_err();
    assert!(
        err.reason.contains("missing a path target"),
        "got: {}",
        err.reason
    );
    // An extracted target still hits the empty allow-list.
    let err = check_request(
        &tools_call(3, "fetch_url", r#"{"url":"https://api.example.com"}"#),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("not in tool network allowed hosts"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_global_deny_all_others_denies_every_extracted_host() {
    // F7: the default posture is `deny_all_others` with empty allow
    // lists — a recognized host/URL argument must be refused, not
    // forwarded because the allow list happens to be empty.
    let mut policy = Policy {
        tools: vec![ToolPolicy::named("fetch", true)],
        ..Default::default()
    };

    let err = check_request(
        &tools_call(1, "fetch", r#"{"url":"https://api.example.com"}"#),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("not in global outbound allow list"),
        "got: {}",
        err.reason
    );
    // A bare host or socket argument is denied the same way.
    let err = check_request(
        &tools_call(2, "fetch", r#"{"peer":"10.9.9.9:443"}"#),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("not in global outbound allow list"),
        "got: {}",
        err.reason
    );
    // FS-only calls carry no destination — they are not required to.
    let ok = tools_call(3, "fetch", r#"{"format":"json"}"#);
    assert!(check_request(&ok, &policy).is_ok());
    // A matching allow rule reopens exactly that destination.
    policy.network.outbound.allowed = vec!["api.example.com".to_string()];
    let ok = tools_call(4, "fetch", r#"{"url":"https://api.example.com"}"#);
    assert!(check_request(&ok, &policy).is_ok());
    let err = check_request(
        &tools_call(5, "fetch", r#"{"url":"https://other.example.com"}"#),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("not in global outbound allow list"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_read_only_sees_aliased_and_bare_network_args() {
    let mut check = ToolPolicy::named("check", true);
    check.side_effect = Some("read_only".into());
    let policy = Policy {
        tools: vec![check],
        ..Default::default()
    };
    for args in [
        r#"{"proxy":"api.example.com"}"#,
        r#"{"peer":"10.0.0.1:9"}"#,
        r#"{"mystery":"10.0.0.1"}"#,
        r#"{"mystery":"sneaky.example"}"#,
    ] {
        let err = check_request(&tools_call(1, "check", args), &policy).unwrap_err();
        assert!(
            err.reason.contains("read_only") || err.reason.contains("unrecognized argument"),
            "read_only must refuse {args}, got: {}",
            err.reason
        );
    }
}

#[test]
fn test_extract_deputy_use_targets_denies_undeclared_selector() {
    use crate::policy::deputy::{DeputyRule, ExtractPointer};

    // A pointer rule names the fields the contract covers; a plausible
    // selector under an undeclared key is an extraction failure.
    let line = r#"{"params":{"arguments":{"path":"/workspace/a.txt","mystery":"sneaky.example"}}}"#;
    let p = ExtractPointer::parse("/params/arguments/path", "params").unwrap();
    let err = extract_deputy_use_targets(line, &[DeputyRule::Pointer(p)]).unwrap_err();
    assert!(err.contains("unrecognized argument"), "got: {err}");

    // Payload-vocabulary values and bare words are not selectors and the
    // declared pointer still resolves.
    let line = r#"{"params":{"arguments":{"path":"/workspace/a.txt","note":"see sneaky.example","mystery":"word"}}}"#;
    let p = ExtractPointer::parse("/params/arguments/path", "params").unwrap();
    let out = extract_deputy_use_targets(line, &[DeputyRule::Pointer(p)]).unwrap();
    assert_eq!(out, vec!["/workspace/a.txt".to_string()]);
}

#[test]
fn test_qualified_egress_rules_gate_port_and_proto() {
    // F41: / qualifiers in a tool network block are part
    // of the contract — an allow for :443 does not authorize :444, and
    // a target whose qualifiers cannot be determined fails closed.
    use crate::policy::{EgressDest, EgressProto, EgressRule};
    let mut policy = Policy::default();
    policy.network.outbound.deny_all_others = false;
    let mut fetch = ToolPolicy::named("fetch", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec!["api.example.com".into()],
        allowed_cidrs: Vec::new(),
        denied_hosts: Vec::new(),
        denied_cidrs: Vec::new(),
        egress_rules: vec![EgressRule {
            allow: true,
            dest: EgressDest::Host("api.example.com".into()),
            proto: EgressProto::Tcp,
            port: Some(443),
        }],
        allow_specified: true,
    });
    policy.tools = vec![fetch];

    // The https:// scheme default port satisfies the :443 qualifier.
    let ok = tools_call(1, "fetch", r#"{"url":"https://api.example.com/x"}"#);
    assert!(
        check_request(&ok, &policy).is_ok(),
        "https default 443 must satisfy the port=443 rule"
    );
    // An explicit :444 is outside the qualifier.
    let err = check_request(
        &tools_call(2, "fetch", r#"{"url":"https://api.example.com:444/x"}"#),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("egress") || err.reason.contains("port"),
        "got: {}",
        err.reason
    );
    // A bare host name carries no verifiable port — fail closed.
    assert!(
        check_request(
            &tools_call(3, "fetch", r#"{"host":"api.example.com"}"#),
            &policy
        )
        .is_err(),
        "unqualified target under a port-qualified allow must be refused"
    );
    // An explicit :443 on a bare host is verifiable and allowed.
    let ok = tools_call(4, "fetch", r#"{"host":"api.example.com:443"}"#);
    assert!(
        check_request(&ok, &policy).is_ok(),
        "explicit :443 under the qualified allow must pass"
    );

    // proto=udp does not authorize a TCP-shaped target.
    policy.tools[0].network = Some(ToolNetworkPolicy {
        allowed_hosts: vec!["dns.example".into()],
        allowed_cidrs: Vec::new(),
        denied_hosts: Vec::new(),
        denied_cidrs: Vec::new(),
        egress_rules: vec![EgressRule {
            allow: true,
            dest: EgressDest::Host("dns.example".into()),
            proto: EgressProto::Udp,
            port: Some(53),
        }],
        allow_specified: true,
    });
    let err = check_request(
        &tools_call(5, "fetch", r#"{"url":"https://dns.example:53/x"}"#),
        &policy,
    )
    .unwrap_err();
    assert!(
        err.reason.contains("egress") || err.reason.contains("proto"),
        "udp-qualified allow must not cover a tcp target, got: {}",
        err.reason
    );
}

#[test]
fn test_input_responses_auto_denies_under_cidr_or_qualified_contract() {
    // F60: deny-cidr / qualified-egress rules are a network security
    // contract even when no host name is listed — input_responses=auto
    // must resolve to deny, not allow.
    let mut policy = Policy::default();
    policy.network.outbound.deny_all_others = false;
    let mut fetch = ToolPolicy::named("fetch_url", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec![],
        allowed_cidrs: vec![],
        denied_hosts: vec![],
        denied_cidrs: vec!["169.254.0.0/16".into()],
        egress_rules: Vec::new(),
        allow_specified: false,
    });
    policy.tools = vec![fetch];
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://api.example.com"},"inputResponses":{"e":{"action":"accept"}}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(
        err.reason.contains("inputResponses"),
        "cidr-only contract must count as a security contract, got: {}",
        err.reason
    );

    // Same for a qualified-egress-only contract.
    use crate::policy::{EgressDest, EgressProto, EgressRule};
    policy.tools[0].network = Some(ToolNetworkPolicy {
        allowed_hosts: vec![],
        allowed_cidrs: vec![],
        denied_hosts: vec![],
        denied_cidrs: vec![],
        egress_rules: vec![EgressRule {
            allow: true,
            dest: EgressDest::Host("api.example.com".into()),
            proto: EgressProto::Tcp,
            port: Some(443),
        }],
        allow_specified: false,
    });
    let err = check_request(line, &policy).unwrap_err();
    assert!(
        err.reason.contains("inputResponses"),
        "qualified-egress contract must count as a security contract, got: {}",
        err.reason
    );
}
