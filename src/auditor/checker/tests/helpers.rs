use super::*;

// --- Helper function tests ---

#[test]
fn test_path_matches_exact() {
    assert!(path_matches(&ws(), &ws()));
}

#[test]
fn test_path_matches_prefix() {
    assert!(path_matches(&ws_at("src/main.rs"), &ws()));
}

#[test]
fn test_path_matches_no_partial() {
    // "{ws}2" should NOT match "{ws}"
    assert!(!path_matches(&format!("{}2", ws()), &ws()));
}

#[test]
fn test_path_matches_no_match() {
    assert!(!path_matches(&format!("{}-other/file", ws()), &ws()));
}

#[test]
fn test_path_matches_glob_recursive() {
    assert!(path_matches(&ws_at("test.txt"), &ws_at("**")));
    assert!(path_matches(&ws_at("src/main.rs"), &ws_at("**")));
    assert!(path_matches(&ws(), &ws_at("**")));
    assert!(!path_matches(&format!("{}-other/file", ws()), &ws_at("**")));
    assert!(!path_matches(&format!("{}2/file", ws()), &ws_at("**")));
}

#[test]
fn test_path_matches_single_wildcard() {
    assert!(path_matches(
        &ws_at("home/user/.ssh/id_rsa"),
        &ws_at("home/*/.ssh/**")
    ));
    assert!(path_matches(
        &ws_at("home/root/.ssh/known_hosts"),
        &ws_at("home/*/.ssh/**")
    ));
    assert!(!path_matches(
        &ws_at("home/.ssh/id_rsa"),
        &ws_at("home/*/.ssh/**")
    ));
}

#[test]
fn test_path_matches_traversal_blocked() {
    // Path traversal: {ws}/../../etc/passwd escapes the workspace and
    // must NOT match it
    assert!(!path_matches(&ws_at("../../etc/passwd"), &ws()));
    assert!(!path_matches(&ws_at("../../etc/passwd"), &ws_at("**")));
}

#[test]
fn test_path_matches_traversal_double_dot() {
    // {ws}/../tmp/evil escapes the workspace root
    assert!(!path_matches(&ws_at("../tmp/evil"), &ws()));
    assert!(!path_matches(&ws_at("../tmp/evil"), &ws_at("**")));
}

#[test]
fn test_path_matches_traversal_with_dot() {
    // Current dir "." should be ignored
    assert!(path_matches(&ws_at("./src/main.rs"), &ws()));
    assert!(path_matches(&ws_at("./src/main.rs"), &ws_at("**")));
}

#[test]
fn test_path_matches_traversal_deep() {
    // Deep traversal that escapes allowed directory
    assert!(!path_matches(&ws_at("a/b/../../../../etc/shadow"), &ws()));
}

#[test]
fn test_normalize_path_basic() {
    assert_eq!(normalize_path("/workspace/../../etc/passwd"), "/etc/passwd");
    assert_eq!(normalize_path("/workspace/../tmp"), "/tmp");
    assert_eq!(normalize_path("/workspace/./src"), "/workspace/src");
    assert_eq!(normalize_path("/a/b/c/../../d"), "/a/d");
    assert_eq!(normalize_path("/.."), "/");
}

#[test]
fn test_host_matches_exact() {
    assert!(host_matches("example.com", "example.com"));
}

#[test]
fn test_host_matches_wildcard() {
    assert!(host_matches("sub.example.com", "*.example.com"));
}

#[test]
fn test_host_matches_wildcard_no_bare() {
    // "example.com" should NOT match "*.example.com"
    assert!(!host_matches("example.com", "*.example.com"));
}

#[test]
fn test_host_matches_no_match() {
    assert!(!host_matches("other.com", "example.com"));
}

#[test]
fn test_host_matches_wildcard_subdomain_boundary() {
    // CRITICAL: "evilexample.com" must NOT match "*.example.com"
    assert!(!host_matches("evilexample.com", "*.example.com"));
    // But legitimate subdomains should still match
    assert!(host_matches("api.example.com", "*.example.com"));
    assert!(host_matches("deep.sub.example.com", "*.example.com"));
}

#[test]
fn test_fs_denied_takes_priority_over_allowed() {
    // Path matches both allowed and denied - denied should win
    let policy = Policy {
        tools: vec![ToolPolicy {
            name: "read_file".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: Some(FsToolPolicy::new(vec![ws()], vec![ws_at("secret")])),
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
            deputy: None,
        }],
        ..Default::default()
    };
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at("secret/key.pem")
    );
    let err = check_request(&line, &policy).unwrap_err();
    assert!(err.reason.contains("denied"), "got: {}", err.reason);
}

#[test]
fn test_network_wildcard_denied_host() {
    let mut policy = Policy {
        tools: vec![ToolPolicy {
            name: "fetch_url".to_string(),
            allowed: true,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: Some(ToolNetworkPolicy {
                allowed_hosts: Vec::new(),
                allowed_cidrs: Vec::new(),
                denied_hosts: vec!["*.evil.com".to_string()],
                denied_cidrs: Vec::new(),
                egress_rules: Vec::new(),
                allow_specified: false,
            }),
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
            deputy: None,
        }],
        ..Default::default()
    };
    policy.network.outbound.deny_all_others = false;
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://api.evil.com/steal"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(err.reason.contains("denied"), "got: {}", err.reason);
}
