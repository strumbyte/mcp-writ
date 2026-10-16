use super::*;

// --- Tool sub-policy tests ---

use crate::policy::FsToolPolicy;

#[test]
fn test_fs_sub_policy_allowed_path_passes() {
    let policy = sub_policy_policy();
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at("src/main.rs")
    );
    let result = check_request(&line, &policy).unwrap();
    assert_eq!(result.sub_policy, Some("tool:read_file".to_string()));
}

#[test]
fn test_fs_sub_policy_denied_path_rejected() {
    let policy = sub_policy_policy();
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at("secrets/key.pem")
    );
    let err = check_request(&line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    assert!(
        err.reason.contains("denied by tool fs sub-policy"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_fs_sub_policy_noncanonical_spelling_rejected() {
    // Authorization runs on the normalized path while the wire forwards
    // the raw spelling; NFKC-equivalent names are distinct directory
    // entries on a byte-preserving filesystem, so the spellings must
    // match exactly when an fs check applies.
    let policy = sub_policy_policy();
    // `file:`-URI spellings differ per platform: a host-less URI needs
    // `file:///tmp/…` on unix but `file:///C:/…` on Windows.
    let file_uri_root = if cfg!(windows) {
        format!("/{}", ws())
    } else {
        ws()
    };
    for spelling in [
        // Full-width ASCII — NFKC folds onto the allowed prefix.
        ws_at("\u{ff41}.txt"),
        format!("{}\u{ff0f}a.txt", ws()),
        // Percent-encoded byte — decodes onto the allowed prefix.
        ws_at("%61.txt"),
        // `file:` URI — maps onto the allowed path but forwards a URI.
        format!("file://localhost{file_uri_root}/a.txt"),
        // Double percent-encoding — one decode leaves `%61` behind, so
        // the checked path still differs from the wire spelling.
        ws_at("%2561.txt"),
    ] {
        let escaped = spelling.replace('\\', "\\\\").replace('"', "\\\"");
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{escaped}"}}}}}}"#
        );
        let err = match check_request(&line, &policy) {
            Err(e) => e,
            Ok(_) => panic!("spelling {spelling:?} unexpectedly passed"),
        };
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("canonical form"),
            "spelling {spelling:?} must be refused as non-canonical, got: {}",
            err.reason
        );
    }
}

#[test]
fn test_noncanonical_spelling_passes_when_no_fs_check_runs() {
    // Without a per-tool fs policy or the secret overlay, no path
    // authorization is spent on the argument — the canonical-spelling
    // rule does not apply. (The overlay is on by default, so the
    // boundary is only reachable when an operator opts out.)
    let mut policy = sub_policy_policy();
    policy.fs.secret_overlay = false;
    let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_files","arguments":{"dir":"file:///workspace/a.txt"}}}"#;
    check_request(line, &policy).unwrap();
}

#[test]
fn test_noncanonical_spelling_overlay_only_still_passes_clean_targets() {
    // The overlay is a deny-list evaluated on the normalized form —
    // spelling tricks cannot slip a disguised secret past it — so the
    // canonical-spelling requirement stays scoped to per-tool allow
    // decisions (and deputy use calls).
    let policy = overlay_on_no_fs_policy();
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/%61.txt"}}}"#;
    check_request(line, &policy).unwrap();
}

#[test]
fn test_fs_sub_policy_unallowed_path_rejected() {
    let policy = sub_policy_policy();
    // A sibling root: resolves under the same restricted ancestor but
    // is outside the allowed workspace.
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}-sibling/other.txt"}}}}}}"#,
        ws()
    );
    let err = check_request(&line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    assert!(
        err.reason.contains("not in tool fs allowed paths"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_fs_sub_policy_bare_name_on_path_key_rejected() {
    // `repo_path` is a `*_path` key: a bare name resolves against the
    // server's working directory like any other relative path — it is
    // not exempt from the tool's allow scope. The allow scope here is a
    // sibling of the cwd-resolved path, so the request cannot become
    // allowed no matter where the test process runs.
    let mut policy = sub_policy_policy();
    let allowed = std::env::current_dir()
        .unwrap()
        .join("__allowed_scope__")
        .to_string_lossy()
        .into_owned();
    policy
        .tools
        .iter_mut()
        .find(|t| t.name == "read_file")
        .unwrap()
        .fs = Some(FsToolPolicy::new(vec![allowed], vec![]));
    let line = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"repo_path":"myrepo"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    // On a shared-writable cwd (mounted repos, group checkouts) the
    // path can also refuse earlier — a replaceable-ancestor rejection
    // is still a refusal.
    assert!(
        err.reason.contains("not in tool fs allowed paths")
            || err.reason.contains("could not be resolved"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_fs_sub_policy_no_path_arg_denied() {
    let policy = sub_policy_policy();
    let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"content":"hello"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(
        err.reason.contains("missing a path target"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_fs_sub_policy_nested_and_alternate_fields() {
    let policy = sub_policy_policy();
    let nested = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"read_file","arguments":{{"file":{{"path":"{}-sibling/etc/passwd"}}}}}}}}"#,
        ws()
    );
    let err = check_request(&nested, &policy).unwrap_err();
    assert!(
        err.reason.contains("not in tool fs allowed paths"),
        "got: {}",
        err.reason
    );

    let allowed = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"read_file","arguments":{{"file":"{}"}}}}}}"#,
        ws_at("ok.txt")
    );
    assert!(check_request(&allowed, &policy).is_ok());
}

#[test]
fn test_file_uri_single_slash_is_stripped() {
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"file:/tmp/a"}}}"#;
    assert_eq!(extract_fs_targets(line), vec!["/tmp/a".to_string()]);

    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"FILE:///workspace/ok.txt"}}}"#;
    assert_eq!(
        extract_fs_targets(line),
        vec!["/workspace/ok.txt".to_string()]
    );
}

#[test]
fn test_network_sub_policy_allowed_host_passes() {
    let policy = sub_policy_policy();
    let line = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://api.example.com/data"}}}"#;
    let result = check_request(line, &policy).unwrap();
    assert_eq!(result.sub_policy, Some("tool:fetch_url".to_string()));
}

#[test]
fn test_network_sub_policy_denied_host_rejected() {
    let policy = sub_policy_policy();
    let line = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.com/steal"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "fetch_url");
    assert!(
        err.reason.contains("denied by tool network sub-policy"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_network_sub_policy_unallowed_host_rejected() {
    let policy = sub_policy_policy();
    let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://random.io/api"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "fetch_url");
    assert!(
        err.reason.contains("not in tool network allowed hosts"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_network_sub_policy_host_argument_fallback() {
    let policy = sub_policy_policy();
    // Uses "host" argument instead of URL
    let line = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"fetch_url","arguments":{"host":"api.example.com"}}}"#;
    assert!(check_request(line, &policy).is_ok());
}

#[test]
fn test_no_sub_policy_returns_none() {
    let policy = sub_policy_policy();
    let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_files","arguments":{}}}"#;
    let result = check_request(line, &policy).unwrap();
    assert_eq!(result.sub_policy, None);
}

#[test]
fn test_sub_policy_metadata_only_returns_sub_policy_tag() {
    // Tool with syscalls sub-policy (no request-level checks, but has_sub = true)
    let policy = sub_policy_policy();
    let line = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"exec_cmd","arguments":{"command":"ls"}}}"#;
    let result = check_request(line, &policy).unwrap();
    assert_eq!(result.sub_policy, Some("tool:exec_cmd".to_string()));
}

#[test]
fn test_non_tools_call_returns_no_sub_policy() {
    let policy = sub_policy_policy();
    let line = r#"{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}"#;
    let result = check_request(line, &policy).unwrap();
    assert_eq!(result.sub_policy, None);
}
