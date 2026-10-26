use super::*;

#[test]
fn test_r02_empty_allow_after_deny_blocks_other_resources() {
    let mut policy = Policy::default();
    let mut read = ToolPolicy::named("read_file", true);
    read.fs = Some(FsToolPolicy {
        allowed_paths: vec![],
        read_only_paths: vec![],
        read_write_paths: vec![],
        denied_paths: vec![ws_at("allowed/**")],
        allow_specified: true, // Specified but emptied by deny
        require_path: None,
    });
    policy.tools = vec![read];

    let req = format!(
        r#"{{"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at("other/file")
    );
    let err = check_request(&req, &policy).unwrap_err();
    assert!(
        err.reason.contains("not in tool fs allowed paths"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_r05_url_backslash_host_spoofing() {
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

    // evil.test\@api.example.com - backslash must not fool host parsing into api.example.com
    let req = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://evil.test\\@api.example.com/"}}}"#;
    assert!(check_request(req, &policy).is_err());
}

#[test]
fn test_r20_host_matches_with_url_and_port() {
    assert!(host_matches("api.example.com", "https://api.example.com"));
    assert!(host_matches("api.example.com", "api.example.com:443"));
    assert!(host_matches("::1", "[::1]"));
    assert!(host_matches("::1", "::1"));
    assert!(host_matches("::1", "https://[::1]/"));
    assert!(!host_matches("1", "::1"));
    assert!(host_matches("sub.example.com", "*.example.com"));
    assert!(!host_matches("evil.test", "https://api.example.com"));
}

#[test]
fn test_s08_url_percent_encoding_and_control_characters() {
    let mut policy = Policy::default();
    policy.network.outbound.deny_all_others = false;
    let mut fetch = ToolPolicy::named("fetch", true);
    fetch.network = Some(ToolNetworkPolicy {
        allowed_hosts: vec![],
        allowed_cidrs: Vec::new(),
        denied_hosts: vec!["blocked.example".into()],
        denied_cidrs: Vec::new(),
        egress_rules: Vec::new(),
        allow_specified: false,
    });
    policy.tools = vec![fetch];

    for (url_raw, url_json) in [
        ("https://blocked.example/", "https://blocked.example/"),
        ("https://%62locked.example/", "https://%62locked.example/"),
        ("https://blo\tcked.example/", "https://blo\\tcked.example/"),
        ("https://blo\rcked.example/", "https://blo\\rcked.example/"),
        ("https://blo\ncked.example/", "https://blo\\ncked.example/"),
    ] {
        let req = format!(
            r#"{{"method":"tools/call","params":{{"name":"fetch","arguments":{{"url":"{url_json}"}}}}}}"#
        );
        let err = check_request(&req, &policy).unwrap_err();
        assert!(
            err.reason.contains("denied by tool network sub-policy"),
            "URL '{url_raw}' should be denied by tool network policy, got error: {}",
            err.reason
        );
    }
}

#[test]
fn test_read_only_side_effect_rejects_url_in_path_key() {
    let mut policy = Policy::default();
    let mut tool = ToolPolicy::named("read_file", true);
    tool.side_effect = Some("read_only".to_string());
    tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
    policy.tools = vec![tool];

    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"https://evil.example/x"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(
        err.reason.contains("read_only") && err.reason.contains("host/URL"),
        "URL-shaped path key must trigger side_effect reject, got: {}",
        err.reason
    );
}

#[test]
fn test_read_only_side_effect_rejects_url_argument() {
    let mut policy = Policy::default();
    let mut tool = ToolPolicy::named("read_file", true);
    tool.side_effect = Some("read_only".to_string());
    tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
    policy.tools = vec![tool];

    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"url":"https://evil.example/x"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(
        err.reason.contains("read_only") && err.reason.contains("host/URL"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_secret_overlay_rejects_uncreated_ssh_under_allow() {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = true;
    let mut tool = ToolPolicy::named("read_file", true);
    tool.fs = Some(FsToolPolicy::new(vec![ws_at("**")], vec![]));
    policy.tools = vec![tool];

    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at(".ssh/id_rsa")
    );
    let err = check_request(&line, &policy).unwrap_err();
    assert!(
        err.reason.contains("secret-path overlay"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_secret_overlay_rejects_percent_encoded_ssh() {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = true;
    let mut tool = ToolPolicy::named("read_file", true);
    tool.fs = Some(FsToolPolicy::new(vec![ws_at("**")], vec![]));
    policy.tools = vec![tool];

    for path in [
        ws_at("%2essh/id_rsa"),
        ws_at(".%73sh/id_rsa"),
        ws_at("%252essh/id_rsa"),
    ] {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{path}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "percent-encoded secret must be denied, path={path} got: {}",
            err.reason
        );
    }
}

#[test]
fn test_secret_overlay_rejects_file_uri_localhost_passwd() {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = true;
    let mut tool = ToolPolicy::named("read_file", true);
    // Allow the reserved file so glob would pass; overlay must still
    // deny. A bare `/etc/passwd` cannot be used on Windows — it
    // qualifies to the process drive and a broad-writable root fails
    // resolution — so it is anchored on the temp tree's root.
    let reserved_file = crate::pathutil::temp_root_abs("/etc/passwd");
    tool.fs = Some(FsToolPolicy::new(
        vec![ws_at("**"), reserved_file.clone()],
        vec![],
    ));
    policy.tools = vec![tool];

    // `file://localhost` URIs keep a `/C:/…` drive spelling on Windows.
    let spelled = if cfg!(windows) {
        format!("/{reserved_file}")
    } else {
        reserved_file
    };
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"file://localhost{spelled}"}}}}}}"#
    );
    let err = check_request(&line, &policy).unwrap_err();
    assert!(
        err.reason.contains("secret-path overlay"),
        "file://localhost{spelled} must hit overlay, got: {}",
        err.reason
    );
}

#[test]
fn test_file_uri_localhost_extracts_as_fs_path() {
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"file://localhost/etc/passwd"}}}"#;
    assert_eq!(extract_fs_targets(line), vec!["/etc/passwd".to_string()]);
}

#[test]
fn test_secret_overlay_rejects_percent_encoded_file_scheme_without_fs() {
    let policy = overlay_on_no_fs_policy();
    for uri in [
        "%66ile://localhost/etc/passwd",
        "%66ile://127.0.0.1/etc/passwd",
        "%66ile://localhost/workspace/.ssh/id_rsa",
    ] {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "encoded file: URI must hit overlay (no fs sub-policy), uri={uri} got: {}",
            err.reason
        );
    }
    assert_eq!(
        extract_fs_targets(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"%66ile://localhost/etc/passwd"}}}"#
        ),
        vec!["/etc/passwd".to_string()]
    );
}

#[test]
fn test_secret_overlay_rejects_whatwg_c0_split_file_scheme_without_fs() {
    let policy = overlay_on_no_fs_policy();
    // JSON `\t`/`\n`/`\r` become TAB/LF/CR in the parsed URI.
    let json_escaped = [
        r#"file\t://localhost/etc/passwd"#,
        r#"file\n://localhost/etc/passwd"#,
        r#"file\r://localhost/etc/passwd"#,
    ];
    let literal_or_percent = [
        "file%0A://localhost/etc/passwd",
        "file%09://localhost/etc/passwd",
        "file%0D://localhost/etc/passwd",
        "%66ile%0A://localhost/etc/passwd",
        "file%0B://localhost/etc/passwd",
        "file%0C://localhost/etc/passwd",
        "file%250B://localhost/etc/passwd",
        "file%C2%85://localhost/etc/passwd",
    ];
    for uri in json_escaped.into_iter().chain(literal_or_percent) {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "C0-split file: URI must hit overlay (no fs sub-policy), uri={uri} got: {}",
            err.reason
        );
    }
    assert_eq!(
        extract_fs_targets(
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"file\t://localhost/etc/passwd"}}}"#
        ),
        vec!["/etc/passwd".to_string()]
    );
}

#[test]
fn test_secret_overlay_rejects_vtab_ff_nel_line_sep_file_scheme_without_fs() {
    let policy = overlay_on_no_fs_policy();
    let uris = [
        "file%0B://localhost/etc/passwd",
        "file%0C://localhost/etc/passwd",
        "file%250B://localhost/etc/passwd",
        "file%C2%85://localhost/etc/passwd",
        "file\u{2028}://localhost/etc/passwd",
        "file\u{2029}://localhost/etc/passwd",
    ];
    for uri in uris {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "extended control/separator file: URI must hit overlay, uri={uri:?} got: {}",
            err.reason
        );
    }
}

#[test]
fn test_secret_overlay_rejects_whitespace_and_nfkc_file_scheme_without_fs() {
    let policy = overlay_on_no_fs_policy();
    let uris = [
        "file\u{00A0}://localhost/etc/passwd",
        "file%C2%A0://localhost/etc/passwd",
        "file%E2%80%82://localhost/etc/passwd",
        "file ://localhost/etc/passwd",
        "file%20://localhost/etc/passwd",
        "\u{FB01}le://localhost/etc/passwd",
        "%EF%BD%86ile://localhost/etc/passwd",
    ];
    for uri in uris {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "whitespace/NFKC file: URI must hit overlay, uri={uri:?} got: {}",
            err.reason
        );
    }
}

#[test]
fn test_secret_overlay_rejects_file_uri_backslash_passwd_without_fs() {
    let policy = overlay_on_no_fs_policy();
    // JSON-escaped `\\` so the parsed URI contains a real backslash.
    let json_uris = [
        r"file://localhost\\etc\\passwd",
        r"file://\\etc\\passwd",
        r"%66ile://localhost\\etc\\passwd",
        r"file://localhost%5Cetc%5Cpasswd",
    ];
    for uri in json_uris {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "backslash file: URI must hit overlay, uri={uri:?} got: {}",
            err.reason
        );
    }
}

#[test]
fn test_secret_overlay_rejects_opaque_file_uri_passwd_without_fs() {
    let policy = overlay_on_no_fs_policy();
    // JSON-escaped `\\` so `file:etc\passwd` is the parsed URI.
    let json_uris = [
        "file:etc/passwd",
        r"file:etc\\passwd",
        "file:./etc/passwd",
        "file:../etc/passwd",
    ];
    for uri in json_uris {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "opaque file: URI must hit overlay (no fs sub-policy), uri={uri:?} got: {}",
            err.reason
        );
    }
    for (json_uri, label) in [
        ("file:etc/passwd", "slash"),
        (r"file:etc\\passwd", "backslash"),
        ("file:./etc/passwd", "dot"),
        ("file:../etc/passwd", "dotdot"),
    ] {
        let extracted = extract_fs_targets(&format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{json_uri}"}}}}}}"#
        ));
        assert_eq!(
            extracted,
            vec!["/etc/passwd".to_string()],
            "opaque file: ({label}) must extract as /etc/passwd, got {extracted:?}"
        );
    }
}

#[test]
fn test_secret_overlay_rejects_non_ascii_scheme_slot_without_fs() {
    let policy = overlay_on_no_fs_policy();
    let uris = [
        "f\u{0456}le://localhost/etc/passwd",
        "f%D1%96le://localhost/etc/passwd",
        "f\u{03B9}le://localhost/etc/passwd",
        "fil\u{0435}://localhost/etc/passwd",
        "file\u{FE00}://localhost/etc/passwd",
        "file\u{FE0F}://localhost/etc/passwd",
    ];
    for uri in uris {
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-overlay") || err.reason.contains("secret-path overlay"),
            "non-ASCII scheme slot must hit overlay, uri={uri:?} got: {}",
            err.reason
        );
    }
}

#[test]
fn test_file_scheme_zwsp_does_not_panic_and_is_denied() {
    let policy = overlay_on_no_fs_policy();
    let uri = "file\u{200b}://localhost/etc/passwd";
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
    );
    let result = std::panic::catch_unwind(|| check_request(&line, &policy));
    let err = result
        .expect("ZWSP in file scheme must not panic")
        .expect_err("ZWSP file URI must be denied or fail closed");
    assert!(
        err.reason.contains("secret-path overlay")
            || err.reason.contains("invisible Unicode")
            || err.reason.contains("read_only"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_secret_overlay_allows_ordinary_new_file() {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = true;
    let mut tool = ToolPolicy::named("read_file", true);
    tool.fs = Some(FsToolPolicy::new(vec![ws_at("**")], vec![]));
    policy.tools = vec![tool];

    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at("notes.txt")
    );
    assert!(check_request(&line, &policy).is_ok());
}

#[test]
fn test_secret_overlay_false_falls_back_to_glob() {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = false;
    let mut tool = ToolPolicy::named("read_file", true);
    tool.fs = Some(FsToolPolicy::new(vec![ws_at("**")], vec![]));
    policy.tools = vec![tool];

    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at(".ssh/id_rsa")
    );
    assert!(
        check_request(&line, &policy).is_ok(),
        "overlay off must honor the allow glob"
    );
}

#[test]
fn test_secret_overlay_follows_symlink() {
    // Same write-restricted-root requirement as the overlay's own
    // symlink test — an unauthorizable fixture dir means the resolved
    // target can never be reached to match the reserved set.
    let Some(dir) = crate::testutil::restricted_tempdir().unwrap() else {
        eprintln!("secret overlay symlink test skipped: no write-restricted root");
        return;
    };
    match crate::secret_paths::try_create_secret_symlink(dir.path()) {
        Ok(link) => {
            let mut policy = Policy::default();
            policy.fs.secret_overlay = true;
            let mut tool = ToolPolicy::named("read_file", true);
            let directory =
                crate::pathutil::resolve_for_authorization(&dir.path().to_string_lossy()).unwrap();
            // Allow both the link location and the follow target so glob
            // authorization would pass; overlay must still deny. The
            // unix link target is `/etc/passwd` — a spelling that only
            // resolves there (on Windows the fixture links into `dir`).
            let mut allowed = vec![format!("{directory}/**")];
            if cfg!(unix) {
                allowed.push("/etc/passwd".to_string());
            }
            tool.fs = Some(FsToolPolicy::new(allowed, vec![]));
            policy.tools = vec![tool];
            let path = link.to_string_lossy().replace('\\', "\\\\");
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{path}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "got: {}",
                err.reason
            );
        }
        Err(e) => {
            eprintln!("secret overlay symlink test skipped: {e}");
        }
    }
}

#[cfg(unix)]
#[test]
fn test_denied_policy_alias_matches_resolved_request() {
    use super::super::sub_policy::authorize_one_path;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir_all(real.join("blocked")).unwrap();
    let alias = dir.path().join("alias");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let tool = ToolPolicy::named("read_file", true);
    let fs = FsToolPolicy::new(
        vec![format!("{}/**", alias.display())],
        vec![format!("{}/blocked/**", alias.display())],
    );
    let err =
        authorize_one_path(&tool, &fs, &real.join("blocked/key").to_string_lossy()).unwrap_err();
    assert!(
        err.reason.contains("denied by tool fs sub-policy"),
        "{err:?}"
    );
    assert!(authorize_one_path(&tool, &fs, &real.join("notes").to_string_lossy()).is_ok());
}

#[test]
fn test_https_url_ending_with_etc_passwd_is_not_secret_overlay() {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = true;
    policy.network.outbound.deny_all_others = false;
    let mut tool = ToolPolicy::named("fetch_url", true);
    tool.side_effect = Some("network".into());
    policy.tools = vec![tool];
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://example.com/etc/passwd"}}}"#;
    match check_request(line, &policy) {
        Ok(_) => {}
        Err(err) => {
            assert!(
                !err.reason.contains("secret-path overlay"),
                "https URL must not be denied by secret overlay, got: {}",
                err.reason
            );
        }
    }
}

#[test]
fn test_nested_etc_passwd_path_is_not_secret_overlay() {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = true;
    let mut tool = ToolPolicy::named("read_file", true);
    tool.fs = Some(FsToolPolicy::new(vec![ws_at("**")], vec![]));
    policy.tools = vec![tool];
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{}"}}}}}}"#,
        ws_at("mirror/etc/passwd")
    );
    assert!(
        check_request(&line, &policy).is_ok(),
        "nested .../etc/passwd must not match reserved /etc/passwd"
    );
}

#[test]
fn test_nul_path_still_rejected() {
    let mut policy = Policy::default();
    let mut tool = ToolPolicy::named("read_file", true);
    tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
    policy.tools = vec![tool];
    let line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/workspace/a\\u0000b\"}}}";
    let err = check_request(line, &policy).unwrap_err();
    assert!(
        err.reason.contains("NUL") || err.reason.contains("could not be resolved"),
        "got: {}",
        err.reason
    );
}
