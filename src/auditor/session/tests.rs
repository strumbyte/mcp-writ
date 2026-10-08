use super::*;
use crate::policy::deputy::KnownShape;

/// Extract all JSON string values from raw JSON text.
///
/// Handles JSON escape sequences (`\"`, `\\`, `\n`, `\t`, `\r`, `\/`, `\b`, `\f`).
/// Iterates over Unicode scalar values (chars) to correctly handle multi-byte
/// UTF-8 sequences in string contents.
fn extract_all_json_strings(json: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut chars = json.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '"' {
            let mut s = String::new();
            loop {
                match chars.next() {
                    None | Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('/') => s.push('/'),
                        Some('b') => s.push('\x08'),
                        Some('f') => s.push('\x0C'),
                        Some('u') => {
                            // Parse \uXXXX Unicode escape (BMP only, no surrogate pairs)
                            let hex: String = chars.by_ref().take(4).collect();
                            if hex.len() == 4 {
                                match u32::from_str_radix(&hex, 16) {
                                    Ok(code_point) => {
                                        if let Some(ch) = char::from_u32(code_point) {
                                            s.push(ch);
                                        } else {
                                            tracing::debug!(
                                                "invalid unicode code point: \\u{:04X}",
                                                code_point
                                            );
                                        }
                                    }
                                    Err(_) => {
                                        tracing::debug!("invalid unicode escape: \\u{}", hex);
                                    }
                                }
                            }
                        }
                        Some(other) => {
                            s.push('\\');
                            s.push(other);
                        }
                        None => break,
                    },
                    Some(ch) => s.push(ch),
                }
            }
            strings.push(s);
        }
    }

    strings
}

// --- SessionState ---

#[test]
fn test_new_session_has_no_known_paths() {
    let state = SessionState::new();
    assert_eq!(state.known_path_count(), 0);
}

#[test]
fn test_record_and_check_access() {
    let mut state = SessionState::new();
    state.record_paths(&[
        "/workspace/file1.txt".to_string(),
        "/workspace/file2.txt".to_string(),
    ]);
    assert!(state.check_access("/workspace/file1.txt").is_ok());
    assert!(state.check_access("/workspace/file2.txt").is_ok());
}

#[test]
fn test_unknown_path_blocked() {
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/file1.txt".to_string()]);
    let err = state.check_access("/etc/passwd").unwrap_err();
    assert!(err.contains("not discovered"));
    assert!(err.contains("/etc/passwd"));
}

#[test]
fn test_empty_known_paths_blocks_all() {
    let state = SessionState::new();
    let err = state.check_access("/workspace/file.txt").unwrap_err();
    assert!(err.contains("not discovered"));
}

#[test]
fn test_path_traversal_forward_slash() {
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/../../etc/passwd".to_string()]);
    let err = state
        .check_access("/workspace/../../etc/passwd")
        .unwrap_err();
    assert!(err.contains("path traversal"));
}

#[test]
fn test_path_traversal_backslash() {
    let state = SessionState::new();
    let err = state
        .check_access("C:\\workspace\\..\\..\\etc\\passwd")
        .unwrap_err();
    assert!(err.contains("path traversal"));
}

#[test]
fn test_path_traversal_detected_even_when_known() {
    let mut state = SessionState::new();
    // Even if ../path is somehow in known_paths, traversal is blocked
    state.known_paths.insert("/workspace/../secret".to_string());
    let err = state.check_access("/workspace/../secret").unwrap_err();
    assert!(err.contains("path traversal"));
}

#[test]
fn test_record_paths_trims_whitespace() {
    let mut state = SessionState::new();
    state.record_paths(&["  /workspace/file.txt  ".to_string()]);
    assert!(state.check_access("/workspace/file.txt").is_ok());
}

#[test]
fn test_record_paths_ignores_empty() {
    let mut state = SessionState::new();
    state.record_paths(&[String::new(), "  ".to_string()]);
    assert_eq!(state.known_path_count(), 0);
}

#[test]
fn test_duplicate_paths_deduplicated() {
    let mut state = SessionState::new();
    state.record_paths(&[
        "/workspace/a.txt".to_string(),
        "/workspace/a.txt".to_string(),
    ]);
    assert_eq!(state.known_path_count(), 1);
}

#[test]
fn test_record_paths_normalizes_like_use_side() {
    // Discovery payloads may name targets as `file:` URIs or
    // percent-encoded strings; both sides run the same normalization,
    // so these seed the canonical path the use call will produce.
    let mut state = SessionState::new();
    state.record_paths(&[
        "file:///workspace/uri-listed.txt".to_string(),
        "/workspace/%65ncoded.txt".to_string(),
    ]);
    assert!(state.check_access("/workspace/uri-listed.txt").is_ok());
    assert!(state.check_access("/workspace/encoded.txt").is_ok());
}

#[test]
fn test_record_paths_normalized_traversal_still_denies() {
    // A seeded value that normalizes to `..` can never grant a
    // traversal — the use side rejects `..` before membership.
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/%2e%2e/secret".to_string()]);
    let err = state.check_access("/workspace/../secret").unwrap_err();
    assert!(err.contains("path traversal"));
    let err = state.check_access("/workspace/%2e%2e/secret").unwrap_err();
    assert!(err.contains("URL-encoded path traversal"));
}

// --- pending list requests ---

/// The rules the compat-mapped discovery tools carry.
const DISCOVER_RULES: &[DeputyRule] = &[DeputyRule::Shape(KnownShape::McpListResult)];

#[test]
fn test_pending_list_record_and_take() {
    let mut state = SessionState::new();
    state
        .record_pending_list(RpcId::Number("1".into()), "list_files", DISCOVER_RULES)
        .unwrap();
    assert!(
        state
            .take_pending_list(&RpcId::Number("1".into()))
            .is_some()
    );
    assert!(
        state
            .take_pending_list(&RpcId::Number("1".into()))
            .is_none()
    ); // already taken
}

#[test]
fn test_rpc_id_number_spellings_canonicalize() {
    let int_id = RpcId::from_line(r#"{"id":1}"#).unwrap();
    let float_id = RpcId::from_line(r#"{"id":1.0}"#).unwrap();
    let exp_id = RpcId::from_line(r#"{"id":1e0}"#).unwrap();
    let neg_zero = RpcId::from_line(r#"{"id":-0}"#).unwrap();
    let zero = RpcId::from_line(r#"{"id":0}"#).unwrap();
    assert_eq!(int_id, float_id);
    assert_eq!(int_id, exp_id);
    assert_eq!(neg_zero, zero);
    assert_ne!(int_id, RpcId::from_line(r#"{"id":2}"#).unwrap());
    // String and number ids never collide.
    assert_ne!(int_id, RpcId::from_line(r#"{"id":"1"}"#).unwrap());
}

#[test]
fn test_pending_correlation_across_number_spellings() {
    let mut state = SessionState::new();
    let req = RpcId::from_line(r#"{"id":7}"#).unwrap();
    let resp = RpcId::from_line(r#"{"id":7.0}"#).unwrap();
    state
        .record_pending_list(req, "list_files", DISCOVER_RULES)
        .unwrap();
    assert!(state.take_pending_list(&resp).is_some());
    assert!(state.take_pending_list(&resp).is_none());
}

#[test]
fn test_rpc_id_number_canonicalization_preserves_precision() {
    // f64 collapses these pairs; decimal canonicalization must not.
    let pairs = [
        (r#"{"id":9007199254740992}"#, r#"{"id":9007199254740993}"#),
        (r#"{"id":1}"#, r#"{"id":1.0000000000000001}"#),
        (
            r#"{"id":18446744073709551616}"#,
            r#"{"id":18446744073709551617}"#,
        ),
        (r#"{"id":0.1}"#, r#"{"id":0.100000000000000000001}"#),
    ];
    for (a, b) in pairs {
        assert_ne!(RpcId::from_line(a), RpcId::from_line(b), "{a} vs {b}");
    }
}

#[test]
fn test_rpc_id_number_out_of_range_exponents() {
    // Beyond f64 range: mathematically equal spellings still correlate.
    let big = RpcId::from_line(r#"{"id":1e400}"#);
    for line in [
        r#"{"id":10e399}"#,
        r#"{"id":0.01e402}"#,
        r#"{"id":100E398}"#,
    ] {
        assert_eq!(RpcId::from_line(line), big, "{line}");
    }
    let tiny = RpcId::from_line(r#"{"id":5e-400}"#);
    for line in [r#"{"id":0.5e-399}"#, r#"{"id":50e-401}"#] {
        assert_eq!(RpcId::from_line(line), tiny, "{line}");
    }
    // Exponent literal beyond i128: raw fallback, no panic, still stable.
    let huge = r#"{"id":1e999999999999999999999999999999999999999}"#;
    assert_eq!(RpcId::from_line(huge), RpcId::from_line(huge));
}

#[test]
fn test_rpc_id_number_exponent_arithmetic_overflow_falls_back() {
    // exp_lit at i128 edges: fraction-digit subtraction and
    // trailing-zero addition must not overflow — falls back to raw.
    let at_min = r#"{"id":0.1e-170141183460469231731687303715884105728}"#;
    let at_max = r#"{"id":10e170141183460469231731687303715884105727}"#;
    assert_eq!(RpcId::from_line(at_min), RpcId::from_line(at_min));
    assert_eq!(RpcId::from_line(at_max), RpcId::from_line(at_max));
    assert_ne!(RpcId::from_line(at_min), RpcId::from_line(at_max));
    // Exactly at the i128 edges the arithmetic still fits and correlates.
    assert_eq!(
        RpcId::from_line(r#"{"id":1e-170141183460469231731687303715884105728}"#),
        RpcId::from_line(r#"{"id":0.001e-170141183460469231731687303715884105725}"#)
    );
    assert_eq!(
        RpcId::from_line(r#"{"id":1e170141183460469231731687303715884105727}"#),
        RpcId::from_line(r#"{"id":100e170141183460469231731687303715884105725}"#)
    );
    // In-range exponents keep normal canonicalization.
    assert_eq!(
        RpcId::from_line(r#"{"id":2.5e3}"#),
        RpcId::from_line(r#"{"id":2500}"#)
    );
}

#[test]
fn test_record_pending_list_rejects_null_id() {
    let mut state = SessionState::new();
    let err = state
        .record_pending_list(RpcId::Null, "list_files", DISCOVER_RULES)
        .unwrap_err();
    assert!(err.contains("null"), "got: {err}");
    assert!(state.take_pending_list(&RpcId::Null).is_none());
}

#[test]
fn test_take_pending_nonexistent() {
    let mut state = SessionState::new();
    assert!(
        state
            .take_pending_list(&RpcId::Number("42".into()))
            .is_none()
    );
}

// --- SessionManager ---

#[test]
fn test_session_manager_independent_sessions() {
    let mut mgr = SessionManager::new();
    mgr.get_or_create("session-a")
        .record_paths(&["/a/file.txt".to_string()]);
    mgr.get_or_create("session-b")
        .record_paths(&["/b/file.txt".to_string()]);

    assert!(
        mgr.get_or_create("session-a")
            .check_access("/a/file.txt")
            .is_ok()
    );
    assert!(
        mgr.get_or_create("session-a")
            .check_access("/b/file.txt")
            .is_err()
    );
    assert!(
        mgr.get_or_create("session-b")
            .check_access("/b/file.txt")
            .is_ok()
    );
    assert!(
        mgr.get_or_create("session-b")
            .check_access("/a/file.txt")
            .is_err()
    );
}

// --- URL-encoded path traversal ---

#[test]
fn test_path_traversal_url_encoded_lowercase() {
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/%2e%2e/etc/passwd".to_string()]);
    let err = state
        .check_access("/workspace/%2e%2e/etc/passwd")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_url_encoded_uppercase() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2E%2E/etc/passwd")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_url_encoded_mixed_case() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2e%2E/etc/passwd")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_url_encoded_mixed_case_2() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2E%2e/etc/passwd")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"));
}

// --- Partial URL-encoded path traversal ---

#[test]
fn test_path_traversal_first_dot_encoded() {
    // %2e./ — only the first dot is URL-encoded
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2e./etc/passwd")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"), "got: {err}");
}

#[test]
fn test_path_traversal_second_dot_encoded() {
    // .%2e/ — only the second dot is URL-encoded
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/.%2e/etc/passwd")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"), "got: {err}");
}

#[test]
fn test_path_traversal_dots_encoded_slash_literal() {
    // %2e%2e/ — both dots encoded, slash literal
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2e%2e/etc/passwd")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"), "got: {err}");
}

#[test]
fn test_path_traversal_backslash_partial_encoded() {
    // .%2e\ — partial encoding with backslash
    let state = SessionState::new();
    let err = state
        .check_access("C:\\workspace\\.%2e\\secret")
        .unwrap_err();
    assert!(err.contains("URL-encoded path traversal"), "got: {err}");
}

// --- Double URL-encoded path traversal ---

#[test]
fn test_path_traversal_double_url_encoded() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252e%252e/etc/passwd")
        .unwrap_err();
    assert!(err.contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_url_encoded_uppercase() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252E%252E/etc/passwd")
        .unwrap_err();
    assert!(err.contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_url_encoded_mixed() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252e%252E/etc/passwd")
        .unwrap_err();
    assert!(err.contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_url_encoded_with_slash() {
    let state = SessionState::new();
    // %252e%252e%252f decodes to %2e%2e%2f which decodes to ../
    let err = state
        .check_access("/workspace/%252e%252e%252fetc/passwd")
        .unwrap_err();
    assert!(err.contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_partial_encoded() {
    // %252e./ — first dot double-encoded, second literal
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252e./etc/passwd")
        .unwrap_err();
    assert!(
        err.contains("URL-encoded path traversal")
            || err.contains("double URL-encoded path traversal"),
        "got: {err}"
    );
}

#[test]
fn test_no_false_positive_on_percent25_without_traversal() {
    let mut state = SessionState::new();
    let path = "/workspace/%2520safe_file.txt";
    state.record_paths(&[path.to_string()]);
    // %2520 decodes once to %20 — no traversal. Both the seeded value
    // and the use-side argument canonicalize identically.
    let normalized = crate::pathutil::normalize_fs_argument(path).unwrap();
    assert!(state.check_access(&normalized).is_ok());
}

// --- extract_all_json_strings ---

#[test]
fn test_extract_strings_simple() {
    let json = r#"{"key":"value","other":"data"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"key".to_string()));
    assert!(strings.contains(&"value".to_string()));
    assert!(strings.contains(&"other".to_string()));
    assert!(strings.contains(&"data".to_string()));
}

#[test]
fn test_extract_strings_with_escapes() {
    let json = r#"{"path":"\/workspace\/file.txt"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"/workspace/file.txt".to_string()));
}

#[test]
fn test_extract_strings_with_newlines() {
    let json = r#"{"text":"/a.txt\n/b.txt\n/c.txt"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"/a.txt\n/b.txt\n/c.txt".to_string()));
}

#[test]
fn test_extract_strings_backspace_escape() {
    let json = r#"{"val":"a\bb"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"a\x08b".to_string()));
}

#[test]
fn test_extract_strings_formfeed_escape() {
    let json = r#"{"val":"a\fb"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"a\x0Cb".to_string()));
}

#[test]
fn test_extract_strings_unicode_escape_basic() {
    // \u0041 = 'A'
    let json = r#"{"val":"\u0041\u0042\u0043"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"ABC".to_string()));
}

#[test]
fn test_extract_strings_unicode_escape_japanese() {
    // \u3042 = 'あ'
    let json = r#"{"val":"\u3042"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"あ".to_string()));
}

#[test]
fn test_extract_strings_unicode_escape_mixed() {
    // Mix of unicode escapes and regular text
    let json = r#"{"path":"\/workspace\/\u0066ile.txt"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"/workspace/file.txt".to_string()));
}

#[test]
fn test_extract_strings_unicode_escape_invalid_hex_skipped() {
    // \uZZZZ is not valid hex — silently skipped
    let json = r#"{"val":"\uZZZZ"}"#;
    let strings = extract_all_json_strings(json);
    // Should not crash; the result won't contain the invalid escape as a char
    assert_eq!(strings.len(), 2); // "val" and whatever remains
}

#[test]
fn test_extract_strings_raw_multibyte_utf8() {
    // Raw multi-byte UTF-8 in JSON strings (e.g., Japanese directory names)
    let json = r#"{"path":"/workspace/日本語/file.txt"}"#;
    let strings = extract_all_json_strings(json);
    assert!(strings.contains(&"/workspace/日本語/file.txt".to_string()));
}

#[test]
fn test_extract_strings_empty_input() {
    let strings = extract_all_json_strings("");
    assert!(strings.is_empty());
}

// --- extract_paths_from_response ---

#[test]
fn test_extract_paths_from_list_response() {
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"/workspace/a.txt\n/workspace/b.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert!(paths.contains(&"/workspace/a.txt".to_string()));
    assert!(paths.contains(&"/workspace/b.txt".to_string()));
}

#[test]
fn test_extract_paths_from_resource_response() {
    let response = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"resource","resource":{"uri":"file:///workspace/file.txt","text":"contents"}}]}}"#;
    let paths = extract_paths_from_response(response);
    assert!(paths.contains(&"file:///workspace/file.txt".to_string()));
}

#[test]
fn test_extract_paths_no_result() {
    let response = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"fail"}}"#;
    let paths = extract_paths_from_response(response);
    assert!(paths.is_empty());
}

#[test]
fn test_extract_paths_invalid_json() {
    let paths = extract_paths_from_response("not json");
    assert!(paths.is_empty());
}

#[test]
fn test_extract_paths_filters_short_strings() {
    let response =
        r#"{"jsonrpc":"2.0","id":1,"result":{"x":"a","path":"/workspace/long_path.txt"}}"#;
    let paths = extract_paths_from_response(response);
    assert!(!paths.contains(&"a".to_string()));
    // Top-level `path` is not a typed list identifier.
    assert!(!paths.contains(&"/workspace/long_path.txt".to_string()));
}

#[test]
fn test_extract_paths_ignores_object_keys_and_metadata() {
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"path":"/etc/passwd","metadata":{"note":"/secret.txt"},"content":[{"type":"text","text":"/workspace/real.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert!(paths.contains(&"/workspace/real.txt".to_string()));
    assert!(!paths.contains(&"/etc/passwd".to_string()));
    assert!(!paths.contains(&"/secret.txt".to_string()));
    assert!(!paths.contains(&"path".to_string()));
}

#[test]
fn test_extract_paths_from_files_array() {
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"/workspace/a.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["/workspace/a.txt".to_string()]);
}

// --- End-to-end flow ---

#[test]
fn test_full_confused_deputy_flow() {
    let mut state = SessionState::new();

    // Step 1: list_files request goes through, record pending
    state
        .record_pending_list(RpcId::Number("1".into()), "list_files", DISCOVER_RULES)
        .unwrap();

    // Step 2: list_files response comes back with paths
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"/workspace/a.txt\n/workspace/b.txt"}]}}"#;
    assert!(
        state
            .take_pending_list(&RpcId::Number("1".into()))
            .is_some()
    );
    let paths = extract_paths_from_response(response);
    state.record_paths(&paths);

    // Step 3: read_file for discovered path → allowed
    assert!(state.check_access("/workspace/a.txt").is_ok());
    assert!(state.check_access("/workspace/b.txt").is_ok());

    // Step 4: read_file for undiscovered path → blocked
    assert!(state.check_access("/etc/shadow").is_err());

    // Step 5: path traversal → always blocked
    assert!(state.check_access("/workspace/../../etc/passwd").is_err());
}

#[test]
fn test_interleaved_list_read_shares_process_scope() {
    let mut state = SessionState::new();
    state
        .record_pending_list(RpcId::Number("1".into()), "list_files", DISCOVER_RULES)
        .unwrap();
    state
        .record_pending_list(RpcId::Number("2".into()), "list_files", DISCOVER_RULES)
        .unwrap();

    assert!(
        state
            .take_pending_list(&RpcId::Number("1".into()))
            .is_some()
    );
    state.record_paths(&["/client-a/file.txt".to_string()]);

    assert!(
        state
            .take_pending_list(&RpcId::Number("2".into()))
            .is_some()
    );
    state.record_paths(&["/client-b/file.txt".to_string()]);

    // Process-scope: interleaved list responses share one known_paths set.
    assert!(state.check_access("/client-a/file.txt").is_ok());
    assert!(state.check_access("/client-b/file.txt").is_ok());
    assert!(state.check_access("/client-c/unlisted.txt").is_err());
}

#[test]
fn test_read_file_mrtr_retry_still_subject_to_known_paths() {
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/a.txt".to_string()]);

    // First tools/call (id=1)
    assert!(state.check_access("/workspace/a.txt").is_ok());
    // MRTR retry: new JSON-RPC id, same path — still allowed
    assert!(state.check_access("/workspace/a.txt").is_ok());
    // requestState / new id must not grant an undiscovered path
    assert!(state.check_access("/etc/passwd").is_err());
}

fn read_only_then_network_rule() -> Vec<crate::policy::TrajectoryRule> {
    vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::ReadOnly,
        deny_next: crate::policy::SideEffect::Network,
    }]
}

#[test]
fn test_trajectory_empty_last_allows_network() {
    let state = SessionState::new();
    assert!(
        state
            .check_trajectory(
                &read_only_then_network_rule(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
                false,
            )
            .is_ok()
    );
    assert!(state.last_successful_side_effect().is_none());
    assert!(state.last_successful_tool().is_none());
}

#[test]
fn test_trajectory_denies_network_after_successful_read_only() {
    let mut state = SessionState::new();
    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("1".into()), true);
    assert_eq!(
        state.last_successful_side_effect(),
        Some(crate::policy::SideEffect::ReadOnly)
    );

    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
    assert!(err.contains("deny-next=\"network\""), "{err}");
}

#[test]
fn test_trajectory_denies_extractable_host_after_read_only() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "post_data",
            Some(crate::policy::SideEffect::Write),
            true,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"network\""), "{err}");
}

#[test]
fn test_trajectory_failed_call_does_not_update_last() {
    let mut state = SessionState::new();
    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("1".into()), false);
    assert!(state.last_successful_side_effect().is_none());
    assert!(
        state
            .check_trajectory(
                &read_only_then_network_rule(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
                false,
            )
            .is_ok()
    );
}

#[test]
fn test_trajectory_failed_write_does_not_clear_successful_read() {
    let mut state = SessionState::new();
    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("1".into()), true);
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "fail_write",
            Some(crate::policy::SideEffect::Write),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("2".into()), false);
    assert_eq!(
        state.last_successful_side_effect(),
        Some(crate::policy::SideEffect::ReadOnly)
    );
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
}

#[test]
fn test_trajectory_same_tool_is_not_denied() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    assert!(
        state
            .check_trajectory(
                &read_only_then_network_rule(),
                "read_file",
                Some(crate::policy::SideEffect::Network),
                true,
            )
            .is_ok()
    );
}

#[test]
fn test_trajectory_same_tool_extra_url_is_denied() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
            true,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
}

#[test]
fn test_trajectory_same_tool_path_only_is_allowed() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    assert!(
        state
            .check_trajectory(
                &read_only_then_network_rule(),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
                false,
            )
            .is_ok()
    );
}

#[test]
fn test_trajectory_mrtr_retry_uses_tool_and_side_effect_only() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    // New JSON-RPC id + requestState must not change the rule.
    state
        .record_pending_tool_call(
            RpcId::Number("99".into()),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
}

fn network_then_execute_rule() -> Vec<crate::policy::TrajectoryRule> {
    vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::Network,
        deny_next: crate::policy::SideEffect::Execute,
    }]
}

fn read_only_then_read_only_rule() -> Vec<crate::policy::TrajectoryRule> {
    vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::ReadOnly,
        deny_next: crate::policy::SideEffect::ReadOnly,
    }]
}

#[test]
fn test_trajectory_unverified_release_feeds_deny_matching() {
    let mut state = SessionState::new();
    // Releasing an id that was never pended is a no-op.
    state.release_pending_tool_call_unverified(&RpcId::Number("9".into()));
    assert!(
        state
            .check_trajectory(
                &network_then_execute_rule(),
                "run_cmd",
                Some(crate::policy::SideEffect::Execute),
                false,
            )
            .is_ok()
    );

    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("1".into()));
    // The cancelled call may have run server-side: its side_effect is
    // a deny-match candidate even though nothing was proven successful.
    let err = state
        .check_trajectory(
            &network_then_execute_rule(),
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"execute\""), "{err}");
    // The verified marker is untouched.
    assert!(state.last_successful_side_effect().is_none());
    assert!(state.last_successful_tool().is_none());
}

#[test]
fn test_trajectory_cancelled_call_cannot_launder_verified_marker() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    // A cancelled benign call must not overwrite the verified marker —
    // if it counted as a success, `after=read_only deny-next=network`
    // would be disarmed just by cancelling a harmless call.
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "stat_file",
            Some(crate::policy::SideEffect::Write),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"network\""), "{err}");
    assert_eq!(
        state.last_successful_side_effect(),
        Some(crate::policy::SideEffect::ReadOnly)
    );
    assert_eq!(state.last_successful_tool(), Some("read_file"));
}

#[test]
fn test_trajectory_unverified_other_tool_breaks_same_tool_exemption() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "other_tool",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    // Without the intervening cancel, read_file → read_file is exempt.
    // The possibly-executed other_tool may be the true last call, so
    // the chain is provably cross-tool and the after rule applies.
    let err = state
        .check_trajectory(
            &read_only_then_read_only_rule(),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"read_only\""), "{err}");
}

#[test]
fn test_trajectory_unverified_same_tool_keeps_exemption() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    // Every candidate is provably read_file, so the same-tool
    // exemption still holds even under a rule that denies
    // read_only → read_only.
    assert!(
        state
            .check_trajectory(
                &read_only_then_read_only_rule(),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
                false,
            )
            .is_ok()
    );
}

#[test]
fn test_trajectory_verified_success_keeps_unverified_candidates() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    // An unrelated verified success proves nothing about whether
    // the cancelled call ran — the Network tombstone still
    // satisfies `after=network` and denies a following Execute.
    state.record_successful_tool_call("write_file", Some(crate::policy::SideEffect::Write));
    let err = state
        .check_trajectory(
            &network_then_execute_rule(),
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"execute\""), "{err}");
    // Only the call's own definitive response resolves the
    // tombstone: a late *error* verdict proves it did not run, so
    // `after=network` no longer matches — while the verified Write
    // marker continues to govern.
    state.complete_pending_tool_call(&RpcId::Number("2".into()), false);
    assert!(
        state
            .check_trajectory(
                &network_then_execute_rule(),
                "run_cmd",
                Some(crate::policy::SideEffect::Execute),
                false,
            )
            .is_ok()
    );
    let err = state
        .check_trajectory(
            &[crate::policy::TrajectoryRule {
                after_side_effect: crate::policy::SideEffect::Write,
                deny_next: crate::policy::SideEffect::Execute,
            }],
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"execute\""), "{err}");
}

#[test]
fn test_trajectory_maybe_tool_name_overflow_disables_exemption() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    // Tombstone bytes are id + retained tool name — pushing the
    // unverified budget over the cap latches "untrusted", so the
    // same-tool exemption stays unreachable for a later matching name.
    let wide = "x".repeat(33_000);
    for i in 0..2 {
        let id = RpcId::Number(i.to_string());
        state
            .record_pending_tool_call(id.clone(), &wide, None)
            .unwrap();
        state.release_pending_tool_call_unverified(&id);
    }
    state
        .record_pending_tool_call(RpcId::Number("3".into()), "read_file", None)
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("3".into()));
    let err = state
        .check_trajectory(
            &read_only_then_read_only_rule(),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"read_only\""), "{err}");
}
