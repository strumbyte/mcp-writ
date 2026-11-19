use super::super::*;

use super::DISCOVER_RULES;

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
    assert!(err.reason().contains("not discovered"));
    assert!(err.reason().contains("/etc/passwd"));
}

#[test]
fn test_empty_known_paths_blocks_all() {
    let state = SessionState::new();
    let err = state.check_access("/workspace/file.txt").unwrap_err();
    assert!(err.reason().contains("not discovered"));
}

#[test]
fn test_path_traversal_forward_slash() {
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/../../etc/passwd".to_string()]);
    let err = state
        .check_access("/workspace/../../etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("path traversal"));
}

#[test]
fn test_path_traversal_backslash() {
    let state = SessionState::new();
    let err = state
        .check_access("C:\\workspace\\..\\..\\etc\\passwd")
        .unwrap_err();
    assert!(err.reason().contains("path traversal"));
}

#[test]
fn test_path_traversal_detected_even_when_known() {
    let mut state = SessionState::new();
    // Even if ../path is somehow in known_paths, traversal is blocked
    state.known_paths.insert("/workspace/../secret".to_string());
    let err = state.check_access("/workspace/../secret").unwrap_err();
    assert!(err.reason().contains("path traversal"));
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
    assert!(err.reason().contains("path traversal"));
    let err = state.check_access("/workspace/%2e%2e/secret").unwrap_err();
    assert!(err.reason().contains("URL-encoded path traversal"));
}

// --- pending list requests ---

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
    // An unrelated id consumes nothing — correlation never aliases
    // a different request's pending entry.
    assert!(
        state
            .take_pending_list(&RpcId::from_line(r#"{"id":8}"#).unwrap())
            .is_none()
    );
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
        let a = RpcId::from_line(a).unwrap();
        let b = RpcId::from_line(b).unwrap();
        assert_ne!(a, b, "distinct spellings must not correlate");
    }
}

#[test]
fn test_rpc_id_number_out_of_range_exponents() {
    // Beyond f64 range: mathematically equal spellings still correlate.
    let big = RpcId::from_line(r#"{"id":1e400}"#).unwrap();
    for line in [
        r#"{"id":10e399}"#,
        r#"{"id":0.01e402}"#,
        r#"{"id":100E398}"#,
    ] {
        assert_eq!(RpcId::from_line(line).unwrap(), big, "{line}");
    }
    let tiny = RpcId::from_line(r#"{"id":5e-400}"#).unwrap();
    for line in [r#"{"id":0.5e-399}"#, r#"{"id":50e-401}"#] {
        assert_eq!(RpcId::from_line(line).unwrap(), tiny, "{line}");
    }
    // Exponent literal beyond i128: raw fallback keeps the whole
    // spelling — compare with the exact `Number` it must produce, not
    // a parse with itself.
    let huge = r#"{"id":1e999999999999999999999999999999999999999}"#;
    assert_eq!(
        RpcId::from_line(huge),
        Some(RpcId::Number(
            "1e999999999999999999999999999999999999999".to_string()
        )),
    );
}

#[test]
fn test_rpc_id_number_exponent_arithmetic_overflow_falls_back() {
    // exp_lit at i128 edges: fraction-digit subtraction and
    // trailing-zero addition overflow — both fall back to the raw
    // spelling as a `Number` id.
    let at_min = r#"{"id":0.1e-170141183460469231731687303715884105728}"#;
    let at_max = r#"{"id":10e170141183460469231731687303715884105727}"#;
    assert_eq!(
        RpcId::from_line(at_min),
        Some(RpcId::Number(
            "0.1e-170141183460469231731687303715884105728".to_string()
        )),
    );
    assert_eq!(
        RpcId::from_line(at_max),
        Some(RpcId::Number(
            "10e170141183460469231731687303715884105727".to_string()
        )),
    );
    assert_ne!(
        RpcId::from_line(at_min).unwrap(),
        RpcId::from_line(at_max).unwrap()
    );
    // Exactly at the i128 edges the arithmetic still fits and correlates.
    assert_eq!(
        RpcId::from_line(r#"{"id":1e-170141183460469231731687303715884105728}"#).unwrap(),
        RpcId::from_line(r#"{"id":0.001e-170141183460469231731687303715884105725}"#).unwrap()
    );
    assert_eq!(
        RpcId::from_line(r#"{"id":1e170141183460469231731687303715884105727}"#).unwrap(),
        RpcId::from_line(r#"{"id":100e170141183460469231731687303715884105725}"#).unwrap()
    );
    // In-range exponents keep normal canonicalization.
    assert_eq!(
        RpcId::from_line(r#"{"id":2.5e3}"#).unwrap(),
        RpcId::from_line(r#"{"id":2500}"#).unwrap()
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
