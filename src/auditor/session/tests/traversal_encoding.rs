use super::super::*;

// --- URL-encoded path traversal ---

#[test]
fn test_path_traversal_url_encoded_lowercase() {
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/%2e%2e/etc/passwd".to_string()]);
    let err = state
        .check_access("/workspace/%2e%2e/etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_url_encoded_uppercase() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2E%2E/etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_url_encoded_mixed_case() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2e%2E/etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_url_encoded_mixed_case_2() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2E%2e/etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("URL-encoded path traversal"));
}

// --- Partial URL-encoded path traversal ---

#[test]
fn test_path_traversal_first_dot_encoded() {
    // %2e./ — only the first dot is URL-encoded
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2e./etc/passwd")
        .unwrap_err();
    assert!(
        err.reason().contains("URL-encoded path traversal"),
        "got: {err}"
    );
}

#[test]
fn test_path_traversal_second_dot_encoded() {
    // .%2e/ — only the second dot is URL-encoded
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/.%2e/etc/passwd")
        .unwrap_err();
    assert!(
        err.reason().contains("URL-encoded path traversal"),
        "got: {err}"
    );
}

#[test]
fn test_path_traversal_dots_encoded_slash_literal() {
    // %2e%2e/ — both dots encoded, slash literal
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%2e%2e/etc/passwd")
        .unwrap_err();
    assert!(
        err.reason().contains("URL-encoded path traversal"),
        "got: {err}"
    );
}

#[test]
fn test_path_traversal_backslash_partial_encoded() {
    // .%2e\ — partial encoding with backslash
    let state = SessionState::new();
    let err = state
        .check_access("C:\\workspace\\.%2e\\secret")
        .unwrap_err();
    assert!(
        err.reason().contains("URL-encoded path traversal"),
        "got: {err}"
    );
}

// --- Double URL-encoded path traversal ---

#[test]
fn test_path_traversal_double_url_encoded() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252e%252e/etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_url_encoded_uppercase() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252E%252E/etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_url_encoded_mixed() {
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252e%252E/etc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_url_encoded_with_slash() {
    let state = SessionState::new();
    // %252e%252e%252f decodes to %2e%2e%2f which decodes to ../
    let err = state
        .check_access("/workspace/%252e%252e%252fetc/passwd")
        .unwrap_err();
    assert!(err.reason().contains("double URL-encoded path traversal"));
}

#[test]
fn test_path_traversal_double_partial_encoded() {
    // %252e./ — first dot double-encoded, second literal
    let state = SessionState::new();
    let err = state
        .check_access("/workspace/%252e./etc/passwd")
        .unwrap_err();
    assert!(
        err.reason().contains("URL-encoded path traversal")
            || err.reason().contains("double URL-encoded path traversal"),
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
