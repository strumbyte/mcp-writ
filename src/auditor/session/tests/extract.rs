use super::super::*;

// --- extract_paths_from_response: escape decoding ---

// Escape fixtures place the candidate inside `files[].path`, a field
// `extract_paths_from_response` actually decodes, so these verify the
// production unescape path rather than a test-side scanner.

#[test]
fn test_extract_paths_escaped_slash() {
    let response =
        r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"\/workspace\/file.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["/workspace/file.txt".to_string()]);
}

#[test]
fn test_extract_paths_escaped_newline() {
    let response =
        r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"/a.txt\n/b.txt\n/c.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["/a.txt\n/b.txt\n/c.txt".to_string()]);
}

#[test]
fn test_extract_paths_backspace_escape() {
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"a\bb"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["a\x08b".to_string()]);
}

#[test]
fn test_extract_paths_formfeed_escape() {
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"a\fb"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["a\x0Cb".to_string()]);
}

#[test]
fn test_extract_paths_unicode_escape_basic() {
    // \u0041 = 'A'
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"\u0041\u0042\u0043"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["ABC".to_string()]);
}

#[test]
fn test_extract_paths_unicode_escape_japanese() {
    // \u3042 = 'あ'
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"w/\u3042"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["w/あ".to_string()]);
}

#[test]
fn test_extract_paths_unicode_escape_mixed() {
    // Mix of unicode escapes and regular text
    let response =
        r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"\/workspace\/\u0066ile.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["/workspace/file.txt".to_string()]);
}

#[test]
fn test_extract_paths_unicode_escape_invalid_hex_skipped() {
    // `\uZZZZ` is not a legal escape — strict parsing refuses the
    // response, so the malformed path can never yield a raw or
    // partially-decoded candidate.
    let response =
        r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"ok\uZZZZx"},{"path":"fine.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert!(paths.is_empty());
}

#[test]
fn test_extract_paths_raw_multibyte_utf8() {
    // Raw multi-byte UTF-8 in JSON strings (e.g., Japanese directory names)
    let response =
        r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"/workspace/日本語/file.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["/workspace/日本語/file.txt".to_string()]);
}

#[test]
fn test_extract_paths_empty_input() {
    assert!(extract_paths_from_response("").is_empty());
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
    // Both candidates sit inside a field the extractor inspects — the
    // short string is filtered for noise while the real path survives,
    // so the assertion cannot pass merely because the extractor
    // ignores the response's fields.
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"a"},{"path":"/workspace/long_path.txt"}]}}"#;
    let paths = extract_paths_from_response(response);
    assert_eq!(paths, vec!["/workspace/long_path.txt".to_string()]);
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
