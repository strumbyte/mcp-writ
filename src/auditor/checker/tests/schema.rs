use super::*;

// --- Schema validation tests ---

#[test]
fn test_schema_valid_args_pass() {
    let policy = schema_policy();
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/f.txt"}}}"#;
    assert!(check_request(line, &policy).is_ok());
}

#[test]
fn test_schema_missing_required_rejected() {
    let policy = schema_policy();
    let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    assert!(
        err.reason.contains("schema validation failed"),
        "got: {}",
        err.reason
    );
    assert!(err.reason.contains("path"), "got: {}", err.reason);
}

#[test]
fn test_schema_wrong_type_rejected() {
    let policy = schema_policy();
    let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":123}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    assert!(
        err.reason.contains("should be string"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_schema_additional_property_rejected() {
    let policy = schema_policy();
    let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp","extra":"bad"}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    assert!(
        err.reason.contains("additional property"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_no_schema_still_passes_name_check_only() {
    let policy = schema_policy();
    let line = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"no_schema","arguments":{"anything":"goes"}}}"#;
    assert!(check_request(line, &policy).is_ok());
}

#[test]
fn test_schema_missing_arguments_validated_as_empty_object() {
    // MCP allows omitting `params.arguments` — the schema sees {}.
    // `read_file` requires `path`, so the omission fails as a schema
    // violation rather than a transport-shape error.
    let policy = schema_policy();
    let line = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_file"}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "read_file");
    assert!(
        err.reason.contains("schema validation failed"),
        "got: {}",
        err.reason
    );
    assert!(
        err.reason.contains("missing required"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_schema_missing_arguments_optional_schema_passes() {
    // An all-optional schema accepts an omitted `arguments`.
    let policy = schema_policy();
    let line =
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"optional_args"}}"#;
    assert!(check_request(line, &policy).is_ok());
}
