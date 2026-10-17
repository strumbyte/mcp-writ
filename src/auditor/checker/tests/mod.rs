use super::sub_policy::{host_matches, normalize_path, path_matches};
use super::*;
use crate::policy::ToolPolicy;

fn test_policy() -> Policy {
    Policy {
        tools: vec![
            ToolPolicy {
                name: "read_file".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: None,
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
            },
            ToolPolicy {
                name: "exec_shell".to_string(),
                allowed: false,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: None,
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
            },
        ],
        ..Default::default()
    }
}

#[test]
fn test_allowed_tool_passes() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
    assert!(check_request(line, &policy).is_ok());
}

#[test]
fn test_denied_tool_rejected() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_shell","arguments":{}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "exec_shell");
}

#[test]
fn test_unknown_tool_rejected() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "unknown_tool");
}

#[test]
fn test_non_tools_call_passes_through() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}"#;
    assert!(check_request(line, &policy).is_ok());
}

#[test]
fn test_invalid_json_rejected() {
    let policy = test_policy();
    let err = check_request("not json at all", &policy).unwrap_err();
    assert_eq!(err.tool_name, "<unknown>");
    assert!(err.reason.contains("invalid JSON"));
}

#[test]
fn test_notification_without_method_passes() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","result":{}}"#;
    assert!(check_request(line, &policy).is_ok());
}

#[test]
fn test_tools_call_missing_params() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call"}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "<unknown>");
    assert!(err.reason.contains("without params"));
}

#[test]
fn test_tools_call_missing_params_name() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"arguments":{}}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "<unknown>");
    assert!(err.reason.contains("params.name"));
}

#[test]
fn test_tools_call_name_not_string() {
    let policy = test_policy();
    let line = r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":123}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert_eq!(err.tool_name, "<unknown>");
    assert!(err.reason.contains("not a string"));
}

#[test]
fn test_empty_policy_denies_all_tools() {
    let policy = Policy::default(); // no tools defined
    let line = r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"anything"}}"#;
    let err = check_request(line, &policy).unwrap_err();
    assert!(err.reason.contains("default deny"));
}

#[test]
fn test_empty_line_rejected() {
    let policy = test_policy();
    let err = check_request("", &policy).unwrap_err();
    assert_eq!(err.tool_name, "<unknown>");
    assert!(err.reason.contains("invalid JSON"));
}

use crate::policy::{FsToolPolicy, ToolNetworkPolicy, ToolSyscallPolicy};

/// A workspace root spelling that resolves on any host: a directory
/// (which need not exist) directly under the temp tree's filesystem
/// root — `C:/mcp-writ-test-ws` on Windows, `/mcp-writ-test-ws` on
/// unix. Bare `/workspace` spellings qualify to the *process* drive on
/// Windows and fail authorization closed when the repo lives on a
/// broad-writable data volume (`Authenticated Users: Modify` on the
/// drive root), so POSIX literals are machine-dependent.
fn ws() -> String {
    crate::pathutil::temp_root_abs("/mcp-writ-test-ws")
}

/// `{ws()}/{rel}` — a path inside the test workspace root.
fn ws_at(rel: &str) -> String {
    format!("{}/{rel}", ws())
}

fn sub_policy_policy() -> Policy {
    Policy {
        tools: vec![
            // Tool with fs sub-policy: only the test root allowed, its
            // `secrets` subtree denied
            ToolPolicy {
                name: "read_file".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: Some(FsToolPolicy::new(vec![ws()], vec![ws_at("secrets")])),
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
            },
            // Tool with network sub-policy
            ToolPolicy {
                name: "fetch_url".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: None,
                syscalls: None,
                network: Some(ToolNetworkPolicy {
                    allowed_hosts: vec!["api.example.com".to_string()],
                    allowed_cidrs: Vec::new(),
                    denied_hosts: vec!["evil.com".to_string()],
                    denied_cidrs: Vec::new(),
                    egress_rules: Vec::new(),
                    allow_specified: true,
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
            },
            // Tool with no sub-policy (global defaults only)
            ToolPolicy {
                name: "list_files".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: None,
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
            },
            // Tool with syscall sub-policy (metadata only, no request-level check)
            ToolPolicy {
                name: "exec_cmd".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: None,
                syscalls: Some(ToolSyscallPolicy {
                    allowed: vec!["read".to_string(), "write".to_string()],
                    denied: vec!["execve".to_string()],
                }),
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
            },
        ],
        // The global default is `deny_all_others` — these tests exercise
        // *tool-level* rules, so open the global egress posture like a
        // real policy that wants outbound reachability would.
        ..{
            let mut p = Policy::default();
            p.network.outbound.deny_all_others = false;
            p
        }
    }
}

fn overlay_on_no_fs_policy() -> Policy {
    let mut policy = Policy::default();
    policy.fs.secret_overlay = true;
    policy.tools = vec![ToolPolicy::named("read_file", true)];
    policy
}

fn tools_call(id: u32, name: &str, arguments: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
    )
}

fn schema_policy() -> Policy {
    Policy {
        tools: vec![
            ToolPolicy {
                name: "read_file".to_string(),
                allowed: true,
                args_schema: Some(
                    r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}"#.to_string()
                ),
                side_effect: None,
                server: None,
                fs: None,
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
            },
            ToolPolicy {
                name: "optional_args".to_string(),
                allowed: true,
                args_schema: Some(
                    r#"{"type":"object","properties":{"opt":{"type":"string"}},"additionalProperties":false}"#.to_string()
                ),
                side_effect: None,
                server: None,
                fs: None,
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
            },
            ToolPolicy {
                name: "no_schema".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: None,
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
            },
        ],
        ..Default::default()
    }
}

mod decoy;
mod helpers;
mod mrtr;
mod schema;
mod tool_sub_policy;
mod trajectory_cidr;
mod url_overlay;
