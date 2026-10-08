//! Confused-deputy protection: configurable discover/use roles and
//! extraction rules, legacy tool-name bindings, isError and
//! MRTR-interim seeding rules, and denial audit events.

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

// ── Confused Deputy: configurable roles & extraction rules (PR-14) ──

/// v2 policy exercising the PR-14 role/extraction model:
/// - `list_workspace` is the discovery tool — `shape "mcp_list_result"`
///   plus an `extract` JSON Pointer onto `/result/files/*/path`.
/// - `list_broken` shares the discover role but answers `isError=true` —
///   a failed response must never seed `known_paths`.
/// - `read_workspace` is the use tool; its `/params/arguments/path` target
///   must already be discovered.
/// - `list_files` / `read_file` ride the fixed-name compatibility mapping,
///   `write_file` stays unregistered.
const DEPUTY_ROLES_POLICY: &str = r#"
policy version=2
confused_deputy_protection #true
server "wire" {
    tool "list_workspace" {
        deputy role="discover" {
            shape "mcp_list_result"
            extract "/result/files/*/path"
        }
    }
    tool "list_broken" {
        deputy role="discover" {
            shape "mcp_list_result"
        }
    }
    tool "read_workspace" {
        deputy role="use" {
            extract "/params/arguments/path"
        }
    }
    tool "list_files"
    tool "list_directory"
    tool "read_file"
    tool "write_file"
}
"#;

fn deputy_call(name: &str, id: u32, path: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{{"path":"{path}"}},{meta}}}}}"#,
        meta = common::META_2026
    )
}

/// Custom role names drive the whole loop: the use tool is denied until a
/// discovery response seeds `known_paths`, then only discovered paths pass.
/// Unknown paths, `../` traversal, and percent-encoded traversal all deny;
/// unregistered tools are untouched by the gate.
#[tokio::test]
async fn deputy_roles_custom_tools_end_to_end() {
    let dir = make_test_dir("deputy_roles");
    let policy = write_policy(dir.path(), DEPUTY_ROLES_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("deputy_paths"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // Before any discovery the use tool cannot pass — extraction succeeds
    // but the path was never discovered.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("read_workspace", 2, "/workspace/notes.txt"),
    )
    .await;
    assert!(has_error(&resp), "pre-discovery use must deny: {resp}");
    assert!(
        resp.contains("confused deputy") && resp.contains("was not discovered"),
        "denial must name the deputy gate: {resp}"
    );

    // Discovery seeds /workspace/notes.txt, /workspace/todo.txt (content
    // lines) and /workspace/data.csv (files[].path via shape + pointer).
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("list_workspace", 3, common::META_2026),
    )
    .await;
    assert!(has_result(&resp), "discovery call must forward: {resp}");

    for (id, path) in [
        (4u32, "/workspace/notes.txt"),
        (5, "/workspace/todo.txt"),
        (6, "/workspace/data.csv"),
    ] {
        let resp = send_and_recv(
            &mut stdin,
            &mut reader,
            &deputy_call("read_workspace", id, path),
        )
        .await;
        assert!(
            has_result(&resp) && !resp.contains("\"isError\":true"),
            "discovered path must pass the deputy gate with a successful result: {resp}"
        );
    }

    // Never-discovered path — same workspace prefix does not help.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("read_workspace", 7, "/workspace/secret.txt"),
    )
    .await;
    assert!(
        has_error(&resp) && resp.contains("was not discovered"),
        "got: {resp}"
    );

    // `../` and percent-encoded traversal deny before the membership
    // check (paths chosen so they do not resolve into the secret-path
    // overlay — the deputy gate itself must produce the denial).
    for (id, path) in [
        (8u32, "/workspace/sub/../notes.txt"),
        (9, "/workspace/%2e%2e/secret"),
    ] {
        let resp = send_and_recv(
            &mut stdin,
            &mut reader,
            &deputy_call("read_workspace", id, path),
        )
        .await;
        assert!(
            has_error(&resp) && resp.contains("path traversal"),
            "traversal must deny: {resp}"
        );
    }

    // A use call whose extraction rules resolve nothing fails closed —
    // an empty target set can never mean "nothing to check".
    let no_target = format!(
        r#"{{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{{"name":"read_workspace","arguments":{{}},{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &no_target).await;
    assert!(
        has_error(&resp) && resp.contains("missing a resolvable path target"),
        "empty extraction must deny: {resp}"
    );

    // A tool with no role bound ignores the gate entirely.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("write_file", 11, "/anywhere/out.bin"),
    )
    .await;
    assert!(has_result(&resp), "unregistered tool must forward: {resp}");

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    let denied = audit_lines(&audit, "tool_call.denied");
    assert!(
        denied.iter().any(|l| l.contains("confused deputy")),
        "deputy denials must be audited: {audit}"
    );
    // The traversal refusals (ids 8/9) also produce their typed
    // `validation.path_traversal` companion records — the `validation`
    // category must stay queryable, not fold silently into the deny.
    let traversal = audit_lines(&audit, "validation.path_traversal");
    assert!(
        traversal.iter().any(|l| l.contains("path traversal")),
        "traversal refusals must emit validation.path_traversal: {audit}"
    );
}

/// An `args_schema` rejection is a user-space validation refusal: the
/// audit stream must carry the typed `validation.argument_invalid`
/// companion record alongside the `tool_call.denied`.
#[tokio::test]
async fn args_schema_denial_emits_validation_event() {
    let dir = make_test_dir("args_schema_validation");
    let policy_kdl = r#"
policy version=1
server "wire" {
    tool "read_file" args_schema="{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}"
}
"#;
    let policy = write_policy(dir.path(), policy_kdl);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("log_ok"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // `path` must be a string — a number violates the schema.
    let bad = format!(
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":123}},{meta}}}}}"#,
        meta = common::META_2026
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &bad).await;
    assert!(has_error(&resp), "schema violation must deny: {resp}");

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    let invalid = audit_lines(&audit, "validation.argument_invalid");
    assert!(
        invalid
            .iter()
            .any(|l| l.contains("schema validation failed")),
        "schema refusal must emit validation.argument_invalid: {audit}"
    );
}

/// `result.isError=true` is a tool failure, not a discovery: the response
/// still reaches the client but must not seed `known_paths`.
#[tokio::test]
async fn deputy_failed_response_seeds_nothing() {
    let dir = make_test_dir("deputy_iserror");
    let policy = write_policy(dir.path(), DEPUTY_ROLES_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("deputy_paths"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("list_broken", 2, common::META_2026),
    )
    .await;
    assert!(
        has_result(&resp) && resp.contains("\"isError\":true"),
        "failed tool result still forwards: {resp}"
    );

    // The payload carried /workspace/notes.txt — had it seeded, this read
    // would pass.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("read_workspace", 3, "/workspace/notes.txt"),
    )
    .await;
    assert!(
        has_error(&resp) && resp.contains("was not discovered"),
        "isError discovery must not seed: {resp}"
    );

    drop(stdin);
}

/// The three legacy names keep their fixed binding without any `deputy`
/// blocks: `list_files` / `list_directory` discover, `read_file` uses.
#[tokio::test]
async fn deputy_legacy_names_still_bind() {
    let dir = make_test_dir("deputy_compat");
    let policy = write_policy(dir.path(), DEPUTY_ROLES_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("deputy_paths"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("read_file", 2, "/workspace/notes.txt"),
    )
    .await;
    assert!(
        has_error(&resp) && resp.contains("confused deputy"),
        "compat read_file must be a use tool: {resp}"
    );

    for (id, name) in [(3u32, "list_files"), (4, "list_directory")] {
        let resp = send_and_recv(
            &mut stdin,
            &mut reader,
            &call_2026(name, id, common::META_2026),
        )
        .await;
        assert!(has_result(&resp), "{name} must discover: {resp}");
    }

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("read_file", 5, "/workspace/todo.txt"),
    )
    .await;
    assert!(
        has_result(&resp) && !resp.contains("\"isError\":true"),
        "compat read_file passes once discovered: {resp}"
    );

    drop(stdin);
}

/// MRTR deputy scenario: `list_workspace` interims with `input_required`,
/// then the `inputResponses` retry completes with the discovery payload.
/// `input_responses="allow"` opts the discovery tool in — the v2 closed
/// network default gives every tool a security contract, so the `auto`
/// resolution denies MRTR retries without it.
const DEPUTY_MRTR_POLICY: &str = r#"
policy version=2
confused_deputy_protection #true
server "wire" {
    tool "list_workspace" input_responses="allow" {
        deputy role="discover" {
            shape "mcp_list_result"
        }
    }
    tool "read_workspace" input_responses="allow" {
        deputy role="use" {
            extract "/params/arguments/path"
        }
    }
    mcp {
        allow "elicitation/create"
    }
}
"#;

/// An `input_required` interim on a discovery call is forwarded verbatim
/// but must not seed `known_paths` — only the completed, correlated retry
/// may. Between the two responses the use tool still denies.
#[tokio::test]
async fn deputy_mrtr_interim_seeds_nothing() {
    let dir = make_test_dir("deputy_mrtr");
    let policy = write_policy(dir.path(), DEPUTY_MRTR_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required_deputy_paths"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    // Interim: the pending discovery entry is consumed without seeding.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("list_workspace", 2, META_2026_ELICIT),
    )
    .await;
    assert_eq!(json_id(&resp).as_deref(), Some("2"), "got: {resp}");
    assert!(
        resp.contains("\"resultType\":\"input_required\""),
        "interim must forward to the client: {resp}"
    );

    // The interim is not a success — no path may have been recorded.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("read_workspace", 3, "/workspace/notes.txt"),
    )
    .await;
    assert!(
        has_error(&resp) && resp.contains("was not discovered"),
        "interim must not seed: {resp}"
    );

    // MRTR retry under a new id, requestState echoed opaquely. The
    // completed response carries the path payload and seeds known_paths.
    let retry = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{{"name":"list_workspace","arguments":{{}},"requestState":"state-blob","inputResponses":{{"github_login":{{"action":"accept","content":{{"name":"octocat"}}}}}},{meta}}}}}"#,
        meta = META_2026_ELICIT
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &retry).await;
    assert_eq!(json_id(&resp).as_deref(), Some("4"), "got: {resp}");
    assert!(
        has_result(&resp)
            && resp.contains("/workspace/data.csv")
            && !resp.contains("\"isError\":true"),
        "completed retry must be a successful result carrying the discovery payload: {resp}"
    );

    // Seeded paths now pass — files[].path came via shape extraction.
    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &deputy_call("read_workspace", 5, "/workspace/data.csv"),
    )
    .await;
    assert!(
        has_result(&resp) && !resp.contains("\"isError\":true"),
        "path seeded by the completed retry must pass with a successful result: {resp}"
    );

    // The retry channel is vetted too: a path inside `inputResponses`
    // that was never discovered must deny even though the `arguments`
    // pointer resolves to a discovered path.
    let sneaky_retry = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"read_workspace","arguments":{{"path":"/workspace/data.csv"}},"requestState":"state-blob","inputResponses":{{"github_login":{{"action":"accept","content":{{"path":"/workspace/secret.txt"}}}}}},{meta}}}}}"#,
        meta = META_2026_ELICIT
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &sneaky_retry).await;
    assert!(
        has_error(&resp) && resp.contains("was not discovered"),
        "inputResponses path must face the deputy gate: {resp}"
    );

    drop(stdin);
}
