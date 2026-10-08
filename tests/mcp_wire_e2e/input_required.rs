//! MRTR `input_required` gating: `inputRequests` entries against
//! allow rules and client capabilities, `inputResponses` retry
//! payloads, and the `requestState` cap applied to the retry channel.

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

// ─── MRTR input_required (PR-11) ────────────────────────────────────────

/// v2 policy granting the `elicitation/create` additional-request slot —
/// `read_file` also opts into `inputResponses` so the MRTR retry completes.
const MRTR_POLICY: &str = r#"
policy version=2
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file" input_responses="allow"
    tool "write_file"
    tool "fail_write"
    tool "fetch_url"
    mcp {
        allow "elicitation/create"
    }
}
"#;

/// Same tools but no `mcp` block — every additional request is `no-rule`.
const MRTR_POLICY_NO_RULES: &str = r#"
policy version=2
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file" input_responses="allow"
    tool "write_file"
    tool "fail_write"
    tool "fetch_url"
}
"#;
/// An `input_required` interim result forwards only when every
/// `inputRequests` entry clears the gate: here the sole
/// `elicitation/create` entry has an explicit allow rule and the original
/// request declared the `elicitation` client capability. The MRTR retry
/// under a NEW JSON-RPC id is an independent `tools/call` — it re-runs the
/// tool allowlist, args schema, and `input_responses` gate.
#[tokio::test]
async fn input_required_forwards_with_rule_and_capability() {
    let dir = make_test_dir("mrtr_allow");
    let policy = write_policy(dir.path(), MRTR_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 2, META_2026_ELICIT),
    )
    .await;
    assert_eq!(json_id(&resp).as_deref(), Some("2"), "got: {resp}");
    assert!(
        resp.contains("\"resultType\":\"input_required\""),
        "allowed interim result must reach the client verbatim: {resp}"
    );
    assert!(resp.contains("\"elicitation/create\""), "got: {resp}");

    // MRTR retry: new id, `inputResponses` keyed by the server's request
    // key, `requestState` echoed opaquely.
    let retry = format!(
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"/workspace/notes.txt"}},"requestState":"state-blob","inputResponses":{{"github_login":{{"action":"accept","content":{{"name":"octocat"}}}}}},{meta}}}}}"#,
        meta = META_2026_ELICIT
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &retry).await;
    assert_eq!(json_id(&resp).as_deref(), Some("3"), "got: {resp}");
    assert!(
        has_result(&resp) && resp.contains("\"answered\":[\"github_login\"]"),
        "retry with inputResponses must complete: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.allowed")
            .iter()
            .any(|l| l.contains("kind=additional-request")
                && l.contains("elicitation/create")
                && l.contains("request_key=github_login")),
        "additional request must be audited as allowed: {audit}"
    );
}

/// The capability declared on the original request is part of the gate:
/// an allow rule alone does not pass `elicitation/create` when the client
/// never claimed `elicitation`.
#[tokio::test]
async fn input_required_denied_without_capability() {
    let dir = make_test_dir("mrtr_no_cap");
    let policy = write_policy(dir.path(), MRTR_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 2, common::META_2026),
    )
    .await;
    assert!(has_error(&resp), "missing capability must deny: {resp}");
    assert!(
        error_message(&resp).contains("capability"),
        "expected capability denial: {resp}"
    );
    assert!(
        !resp.contains("inputRequests"),
        "the interim payload must not leak to the client: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("kind=additional-request")
                && l.contains("elicitation/create")
                && l.contains("capability")),
        "capability denial must be audited per entry: {audit}"
    );
}

/// No `mcp` block at all: even with the capability declared, the default
/// profile has no allow rule for `elicitation/create` — fail closed.
#[tokio::test]
async fn input_required_denied_without_rule() {
    let dir = make_test_dir("mrtr_no_rule");
    let policy = write_policy(dir.path(), MRTR_POLICY_NO_RULES);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 2, META_2026_ELICIT),
    )
    .await;
    assert!(has_error(&resp), "missing allow rule must deny: {resp}");
    assert!(
        error_message(&resp).contains("no-rule"),
        "expected no-rule denial: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("kind=additional-request") && l.contains("no-rule")),
        "no-rule denial must be audited: {audit}"
    );
}

/// One inadmissible entry rejects the whole interim result: the allowed
/// `elicitation/create` sibling cannot rescue the unruled
/// `sampling/createMessage` — the interim result is the server's unit of
/// continuation and is never partially rewritten.
#[tokio::test]
async fn input_required_mixed_entries_reject_whole_response() {
    let dir = make_test_dir("mrtr_mixed");
    let policy = write_policy(dir.path(), MRTR_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required_mixed"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 2, META_2026_TWO_CAPS),
    )
    .await;
    assert!(
        has_error(&resp),
        "one denied entry must reject the whole result: {resp}"
    );
    assert!(
        !resp.contains("inputRequests"),
        "no partial interim forward: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    let entries = audit_lines(&audit, "mcp_message.allowed")
        .into_iter()
        .chain(audit_lines(&audit, "mcp_message.denied"))
        .filter(|l| l.contains("kind=additional-request"))
        .collect::<Vec<_>>();
    assert!(
        entries
            .iter()
            .any(|l| l.contains("elicitation/create") && l.contains("verdict=allow")),
        "the eligible entry is audited allowed: {audit}"
    );
    assert!(
        entries
            .iter()
            .any(|l| l.contains("sampling/createMessage") && l.contains("verdict=deny")),
        "the unruled entry is audited denied: {audit}"
    );
}

/// `inputRequests` is a map of request descriptors — an array (or any
/// non-object) cannot even be iterated into lawful answers; the interim
/// result is malformed and fails closed.
#[tokio::test]
async fn input_required_malformed_map_is_denied() {
    let dir = make_test_dir("mrtr_bad");
    let policy = write_policy(dir.path(), MRTR_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required_bad"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 2, META_2026_ELICIT),
    )
    .await;
    assert!(
        has_error(&resp),
        "malformed inputRequests must deny: {resp}"
    );
    assert!(
        error_message(&resp).contains("shape"),
        "expected shape denial: {resp}"
    );

    drop(stdin);
}

/// An `input_required` carrying only `requestState` (no `inputRequests`)
/// is a valid interim form and passes ungated — the opaque blob is never
/// inspected.
#[tokio::test]
async fn input_required_request_state_only_forwards() {
    let dir = make_test_dir("mrtr_state");
    let policy = write_policy(dir.path(), WIRE_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required_state"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let _guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 2, common::META_2026),
    )
    .await;
    assert!(
        resp.contains("\"resultType\":\"input_required\""),
        "requestState-only interim must forward: {resp}"
    );
    assert!(resp.contains("state-blob"), "got: {resp}");

    drop(stdin);
}

/// `input_required` may only answer tools/call, resources/read, or
/// prompts/get — a `prompts/list` interim result is a spec violation and
/// is rejected even though the request itself was allowed.
#[tokio::test]
async fn input_required_on_ineligible_method_is_denied() {
    let dir = make_test_dir("mrtr_ineligible");
    let policy_kdl = r#"
policy version=2
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file"
    mcp {
        allow "prompts/list"
        allow "elicitation/create"
    }
}
"#;
    let policy = write_policy(dir.path(), policy_kdl);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let req = format!(
        r#"{{"jsonrpc":"2.0","id":4,"method":"prompts/list","params":{{{meta}}}}}"#,
        meta = META_2026_ELICIT
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    assert!(
        has_error(&resp),
        "input_required on prompts/list must deny: {resp}"
    );
    assert!(
        error_message(&resp).contains("input-required-target"),
        "expected input-required-target denial: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
}

/// The same gate applies to an explicitly-allowed `resources/read`: the
/// interim result still needs the additional-request rule + capability.
#[tokio::test]
async fn input_required_on_resources_read_needs_entry_rules() {
    let dir = make_test_dir("mrtr_read");
    // resources/read is allowed (with its uri range), elicitation/create
    // is NOT — the interim result must be rejected.
    let policy_kdl = r#"
policy version=2
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file"
    mcp {
        allow "resources/read" { uri "file:///workspace/notes.txt" }
    }
}
"#;
    let policy = write_policy(dir.path(), policy_kdl);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let req = format!(
        r#"{{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{{"uri":"file:///workspace/notes.txt",{meta}}}}}"#,
        meta = META_2026_ELICIT
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    assert!(
        has_error(&resp),
        "unruled elicitation on resources/read must deny: {resp}"
    );
    assert!(
        !resp.contains("inputRequests"),
        "interim payload must not leak: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("kind=additional-request") && l.contains("no-rule")),
        "the unruled additional request must be audited: {audit}"
    );
}

/// Dry-run still forwards a denied `tools/call` request for
/// observation — but its `input_required` interim response is a denied
/// server-to-client frame, judged on the original DENIED status and
/// refused back with an error rather than observed-forwarded.
#[tokio::test]
async fn dry_run_denied_call_input_required_is_not_an_allow() {
    let dir = make_test_dir("mrtr_dryrun");
    let policy_kdl = r#"
policy version=2
logging level="info" fail_closed=#false
server "wire" {
    tool "read_file" input_responses="allow"
    tool "exec_shell" deny=#true
    mcp {
        allow "elicitation/create"
    }
}
"#;
    let policy = write_policy(dir.path(), policy_kdl);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        true,
        common::scripted_stdio_argv_v26("input_required"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let req = format!(
        r#"{{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{{"name":"exec_shell","arguments":{{"cmd":"id"}},{meta}}}}}"#,
        meta = META_2026_ELICIT
    );
    let resp = send_and_recv(&mut stdin, &mut reader, &req).await;
    // The denied interim result is refused back with an error — dry-run
    // no longer forwards denied server-to-client traffic.
    assert!(
        has_error(&resp),
        "the denied interim result must fail closed: {resp}"
    );
    assert!(
        resp.contains("input-required-target"),
        "the rejection reason must reach the client: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    // The audit record must not read as an allow or an observed forward:
    // the additional request is denied (input-required-target — the
    // origin request was never allowed) and stays unforwarded.
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("kind=additional-request")
                && l.contains("input-required-target")
                && l.contains("forwarded=false")),
        "a denied origin's request must audit deny+not forwarded: {audit}"
    );
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("kind=response") && l.contains("forwarded=false")),
        "the denied interim response must not be forwarded: {audit}"
    );
}

/// The interim `result.requestState` obeys the same 64 KiB cap — the
/// client echoes the blob back verbatim in the retry's
/// `params.requestState`, so an oversized one is rejected before any
/// `inputRequests` entry is judged.
#[tokio::test]
async fn input_required_oversized_request_state_is_denied() {
    let dir = make_test_dir("mrtr_bigstate");
    let policy = write_policy(dir.path(), MRTR_POLICY);
    let audit_log = common::next_audit_log_path();
    let mut child = spawn_guard(
        &policy,
        false,
        common::scripted_stdio_argv_v26("input_required_bigstate"),
        &audit_log,
    );
    let mut stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");
    let mut guard = ChildGuard(child);
    let mut reader = BufReader::new(stdout).lines();

    let resp = send_and_recv(
        &mut stdin,
        &mut reader,
        &call_2026("read_file", 2, META_2026_ELICIT),
    )
    .await;
    assert!(has_error(&resp), "oversized requestState must deny: {resp}");
    assert!(
        !resp.contains("inputRequests"),
        "interim payload must not leak: {resp}"
    );

    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), guard.0.wait()).await;
    let audit = read_audit(&audit_log);
    assert!(
        audit_lines(&audit, "mcp_message.denied")
            .iter()
            .any(|l| l.contains("kind=response") && l.contains("shape")),
        "oversized requestState must be audited denied: {audit}"
    );
}
