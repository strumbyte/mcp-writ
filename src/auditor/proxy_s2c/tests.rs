//! End-to-end `s2c_response` coverage: bare `S2cKind` comparisons prove
//! nothing about the response path, so fixtures go through the real
//! handler — tracked request, policy decision, additional-request
//! audits, and the forward disposition itself.

use super::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use crate::auditor::proxy_rpc::{self, ExtractedRequest, TrackedRequest};
use crate::auditor::proxy_state::{CallTally, PendingToolsList, VerifiedToolSet};
use crate::policy::Policy;
use crate::policy::mcp::{McpRule, RuleEffect, ServerMcpRules};
use crate::protocol::fields::{RequestMeta, SchemaField};
use tokio::sync::{Mutex, watch};

/// A `ProxyShared` matching the `forward::tests` wiring. `client_out`
/// is a duplex the test drains — what the client actually receives is
/// asserted on the emitted bytes, not inferred from bookkeeping.
fn shared_for_test() -> (
    ProxyShared<tokio::io::DuplexStream>,
    watch::Receiver<bool>,
    tokio::io::DuplexStream,
) {
    let (abort_tx, abort_rx) = watch::channel(false);
    // The read halves must outlive the test — a dropped reader makes
    // the matching writer fail with BrokenPipe.
    let (_child_read, child_write) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::duplex(64 * 1024);
    (
        ProxyShared {
            policy: Policy::default(),
            dry_run: false,
            fail_on: crate::verifier::fail_on::FailOn::None,
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
            audit: Arc::new(crate::audit_log::AuditLogger::to_tracing()),
            tally: std::sync::Arc::new(std::sync::Mutex::new(CallTally::default())),
            session: None,
            wire: Arc::new(Mutex::new(proxy_rpc::WireState::new())),
            pending_tools_list: Arc::new(Mutex::new(PendingToolsList::new())),
            client_out: Arc::new(Mutex::new(
                Box::new(client_write) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>
            )),
            child_stdin: Arc::new(Mutex::new(Some(child_write))),
            original_tools_list: Arc::new(Mutex::new(
                std::collections::HashMap::<RpcId, String>::new(),
            )),
            list_busy: Arc::new(AtomicBool::new(false)),
            list_kick: Arc::new(tokio::sync::Notify::new()),
            cancelled_list_id: Arc::new(Mutex::new(None)),
            held_client_list: Arc::new(Mutex::new(None)),
            internal_list_failure: Arc::new(tokio::sync::Mutex::new(None)),
            list_epoch: Arc::new(tokio::sync::Mutex::new(())),
            list_generation: Arc::new(AtomicU64::new(0)),
            verified_tools: Arc::new(std::sync::Mutex::new(VerifiedToolSet {
                generation: 0,
                names: std::collections::HashSet::new(),
            })),
            last_list_template: Arc::new(Mutex::new(String::new())),
            next_internal_id: Arc::new(AtomicU64::new(910_001)),
            init_order_warned: Arc::new(AtomicBool::new(false)),
            abort_tx,
        },
        abort_rx,
        client_read,
    )
}

/// The `input_required` fixture through the real response path: a
/// tracked, allowed `tools/call` whose `_meta` declared the
/// `elicitation` capability gets its interim result decided entry by
/// entry — and the response forwards as the fixture's own result
/// under the original id, not as a policy error.
#[tokio::test]
async fn input_required_fixture_forwards_its_result_to_the_client() {
    let (mut shared, _rx, mut client_read) = shared_for_test();
    shared.policy.mcp_rules.push(ServerMcpRules::new(
        None,
        vec![McpRule {
            effect: RuleEffect::Allow,
            method: "elicitation/create".to_string(),
            versions: Vec::new(),
            direction: None,
            uris: Vec::new(),
            filters: Vec::new(),
        }],
    ));

    let path = format!(
        "{}/tests/fixtures/mrtr/input_required_result.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let line = std::fs::read_to_string(&path).expect("fixture");
    let line = line.trim_end();

    // The tools/call the interim result answers: allowed, tracked, and
    // carrying the client's declared `elicitation` capability in its
    // `_meta` — the facts `decide_additional` judges entries against.
    let id = RpcId::from_u64(2);
    let ext = ExtractedRequest {
        meta: Some(RequestMeta {
            malformed: false,
            protocol_version: None,
            client_capabilities_shape: SchemaField::Valid,
            client_capabilities: vec!["elicitation".to_string()],
            log_level: None,
            subscription_id: None,
        }),
        ..ExtractedRequest::default()
    };
    {
        let mut wire = shared.wire.lock().await;
        wire.register(
            C2S,
            id.clone(),
            TrackedRequest::from_extracted("tools/call", V26, true, false, &ext),
        )
        .expect("register the tracked tools/call");
        wire.mark_dispatched(C2S, &id);
        // Establish the 2026 revision the way a first C2S forward does.
        wire.on_request_forwarded(C2S, &id, "tools/call", V26, &ext);
    }

    // The response forward and the client drain run under one shared
    // deadline, and `shared` dies with the handler: dropping the last
    // `client_out` writer closes the pipe, so `read_to_end` observes
    // EOF after exactly the emitted frames. A duplicated forward then
    // fails the exact-bytes assertion instead of passing on a prefix.
    let handler = async move {
        let parsed = nojson::RawJson::parse(line);
        let value = parsed.as_ref().expect("fixture parses").value();
        let mut st = S2cListState::new();
        response::s2c_response(&shared, &mut st, value, line, &parsed, &id, "2")
            .await
            .expect("an allowed interim result must forward, not fail");

        // The forward path consumed the tracked request — a policy
        // error would have left it registered for the response's own
        // denial.
        assert!(
            shared.wire.lock().await.get(C2S, &id).is_none(),
            "the forwarded response must complete its tracked request"
        );
    };
    let reader = async move {
        let mut emitted = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client_read, &mut emitted)
            .await
            .expect("the client read must complete");
        emitted
    };
    let ((), emitted) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(handler, reader)
    })
    .await
    .expect("the forward and the client drain must complete within the bound");

    // What the client actually received: exactly the fixture plus the
    // framing newline — the proxy's emitted bytes, not fixture data.
    let expected = format!("{line}\n");
    assert_eq!(
        emitted,
        expected.as_bytes(),
        "the client must receive exactly one forwarded frame"
    );
    let emitted_json =
        nojson::RawJson::parse(std::str::from_utf8(&emitted[..emitted.len() - 1]).unwrap())
            .expect("the emitted frame parses");
    let emitted = emitted_json.value();
    assert_eq!(
        emitted
            .to_member("id")
            .unwrap()
            .required()
            .unwrap()
            .as_raw_str(),
        "2",
        "the result must arrive under the original request id"
    );
    assert!(
        emitted
            .to_member("result")
            .unwrap()
            .required()
            .unwrap()
            .to_member("resultType")
            .unwrap()
            .optional()
            .is_some_and(|v| v.as_string_str().ok() == Some("input_required")),
        "the client must receive the input_required result"
    );
    assert!(
        emitted.to_member("error").unwrap().optional().is_none(),
        "the forwarded frame must not be a policy error"
    );
}

/// Trajectory wiring for the response-path tests: a session for a
/// cancelled Network call and one rule denying Network → Execute, so
/// `check_trajectory` reports whether the cancelled call's candidate
/// still stands after each response.
fn trajectory_shared() -> (
    ProxyShared<tokio::io::DuplexStream>,
    tokio::io::DuplexStream,
    Arc<Mutex<crate::auditor::session::SessionState>>,
    RpcId,
) {
    let (mut shared, _rx, client_read) = shared_for_test();
    shared.policy.mcp_rules.push(ServerMcpRules::new(
        None,
        vec![McpRule {
            effect: RuleEffect::Allow,
            method: "elicitation/create".to_string(),
            versions: Vec::new(),
            direction: None,
            uris: Vec::new(),
            filters: Vec::new(),
        }],
    ));
    shared.policy.trajectory = true;
    shared.policy.trajectory_rules = vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::Network,
        deny_next: crate::policy::SideEffect::Execute,
    }];
    let session = Arc::new(Mutex::new(crate::auditor::session::SessionState::new()));
    shared.session = Some(session.clone());
    (shared, client_read, session, RpcId::from_u64(2))
}

/// The tracked `tools/call` the fixture's interim result answers —
/// identical to [`input_required_fixture_forwards_its_result_to_the_client`].
async fn register_fixture_call(shared: &ProxyShared<tokio::io::DuplexStream>, id: &RpcId) {
    let ext = ExtractedRequest {
        meta: Some(RequestMeta {
            malformed: false,
            protocol_version: None,
            client_capabilities_shape: SchemaField::Valid,
            client_capabilities: vec!["elicitation".to_string()],
            log_level: None,
            subscription_id: None,
        }),
        ..ExtractedRequest::default()
    };
    let mut wire = shared.wire.lock().await;
    wire.register(
        C2S,
        id.clone(),
        TrackedRequest::from_extracted("tools/call", V26, true, false, &ext),
    )
    .expect("register the tracked tools/call");
    wire.on_request_forwarded(C2S, id, "tools/call", V26, &ext);
    wire.mark_dispatched(C2S, id);
}

/// A forwarded `notifications/cancelled` turns the pending Network call
/// into an unverified deny candidate: it may have run server-side, so a
/// follow-up Execute stays denied until the call's own verdict arrives.
async fn release_network_call_unverified(
    session: &Mutex<crate::auditor::session::SessionState>,
    id: &RpcId,
) {
    let mut state = session.lock().await;
    state
        .record_pending_tool_call(
            id.clone(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(id);
}

/// `check_trajectory` for the follow-up Execute call against the shared
/// rule set — `true` while the cancelled Network call still denies it.
async fn execute_denied(session: &Mutex<crate::auditor::session::SessionState>) -> bool {
    let rules = vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::Network,
        deny_next: crate::policy::SideEffect::Execute,
    }];
    session
        .lock()
        .await
        .check_trajectory(
            &rules,
            "exec_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .is_err()
}

/// Run one server→client frame through `s2c_response` while draining
/// the client pipe under a shared deadline. Returns the emitted bytes —
/// empty when the handler dropped the frame without answering.
async fn run_response(
    shared: ProxyShared<tokio::io::DuplexStream>,
    mut client_read: tokio::io::DuplexStream,
    id: RpcId,
    raw_id: &'static str,
    line: &str,
) -> Vec<u8> {
    // `shared` moves into the handler so its `client_out` writer drops
    // with it — `read_to_end` observes EOF after the emitted frames.
    let handler = async move {
        let parsed = nojson::RawJson::parse(line);
        let value = parsed.as_ref().expect("frame parses").value();
        let mut st = S2cListState::new();
        response::s2c_response(&shared, &mut st, value, line, &parsed, &id, raw_id)
            .await
            .expect("the response path must not abort the session");
    };
    let reader = async move {
        let mut emitted = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut client_read, &mut emitted)
            .await
            .expect("the client read must complete");
        emitted
    };
    let ((), emitted) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(handler, reader)
    })
    .await
    .expect("the response path and the client drain must complete within the bound");
    emitted
}

/// A correlated tool error is an ambiguous verdict — the call may still
/// have run — so the cancelled call's candidate keeps denying Execute.
#[tokio::test]
async fn tool_error_keeps_cancelled_calls_deny_candidate() {
    let (shared, client_read, session, id) = trajectory_shared();
    register_fixture_call(&shared, &id).await;
    release_network_call_unverified(&session, &id).await;
    assert!(
        execute_denied(&session).await,
        "the cancelled call must deny Execute while its verdict is open"
    );
    let frame = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"boom"}}"#;
    let emitted = run_response(shared, client_read, id, "2", frame).await;
    assert_eq!(
        emitted,
        format!("{frame}\n").into_bytes(),
        "the server's own error frame must reach the client verbatim"
    );
    assert!(
        execute_denied(&session).await,
        "an ambiguous verdict must keep the deny candidate"
    );
}

/// The same ambiguous-verdict coverage, but with the call still
/// *pending* when the error arrives — no forwarded `cancelled`
/// pre-created its tombstone. The error itself is not a definitive
/// verdict (the call may have run), so the response's own session
/// update releases it into the same unverified candidate set: the
/// client receives the error unchanged, the new candidate denies
/// Execute, and the verified marker stays unset.
#[tokio::test]
async fn tool_error_releases_pending_call_as_deny_candidate() {
    let (shared, client_read, session, id) = trajectory_shared();
    register_fixture_call(&shared, &id).await;
    {
        let mut state = session.lock().await;
        state
            .record_pending_tool_call(
                id.clone(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
            )
            .unwrap();
    }
    let frame = r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32000,"message":"boom"}}"#;
    let emitted = run_response(shared, client_read, id, "2", frame).await;
    assert_eq!(
        emitted,
        format!("{frame}\n").into_bytes(),
        "the server's own error frame must reach the client verbatim"
    );
    assert!(
        execute_denied(&session).await,
        "an ambiguous verdict must keep the deny candidate"
    );
    assert!(
        session.lock().await.last_successful_side_effect().is_none(),
        "an ambiguous verdict must not move the verified marker"
    );
}

/// The same cancelled call keeps its deny candidate through the
/// fixture's `input_required` interim result: the suspend proves only
/// that this id will not complete — a tool may have done work before
/// asking for input, and nothing enforces pre-suspend purity — so the
/// candidate keeps denying Execute like any ambiguous verdict.
#[tokio::test]
async fn input_required_result_keeps_cancelled_calls_deny_candidate() {
    let (shared, client_read, session, id) = trajectory_shared();
    register_fixture_call(&shared, &id).await;
    release_network_call_unverified(&session, &id).await;
    assert!(execute_denied(&session).await);
    let path = format!(
        "{}/tests/fixtures/mrtr/input_required_result.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let line = std::fs::read_to_string(&path).expect("fixture");
    let line = line.trim_end();
    let emitted = run_response(shared, client_read, id, "2", line).await;
    assert_eq!(
        emitted,
        format!("{line}\n").into_bytes(),
        "a valid interim result still forwards to the client unchanged"
    );
    assert!(
        execute_denied(&session).await,
        "an ambiguous suspend must keep the deny candidate"
    );
}

/// A response that lands while its own request is still dispatching —
/// registered but not yet `mark_dispatched`-ed — waits on the dispatch
/// outcome rather than being rejected as uncorrelated. Once the write
/// lands and the mark runs, the held response correlates and forwards.
#[tokio::test]
async fn response_arriving_mid_dispatch_waits_for_the_mark() {
    let (shared, client_read, _session, id) = trajectory_shared();
    {
        let ext = ExtractedRequest::default();
        let mut tracked = TrackedRequest::from_extracted("tools/call", V26, true, false, &ext);
        tracked.dispatched = false;
        shared
            .wire
            .lock()
            .await
            .register(C2S, id.clone(), tracked)
            .expect("register the in-flight dispatch");
    }
    // The C2S side's write is still in flight; the mark lands only
    // after the response handler has provably parked on the entry.
    // A parked waiter holds a `dispatch_changed` clone across its
    // `notified().await`, so a third strong reference proves it is
    // registered — `enable()` runs under the wire lock before the
    // handler drops it, so observing the clone while holding that lock
    // means the mark below cannot be missed. Only `wire` crosses into
    // the task — a `ProxyShared` clone would keep `client_out` (and so
    // the client pipe's writer) alive past the handler, and
    // `run_response` drains to EOF.
    let marker_wire = shared.wire.clone();
    let marker_id = id.clone();
    tokio::spawn(async move {
        let notify = marker_wire.lock().await.dispatch_changed();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while Arc::strong_count(&notify) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the response handler must park on the undispatched entry");
        marker_wire.lock().await.mark_dispatched(C2S, &marker_id);
    });
    let frame = r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"complete","content":[{"type":"text","text":"ok"}]}}"#;
    let emitted = run_response(shared, client_read, id, "2", frame).await;
    assert_eq!(
        emitted,
        format!("{frame}\n").into_bytes(),
        "a response that raced its own dispatch must forward once the mark lands"
    );
}

/// Feed one frame through `s2c_response` without draining — for frames
/// the handler drops, where nothing is emitted anyway.
async fn run_dropped_response(
    shared: &ProxyShared<tokio::io::DuplexStream>,
    st: &mut S2cListState,
    id: &RpcId,
    line: &str,
) {
    let parsed = nojson::RawJson::parse(line);
    let value = parsed.as_ref().expect("frame parses").value();
    response::s2c_response(shared, st, value, line, &parsed, id, "2")
        .await
        .expect("a dropped response must not abort the session");
}

/// When the cancelled call's wire entry is already gone — reclaimed
/// under in-flight pressure or consumed by a malformed frame — no
/// `input_required` clears its tombstone: the suspend verdict is
/// ambiguous — work may have preceded it — so a stray interim result,
/// shape-valid or not, must never resolve a deny candidate.
#[tokio::test]
async fn late_input_required_keeps_tombstone_without_a_wire_entry() {
    let (shared, mut client_read, session, id) = trajectory_shared();
    // No wire registration — the cancelled call's entry is gone. Only
    // the session-side tombstone remains, exactly as the forwarded
    // cancel left it.
    release_network_call_unverified(&session, &id).await;
    let mut st = S2cListState::new();
    // A bare `input_required` — no `requestState`, no `inputRequests` —
    // fails the interim-result contract, so the candidate must stand.
    run_dropped_response(
        &shared,
        &mut st,
        &id,
        r#"{"jsonrpc":"2.0","id":2,"result":{"resultType":"input_required"}}"#,
    )
    .await;
    assert!(
        execute_denied(&session).await,
        "an invalid interim result must not clear the candidate"
    );
    // The shape-valid fixture resolves nothing either: a stray frame
    // naming a retired id is never the call's own verdict.
    let path = format!(
        "{}/tests/fixtures/mrtr/input_required_result.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let line = std::fs::read_to_string(&path).expect("fixture");
    let line = line.trim_end();
    run_dropped_response(&shared, &mut st, &id, line).await;
    assert!(
        execute_denied(&session).await,
        "a stray interim result must keep the deny candidate"
    );
    // Uncorrelated responses are dropped, never relayed: both frames
    // left the client pipe empty — a Pending poll is direct proof.
    let mut buf = [0u8; 1];
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        std::future::Future::poll(
            std::pin::pin!(tokio::io::AsyncReadExt::read(&mut client_read, &mut buf)),
            &mut cx
        )
        .is_pending(),
        "dropped responses must emit nothing to the client"
    );
}

/// An oversized response whose real envelope `id` fell into the dropped
/// middle retains only nested response data at the tail — for an
/// unterminated frame that tail `}` can anchor the backward scan and
/// promote a nested `result.id` to apparent envelope depth. The nested
/// id must never retire a live request it was not addressed to: with no
/// proven candidate the frame is unattributable, so the session fails
/// closed while the registration itself survives unretired.
#[tokio::test]
async fn unterminated_oversize_nested_tail_id_cannot_retire_a_live_request() {
    let (shared, _abort_rx, _client_read) = shared_for_test();
    let mut st = S2cListState::new();
    let id = RpcId::from_u64(99);
    {
        let mut wire = shared.wire.lock().await;
        let ext = ExtractedRequest::default();
        wire.register(
            C2S,
            id.clone(),
            TrackedRequest::from_extracted("tools/call", V26, true, false, &ext),
        )
        .expect("register the tracked tools/call");
        wire.mark_dispatched(C2S, &id);
    }
    let frame = crate::framing::OversizeFrame {
        // `result` at envelope depth proves response shape; the nested
        // `result.id` sits in the tail behind a dropped middle, and the
        // unterminated cut leaves the tail `}` ambiguous as an anchor.
        head: br##"{"jsonrpc":"2.0","result":{"content":["##.to_vec(),
        tail: br##"xxx","id":99}"##.to_vec(),
        head_next: Some(b'x'),
        bytes: 2 * 1024 * 1024,
        terminated: false,
    };
    let result = oversize::s2c_oversize(&shared, &mut st, &frame).await;
    assert!(
        matches!(result, Err(AuditorError::VerificationFailed(_))),
        "an unattributable oversized response must fail closed, not pass silently: {result:?}"
    );
    assert!(
        shared.wire.lock().await.get(C2S, &id).is_some(),
        "the nested result.id must not retire the live request"
    );
}

/// A *terminated* frame offers no more guarantee: `terminated` only
/// means the frame ended on a newline, not that the document's root
/// closed — `{"result":{…,"a":{"id":99}` ends on a nested `}` the
/// backward scan would anchor on, promoting the nested `"id"` to
/// apparent envelope depth. The structural check rescues it: the
/// depth-1 `{` inside a disjoint tail is necessarily a nested
/// container's open, so every hit under that anchor is dropped and the
/// frame is unattributable — fail closed, live request unretired.
#[tokio::test]
async fn terminated_oversize_nested_close_cannot_retire_a_live_request() {
    let (shared, _abort_rx, _client_read) = shared_for_test();
    let mut st = S2cListState::new();
    let id = RpcId::from_u64(99);
    {
        let mut wire = shared.wire.lock().await;
        let ext = ExtractedRequest::default();
        wire.register(
            C2S,
            id.clone(),
            TrackedRequest::from_extracted("tools/call", V26, true, false, &ext),
        )
        .expect("register the tracked tools/call");
        wire.mark_dispatched(C2S, &id);
    }
    let frame = crate::framing::OversizeFrame {
        // Root and `result` both stay unclosed — the tail's last `}`
        // closed a *nested* object, and that object's `{` is inside the
        // window where the structural check can see it.
        head: br##"{"jsonrpc":"2.0","result":{"pad":"##.to_vec(),
        tail: br##"x","a":{"id":99}"##.to_vec(),
        head_next: Some(b'x'),
        bytes: 2 * 1024 * 1024,
        terminated: true,
    };
    let result = oversize::s2c_oversize(&shared, &mut st, &frame).await;
    assert!(
        matches!(result, Err(AuditorError::VerificationFailed(_))),
        "an unattributable oversized response must fail closed, not pass silently: {result:?}"
    );
    assert!(
        shared.wire.lock().await.get(C2S, &id).is_some(),
        "the nested trailing id must not retire the live request"
    );
}

/// A reassembled two-root frame: the response shape comes from the
/// first root, so only that root may name the request it answers. A
/// second root's `id` — provable as that root's own envelope member —
/// was never named by the response and must not retire a live
/// request. The frame is unattributable: fail closed, registration
/// preserved.
#[tokio::test]
async fn reassembled_second_root_id_cannot_retire_a_live_request() {
    let (shared, _abort_rx, _client_read) = shared_for_test();
    let mut st = S2cListState::new();
    let id = RpcId::from_u64(99);
    {
        let mut wire = shared.wire.lock().await;
        let ext = ExtractedRequest::default();
        wire.register(
            C2S,
            id.clone(),
            TrackedRequest::from_extracted("tools/call", V26, true, false, &ext),
        )
        .expect("register the tracked tools/call");
        wire.mark_dispatched(C2S, &id);
    }
    // The windows cover the whole frame: root-1 is a complete
    // response-shaped document carrying no `id`, root-2 a separate
    // response-shaped document carrying the live request's id. A
    // `method` in root-2 would route the frame to the request arm
    // instead of exercising the response attribution under test.
    let frame = crate::framing::OversizeFrame {
        head: br##"{"jsonrpc":"2.0","result":{"x":1}}{"##.to_vec(),
        tail: br##""id":99,"result":{}}"##.to_vec(),
        head_next: None,
        bytes: 55,
        terminated: true,
    };
    let result = oversize::s2c_oversize(&shared, &mut st, &frame).await;
    assert!(
        matches!(result, Err(AuditorError::VerificationFailed(_))),
        "an unattributable oversized response must fail closed: {result:?}"
    );
    assert!(
        shared.wire.lock().await.get(C2S, &id).is_some(),
        "a second root's id must not retire the live request"
    );
}
