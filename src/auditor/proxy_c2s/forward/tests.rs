use super::register::*;
use super::session_gates::*;
use super::*;
use crate::auditor::proxy_state::PendingToolsList;
use crate::auditor::session::SessionState;
use crate::policy::Policy;
use crate::policy::mcp::AllowReason;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::{Mutex, watch};

fn shared_for_test() -> (
    ProxyShared<tokio::io::DuplexStream>,
    watch::Receiver<bool>,
    tokio::io::DuplexStream,
) {
    // The read half must outlive the test — a dropped reader makes
    // `write_child_frame` fail with BrokenPipe.
    let (child_read, child_write) = tokio::io::duplex(64 * 1024);
    let (shared, abort_rx) = shared_for_test_with_writer(child_write);
    (shared, abort_rx, child_read)
}

/// `shared_for_test` over an arbitrary child-stdin writer, so a test
/// can instrument the pipe. The caller keeps the read half.
fn shared_for_test_with_writer<W>(child_write: W) -> (ProxyShared<W>, watch::Receiver<bool>) {
    let (abort_tx, abort_rx) = watch::channel(false);
    (
        ProxyShared {
            policy: Policy::default(),
            dry_run: false,
            fail_on: crate::verifier::fail_on::FailOn::None,
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
            audit: Arc::new(crate::audit_log::AuditLogger::to_tracing()),
            tally: std::sync::Arc::new(std::sync::Mutex::new(
                crate::auditor::proxy_state::CallTally::default(),
            )),
            session: None,
            wire: Arc::new(Mutex::new(proxy_rpc::WireState::new())),
            pending_tools_list: Arc::new(Mutex::new(PendingToolsList::new())),
            client_out: Arc::new(Mutex::new(
                Box::new(tokio::io::stdout()) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>
            )),
            child_stdin: Arc::new(Mutex::new(Some(child_write))),
            original_tools_list: Arc::new(Mutex::new(std::collections::HashMap::new())),
            list_busy: Arc::new(AtomicBool::new(false)),
            list_kick: Arc::new(tokio::sync::Notify::new()),
            cancelled_list_id: Arc::new(Mutex::new(None)),
            held_client_list: Arc::new(Mutex::new(None)),
            internal_list_failure: Arc::new(tokio::sync::Mutex::new(None)),
            list_epoch: Arc::new(tokio::sync::Mutex::new(())),
            list_generation: Arc::new(AtomicU64::new(0)),
            verified_tools: Arc::new(std::sync::Mutex::new(
                crate::auditor::proxy_state::VerifiedToolSet {
                    generation: 0,
                    names: std::collections::HashSet::new(),
                },
            )),
            last_list_template: Arc::new(Mutex::new(String::new())),
            next_internal_id: Arc::new(AtomicU64::new(910_001)),
            init_order_warned: Arc::new(AtomicBool::new(false)),
            abort_tx,
        },
        abort_rx,
    )
}

/// Child-stdin writer that signals the first `poll_write` returning
/// `Poll::Pending` — the moment the pipe is provably full. A test
/// waiting on the notify observes the writer parked mid-frame instead
/// of inferring the stall from a fixed yield count. `Notify` keeps a
/// permit, so the signal is not lost when it fires before the test
/// starts listening.
struct PendingSignalWriter {
    inner: tokio::io::DuplexStream,
    pending: Arc<tokio::sync::Notify>,
    signalled: bool,
}

impl tokio::io::AsyncWrite for PendingSignalWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match std::pin::Pin::new(&mut this.inner).poll_write(cx, buf) {
            std::task::Poll::Pending => {
                if !this.signalled {
                    this.signalled = true;
                    this.pending.notify_one();
                }
                std::task::Poll::Pending
            }
            poll => poll,
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

const CALL_LINE: &str =
    r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"t","arguments":{}}}"#;

/// The verified view the production path hands the forward machinery —
/// tests enter below the structural gate, so they build the same
/// shared-parse view the relay would.
fn verified(line: &str) -> checker::VerifiedFrame<'_> {
    checker::VerifiedFrame::parse_and_verify(line).unwrap()
}

/// RF04 measurement: building the `VerifiedFrame` plus running
/// `forward_allowed` costs exactly one parse and one duplicate-key
/// scan — both inside `parse_and_verify`. Tool extraction,
/// `check_request`, id handling, and the session gates (a session
/// with trajectory enabled is attached here so they actually run)
/// all share the gate's `RawJson` through the view instead of
/// reparsing the frame per consumer.
///
/// Scope: the test enters below the C2S loop at `forward_allowed` —
/// `classify_frame` and the `c2s_*` dispatch are upstream of it, so
/// this does not measure the loop's own frame-boundary work. The
/// per-thread `CountWindow` reads back only this thread's
/// increments: the process-wide counters keep counting whatever
/// parallel tests parse, so an exact global count would race.
#[cfg(feature = "measure")]
#[tokio::test]
async fn allowed_tools_call_runs_one_parse_and_one_dupkey_scan() {
    let (mut shared, _rx, mut child_read) = shared_for_test();
    shared
        .policy
        .tools
        .push(crate::policy::ToolPolicy::named("t", true));
    // Trajectory on + a session so `apply_session_gates` exercises
    // the shared-`RawJson` checks (`check_trajectory_json`,
    // `request_has_host_or_url_json`) rather than early-returning.
    shared.policy.trajectory = true;
    shared.session = Some(Arc::new(Mutex::new(SessionState::new())));
    let window = crate::measure::CountWindow::open();
    let view = verified(CALL_LINE);
    let id = RpcId::from_u64(7);
    forward_allowed(
        &shared,
        &view,
        "tools/call",
        &id,
        "7",
        SupportedProtocolVersion::Mcp2025November25,
        McpVerdict::Allow(AllowReason::RuleAllow),
        ExtractedRequest::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        window.count("json.parse.calls"),
        1,
        "the gate's parse must be the only parse through `forward_allowed`"
    );
    assert_eq!(
        window.count("json.dupkey.scan.calls"),
        1,
        "the gate's duplicate-key walk must be the only scan"
    );
    // The forwarded bytes are the original frame verbatim — a passing
    // `forward_allowed` alone does not prove the child write happened.
    let expected = format!("{CALL_LINE}\n");
    let mut buf = vec![0u8; expected.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_exact(&mut child_read, &mut buf),
    )
    .await
    .expect("the forwarded frame must arrive within the bound")
    .expect("the child read must complete");
    assert_eq!(buf, expected.as_bytes());
}

/// Publish a verified generation the way `verify_and_emit_list` does:
/// the name set and counter move together under the mutex, and the
/// atomic mirror follows.
fn set_verified<W>(shared: &ProxyShared<W>, generation: u64, names: &[&str]) {
    {
        let mut vt = shared.verified_tools.lock().unwrap();
        vt.generation = generation;
        vt.names = names.iter().map(|s| s.to_string()).collect();
    }
    shared.list_generation.store(generation, Ordering::SeqCst);
}

/// F10: a tools/call admitted under verified generation N must
/// unwind and refuse the child write when a revalidation published
/// a newer generation in between.
#[tokio::test]
async fn stale_list_generation_unwinds_registration_before_write() {
    let (shared, _rx, mut child_read) = shared_for_test();
    // Verification of the *next* set published since admission.
    set_verified(&shared, 2, &["t"]);
    let id = RpcId::from_u64(7);
    let ext = ExtractedRequest::default();
    let forwarded = register_and_forward_impl(
        &shared,
        &verified(CALL_LINE),
        "tools/call",
        &id,
        "7",
        SupportedProtocolVersion::Mcp2025November25,
        &ext,
        true,
        Some(McpVerdict::Allow(AllowReason::RuleAllow)),
        Some(1),
    )
    .await
    .unwrap();
    assert!(!forwarded, "stale generation must refuse the forward");
    assert!(
        shared.wire.lock().await.get(C2S, &id).is_none(),
        "the refused registration must be unwound"
    );
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        tokio::io::AsyncReadExt::read(&mut child_read, &mut buf),
    )
    .await;
    assert!(
        read.is_err(),
        "a stale-generation refusal writes no child bytes"
    );
}

/// F10: a list_changed revalidation raises the busy gate before it
/// starts — a call admitted just before the mark unwinds at the
/// pre-write recheck even if the generation has not moved yet.
#[tokio::test]
async fn busy_gate_mid_authorization_unwinds_before_write() {
    let (shared, _rx, mut child_read) = shared_for_test();
    set_verified(&shared, 1, &["t"]);
    shared.list_busy.store(true, Ordering::SeqCst);
    let id = RpcId::from_u64(7);
    let ext = ExtractedRequest::default();
    let forwarded = register_and_forward_impl(
        &shared,
        &verified(CALL_LINE),
        "tools/call",
        &id,
        "7",
        SupportedProtocolVersion::Mcp2025November25,
        &ext,
        true,
        Some(McpVerdict::Allow(AllowReason::RuleAllow)),
        Some(1),
    )
    .await
    .unwrap();
    assert!(!forwarded, "a raised busy gate must refuse the forward");
    assert!(shared.wire.lock().await.get(C2S, &id).is_none());
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        tokio::io::AsyncReadExt::read(&mut child_read, &mut buf),
    )
    .await;
    assert!(read.is_err(), "a busy-gate refusal writes no child bytes");
}

/// F-dispatch-race: the recheck+write critical section is serialized
/// against the gate raise by `list_epoch`. With the dispatch queued
/// on the epoch ahead of a `list_changed` raise, the frame must
/// reach the child *before* the gate flips — the call legitimately
/// predates the revalidation.
#[tokio::test]
async fn dispatch_holding_epoch_writes_before_gate_raise() {
    let pending = Arc::new(tokio::sync::Notify::new());
    // The read half must outlive the test — a dropped reader makes
    // `write_child_frame` fail with BrokenPipe.
    let (mut child_read, child_write) = tokio::io::duplex(64 * 1024);
    let (shared, _rx) = shared_for_test_with_writer(PendingSignalWriter {
        inner: child_write,
        pending: pending.clone(),
        signalled: false,
    });
    set_verified(&shared, 1, &["t"]);

    // A frame larger than the duplex capacity makes the epoch-held
    // child write genuinely pend: it stalls mid-frame until the test
    // drains, so a raise queued behind the dispatch provably cannot
    // complete while that write is paused.
    let big_frame = format!(
        r#"{{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{{"name":"t","arguments":{{"pad":"{}"}}}}}}"#,
        "x".repeat(96 * 1024)
    );

    // Hold the epoch so both contenders queue behind us; tokio's
    // mutex grants waiters FIFO, so request order fixes the winner.
    // Each contender fires a oneshot immediately before its
    // `list_epoch.lock().await` request — the send and the lock's
    // first poll run in one task step, so the receiver resolving
    // proves that contender is already queued on the epoch. (On the
    // dispatch side every await between the send and the epoch lock —
    // the uncontended wire lock, the synchronous-on-`to_tracing`
    // audit record, `ensure_available` — completes without parking.)
    let epoch_guard = shared.list_epoch.lock().await;

    let (dispatch_queued_tx, dispatch_queued_rx) = tokio::sync::oneshot::channel();
    let shared_dispatch = shared.clone();
    let frame_for_dispatch = big_frame.clone();
    let dispatch = tokio::spawn(async move {
        dispatch_queued_tx.send(()).ok();
        let id = RpcId::from_u64(7);
        let ext = ExtractedRequest::default();
        register_and_forward_impl(
            &shared_dispatch,
            &verified(&frame_for_dispatch),
            "tools/call",
            &id,
            "7",
            SupportedProtocolVersion::Mcp2025November25,
            &ext,
            true,
            Some(McpVerdict::Allow(AllowReason::RuleAllow)),
            Some(1),
        )
        .await
    });
    dispatch_queued_rx.await.unwrap();

    drop(epoch_guard);
    // The dispatch runs until its write stalls on the full pipe: the
    // writer's first `Pending` fires `pending`, so this wait proves the
    // frame is parked mid-write holding the epoch — not merely that a
    // fixed number of scheduler turns elapsed.
    tokio::time::timeout(std::time::Duration::from_secs(2), pending.notified())
        .await
        .expect("the epoch-held child write must stall on the full pipe");
    // The write is paused mid-frame holding the epoch: with the test's
    // guard dropped, the stalled dispatch is the only possible owner.
    assert!(
        shared.list_epoch.try_lock().is_err(),
        "the epoch must be held by the stalled dispatch"
    );
    assert!(
        !dispatch.is_finished(),
        "the dispatch must be parked on the stalled epoch write"
    );
    assert!(!shared.list_busy.load(Ordering::SeqCst));

    // Only now queue the raise — it must wait behind the epoch the
    // stalled write still holds.
    let (raise_queued_tx, raise_queued_rx) = tokio::sync::oneshot::channel();
    let shared_raise = shared.clone();
    let raise = tokio::spawn(async move {
        raise_queued_tx.send(()).ok();
        shared_raise.raise_list_gate().await
    });
    raise_queued_rx.await.unwrap();

    assert!(
        !dispatch.is_finished(),
        "the dispatch must still be parked on the stalled epoch write"
    );
    assert!(
        !raise.is_finished(),
        "the raise must still be queued behind the paused epoch write"
    );
    assert!(!shared.list_busy.load(Ordering::SeqCst));

    // Resume the writer by draining: the full frame (plus newline)
    // must cross before the gate can rise.
    let expected = format!("{big_frame}\n");
    let mut buf = vec![0u8; expected.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_exact(&mut child_read, &mut buf),
    )
    .await
    .expect("the forwarded frame must arrive within the bound")
    .expect("the child read must complete");
    assert_eq!(buf, expected.as_bytes());

    let forwarded = dispatch.await.unwrap().unwrap();
    let was_busy = raise.await.unwrap();

    assert!(
        forwarded,
        "the dispatch held the epoch first — its write predates the raise"
    );
    assert!(!was_busy, "the raise must observe the gate still down");
    assert!(
        shared.list_busy.load(Ordering::SeqCst),
        "the raise must own the gate afterwards"
    );
}

/// F-dispatch-race, opposite winner: the `list_changed` raise queued
/// on the epoch first — the stale-generation call that arrives after
/// observes the raised gate and unwinds instead of writing.
#[tokio::test]
async fn dispatch_behind_gate_raise_unwinds_without_write() {
    let (shared, _rx, mut child_read) = shared_for_test();
    set_verified(&shared, 1, &["t"]);

    // Same ordering mechanism as `dispatch_holding_epoch_*` — the
    // raise's oneshot resolves only once its `list_epoch.lock().await`
    // request is queued first.
    let epoch_guard = shared.list_epoch.lock().await;

    let (raise_queued_tx, raise_queued_rx) = tokio::sync::oneshot::channel();
    let shared_raise = shared.clone();
    let raise = tokio::spawn(async move {
        raise_queued_tx.send(()).ok();
        shared_raise.raise_list_gate().await
    });
    raise_queued_rx.await.unwrap();

    let (dispatch_queued_tx, dispatch_queued_rx) = tokio::sync::oneshot::channel();
    let shared_dispatch = shared.clone();
    let dispatch = tokio::spawn(async move {
        dispatch_queued_tx.send(()).ok();
        let id = RpcId::from_u64(7);
        let ext = ExtractedRequest::default();
        register_and_forward_impl(
            &shared_dispatch,
            &verified(CALL_LINE),
            "tools/call",
            &id,
            "7",
            SupportedProtocolVersion::Mcp2025November25,
            &ext,
            true,
            Some(McpVerdict::Allow(AllowReason::RuleAllow)),
            Some(1),
        )
        .await
    });
    dispatch_queued_rx.await.unwrap();

    assert!(!shared.list_busy.load(Ordering::SeqCst));
    assert!(
        !dispatch.is_finished(),
        "the dispatch must still be queued on the epoch"
    );
    assert!(
        !raise.is_finished(),
        "the raise must still be queued on the epoch"
    );

    drop(epoch_guard);
    let was_busy = raise.await.unwrap();
    let forwarded = dispatch.await.unwrap().unwrap();

    assert!(!was_busy);
    assert!(
        !forwarded,
        "a call queued behind the raise must see the gate and refuse"
    );
    assert!(shared.list_busy.load(Ordering::SeqCst));
    let id = RpcId::from_u64(7);
    assert!(
        shared.wire.lock().await.get(C2S, &id).is_none(),
        "the refused registration must be unwound"
    );
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        tokio::io::AsyncReadExt::read(&mut child_read, &mut buf),
    )
    .await;
    assert!(
        read.is_err(),
        "no frame may reach the child after the gate rose"
    );
}

/// F10: with the admission generation still current and no
/// revalidation raised, the call forwards and stays registered.
#[tokio::test]
async fn matching_list_generation_forwards() {
    let (shared, _rx, _child_read) = shared_for_test();
    set_verified(&shared, 1, &["t"]);
    let id = RpcId::from_u64(7);
    let ext = ExtractedRequest::default();
    let forwarded = register_and_forward_impl(
        &shared,
        &verified(CALL_LINE),
        "tools/call",
        &id,
        "7",
        SupportedProtocolVersion::Mcp2025November25,
        &ext,
        true,
        Some(McpVerdict::Allow(AllowReason::RuleAllow)),
        Some(1),
    )
    .await
    .unwrap();
    assert!(forwarded);
    let answered = shared.wire.lock().await.answered(super::super::S2C, &id);
    assert!(
        answered.is_some_and(|a| a.method == "tools/call"),
        "the forwarded request must be dispatched and correlate a response"
    );
}

/// F6: a statically allowed tool the verified listing did not
/// advertise is refused at admission — the generation number alone
/// never carried the tool-name set, so an omitted `t` must not keep
/// its channel.
#[tokio::test]
async fn unadvertised_tool_is_denied_at_admission() {
    let (mut shared, _rx, mut child_read) = shared_for_test();
    shared.fail_on = crate::verifier::fail_on::FailOn::Critical;
    shared
        .policy
        .tools
        .push(crate::policy::ToolPolicy::named("t", true));
    set_verified(&shared, 1, &["other_tool"]);
    let id = RpcId::from_u64(7);
    forward_allowed(
        &shared,
        &verified(CALL_LINE),
        "tools/call",
        &id,
        "7",
        SupportedProtocolVersion::Mcp2025November25,
        McpVerdict::Allow(AllowReason::RuleAllow),
        ExtractedRequest::default(),
    )
    .await
    .unwrap();
    assert!(shared.wire.lock().await.get(C2S, &id).is_none());
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        tokio::io::AsyncReadExt::read(&mut child_read, &mut buf),
    )
    .await;
    assert!(read.is_err(), "the denied call must not reach the child");
}

/// F6: a tool the verified listing advertised — and the policy
/// allows — forwards under its generation.
#[tokio::test]
async fn advertised_tool_forwards_under_its_generation() {
    let (mut shared, _rx, mut child_read) = shared_for_test();
    shared.fail_on = crate::verifier::fail_on::FailOn::Critical;
    shared
        .policy
        .tools
        .push(crate::policy::ToolPolicy::named("t", true));
    set_verified(&shared, 1, &["t"]);
    let id = RpcId::from_u64(7);
    forward_allowed(
        &shared,
        &verified(CALL_LINE),
        "tools/call",
        &id,
        "7",
        SupportedProtocolVersion::Mcp2025November25,
        McpVerdict::Allow(AllowReason::RuleAllow),
        ExtractedRequest::default(),
    )
    .await
    .unwrap();
    assert!(shared.wire.lock().await.get(C2S, &id).is_some());
    let expected = format!("{CALL_LINE}\n");
    let mut buf = vec![0u8; expected.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_exact(&mut child_read, &mut buf),
    )
    .await
    .expect("the forwarded frame must arrive within the bound")
    .expect("the child read must complete");
    assert_eq!(buf, expected.as_bytes());
}

/// F6: an admission captured before a revalidation publishes is
/// denied at the pre-write recheck even when the *new* set also
/// names the tool — the generation is bound to the set, not to the
/// name alone.
#[tokio::test]
async fn republished_set_still_stales_an_earlier_admission() {
    let (shared, _rx, _child_read) = shared_for_test();
    set_verified(&shared, 2, &["t"]);
    // Rewind only the atomic mirror: if the recheck read the mirror
    // instead of authoritative `verified_tools.generation`, it would
    // see generation 1 and let the stale admission through.
    shared.list_generation.store(1, Ordering::SeqCst);
    let id = RpcId::from_u64(7);
    let ext = ExtractedRequest::default();
    let forwarded = register_and_forward_impl(
        &shared,
        &verified(CALL_LINE),
        "tools/call",
        &id,
        "7",
        SupportedProtocolVersion::Mcp2025November25,
        &ext,
        true,
        Some(McpVerdict::Allow(AllowReason::RuleAllow)),
        Some(1),
    )
    .await
    .unwrap();
    assert!(!forwarded);
    assert!(shared.wire.lock().await.get(C2S, &id).is_none());
}

/// A client `tools/list` that loses the busy-gate CAS to an internal
/// listing — the post-`initialize` probe or a `list_changed`
/// revalidation — is held for the verified emit to answer instead
/// of being refused: `pending_tools_list` stays empty, so the
/// internal owner drains it when the listing settles.
#[tokio::test]
async fn arm_tools_list_holds_a_request_racing_internal_listing() {
    let (shared, _rx, _child_read) = shared_for_test();
    shared.list_busy.store(true, Ordering::SeqCst);
    let id = RpcId::from_u64(0);
    let armed = arm_tools_list(
        &shared,
        &verified(r#"{"jsonrpc":"2.0","id":0,"method":"tools/list"}"#),
        &id,
        "0",
        SupportedProtocolVersion::Mcp2025November25,
    )
    .await
    .unwrap();
    assert!(!armed, "a held request is not forwarded to the child");
    assert_eq!(
        shared
            .held_client_list
            .lock()
            .await
            .as_ref()
            .map(|(_, raw)| raw.as_str()),
        Some("0")
    );
    assert!(shared.pending_tools_list.lock().await.is_empty());
}

/// A gate owned by a *client* listing still refuses outright — the
/// hold slot is only for internally-owned gates, and real
/// client-side contention keeps the "already in progress" refusal.
#[tokio::test]
async fn arm_tools_list_refuses_when_a_client_listing_owns_the_gate() {
    let (shared, _rx, _child_read) = shared_for_test();
    // Capture the client stream so the refusal's wire reply is
    // observable — the helper's default `client_out` is stdout.
    let (mut client_read, client_write) = tokio::io::duplex(64 * 1024);
    *shared.client_out.lock().await = Box::new(client_write);
    shared.list_busy.store(true, Ordering::SeqCst);
    shared
        .pending_tools_list
        .lock()
        .await
        .try_insert(RpcId::from_u64(9));
    let id = RpcId::from_u64(0);
    let armed = arm_tools_list(
        &shared,
        &verified(r#"{"jsonrpc":"2.0","id":0,"method":"tools/list"}"#),
        &id,
        "0",
        SupportedProtocolVersion::Mcp2025November25,
    )
    .await
    .unwrap();
    assert!(!armed);
    assert!(shared.held_client_list.lock().await.is_none());
    // The owning listing's pending entry is untouched, and the refused
    // request is answered with exactly one error frame.
    assert!(
        shared
            .pending_tools_list
            .lock()
            .await
            .contains(&RpcId::from_u64(9)),
        "the owning listing's pending id must survive the refusal"
    );
    // `shared` drops here — the client write half closes, so
    // `read_to_end` sees EOF after the refusal and any stray extra
    // frame would fail the byte comparison.
    drop(shared);
    let mut out = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut client_read, &mut out)
        .await
        .unwrap();
    let expected = format!(
        "{}\n",
        crate::auditor::proxy_wire::build_jsonrpc_error("0", "tools/list already in progress")
    );
    assert_eq!(
        out,
        expected.as_bytes(),
        "the refusal must emit exactly one already-in-progress error"
    );
}

/// The deputy gate's `AccessDenial` carries the refusal kind: a
/// `..` escape keeps earning the `validation.path_traversal` audit
/// event while an ordinary undiscovered path stays a session-state
/// refusal — neither lands in the widening candidates. The
/// classification reads the typed error, never the wrapped reason
/// text.
#[test]
fn deputy_gate_denials_carry_typed_kind() {
    let policy = Policy {
        confused_deputy_protection: true,
        ..Default::default()
    };
    let mut state = SessionState::new();
    // `read_file` binds the compat use-role (FsTargets) — every
    // extracted path must already be in `known_paths`, and a `..`
    // spelling is refused outright.
    let traversal = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/../secret"}}}"#;
    let traversal_json = nojson::RawJson::parse(traversal).unwrap();
    let err = apply_confused_deputy_c2s(
        &policy,
        &mut state,
        &traversal_json,
        None,
        Some("read_file"),
    )
    .unwrap_err();
    assert_eq!(
        err.validation_kind(),
        Some(EventType::ValidationPathTraversal),
        "{}",
        err.reason
    );
    assert!(err.reason.contains("path traversal"), "{}", err.reason);
    assert!(!err.is_denied_target());

    let undiscovered = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/undiscovered.txt"}}}"#;
    let undiscovered_json = nojson::RawJson::parse(undiscovered).unwrap();
    let err = apply_confused_deputy_c2s(
        &policy,
        &mut state,
        &undiscovered_json,
        None,
        Some("read_file"),
    )
    .unwrap_err();
    assert!(err.validation_kind().is_none(), "{}", err.reason);
    assert!(!err.is_denied_target());
    assert!(err.reason.contains("confused deputy"), "{}", err.reason);
}

/// MRTR retry at the request handler: a retry is a NEW JSON-RPC id
/// carrying `requestState`/`inputResponses` — the deputy gate still
/// extracts the use-side path from `params.arguments` and checks it
/// against `known_paths`. The retry envelope is opaque to the gate.
#[test]
fn mrtr_retry_still_passes_the_deputy_gate() {
    let policy = Policy {
        confused_deputy_protection: true,
        ..Default::default()
    };
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/a.txt".to_string()]);

    // The retry: new id + requestState + inputResponses for the
    // discovered path — allowed.
    let retry_known = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/a.txt"},"requestState":"eyJzIjoxfQ","inputResponses":{"k":{"x":1}}}}"#;
    let json = nojson::RawJson::parse(retry_known).unwrap();
    apply_confused_deputy_c2s(
        &policy,
        &mut state,
        &json,
        Some(&RpcId::from_u64(9)),
        Some("read_file"),
    )
    .expect("the discovered path must pass the deputy gate on retry");

    // The same retry envelope must not launder an undiscovered path.
    let retry_unknown = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"},"requestState":"eyJzIjoxfQ","inputResponses":{"k":{"x":1}}}}"#;
    let json = nojson::RawJson::parse(retry_unknown).unwrap();
    assert!(
        apply_confused_deputy_c2s(
            &policy,
            &mut state,
            &json,
            Some(&RpcId::from_u64(10)),
            Some("read_file"),
        )
        .is_err(),
        "an undiscovered path must stay blocked on retry"
    );
}

/// The request handler runs the trajectory check on the retry path
/// itself: `requestState` passing through must not skip it — after a
/// verified ReadOnly, a Network retry under a new id still fails.
#[test]
fn mrtr_retry_still_runs_the_trajectory_gate() {
    let mut policy = Policy::default();
    policy.trajectory = true;
    policy.trajectory_rules = vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::ReadOnly,
        deny_next: crate::policy::SideEffect::Network,
    }];
    policy.tools.push({
        let mut t = crate::policy::ToolPolicy::named("fetch_url", true);
        t.side_effect = Some("network".to_string());
        t
    });
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));

    // A retry carrying requestState: the handler must still consult
    // trajectory — skipping the check is the failure this asserts.
    let retry = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fetch_url","arguments":{},"requestState":"eyJzIjoxfQ"}}"#;
    let json = nojson::RawJson::parse(retry).unwrap();
    let err = checker::check_trajectory_json(&json, &policy, &state)
        .expect_err("a Network retry after ReadOnly must be denied");
    assert!(
        err.reason.contains("trajectory"),
        "the retry must fail on the trajectory check: {}",
        err.reason
    );
}

/// MRTR retry at the C2S handler itself: `forward_allowed` runs the
/// whole gate chain — admission, deputy, trajectory, registration,
/// dispatch — so a permitted retry crosses to the child while a retry
/// the session gates refuse never leaves the audit path.
#[tokio::test]
async fn mrtr_retry_through_forward_allowed_enforces_deputy() {
    let (mut shared, _rx, mut child_read) = shared_for_test();
    shared.policy.confused_deputy_protection = true;
    shared
        .policy
        .tools
        .push(crate::policy::ToolPolicy::named("read_file", true));
    let session = Arc::new(Mutex::new(SessionState::new()));
    session
        .lock()
        .await
        .record_paths(&["/workspace/a.txt".to_string()]);
    shared.session = Some(session);

    // A permitted retry — new id + requestState + discovered path —
    // forwards like any admitted call.
    let retry_known = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/a.txt"},"requestState":"eyJzIjoxfQ","inputResponses":{"k":{"x":1}}}}"#;
    forward_allowed(
        &shared,
        &verified(retry_known),
        "tools/call",
        &RpcId::from_u64(9),
        "9",
        SupportedProtocolVersion::Mcp2025November25,
        McpVerdict::Allow(AllowReason::RuleAllow),
        ExtractedRequest::default(),
    )
    .await
    .unwrap();
    assert!(
        shared
            .wire
            .lock()
            .await
            .get(C2S, &RpcId::from_u64(9))
            .is_some()
    );
    let expected = format!("{retry_known}\n");
    let mut buf = vec![0u8; expected.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_exact(&mut child_read, &mut buf),
    )
    .await
    .expect("the permitted retry must reach the child")
    .expect("the child read must complete");
    assert_eq!(buf, expected.as_bytes());

    // The same retry envelope carrying an undiscovered path is denied
    // at the deputy gate — nothing registers or reaches the child.
    let retry_unknown = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"},"requestState":"eyJzIjoxfQ","inputResponses":{"k":{"x":1}}}}"#;
    forward_allowed(
        &shared,
        &verified(retry_unknown),
        "tools/call",
        &RpcId::from_u64(10),
        "10",
        SupportedProtocolVersion::Mcp2025November25,
        McpVerdict::Allow(AllowReason::RuleAllow),
        ExtractedRequest::default(),
    )
    .await
    .unwrap();
    assert!(
        shared
            .wire
            .lock()
            .await
            .get(C2S, &RpcId::from_u64(10))
            .is_none(),
        "a deputy-denied retry must never register"
    );
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        tokio::io::AsyncReadExt::read(&mut child_read, &mut buf),
    )
    .await;
    assert!(
        read.is_err(),
        "a deputy-denied retry must not reach the child"
    );
}

/// The trajectory gate is part of the same handler path: a Network
/// retry after a verified ReadOnly is refused before dispatch — the
/// `requestState` member must not tunnel past `check_trajectory_json`.
#[tokio::test]
async fn mrtr_retry_through_forward_allowed_enforces_trajectory() {
    let (mut shared, _rx, mut child_read) = shared_for_test();
    shared.policy.trajectory = true;
    shared.policy.trajectory_rules = vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::ReadOnly,
        deny_next: crate::policy::SideEffect::Network,
    }];
    shared.policy.tools.push({
        let mut t = crate::policy::ToolPolicy::named("fetch_url", true);
        t.side_effect = Some("network".to_string());
        t
    });
    let session = Arc::new(Mutex::new(SessionState::new()));
    session
        .lock()
        .await
        .record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    shared.session = Some(session);

    let retry = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"fetch_url","arguments":{},"requestState":"eyJzIjoxfQ"}}"#;
    forward_allowed(
        &shared,
        &verified(retry),
        "tools/call",
        &RpcId::from_u64(11),
        "11",
        SupportedProtocolVersion::Mcp2025November25,
        McpVerdict::Allow(AllowReason::RuleAllow),
        ExtractedRequest::default(),
    )
    .await
    .unwrap();
    assert!(
        shared
            .wire
            .lock()
            .await
            .get(C2S, &RpcId::from_u64(11))
            .is_none(),
        "a trajectory-denied retry must never register"
    );
    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        tokio::io::AsyncReadExt::read(&mut child_read, &mut buf),
    )
    .await;
    assert!(
        read.is_err(),
        "a trajectory-denied retry must not reach the child"
    );

    // The same retry frame on a fresh session — no ReadOnly
    // predecessor — must forward: the deny above was the trajectory
    // predecessor, not anything in the `requestState` retry itself.
    shared.session = Some(Arc::new(Mutex::new(SessionState::new())));
    forward_allowed(
        &shared,
        &verified(retry),
        "tools/call",
        &RpcId::from_u64(11),
        "11",
        SupportedProtocolVersion::Mcp2025November25,
        McpVerdict::Allow(AllowReason::RuleAllow),
        ExtractedRequest::default(),
    )
    .await
    .unwrap();
    let mut frame = vec![0u8; retry.len() + 1];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_exact(&mut child_read, &mut frame),
    )
    .await
    .expect("the retry must reach the child within the bound")
    .expect("the child read must complete");
    assert_eq!(
        String::from_utf8(frame).unwrap(),
        format!("{retry}\n"),
        "the child must receive the retry frame verbatim"
    );
}
