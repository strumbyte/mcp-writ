//! Client→server direction of `run_proxy`: frame classification, MCP
//! decision enforcement, legacy tools/call / tools/list policy checks,
//! opt-in trajectory / Confused Deputy session accounting, and forwarding.
//!
//! Every frame is classified (request / notification / response) and
//! decided through `Policy::decide_mcp` before it crosses the wire:
//! denied requests get a JSON-RPC error, denied notifications are
//! dropped, and malformed frames are never forwarded.

use tokio::io::{AsyncBufReadExt, BufReader};

use super::checker;
use super::proxy_rpc::{self, WireFrame, WireState};
use super::proxy_state::ProxyShared;
use super::proxy_wire::{
    build_jsonrpc_error, build_tools_list_error_response, extract_raw_id,
    extract_tool_name_from_line, frame_too_large_message, oversize_extra, read_proxy_frame,
    recover_id_candidates, recover_method, rpc_id_from_raw_id, write_child_frame,
    write_client_frame,
};
use super::session::RpcId;
use crate::error::AuditorError;
use crate::framing::{BoundedFrame, OversizeFrame};
use crate::policy::mcp::{DenyReason, DropReason, McpVerdict};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

const C2S: MessageDirection = MessageDirection::ClientToServer;
const S2C: MessageDirection = MessageDirection::ServerToClient;
const V26: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2026July28;

/// Client → Server direction.
///
/// Each stdin line is parsed once, classified, and decided. Allowed
/// requests are registered in the shared wire table so responses in the
/// opposite direction can correlate; denied ones are answered with a
/// JSON-RPC error (under `--dry-run` only observable `tools/call` policy
/// denials forward-but-tracked — every other denial stays enforced).
/// Allowed
/// notifications are forwarded; dropped ones are audited only. Responses
/// must answer a tracked server→client request or they are dropped.
pub(crate) async fn c2s_loop<W>(
    shared: ProxyShared<W>,
    mut abort_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut fail_watch = shared.audit.failure_watch();

    loop {
        shared.audit.ensure_available()?;
        // Peek before committing to a frame read — the same contract the
        // S2C loop follows (F-31): `fill_buf` only peeks, so a fail/abort
        // edge observed while idle loses no input. Once bytes are
        // buffered the frame read — including an oversized frame's drain
        // to its newline — runs to completion uninterruptibly, so a
        // watch edge can never strand a half-consumed line in the
        // reader's buffer.
        let read = tokio::select! {
            biased;
            _ = fail_watch.changed() => {
                // The writer died while the relay sat idle — a
                // fail-closed session ends here rather than
                // discovering the dead sink on the next frame.
                if shared.audit.is_failed() {
                    return Err(AuditorError::AuditUnavailable(
                        "audit writer failed while the relay was idle".into(),
                    ));
                }
                continue;
            }
            res = abort_rx.changed() => {
                if res.is_ok() && *abort_rx.borrow() {
                    tracing::error!("session aborted due to S2C verification failure; stopping C2S immediately");
                    answer_inflight_client_list(&shared, &mut reader).await?;
                    return Err(AuditorError::VerificationFailed("session aborted on server→client verification".to_string()));
                }
                continue;
            }
            avail = reader.fill_buf() => match avail {
                Err(e) => return Err(AuditorError::Io(e)),
                Ok(_) => read_proxy_frame(&mut reader, shared.max_frame_bytes).await,
            },
        };

        match read {
            Ok(Some(BoundedFrame::Line(line))) => {
                // Structural gate: invalid JSON or duplicate keys never
                // reach the decision layer — the client gets an error and
                // nothing is forwarded.
                let parsed = nojson::RawJson::parse(line.trim());
                let Ok(json) = parsed else {
                    deny_malformed(&shared, None, "invalid JSON").await?;
                    continue;
                };
                if let Err(violation) = checker::check_duplicate_keys_recursively(json.value()) {
                    deny_malformed(
                        &shared,
                        extract_raw_id(&line).or(Some("null".to_string())),
                        &violation.reason,
                    )
                    .await?;
                    continue;
                }
                match proxy_rpc::classify_frame(json.value()) {
                    WireFrame::Malformed { reason, raw_id } => {
                        deny_malformed(&shared, raw_id.or_else(|| extract_raw_id(&line)), reason)
                            .await?;
                    }
                    WireFrame::Notification { method } => {
                        c2s_notification(&shared, json.value(), &line, &method).await?;
                    }
                    WireFrame::Response { id, raw_id } => {
                        c2s_response(&shared, json.value(), &line, &id, &raw_id).await?;
                    }
                    WireFrame::Request { method, id, raw_id } => {
                        c2s_request(&shared, json.value(), &line, &method, &id, &raw_id).await?;
                    }
                }
            }
            Ok(Some(BoundedFrame::Oversize(frame))) => {
                c2s_oversize(&shared, &frame).await?;
            }
            Ok(None) => {
                // AsyncWrite::shutdown is only a flush for tokio::fs::File
                // (Windows pipes). Drop the writer to deliver EOF instead.
                shared.child_stdin.lock().await.take();
                break;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Emit the client-visible error for an internally-owned listing that
/// failed on the S2C side (the post-`initialize` probe, a `list_changed`
/// revalidation — verification failure or policy rejection). The S2C
/// path only records the failure reason here; this side knows which
/// client request, if any, was coalesced behind the dead listing: one
/// already `hold_client_list`-ed, or one still in transit in this pipe
/// because the C2S pump had not run when the failure fired. A coalesced
/// request's denial echoes its own id — an `id:null` frame answers
/// nothing the client is waiting on — while a failure with no coalesced
/// request still emits `id:null` so the abort stays observable. The scan
/// window is bounded — a frame the client has not written yet dies with
/// the session, as before.
///
/// Non-listing aborts carry no recorded failure: the S2C site already
/// emitted whatever the client sees, so this returns without scanning.
async fn answer_inflight_client_list<W>(
    shared: &ProxyShared<W>,
    reader: &mut BufReader<tokio::io::Stdin>,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Some(reason) = shared.internal_list_failure.lock().await.take() else {
        return Ok(());
    };
    let mut emitted = false;
    if let Some((_id, raw_id)) = shared.held_client_list.lock().await.take() {
        let response = build_tools_list_error_response(&raw_id, &reason);
        write_client_frame(&shared.client_out, &response).await?;
        emitted = true;
    }
    // The window only has to cover delivery of bytes the client already
    // flushed into the OS pipe — anything later legitimately dies with
    // the session.
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(150);
    loop {
        let read = match tokio::time::timeout_at(deadline, reader.fill_buf()).await {
            Ok(Ok(buf)) if !buf.is_empty() => {
                read_proxy_frame(reader, shared.max_frame_bytes).await
            }
            Ok(Ok(_)) => break,
            Ok(Err(e)) => return Err(AuditorError::Io(e)),
            Err(_) => break,
        };
        let Ok(Some(BoundedFrame::Line(line))) = read else {
            break;
        };
        let Ok(json) = nojson::RawJson::parse(line.trim()) else {
            continue;
        };
        if let WireFrame::Request { method, raw_id, .. } = proxy_rpc::classify_frame(json.value())
            && method == "tools/list"
        {
            let response = build_tools_list_error_response(&raw_id, &reason);
            write_client_frame(&shared.client_out, &response).await?;
            emitted = true;
        }
    }
    if !emitted {
        let response = build_tools_list_error_response("null", &reason);
        write_client_frame(&shared.client_out, &response).await?;
    }
    Ok(())
}

/// A client→server frame that exceeded `max_frame_bytes`: refused
/// before parse, so the retained head/tail windows stand in for it.
///
/// A `method` member marks a request or notification. A request's
/// recovered `id` is echoed back in a JSON-RPC error — the sender gets
/// a per-request failure instead of a dead session; a notification
/// (recovered `method`, no `id`) is audited and dropped, since
/// notifications never produce responses. Without `method` the frame is
/// likely a *response* to a server→client request: resolved `id`
/// candidates release that request's tracked entry and an error goes to
/// the *server* (2025 only — 2026 forbids client→server responses) so
/// its request does not hang. Unidentifiable frames get an `id: null`
/// error, the same posture `deny_malformed` takes.
///
/// Nothing oversized is ever forwarded — including under `--dry-run`,
/// because dry-run observes decisions on frames the proxy still
/// possesses; here only bounded windows were retained.
async fn c2s_oversize<W>(shared: &ProxyShared<W>, frame: &OversizeFrame) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let method = recover_method(frame);
    // `prefer_tail`: a response's `id` is serialized last by the TS SDK;
    // a request's sits ahead of `params`.
    let ids = recover_id_candidates(frame, method.is_none());

    if method.is_none() {
        // Response interpretation first: a recovered id that names a
        // tracked server→client request is answered with an error back
        // to the server (the denied-response path's existing posture).
        let mut released: Option<(String, super::proxy_rpc::TrackedRequest)> = None;
        {
            let mut wire = shared.wire.lock().await;
            for raw in &ids {
                let Some(id) = rpc_id_from_raw_id(raw) else {
                    continue;
                };
                if wire.answered(C2S, &id).is_none() {
                    continue;
                }
                if let Some(entry) = wire.take(S2C, &id) {
                    released = Some((raw.clone(), entry));
                }
                break;
            }
        }
        if let Some((raw, entry)) = released {
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "response",
                Some(entry.method.as_str()),
                Some(raw.as_str()),
                entry.version,
                McpVerdict::Deny(DenyReason::FrameTooLarge),
                false,
                shared.dry_run,
                Some(oversize_extra(frame, shared.max_frame_bytes)),
            )?;
            if !matches!(entry.version, V26) {
                let msg = format!(
                    "mcp-writ: response to '{}' rejected ({})",
                    entry.method,
                    DenyReason::FrameTooLarge.as_str(),
                );
                write_child_frame(&shared.child_stdin, &build_jsonrpc_error(&raw, &msg)).await?;
            }
            return Ok(());
        }
    }

    // Request, notification, or unidentifiable: audit, then answer the
    // client — requests (and unidentifiable frames) get the recovered id
    // or `null`; notifications get nothing, since a notification is
    // never owed an answer.
    let raw_id = ids
        .iter()
        .find(|raw| rpc_id_from_raw_id(raw).is_some_and(|id| !matches!(id, RpcId::Null)))
        .cloned();
    let version = shared.wire.lock().await.passive_version();
    let kind = if method.is_none() {
        // No `method` anywhere in the retained windows and no tracked
        // server request resolved — an oversized response that cannot
        // be correlated, or an unidentifiable frame.
        "response"
    } else if raw_id.is_none() {
        "notification"
    } else {
        "request"
    };
    proxy_rpc::audit_decision(
        &shared.audit,
        C2S,
        kind,
        method.as_deref(),
        raw_id.as_deref(),
        version,
        McpVerdict::Deny(DenyReason::FrameTooLarge),
        false,
        shared.dry_run,
        Some(oversize_extra(frame, shared.max_frame_bytes)),
    )?;
    if kind == "notification" {
        return Ok(());
    }
    write_client_frame(
        &shared.client_out,
        &build_jsonrpc_error(
            raw_id.as_deref().unwrap_or("null"),
            &frame_too_large_message("request", shared.max_frame_bytes),
        ),
    )
    .await
}

/// Malformed client frames get a JSON-RPC error (`id` echoed when
/// readable) and a `mcp_message.denied` audit event — nothing forwards.
async fn deny_malformed<W>(
    shared: &ProxyShared<W>,
    raw_id: Option<String>,
    reason: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    proxy_rpc::audit_decision(
        &shared.audit,
        C2S,
        "malformed",
        None,
        raw_id.as_deref(),
        shared
            .wire
            .lock()
            .await
            .wire_version()
            .unwrap_or(SupportedProtocolVersion::Mcp2025November25),
        McpVerdict::Deny(DenyReason::Shape),
        false,
        shared.dry_run,
        Some(format!("malformed={reason}")),
    )?;
    write_client_frame(
        &shared.client_out,
        &build_jsonrpc_error(
            raw_id.as_deref().unwrap_or("null"),
            &format!("malformed JSON-RPC frame ({reason})"),
        ),
    )
    .await
}

/// One client-originated notification: decide, then forward or drop.
async fn c2s_notification<W>(
    shared: &ProxyShared<W>,
    value: nojson::RawJsonValue<'_, '_>,
    line: &str,
    method: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ext = proxy_rpc::extract_notification(value, method);
    let mut wire = shared.wire.lock().await;
    let version = wire.passive_version();
    // A `notifications/cancelled` naming the reserved internal-request
    // namespace is consumed here — audited, never forwarded: the client
    // cannot legitimately name an id only the auditor mints, and letting
    // one reach the server would cancel a real internal request and
    // stall list revalidation mid-flight. Under --dry-run the "observe
    // but forward" rule still cannot apply — the server must not see a
    // cancel for an id it never received a request for.
    if method == "notifications/cancelled"
        && ext
            .cancel_id
            .as_ref()
            .is_some_and(RpcId::is_internal_namespace)
    {
        drop(wire);
        proxy_rpc::audit_decision(
            &shared.audit,
            C2S,
            "notification",
            Some(method),
            None,
            version,
            McpVerdict::Drop(DropReason::Shape),
            false,
            shared.dry_run,
            Some("cancel id uses the reserved internal namespace".to_string()),
        )?;
        return Ok(());
    }
    let verdict = {
        let cancel_target = ext
            .cancel_id
            .as_ref()
            .map(|id| wire.cancel_facts(C2S, id, version))
            .unwrap_or_default();
        let progress = ext
            .progress_token
            .as_ref()
            .map(|t| wire.progress(C2S, t))
            .unwrap_or_default();
        let msg = proxy_rpc::notification_message(
            version,
            C2S,
            method,
            &ext,
            cancel_target,
            progress,
            None,
            None,
        );
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    match verdict {
        McpVerdict::Allow(_) => {
            // A cancelled in-flight request may never see the response
            // that would close its bookkeeping — release the pending
            // entries while the wire entry still identifies the id's
            // method (on_notification_forwarded marks/removes it).
            let cancelled = if method == "notifications/cancelled" {
                ext.cancel_id.as_ref().and_then(|cancel_id| {
                    cancelled_release_for(&wire, cancel_id)
                        .map(|release| (cancel_id.clone(), release))
                })
            } else {
                None
            };
            wire.on_notification_forwarded(C2S, version, method, &ext);
            drop(wire);
            if let Some((cancel_id, release)) = cancelled {
                release_cancelled_bookkeeping(shared, &cancel_id, release).await;
            }
            // A `tools/list` held behind an internal listing never
            // reached the wire — cancel it by dropping the hold so the
            // settled emit does not answer a dead request.
            if method == "notifications/cancelled"
                && let Some(cancel_id) = ext.cancel_id.as_ref()
            {
                let mut held = shared.held_client_list.lock().await;
                if held.as_ref().is_some_and(|(id, _)| id == cancel_id) {
                    *held = None;
                }
            }
            proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                C2S,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                shared.dry_run,
                None,
            )
            .await?;
            match write_child_frame(&shared.child_stdin, line).await {
                Ok(()) => Ok(()),
                Err(e) => {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        C2S,
                        "notification",
                        Some(method),
                        None,
                        version,
                        verdict,
                        shared.dry_run,
                        None,
                    );
                    Err(e)
                }
            }
        }
        McpVerdict::Drop(_) => {
            // Dropped notifications never reach the server — a dry-run
            // forward would leak a notification the policy refused to a
            // server that may act on it (a dropped `cancelled` still
            // cancels, a dropped `initialized` still arms the session).
            drop(wire);
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                false,
                shared.dry_run,
                None,
            )?;
            Ok(())
        }
        // Notifications never produce a JSON-RPC answer — deny/undecided
        // cannot arise for them; fail closed as a drop.
        _ => {
            drop(wire);
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                false,
                shared.dry_run,
                None,
            )?;
            Ok(())
        }
    }
}

/// Bookkeeping a forwarded `notifications/cancelled` can strand when the
/// server honours the cancel by dropping the request without responding —
/// decided while the wire entry still identifies the cancel target's
/// method (registration entries do not survive `on_notification_forwarded`
/// in a form that carries it).
#[derive(Clone, Copy)]
enum CancelledRelease {
    /// A forwarded in-flight `tools/call`: the trajectory pending call
    /// and the Confused Deputy pending list its response would close.
    ToolCall,
    /// A forwarded client `tools/list`: the busy gate, the bounded
    /// pending-id set, and the stored request template the response
    /// would consume.
    ToolsList,
}

/// Which bookkeeping a forwarded cancel must release for the request it
/// names — `None` for ids that aren't tracked or that release nothing on
/// cancellation. Internal `tools/list` requests are unreachable here —
/// their ids sit in the reserved string namespace, and client cancels
/// naming it are consumed in `c2s_notification` before this runs. The
/// `!entry.internal` guard stays as the structural backstop: internal
/// bookkeeping is never released by client traffic, and a reserved-id
/// cancel is dropped, not forwarded.
fn cancelled_release_for(wire: &WireState, cancel_id: &RpcId) -> Option<CancelledRelease> {
    let entry = wire.get(C2S, cancel_id)?;
    if entry.method == "tools/call" {
        Some(CancelledRelease::ToolCall)
    } else if entry.method == "tools/list" && !entry.internal {
        Some(CancelledRelease::ToolsList)
    } else {
        None
    }
}

/// Release the bookkeeping a forwarded cancel can strand. A `tools/call`
/// releases the session entries its response would close; a client
/// `tools/list` releases the bounded pending-id set and the stored
/// request template, then hands the cancelled id to the S2C loop, which
/// drops the dead collection and either drives a queued `list_changed`
/// revalidation or clears `list_busy` — without that handoff a cancelled
/// list leaves the gate latched (every later `tools/call` denied,
/// fail-closed degraded into a liveness failure) or, mid-`list_changed`,
/// unlatches it against a stale verified set.
async fn release_cancelled_bookkeeping<W>(
    shared: &ProxyShared<W>,
    cancel_id: &RpcId,
    release: CancelledRelease,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    match release {
        CancelledRelease::ToolCall => {
            if let Some(ref session) = shared.session {
                let mut state = session.lock().await;
                state.take_pending_list(cancel_id);
                // Cancellation is advisory — the forwarded call may
                // already have run server-side, so release it as an
                // unverified completion: its side_effect still feeds
                // trajectory deny matching, but it must not overwrite
                // the verified marker (a cancelled benign call would
                // otherwise launder `after=X` rules keyed on the real
                // predecessor). `take_pending_list` still releases the
                // deputy's pending list.
                state.release_pending_tool_call_unverified(cancel_id);
            }
        }
        CancelledRelease::ToolsList => {
            shared.pending_tools_list.lock().await.remove(cancel_id);
            // `original_tools_list` is keyed by canonical `RpcId`, so the
            // cancel's canonical id resolves the entry directly.
            shared.original_tools_list.lock().await.remove(cancel_id);
            // Hand the cancelled id to the S2C loop: it releases the
            // dead collection, then drives any queued `list_changed`
            // revalidation — or clears the busy gate when none is owed.
            // Clearing `list_busy` here would race `handle_list_changed`'s
            // `swap(true)`, so only the S2C side ever releases the gate.
            *shared.cancelled_list_id.lock().await = Some(cancel_id.clone());
            shared.list_kick.notify_one();
        }
    }
}

/// One client-originated response — must answer a tracked server→client
/// request. An uncorrelated or malformed response is dropped; when a
/// tracked request exists the proxy answers the server on the client's
/// behalf so the request does not hang (2025 only — 2026 forbids
/// client→server responses entirely).
async fn c2s_response<W>(
    shared: &ProxyShared<W>,
    value: nojson::RawJsonValue<'_, '_>,
    line: &str,
    id: &RpcId,
    raw_id: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ext = proxy_rpc::extract_response(value);
    let mut wire = shared.wire.lock().await;
    let answered = wire.answered(C2S, id);
    // The revision a response is judged under is the answered request's —
    // absent a tracked request, fall back to the established wire.
    let version = wire
        .get(S2C, id)
        .map(|e| e.version)
        .unwrap_or_else(|| wire.passive_version());
    let verdict = {
        let answered_facts = answered.as_ref().map(proxy_rpc::answered_facts);
        let msg = proxy_rpc::response_message(C2S, version, &ext, answered_facts);
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    match verdict {
        McpVerdict::Allow(_) => {
            let entry = wire.take(S2C, id);
            if let Some(ref e) = entry {
                wire.on_response_forwarded(C2S, e, &ext, ext.has_result && !ext.is_error);
            }
            drop(wire);
            proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                C2S,
                "response",
                entry.as_ref().map(|e| e.method.as_str()),
                Some(raw_id),
                version,
                verdict,
                shared.dry_run,
                None,
            )
            .await?;
            match write_child_frame(&shared.child_stdin, line).await {
                Ok(()) => Ok(()),
                Err(e) => {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        C2S,
                        "response",
                        entry.as_ref().map(|e| e.method.as_str()),
                        Some(raw_id),
                        version,
                        verdict,
                        shared.dry_run,
                        None,
                    );
                    Err(e)
                }
            }
        }
        _ => {
            // Denied response: consume the request entry and close the
            // server's wait with an error (2025). Uncorrelated or
            // direction-illegal responses are dropped without a reply —
            // and an entry whose response already correlated (`responded`)
            // is left alone rather than consumed by a stray frame.
            let entry = if answered.is_some() {
                wire.take(S2C, id)
            } else {
                None
            };
            let had_entry = entry.is_some();
            let version_v26 = matches!(version, V26);
            drop(wire);
            // A denied response never crosses to the server — not even
            // to be observed: a refused `elicitation`/`sampling` answer
            // still conveys the refused payload.
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "response",
                entry.as_ref().map(|e| e.method.as_str()),
                Some(raw_id),
                version,
                verdict,
                false,
                shared.dry_run,
                None,
            )?;
            if had_entry && !version_v26 {
                let msg = format!(
                    "mcp-writ: response to '{}' rejected ({})",
                    entry
                        .as_ref()
                        .map(|e| e.method.as_str())
                        .unwrap_or("request"),
                    verdict.reason_code()
                );
                write_child_frame(&shared.child_stdin, &build_jsonrpc_error(raw_id, &msg)).await?;
            }
            Ok(())
        }
    }
}

/// One client-originated request: revision classification, decision,
/// then method-specific legacy gates for `tools/call` and `tools/list`.
async fn c2s_request<W>(
    shared: &ProxyShared<W>,
    value: nojson::RawJsonValue<'_, '_>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ext = proxy_rpc::extract_request(value, method);

    // A null id cannot be tracked — deny outright.
    if matches!(id, RpcId::Null) {
        return deny_request(
            shared,
            line,
            method,
            id,
            raw_id,
            wire_version_or_default(shared).await,
            &ext,
            McpVerdict::Deny(DenyReason::Shape),
            "request id must not be null",
        )
        .await;
    }

    // Internal-request ids live in a reserved string namespace only the
    // auditor mints: a client request carrying one would alias an
    // in-flight internal listing's correlation key (and a later cancel
    // for it could retire that internal request). Answer with an error
    // and never forward — under --dry-run a registered+forwarded denied
    // frame would still claim the reserved id on the wire table.
    if id.is_internal_namespace() {
        let version = wire_version_or_default(shared).await;
        let verdict = McpVerdict::Deny(DenyReason::Shape);
        proxy_rpc::audit_decision(
            &shared.audit,
            C2S,
            "request",
            Some(method),
            Some(raw_id),
            version,
            verdict,
            false,
            shared.dry_run,
            request_extra(&ext),
        )?;
        let reason = DenyReason::Shape.as_str();
        return write_client_frame(
            &shared.client_out,
            &build_jsonrpc_error(
                raw_id,
                &format!("request '{method}' denied by MCP policy ({reason})"),
            ),
        )
        .await;
    }

    let params = ext.params();
    let (version, verdict) = {
        let wire = shared.wire.lock().await;
        let classified = wire.request_version(method, ext.meta_declares_version);
        // A classification error still records and audits under the
        // established wire revision — only a successful classification
        // may pin the frame to a version.
        let version = classified.unwrap_or_else(|_| wire.passive_version());
        let verdict = match classified {
            Err(reason) => McpVerdict::Deny(reason),
            Ok(version) => {
                let msg = proxy_rpc::request_message(version, C2S, method, &ext, &params);
                shared.policy.decide_mcp(&msg, &wire.session_facts())
            }
        };
        (version, verdict)
    };

    match verdict {
        McpVerdict::Allow(_) => {
            forward_allowed(shared, line, method, id, raw_id, version, verdict, ext).await
        }
        McpVerdict::Deny(_) => {
            let message = match extract_tool_name_from_line(line) {
                Some(tool) if method == "tools/call" => {
                    format!("request '{method}' tool '{tool}' denied by MCP policy")
                }
                _ => format!("request '{method}' denied by MCP policy"),
            };
            deny_request(
                shared, line, method, id, raw_id, version, &ext, verdict, &message,
            )
            .await
        }
        // Responses-only verdicts cannot arise for requests; fail closed.
        _ => {
            deny_request(
                shared,
                line,
                method,
                id,
                raw_id,
                version,
                &ext,
                McpVerdict::Deny(DenyReason::Shape),
                "undecidable request",
            )
            .await
        }
    }
}

/// The wire revision for audit of frames denied before classification.
mod forward;

use forward::{deny_request, forward_allowed, request_extra, wire_version_or_default};
