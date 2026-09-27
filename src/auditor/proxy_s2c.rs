//! Server→client direction of `run_proxy`: frame classification, MCP
//! decision enforcement, response correlation, session accounting (CDP
//! list paths / trajectory completion), and delegation of tools/list
//! traffic to the verification pipeline in `proxy_tools_list`.
//!
//! Every frame is classified (request / notification / response) and
//! decided through `Policy::decide_mcp` before it crosses the wire:
//! denied server requests are answered with a JSON-RPC error (2025),
//! denied notifications are dropped, and responses must answer a tracked
//! client→server request — uncorrelated or malformed frames are never
//! forwarded.

use std::sync::atomic::Ordering;

use tokio::io::BufReader;

use super::checker;
use super::proxy_list_state::S2cListState;
use super::proxy_rpc::{self, ExtractedRequest, TrackedRequest, WireFrame, WireState};
use super::proxy_state::ProxyShared;
use super::proxy_tools_list::{self, ListFlow, S2cFrame};
use super::proxy_wire::{
    build_jsonrpc_error, extract_raw_id, read_proxy_line, tools_call_result_succeeded,
    write_child_frame, write_client_frame,
};
use super::session::{self, RpcId};
use crate::error::AuditorError;
use crate::policy::Policy;
use crate::policy::mcp::{
    AdditionalRequestMessage, AllowReason, DenyReason, McpVerdict, OriginalRequestFacts,
    TrafficMessage, UndecidedReason,
};
use crate::protocol::fields::{self, SchemaField};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

const C2S: MessageDirection = MessageDirection::ClientToServer;
const S2C: MessageDirection = MessageDirection::ServerToClient;
const V25: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2025November25;
const V26: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2026July28;

/// Server → Client direction.
///
/// Lines are classified and decided, then forwarded to the client,
/// dropped, or answered with an error to the server. tools/list traffic
/// is collected, verified, and re-emitted via [`proxy_tools_list`]; MRTR
/// `input_required` interim results are decided by the additional requests
/// they carry ([`resolve_input_required`]).
pub(crate) async fn s2c_loop<W, R>(
    shared: ProxyShared<W>,
    child_stdout: R,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(child_stdout);
    let mut st = S2cListState::new();

    loop {
        shared.audit.ensure_available()?;
        match read_proxy_line(&mut reader).await {
            Ok(Some(line)) => {
                s2c_frame(&shared, &mut st, &line).await?;
            }
            Ok(None) => {
                if st.has_incomplete_listing() || shared.list_busy.load(Ordering::SeqCst) {
                    return Err(AuditorError::VerificationFailed(
                        "server closed stdout before tools/list verification completed".into(),
                    ));
                }
                break;
            }
            Err(e) => {
                tracing::error!("server→client: read error: {e}");
                return Err(e);
            }
        }
    }
    Ok(())
}

/// One server→client line: classify, decide, then forward / drop /
/// reject. Returns `Err` only on I/O failure or verification abort.
async fn s2c_frame<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    line: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let parsed = nojson::RawJson::parse(line.trim());
    let Ok(json) = &parsed else {
        // Fail closed: unparseable frames from the server are dropped.
        audit_malformed(shared, None, "invalid JSON").await;
        return Ok(());
    };
    // Same structural gate as the client→server direction: a frame with
    // duplicate keys can parse differently downstream than it did here —
    // drop it rather than forward a disagreement.
    if let Err(violation) = checker::check_duplicate_keys_recursively(json.value()) {
        let raw_id = extract_raw_id(line);
        audit_malformed(shared, raw_id.as_deref(), &violation.reason).await;
        return Ok(());
    }
    let value = json.value();
    match proxy_rpc::classify_frame(value) {
        // A malformed frame cannot carry a usable correlation id — it is
        // dropped and audited; a pending listing keeps waiting for a real
        // response. Exception: a frame carrying response members on a
        // tracked tools/list id still reaches the verification pipeline,
        // which fails closed on it — dropping it would leave the listing
        // hung until EOF.
        WireFrame::Malformed { reason, raw_id } => {
            if proxy_rpc::has_response_members(value) {
                let rpc_id = value
                    .to_member("id")
                    .ok()
                    .and_then(|m| m.optional())
                    .and_then(RpcId::parse_from_json);
                let tracked = st.is_internal_response(raw_id.as_deref())
                    || match rpc_id {
                        Some(ref id) => shared.pending_tools_list.lock().await.contains(id),
                        None => false,
                    };
                if tracked {
                    return route_tools_list(shared, st, line, &parsed, value, Some(reason)).await;
                }
            }
            audit_malformed(shared, raw_id.as_deref(), reason).await;
            Ok(())
        }
        WireFrame::Notification { method } => {
            s2c_notification(shared, st, value, line, &method).await
        }
        WireFrame::Response { id, raw_id } => {
            s2c_response(shared, st, value, line, &parsed, &id, &raw_id).await
        }
        WireFrame::Request { method, id, raw_id } => {
            s2c_request(shared, value, line, &method, &id, &raw_id).await
        }
    }
}

/// tools/list pipeline handoff — collects, verifies, re-emits.
async fn route_tools_list<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    line: &str,
    parsed: &Result<nojson::RawJson<'_>, nojson::JsonParseError>,
    value: nojson::RawJsonValue<'_, '_>,
    malformed_reason: Option<&str>,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let id_member = value.to_member("id").ok().and_then(|m| m.optional());
    let raw_id = id_member.map(|v| v.as_raw_str().to_string());
    let rpc_id = id_member.and_then(RpcId::parse_from_json);
    let is_response = crate::protocol::value_is_response(value);
    let has_method = value
        .to_member("method")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    match proxy_tools_list::handle_tools_list_response(
        shared,
        st,
        S2cFrame {
            line,
            parsed,
            rpc_id: rpc_id.as_ref(),
            raw_id: raw_id.as_deref(),
            has_method,
            is_response,
            malformed_reason,
        },
    )
    .await?
    {
        ListFlow::Handled => Ok(()),
        // Cannot happen for a list-tracked frame — defensive forward.
        ListFlow::ForwardRaw => write_client_frame(&shared.client_out, line).await,
    }
}

/// One server→client notification: decide (capability / subscription /
/// correlation gates), then forward or drop.
async fn s2c_notification<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
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
    let verdict = {
        let cancel_target = ext
            .cancel_id
            .as_ref()
            .map(|id| wire.cancel_facts(S2C, id, version))
            .unwrap_or_default();
        let progress = ext
            .progress_token
            .as_ref()
            .map(|t| wire.progress(S2C, t))
            .unwrap_or_default();
        let message_for = (method == "notifications/message")
            .then(|| {
                wire.message_correlation(ext.subscription_id.as_ref(), ext.progress_token.as_ref())
            })
            .flatten();
        let subscription = ext
            .subscription_id
            .as_ref()
            .and_then(|id| wire.subscription_facts(id));
        let msg = proxy_rpc::notification_message(
            version,
            S2C,
            method,
            &ext,
            cancel_target,
            progress,
            message_for,
            subscription,
        );
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    match verdict {
        McpVerdict::Allow(_) => {
            wire.on_notification_forwarded(S2C, version, method, &ext);
            drop(wire);
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                true,
                shared.dry_run,
                None,
            );
            if method == "notifications/tools/list_changed" {
                return proxy_tools_list::handle_list_changed(shared, st, line).await;
            }
            write_client_frame(&shared.client_out, line).await
        }
        _ => {
            // Drop or (defensively) deny/undecided — notifications are
            // never answered.
            drop(wire);
            let forward = shared.dry_run;
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                forward,
                shared.dry_run,
                None,
            );
            if forward {
                let mut wire = shared.wire.lock().await;
                wire.on_notification_forwarded(S2C, version, method, &ext);
                drop(wire);
                if method == "notifications/tools/list_changed" {
                    return proxy_tools_list::handle_list_changed(shared, st, line).await;
                }
                write_client_frame(&shared.client_out, line).await?;
            }
            Ok(())
        }
    }
}

/// One server→client response — must answer a tracked client→server
/// request. tools/list responses route to the verification pipeline;
/// `initialize` responses additionally validate `result.protocolVersion`.
async fn s2c_response<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    value: nojson::RawJsonValue<'_, '_>,
    line: &str,
    parsed: &Result<nojson::RawJson<'_>, nojson::JsonParseError>,
    id: &RpcId,
    raw_id: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ext = proxy_rpc::extract_response(value);
    let mut wire = shared.wire.lock().await;
    let answered = wire.answered(S2C, id);
    let version = wire
        .get(C2S, id)
        .map(|e| e.version)
        .unwrap_or_else(|| wire.passive_version());
    let verdict = {
        let answered_facts = answered.as_ref().map(proxy_rpc::answered_facts);
        let msg = proxy_rpc::response_message(S2C, version, &ext, answered_facts);
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    // MRTR: `resultType=input_required` is decided by the additional
    // requests it carries — each `inputRequests` entry is judged against
    // the tracked original request's facts (never the frame's claims).
    let (verdict, additional_audits) = match verdict {
        McpVerdict::Undecided(UndecidedReason::InputRequired) => {
            resolve_input_required(&shared.policy, &wire, value, id, version)
        }
        verdict => (verdict, Vec::new()),
    };

    // The tools/list pipeline owns any tracked list id — even when the
    // policy denies the response, list bookkeeping must unwind.
    let on_list_path = answered
        .as_ref()
        .map(|a| a.method == "tools/list")
        .unwrap_or(false)
        || shared.pending_tools_list.lock().await.contains(id)
        || st.is_internal_response(Some(raw_id));

    // `deny_reason` is the wire-facing rejection; a dropped response
    // still rejects the waiter's correlation id but surfaces as the
    // generic `shape` error, while the audit record keeps the true
    // verdict (`Drop` keeps its real reason code).
    let deny_reason = match verdict {
        McpVerdict::Allow(_) => None,
        // `Undecided` was resolved above — the MRTR gate is the only
        // producer for S2C responses; anything left is fail-closed.
        McpVerdict::Undecided(_) => Some(DenyReason::ResultType),
        McpVerdict::Deny(reason) => Some(reason),
        McpVerdict::Drop(_) => Some(DenyReason::Shape),
    };

    // `initialize` result revision pinning — decide cannot express it.
    let (audit_verdict, deny_reason) = if deny_reason.is_none()
        && answered
            .as_ref()
            .map(|a| a.method == "initialize" && !a.internal)
            .unwrap_or(false)
        && ext.has_result
        && !ext.is_error
        && !proxy_rpc::WireState::initialize_result_version_ok(&ext)
    {
        (McpVerdict::Deny(DenyReason::Shape), Some(DenyReason::Shape))
    } else {
        (verdict, deny_reason)
    };

    match deny_reason {
        None => {
            let is_result = ext.has_result && !ext.is_error;
            // A `subscriptions/listen` entry outlives its *result*
            // response — the subscription keeps resolving under the same
            // id. An error response means the subscription never started.
            let is_listen = answered
                .as_ref()
                .is_some_and(|a| a.method == "subscriptions/listen");
            let entry = if is_listen && is_result {
                wire.mark_responded(C2S, id)
            } else {
                wire.take(C2S, id)
            };
            if let Some(ref e) = entry {
                wire.on_response_forwarded(S2C, e, &ext, is_result);
            }
            let method_label = answered
                .as_ref()
                .map(|a| a.method.clone())
                .or_else(|| entry.as_ref().map(|e| e.method.clone()));
            let internal = answered.as_ref().map(|a| a.internal).unwrap_or(false);
            drop(wire);
            audit_additional_requests(shared, &additional_audits, raw_id, version, true);
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "response",
                method_label.as_deref(),
                Some(raw_id),
                version,
                audit_verdict,
                true,
                shared.dry_run,
                None,
            );
            if on_list_path || internal {
                return route_tools_list(shared, st, line, parsed, value, None).await;
            }
            apply_response_session_updates(shared, line, entry.as_ref()).await;
            write_client_frame(&shared.client_out, line).await
        }
        Some(reason) => {
            // Consume the answered entry — but never a `responded`
            // `subscriptions/listen` entry: the subscription keeps
            // resolving ack/notification/cancel traffic under the same
            // id, so a rejected late response must not take the live
            // subscription tracking (and id-retirement) down with it.
            let entry = if answered.is_some() {
                wire.take(C2S, id)
            } else {
                None
            };
            let method_label = entry
                .as_ref()
                .map(|e| e.method.clone())
                .or_else(|| wire.get(C2S, id).map(|e| e.method.clone()));
            let internal = entry.as_ref().map(|e| e.internal).unwrap_or(false);
            let had_answered = answered.is_some();
            drop(wire);
            audit_additional_requests(shared, &additional_audits, raw_id, version, shared.dry_run);
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "response",
                method_label.as_deref(),
                Some(raw_id),
                version,
                audit_verdict,
                shared.dry_run,
                shared.dry_run,
                None,
            );
            if shared.dry_run {
                if on_list_path || internal {
                    return route_tools_list(shared, st, line, parsed, value, None).await;
                }
                apply_response_session_updates(shared, line, entry.as_ref()).await;
                return write_client_frame(&shared.client_out, line).await;
            }
            // A denied response still terminates the original RPC for
            // the client — release the session bookkeeping a forwarded
            // tools/call registered (the trajectory pending call and the
            // deputy pending list) without recording a success; a retry
            // arrives under a new id.
            if let Some(ref e) = entry
                && e.method == "tools/call"
                && let Some(ref session) = shared.session
            {
                let mut state = session.lock().await;
                state.take_pending_list(id);
                state.complete_pending_tool_call(id, false);
            }
            if internal {
                // Our own request got a rejected answer — the listing can
                // never verify; fail closed.
                let block_reason = format!(
                    "internal tools/list response rejected ({})",
                    reason.as_str()
                );
                st.discard_pages();
                shared.list_busy.store(true, Ordering::SeqCst);
                shared.abort_tx.send(true).ok();
                return Err(AuditorError::VerificationFailed(block_reason));
            }
            if on_list_path {
                // Unwind the client-facing pending state, then error.
                shared.pending_tools_list.lock().await.remove(id);
                st.discard_pages();
                {
                    let mut originals = shared.original_tools_list.lock().await;
                    if let Some(client_id) = st.client_id() {
                        originals.remove(client_id);
                    }
                    originals.remove(raw_id);
                }
                shared.list_busy.store(false, Ordering::SeqCst);
                let client_id = st.take_client_id().unwrap_or_else(|| raw_id.to_string());
                write_client_frame(
                    &shared.client_out,
                    &build_jsonrpc_error(
                        &client_id,
                        &format!("tools/list response rejected ({})", reason.as_str()),
                    ),
                )
                .await?;
                return Ok(());
            }
            if had_answered {
                // The client is waiting on this request — answer with an
                // error rather than leave it hanging.
                write_client_frame(
                    &shared.client_out,
                    &build_jsonrpc_error(
                        raw_id,
                        &format!("response rejected ({})", reason.as_str()),
                    ),
                )
                .await?;
            }
            Ok(())
        }
    }
}

/// One server→client request (2025 only — 2026 forbids them). Allowed
/// requests register in the wire table and forward; denied ones get an
/// error back to the server (never generated on a 2026 wire).
async fn s2c_request<W>(
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
    // `classify_frame` already rejected `method`+`result`/`error`
    // hybrids; the Malformed arm routes tracked tools/list ids on them to
    // the verification pipeline's fail-closed path.
    let ext = proxy_rpc::extract_request(value, method);
    let params = ext.params();
    let mut wire = shared.wire.lock().await;
    let version = wire.passive_version();
    let verdict = {
        let msg = proxy_rpc::request_message(version, S2C, method, &ext, &params);
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    match verdict {
        McpVerdict::Allow(_) if !matches!(id, RpcId::Null) => {
            // Commit the forward side effect (`elicitation_pending`)
            // under the same lock as the registration, before the write —
            // a client answer arriving the instant the frame lands must
            // correlate.
            let registered = wire
                .register(
                    S2C,
                    id.clone(),
                    TrackedRequest::from_extracted(method, version, true, shared.dry_run, &ext),
                )
                .map(|()| wire.on_request_forwarded(S2C, id, method, version, &ext));
            drop(wire);
            match registered {
                Ok(undo) => {
                    proxy_rpc::audit_decision(
                        &shared.audit,
                        S2C,
                        "request",
                        Some(method),
                        Some(raw_id),
                        version,
                        verdict,
                        true,
                        shared.dry_run,
                        None,
                    );
                    match write_client_frame(&shared.client_out, line).await {
                        Ok(()) => Ok(()),
                        // The client never saw it — drop the tracking and
                        // the side effect committed with it.
                        Err(e) => {
                            shared.wire.lock().await.rollback_forwarded_request(undo);
                            Err(e)
                        }
                    }
                }
                Err(register_reason) => {
                    proxy_rpc::audit_decision(
                        &shared.audit,
                        S2C,
                        "request",
                        Some(method),
                        Some(raw_id),
                        version,
                        McpVerdict::Deny(DenyReason::Shape),
                        false,
                        shared.dry_run,
                        Some(format!("register={register_reason}")),
                    );
                    // Registration refused — the request cannot be
                    // tracked; answer the server with an error (2025).
                    if version != V26 {
                        write_child_frame(
                            &shared.child_stdin,
                            &build_jsonrpc_error(
                                raw_id,
                                &format!("mcp-writ: request refused ({register_reason})"),
                            ),
                        )
                        .await?;
                    }
                    Ok(())
                }
            }
        }
        _ => {
            drop(wire);
            if shared.dry_run {
                // Dry-run: forward and track as denied so the client's
                // response still correlates.
                let forwarded =
                    forward_denied_s2c(shared, line, method, id, raw_id, version, &ext).await?;
                proxy_rpc::audit_decision(
                    &shared.audit,
                    S2C,
                    "request",
                    Some(method),
                    Some(raw_id),
                    version,
                    verdict,
                    forwarded,
                    shared.dry_run,
                    None,
                );
                return Ok(());
            }
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "request",
                Some(method),
                Some(raw_id),
                version,
                verdict,
                false,
                shared.dry_run,
                None,
            );
            // Denied (or undecidable / null id): answer the server with a
            // JSON-RPC error — but never emit a client→server response on
            // a 2026 wire.
            if version != V26 {
                let reason = match verdict {
                    McpVerdict::Deny(r) => r.as_str(),
                    other => other.reason_code(),
                };
                write_child_frame(
                    &shared.child_stdin,
                    &build_jsonrpc_error(
                        raw_id,
                        &format!("mcp-writ: server request '{method}' denied ({reason})"),
                    ),
                )
                .await?;
            }
            Ok(())
        }
    }
}

/// Dry-run forward of a denied server request: registered with
/// `allowed: false` before the write so the client's answer correlates.
/// Forward-time side effects (`elicitation_pending`) commit under the
/// same lock — a denied `elicitation/create` still reached the client,
/// so its `notifications/elicitation/complete` must resolve. A refused
/// registration (duplicate id / capacity) blocks the forward — the
/// server gets a JSON-RPC error instead of an untracked request — and
/// a failed write unwinds both. Returns whether the request was
/// actually forwarded.
async fn forward_denied_s2c<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    ext: &ExtractedRequest,
) -> Result<bool, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let undo = {
        let mut wire = shared.wire.lock().await;
        match wire.register(
            S2C,
            id.clone(),
            TrackedRequest::from_extracted(method, version, false, true, ext),
        ) {
            Err(reason) => {
                drop(wire);
                if version != V26 {
                    write_child_frame(
                        &shared.child_stdin,
                        &build_jsonrpc_error(
                            raw_id,
                            &format!("mcp-writ: server request refused ({reason})"),
                        ),
                    )
                    .await?;
                }
                return Ok(false);
            }
            Ok(()) => wire.on_request_forwarded(S2C, id, method, version, ext),
        }
    };
    match write_client_frame(&shared.client_out, line).await {
        Ok(()) => Ok(true),
        Err(e) => {
            shared.wire.lock().await.rollback_forwarded_request(undo);
            Err(e)
        }
    }
}

/// CDP path recording + trajectory completion for a forwarded response —
/// only meaningful for tracked `tools/call` answers.
async fn apply_response_session_updates<W>(
    shared: &ProxyShared<W>,
    line: &str,
    entry: Option<&TrackedRequest>,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Some(ref session) = shared.session else {
        return;
    };
    let Some(entry) = entry else { return };
    if entry.method != "tools/call" {
        return;
    }
    // The entry was consumed by `take`; the response id is re-derived.
    let Some(id) = RpcId::from_line(line) else {
        return;
    };
    if matches!(id, RpcId::Null) {
        return;
    }
    let mut state = session.lock().await;
    if state.take_pending_list(&id) {
        let paths = session::extract_paths_from_response(line);
        if !paths.is_empty() {
            tracing::debug!(
                count = paths.len(),
                "Session: recorded paths from list response"
            );
            state.record_paths(&paths);
        }
    }
    if shared.policy.trajectory {
        let parsed = nojson::RawJson::parse(line.trim());
        let succeeded = parsed
            .as_ref()
            .ok()
            .map(|j| j.value())
            .is_some_and(tools_call_result_succeeded);
        state.complete_pending_tool_call(&id, succeeded);
    }
}

/// One `inputRequests` entry's decision — emitted as its own audit record
/// under the original request's correlation id.
struct AdditionalRequestAudit {
    /// Server-assigned map key under `inputRequests` (the retry's
    /// `inputResponses` answers under the same key).
    request_key: Option<String>,
    /// Entry `method` — `None` when the descriptor failed the shape gate.
    method: Option<String>,
    verdict: McpVerdict,
}

/// Emit one `mcp_message.*` record per decided `inputRequests` entry.
/// `forwarded` tracks the frame's disposition (true when the interim
/// result crossed to the client; `dry_run` on a denied forward).
fn audit_additional_requests<W>(
    shared: &ProxyShared<W>,
    entries: &[AdditionalRequestAudit],
    raw_id: &str,
    version: SupportedProtocolVersion,
    forwarded: bool,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    for entry in entries {
        proxy_rpc::audit_decision(
            &shared.audit,
            S2C,
            "additional-request",
            entry.method.as_deref(),
            Some(raw_id),
            version,
            entry.verdict,
            forwarded,
            shared.dry_run,
            entry
                .request_key
                .as_deref()
                .map(|k| format!("request_key={}", proxy_rpc::truncate_for_audit(k))),
        );
    }
}

/// Resolve a `resultType=input_required` interim result to a final verdict
/// by judging every `inputRequests` entry against the tracked original
/// request. Capabilities and the pass-time allow verdict come from
/// `WireState` tracking — never from the frame's own claims.
///
/// One denied or malformed entry rejects the whole response: the set is
/// the server's unit of continuation, and forwarding a subset would
/// rewrite what the client is being asked. With no usable `inputRequests`
/// the interim result must still carry a `requestState` string — a bare
/// `input_required` holds no continuation and fails closed.
fn resolve_input_required(
    policy: &Policy,
    wire: &WireState,
    value: nojson::RawJsonValue<'_, '_>,
    id: &RpcId,
    version: SupportedProtocolVersion,
) -> (McpVerdict, Vec<AdditionalRequestAudit>) {
    // `decide` emitted `Undecided` only for a correlated answer; the
    // tracked entry is re-read rather than trusting that ordering.
    let Some(tracked) = wire.get(C2S, id) else {
        return (McpVerdict::Deny(DenyReason::Uncorrelated), Vec::new());
    };
    let original = OriginalRequestFacts {
        method: tracked.method.as_str(),
        // The raw `allowed` flag — a dry-run forward of a denied request
        // is not a normal pass, and its additional requests stay denied.
        allowed: tracked.allowed,
        client_capabilities: tracked.client_capabilities.as_slice(),
    };
    let Some(result) = value.to_member("result").ok().and_then(|m| m.optional()) else {
        return (McpVerdict::Deny(DenyReason::Shape), Vec::new());
    };
    // `requestState` is an opaque string when present — any other type is
    // malformed outright (never parsed, never trusted), and the same size
    // cap as retry requests applies: the client echoes the blob back in
    // `params.requestState`.
    let oversized_state = result
        .to_member("requestState")
        .ok()
        .and_then(|m| m.optional())
        .is_some_and(|v| checker::request_state_byte_len(v) > checker::REQUEST_STATE_MAX_BYTES);
    if fields::request_state(result) == SchemaField::Invalid || oversized_state {
        return (McpVerdict::Deny(DenyReason::Shape), Vec::new());
    }
    let entries = match fields::input_requests(result) {
        fields::InputRequests::Absent => Vec::new(),
        fields::InputRequests::Map(entries) => entries,
        // A non-map `inputRequests` (e.g. an array) cannot even be
        // iterated — the client has nothing it could lawfully answer.
        fields::InputRequests::Malformed => {
            return (
                McpVerdict::Deny(DenyReason::Shape),
                vec![AdditionalRequestAudit {
                    request_key: None,
                    method: None,
                    verdict: McpVerdict::Deny(DenyReason::Shape),
                }],
            );
        }
    };
    if entries.is_empty() {
        // `requestState`-only is the other valid interim form; with no
        // carrier at all the interim result is indistinguishable from a
        // malformed one.
        return match fields::request_state(result) {
            SchemaField::Valid => (McpVerdict::Allow(AllowReason::ProtocolPass), Vec::new()),
            _ => (McpVerdict::Deny(DenyReason::Shape), Vec::new()),
        };
    }
    let mut audits = Vec::with_capacity(entries.len());
    let mut first_deny = None;
    for entry in &entries {
        let verdict = match entry.method.as_deref() {
            Some(method) => policy.decide_mcp(
                &TrafficMessage::AdditionalRequest(AdditionalRequestMessage {
                    version,
                    method,
                    original,
                }),
                &wire.session_facts(),
            ),
            None => McpVerdict::Deny(DenyReason::Shape),
        };
        if first_deny.is_none() && !matches!(verdict, McpVerdict::Allow(_)) {
            first_deny = Some(verdict);
        }
        audits.push(AdditionalRequestAudit {
            request_key: Some(entry.key.clone()),
            method: entry.method.clone(),
            verdict,
        });
    }
    (
        first_deny.unwrap_or(McpVerdict::Allow(AllowReason::RuleAllow)),
        audits,
    )
}

/// Malformed server frames: drop + audit (never forwarded, never
/// answered).
async fn audit_malformed<W>(shared: &ProxyShared<W>, raw_id: Option<&str>, reason: &str)
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let version = shared.wire.lock().await.wire_version().unwrap_or(V25);
    proxy_rpc::audit_decision(
        &shared.audit,
        S2C,
        "malformed",
        None,
        raw_id,
        version,
        McpVerdict::Deny(DenyReason::Shape),
        false,
        shared.dry_run,
        Some(format!("malformed={reason}")),
    );
}
