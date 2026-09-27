//! Client→server direction of `run_proxy`: frame classification, MCP
//! decision enforcement, legacy tools/call / tools/list policy checks,
//! trajectory / Confused Deputy session accounting, and forwarding.
//!
//! Every frame is classified (request / notification / response) and
//! decided through `Policy::decide_mcp` before it crosses the wire:
//! denied requests get a JSON-RPC error, denied notifications are
//! dropped, and malformed frames are never forwarded.

use std::sync::atomic::Ordering;

use tokio::io::BufReader;

use uuid::Uuid;

use super::checker;
use super::proxy_rpc::{self, ExtractedRequest, TrackedRequest, WireFrame};
use super::proxy_state::ProxyShared;
use super::proxy_wire::{
    build_error_response, build_jsonrpc_error, extract_raw_id, extract_tool_name_from_line,
    join_audit_details, read_proxy_line, write_child_frame, write_client_frame,
};
use super::session::{RpcId, SessionState};
use crate::audit_log::{Action, AuditEvent, EventType, Outcome, Severity};
use crate::error::AuditorError;
use crate::policy::Policy;
use crate::policy::mcp::{DenyReason, McpVerdict};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

const C2S: MessageDirection = MessageDirection::ClientToServer;
const S2C: MessageDirection = MessageDirection::ServerToClient;
const V26: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2026July28;

/// Client → Server direction.
///
/// Each stdin line is parsed once, classified, and decided. Allowed
/// requests are registered in the shared wire table so responses in the
/// opposite direction can correlate; denied ones are answered with a
/// JSON-RPC error (or forwarded-but-tracked under `--dry-run`). Allowed
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

    loop {
        shared.audit.ensure_available()?;
        let next_line_future = read_proxy_line(&mut reader);
        let line_opt = tokio::select! {
            res = abort_rx.changed() => {
                if res.is_ok() && *abort_rx.borrow() {
                    tracing::error!("session aborted due to S2C verification failure; stopping C2S immediately");
                    return Err(AuditorError::VerificationFailed("session aborted on server→client verification".to_string()));
                }
                continue;
            }
            res = next_line_future => res?
        };

        match line_opt {
            Some(line) => {
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
            None => {
                // AsyncWrite::shutdown is only a flush for tokio::fs::File
                // (Windows pipes). Drop the writer to deliver EOF instead.
                shared.child_stdin.lock().await.take();
                break;
            }
        }
    }
    Ok(())
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
    );
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
            wire.on_notification_forwarded(C2S, version, method, &ext);
            drop(wire);
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                true,
                shared.dry_run,
                None,
            );
            write_child_frame(&shared.child_stdin, line).await
        }
        McpVerdict::Drop(_) => {
            drop(wire);
            let forward = shared.dry_run;
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
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
                // Dry-run: observe the drop, forward anyway, and keep the
                // tracking effects honest — the server saw it.
                let mut wire = shared.wire.lock().await;
                wire.on_notification_forwarded(C2S, version, method, &ext);
                drop(wire);
                write_child_frame(&shared.child_stdin, line).await?;
            }
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
            );
            Ok(())
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
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "response",
                entry.as_ref().map(|e| e.method.as_str()),
                Some(raw_id),
                version,
                verdict,
                true,
                shared.dry_run,
                None,
            );
            write_child_frame(&shared.child_stdin, line).await
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
            let forward = shared.dry_run;
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "response",
                entry.as_ref().map(|e| e.method.as_str()),
                Some(raw_id),
                version,
                verdict,
                forward,
                shared.dry_run,
                None,
            );
            if forward {
                write_child_frame(&shared.child_stdin, line).await?;
            } else if had_entry && !version_v26 {
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

    let params = ext.params();
    let (version, verdict) = {
        let wire = shared.wire.lock().await;
        let classified = wire.request_version(method, ext.meta_declares_version);
        let version = classified.unwrap_or(V26);
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
async fn wire_version_or_default<W>(shared: &ProxyShared<W>) -> SupportedProtocolVersion
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    shared
        .wire
        .lock()
        .await
        .wire_version()
        .unwrap_or(SupportedProtocolVersion::Mcp2025November25)
}

/// Deny a client request: audit the decision, then answer the client with
/// a JSON-RPC error. Under `--dry-run` the request forwards anyway and is
/// registered with `allowed: false` so its response cannot pose as a
/// genuine completion.
#[allow(clippy::too_many_arguments)]
async fn deny_request<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    ext: &ExtractedRequest,
    verdict: McpVerdict,
    message: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if shared.dry_run {
        // Register the denied request as not-allowed so an answering
        // frame is still correlation-checked.
        let forwarded =
            register_and_forward_denied(shared, line, method, id, raw_id, version, ext).await?;
        proxy_rpc::audit_decision(
            &shared.audit,
            C2S,
            "request",
            Some(method),
            Some(raw_id),
            version,
            verdict,
            forwarded,
            shared.dry_run,
            request_extra(ext),
        );
        return Ok(());
    }
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
        request_extra(ext),
    );
    let reason = match verdict {
        McpVerdict::Deny(r) => r.as_str(),
        other => other.reason_code(),
    };
    write_client_frame(
        &shared.client_out,
        &build_jsonrpc_error(raw_id, &format!("{message} ({reason})")),
    )
    .await
}

/// Audit detail: request-declared capabilities / progressToken / logLevel.
fn request_extra(ext: &ExtractedRequest) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(meta) = &ext.meta {
        if !meta.client_capabilities.is_empty() {
            parts.push(format!("caps={}", meta.client_capabilities.join(",")));
        }
        if let Some(level) = &meta.log_level {
            parts.push(format!("log_level={level}"));
        }
    }
    if ext.progress_token.is_some() {
        parts.push("progress_token=present".to_string());
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// An allowed client request: run the legacy tools/call gates and the
/// tools/list bookkeeping, then register in the wire table and forward.
/// `verdict` is the `decide` result being enforced — it is recorded in
/// the decision audit when the request actually forwards.
#[allow(clippy::too_many_arguments)]
async fn forward_allowed<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    ext: ExtractedRequest,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // ── tools/call legacy gates: list-busy, tool policy, session ──
    if method == "tools/call" {
        if shared.list_busy.load(Ordering::SeqCst) {
            deny_busy_tools_call(shared, raw_id, line).await?;
            return Ok(());
        }
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
                let correlation_id = Uuid::now_v7();
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallAllowed,
                    Severity::Info,
                    Outcome::Success,
                    Action::Allowed,
                );
                event.target_tool = tool;
                event.details =
                    join_audit_details(check_pass.sub_policy.as_deref(), &check_pass.audit_notes);
                shared.audit.log_committed(event).await?;
                register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
                    .await
                    .map(|_| ())
            }
            Err(violation) => {
                let request_id = extract_raw_id(line);
                if shared.dry_run {
                    tracing::warn!(
                        tool = %violation.tool_name,
                        reason = %violation.reason,
                        "[DRY-RUN] Policy violation detected, forwarding request"
                    );
                    register_and_forward_denied(shared, line, method, id, raw_id, version, &ext)
                        .await?;
                } else {
                    tracing::warn!(
                        tool = %violation.tool_name,
                        reason = %violation.reason,
                        "Policy violation: blocking tools/call"
                    );
                    let id_str = request_id.clone().unwrap_or_else(|| "null".to_string());
                    let error_response =
                        build_error_response(&id_str, &violation.tool_name, &violation.reason);
                    write_client_frame(&shared.client_out, &error_response).await?;
                }
                let correlation_id = Uuid::now_v7();
                let action = if shared.dry_run {
                    Action::Observed
                } else {
                    Action::Denied
                };
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallDenied,
                    Severity::High,
                    Outcome::Failure,
                    action,
                );
                event.target_tool = Some(violation.tool_name.clone());
                event.request_id = request_id;
                event.details = Some(violation.reason.clone());
                shared.audit.log(event);
                shared.audit.ensure_available()?;
                Ok(())
            }
        };
    }

    // ── tools/list bookkeeping: bounded pending set + template capture ──
    if method == "tools/list" {
        if shared.list_busy.load(Ordering::SeqCst) {
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "request",
                Some(method),
                Some(raw_id),
                version,
                McpVerdict::Deny(DenyReason::Shape),
                false,
                shared.dry_run,
                Some("tools/list already in progress".to_string()),
            );
            write_client_frame(
                &shared.client_out,
                &build_jsonrpc_error(raw_id, "tools/list already in progress"),
            )
            .await?;
            return Ok(());
        }
        let accepted = shared
            .pending_tools_list
            .lock()
            .await
            .try_insert(id.clone());
        if !accepted {
            tracing::warn!("rejecting tools/list: duplicate or too many unanswered ids");
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "request",
                Some(method),
                Some(raw_id),
                version,
                McpVerdict::Deny(DenyReason::Shape),
                false,
                shared.dry_run,
                Some("duplicate or too many unanswered tools/list requests".to_string()),
            );
            write_client_frame(
                &shared.client_out,
                &build_jsonrpc_error(
                    raw_id,
                    "duplicate or too many unanswered tools/list requests",
                ),
            )
            .await?;
            return Ok(());
        }
        shared.list_busy.store(true, Ordering::SeqCst);
        *shared.last_list_template.lock().await = line.to_string();
        shared
            .original_tools_list
            .lock()
            .await
            .insert(raw_id.to_string(), line.to_string());
        return match register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
            .await
        {
            Ok(true) => Ok(()),
            result => {
                // Registration refused or write failed: unwind the
                // pending bookkeeping so the session is not left busy.
                shared.pending_tools_list.lock().await.remove(id);
                shared.original_tools_list.lock().await.remove(raw_id);
                shared.list_busy.store(false, Ordering::SeqCst);
                match result {
                    Ok(false) => Ok(()),
                    Err(e) => Err(e),
                    Ok(true) => unreachable!(),
                }
            }
        };
    }

    register_and_forward(shared, line, method, id, raw_id, version, verdict, &ext)
        .await
        .map(|_| ())
}

/// Register in the wire table, apply forward-time side effects, write.
/// Side effects commit under the same lock as the registration so a
/// response that lands the instant the write completes already sees
/// them; a failed write unwinds both so the table never tracks a
/// request the server did not see. Returns `Ok(false)` when registration
/// refused the request (duplicate id / capacity) — the client already
/// got an error; callers with bookkeeping must unwind.
#[allow(clippy::too_many_arguments)]
async fn register_and_forward<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    ext: &ExtractedRequest,
) -> Result<bool, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    register_and_forward_impl(
        shared,
        line,
        method,
        id,
        raw_id,
        version,
        ext,
        true,
        Some(verdict),
    )
    .await
}

/// Dry-run forward of a denied request: tracked with `allowed: false`.
/// The caller audits the deny verdict itself, once the forward result
/// is known.
async fn register_and_forward_denied<W>(
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
    register_and_forward_impl(shared, line, method, id, raw_id, version, ext, false, None).await
}

/// `audit_verdict` is `Some` only for policy-allowed forwards — the
/// decision (or a registration refusal) is recorded here. Denied
/// dry-run forwards pass `None`; their caller owns the audit record.
#[allow(clippy::too_many_arguments)]
async fn register_and_forward_impl<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    ext: &ExtractedRequest,
    allowed: bool,
    audit_verdict: Option<McpVerdict>,
) -> Result<bool, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let undo = {
        let mut wire = shared.wire.lock().await;
        match wire.register(
            C2S,
            id.clone(),
            TrackedRequest::from_extracted(method, version, allowed, shared.dry_run, ext),
        ) {
            Err(reason) => {
                drop(wire);
                if audit_verdict.is_some() {
                    // Registration refused an allowed request (duplicate
                    // id / capacity) — audit it like the S2C direction.
                    proxy_rpc::audit_decision(
                        &shared.audit,
                        C2S,
                        "request",
                        Some(method),
                        Some(raw_id),
                        version,
                        McpVerdict::Deny(DenyReason::Shape),
                        false,
                        shared.dry_run,
                        Some(format!("register={reason}")),
                    );
                }
                write_client_frame(
                    &shared.client_out,
                    &build_jsonrpc_error(raw_id, &format!("request denied ({reason})")),
                )
                .await?;
                return Ok(false);
            }
            Ok(()) => wire.on_request_forwarded(C2S, id, method, version, ext),
        }
    };
    let result = write_child_frame(&shared.child_stdin, line).await;
    if let Some(verdict) = audit_verdict {
        // Recorded only once the write outcome is known: `forwarded` is
        // the wire truth, so a failed write logs a distinct
        // not-forwarded record rather than a false allow.
        proxy_rpc::audit_decision(
            &shared.audit,
            C2S,
            "request",
            Some(method),
            Some(raw_id),
            version,
            verdict,
            result.is_ok(),
            shared.dry_run,
            request_extra(ext),
        );
    }
    match result {
        Ok(()) => Ok(true),
        Err(e) => {
            // The request never reached the server: unwind the
            // registration and the side effects committed with it.
            shared.wire.lock().await.rollback_forwarded_request(undo);
            Err(e)
        }
    }
}

/// The existing list-busy denial for a tools/call mid-revalidation.
async fn deny_busy_tools_call<W>(
    shared: &ProxyShared<W>,
    raw_id: &str,
    line: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let tool = extract_tool_name_from_line(line).unwrap_or_else(|| "<unknown>".into());
    let reason = "tools/list revalidation in progress";
    let error_response = build_error_response(raw_id, &tool, reason);
    write_client_frame(&shared.client_out, &error_response).await?;
    let correlation_id = Uuid::now_v7();
    let mut event = AuditEvent::new(
        correlation_id,
        EventType::ToolCallDenied,
        Severity::High,
        Outcome::Failure,
        Action::Denied,
    );
    event.target_tool = Some(tool);
    event.request_id = Some(raw_id.to_string());
    event.details = Some(reason.to_string());
    shared.audit.log(event);
    Ok(())
}

/// The legacy per-session gates for an allowed `tools/call`: trajectory
/// check, then Confused Deputy, then pending-call registration. Mirrors
/// the pre-PR-10 ordering.
async fn apply_session_gates<W>(
    shared: &ProxyShared<W>,
    check_result: Result<checker::CheckPass, checker::PolicyViolation>,
    line: &str,
    id: &RpcId,
) -> Result<checker::CheckPass, checker::PolicyViolation>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(check_pass) = check_result else {
        return check_result;
    };
    let Some(ref session) = shared.session else {
        return Ok(check_pass);
    };
    let mut state = session.lock().await;
    let tool = extract_tool_name_from_line(line);
    if shared.policy.trajectory
        && let Err(violation) = checker::check_trajectory(line, &shared.policy, &state)
    {
        return Err(violation);
    }
    apply_confused_deputy_c2s(&shared.policy, &mut state, line, Some(id), tool.as_deref())?;
    if shared.policy.trajectory {
        let se = tool
            .as_deref()
            .and_then(|name| checker::tool_side_effect(&shared.policy, name));
        if let Err(reason) =
            state.record_pending_tool_call(id.clone(), tool.as_deref().unwrap_or("<unknown>"), se)
        {
            return Err(checker::PolicyViolation {
                tool_name: tool.unwrap_or_else(|| "<unknown>".into()),
                reason: format!("trajectory: {reason}"),
            });
        }
    }
    Ok(check_pass)
}

fn apply_confused_deputy_c2s(
    policy: &Policy,
    state: &mut SessionState,
    line: &str,
    envelope_id: Option<&RpcId>,
    tool: Option<&str>,
) -> Result<(), checker::PolicyViolation> {
    if !policy.confused_deputy_protection {
        return Ok(());
    }
    match tool {
        Some("list_files") | Some("list_directory") => {
            if matches!(envelope_id, Some(&RpcId::Null)) {
                return Err(checker::PolicyViolation {
                    tool_name: tool.unwrap_or("list_files").to_string(),
                    reason: "confused deputy: JSON-RPC id must not be null".to_string(),
                });
            }
            if let Some(id) = envelope_id
                && let Err(reason) =
                    state.record_pending_list(id.clone(), tool.unwrap_or("list_files"))
            {
                return Err(checker::PolicyViolation {
                    tool_name: tool.unwrap_or("list_files").to_string(),
                    reason: format!("confused deputy: {reason}"),
                });
            }
            Ok(())
        }
        Some("read_file") => {
            let paths = checker::extract_fs_targets(line);
            if paths.is_empty() {
                return Err(checker::PolicyViolation {
                    tool_name: "read_file".to_string(),
                    reason: "confused deputy: read_file is missing a resolvable path target"
                        .to_string(),
                });
            }
            for path in &paths {
                if let Err(reason) = state.check_access(path) {
                    return Err(checker::PolicyViolation {
                        tool_name: "read_file".to_string(),
                        reason: format!("confused deputy: {reason}"),
                    });
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
