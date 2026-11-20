//! Forward/deny machinery for the client-to-server direction: the shared
//! write path for allowed requests, tools/list arming, request
//! bookkeeping, and the per-request session gates that run before a
//! frame crosses to the child.

use std::sync::atomic::Ordering;

use uuid::Uuid;

use super::C2S;
use crate::audit_log::{Action, AuditEvent, EventType, Outcome, Severity};
use crate::auditor::checker;
use crate::auditor::proxy_rpc::{self, ExtractedRequest};
use crate::auditor::proxy_state::ProxyShared;
use crate::auditor::proxy_wire::{
    build_error_response, build_jsonrpc_error, deny_explanation, extract_tool_name_from_json,
    join_audit_details, write_client_frame,
};
use crate::auditor::session::RpcId;
use crate::error::AuditorError;
use crate::policy::mcp::{DenyReason, McpVerdict};
use crate::protocol::SupportedProtocolVersion;

mod register;
mod session_gates;
mod tools_list;

use register::{register_and_forward, register_and_forward_denied};
use session_gates::apply_session_gates;
use tools_list::{arm_tools_list, unwind_tools_list};
pub(super) async fn wire_version_or_default<W>(shared: &ProxyShared<W>) -> SupportedProtocolVersion
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
/// a JSON-RPC error. Under `--dry-run` a *tool authorization* denial —
/// `tools/call` refused by the allow/deny atoms — still forwards and is
/// registered with `allowed: false` so its response cannot pose as a
/// genuine completion; every other denial (lifecycle, capability, URI,
/// shape, non-tool methods) stays enforced exactly as in enforce mode.
#[expect(clippy::too_many_arguments)]
pub(super) async fn deny_request<W>(
    shared: &ProxyShared<W>,
    view: &checker::VerifiedFrame<'_>,
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
    if method == "tools/call"
        && let Some(tool) = extract_tool_name_from_json(view.json())
    {
        shared.tally.lock().unwrap().record_call(&tool);
    }
    if shared.dry_run && dry_run_observable(method, &verdict) {
        // The deny decision is send-ordered ahead of the observed
        // forward — even a denied-tracked frame must not cross ahead of
        // its record. Registration still marks it not-allowed so an
        // answering frame is correlation-checked.
        proxy_rpc::audit_forwarded_decision(
            &shared.audit,
            C2S,
            "request",
            Some(method),
            Some(raw_id),
            version,
            verdict,
            shared.dry_run,
            request_extra(ext),
        )
        .await?;
        match register_and_forward_denied(shared, view, method, id, raw_id, version, ext, None)
            .await
        {
            Ok(true) => return Ok(()),
            result => {
                // Skipped for `DeliveryUncertain` — the complete frame
                // may still have crossed, so "not forwarded" is
                // unprovable. `Ok(false)` refusal and proven write
                // failures still reconcile.
                if !matches!(result, Err(AuditorError::DeliveryUncertain(_))) {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        C2S,
                        "request",
                        Some(method),
                        Some(raw_id),
                        version,
                        verdict,
                        shared.dry_run,
                        request_extra(ext),
                    );
                }
                return result.map(|_| ());
            }
        }
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
    )?;
    let text = match verdict {
        McpVerdict::Deny(r) => match deny_explanation(r, method, C2S) {
            Some(text) => text,
            None => format!("{message} ({})", r.as_str()),
        },
        other => format!("{message} ({})", other.reason_code()),
    };
    if matches!(verdict, McpVerdict::Deny(DenyReason::InitOrder))
        && !shared.init_order_warned.swap(true, Ordering::SeqCst)
    {
        // Per-request warns would flood stderr on a mis-ordering
        // client — the wire error repeats on every denial, so the
        // stderr diagnostic logs once per session.
        tracing::warn!("client→server: {text}");
    }
    write_client_frame(&shared.client_out, &build_jsonrpc_error(raw_id, &text)).await
}

/// Dry-run observes only a genuine tool authorization verdict —
/// `tools/call` refused by the allow/deny atoms — and forwards it so the
/// denial lands in the audit trail against real traffic. Everything
/// else (lifecycle, capability, shape/meta, URI, subscription, non-tool
/// authorization, other methods) stays enforced: observing it would
/// forward traffic the protocol itself forbids, and a `tools/call`
/// refused for structural reasons is a protocol violation, not a policy
/// judgement worth observing.
pub(super) fn dry_run_observable(method: &str, verdict: &McpVerdict) -> bool {
    method == "tools/call"
        && matches!(
            verdict,
            McpVerdict::Deny(DenyReason::NoRule | DenyReason::RuleDeny)
        )
}

/// Audit detail: request-declared capabilities / progressToken / logLevel.
pub(super) fn request_extra(ext: &ExtractedRequest) -> Option<String> {
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
#[expect(clippy::too_many_arguments)]
pub(super) async fn forward_allowed<W>(
    shared: &ProxyShared<W>,
    view: &checker::VerifiedFrame<'_>,
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
        let tool = extract_tool_name_from_json(view.json());
        if let Some(tool) = tool.as_deref() {
            shared.tally.lock().unwrap().record_call(tool);
        }
        // Verified-generation capture (F10): when manifest scanning or a
        // `tools-list-hash` pin enforces the manifest, a call may only
        // run against a published verified set. `0` means none
        // ever verified — fail closed. The captured generation is
        // re-checked immediately before the child write inside
        // `register_and_forward_impl`, closing the window where a
        // `list_changed` revalidation begins mid-authorization. The
        // advertised-name membership check runs on the allowed arm
        // below, after the richer policy/session denials keep their
        // own reasons.
        let expected_list_gen = if crate::auditor::proxy_state::list_verification_required(
            &shared.policy,
            shared.fail_on,
        ) {
            let generation = shared.verified_tools.lock().unwrap().generation;
            if generation == 0 {
                deny_busy_tools_call(
                    shared,
                    raw_id,
                    tool.as_deref(),
                    "no verified tools/list has been published yet",
                    None,
                    false,
                )
                .await?;
                return Ok(());
            }
            Some(generation)
        } else {
            None
        };
        if shared.list_busy.load(Ordering::SeqCst) {
            deny_busy_tools_call(
                shared,
                raw_id,
                tool.as_deref(),
                "tools/list revalidation in progress",
                None,
                false,
            )
            .await?;
            return Ok(());
        }
        // Registration eligibility must be validated before any session
        // bookkeeping or the `ToolCallAllowed` record — those commit
        // under this id, and a refused request's deny/rollback would
        // release records the request already carrying it owns (and log
        // an allowed event for a request that never forwarded). The
        // check is advisory: `register` under the lock stays
        // authoritative, and its refusal still unwinds the gates.
        // Release the wire guard before the denial path — `deny_request`
        // re-locks `shared.wire` (dry-run forwards arm tools/list
        // bookkeeping), and an `if let` scrutinee temporary would hold
        // it across the await into a non-reentrant re-lock.
        let eligibility = shared.wire.lock().await.can_register(C2S, id);
        if let Err(reason) = eligibility {
            return deny_request(
                shared,
                view,
                method,
                id,
                raw_id,
                version,
                &ext,
                McpVerdict::Deny(DenyReason::Shape),
                &format!("request denied ({reason})"),
            )
            .await;
        }
        let check_result = checker::check_request_verified(view, &shared.policy);
        let check_result =
            apply_session_gates(shared, check_result, view, id, tool.as_deref()).await;
        return match check_result {
            Ok(check_pass) => {
                // F6: among calls the policy allows, only names the
                // verified listing actually advertised to this client
                // may forward — a statically allowed tool the server
                // omitted must not keep an authorized channel. Membership
                // is bound to the captured generation under the same
                // lock, so the pair can never straddle a publish.
                if let Some(expected) = expected_list_gen {
                    let advertised = {
                        let vt = shared.verified_tools.lock().unwrap();
                        vt.generation == expected
                            && tool.as_deref().is_some_and(|name| vt.names.contains(name))
                    };
                    if !advertised {
                        if let Some(ref session) = shared.session {
                            let mut state = session.lock().await;
                            state.take_pending_list(id);
                            state.complete_pending_tool_call(id, false);
                        }
                        // Wire text must not reveal that the name is
                        // policy-allowed but unadvertised — that probes
                        // policy membership through tools/call. The
                        // advertised-set detail stays in the audit
                        // record.
                        deny_busy_tools_call(
                            shared,
                            raw_id,
                            tool.as_deref(),
                            crate::auditor::checker::REASON_TOOL_NOT_ALLOWED,
                            Some(&format!(
                                "tool '{}' is not advertised by the verified tools/list",
                                tool.as_deref().unwrap_or("<unknown>")
                            )),
                            true,
                        )
                        .await?;
                        return Ok(());
                    }
                }
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
                match register_and_forward(
                    shared,
                    view,
                    method,
                    id,
                    raw_id,
                    version,
                    verdict,
                    &ext,
                    expected_list_gen,
                )
                .await
                {
                    Ok(true) => Ok(()),
                    result => {
                        // Registration refused or the write failed — no
                        // response will ever close the session entries
                        // `apply_session_gates` recorded, so drop them.
                        if let Some(ref session) = shared.session {
                            let mut state = session.lock().await;
                            state.take_pending_list(id);
                            // A write whose delivery is unprovable may
                            // still have crossed — the call keeps an
                            // unverified candidate rather than resolving
                            // as proven non-execution.
                            if matches!(result, Err(AuditorError::DeliveryUncertain(_))) {
                                state.release_pending_tool_call_unverified(id);
                            } else {
                                state.complete_pending_tool_call(id, false);
                            }
                        }
                        result.map(|_| ())
                    }
                }
            }
            Err(violation) => {
                // The classified `raw_id` is the request's `id` literal —
                // no member re-extraction from the frame is needed.
                let request_id = Some(raw_id.to_string());
                // Dry-run observes the tool violation — except the one
                // refusal that exists only to keep a blob off the wire:
                // forwarding an over-cap requestState defeats the cap
                // outright.
                let observe =
                    shared.dry_run && checker::request_state_over_cap_json(view.json()).is_none();
                // A refused request carries no session bookkeeping: the
                // gates record pending entries only on their success
                // path, and the one partial record a mid-sequence
                // refusal can leave (the deputy pending list ahead of
                // the trajectory pending call) is rolled back inside
                // `apply_session_gates` — scoped to entries *this* call
                // created so a denied duplicate can never release an
                // earlier in-flight call's discovery credit.
                // In dry-run the request still forwards, so any response
                // path consumes whatever it legitimately registered.
                let correlation_id = Uuid::now_v7();
                let action = if observe {
                    Action::Observed
                } else {
                    Action::Denied
                };
                // A user-space validation refusal (traversal, args_schema)
                // also gets its typed `validation.*` record under the
                // same correlation id — the `validation` category stays
                // queryable instead of folding silently into the deny.
                if let Some(kind) = violation.validation_kind() {
                    let severity = match kind {
                        EventType::ValidationPathTraversal => Severity::High,
                        _ => Severity::Medium,
                    };
                    let mut validation =
                        AuditEvent::new(correlation_id, kind, severity, Outcome::Failure, action);
                    validation.target_tool = Some(violation.tool_name.clone());
                    validation.request_id = request_id
                        .clone()
                        .map(|id| proxy_rpc::truncate_for_audit(&id));
                    validation.details = Some(violation.reason.clone());
                    shared.audit.log(validation);
                }
                let mut event = AuditEvent::new(
                    correlation_id,
                    EventType::ToolCallDenied,
                    Severity::High,
                    Outcome::Failure,
                    action,
                );
                event.target_tool = Some(violation.tool_name.clone());
                let id_str = request_id.clone().unwrap_or_else(|| "null".to_string());
                event.request_id = request_id.map(|id| proxy_rpc::truncate_for_audit(&id));
                event.details = Some(violation.reason.clone());
                // The violation record is the authoritative audit for the
                // request's fate — it must be durable *before* a dry-run
                // forward reaches the server (or the client learns the
                // refusal). A refused commit propagates: the violating
                // request never crosses unaudited.
                shared.audit.log_committed(event).await?;
                // Recorded for both fates: a dry-run observation is
                // exactly the evidence the report's widening
                // candidates are computed from, and an enforced
                // denial is the same evidence after the fact.
                // Only target-policy denials land — the tally's
                // documented contract. Tool-level authorization
                // refusals, args_schema validation failures, and
                // session-state refusals are not targets a wider
                // grant could answer.
                if violation.is_denied_target() {
                    shared
                        .tally
                        .lock()
                        .unwrap()
                        .record_denial(&violation.tool_name, &violation.reason);
                }
                // Tool name and reason are client-controlled — escape
                // terminal controls before they reach a TTY log.
                if observe {
                    tracing::warn!(
                        tool = %crate::termutil::sanitize_for_terminal(&violation.tool_name),
                        reason = %crate::termutil::sanitize_for_terminal(&violation.reason),
                        "[DRY-RUN] Policy violation detected, forwarding request"
                    );
                    register_and_forward_denied(
                        shared,
                        view,
                        method,
                        id,
                        raw_id,
                        version,
                        &ext,
                        expected_list_gen,
                    )
                    .await?;
                } else {
                    tracing::warn!(
                        tool = %crate::termutil::sanitize_for_terminal(&violation.tool_name),
                        reason = %crate::termutil::sanitize_for_terminal(&violation.reason),
                        "Policy violation: blocking tools/call"
                    );
                    // The wire reason must not reveal whether the name
                    // exists in the policy — `client_reason` collapses
                    // the hidden/unknown distinction; `violation.reason`
                    // keeps the detail for the audit record above.
                    let error_response = build_error_response(
                        &id_str,
                        &violation.tool_name,
                        violation.client_reason(),
                        violation.is_authorization_denial(),
                    );
                    write_client_frame(&shared.client_out, &error_response).await?;
                }
                Ok(())
            }
        };
    }

    // ── MRTR `params.requestState` cap — the tools/call checker enforces
    //    it on its own path; every other allowed request caps here so a
    //    retry blob stays bounded on any method. ──
    if let Some(size) = checker::request_state_over_cap_json(view.json()) {
        return deny_request(
            shared,
            view,
            method,
            id,
            raw_id,
            version,
            &ext,
            McpVerdict::Deny(DenyReason::Shape),
            &format!(
                "request '{method}' denied by MCP policy: requestState exceeds size cap ({size} > {} bytes)",
                checker::REQUEST_STATE_MAX_BYTES
            ),
        )
        .await;
    }

    // ── tools/list bookkeeping: bounded pending set + template capture ──
    if method == "tools/list" {
        if !arm_tools_list(shared, view, id, raw_id, version).await? {
            return Ok(());
        }
        // The revalidation template is published inside
        // `register_and_forward` immediately before the request becomes
        // answerable — after its bytes crossed, inside the same
        // `list_epoch` section — so a direct or queued revalidation can
        // never observe the prior listing's params for this request,
        // and a refused or unwritten request can never seed it.
        return match register_and_forward(
            shared, view, method, id, raw_id, version, verdict, &ext, None,
        )
        .await
        {
            Ok(true) => Ok(()),
            result => {
                unwind_tools_list(shared, id, raw_id).await;
                match result {
                    Ok(false) => Ok(()),
                    Err(e) => Err(e),
                    Ok(true) => unreachable!(),
                }
            }
        };
    }

    register_and_forward(
        shared, view, method, id, raw_id, version, verdict, &ext, None,
    )
    .await
    .map(|_| ())
}

/// The tools/call denial while the verified-list gate is closed — a
/// revalidation in flight or (when verification is enforced) no
/// verified listing published yet. `reason` is the client-facing text;
/// `audit_reason` carries the detail for the audit record when the wire
/// text must stay membership-blind (an allowed-but-unadvertised name
/// must read exactly like a denied or unknown one). `tool_denied`
/// selects the authorization-refusal lead for that unadvertised-name
/// refusal — it is an authorization denial, not a call-level one, so
/// the wire wording stays identical to a policy allow/deny refusal.
pub(super) async fn deny_busy_tools_call<W>(
    shared: &ProxyShared<W>,
    raw_id: &str,
    tool: Option<&str>,
    reason: &str,
    audit_reason: Option<&str>,
    tool_denied: bool,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let tool = tool.unwrap_or("<unknown>");
    let error_response = build_error_response(raw_id, tool, reason, tool_denied);
    write_client_frame(&shared.client_out, &error_response).await?;
    let correlation_id = Uuid::now_v7();
    let mut event = AuditEvent::new(
        correlation_id,
        EventType::ToolCallDenied,
        Severity::High,
        Outcome::Failure,
        Action::Denied,
    );
    event.target_tool = Some(tool.to_string());
    event.request_id = Some(proxy_rpc::truncate_for_audit(raw_id));
    event.details = Some(audit_reason.unwrap_or(reason).to_string());
    shared.audit.log(event);
    Ok(())
}

#[cfg(test)]
mod tests;
