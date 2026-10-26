//! Forward/deny machinery for the client-to-server direction: the shared
//! write path for allowed requests, tools/list arming, request
//! bookkeeping, and the per-request session gates that run before a
//! frame crosses to the child.

use std::sync::atomic::Ordering;

use uuid::Uuid;

use super::C2S;
use crate::audit_log::{Action, AuditEvent, EventType, Outcome, Severity};
use crate::auditor::checker;
use crate::auditor::proxy_rpc::{self, ExtractedRequest, TrackedRequest};
use crate::auditor::proxy_state::{MAX_ORIGINAL_TOOLS_LIST_BYTES, ProxyShared};
use crate::auditor::proxy_wire::{
    build_error_response, build_jsonrpc_error, deny_explanation, extract_raw_id,
    extract_tool_name_from_line, join_audit_details, write_child_frame, write_client_frame,
};
use crate::auditor::session::{RpcId, SessionState};
use crate::error::AuditorError;
use crate::policy::Policy;
use crate::policy::mcp::{DenyReason, McpVerdict};
use crate::protocol::SupportedProtocolVersion;

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
        match register_and_forward_denied(shared, line, method, id, raw_id, version, ext, None)
            .await
        {
            Ok(true) => return Ok(()),
            result => {
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
        McpVerdict::Deny(r) => match deny_explanation(r, method) {
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
                    line,
                    "no verified tools/list has been published yet",
                    None,
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
                line,
                "tools/list revalidation in progress",
                None,
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
                line,
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
        let check_result = checker::check_request(line, &shared.policy);
        let check_result = apply_session_gates(shared, check_result, line, id).await;
        return match check_result {
            Ok(check_pass) => {
                let tool = extract_tool_name_from_line(line);
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
                            line,
                            crate::auditor::checker::REASON_TOOL_NOT_ALLOWED,
                            Some(&format!(
                                "tool '{}' is not advertised by the verified tools/list",
                                tool.as_deref().unwrap_or("<unknown>")
                            )),
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
                    line,
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
                            state.complete_pending_tool_call(id, false);
                        }
                        result.map(|_| ())
                    }
                }
            }
            Err(violation) => {
                let request_id = extract_raw_id(line);
                // Dry-run observes the tool violation — except the one
                // refusal that exists only to keep a blob off the wire:
                // forwarding an over-cap requestState defeats the cap
                // outright.
                let observe = shared.dry_run && checker::request_state_over_cap(line).is_none();
                if !observe {
                    // Session gates may have partially registered (the
                    // deputy pending list runs before the trajectory
                    // pending call): release whatever was recorded — the
                    // denied request never completes its own RPC. In
                    // dry-run the request still forwards, so the response
                    // path consumes the entries instead.
                    if let Some(ref session) = shared.session {
                        let mut state = session.lock().await;
                        state.take_pending_list(id);
                        state.complete_pending_tool_call(id, false);
                    }
                }
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
                        line,
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
    if let Some(size) = checker::request_state_over_cap(line) {
        return deny_request(
            shared,
            line,
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
        if !arm_tools_list(shared, line, id, raw_id, version).await? {
            return Ok(());
        }
        return match register_and_forward(
            shared, line, method, id, raw_id, version, verdict, &ext, None,
        )
        .await
        {
            Ok(true) => Ok(()),
            result => {
                // Registration refused or write failed: unwind the
                // pending bookkeeping so the session is not left busy.
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
        shared, line, method, id, raw_id, version, verdict, &ext, None,
    )
    .await
    .map(|_| ())
}

/// Arm the client-facing tracking a forwarded `tools/list` needs on the
/// response side: the bounded pending-id set, the busy gate, the request
/// template internal pagination rebuilds from, and the original request
/// keyed by raw id. Returns `true` when armed; on contention the entry
/// is unwound, the refusal audited, and the client answered — the
/// request is not forwarded either way.
pub(super) async fn arm_tools_list<W>(
    shared: &ProxyShared<W>,
    line: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
) -> Result<bool, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
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
            Some("tools/list"),
            Some(raw_id),
            version,
            McpVerdict::Deny(DenyReason::Shape),
            false,
            shared.dry_run,
            Some("duplicate or too many unanswered tools/list requests".to_string()),
        )?;
        write_client_frame(
            &shared.client_out,
            &build_jsonrpc_error(
                raw_id,
                "duplicate or too many unanswered tools/list requests",
            ),
        )
        .await?;
        return Ok(false);
    }
    // Acquire the busy gate atomically — a load-then-store pair would
    // let two racing tools/list requests both win. On contention the
    // pending entry is unwound and the request rejected; this side
    // never clears the gate (S2C owns release).
    let mut armed = shared
        .list_busy
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok();
    if !armed {
        shared.pending_tools_list.lock().await.remove(id);
        // The raised gate may belong to an internal listing — the
        // post-`initialize` probe or a `list_changed` revalidation —
        // rather than a client request (nothing client-side is in
        // `pending_tools_list`). That listing settles shortly: hold the
        // request so the verified emit, or an unwind error, answers it
        // instead of refusing a routine client listing.
        if hold_client_list(shared, id, raw_id).await {
            return Ok(false);
        }
        // Not held — either a live client listing owns the gate, or it
        // raced closed beneath the hold attempt. One CAS retry
        // separates the two cases before refusing on real contention.
        armed = shared
            .pending_tools_list
            .lock()
            .await
            .try_insert(id.clone())
            && shared
                .list_busy
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok();
        if !armed {
            shared.pending_tools_list.lock().await.remove(id);
            // The raised gate this CAS lost to may be a stale latch that
            // `resume_queued_revalidation` left in place because this
            // pending entry was still visible — wake the S2C loop so it
            // re-resolves now that the entry is unwound (a live listing
            // owner makes that resume a no-op).
            shared.list_kick.notify_one();
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "request",
                Some("tools/list"),
                Some(raw_id),
                version,
                McpVerdict::Deny(DenyReason::Shape),
                false,
                shared.dry_run,
                Some("tools/list already in progress".to_string()),
            )?;
            write_client_frame(
                &shared.client_out,
                &build_jsonrpc_error(raw_id, "tools/list already in progress"),
            )
            .await?;
            return Ok(false);
        }
    }
    *shared.last_list_template.lock().await = line.to_string();
    {
        // Keyed by canonical RpcId — a canonically-equal response id in
        // a different spelling (`1` vs `1.0`) still resolves the entry.
        let mut originals = shared.original_tools_list.lock().await;
        let retained: usize = originals.values().map(|v| v.len()).sum();
        if retained.saturating_add(line.len()) > MAX_ORIGINAL_TOOLS_LIST_BYTES {
            shared.pending_tools_list.lock().await.remove(id);
            shared.list_kick.notify_one();
            proxy_rpc::audit_decision(
                &shared.audit,
                C2S,
                "request",
                Some("tools/list"),
                Some(raw_id),
                version,
                McpVerdict::Deny(DenyReason::Shape),
                false,
                shared.dry_run,
                Some("tools/list original retention budget exhausted".to_string()),
            )?;
            write_client_frame(
                &shared.client_out,
                &build_jsonrpc_error(raw_id, "tools/list retention budget exhausted"),
            )
            .await?;
            // `list_busy` stays raised; S2C's resume path releases it.
            return Ok(false);
        }
        originals.insert(id.clone(), line.to_string());
    }
    Ok(true)
}

/// Hold a client `tools/list` that lost the busy-gate CAS while the gate
/// is owned by internal work — the post-`initialize` probe or a
/// `list_changed` revalidation — rather than a client listing (then a
/// `pending_tools_list` entry would exist). The request is stored, not
/// forwarded; the S2C side answers it from the verified emit when the
/// in-flight listing settles, or with an error when that listing
/// unwinds. Returns `true` only when actually held: a live client
/// listing, an existing hold, or a gate that already raced closed all
/// fall back to the caller's contention path. A gate still raised is
/// drained by its owner's release path; `list_kick` covers a residual
/// raise with nothing left in flight.
async fn hold_client_list<W>(shared: &ProxyShared<W>, id: &RpcId, raw_id: &str) -> bool {
    let mut slot = shared.held_client_list.lock().await;
    if slot.is_some() || !shared.pending_tools_list.lock().await.is_empty() {
        return false;
    }
    *slot = Some((id.clone(), raw_id.to_string()));
    if shared.list_busy.load(Ordering::SeqCst) {
        drop(slot);
        shared.list_kick.notify_one();
        return true;
    }
    slot.take();
    false
}

/// Unwind [`arm_tools_list`] when the forward never reached the server:
/// drop the pending id and the stored request. `list_busy` is not
/// cleared here — only the S2C side ever releases the gate: a
/// `store(false)` from this side could land underneath a revalidation
/// queued in the meantime, stranding it. Wake the loop;
/// `resume_queued_revalidation` inspects `st.idle()` and
/// `pending_tools_list`, then drives owed work or clears the gate
/// itself. The request never reached the server, so no collection
/// can be bound to its id and the cancelled-id slot stays for a real
/// cancel.
pub(super) async fn unwind_tools_list<W>(shared: &ProxyShared<W>, id: &RpcId, _raw_id: &str)
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    shared.pending_tools_list.lock().await.remove(id);
    shared.original_tools_list.lock().await.remove(id);
    shared.list_kick.notify_one();
}

/// Register in the wire table, apply forward-time side effects, write.
/// Side effects commit under the same lock as the registration so a
/// response that lands the instant the write completes already sees
/// them; a failed write unwinds both so the table never tracks a
/// request the server did not see. Returns `Ok(false)` when registration
/// refused the request (duplicate id / capacity) — the client already
/// got an error; callers with bookkeeping must unwind.
#[expect(clippy::too_many_arguments)]
pub(super) async fn register_and_forward<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    ext: &ExtractedRequest,
    expected_list_gen: Option<u64>,
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
        expected_list_gen,
    )
    .await
}

/// Dry-run forward of a denied request: tracked with `allowed: false`.
/// The caller audits the deny verdict itself, once the forward result
/// is known.
#[allow(clippy::too_many_arguments)]
pub(super) async fn register_and_forward_denied<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    ext: &ExtractedRequest,
    expected_list_gen: Option<u64>,
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
        false,
        None,
        expected_list_gen,
    )
    .await
}

/// `audit_verdict` is `Some` only for policy-allowed forwards — the
/// decision (or a registration refusal) is recorded here. Denied
/// dry-run forwards pass `None`; their caller owns the audit record.
#[expect(clippy::too_many_arguments)]
pub(super) async fn register_and_forward_impl<W>(
    shared: &ProxyShared<W>,
    line: &str,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    ext: &ExtractedRequest,
    allowed: bool,
    audit_verdict: Option<McpVerdict>,
    expected_list_gen: Option<u64>,
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
                    )?;
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
    // The decision record is send-ordered ahead of the frame — the
    // protected action must never cross ahead of its own authorization
    // record, so a saturated or dead sink refuses the forward here
    // rather than discovering the failure on the next frame.
    if let Some(verdict) = audit_verdict {
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
    }
    shared.audit.ensure_available()?;
    // Verified-set recheck (F6/F10): the admission-time capture is
    // compared immediately before the child write. A `list_changed`
    // revalidation raises `list_busy` before it starts and bumps the
    // generation (with its advertised-name set) when it verifies, so a
    // stale admission is caught by either arm — unwind the registration
    // and deny rather than let the call execute against a tool set that
    // may have moved. `verified_tools` is authoritative: the names a
    // call was admitted against cannot change without its generation.
    if let Some(expected) = expected_list_gen
        && (shared.list_busy.load(Ordering::SeqCst)
            || shared.verified_tools.lock().unwrap().generation != expected)
    {
        shared.wire.lock().await.rollback_forwarded_request(undo);
        if let Some(verdict) = audit_verdict {
            // The pre-write record claimed `forwarded=true`; reconcile
            // the wire truth with a corrective not-forwarded record.
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
        write_client_frame(
            &shared.client_out,
            &build_jsonrpc_error(raw_id, "tools/list revalidation began during authorization"),
        )
        .await?;
        return Ok(false);
    }
    let result = write_child_frame(&shared.child_stdin, line).await;
    if let Some(verdict) = audit_verdict
        && result.is_err()
    {
        // The pre-write record claimed `forwarded=true`; reconcile the
        // wire truth with a corrective not-forwarded record.
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

/// The tools/call denial while the verified-list gate is closed — a
/// revalidation in flight or (when verification is enforced) no
/// verified listing published yet. `reason` is the client-facing text;
/// `audit_reason` carries the detail for the audit record when the wire
/// text must stay membership-blind (an allowed-but-unadvertised name
/// must read exactly like a denied or unknown one).
pub(super) async fn deny_busy_tools_call<W>(
    shared: &ProxyShared<W>,
    raw_id: &str,
    line: &str,
    reason: &str,
    audit_reason: Option<&str>,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let tool = extract_tool_name_from_line(line).unwrap_or_else(|| "<unknown>".into());
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
    event.request_id = Some(proxy_rpc::truncate_for_audit(raw_id));
    event.details = Some(audit_reason.unwrap_or(reason).to_string());
    shared.audit.log(event);
    Ok(())
}

/// The legacy per-session gates for an allowed `tools/call`: trajectory
/// check, then the name-fixed Confused Deputy gate, then pending-call
/// registration. Mirrors the pre-PR-10 ordering.
pub(super) async fn apply_session_gates<W>(
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
            // A discover-role gate above may have registered a pending
            // list under this id — roll it back here so the entry cannot
            // linger toward the cap. The caller's deny path releases it
            // too; a still-forwarded dry-run deny must not seed either.
            state.take_pending_list(id);
            return Err(checker::PolicyViolation {
                tool_name: tool.unwrap_or_else(|| "<unknown>".into()),
                reason: format!("trajectory: {reason}"),
            });
        }
    }
    Ok(check_pass)
}

/// Opt-in Confused Deputy gate (`confused_deputy_protection`, default
/// off). The tool's role comes from `deputy::deputy_binding` — an
/// explicit `deputy` block wins, else the fixed-name compatibility
/// mapping applies:
///
/// - `Discover` (`deputy role="discover"`, or compat `list_files` /
///   `list_directory`): register the call's id, snapshotting the
///   extraction rules its **successful** correlated response may seed
///   `known_paths` with.
/// - `Use` (`deputy role="use"`, or compat `read_file`): every path the
///   tool's rules extract must already be in `known_paths`. A call whose
///   rules extract nothing — or whose extraction fails (bad JSON,
///   pointer value-bound overflow) — is denied; a `use` call never
///   passes unchecked. `../` traversal (incl. percent-encoded forms) is
///   always denied.
/// - `None` (`deputy role="none"` or no role bound): no check here — the
///   tool's ordinary policy gates (allowlist / `args_schema` /
///   `side_effect` / fs / net / trajectory) apply unchanged.
///
/// `known_paths` is process-local to this child — interleaved clients
/// share the set; configurable roles are not session separation.
pub(super) fn apply_confused_deputy_c2s(
    policy: &Policy,
    state: &mut SessionState,
    line: &str,
    envelope_id: Option<&RpcId>,
    tool: Option<&str>,
) -> Result<(), checker::PolicyViolation> {
    if !policy.confused_deputy_protection {
        return Ok(());
    }
    let Some(tool_name) = tool else {
        return Ok(());
    };
    match crate::policy::deputy::deputy_binding(policy, tool_name) {
        crate::policy::deputy::DeputyBinding::Discover(rules) => {
            if matches!(envelope_id, Some(&RpcId::Null)) {
                return Err(checker::PolicyViolation {
                    tool_name: tool_name.to_string(),
                    reason: "confused deputy: JSON-RPC id must not be null".to_string(),
                });
            }
            if let Some(id) = envelope_id
                && let Err(reason) = state.record_pending_list(id.clone(), tool_name, rules)
            {
                return Err(checker::PolicyViolation {
                    tool_name: tool_name.to_string(),
                    reason: format!("confused deputy: {reason}"),
                });
            }
            Ok(())
        }
        crate::policy::deputy::DeputyBinding::Use(rules) => {
            let paths = checker::extract_deputy_use_targets(line, rules).map_err(|reason| {
                checker::PolicyViolation {
                    tool_name: tool_name.to_string(),
                    reason: format!("confused deputy: {reason}"),
                }
            })?;
            if paths.is_empty() {
                return Err(checker::PolicyViolation {
                    tool_name: tool_name.to_string(),
                    reason: format!(
                        "confused deputy: tool '{tool_name}' is missing a resolvable path target"
                    ),
                });
            }
            for path in &paths {
                if let Err(reason) = state.check_access(path) {
                    return Err(checker::PolicyViolation {
                        tool_name: tool_name.to_string(),
                        reason: format!("confused deputy: {reason}"),
                    });
                }
            }
            Ok(())
        }
        crate::policy::deputy::DeputyBinding::None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auditor::proxy_state::PendingToolsList;
    use crate::policy::mcp::AllowReason;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use tokio::sync::{Mutex, watch};

    fn shared_for_test() -> (
        ProxyShared<tokio::io::DuplexStream>,
        watch::Receiver<bool>,
        tokio::io::DuplexStream,
    ) {
        let (abort_tx, abort_rx) = watch::channel(false);
        // The read half must outlive the test — a dropped reader makes
        // `write_child_frame` fail with BrokenPipe.
        let (child_read, child_write) = tokio::io::duplex(64 * 1024);
        (
            ProxyShared {
                policy: Policy::default(),
                dry_run: false,
                fail_on: crate::verifier::fail_on::FailOn::None,
                max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
                audit: Arc::new(crate::audit_log::AuditLogger::to_tracing()),
                session: None,
                wire: Arc::new(Mutex::new(proxy_rpc::WireState::new())),
                pending_tools_list: Arc::new(Mutex::new(PendingToolsList::new())),
                client_out: Arc::new(Mutex::new(tokio::io::stdout())),
                child_stdin: Arc::new(Mutex::new(Some(child_write))),
                original_tools_list: Arc::new(Mutex::new(std::collections::HashMap::new())),
                list_busy: Arc::new(AtomicBool::new(false)),
                list_kick: Arc::new(tokio::sync::Notify::new()),
                cancelled_list_id: Arc::new(Mutex::new(None)),
                held_client_list: Arc::new(Mutex::new(None)),
                internal_list_failure: Arc::new(tokio::sync::Mutex::new(None)),
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
            child_read,
        )
    }

    const CALL_LINE: &str =
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"t","arguments":{}}}"#;

    /// Publish a verified generation the way `verify_and_emit_list` does:
    /// the name set and counter move together under the mutex, and the
    /// atomic mirror follows.
    fn set_verified(
        shared: &ProxyShared<tokio::io::DuplexStream>,
        generation: u64,
        names: &[&str],
    ) {
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
        let (shared, _rx, _child_read) = shared_for_test();
        // Verification of the *next* set published since admission.
        set_verified(&shared, 2, &["t"]);
        let id = RpcId::from_u64(7);
        let ext = ExtractedRequest::default();
        let forwarded = register_and_forward_impl(
            &shared,
            CALL_LINE,
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
    }

    /// F10: a list_changed revalidation raises the busy gate before it
    /// starts — a call admitted just before the mark unwinds at the
    /// pre-write recheck even if the generation has not moved yet.
    #[tokio::test]
    async fn busy_gate_mid_authorization_unwinds_before_write() {
        let (shared, _rx, _child_read) = shared_for_test();
        set_verified(&shared, 1, &["t"]);
        shared.list_busy.store(true, Ordering::SeqCst);
        let id = RpcId::from_u64(7);
        let ext = ExtractedRequest::default();
        let forwarded = register_and_forward_impl(
            &shared,
            CALL_LINE,
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
            CALL_LINE,
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
        assert!(shared.wire.lock().await.get(C2S, &id).is_some());
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
            CALL_LINE,
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
            CALL_LINE,
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
        let mut buf = [0u8; 256];
        let n = tokio::io::AsyncReadExt::read(&mut child_read, &mut buf)
            .await
            .unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).contains("tools/call"));
    }

    /// F6: an admission captured before a revalidation publishes is
    /// denied at the pre-write recheck even when the *new* set also
    /// names the tool — the generation is bound to the set, not to the
    /// name alone.
    #[tokio::test]
    async fn republished_set_still_stales_an_earlier_admission() {
        let (shared, _rx, _child_read) = shared_for_test();
        set_verified(&shared, 2, &["t"]);
        let id = RpcId::from_u64(7);
        let ext = ExtractedRequest::default();
        let forwarded = register_and_forward_impl(
            &shared,
            CALL_LINE,
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
            r#"{"jsonrpc":"2.0","id":0,"method":"tools/list"}"#,
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
        shared.list_busy.store(true, Ordering::SeqCst);
        shared
            .pending_tools_list
            .lock()
            .await
            .try_insert(RpcId::from_u64(9));
        let id = RpcId::from_u64(0);
        let armed = arm_tools_list(
            &shared,
            r#"{"jsonrpc":"2.0","id":0,"method":"tools/list"}"#,
            &id,
            "0",
            SupportedProtocolVersion::Mcp2025November25,
        )
        .await
        .unwrap();
        assert!(!armed);
        assert!(shared.held_client_list.lock().await.is_none());
    }
}
