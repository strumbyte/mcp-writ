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

use tokio::io::{AsyncBufReadExt, BufReader};

use super::checker;
use super::proxy_list_state::S2cListState;
use super::proxy_rpc::{self, TrackedRequest, WireFrame, WireState};
use super::proxy_state::{self, ProxyShared};
use super::proxy_tools_list::{self, ListFlow, S2cFrame};
use super::proxy_wire::{
    build_jsonrpc_error, extract_raw_id, frame_too_large_message, negotiated_version_value,
    oversize_extra, read_proxy_frame, recover_id_candidates, recover_method, rpc_id_from_raw_id,
    tools_call_result_succeeded, unsupported_version_message, write_child_frame,
    write_client_frame,
};
use super::session::{self, RpcId};
use crate::error::AuditorError;
use crate::framing::{BoundedFrame, OversizeFrame};
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
    let mut fail_watch = shared.audit.failure_watch();

    loop {
        shared.audit.ensure_available()?;
        // `fill_buf` only peeks — a `list_kick` cancelled mid-wait loses
        // no input, unlike interrupting `read_proxy_frame` (its partial
        // line buffer would be dropped). Once bytes are buffered the
        // frame read runs uninterruptibly — including an oversized
        // frame's drain to its newline — so a kick can never tear a
        // frame in half; at worst it waits for a complete frame.
        let read = tokio::select! {
            biased;
            _ = fail_watch.changed() => {
                // Writer failure observed while idle — same fail-closed
                // contract as the loop-top `ensure_available`.
                if shared.audit.is_failed() {
                    return Err(AuditorError::AuditUnavailable(
                        "audit writer failed while the relay was idle".into(),
                    ));
                }
                continue;
            }
            _ = shared.list_kick.notified() => {
                proxy_tools_list::resume_queued_revalidation(&shared, &mut st).await?;
                continue;
            }
            avail = reader.fill_buf() => match avail {
                Err(e) => return Err(AuditorError::Io(e)),
                Ok(_) => read_proxy_frame(&mut reader, shared.max_frame_bytes).await,
            },
        };
        match read {
            Ok(Some(BoundedFrame::Line(line))) => {
                s2c_frame(&shared, &mut st, &line).await?;
            }
            Ok(Some(BoundedFrame::Oversize(frame))) => {
                s2c_oversize(&shared, &mut st, &frame).await?;
            }
            Ok(None) => {
                if st.has_incomplete_listing() || shared.list_busy.load(Ordering::SeqCst) {
                    let block_reason =
                        "server closed stdout before tools/list verification completed".to_string();
                    // A client listing coalesced behind the dead one —
                    // held, or still in transit in the C2S pipe — is
                    // answered by the abort drain.
                    *shared.internal_list_failure.lock().await =
                        Some((block_reason.clone(), false));
                    shared.abort_tx.send(true).ok();
                    return Err(AuditorError::VerificationFailed(block_reason));
                }
                break;
            }
            Err(e) => {
                tracing::error!(
                    "server→client: read error: {}",
                    crate::termutil::sanitize_for_terminal(&e.to_string())
                );
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
        audit_malformed(shared, None, "invalid JSON").await?;
        return Ok(());
    };
    // Same structural gate as the client→server direction: a frame with
    // duplicate keys can parse differently downstream than it did here —
    // drop it rather than forward a disagreement.
    if let Err(violation) = checker::check_duplicate_keys_recursively(json.value()) {
        let raw_id = extract_raw_id(line);
        audit_malformed(shared, raw_id.as_deref(), &violation.reason).await?;
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
                let tracked = st.is_internal_response(rpc_id.as_ref())
                    || match rpc_id {
                        Some(ref id) => shared.pending_tools_list.lock().await.contains(id),
                        None => false,
                    };
                if tracked {
                    return route_tools_list(shared, st, line, &parsed, value, Some(reason)).await;
                }
                // A malformed response answering any other tracked
                // request still terminates that RPC — dropping it would
                // leave the client's waiter hanging and leak the wire
                // entry plus the tools/call pending bookkeeping. Consume
                // the entry the same way the denied-response path does
                // (`responded` entries are never re-answerable), release
                // the session state, and answer the waiter with an
                // error; dry-run observes by forwarding the frame.
                let entry = if let Some(ref id) = rpc_id {
                    let mut wire = shared.wire.lock().await;
                    if wire.answered(S2C, id).is_some() {
                        wire.take(C2S, id)
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let (Some(e), Some(id)) = (&entry, &rpc_id)
                    && e.method == "tools/call"
                    && let Some(ref session) = shared.session
                {
                    let mut state = session.lock().await;
                    state.take_pending_list(id);
                    state.release_pending_tool_call_unverified(id);
                }
                audit_malformed(shared, raw_id.as_deref(), reason).await?;
                if entry.is_some() {
                    // Never raw-forward a malformed frame — even in
                    // dry-run the client gets the JSON-RPC error.
                    return write_client_frame(
                        &shared.client_out,
                        &build_jsonrpc_error(
                            raw_id.as_deref().unwrap_or("null"),
                            &format!("malformed response ({reason})"),
                        ),
                    )
                    .await;
                }
                return Ok(());
            }
            audit_malformed(shared, raw_id.as_deref(), reason).await?;
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
        // A frame routed onto the tools/list path that the pipeline did
        // not recognize is fail-closed: dropping it keeps an
        // unverified same-id frame from reaching the client; the real
        // response can still resolve the pending listing. The anomaly is
        // recorded in every mode — dry-run never raw-forwards an
        // unverified tools/list frame.
        ListFlow::ForwardRaw => {
            audit_malformed(shared, raw_id.as_deref(), "unrecognized tools/list frame").await?;
            Ok(())
        }
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
            proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                S2C,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                shared.dry_run,
                None,
            )
            .await?;
            let result = if method == "notifications/tools/list_changed" {
                proxy_tools_list::handle_list_changed(shared, st, line).await
            } else {
                write_client_frame(&shared.client_out, line).await
            };
            match result {
                Ok(()) => Ok(()),
                Err(e) => {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        S2C,
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
        _ => {
            // Drop or (defensively) deny/undecided — notifications are
            // never answered and never forwarded: server authorization
            // stays enforced in dry-run exactly as it does when
            // enforcing.
            drop(wire);
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
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
        || st.is_internal_response(Some(id));

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
    // Denied as `unsupported-version`, not `shape`: the envelope is
    // well-formed; the negotiated revision itself is the violation.
    // The session is left open — the denied response never establishes
    // a revision, `init` stays PendingInitialize, so a retried
    // `initialize` can still renegotiate while every other method keeps
    // failing init-order (PR-23 decision: diagnose, don't abort).
    // Auditor-internal `initialize` requests stay outside the pin: none
    // are issued today, and a rejected internal response already aborts
    // via `VerificationFailed` below — the pin exists to hand the
    // waiting *client* a diagnosable error, which internal traffic
    // never produces.
    let initialize_result = answered
        .as_ref()
        .map(|a| a.method == "initialize" && !a.internal)
        .unwrap_or(false)
        && ext.has_result
        && !ext.is_error;
    let unsupported_negotiation = deny_reason.is_none()
        && initialize_result
        && !proxy_rpc::WireState::initialize_result_version_ok(&ext);
    let (audit_verdict, deny_reason) = if unsupported_negotiation {
        (
            McpVerdict::Deny(DenyReason::UnsupportedVersion),
            Some(DenyReason::UnsupportedVersion),
        )
    } else {
        (verdict, deny_reason)
    };

    // PR-23: record the version the server actually returned on every
    // external `initialize` result — allowed or denied — so the
    // negotiated revision is never lost when another denial reason wins
    // first (`revision=` is the judged wire revision, never the
    // negotiated one). `supported=` marks the unsupported-version
    // denial itself.
    let negotiated_extra = initialize_result.then(|| {
        let mut extra = format!(
            "server_protocol_version={}",
            negotiated_version_value(ext.initialize_protocol_version.as_deref())
        );
        if unsupported_negotiation {
            extra.push_str(&format!(
                " supported={}",
                crate::protocol::SUPPORTED_INITIALIZE_VERSIONS.join(",")
            ));
        }
        extra
    });

    // A late response to a cancelled client `tools/list` is dead
    // traffic: the cancel already released its pending id, so only the
    // wire entry still ties it to the verification pipeline — where a
    // tools-shaped payload could resurrect a listing nobody awaits,
    // interleave into a live collection, or trip a queued revalidation
    // into an abort. Consume the wire entry, record the anomaly, and
    // drop it — in every mode, including dry-run.
    if answered
        .as_ref()
        .is_some_and(|a| a.method == "tools/list" && !a.internal)
        && !shared.pending_tools_list.lock().await.contains(id)
        && !st.is_internal_response(Some(id))
    {
        wire.take(C2S, id);
        drop(wire);
        audit_additional_requests(shared, &additional_audits, raw_id, version, false).await?;
        proxy_rpc::audit_decision(
            &shared.audit,
            S2C,
            "response",
            Some("tools/list"),
            Some(raw_id),
            version,
            audit_verdict,
            false,
            shared.dry_run,
            None,
        )?;
        audit_malformed(shared, Some(raw_id), "response to cancelled tools/list").await?;
        return Ok(());
    }

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
            audit_additional_requests(shared, &additional_audits, raw_id, version, true).await?;
            proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                S2C,
                "response",
                method_label.as_deref(),
                Some(raw_id),
                version,
                audit_verdict,
                shared.dry_run,
                negotiated_extra.clone(),
            )
            .await?;
            if on_list_path || internal {
                let result = route_tools_list(shared, st, line, parsed, value, None).await;
                if result.is_err() {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        S2C,
                        "response",
                        method_label.as_deref(),
                        Some(raw_id),
                        version,
                        audit_verdict,
                        shared.dry_run,
                        negotiated_extra.clone(),
                    );
                }
                return result;
            }
            apply_response_session_updates(shared, value, line, entry.as_ref()).await;
            match write_client_frame(&shared.client_out, line).await {
                Ok(()) => {
                    // When verification is enforced, open the initial
                    // internal tools/list right after `initialize`
                    // completes — `tools/call` stays fail closed until a
                    // verified generation publishes. The busy gate is
                    // raised first so no call can race the write. The
                    // probe only fires when the result advertised a
                    // `tools` capability: a server without one has no
                    // list to verify and its error would abort the
                    // session over a listing nobody needed.
                    if is_result
                        && entry.as_ref().is_some_and(|e| e.method == "initialize")
                        && ext
                            .initialize_server_capabilities
                            .iter()
                            .any(|cap| cap == "tools")
                        && proxy_state::list_verification_required(&shared.policy, shared.fail_on)
                        && shared.list_generation.load(Ordering::SeqCst) == 0
                        && st.idle()
                        && !shared.list_busy.swap(true, Ordering::SeqCst)
                    {
                        proxy_tools_list::begin_revalidation(shared, st).await?;
                    }
                    Ok(())
                }
                Err(e) => {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        S2C,
                        "response",
                        method_label.as_deref(),
                        Some(raw_id),
                        version,
                        audit_verdict,
                        shared.dry_run,
                        negotiated_extra.clone(),
                    );
                    Err(e)
                }
            }
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
            audit_additional_requests(shared, &additional_audits, raw_id, version, false).await?;
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "response",
                method_label.as_deref(),
                Some(raw_id),
                version,
                audit_verdict,
                false,
                shared.dry_run,
                negotiated_extra,
            )?;
            // A denied response still terminates the original RPC for
            // the client — release the session bookkeeping a forwarded
            // tools/call registered (the trajectory pending call and the
            // deputy pending list). The release is unverified: a refused
            // response means the call reached the server and may have
            // run, but it is no proven success either — it feeds
            // trajectory deny candidates without touching the verified
            // marker. A retry arrives under a new id.
            if let Some(ref e) = entry
                && e.method == "tools/call"
                && let Some(ref session) = shared.session
            {
                let mut state = session.lock().await;
                state.take_pending_list(id);
                state.release_pending_tool_call_unverified(id);
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
                // A client listing coalesced behind this internal one —
                // held, or still in transit in the C2S pipe — is
                // answered with this reason by the abort drain.
                *shared.internal_list_failure.lock().await =
                    Some((reason.as_str().to_string(), false));
                shared.abort_tx.send(true).ok();
                return Err(AuditorError::VerificationFailed(block_reason));
            }
            if on_list_path {
                // Unwind the client-facing pending state, then error.
                shared.pending_tools_list.lock().await.remove(id);
                st.discard_pages();
                {
                    // Keys are canonical `RpcId`s: the response's id and
                    // the bound client id resolve to the same entry.
                    let mut originals = shared.original_tools_list.lock().await;
                    originals.remove(id);
                    if let Some(client_id) = st.client_id().and_then(rpc_id_from_raw_id) {
                        originals.remove(&client_id);
                    }
                }
                if st.requires_abort_on_error() {
                    // A revalidation or held list_changed outlives this
                    // listing — dropping the gate now would admit
                    // tools/call against a tool set the server already
                    // moved past, and nothing else re-drives the queue.
                    // Fail the session like an in-flight revalidation
                    // error, keeping the gate latched until the abort.
                    let block_reason = format!(
                        "tools/list response rejected while a revalidation is pending ({})",
                        reason.as_str()
                    );
                    shared.list_busy.store(true, Ordering::SeqCst);
                    // The bound client listing dies with the session —
                    // answer it on its own id first: it already crossed
                    // C2S, so the abort drain cannot correlate it (it is
                    // neither held nor in transit in the pipe).
                    let client_id = st.take_client_id().unwrap_or_else(|| raw_id.to_string());
                    write_client_frame(
                        &shared.client_out,
                        &build_jsonrpc_error(
                            &client_id,
                            &format!("tools/list response rejected ({})", reason.as_str()),
                        ),
                    )
                    .await?;
                    // A client listing held behind the pending
                    // revalidation is answered by the abort drain; the
                    // inline reply marks the failure already-answered.
                    *shared.internal_list_failure.lock().await =
                        Some((reason.as_str().to_string(), true));
                    shared.abort_tx.send(true).ok();
                    return Err(AuditorError::VerificationFailed(block_reason));
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
                let msg = if unsupported_negotiation {
                    // PR-23: the same negotiated/supported pair goes to
                    // stderr so the cause reads identically on all three
                    // surfaces (client error, stderr, audit details).
                    let cause =
                        unsupported_version_message(ext.initialize_protocol_version.as_deref());
                    tracing::error!("server→client: {cause}");
                    format!("response rejected ({}): {cause}", reason.as_str())
                } else {
                    format!("response rejected ({})", reason.as_str())
                };
                write_client_frame(&shared.client_out, &build_jsonrpc_error(raw_id, &msg)).await?;
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
    // A request carrying `id: null` can never be answered — deny it as
    // malformed shape without consulting the policy.
    let verdict = if matches!(id, RpcId::Null) {
        McpVerdict::Deny(DenyReason::Shape)
    } else {
        let msg = proxy_rpc::request_message(version, S2C, method, &ext, &params);
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    match verdict {
        McpVerdict::Allow(_) => {
            // Commit the forward side effect (a URL-mode `elicitationId`
            // joins `pending_elicitations`) under the same lock as the
            // registration, before the write — a completion notification
            // arriving the instant the frame lands must correlate.
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
                    proxy_rpc::audit_forwarded_decision(
                        &shared.audit,
                        S2C,
                        "request",
                        Some(method),
                        Some(raw_id),
                        version,
                        verdict,
                        shared.dry_run,
                        None,
                    )
                    .await?;
                    match write_client_frame(&shared.client_out, line).await {
                        Ok(()) => Ok(()),
                        // The client never saw it — drop the tracking and
                        // the side effect committed with it, and reconcile
                        // the pre-write `forwarded=true` record.
                        Err(e) => {
                            shared.wire.lock().await.rollback_forwarded_request(undo);
                            proxy_rpc::audit_forward_failed(
                                &shared.audit,
                                S2C,
                                "request",
                                Some(method),
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
                    )?;
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
            // Denied server requests never cross to the client — dry-run
            // observes the deny decision only, it does not relax server
            // authorization the way it relaxes client tool calls.
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
            )?;
            // Denied (or undecidable): answer the server with a
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

/// CDP path recording + trajectory completion for a forwarded response —
/// only meaningful for tracked `tools/call` answers.
async fn apply_response_session_updates<W>(
    shared: &ProxyShared<W>,
    value: nojson::RawJsonValue<'_, '_>,
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
    // Discovery state seeds only from a correlated **success**: JSON-RPC
    // errors, `result.isError=true`, and MRTR `input_required` interim
    // results release the pending entry without recording a single path.
    let succeeded = tools_call_result_succeeded(value);
    let mut state = session.lock().await;
    if let Some(pending) = state.take_pending_list(&id)
        && succeeded
    {
        let paths = session::extract_paths_for_pending(value, pending.rules());
        if !paths.is_empty() {
            tracing::debug!(
                tool = %crate::termutil::sanitize_for_terminal(pending.tool()),
                count = paths.len(),
                "Session: recorded paths from discovery response"
            );
            state.record_paths(&paths);
        }
    }
    if shared.policy.trajectory {
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
/// result crossed to the client; `dry_run` on a denied forward). On the
/// forwarded path the records are send-ordered ahead of the frame, same
/// as the response's own decision record.
async fn audit_additional_requests<W>(
    shared: &ProxyShared<W>,
    entries: &[AdditionalRequestAudit],
    raw_id: &str,
    version: SupportedProtocolVersion,
    forwarded: bool,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    for entry in entries {
        let extra = entry
            .request_key
            .as_deref()
            .map(|k| format!("request_key={}", proxy_rpc::truncate_for_audit(k)));
        if forwarded {
            proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                S2C,
                "additional-request",
                entry.method.as_deref(),
                Some(raw_id),
                version,
                entry.verdict,
                shared.dry_run,
                extra,
            )
            .await?;
        } else {
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "additional-request",
                entry.method.as_deref(),
                Some(raw_id),
                version,
                entry.verdict,
                false,
                shared.dry_run,
                extra,
            )?;
        }
    }
    Ok(())
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
        // A map over the protocol bound is refused as a unit — one
        // aggregate record, not one audit write per rejected entry.
        fields::InputRequests::Overrun => {
            return (
                McpVerdict::Deny(DenyReason::Shape),
                vec![AdditionalRequestAudit {
                    request_key: None,
                    method: None,
                    verdict: McpVerdict::Deny(DenyReason::Shape),
                }],
            );
        }
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
async fn audit_malformed<W>(
    shared: &ProxyShared<W>,
    raw_id: Option<&str>,
    reason: &str,
) -> Result<(), AuditorError>
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
    )
}

/// A server→client frame that exceeded `max_frame_bytes`: refused
/// before parse, so the retained head/tail windows stand in for it.
///
/// A recovered `method` marks a server request or notification — a
/// request is answered with an error back to the *server* (2025 only —
/// 2026 forbids server→client requests). A frame whose `method`
/// survives but whose `id` does not is answered on `id: null` unless
/// the method names a `notifications/*` method: JSON-RPC orders
/// members freely, so a request's `id` can sit between the retained
/// windows, and answering costs a stray error on a true notification
/// where silence would hang a true request's waiter. Both outcomes are
/// audited. Otherwise the frame is a response: candidate `id`
/// literals resolve tail-first (the TS SDK serializes a response's `id`
/// as the last member) against the tracked request table. A resolved id
/// releases the request's tracking — tools/list bookkeeping unwinds the
/// same way a rejected list response does — and the client gets a
/// per-request JSON-RPC error on that id; the session continues on the
/// next frame. A response that cannot be correlated (nothing recovered,
/// or nothing tracked) is audited and answered with `id: null` — the
/// JSON-RPC convention for an error that cannot name its request —
/// rather than dropping the session over it.
///
/// Nothing oversized is ever forwarded — under `--dry-run` either,
/// because only bounded windows were retained of the refused frame.
async fn s2c_oversize<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    frame: &OversizeFrame,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let version = shared.wire.lock().await.passive_version();
    let extra = || Some(oversize_extra(frame, shared.max_frame_bytes));

    if let Some(method) = recover_method(frame) {
        // A request's `id` sits ahead of `params` — head-first recovery.
        let raw_id = recover_id_candidates(frame, false)
            .into_iter()
            .find(|raw| rpc_id_from_raw_id(raw).is_some_and(|id| !matches!(id, RpcId::Null)));
        // Only a recovered `notifications/*` method proves a dropped
        // frame owed no answer — any other method could belong to a
        // request whose `id` fell between the retained windows.
        let notification = raw_id.is_none() && method.starts_with("notifications/");
        proxy_rpc::audit_decision(
            &shared.audit,
            S2C,
            if notification {
                "notification"
            } else {
                "request"
            },
            Some(method.as_str()),
            raw_id.as_deref(),
            version,
            McpVerdict::Deny(DenyReason::FrameTooLarge),
            false,
            shared.dry_run,
            extra(),
        )?;
        if notification {
            // Notification — no answer is owed.
            return Ok(());
        }
        if matches!(version, V26) {
            // Server→client requests are revision-illegal on 2026: a
            // recovered one is dropped like a denied one, not answered.
            return Ok(());
        }
        let msg = format!(
            "mcp-writ: request '{method}' denied ({})",
            DenyReason::FrameTooLarge.as_str(),
        );
        return write_child_frame(
            &shared.child_stdin,
            &build_jsonrpc_error(raw_id.as_deref().unwrap_or("null"), &msg),
        )
        .await;
    }

    // Response: resolve recovered ids against the tracked table —
    // tail-first, since the TS SDK serializes a response's `id` last.
    // Every candidate must answer a live (non-`responded`) request
    // before it is trusted — a nested `result.id` that names no
    // in-flight request is inert.
    let mut resolved: Option<(String, RpcId)> = None;
    for raw in recover_id_candidates(frame, true) {
        let Some(id) = rpc_id_from_raw_id(&raw) else {
            continue;
        };
        if matches!(id, RpcId::Null) {
            continue;
        }
        let wire = shared.wire.lock().await;
        if wire.answered(S2C, &id).is_some() {
            drop(wire);
            resolved = Some((raw, id));
            break;
        }
    }
    let Some((raw_id, id)) = resolved else {
        // Unresolvable — audit and surface a generic refusal so the
        // client sees the drop rather than silence.
        proxy_rpc::audit_decision(
            &shared.audit,
            S2C,
            "response",
            None,
            None,
            version,
            McpVerdict::Deny(DenyReason::FrameTooLarge),
            false,
            shared.dry_run,
            extra(),
        )?;
        return write_client_frame(
            &shared.client_out,
            &build_jsonrpc_error(
                "null",
                &frame_too_large_message("response", shared.max_frame_bytes),
            ),
        )
        .await;
    };

    let on_list_path =
        shared.pending_tools_list.lock().await.contains(&id) || st.is_internal_response(Some(&id));
    let entry = {
        let mut wire = shared.wire.lock().await;
        wire.take(C2S, &id)
    };
    let method_label = entry.as_ref().map(|e| e.method.as_str().to_string());
    proxy_rpc::audit_decision(
        &shared.audit,
        S2C,
        "response",
        method_label.as_deref(),
        Some(raw_id.as_str()),
        version,
        McpVerdict::Deny(DenyReason::FrameTooLarge),
        false,
        shared.dry_run,
        extra(),
    )?;

    if entry.as_ref().is_some_and(|e| e.internal) || st.is_internal_response(Some(&id)) {
        // Our own tools/list request got refused on size — the listing
        // can never verify; fail closed like any other rejected
        // internal response.
        st.discard_pages();
        shared.list_busy.store(true, Ordering::SeqCst);
        // A client listing coalesced behind this internal one — held,
        // or still in transit in the C2S pipe — is answered with this
        // reason by the abort drain.
        *shared.internal_list_failure.lock().await =
            Some((DenyReason::FrameTooLarge.as_str().to_string(), false));
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(format!(
            "internal tools/list response rejected ({})",
            DenyReason::FrameTooLarge.as_str()
        )));
    }
    if on_list_path {
        // Client-facing listing: unwind pending/original/collection and
        // answer the client — the same unwind a rejected tools/list
        // response takes.
        shared.pending_tools_list.lock().await.remove(&id);
        // The bound client request id is what the client-facing error
        // echoes — peeked here because `release_collection_for` clears
        // it while checking the binding. Canonically it equals the
        // recovered id; the request's own spelling is the right echo.
        let bound_id = st.client_id().map(str::to_string);
        // A pagination request in flight for this listing is still
        // registered on the wire table — retire it so a late answer
        // resolves as untracked rather than inheriting the freed id.
        if let Some(internal) = st.release_collection_for(&id) {
            shared.wire.lock().await.take(C2S, &internal);
        }
        let client_id = st
            .take_client_id()
            .or(bound_id)
            .unwrap_or_else(|| raw_id.clone());
        st.discard_pages();
        {
            // Keys are canonical `RpcId`s: the response's id and the
            // bound client id resolve to the same entry.
            let mut originals = shared.original_tools_list.lock().await;
            originals.remove(&id);
            if let Some(cid) = rpc_id_from_raw_id(&client_id) {
                originals.remove(&cid);
            }
        }
        if st.requires_abort_on_error() {
            // A revalidation or held list_changed outlives this listing
            // — fail the session like an in-flight revalidation error,
            // keeping the gate latched until the abort.
            shared.list_busy.store(true, Ordering::SeqCst);
            // The bound client listing dies with the session — answer
            // it on its own id first: it already crossed C2S, so the
            // abort drain cannot correlate it (it is neither held nor
            // in transit in the pipe).
            write_client_frame(
                &shared.client_out,
                &build_jsonrpc_error(
                    &client_id,
                    &format!(
                        "tools/list response rejected ({})",
                        DenyReason::FrameTooLarge.as_str()
                    ),
                ),
            )
            .await?;
            // A client listing held behind the pending revalidation is
            // answered by the abort drain; the inline reply marks the
            // failure already-answered.
            *shared.internal_list_failure.lock().await =
                Some((DenyReason::FrameTooLarge.as_str().to_string(), true));
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::VerificationFailed(format!(
                "tools/list response rejected while a revalidation is pending ({})",
                DenyReason::FrameTooLarge.as_str()
            )));
        }
        shared.list_busy.store(false, Ordering::SeqCst);
        return write_client_frame(
            &shared.client_out,
            &build_jsonrpc_error(
                &client_id,
                &format!(
                    "tools/list response rejected ({})",
                    DenyReason::FrameTooLarge.as_str()
                ),
            ),
        )
        .await;
    }
    if method_label.as_deref() == Some("tools/list") {
        // A stale answer to a cancelled client listing — the cancel
        // already released its pending entry and no collection is bound
        // to it, so the wire entry consumed above was the only live
        // bookkeeping. Nothing is owed to the client: the normal
        // cancelled-listing path drops the frame the same way.
        return Ok(());
    }
    // Ordinary request: release the session bookkeeping a forwarded
    // tools/call registered — the release is unverified, the same
    // posture a denied response takes — then answer the client on the
    // recovered id.
    if method_label.as_deref() == Some("tools/call")
        && let Some(ref session) = shared.session
    {
        let mut state = session.lock().await;
        state.take_pending_list(&id);
        state.release_pending_tool_call_unverified(&id);
    }
    write_client_frame(
        &shared.client_out,
        &build_jsonrpc_error(
            &raw_id,
            &frame_too_large_message("response", shared.max_frame_bytes),
        ),
    )
    .await
}
