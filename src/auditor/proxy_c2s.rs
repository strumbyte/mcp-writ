//! Client→server direction of `run_proxy`: frame classification, MCP
//! decision enforcement, legacy tools/call / tools/list policy checks,
//! opt-in trajectory / Confused Deputy session accounting, and forwarding.
//!
//! Every frame is classified (request / notification / response) and
//! decided through `Policy::decide_mcp` before it crosses the wire:
//! denied requests get a JSON-RPC error, denied notifications are
//! dropped, and malformed frames are never forwarded.

use tokio::io::BufReader;

use super::checker;
use super::proxy_rpc::{self, WireFrame, WireState};
use super::proxy_state::ProxyShared;
use super::proxy_wire::{
    build_jsonrpc_error, extract_raw_id, extract_tool_name_from_line, read_proxy_line,
    rpc_id_from_raw_id, write_child_frame, write_client_frame,
};
use super::session::RpcId;
use crate::error::AuditorError;
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
        );
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
            );
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
            {
                // `original_tools_list` is keyed by the request's raw
                // `id` text; the cancel carries the same id in canonical
                // form, so match by re-parsing the stored key.
                let mut originals = shared.original_tools_list.lock().await;
                if let Some(raw) = originals
                    .keys()
                    .find(|raw| rpc_id_from_raw_id(raw).as_ref() == Some(cancel_id))
                    .cloned()
                {
                    originals.remove(&raw);
                }
            }
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
            );
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
        );
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
