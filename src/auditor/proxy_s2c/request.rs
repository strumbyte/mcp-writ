//! The server→client request path: a 2025-only direction (2026 forbids
//! server→client requests). Allowed requests register in the wire table
//! and forward; denied ones get a JSON-RPC error back to the server.

use super::{S2C, V26};
use crate::auditor::proxy_rpc::{self, TrackedRequest};
use crate::auditor::proxy_state::ProxyShared;
use crate::auditor::proxy_wire::{
    build_jsonrpc_error, deny_explanation, write_child_frame, write_client_frame,
};
use crate::auditor::session::RpcId;
use crate::error::AuditorError;
use crate::policy::mcp::{DenyReason, McpVerdict};
/// One server→client request (2025 only — 2026 forbids them). Allowed
/// requests register in the wire table and forward; denied ones get an
/// error back to the server (never generated on a 2026 wire).
pub(super) async fn s2c_request<W>(
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
            // The entry is born undispatched — invisible to `answered`/
            // `take` until the client write completes, so a response
            // frame cannot retire a request the client never saw.
            let mut tracked =
                TrackedRequest::from_extracted(method, version, true, shared.dry_run, &ext);
            tracked.dispatched = false;
            let registered = wire
                .register(S2C, id.clone(), tracked)
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
                        Ok(()) => {
                            // The request reached the client — it may
                            // now correlate an answer.
                            shared.wire.lock().await.mark_dispatched(S2C, id);
                            Ok(())
                        }
                        // The client never saw it — drop the tracking and
                        // the side effect committed with it, and reconcile
                        // the pre-write `forwarded=true` record. Skipped
                        // for `DeliveryUncertain`: the complete frame may
                        // still have crossed, so "not forwarded" is
                        // unprovable and the request stays tracked until
                        // the session ends on the error.
                        Err(e) => {
                            if !matches!(e, AuditorError::DeliveryUncertain(_)) {
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
                            }
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
                let msg = match verdict {
                    McpVerdict::Deny(r) => match deny_explanation(r, method, S2C) {
                        Some(text) => format!("mcp-writ: {text}"),
                        None => format!(
                            "mcp-writ: server request '{method}' denied ({})",
                            r.as_str()
                        ),
                    },
                    other => format!(
                        "mcp-writ: server request '{method}' denied ({})",
                        other.reason_code()
                    ),
                };
                if matches!(verdict, McpVerdict::Deny(DenyReason::InitOrder))
                    && !shared
                        .init_order_warned
                        .swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    // Same once-per-session rule as the C2S deny path —
                    // the server's error reply repeats on every denial.
                    tracing::warn!("server→client: {msg}");
                }
                write_child_frame(&shared.child_stdin, &build_jsonrpc_error(raw_id, &msg)).await?;
            }
            Ok(())
        }
    }
}
