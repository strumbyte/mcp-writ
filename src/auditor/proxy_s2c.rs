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
use super::proxy_rpc::{self, WireFrame};
use super::proxy_state::ProxyShared;
use super::proxy_tools_list::{self, ListFlow, S2cFrame};
use super::proxy_wire::{
    build_jsonrpc_error, extract_raw_id_json, read_proxy_frame, write_client_frame,
};
use super::session::RpcId;
use crate::error::AuditorError;
use crate::framing::BoundedFrame;
use crate::policy::mcp::{DenyReason, McpVerdict};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

mod notification;
mod oversize;
mod request;
mod response;
#[cfg(test)]
mod tests;

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
/// they carry ([`resolve_input_required`](response::resolve_input_required)).
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
                oversize::s2c_oversize(&shared, &mut st, &frame).await?;
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
    // Parse the frame's exact bytes — the same text the client would
    // receive on a forward. `RawJson` skips only the four JSON
    // whitespace characters, so a Unicode "space" like U+00A0 around
    // the frame is a parse rejection, not a silent normalization
    // (same posture as the C2S gate's `parse_and_verify`).
    let parsed = nojson::RawJson::parse(line);
    let Ok(json) = &parsed else {
        // Fail closed: unparseable frames from the server are dropped.
        audit_malformed(shared, None, "invalid JSON").await?;
        return Ok(());
    };
    // Same structural gate as the client→server direction: a frame with
    // duplicate keys can parse differently downstream than it did here —
    // drop it rather than forward a disagreement.
    if let Err(violation) = checker::check_duplicate_keys_recursively(json.value()) {
        let raw_id = extract_raw_id_json(json);
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
                // Pending membership alone cannot admit a frame — the
                // entry is inserted before the forward's wire
                // registration, so a stray could name an id whose
                // request never crossed. A live tools/list wire entry
                // is what proves the request left (same rule as
                // `on_list_path`).
                let tracked = st.is_internal_response(rpc_id.as_ref())
                    || match rpc_id {
                        Some(ref id) => {
                            shared.pending_tools_list.lock().await.contains(id)
                                && shared
                                    .wire
                                    .lock()
                                    .await
                                    .answered(S2C, id)
                                    .is_some_and(|a| a.method == "tools/list")
                        }
                        None => false,
                    };
                if tracked {
                    return route_tools_list(shared, st, line, &parsed, value, Some(reason)).await;
                }
                // Dispatch resolution, method classification, and the
                // consume itself share one wire lock — a tools/list
                // request could reach `dispatched` between separate
                // probes (armed on the C2S side after `answered` missed
                // the first time), and a listing taken here would
                // bypass the pipeline's own fail-closed settlement.
                let entry = if let Some(ref id) = rpc_id {
                    // The frame can still race its own request's
                    // dispatch mark — wait on the outcome bound to the
                    // registration first observed, as the well-formed
                    // response path does. A rollback frees the id, and
                    // a same-id replacement must neither keep the wait
                    // parked nor be consumed by a frame addressed to
                    // the removed registration.
                    match proxy_rpc::answered_after_dispatch(&shared.wire, C2S, id, None).await {
                        // `answered` proves the listing genuinely
                        // crossed — the frame belongs to the list
                        // pipeline's malformed handling. Route without
                        // consuming: `handle_tools_list_response`
                        // unwinds the `pending_tools_list` membership
                        // and gate state itself — an entry already
                        // taken here leaves its listing armed with no
                        // registration left to complete it.
                        Some(a) if a.method == "tools/list" => {
                            return route_tools_list(
                                shared,
                                st,
                                line,
                                &parsed,
                                value,
                                Some(reason),
                            )
                            .await;
                        }
                        // A malformed response answering any other
                        // tracked request still terminates that RPC —
                        // dropping it would leave the client's waiter
                        // hanging and leak the wire entry plus the
                        // tools/call pending bookkeeping. Consume the
                        // entry the same way the denied-response path
                        // does (`responded` entries are never
                        // re-answerable), release the session state,
                        // and answer the waiter with an error; dry-run
                        // observes by forwarding the frame.
                        // Consume bound to the resolved registration's
                        // seq — the probe-to-take gap can have seen a
                        // removal plus a same-id replacement, which
                        // this frame must not retire.
                        Some(a) => {
                            proxy_rpc::take_after_dispatch(&shared.wire, C2S, id, Some(a.seq)).await
                        }
                        // The observed registration vanished, or a
                        // same-id replacement sits under the id now —
                        // the frame matched neither, so it drops.
                        None => None,
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
                audit_malformed(shared, raw_id, reason).await?;
                if entry.is_some() {
                    // Never raw-forward a malformed frame — even in
                    // dry-run the client gets the JSON-RPC error.
                    return write_client_frame(
                        &shared.client_out,
                        &build_jsonrpc_error(
                            raw_id.unwrap_or("null"),
                            &format!("malformed response ({reason})"),
                        ),
                    )
                    .await;
                }
                return Ok(());
            }
            audit_malformed(shared, raw_id, reason).await?;
            Ok(())
        }
        WireFrame::Notification { method } => {
            notification::s2c_notification(shared, st, value, line, &method).await
        }
        WireFrame::Response { id, raw_id } => {
            response::s2c_response(shared, st, value, line, &parsed, &id, raw_id).await
        }
        WireFrame::Request { method, id, raw_id } => {
            request::s2c_request(shared, value, line, &method, &id, raw_id).await
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
