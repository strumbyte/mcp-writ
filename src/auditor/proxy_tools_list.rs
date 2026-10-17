//! tools/list collection, verification, and revalidation for the
//! server→client direction of `run_proxy`.
//!
//! Responsibilities:
//! - `notifications/tools/list_changed` hold + internal revalidation emission
//! - response id matching, pagination, cursor tracking, page cap
//! - first-seen manifest scan, baseline/hash diff, verified response emission
//! - fail-closed error responses and session abort on verification failure

use std::sync::atomic::Ordering;

use uuid::Uuid;

use super::checker;
use super::proxy_list_state::S2cListState;
use super::proxy_rpc;
use super::proxy_state::ProxyShared;
use super::proxy_wire::{
    build_internal_tools_list_request, build_pagination_request, build_tools_list_error_response,
    build_verified_tools_list_response, client_facing_id, response_result_has_tools_field,
    rpc_id_from_raw_id, write_child_frame, write_client_frame,
};
use super::session::RpcId;
use crate::audit_log::{Action, AuditEvent, EventType, Outcome, Severity};
use crate::error::AuditorError;
use crate::protocol::MessageDirection;
use crate::tool_def::ToolDefinition;

/// How the S2C loop proceeds after tools/list handling.
pub(crate) enum ListFlow {
    /// The line was consumed by the tools/list pipeline; read the next line.
    Handled,
    /// The line is not on the tools/list path; forward it verbatim to the client.
    ForwardRaw,
}

/// One server→client line, pre-parsed by the S2C loop.
///
/// The loop parses each line once and hands this view to
/// [`handle_tools_list_response`] so the tools/list pipeline never
/// reparses the raw text.
pub(crate) struct S2cFrame<'a> {
    /// Raw line as read from the server.
    pub(crate) line: &'a str,
    /// Parse result for `line`; kept as `Result` because a malformed
    /// frame on the tools/list path is fail-closed.
    pub(crate) parsed: &'a Result<nojson::RawJson<'a>, nojson::JsonParseError>,
    /// Canonical JSON-RPC id, when the frame carries a valid `id` member
    /// (`None` for notifications and top-level batch arrays).
    pub(crate) rpc_id: Option<&'a RpcId>,
    /// Raw `id` member text (quoted for strings), when present.
    pub(crate) raw_id: Option<&'a str>,
    /// True when the frame carries a `method` member.
    pub(crate) has_method: bool,
    /// True when the frame is a JSON-RPC response: a `result` or `error`
    /// member and no `method`.
    pub(crate) is_response: bool,
    /// Wire-gate rejection reason when `classify_frame` refused the
    /// envelope but the frame was routed here anyway (a response-member
    /// frame bearing a tracked tools/list id). `None` for well-formed
    /// envelopes.
    pub(crate) malformed_reason: Option<&'a str>,
}

/// Handle `notifications/tools/list_changed` from the server.
///
/// The notification is held until revalidation completes; if a listing is
/// already in flight a revalidation is queued instead of emitting a second
/// internal request.
pub(crate) async fn handle_list_changed<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    line: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Atomically mark busy and capture the prior state: C2S sets
    // list_busy when it registers a client tools/list whose response
    // has not arrived yet, a window the local collection state
    // cannot see. A prior busy flag means a listing is in flight.
    // The gate stays raised until the verified emit or
    // resume_queued_revalidation drops it on this side.
    let was_busy = shared.list_busy.swap(true, Ordering::SeqCst);
    if st.hold_list_changed(line, was_busy) {
        return Ok(());
    }
    begin_revalidation(shared, st).await
}

/// A cancelled client `tools/list` released its C2S bookkeeping — the
/// response that would have closed the listing is never coming, so the
/// S2C loop does it here. Releases the half-collected state still bound
/// to the cancelled request id, then: drives the queued `list_changed`
/// revalidation when one is owed (keeping the busy gate until it
/// verifies), or releases the gate itself when nothing is pending —
/// `list_busy` is only ever cleared on this side so a cancel can never
/// race `handle_list_changed`'s `swap`. A no-op while other list work
/// is in flight — including a client listing in `pending_tools_list`
/// that the local collection state cannot see yet: it owns the gate
/// and drains the queue itself on completion.
pub(crate) async fn resume_queued_revalidation<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if let Some(cancelled) = shared.cancelled_list_id.lock().await.take()
        && let Some(internal) = st.release_collection_for(&cancelled)
    {
        // Retire the wire entry for the dead listing's in-flight
        // internal page request so a late answer cannot resolve it.
        shared
            .wire
            .lock()
            .await
            .take(MessageDirection::ClientToServer, &internal);
    }
    if !st.idle() {
        return Ok(());
    }
    // A client tools/list that registered since the cancelled request
    // owns the busy gate now — clearing it would admit tools/call while
    // that listing is still unverified, and driving a queued
    // revalidation would interleave a second collection into `st`. The
    // pending entry can also belong to a registration still racing its
    // `list_busy` CAS; when that CAS loses to the raised gate the C2S
    // unwind re-kicks and this re-evaluates once the entry is gone.
    if !shared.pending_tools_list.lock().await.is_empty() {
        return Ok(());
    }
    if st.take_queued_revalidation() {
        return begin_revalidation(shared, st).await;
    }
    shared.list_busy.store(false, Ordering::SeqCst);
    // A request held behind the just-released gate has nothing in flight
    // that could produce a verified set — answer it with an error so the
    // client retries instead of hanging.
    answer_held_client_list_with_error(shared).await?;
    Ok(())
}

/// Answer a client `tools/list` held behind an internally-owned gate
/// when no in-flight listing can produce a verified set for it — the
/// internal listing errored or the gate was residual. Emitting an error
/// keeps the client honest (it retries on a clean path) instead of
/// hanging on a slot nobody drains. Runs after `list_busy` drops so a
/// hold landing in the release window re-arms as an ordinary listing.
async fn answer_held_client_list_with_error<W>(shared: &ProxyShared<W>) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if let Some((_id, raw_id)) = shared.held_client_list.lock().await.take() {
        let response = build_tools_list_error_response(&raw_id, "tools/list did not complete");
        write_client_frame(&shared.client_out, &response).await?;
    }
    Ok(())
}

/// The id a client-facing listing failure answers: the bound or
/// correlated client id when the listing is client-owned, else a
/// `tools/list` held behind the internally-owned gate — the aborting
/// failure denies that held request, so its id is the right echo and
/// the slot is drained. `None` when nothing client-visible can be
/// correlated — a request still in transit in the C2S pipe is answered
/// by the abort drain instead.
///
/// The failure is recorded into `internal_list_failure` only when
/// nothing here can emit the denial — when the held request is
/// answered inline the client-visible signal already went out, and a
/// held slot can never coexist with a second pending listing (the
/// gate refuses it), so no drain work remains.
async fn failure_emit_id<W>(
    shared: &ProxyShared<W>,
    resolved: Option<&str>,
    reason: &str,
) -> Option<String> {
    if let Some(id) = resolved {
        return Some(id.to_string());
    }
    if let Some((_id, raw_id)) = shared.held_client_list.lock().await.take() {
        return Some(raw_id);
    }
    *shared.internal_list_failure.lock().await = Some(reason.to_string());
    None
}

/// Start a re-list without releasing the shared busy flag or held
/// notification. Also used to emit the initial internal `tools/list`
/// right after `initialize` when verification is enforced — the caller
/// must raise `list_busy` first so `tools/call` cannot race in.
pub(crate) async fn begin_revalidation<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let internal_id = shared.next_internal_id.fetch_add(1, Ordering::Relaxed);
    let template = shared.last_list_template.lock().await.clone();
    st.begin_revalidation(template.clone(), internal_id);
    let follow = build_internal_tools_list_request(&template, internal_id);
    // Register before the write: a failed write aborts the session, so
    // the entry can never outlive the request it tracks. A refused
    // registration must not emit an untracked request either — fail
    // closed and keep list_busy set so tools/call stays denied until
    // the abort completes.
    let registered = {
        let mut wire = shared.wire.lock().await;
        let version = wire.passive_version();
        wire.register(
            MessageDirection::ClientToServer,
            RpcId::internal(internal_id),
            proxy_rpc::TrackedRequest::internal_list(version),
        )
    };
    if let Err(reason) = registered {
        let block_reason = format!("internal tools/list request refused ({reason})");
        tracing::error!(reason = %block_reason, "internal tools/list tracking failed: aborting session");
        // A client listing held behind this internal one — or still in
        // transit in the C2S pipe — is answered by the abort drain.
        *shared.internal_list_failure.lock().await = Some(block_reason.clone());
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(block_reason));
    }
    write_child_frame(&shared.child_stdin, &follow).await?;
    Ok(())
}

/// Runtime verification of a server→client line on the tools/list path.
///
/// Consumes responses to tracked tools/list ids (including internally
/// emitted pagination / revalidation requests), accumulates pages, runs the
/// first-seen scan before the hash/baseline diff, and emits a response rebuilt
/// from verified fields on success. Returns `ListFlow::ForwardRaw` when the line
/// is not part of tools/list handling.
pub(crate) async fn handle_tools_list_response<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    frame: S2cFrame<'_>,
) -> Result<ListFlow, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let S2cFrame {
        line,
        parsed: parsed_line,
        rpc_id,
        raw_id,
        has_method,
        is_response,
        malformed_reason,
    } = frame;
    let parsed_value = parsed_line.as_ref().ok().map(|j| j.value());
    // True when this response answers an internally emitted
    // request (pagination follow-up or list_changed
    // revalidation). Its id is an internal request id that
    // must never be echoed to the client. Captured once here
    // because waiting_internal_id is cleared later in the loop.
    let answered_internal = st.is_internal_response(rpc_id);

    // A top-level array is a JSON-RPC batch frame. C2S already rejects
    // client batch requests, so no in-flight tools/list id can
    // legitimately be answered inside a batch; per-element verification
    // is unavailable, so the frame is rejected rather than forwarded
    // (a pending-id response inside a batch would bypass verification).
    if parsed_value.is_some_and(|v| v.kind() == nojson::JsonValueKind::Array) {
        let block_reason = "batch frames are not supported in server responses".to_string();
        // An unverifiable frame is never forwarded — dry-run observes
        // the block rather than authorizing a bypass.
        if shared.dry_run {
            tracing::warn!(reason = %block_reason, "[DRY-RUN] batch frame from server: blocking");
        } else {
            tracing::error!(reason = %block_reason, "batch frame from server: blocking");
        }
        if let Some(id_str) = failure_emit_id(
            shared,
            client_facing_id(st.client_id(), raw_id, answered_internal),
            &block_reason,
        )
        .await
        {
            let error_response = build_tools_list_error_response(&id_str, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
        }
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(block_reason));
    }
    let has_result_or_error = parsed_value.is_some_and(|v| {
        v.to_member("result")
            .ok()
            .and_then(|m| m.optional())
            .is_some()
            || v.to_member("error")
                .ok()
                .and_then(|m| m.optional())
                .is_some()
    });

    let is_tools_list_response = if let Some(id) = rpc_id {
        if matches!(id, RpcId::Null) {
            false
        } else {
            let mut pending = shared.pending_tools_list.lock().await;
            // Pending tools/list ids are consumed only by genuine
            // responses; a same-id server-initiated request must not
            // consume them. An envelope that already failed the wire
            // gate is flagged so the malformed-envelope check below
            // blocks it, without consuming the entry — in dry-run a
            // legitimate response can still resolve the listing.
            let tracked = if is_response && malformed_reason.is_none() {
                pending.remove(id)
            } else {
                has_result_or_error && pending.contains(id)
            };
            tracked || answered_internal
        }
    } else {
        false
    };

    let seems_tools_list = is_tools_list_response
        || (!shared.policy.tools_list_hashes.is_empty()
            && parsed_value.is_some_and(response_result_has_tools_field));

    // A tracked frame rejected by the wire-level envelope gate (mixed
    // `method`/`result` members, both `result` and `error`, a missing
    // `jsonrpc` member, …) must never be verified and emitted — reject
    // it fail-closed. `has_method` is retained defensively for
    // request-shaped frames that arrive without a gate reason.
    let malformed_reason = malformed_reason.or_else(|| has_method.then_some("method"));
    if is_tools_list_response && let Some(reason) = malformed_reason {
        let block_reason = format!("malformed tools/list envelope ({reason})");
        if shared.dry_run {
            tracing::warn!(reason = %block_reason, "[DRY-RUN] malformed tools/list envelope: blocking");
        } else {
            tracing::error!(reason = %block_reason, "malformed tools/list envelope: blocking");
        }
        if let Some(id_str) = failure_emit_id(
            shared,
            client_facing_id(st.client_id(), raw_id, answered_internal),
            &block_reason,
        )
        .await
        {
            let error_response = build_tools_list_error_response(&id_str, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
        }
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(block_reason));
    }

    // Echo/mock servers may reflect the client's tools/list *request*
    // (which has `method`). JSON-RPC responses never carry `method`.
    if !(seems_tools_list && !has_method) {
        return Ok(ListFlow::ForwardRaw);
    }

    // Verify valid JSON and no duplicate keys anywhere in the response
    let parsed_json = match parsed_line {
        Ok(j) => j,
        Err(e) => {
            let block_reason = format!(
                "invalid JSON in tools/list response: {}",
                crate::termutil::sanitize_for_terminal(&e.to_string())
            );
            if shared.dry_run {
                tracing::warn!(reason = %block_reason, "[DRY-RUN] Invalid JSON in tools/list response: blocking session");
            } else {
                tracing::error!(reason = %block_reason, "Invalid JSON in tools/list response: blocking session");
            }
            if let Some(id_str) = failure_emit_id(
                shared,
                client_facing_id(st.client_id(), raw_id, answered_internal),
                &block_reason,
            )
            .await
            {
                let error_response = build_tools_list_error_response(&id_str, &block_reason);
                write_client_frame(&shared.client_out, &error_response).await?;
            }
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::VerificationFailed(block_reason));
        }
    };

    if let Err(violation) = checker::check_duplicate_keys_recursively(parsed_json.value()) {
        let block_reason = format!(
            "duplicate keys in tools/list response: {}",
            crate::termutil::sanitize_for_terminal(&violation.reason)
        );
        if shared.dry_run {
            tracing::warn!(reason = %block_reason, "[DRY-RUN] Duplicate keys in tools/list response: blocking session");
        } else {
            tracing::error!(reason = %block_reason, "Duplicate keys in tools/list response: blocking session");
        }
        if let Some(id_str) = failure_emit_id(
            shared,
            client_facing_id(st.client_id(), raw_id, answered_internal),
            &block_reason,
        )
        .await
        {
            let error_response = build_tools_list_error_response(&id_str, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
        }
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(block_reason));
    }

    // Distinguish legitimate JSON-RPC error response from malformed result
    let is_jsonrpc_error = parsed_json
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some();

    if is_jsonrpc_error {
        st.discard_pages();
        {
            // Canonical `RpcId` keys: the client id and the response's
            // raw id resolve to the same entry.
            let mut originals = shared.original_tools_list.lock().await;
            if let Some(id) = st.client_id().and_then(rpc_id_from_raw_id) {
                originals.remove(&id);
            }
            if let Some(id) = raw_id.and_then(rpc_id_from_raw_id) {
                originals.remove(&id);
            }
        }
        // An error answering the post-`initialize` internal listing is
        // not a session fault — the client never asked for that list.
        // Nothing verified ever published, so `list_generation == 0`
        // keeps tools/call denied on its own; unwind the collection
        // instead of aborting and let a later client-initiated listing
        // drive verification.
        let initial_internal = answered_internal
            && st.is_revalidating()
            && st.client_id().is_none()
            && shared.list_generation.load(Ordering::SeqCst) == 0;
        if st.requires_abort_on_error() && !initial_internal {
            // Keep list_busy set until session abort completes so
            // concurrent tools/call stays denied (fail-secure).
            let block_reason = "tools/list revalidation returned an error".to_string();
            tracing::error!(reason = %block_reason, "list_changed revalidation failed");
            // A client listing held behind this revalidation — or
            // still in transit in the C2S pipe — is answered by the
            // abort drain.
            *shared.internal_list_failure.lock().await = Some(block_reason.clone());
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::VerificationFailed(block_reason));
        }
        if initial_internal {
            st.finish_verification();
        }
        shared.list_busy.store(false, Ordering::SeqCst);
        // A held client listing must not be orphaned — its internal
        // owner just failed, so answer it with the same error shape.
        answer_held_client_list_with_error(shared).await?;
        if let Some(client_id) = st.take_client_id() {
            let error_response =
                build_tools_list_error_response(&client_id, "tools/list returned an error");
            write_client_frame(&shared.client_out, &error_response).await?;
        } else if !answered_internal {
            write_client_frame(&shared.client_out, line).await?;
        }
        // An error answering an internally emitted request
        // carries an internal request id; without a client
        // id to correlate it is dropped rather than echoed
        // downstream.
        return Ok(ListFlow::Handled);
    }

    // Must parse successfully as ToolsListPage; parsing failures are
    // verification aborts in EVERY mode — a dry-run raw forward would
    // deliver an unscanned, unpinned manifest to a tolerant client.
    let page = match crate::protocol::tools_list::parse_tools_list_response_page(line) {
        Ok(p) => p,
        Err(e) => {
            let block_reason = format!(
                "malformed tools/list response: {}",
                crate::termutil::sanitize_for_terminal(&e.0)
            );
            if shared.dry_run {
                tracing::warn!(reason = %block_reason, "[DRY-RUN] Malformed tools/list response: blocking session");
            } else {
                tracing::error!(reason = %block_reason, "Malformed tools/list response: blocking session");
            }
            if let Some(id_str) = failure_emit_id(
                shared,
                client_facing_id(st.client_id(), raw_id, answered_internal),
                &block_reason,
            )
            .await
            {
                let error_response = build_tools_list_error_response(&id_str, &block_reason);
                write_client_frame(&shared.client_out, &error_response).await?;
            }
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::VerificationFailed(block_reason));
        }
    };

    // Buffer tools across pages; never emit until the final page verifies.
    // The page's serialized bytes charge against the collection's
    // cumulative budget (F69) — a listing of many fat pages fails
    // closed exactly like an over-cap tool count.
    if let Err(block_reason) = st
        .note_page_bytes(line.len())
        .and_then(|()| st.append_page(page.tools))
        .and_then(|()| st.record_result_extras(page.result_extras))
    {
        if let Some(id_str) = failure_emit_id(
            shared,
            client_facing_id(st.client_id(), raw_id, answered_internal),
            &block_reason,
        )
        .await
        {
            let error_response = build_tools_list_error_response(&id_str, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
        }
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(block_reason));
    }

    if st.needs_client_binding() {
        if let Some(id) = raw_id.map(str::to_string) {
            let original = if let Some(key) = rpc_id_from_raw_id(&id) {
                shared
                    .original_tools_list
                    .lock()
                    .await
                    .remove(&key)
                    .unwrap_or_default()
            } else {
                String::new()
            };
            st.bind_client(id, original);
        }
        shared.list_busy.store(true, Ordering::SeqCst);
    }

    let has_next_cursor = page
        .next_cursor
        .as_deref()
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if has_next_cursor {
        let cursor = page.next_cursor.clone().unwrap_or_default();
        if let Err(block_reason) = st.record_cursor(&cursor) {
            if let Some(id_str) = failure_emit_id(
                shared,
                client_facing_id(st.client_id(), raw_id, answered_internal),
                &block_reason,
            )
            .await
            {
                let error_response = build_tools_list_error_response(&id_str, &block_reason);
                write_client_frame(&shared.client_out, &error_response).await?;
            }
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::VerificationFailed(block_reason));
        }
        let internal_id = shared.next_internal_id.fetch_add(1, Ordering::Relaxed);
        let follow = build_pagination_request(st.original_request(), internal_id, &cursor);
        st.expect_internal_response(internal_id);
        // Never emit an untracked pagination request — same fail-closed
        // rule as the initial internal request; list_busy stays set.
        let registered = {
            let mut wire = shared.wire.lock().await;
            let version = wire.passive_version();
            wire.register(
                MessageDirection::ClientToServer,
                RpcId::internal(internal_id),
                proxy_rpc::TrackedRequest::internal_list(version),
            )
        };
        if let Err(reason) = registered {
            let block_reason = format!("internal tools/list request refused ({reason})");
            tracing::error!(reason = %block_reason, "internal tools/list tracking failed: aborting session");
            // A client listing held behind this internal one — or still
            // in transit in the C2S pipe — is answered by the abort
            // drain.
            *shared.internal_list_failure.lock().await = Some(block_reason.clone());
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::VerificationFailed(block_reason));
        }
        write_child_frame(&shared.child_stdin, &follow).await?;
        return Ok(ListFlow::Handled);
    }

    verify_and_emit_list(shared, st, raw_id, answered_internal).await
}

/// Verification begins only after all pages have been collected. Preserve
/// the revalidation context until the result and held notification are emitted.
///
/// Ordering contract: the manifest scan, `verify_tools_list`,
/// `hash_tools_list`, and `record_verified_digest` all run on the full
/// advertised set (`tools_to_verify`) — the pin and the recorded digest
/// describe what the server offers, not the filtered view the client sees.
/// The policy allowlist filter applies only to the client-facing response
/// built afterwards. `--dry-run` never filters: it forwards the full
/// advertised list and audits the tools a normal run would have hidden.
async fn verify_and_emit_list<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    raw_id: Option<&str>,
    answered_internal: bool,
) -> Result<ListFlow, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tools_to_verify, client_emit_id, result_extras) = st.take_completed_pages();

    let mut blocked = false;
    let mut block_reason = String::new();

    // first-seen CC scan on the pagination-assembled set.
    // Hash match does not waive Critical/High findings.
    // `scan_server` is the pinned server name when the policy has one;
    // without pins, a policy bound to a single declared server identity
    // still names the upstream. `None` leaves `target_server` absent —
    // a synthetic "default" label is never recorded.
    let scan_server = shared
        .policy
        .tools_list_hashes
        .first()
        .map(|e| e.server_name.clone())
        .or_else(|| match shared.policy.declared_servers().as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        });
    let manifest_findings = crate::verifier::manifest::scan_manifest(&tools_to_verify);
    crate::verifier::manifest::log_manifest_scan_for(
        scan_server.as_deref(),
        &manifest_findings,
        &shared.audit,
        shared.fail_on,
    );
    let first_seen_block =
        crate::verifier::manifest::format_blocking_reason_for(&manifest_findings, shared.fail_on);
    if let Some(reason) = first_seen_block.clone() {
        blocked = true;
        // Findings embed server-controlled tool names — the reason is
        // rendered to terminal logs, so control characters are escaped
        // before it is stored.
        block_reason = crate::termutil::sanitize_for_terminal(&reason);
    }

    if !blocked && shared.policy.tools_list_hashes.is_empty() {
        let baseline = crate::verifier::tools_baseline::load_baseline("default")
            .ok()
            .flatten();
        if let Err(crate::verifier::tools_diff::ToolsDiffError::Blocked { diff_output }) =
            crate::verifier::tools_diff::verify_tools_list(
                "default",
                &tools_to_verify,
                None,
                baseline.as_deref(),
                &shared.audit,
            )
        {
            blocked = true;
            block_reason = crate::termutil::sanitize_for_terminal(&diff_output);
        }
    } else if !blocked {
        for entry in &shared.policy.tools_list_hashes {
            let baseline = crate::verifier::tools_baseline::load_baseline(&entry.server_name)
                .ok()
                .flatten();
            let res = crate::verifier::tools_diff::verify_tools_list(
                &entry.server_name,
                &tools_to_verify,
                Some(entry),
                baseline.as_deref(),
                &shared.audit,
            );
            match res {
                Ok(_) => {}
                Err(crate::verifier::tools_diff::ToolsDiffError::Blocked { diff_output }) => {
                    blocked = true;
                    block_reason = crate::termutil::sanitize_for_terminal(&diff_output);
                    break;
                }
            }
        }
    }

    if blocked {
        // Identity/integrity failures fail closed in every mode: a hash
        // or baseline mismatch, a first-seen manifest block, and any
        // verification error all refuse the advertised list. Dry-run
        // relaxes only *authorization observation* — it never exposes
        // tool definitions whose integrity check failed.
        if shared.dry_run {
            tracing::warn!(
                reason = %block_reason,
                fail_on = shared.fail_on.as_str(),
                "[DRY-RUN] tools/list verification failed: emitting error, not forwarding tools/list result"
            );
        } else {
            tracing::error!(
                reason = %block_reason,
                "tools/list verification failed: blocking response"
            );
        }
        if let Some(emit_id) = failure_emit_id(
            shared,
            client_facing_id(client_emit_id.as_deref(), raw_id, answered_internal),
            &block_reason,
        )
        .await
        {
            let error_response = build_tools_list_error_response(&emit_id, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
        }
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(format!(
            "tools/list {block_reason}"
        )));
    }

    let digest = match crate::verifier::tools_diff::hash_tools_list(&tools_to_verify) {
        Ok(digest) => Some(digest),
        Err(e) => {
            let block_reason = format!(
                "tools/list hashing failed: {}",
                crate::termutil::sanitize_for_terminal(&e.to_string())
            );
            // Canonicalization is an integrity check too — it fails
            // closed in every mode; dry-run cannot expose definitions
            // whose canonical form could not be produced.
            if shared.dry_run {
                tracing::warn!(reason = %block_reason, "[DRY-RUN] tools/list canonicalization failed: blocking session");
            } else {
                tracing::error!(reason = %block_reason, "tools/list canonicalization failed: blocking session");
            }
            // Internal request ids are never echoed:
            // the frame id is the client-facing id, or
            // null when no client request can be
            // correlated.
            if let Some(emit_id) = failure_emit_id(
                shared,
                client_facing_id(client_emit_id.as_deref(), raw_id, answered_internal),
                &block_reason,
            )
            .await
            {
                let error_response = build_tools_list_error_response(&emit_id, &block_reason);
                write_client_frame(&shared.client_out, &error_response).await?;
            }
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::VerificationFailed(block_reason));
        }
    };

    // Split the advertised set for the client-facing response only — pure
    // computation; the pin and the recorded digest cover the full
    // advertised set, not the filtered view the client sees.
    let (visible, hidden): (Vec<&ToolDefinition>, Vec<&ToolDefinition>) = tools_to_verify
        .iter()
        .partition(|tool| checker::tool_is_allowed(&shared.policy, &tool.name));

    // The authoritative verification record must be durable before any
    // verified state transition — `record_verified_digest`,
    // `finish_verification`, the busy-gate release, and the client emit
    // all follow this commit. A dead or saturated sink refuses here: no
    // unaudited manifest can publish verified state or cross to the
    // client. (On a best-effort logger the commit degrades to `log`.)
    {
        let mut event = AuditEvent::new(
            Uuid::now_v7(),
            EventType::ToolsListVerified,
            Severity::Info,
            if blocked {
                Outcome::Failure
            } else {
                Outcome::Success
            },
            if blocked {
                Action::Observed
            } else {
                Action::Allowed
            },
        );
        event.target_server = scan_server.clone();
        // Internal request ids are never echoed: record the client-facing
        // id so the event correlates with the request that produced it.
        event.request_id = client_facing_id(client_emit_id.as_deref(), raw_id, answered_internal)
            .map(str::to_string);
        let mut details = format!(
            "tools={} hidden={} blocked={blocked}",
            tools_to_verify.len(),
            hidden.len()
        );
        if let Some(digest) = &digest {
            details.push_str(&format!(" digest={digest}"));
        }
        if shared.dry_run {
            details.push_str(" dry_run=true");
        }
        event.details = Some(details);
        shared.audit.log_committed(event).await?;
    }

    let mut digest_changed = false;
    if let Some(digest) = digest {
        let (verified_digest, changed) = st.record_verified_digest(digest);
        digest_changed = changed;
        // Publish a new verified generation before the busy gate drops:
        // a tools/call admitted under the prior generation sees the
        // mismatch at its pre-write recheck and unwinds.
        shared.list_generation.fetch_add(1, Ordering::SeqCst);
        if changed {
            tracing::debug!(hash = verified_digest, "tools/list last_verified updated");
        }
    }

    // A list_changed revalidation that reproduces the last verified
    // digest hides the same tool set an earlier event already
    // enumerated — re-logging identical events adds noise, not
    // information.
    let already_reported = st.is_revalidating() && !digest_changed;
    if !hidden.is_empty() && !already_reported {
        let names = hidden
            .iter()
            .map(|tool| tool.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        // Same outcome convention as tool_call.denied: the requested
        // operation — seeing the full advertised list — was refused.
        // Dry-run records the would-be denial as `observed`.
        let mut event = AuditEvent::new(
            Uuid::now_v7(),
            EventType::ToolsListFiltered,
            Severity::Info,
            Outcome::Failure,
            if shared.dry_run {
                Action::Observed
            } else {
                Action::Denied
            },
        );
        // Record the pinned or bound server name only; never the
        // "default" fallback label.
        event.target_server = scan_server.clone();
        // Internal request ids are never echoed: record the client-facing
        // id so the event correlates with the request that produced it.
        event.request_id = client_facing_id(client_emit_id.as_deref(), raw_id, answered_internal)
            .map(str::to_string);
        event.details = Some(if shared.dry_run {
            format!("tools that would be hidden from the client: {names}")
        } else {
            format!("tools hidden from the client: {names}")
        });
        // Fail-closed: a filtered response is withheld when the audit
        // event cannot be accepted (same contract as tools/call).
        shared.audit.log_committed(event).await?;
    }

    // Dry-run forwards the full advertised list; otherwise the client sees
    // only tools the policy allows.
    let emit_tools: Vec<ToolDefinition> = if shared.dry_run {
        tools_to_verify.clone()
    } else {
        visible.into_iter().cloned().collect()
    };

    // A filtered list is a client-specific view of the advertised set: a
    // server-advertised `cacheScope` (e.g. shared) no longer describes it
    // — a shared cache could serve this subset to another client. Mark
    // it `private` when normal mode actually hid tools; `ttlMs` and the
    // other extras pass through unchanged.
    let mut result_extras = result_extras;
    if !shared.dry_run && !hidden.is_empty() {
        if let Some(entry) = result_extras
            .iter_mut()
            .find(|(name, _)| name == "cacheScope")
        {
            entry.1 = "\"private\"".to_string();
        } else {
            result_extras.push(("cacheScope".to_string(), "\"private\"".to_string()));
        }
    }

    let verified = if let Some(emit_id) = client_emit_id {
        Some(build_verified_tools_list_response(
            &emit_id,
            &emit_tools,
            &result_extras,
        ))
    } else if !st.is_revalidating() && !answered_internal {
        let emit_id = raw_id.unwrap_or("null");
        Some(build_verified_tools_list_response(
            emit_id,
            &emit_tools,
            &result_extras,
        ))
    } else {
        None
    };

    let revalidate = st.take_queued_revalidation();
    if !revalidate {
        // Verification is complete. Publish that state before the response
        // or notification can reach a client that immediately calls a tool.
        // Never clear it after I/O: C2S may already have started a new list.
        st.finish_verification();
        shared.list_busy.store(false, Ordering::SeqCst);
    }

    if let Some(verified) = verified {
        // Re-check immediately before the forward: the committed record
        // above raced nothing, but the sink could have died in between —
        // a saturated or dead queue must not let this response through.
        shared.audit.ensure_available()?;
        write_client_frame(&shared.client_out, &verified).await?;
    }

    if revalidate {
        begin_revalidation(shared, st).await?;
        return Ok(ListFlow::Handled);
    }

    // A client `tools/list` held while this internally-owned listing
    // collected is answered from the same verified set — it asked for
    // the inventory this collection just produced. Draining after
    // `list_busy` drops keeps a hold that lands inside the release
    // window from hanging: its arm re-check sees the free gate and
    // re-arms as an ordinary listing instead.
    if let Some((_id, raw_id)) = shared.held_client_list.lock().await.take() {
        let response = build_verified_tools_list_response(&raw_id, &emit_tools, &result_extras);
        shared.audit.ensure_available()?;
        write_client_frame(&shared.client_out, &response).await?;
    }

    if let Some(notif) = st.take_verified_notification() {
        shared.audit.ensure_available()?;
        write_client_frame(&shared.client_out, &notif).await?;
    }
    Ok(ListFlow::Handled)
}

#[cfg(test)]
mod tests {
    use super::super::proxy_state::PendingToolsList;
    use super::*;
    use std::sync::Arc;
    use tokio::sync::{Mutex, watch};

    fn shared_for_test(
        dry_run: bool,
    ) -> (ProxyShared<tokio::io::DuplexStream>, watch::Receiver<bool>) {
        shared_for_test_with(
            dry_run,
            crate::policy::Policy::default(),
            crate::audit_log::AuditLogger::to_tracing(),
        )
    }

    fn shared_for_test_with(
        dry_run: bool,
        policy: crate::policy::Policy,
        audit: crate::audit_log::AuditLogger,
    ) -> (ProxyShared<tokio::io::DuplexStream>, watch::Receiver<bool>) {
        let (abort_tx, abort_rx) = watch::channel(false);
        let (_child_read, child_write) = tokio::io::duplex(64);
        let shared = ProxyShared {
            policy,
            dry_run,
            fail_on: crate::verifier::fail_on::FailOn::DEFAULT,
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
            audit: Arc::new(audit),
            session: None,
            wire: Arc::new(Mutex::new(proxy_rpc::WireState::new())),
            pending_tools_list: Arc::new(Mutex::new(PendingToolsList::new())),
            client_out: Arc::new(Mutex::new(tokio::io::stdout())),
            child_stdin: Arc::new(Mutex::new(Some(child_write))),
            original_tools_list: Arc::new(Mutex::new(std::collections::HashMap::new())),
            list_busy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            list_kick: Arc::new(tokio::sync::Notify::new()),
            cancelled_list_id: Arc::new(Mutex::new(None)),
            held_client_list: Arc::new(Mutex::new(None)),
            internal_list_failure: Arc::new(tokio::sync::Mutex::new(None)),
            list_generation: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            last_list_template: Arc::new(Mutex::new(String::new())),
            next_internal_id: Arc::new(std::sync::atomic::AtomicU64::new(910_001)),
            abort_tx,
        };
        (shared, abort_rx)
    }

    #[tokio::test]
    async fn verified_list_releases_busy_before_client_can_reply() {
        let (shared, _abort_rx) = shared_for_test(false);
        shared.list_busy.store(true, Ordering::SeqCst);
        let mut st = S2cListState::new();
        st.bind_client("1".into(), String::new());

        // Pause at the response write to exercise the scheduling window
        // where a client can read the result before the write future resumes.
        let output_lock = shared.client_out.lock().await;
        let verification = verify_and_emit_list(&shared, &mut st, Some("1"), false);
        tokio::pin!(verification);
        tokio::select! {
            biased;
            _ = &mut verification => panic!("verification must wait for client output"),
            _ = std::future::ready(()) => {}
        }
        assert!(
            !shared.list_busy.load(Ordering::SeqCst),
            "completed verification must be visible before the response"
        );

        // A new client tools/list can start immediately after receiving the
        // response. Finishing the old write must not clear that new request.
        shared.list_busy.store(true, Ordering::SeqCst);
        drop(output_lock);
        verification.await.unwrap();
        assert!(shared.list_busy.load(Ordering::SeqCst));
    }

    /// F10: a successful verification publishes a new list generation —
    /// `tools/call` admissions capture it and unwind on any later bump.
    #[tokio::test]
    async fn verified_list_publishes_a_new_generation() {
        let (shared, _abort_rx) = shared_for_test(false);
        assert_eq!(shared.list_generation.load(Ordering::SeqCst), 0);
        let mut st = S2cListState::new();
        st.bind_client("1".into(), String::new());
        verify_and_emit_list(&shared, &mut st, Some("1"), false)
            .await
            .unwrap();
        assert_eq!(shared.list_generation.load(Ordering::SeqCst), 1);
        // A second verification publishes the next generation.
        verify_and_emit_list(&shared, &mut st, Some("1"), false)
            .await
            .unwrap();
        assert_eq!(shared.list_generation.load(Ordering::SeqCst), 2);
    }

    /// F10: the enforcement predicate — a pinned hash or a `fail-on`
    /// setting stricter than `none` requires a verified listing before
    /// `tools/call` may run.
    #[test]
    fn list_verification_required_predicate() {
        let mut policy = crate::policy::Policy::default();
        assert!(crate::auditor::proxy_state::list_verification_required(
            &policy,
            crate::verifier::fail_on::FailOn::High
        ));
        assert!(!crate::auditor::proxy_state::list_verification_required(
            &policy,
            crate::verifier::fail_on::FailOn::None
        ));
        policy
            .tools_list_hashes
            .push(crate::policy::ToolsListHashEntry {
                server_name: "s".to_string(),
                hash_value: "sha256:00".to_string(),
                approved: None,
            });
        assert!(crate::auditor::proxy_state::list_verification_required(
            &policy,
            crate::verifier::fail_on::FailOn::None
        ));
    }

    #[tokio::test]
    async fn queued_revalidation_keeps_calls_blocked_while_response_is_emitted() {
        let (shared, _abort_rx) = shared_for_test(false);
        shared.list_busy.store(true, Ordering::SeqCst);
        let mut st = S2cListState::new();
        st.bind_client("1".into(), String::new());
        assert!(st.hold_list_changed(
            r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#,
            true,
        ));

        let _output_lock = shared.client_out.lock().await;
        let verification = verify_and_emit_list(&shared, &mut st, Some("1"), false);
        tokio::pin!(verification);
        tokio::select! {
            biased;
            _ = &mut verification => panic!("verification must wait for client output"),
            _ = std::future::ready(()) => {}
        }
        assert!(
            shared.list_busy.load(Ordering::SeqCst),
            "a queued revalidation must keep tools/call blocked"
        );
    }

    /// Build the `S2cFrame` the S2C loop derives for a top-level array:
    /// `to_member` fails on non-objects, so no id/method is extracted and
    /// `value_is_response` is false.
    fn batch_frame<'a>(
        line: &'a str,
        parsed: &'a Result<nojson::RawJson<'a>, nojson::JsonParseError>,
    ) -> S2cFrame<'a> {
        S2cFrame {
            line,
            parsed,
            rpc_id: None,
            raw_id: None,
            has_method: false,
            is_response: false,
            malformed_reason: None,
        }
    }

    #[tokio::test]
    async fn batch_frame_with_pending_tools_list_id_is_blocked() {
        let (shared, abort_rx) = shared_for_test(false);
        assert!(
            shared
                .pending_tools_list
                .lock()
                .await
                .try_insert(RpcId::Number("1".into()))
        );
        let line = r#"[{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"evil_tool"}]}}]"#;
        let parsed = nojson::RawJson::parse(line);
        let mut st = S2cListState::new();
        let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
        assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
        assert!(*abort_rx.borrow());
    }

    #[tokio::test]
    async fn batch_frame_without_pending_ids_is_blocked() {
        let (shared, abort_rx) = shared_for_test(false);
        let line = r#"[{"jsonrpc":"2.0","method":"notifications/progress","params":{}}]"#;
        let parsed = nojson::RawJson::parse(line);
        let mut st = S2cListState::new();
        let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
        assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
        assert!(*abort_rx.borrow());
    }

    /// A frame that failed the wire-level envelope gate but carries
    /// response members on a tracked tools/list id is rejected —
    /// never verified, emitted, or silently discarded.
    #[tokio::test]
    async fn malformed_result_and_error_on_pending_id_is_rejected() {
        let (shared, abort_rx) = shared_for_test(false);
        let id = RpcId::Number("1".into());
        assert!(
            shared
                .pending_tools_list
                .lock()
                .await
                .try_insert(id.clone())
        );
        // Both `result` and `error` — `classify_frame` rejects the
        // envelope; a routed frame must be blocked, not interpreted.
        let line = r#"{"id":1,"result":{"tools":[{"name":"evil_tool"}]},"error":{"code":-32000,"message":"ambiguous"}}"#;
        let parsed = nojson::RawJson::parse(line);
        let mut st = S2cListState::new();
        let result = handle_tools_list_response(
            &shared,
            &mut st,
            S2cFrame {
                line,
                parsed: &parsed,
                rpc_id: Some(&id),
                raw_id: Some("1"),
                has_method: false,
                is_response: true,
                malformed_reason: Some("response carries both result and error"),
            },
        )
        .await;
        assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
        assert!(*abort_rx.borrow());
        // The pending entry is not consumed by the malformed frame — in
        // dry-run a genuine response can still resolve the listing.
        assert!(shared.pending_tools_list.lock().await.contains(&id));
    }

    /// An envelope-invalid frame carrying `result` on a tracked id is
    /// likewise rejected: without a `jsonrpc` member it must not be
    /// parsed and emitted as a verified listing.
    #[tokio::test]
    async fn jsonrpc_less_response_on_pending_id_is_rejected() {
        let (shared, abort_rx) = shared_for_test(false);
        let id = RpcId::Number("2".into());
        assert!(
            shared
                .pending_tools_list
                .lock()
                .await
                .try_insert(id.clone())
        );
        let line = r#"{"id":2,"result":{"tools":[{"name":"evil_tool"}]}}"#;
        let parsed = nojson::RawJson::parse(line);
        let mut st = S2cListState::new();
        let result = handle_tools_list_response(
            &shared,
            &mut st,
            S2cFrame {
                line,
                parsed: &parsed,
                rpc_id: Some(&id),
                raw_id: Some("2"),
                has_method: false,
                is_response: true,
                malformed_reason: Some("missing or invalid jsonrpc member"),
            },
        )
        .await;
        assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
        assert!(*abort_rx.borrow());
    }

    /// An unverifiable batch frame is blocked in dry-run the same as in
    /// enforce mode — dry-run must never raw-forward frames verification
    /// cannot cover.
    #[tokio::test]
    async fn batch_frame_is_blocked_in_dry_run() {
        let (shared, abort_rx) = shared_for_test(true);
        let line = r#"[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}]"#;
        let parsed = nojson::RawJson::parse(line);
        let mut st = S2cListState::new();
        let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
        assert!(matches!(result, Err(AuditorError::VerificationFailed(_))));
        assert!(*abort_rx.borrow());
    }

    /// Fail-closed ordering: the authoritative `tools_list.verified`
    /// record must commit before `record_verified_digest`, the busy-gate
    /// release, or the client emit. A dead sink refuses the whole
    /// transition — the response never leaves and calls stay gated.
    #[tokio::test]
    async fn dead_audit_sink_blocks_verified_transitions() {
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
        let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
        // Kill the sink before verification — the commit must refuse.
        shared.audit.shutdown().await.unwrap();

        shared.list_busy.store(true, Ordering::SeqCst);
        let mut st = S2cListState::new();
        st.bind_client("1".into(), String::new());
        st.append_page(two_tools()).unwrap();

        let result = verify_and_emit_list(&shared, &mut st, Some("1"), false).await;
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("dead audit sink must refuse verified transitions"),
        };
        assert!(
            matches!(err, AuditorError::AuditUnavailable(_)),
            "expected AuditUnavailable, got: {err:?}"
        );
        assert!(
            shared.list_busy.load(Ordering::SeqCst),
            "a refused verification must leave tools/call gated"
        );
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            !log.contains("\"event_type\":\"tools_list.verified\""),
            "no verified record may be claimed durable: {log}"
        );
    }

    /// On a live fail-closed sink the verification record is durable —
    /// the committed `tools_list.verified` precedes the client response
    /// in the stream.
    #[tokio::test]
    async fn verified_record_commits_before_client_emit() {
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
        let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
        let mut st = S2cListState::new();
        st.bind_client("1".into(), String::new());
        st.append_page(two_tools()).unwrap();
        verify_and_emit_list(&shared, &mut st, Some("1"), false)
            .await
            .unwrap();
        let _ = shared.audit.shutdown().await;
        let log = std::fs::read_to_string(&log_path).expect("read audit log");
        assert!(
            log.contains("\"event_type\":\"tools_list.verified\""),
            "verified record must persist, got: {log}"
        );
        assert!(log.contains("digest="), "got: {log}");
    }

    fn policy_allowing(name: &str) -> crate::policy::Policy {
        let mut policy = crate::policy::Policy::default();
        policy
            .tools
            .push(crate::policy::ToolPolicy::named(name, true));
        policy
    }

    fn two_tools() -> Vec<ToolDefinition> {
        vec![
            ToolDefinition::new("alpha", ""),
            ToolDefinition::new("beta", ""),
        ]
    }

    async fn revalidate_with(
        shared: &ProxyShared<tokio::io::DuplexStream>,
        st: &mut S2cListState,
        internal_id: u64,
        tools: Vec<ToolDefinition>,
    ) {
        st.begin_revalidation(String::new(), internal_id);
        st.append_page(tools).unwrap();
        let raw_id = internal_id.to_string();
        verify_and_emit_list(shared, st, Some(&raw_id), true)
            .await
            .unwrap();
    }

    /// A `list_changed` revalidation that yields the same advertised set
    /// as the last verified listing must not repeat the
    /// `tools_list.filtered` event — the hidden set it would enumerate was
    /// already audited.
    #[tokio::test]
    async fn identical_revalidation_does_not_repeat_filtered_event() {
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
        let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
        let mut st = S2cListState::new();

        // Client-initiated listing hides `beta` and logs the event once.
        st.bind_client("1".into(), String::new());
        st.append_page(two_tools()).unwrap();
        verify_and_emit_list(&shared, &mut st, Some("1"), false)
            .await
            .unwrap();

        // Identical internal revalidations add no new information.
        revalidate_with(&shared, &mut st, 910_001, two_tools()).await;
        revalidate_with(&shared, &mut st, 910_002, two_tools()).await;

        let _ = shared.audit.shutdown().await;
        let log = std::fs::read_to_string(&log_path).expect("read audit log");
        let events = log
            .matches("\"event_type\":\"tools_list.filtered\"")
            .count();
        assert_eq!(events, 1, "unchanged revalidations must not re-log: {log}");
    }

    /// Suppression applies only to identical relists: a revalidation whose
    /// advertised set changed still emits the filtered event.
    #[tokio::test]
    async fn changed_revalidation_logs_filtered_event() {
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
        let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
        let mut st = S2cListState::new();

        // First listing advertises only the allowed tool: nothing hidden.
        st.bind_client("1".into(), String::new());
        st.append_page(vec![ToolDefinition::new("alpha", "")])
            .unwrap();
        verify_and_emit_list(&shared, &mut st, Some("1"), false)
            .await
            .unwrap();

        // The relist now advertises an extra unlisted tool: logged.
        revalidate_with(&shared, &mut st, 910_001, two_tools()).await;
        // An identical relist is suppressed.
        revalidate_with(&shared, &mut st, 910_002, two_tools()).await;
        // A relist with yet another tool is a new set: logged again.
        let mut grown = two_tools();
        grown.push(ToolDefinition::new("gamma", ""));
        revalidate_with(&shared, &mut st, 910_003, grown).await;

        let _ = shared.audit.shutdown().await;
        let log = std::fs::read_to_string(&log_path).expect("read audit log");
        let events = log
            .matches("\"event_type\":\"tools_list.filtered\"")
            .count();
        assert_eq!(events, 2, "changed revalidations must each log: {log}");
        assert!(
            log.contains("gamma"),
            "new hidden tool must be named: {log}"
        );
    }

    /// Under dry-run the hidden set is forwarded, so the event must say
    /// the tools *would be* hidden. Without a tools-list-hash pin,
    /// `target_server` falls back to the single declared server identity.
    #[tokio::test]
    async fn dry_run_filtered_event_reports_would_be_hidden_and_declared_server() {
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
        let mut policy = policy_allowing("alpha");
        policy.tools[0].server = Some("bound-server".to_string());
        let (shared, _abort_rx) = shared_for_test_with(true, policy, audit);
        let mut st = S2cListState::new();

        st.bind_client("9".into(), String::new());
        st.append_page(two_tools()).unwrap();
        verify_and_emit_list(&shared, &mut st, Some("9"), false)
            .await
            .unwrap();

        let _ = shared.audit.shutdown().await;
        let log = std::fs::read_to_string(&log_path).expect("read audit log");
        let line = log
            .lines()
            .find(|l| l.contains("\"event_type\":\"tools_list.filtered\""))
            .expect("filtered event missing");
        assert!(line.contains("\"action\":\"observed\""), "got: {line}");
        assert!(line.contains("would be hidden"), "got: {line}");
        assert!(line.contains("beta"), "got: {line}");
        assert!(
            line.contains("\"target_server\":\"bound-server\""),
            "declared server name must be recorded: {line}"
        );
    }

    /// With no declared server identity the filtered event records no
    /// `target_server` — a synthetic name is never written.
    #[tokio::test]
    async fn filtered_event_without_declared_server_has_no_target() {
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
        let (shared, _abort_rx) = shared_for_test_with(false, policy_allowing("alpha"), audit);
        let mut st = S2cListState::new();

        st.bind_client("1".into(), String::new());
        st.append_page(two_tools()).unwrap();
        verify_and_emit_list(&shared, &mut st, Some("1"), false)
            .await
            .unwrap();

        let _ = shared.audit.shutdown().await;
        let log = std::fs::read_to_string(&log_path).expect("read audit log");
        let line = log
            .lines()
            .find(|l| l.contains("\"event_type\":\"tools_list.filtered\""))
            .expect("filtered event missing");
        assert!(line.contains("\"target_server\":null"), "got: {line}");
        assert!(line.contains("beta"), "got: {line}");
    }

    /// Multiple declared server identities are ambiguous — the event
    /// records no `target_server` rather than guessing one.
    #[tokio::test]
    async fn filtered_event_with_multiple_declared_servers_has_no_target() {
        let dir = crate::testutil::real_tempdir().expect("tempdir");
        let log_path = dir.path().join("audit.jsonl");
        let audit = crate::audit_log::AuditLogger::to_file(&log_path).expect("audit log");
        let mut policy = policy_allowing("alpha");
        policy.tools[0].server = Some("srv-a".to_string());
        let mut second = crate::policy::ToolPolicy::named("beta", true);
        second.server = Some("srv-b".to_string());
        policy.tools.push(second);
        let (shared, _abort_rx) = shared_for_test_with(false, policy, audit);
        let mut st = S2cListState::new();

        st.bind_client("1".into(), String::new());
        let mut advertised = two_tools();
        advertised.push(ToolDefinition::new("gamma", ""));
        st.append_page(advertised).unwrap();
        verify_and_emit_list(&shared, &mut st, Some("1"), false)
            .await
            .unwrap();

        let _ = shared.audit.shutdown().await;
        let log = std::fs::read_to_string(&log_path).expect("read audit log");
        let line = log
            .lines()
            .find(|l| l.contains("\"event_type\":\"tools_list.filtered\""))
            .expect("filtered event missing");
        assert!(line.contains("\"target_server\":null"), "got: {line}");
        assert!(line.contains("gamma"), "got: {line}");
    }

    #[tokio::test]
    async fn cancelled_list_kick_drives_queued_revalidation() {
        let (shared, _abort_rx) = shared_for_test(false);
        let mut st = S2cListState::new();
        // A client listing that already collected a page, cancelled while
        // a list_changed waited behind it.
        st.bind_client("7".into(), "{}".into());
        st.append_page(vec![]).unwrap();
        assert!(st.hold_list_changed("{}", true));
        shared.list_busy.store(true, Ordering::SeqCst);
        *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());
        // The resumed revalidation emits an internal tools/list request —
        // keep a live read half so the child_stdin write succeeds.
        let (_child_read, child_write) = tokio::io::duplex(4096);
        *shared.child_stdin.lock().await = Some(child_write);

        resume_queued_revalidation(&shared, &mut st).await.unwrap();

        assert!(st.is_revalidating());
        assert!(st.client_id().is_none());
        assert!(shared.list_busy.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn cancelled_list_kick_releases_gate_when_nothing_queued() {
        let (shared, _abort_rx) = shared_for_test(false);
        let mut st = S2cListState::new();
        st.bind_client("7".into(), "{}".into());
        st.append_page(vec![]).unwrap();
        shared.list_busy.store(true, Ordering::SeqCst);
        *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());

        resume_queued_revalidation(&shared, &mut st).await.unwrap();

        assert!(st.idle());
        assert!(!shared.list_busy.load(Ordering::SeqCst));
        assert!(!st.has_incomplete_listing());
    }

    #[tokio::test]
    async fn cancelled_list_kick_leaves_a_live_collection_alone() {
        let (shared, _abort_rx) = shared_for_test(false);
        let mut st = S2cListState::new();
        // The cancelled id is 7 but a *different* collection (id 9) is in
        // flight — it must not be released, and the gate must stay up
        // until that listing completes and drains the queue itself.
        st.bind_client("9".into(), "{}".into());
        st.append_page(vec![]).unwrap();
        shared.list_busy.store(true, Ordering::SeqCst);
        *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());

        resume_queued_revalidation(&shared, &mut st).await.unwrap();

        assert!(!st.idle());
        assert_eq!(st.client_id(), Some("9"));
        assert!(shared.list_busy.load(Ordering::SeqCst));
    }

    /// A cancel for an already-finished listing reaches the S2C loop
    /// *after* a new client `tools/list` has registered: the pending id
    /// is invisible to the local collection state (`st` is idle and no
    /// collection is bound), so only `pending_tools_list` tells resume
    /// that the raised gate now belongs to the new request. Clearing it
    /// would admit tools/call against an unverified listing; the queued
    /// revalidation must also stay queued for the new listing's own
    /// completion to drain.
    #[tokio::test]
    async fn cancelled_list_kick_keeps_the_gate_for_a_pending_listing() {
        let (shared, _abort_rx) = shared_for_test(false);
        let mut st = S2cListState::new();
        assert!(st.hold_list_changed("{}", true));
        shared.list_busy.store(true, Ordering::SeqCst);
        // id 7 finished on the S2C side already; id 8 registered its own
        // pending entry and re-acquired the gate.
        *shared.cancelled_list_id.lock().await = Some(RpcId::from_line(r#"{"id":7}"#).unwrap());
        shared
            .pending_tools_list
            .lock()
            .await
            .try_insert(RpcId::from_line(r#"{"id":8}"#).unwrap());

        resume_queued_revalidation(&shared, &mut st).await.unwrap();

        assert!(shared.list_busy.load(Ordering::SeqCst));
        assert!(
            !st.is_revalidating(),
            "a pending client listing owns the queue — revalidation must wait for its completion"
        );

        // Once the pending entry unwinds (its CAS lost, or its listing
        // completed), the same kick path re-drives the queued
        // revalidation instead of dropping the gate.
        let (_child_read, child_write) = tokio::io::duplex(4096);
        *shared.child_stdin.lock().await = Some(child_write);
        shared
            .pending_tools_list
            .lock()
            .await
            .remove(&RpcId::from_line(r#"{"id":8}"#).unwrap());
        resume_queued_revalidation(&shared, &mut st).await.unwrap();

        assert!(st.is_revalidating());
        assert!(shared.list_busy.load(Ordering::SeqCst));
    }

    /// A client `tools/list` held behind the post-`initialize` probe is
    /// answered from the verified emit the internal listing produces —
    /// the gate releases and the hold drains in the same completion.
    #[tokio::test]
    async fn held_client_list_is_answered_by_the_verified_emit() {
        let (shared, _abort_rx) = shared_for_test(false);
        let mut st = S2cListState::new();
        st.begin_revalidation("{}".into(), 910_001);
        shared.list_busy.store(true, Ordering::SeqCst);
        *shared.held_client_list.lock().await =
            Some((RpcId::from_line(r#"{"id":0}"#).unwrap(), "0".to_string()));
        st.append_page(vec![ToolDefinition::new("read_file", "")])
            .unwrap();

        verify_and_emit_list(&shared, &mut st, Some("910001"), true)
            .await
            .unwrap();

        assert!(shared.held_client_list.lock().await.is_none());
        assert!(!shared.list_busy.load(Ordering::SeqCst));
    }

    /// The residual-gate counterpart: a held listing that outlives its
    /// internal owner is answered with an error, not orphaned — the
    /// client retries on a clean path.
    #[tokio::test]
    async fn held_client_list_is_errored_by_a_residual_release() {
        let (shared, _abort_rx) = shared_for_test(false);
        let mut st = S2cListState::new();
        shared.list_busy.store(true, Ordering::SeqCst);
        *shared.held_client_list.lock().await =
            Some((RpcId::from_line(r#"{"id":0}"#).unwrap(), "0".to_string()));

        resume_queued_revalidation(&shared, &mut st).await.unwrap();

        assert!(shared.held_client_list.lock().await.is_none());
        assert!(!shared.list_busy.load(Ordering::SeqCst));
    }
}
