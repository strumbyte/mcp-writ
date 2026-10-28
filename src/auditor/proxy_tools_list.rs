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
        let response = build_tools_list_error_response(&raw_id);
        write_client_frame(&shared.client_out, &response).await?;
    }
    Ok(())
}

/// The id a client-facing listing failure answers: the bound or
/// correlated client id when the listing is client-owned, else a
/// `tools/list` held behind the internally-owned gate — the aborting
/// failure denies that held request, so its id is the right echo and
/// the slot is drained. `None` when nothing client-visible can be
/// correlated.
///
/// The failure reason is recorded into `internal_list_failure`
/// unconditionally: a `tools/list` still in transit in the C2S pipe —
/// flushed by the client but not yet parsed when the failure fired —
/// is answered by the abort drain whether or not a held request was
/// already denied inline (the drain's own held-slot take finds the
/// slot already drained, so nothing is answered twice). The recorded
/// bool tells the drain an inline reply already went out on a real
/// request id, so its `id: null` observability fallback stays silent.
async fn failure_emit_id<W>(
    shared: &ProxyShared<W>,
    resolved: Option<&str>,
    reason: &str,
) -> Option<String> {
    let emit = if let Some(id) = resolved {
        Some(id.to_string())
    } else {
        shared
            .held_client_list
            .lock()
            .await
            .take()
            .map(|(_id, raw_id)| raw_id)
    };
    *shared.internal_list_failure.lock().await = Some((reason.to_string(), emit.is_some()));
    emit
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
        *shared.internal_list_failure.lock().await = Some((block_reason.clone(), false));
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
            let error_response = build_tools_list_error_response(&id_str);
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
            let error_response = build_tools_list_error_response(&id_str);
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
                let error_response = build_tools_list_error_response(&id_str);
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
            let error_response = build_tools_list_error_response(&id_str);
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
            *shared.internal_list_failure.lock().await = Some((block_reason.clone(), false));
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
            let error_response = build_tools_list_error_response(&client_id);
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
                let error_response = build_tools_list_error_response(&id_str);
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
            let error_response = build_tools_list_error_response(&id_str);
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
                let error_response = build_tools_list_error_response(&id_str);
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
            *shared.internal_list_failure.lock().await = Some((block_reason.clone(), false));
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

    // Split the advertised set for the client-facing response only — pure
    // computation; the pin and the recorded digest cover the full
    // advertised set, not the filtered view the client sees.
    let (visible, hidden): (Vec<&ToolDefinition>, Vec<&ToolDefinition>) = tools_to_verify
        .iter()
        .partition(|tool| checker::tool_is_allowed(&shared.policy, &tool.name));

    let digest = match crate::verifier::tools_diff::hash_tools_list(&tools_to_verify) {
        Ok(digest) => Some(digest),
        Err(e) => {
            // Canonicalization is an integrity check too — it fails
            // closed in every mode; dry-run cannot expose definitions
            // whose canonical form could not be produced. The listing
            // joins the blocked path below: its `tools_list.verified`
            // record commits with `blocked=true` and no digest before
            // the refusal is emitted, so a refusal never goes
            // unrecorded.
            blocked = true;
            block_reason = format!(
                "hashing failed: {}",
                crate::termutil::sanitize_for_terminal(&e.to_string())
            );
            None
        }
    };

    // The authoritative verification record must be durable before any
    // verified state transition — `record_verified_digest`,
    // `finish_verification`, the busy-gate release, and the client emit
    // all follow this commit. A dead or saturated sink refuses here: no
    // unaudited manifest can publish verified state or cross to the
    // client. (On a best-effort logger the commit degrades to `log`.)
    // A blocked listing is recorded too: `blocked=true` carries
    // `outcome=failure`/`action=observed` — the refusal it precedes is
    // the error emit and abort below, not a verified state transition.
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
        if let Err(e) = shared.audit.log_committed(event).await {
            if blocked {
                // The blocked path still owes the session its abort
                // contract: record the refusal for the abort drain,
                // answer any correlatable client listing, and stop the
                // session — a held `tools/list` must not be left to
                // die at EOF just because the verification record
                // could not be committed.
                let emit_id = failure_emit_id(
                    shared,
                    client_facing_id(client_emit_id.as_deref(), raw_id, answered_internal),
                    &block_reason,
                )
                .await;
                // Abort ahead of the client write — a stalled client
                // must not delay session teardown.
                shared.abort_tx.send(true).ok();
                if let Some(emit_id) = emit_id {
                    let error_response = build_tools_list_error_response(&emit_id);
                    // Best-effort emit — the session is already ending
                    // on the audit-sink failure, which is the error
                    // this path reports.
                    let _ = write_client_frame(&shared.client_out, &error_response).await;
                }
            }
            return Err(e);
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
            let error_response = build_tools_list_error_response(&emit_id);
            write_client_frame(&shared.client_out, &error_response).await?;
        }
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::VerificationFailed(format!(
            "tools/list {block_reason}"
        )));
    }

    let mut digest_changed = false;
    if let Some(digest) = digest {
        let (verified_digest, changed) = st.record_verified_digest(digest);
        digest_changed = changed;
        // Publish a new verified generation before the busy gate drops:
        // a tools/call admitted under the prior generation sees the
        // mismatch at its pre-write recheck and unwinds. The advertised
        // name set moves with the counter under one lock — the pair is
        // the object `tools/call` authorization binds to, so a tool the
        // verified listing omitted loses its channel on this bump even
        // when the static policy names it.
        let next = {
            // A poisoned mutex still holds the generation/name pair —
            // recovering the guard keeps the S2C task alive instead of
            // panicking the forwarding path on a sibling task's panic.
            let mut vt = shared
                .verified_tools
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            vt.generation += 1;
            vt.names = if shared.dry_run {
                tools_to_verify.iter().map(|t| t.name.clone()).collect()
            } else {
                visible.iter().map(|t| t.name.clone()).collect()
            };
            vt.generation
        };
        shared.list_generation.store(next, Ordering::SeqCst);
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
        // The requested operation — filtering the advertised tools/list
        // down to the allowed set — completed, so the outcome is
        // `success`; the refusal itself travels in `action` (`denied`,
        // or `observed` for the would-be denial under dry-run). The
        // record commits before the filtered response is forwarded, so
        // `success` asserts that filtering finished — it is not proof
        // the reply reached the client. `outcome=failure` stays
        // reserved for operations that did not complete, like a blocked
        // verification.
        let mut event = AuditEvent::new(
            Uuid::now_v7(),
            EventType::ToolsListFiltered,
            Severity::Info,
            Outcome::Success,
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
mod tests;
