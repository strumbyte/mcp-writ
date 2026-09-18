//! tools/list collection, verification, and revalidation for the
//! server→client direction of `run_proxy`.
//!
//! Responsibilities:
//! - `notifications/tools/list_changed` hold + internal revalidation emission
//! - response id matching, pagination, cursor tracking, page cap
//! - first-seen manifest scan, baseline/hash diff, verified response emission
//! - fail-closed error responses and session abort on verification failure

use std::sync::atomic::Ordering;

use super::checker;
use super::proxy_list_state::S2cListState;
use super::proxy_state::ProxyShared;
use super::proxy_wire::{
    build_internal_tools_list_request, build_pagination_request, build_tools_list_error_response,
    build_verified_tools_list_response, client_facing_id, response_result_has_tools_field,
    write_child_frame, write_client_frame,
};
use super::session::RpcId;
use crate::error::AuditorError;

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
    let was_busy = shared.list_busy.swap(true, Ordering::SeqCst);
    if st.hold_list_changed(line, was_busy) {
        return Ok(());
    }
    begin_revalidation(shared, st).await
}

/// Start a re-list without releasing the shared busy flag or held notification.
async fn begin_revalidation<W>(
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
    } = frame;
    let parsed_value = parsed_line.as_ref().ok().map(|j| j.value());
    // True when this response answers an internally emitted
    // request (pagination follow-up or list_changed
    // revalidation). Its id is an internal request id that
    // must never be echoed to the client. Captured once here
    // because waiting_internal_id is cleared later in the loop.
    let answered_internal = st.is_internal_response(raw_id);

    // A top-level array is a JSON-RPC batch frame. C2S already rejects
    // client batch requests, so no in-flight tools/list id can
    // legitimately be answered inside a batch; per-element verification
    // is unavailable, so the frame is rejected rather than forwarded
    // (a pending-id response inside a batch would bypass verification).
    if parsed_value.is_some_and(|v| v.kind() == nojson::JsonValueKind::Array) {
        let block_reason = "batch frames are not supported in server responses".to_string();
        if shared.dry_run {
            tracing::warn!(reason = %block_reason, "[DRY-RUN] batch frame from server, forwarding");
            write_client_frame(&shared.client_out, line).await?;
            return Ok(ListFlow::Handled);
        }
        tracing::error!(reason = %block_reason, "batch frame from server: blocking");
        let id_str = client_facing_id(st.client_id(), raw_id, answered_internal).unwrap_or("null");
        let error_response = build_tools_list_error_response(id_str, &block_reason);
        write_client_frame(&shared.client_out, &error_response).await?;
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::PolicyViolation(block_reason));
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
            // consume them. A malformed envelope carrying a pending id
            // (method plus result/error) is still flagged so the
            // malformed-envelope check below blocks it, without
            // consuming the entry.
            let tracked = if is_response {
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

    if is_tools_list_response && has_method {
        let block_reason = "malformed tools/list envelope (method)".to_string();
        if shared.dry_run {
            tracing::warn!(reason = %block_reason, "[DRY-RUN] malformed tools/list envelope, forwarding");
            write_client_frame(&shared.client_out, line).await?;
            return Ok(ListFlow::Handled);
        }
        tracing::error!(reason = %block_reason, "malformed tools/list envelope: blocking");
        let id_str = client_facing_id(st.client_id(), raw_id, answered_internal).unwrap_or("null");
        let error_response = build_tools_list_error_response(id_str, &block_reason);
        write_client_frame(&shared.client_out, &error_response).await?;
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::PolicyViolation(block_reason));
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
            let block_reason = format!("invalid JSON in tools/list response: {e}");
            if shared.dry_run {
                tracing::warn!(reason = %block_reason, "[DRY-RUN] Invalid JSON in tools/list response, forwarding");
            } else {
                tracing::error!(reason = %block_reason, "Invalid JSON in tools/list response: blocking session");
                let id_str =
                    client_facing_id(st.client_id(), raw_id, answered_internal).unwrap_or("null");
                let error_response = build_tools_list_error_response(id_str, &block_reason);
                write_client_frame(&shared.client_out, &error_response).await?;
                shared.abort_tx.send(true).ok();
                return Err(AuditorError::PolicyViolation(block_reason));
            }
            write_client_frame(&shared.client_out, line).await?;
            return Ok(ListFlow::Handled);
        }
    };

    if let Err(violation) = checker::check_duplicate_keys_recursively(parsed_json.value()) {
        let block_reason = format!(
            "duplicate keys in tools/list response: {}",
            violation.reason
        );
        if shared.dry_run {
            tracing::warn!(reason = %block_reason, "[DRY-RUN] Duplicate keys in tools/list response, forwarding");
        } else {
            tracing::error!(reason = %block_reason, "Duplicate keys in tools/list response: blocking session");
            let id_str =
                client_facing_id(st.client_id(), raw_id, answered_internal).unwrap_or("null");
            let error_response = build_tools_list_error_response(id_str, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::PolicyViolation(block_reason));
        }
        write_client_frame(&shared.client_out, line).await?;
        return Ok(ListFlow::Handled);
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
            let mut originals = shared.original_tools_list.lock().await;
            if let Some(id) = st.client_id() {
                originals.remove(id);
            }
            if let Some(id) = raw_id {
                originals.remove(id);
            }
        }
        if st.requires_abort_on_error() {
            // Keep list_busy set until session abort completes so
            // concurrent tools/call stays denied (fail-secure).
            let block_reason = "tools/list revalidation returned an error".to_string();
            tracing::error!(reason = %block_reason, "list_changed revalidation failed");
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::PolicyViolation(block_reason));
        }
        shared.list_busy.store(false, Ordering::SeqCst);
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

    // Must parse successfully as ToolsListPage; parsing failures are blocked
    let page = match crate::legislator::tools_list::parse_tools_list_response_page(line) {
        Ok(p) => p,
        Err(e) => {
            let block_reason = format!("malformed tools/list response: {e}");
            if shared.dry_run {
                tracing::warn!(reason = %block_reason, "[DRY-RUN] Malformed tools/list response, forwarding");
            } else {
                tracing::error!(reason = %block_reason, "Malformed tools/list response: blocking session");
                let id_str =
                    client_facing_id(st.client_id(), raw_id, answered_internal).unwrap_or("null");
                let error_response = build_tools_list_error_response(id_str, &block_reason);
                write_client_frame(&shared.client_out, &error_response).await?;
                shared.abort_tx.send(true).ok();
                return Err(AuditorError::PolicyViolation(block_reason));
            }
            write_client_frame(&shared.client_out, line).await?;
            return Ok(ListFlow::Handled);
        }
    };

    // Buffer tools across pages; never emit until the final page verifies.
    if let Err(block_reason) = st.append_page(page.tools) {
        let id_str = client_facing_id(st.client_id(), raw_id, answered_internal).unwrap_or("null");
        let error_response = build_tools_list_error_response(id_str, &block_reason);
        write_client_frame(&shared.client_out, &error_response).await?;
        shared.abort_tx.send(true).ok();
        return Err(AuditorError::PolicyViolation(block_reason));
    }

    if st.needs_client_binding() {
        if let Some(id) = raw_id.map(str::to_string) {
            let original = shared
                .original_tools_list
                .lock()
                .await
                .remove(&id)
                .unwrap_or_default();
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
            let id_str =
                client_facing_id(st.client_id(), raw_id, answered_internal).unwrap_or("null");
            let error_response = build_tools_list_error_response(id_str, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::PolicyViolation(block_reason));
        }
        let internal_id = shared.next_internal_id.fetch_add(1, Ordering::Relaxed);
        let follow = build_pagination_request(st.original_request(), internal_id, &cursor);
        st.expect_internal_response(internal_id);
        write_child_frame(&shared.child_stdin, &follow).await?;
        return Ok(ListFlow::Handled);
    }

    verify_and_emit_list(shared, st, raw_id, answered_internal).await
}

/// Verification begins only after all pages have been collected. Preserve
/// the revalidation context until the result and held notification are emitted.
async fn verify_and_emit_list<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    raw_id: Option<&str>,
    answered_internal: bool,
) -> Result<ListFlow, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (tools_to_verify, client_emit_id) = st.take_completed_pages();

    let mut blocked = false;
    let mut block_reason = String::new();

    // first-seen CC scan on the pagination-assembled set.
    // Hash match does not waive Critical/High findings.
    let scan_server = shared
        .policy
        .tools_list_hashes
        .first()
        .map(|e| e.server_name.as_str())
        .unwrap_or("default");
    let manifest_findings = crate::verifier::manifest::scan_manifest(&tools_to_verify);
    crate::verifier::manifest::log_manifest_scan_for(
        scan_server,
        &manifest_findings,
        &shared.audit,
        shared.fail_on,
    );
    let first_seen_block =
        crate::verifier::manifest::format_blocking_reason_for(&manifest_findings, shared.fail_on);
    if let Some(reason) = first_seen_block.clone() {
        blocked = true;
        block_reason = reason;
    }

    if !blocked && shared.policy.tools_list_hashes.is_empty() {
        let baseline = crate::legislator::tools_list::load_baseline("default")
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
            block_reason = diff_output;
        }
    } else if !blocked {
        for entry in &shared.policy.tools_list_hashes {
            let baseline = crate::legislator::tools_list::load_baseline(&entry.server_name)
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
                    block_reason = diff_output;
                    break;
                }
            }
        }
    }

    if blocked {
        // Effective first-seen blocking is fail-closed even in
        // dry-run: never forward a tools/list result.
        // list_changed revalidation uses the same fail-on
        // threshold. Other verification failures (hash
        // mismatch) keep the dry-run forward path only for
        // client-initiated tools/list.
        let fail_closed = first_seen_block.is_some() || !shared.dry_run || st.is_revalidating();
        if fail_closed {
            if shared.dry_run {
                tracing::warn!(
                    reason = %block_reason,
                    fail_on = shared.fail_on.as_str(),
                    "[DRY-RUN] first-seen CC at fail-on threshold: emitting error, not forwarding tools/list result"
                );
            } else {
                tracing::error!(
                    reason = %block_reason,
                    "tools/list verification failed: blocking response"
                );
            }
            let emit_id = client_facing_id(client_emit_id.as_deref(), raw_id, answered_internal)
                .unwrap_or("null");
            let error_response = build_tools_list_error_response(emit_id, &block_reason);
            write_client_frame(&shared.client_out, &error_response).await?;
            shared.abort_tx.send(true).ok();
            return Err(AuditorError::PolicyViolation(format!(
                "tools/list verification failed: {block_reason}"
            )));
        }
        tracing::warn!(
            reason = %block_reason,
            "[DRY-RUN] tools/list verification failed (blocked), forwarding synthetic list"
        );
    }

    let digest = match crate::verifier::tools_diff::hash_tools_list(&tools_to_verify) {
        Ok(digest) => Some(digest),
        Err(e) => {
            let block_reason = format!("tools/list hashing failed: {e}");
            // Same fail-closed rule as blocked verification
            // above: dry-run tolerates the failure only for
            // client-initiated tools/list; internal
            // revalidation always aborts.
            if shared.dry_run && !st.is_revalidating() {
                tracing::warn!(
                    reason = %block_reason,
                    "[DRY-RUN] tools/list canonicalization failed, forwarding synthetic list"
                );
                None
            } else {
                if shared.dry_run {
                    tracing::warn!(reason = %block_reason, "[DRY-RUN] tools/list canonicalization failed during internal revalidation: blocking session");
                } else {
                    tracing::error!(reason = %block_reason, "tools/list canonicalization failed: blocking session");
                }
                // Internal request ids are never echoed:
                // the frame id is the client-facing id, or
                // null when no client request can be
                // correlated.
                let emit_id =
                    client_facing_id(client_emit_id.as_deref(), raw_id, answered_internal)
                        .unwrap_or("null");
                let error_response = build_tools_list_error_response(emit_id, &block_reason);
                write_client_frame(&shared.client_out, &error_response).await?;
                shared.abort_tx.send(true).ok();
                return Err(AuditorError::PolicyViolation(format!(
                    "tools/list verification failed: {block_reason}"
                )));
            }
        }
    };
    if let Some(digest) = digest {
        let verified_digest = st.record_verified_digest(digest);
        tracing::debug!(hash = verified_digest, "tools/list last_verified updated");
    }

    let verified = if let Some(emit_id) = client_emit_id {
        Some(build_verified_tools_list_response(
            &emit_id,
            &tools_to_verify,
        ))
    } else if !st.is_revalidating() && !answered_internal {
        let emit_id = raw_id.unwrap_or("null");
        Some(build_verified_tools_list_response(
            emit_id,
            &tools_to_verify,
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
        write_client_frame(&shared.client_out, &verified).await?;
    }

    if revalidate {
        begin_revalidation(shared, st).await?;
        return Ok(ListFlow::Handled);
    }

    if let Some(notif) = st.take_verified_notification() {
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
        let (abort_tx, abort_rx) = watch::channel(false);
        let (_child_read, child_write) = tokio::io::duplex(64);
        let shared = ProxyShared {
            policy: crate::policy::Policy::default(),
            dry_run,
            fail_on: crate::verifier::fail_on::FailOn::DEFAULT,
            audit: Arc::new(crate::auditor::audit_log::AuditLogger::to_tracing()),
            session: None,
            pending_tools_list: Arc::new(Mutex::new(PendingToolsList::new())),
            client_out: Arc::new(Mutex::new(tokio::io::stdout())),
            child_stdin: Arc::new(Mutex::new(Some(child_write))),
            original_tools_list: Arc::new(Mutex::new(std::collections::HashMap::new())),
            list_busy: Arc::new(std::sync::atomic::AtomicBool::new(false)),
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
        assert!(matches!(result, Err(AuditorError::PolicyViolation(_))));
        assert!(*abort_rx.borrow());
    }

    #[tokio::test]
    async fn batch_frame_without_pending_ids_is_blocked() {
        let (shared, abort_rx) = shared_for_test(false);
        let line = r#"[{"jsonrpc":"2.0","method":"notifications/progress","params":{}}]"#;
        let parsed = nojson::RawJson::parse(line);
        let mut st = S2cListState::new();
        let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
        assert!(matches!(result, Err(AuditorError::PolicyViolation(_))));
        assert!(*abort_rx.borrow());
    }

    #[tokio::test]
    async fn batch_frame_forwards_in_dry_run() {
        let (shared, abort_rx) = shared_for_test(true);
        let line = r#"[{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}]"#;
        let parsed = nojson::RawJson::parse(line);
        let mut st = S2cListState::new();
        let result = handle_tools_list_response(&shared, &mut st, batch_frame(line, &parsed)).await;
        assert!(matches!(result, Ok(ListFlow::Handled)));
        assert!(!*abort_rx.borrow());
    }
}
