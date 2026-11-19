//! Oversized server→client frames: refused before parse, so the
//! retained head/tail windows stand in for the frame — recovered
//! `method`/`id` literals drive the drop, the server-side error, or the
//! correlated client error.

use std::sync::atomic::Ordering;

use super::{C2S, S2C, V26};
use crate::auditor::proxy_list_state::S2cListState;
use crate::auditor::proxy_rpc;
use crate::auditor::proxy_state::ProxyShared;
use crate::auditor::proxy_wire::{
    build_jsonrpc_error, frame_too_large_message, oversize_extra, recover_id_candidates,
    recover_method, rpc_id_from_raw_id, write_child_frame, write_client_frame,
};
use crate::auditor::session::RpcId;
use crate::error::AuditorError;
use crate::framing::OversizeFrame;
use crate::policy::mcp::{DenyReason, McpVerdict};
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
pub(super) async fn s2c_oversize<W>(
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
    // in-flight request is inert. `answered` and `take` run under one
    // lock hold: probing first and removing later would let a cancel /
    // capacity reclaim retire the matched request in between and hand
    // this handler either a stale entry or a replacement request
    // carrying the same id.
    let mut resolved: Option<(String, RpcId, proxy_rpc::TrackedRequest)> = None;
    for raw in recover_id_candidates(frame, true) {
        let Some(id) = rpc_id_from_raw_id(&raw) else {
            continue;
        };
        if matches!(id, RpcId::Null) {
            continue;
        }
        let entry = {
            let mut wire = shared.wire.lock().await;
            match wire.answered(S2C, &id) {
                Some(_) => wire.take(C2S, &id),
                None => None,
            }
        };
        if let Some(entry) = entry {
            resolved = Some((raw, id, entry));
            break;
        }
    }
    let Some((raw_id, id, entry)) = resolved else {
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

    // `entry` is the consumed wire registration — pending membership
    // alone cannot admit the frame since the pending entry is inserted
    // before registration, and a same-id entry for another method must
    // not unwind list bookkeeping.
    let on_list_path = (entry.method == "tools/list"
        && shared.pending_tools_list.lock().await.contains(&id))
        || st.is_internal_response(Some(&id));
    let method_label = entry.method.as_str().to_string();
    proxy_rpc::audit_decision(
        &shared.audit,
        S2C,
        "response",
        Some(method_label.as_str()),
        Some(raw_id.as_str()),
        version,
        McpVerdict::Deny(DenyReason::FrameTooLarge),
        false,
        shared.dry_run,
        extra(),
    )?;

    if entry.internal || st.is_internal_response(Some(&id)) {
        // Our own tools/list request got refused on size — the listing
        // can never verify; fail closed like any other rejected
        // internal response.
        st.discard_pages();
        shared.raise_list_gate().await;
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
        // Gate ownership needs more than pending membership: an arm
        // inserts its pending id BEFORE the gate CAS, so a response
        // naming an id whose CAS lost — transiently pending while the
        // gate belongs to the listing that beat it — could otherwise
        // consume the entry and clear a gate it never owned. An armed
        // listing publishes its original only after winning the CAS,
        // so `originals` membership separates owner from transient.
        let was_pending = shared.pending_tools_list.lock().await.remove(&id);
        let owned_unbound =
            was_pending && shared.original_tools_list.lock().await.contains_key(&id);
        // The bound client request id is what the client-facing error
        // echoes — peeked here because `release_collection_for` clears
        // it while checking the binding. The collection unwinds only
        // when this response's id canonically equals it — a reply
        // naming another pending listing id must leave the surviving
        // collection alone.
        let bound_id = st.client_id().map(str::to_string);
        let bound = bound_id
            .as_deref()
            .and_then(rpc_id_from_raw_id)
            .is_some_and(|cid| cid == id);
        // A pagination request in flight for this listing is still
        // registered on the wire table — retire it so a late answer
        // resolves as untracked rather than inheriting the freed id.
        if let Some(internal) = st.release_collection_for(&id) {
            shared.wire.lock().await.take(C2S, &internal);
        }
        // The gate drops when the rejected listing owned it: the bound
        // collection naming it, OR an armed but unbound listing whose
        // stored original proves it won the gate CAS. A collection
        // bound to a different id, or a transient pending id that lost
        // the CAS, keeps the real owner's gate latched.
        let rejected_owned_gate = bound || owned_unbound;
        // The error echoes the bound listing's id only when this
        // response was for it — a reply naming another pending id is
        // answered on its own raw id so the surviving collection is
        // never told its listing failed.
        let client_id = if bound {
            bound_id.unwrap_or_else(|| raw_id.clone())
        } else {
            raw_id.clone()
        };
        {
            // Keys are canonical `RpcId`s: the response's id and the
            // bound client id resolve to the same entry. The bound
            // listing's original goes only when this response was for
            // it.
            let mut originals = shared.original_tools_list.lock().await;
            originals.remove(&id);
            if bound && let Some(cid) = rpc_id_from_raw_id(&client_id) {
                originals.remove(&cid);
            }
        }
        if st.requires_abort_on_error() {
            // A revalidation or held list_changed outlives this listing
            // — fail the session like an in-flight revalidation error,
            // keeping the gate latched until the abort.
            shared.raise_list_gate().await;
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
        if rejected_owned_gate {
            shared.list_busy.store(false, Ordering::SeqCst);
        }
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
    if method_label == "tools/list" {
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
    if method_label == "tools/call"
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
