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
    recover_id_candidates_proven, recover_method, recover_response_evidence,
    recover_response_shape, rpc_id_from_raw_id, write_child_frame, write_client_frame,
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
/// audited. Otherwise the frame may be a response — but a request's
/// `method` can also sit in the omitted middle, so correlation first
/// requires the retained head to *prove* response shape (a `result` or
/// `error` member at envelope depth) and only provable top-level `id`
/// candidates — head-window hits, never a tail hit a nested
/// `result.id` could impersonate — are resolved against the tracked
/// request table. A resolved id releases the request's tracking —
/// tools/list bookkeeping unwinds the same way a rejected list
/// response does — and the client gets a per-request JSON-RPC error on
/// that id; the session continues on the next frame. A response that
/// cannot be correlated is audited and answered with `id: null` — the
/// JSON-RPC convention for an error that cannot name its request —
/// rather than dropping the session over it. The unproven `id`
/// candidates still decide what the frame may have stranded: an id
/// naming a live request retires it with a per-request error (an
/// internal id aborts, a pending `tools/list` unwinds through the list
/// machinery), while a frame offering no trustworthy request-specific
/// evidence — no candidates, or only untracked ones — must not select
/// or fail unrelated pending requests.
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

    // Response-shaped — but a request's `method` can sit in the omitted
    // middle, so correlation is allowed only when the retained head
    // proves the frame is a response (`result`/`error` at envelope
    // depth); a frame showing neither may be an oversized server
    // request whose live `id` must not be retired. Correlation
    // candidates are likewise restricted to provable top-level members
    // — head-window hits only: a disjoint tail's backward scan can
    // promote a nested `result.id` to apparent envelope depth. (The
    // unresolvable arm below does consult unproven tail hits — as
    // attribution hints for which live requests the frame stranded —
    // never as the frame's own proven id.) `answered` and `take` run
    // under one lock hold: probing first and removing later would let a
    // cancel / capacity reclaim retire the matched request in between
    // and hand this handler either a stale entry or a replacement
    // request carrying the same id.
    let mut resolved: Option<(String, RpcId, proxy_rpc::TrackedRequest)> = None;
    if recover_response_evidence(frame) {
        for raw in recover_id_candidates_proven(frame) {
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
        write_client_frame(
            &shared.client_out,
            &build_jsonrpc_error(
                "null",
                &frame_too_large_message("response", shared.max_frame_bytes),
            ),
        )
        .await?;
        // The frame provably carried a response the proxy could not
        // correlate, so whichever in-flight request it answered may now
        // wait forever on a reply that is never coming. Shape — a
        // `result`/`error` member at envelope depth — is enough for
        // this: even a fully retained frame whose `jsonrpc` member is
        // missing or invalid consumed its response slot, so returning
        // success here would strand whatever it answered. The unproven
        // `id` candidates — tail hits never complete an RPC, but they
        // are the best attribution hint the frame leaves — select what
        // the frame plausibly stranded: a candidate naming a live
        // request marks that call, a tools/list candidate unwinds its
        // listing through the same path a correlated refusal takes,
        // and an internal id aborts like the internal rejection.
        // Candidates naming only untracked ids make the frame an
        // orphan that stranded nothing, and a frame that yields no
        // candidate at all provides no request-specific evidence — a
        // null-id error must never select or fail unrelated pending
        // requests.
        if recover_response_shape(frame) {
            // Tail-window candidates are attribution hints only when
            // the windows cover the whole frame: the tail scan then
            // proves the trailing `}`/`]` really is a root close —
            // the forward scan must see depth return to 0 exactly at
            // the frame's last byte, back to the frame's own first
            // byte. On a disjoint tail no byte is the frame start, so
            // no close in it can be proven a root close — a nested
            // `result.id` ending an unclosed root reads identically to
            // a genuine trailing envelope `id` — and on an
            // unterminated tail cut mid-frame the last byte may be a
            // nested close either way. Unproven hits could retire,
            // unwind, or abort a live request they were never
            // addressed to, so only proven candidates are trusted.
            let candidates = recover_id_candidates(frame, true);
            let no_candidates = candidates.is_empty();
            for raw in candidates {
                let Some(sid) = rpc_id_from_raw_id(&raw) else {
                    continue;
                };
                if matches!(sid, RpcId::Null) {
                    continue;
                }
                // Only a live, dispatched request can have been answered
                // — the `take` below still revalidates because a cancel
                // or reclaim can retire the selected entry first.
                let Some(answered) = shared.wire.lock().await.answered(S2C, &sid) else {
                    continue;
                };
                if answered.internal || st.is_internal_response(Some(&sid)) {
                    return Err(abort_internal_listing(shared, st).await);
                }
                let on_list_path = answered.method == "tools/list"
                    && shared.pending_tools_list.lock().await.contains(&sid);
                if on_list_path {
                    // Retire the registration, then unwind the pending
                    // listing — the same unwind a correlated refusal
                    // takes.
                    shared.wire.lock().await.take(C2S, &sid);
                    return unwind_oversized_listing(shared, st, &sid, &raw).await;
                }
                if answered.method == "tools/list" {
                    // A stale answer to a cancelled client listing —
                    // its bookkeeping is already gone; nothing is owed.
                    continue;
                }
                let entry = shared.wire.lock().await.take(C2S, &sid);
                let Some(entry) = entry else {
                    continue;
                };
                if entry.method == "tools/call"
                    && let Some(ref session) = shared.session
                {
                    let mut state = session.lock().await;
                    state.take_pending_list(&sid);
                    state.release_pending_tool_call_unverified(&sid);
                }
                write_client_frame(
                    &shared.client_out,
                    &build_jsonrpc_error(
                        &sid.to_json_literal(),
                        &frame_too_large_message("response", shared.max_frame_bytes),
                    ),
                )
                .await?;
            }
            // Nothing was attributed: the frame provably consumed a
            // response slot yet named no recoverable request — when
            // dispatched requests are still awaiting answers, whichever
            // one it answered may now wait forever, and its identity is
            // unprovable. A dropped `id` in the omitted middle is
            // indistinguishable from a stray frame, so per-request
            // failure cannot be isolated: terminate the session and
            // let teardown settle the pending calls rather than leave
            // them hanging or fail unrelated work. Candidates that
            // resolved to live requests were handled above; candidates
            // naming only untracked ids make the frame an orphan that
            // stranded nothing it claimed.
            if no_candidates && shared.wire.lock().await.has_unanswered(C2S) {
                return Err(AuditorError::VerificationFailed(
                    "oversized response could not be attributed to an in-flight request"
                        .to_string(),
                ));
            }
        }
        return Ok(());
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
        return Err(abort_internal_listing(shared, st).await);
    }
    if on_list_path {
        // Client-facing listing: unwind pending/original/collection and
        // answer the client — the same unwind a rejected tools/list
        // response takes.
        return unwind_oversized_listing(shared, st, &id, &raw_id).await;
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

/// The fail-closed unwind an oversized internal `tools/list` response
/// takes — the listing can never verify: drop the collection, keep the
/// gate raised until the abort, record the failure for the abort drain,
/// and stop the session. Shared by the correlated arm and the
/// candidate-driven path that attributes the frame to an internal id.
async fn abort_internal_listing<W>(shared: &ProxyShared<W>, st: &mut S2cListState) -> AuditorError
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    st.discard_pages();
    shared.raise_list_gate().await;
    // A client listing coalesced behind this internal one — held, or
    // still in transit in the C2S pipe — is answered with this reason
    // by the abort drain.
    *shared.internal_list_failure.lock().await =
        Some((DenyReason::FrameTooLarge.as_str().to_string(), false));
    shared.abort_tx.send(true).ok();
    AuditorError::VerificationFailed(format!(
        "internal tools/list response rejected ({})",
        DenyReason::FrameTooLarge.as_str()
    ))
}

/// The client-facing listing unwind a rejected or unresolvable oversized
/// `tools/list` response takes: pending/original/collection bookkeeping
/// releases, the busy gate drops only when this listing owned it, and
/// the client gets a JSON-RPC error on the correlated id. A queued
/// revalidation outliving the listing fails the session instead.
async fn unwind_oversized_listing<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    id: &RpcId,
    raw_id: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Gate ownership needs more than pending membership: an arm inserts
    // its pending id BEFORE the gate CAS, so a response naming an id
    // whose CAS lost — transiently pending while the gate belongs to the
    // listing that beat it — could otherwise consume the entry and clear
    // a gate it never owned. An armed listing publishes its original
    // only after winning the CAS, so `originals` membership separates
    // owner from transient.
    let was_pending = shared.pending_tools_list.lock().await.remove(id);
    let owned_unbound = was_pending && shared.original_tools_list.lock().await.contains_key(id);
    // The bound client request id is what the client-facing error echoes
    // — peeked here because `release_collection_for` clears it while
    // checking the binding. The collection unwinds only when this
    // response's id canonically equals it — a reply naming another
    // pending listing id must leave the surviving collection alone.
    let bound_id = st.client_id().map(str::to_string);
    let bound = bound_id
        .as_deref()
        .and_then(rpc_id_from_raw_id)
        .is_some_and(|cid| cid == *id);
    // A pagination request in flight for this listing is still
    // registered on the wire table — retire it so a late answer resolves
    // as untracked rather than inheriting the freed id.
    if let Some(internal) = st.release_collection_for(id) {
        shared.wire.lock().await.take(C2S, &internal);
    }
    // The gate drops when the rejected listing owned it: the bound
    // collection naming it, OR an armed but unbound listing whose stored
    // original proves it won the gate CAS. A collection bound to a
    // different id, or a transient pending id that lost the CAS, keeps
    // the real owner's gate latched.
    let rejected_owned_gate = bound || owned_unbound;
    // The error echoes the bound listing's id only when this response
    // was for it — a reply naming another pending id is answered on its
    // own raw id so the surviving collection is never told its listing
    // failed.
    let client_id = if bound {
        bound_id.unwrap_or_else(|| raw_id.to_string())
    } else {
        raw_id.to_string()
    };
    {
        // Keys are canonical `RpcId`s: the response's id and the bound
        // client id resolve to the same entry. The bound listing's
        // original goes only when this response was for it.
        let mut originals = shared.original_tools_list.lock().await;
        originals.remove(id);
        if bound && let Some(cid) = rpc_id_from_raw_id(&client_id) {
            originals.remove(&cid);
        }
    }
    if st.requires_abort_on_error() {
        // A revalidation or held list_changed outlives this listing —
        // fail the session like an in-flight revalidation error, keeping
        // the gate latched until the abort.
        shared.raise_list_gate().await;
        // The bound client listing dies with the session — answer it on
        // its own id first: it already crossed C2S, so the abort drain
        // cannot correlate it (it is neither held nor in transit in the
        // pipe).
        let answered = write_client_frame(
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
        // A client listing held behind the pending revalidation is
        // answered by the abort drain; the flag records whether the
        // inline reply on a real request id made the abort observable —
        // record it and signal abort even when the reply write failed,
        // so the drain settles held work with the right reason.
        *shared.internal_list_failure.lock().await = Some((
            DenyReason::FrameTooLarge.as_str().to_string(),
            answered.is_ok(),
        ));
        shared.abort_tx.send(true).ok();
        answered?;
        return Err(AuditorError::VerificationFailed(format!(
            "tools/list response rejected while a revalidation is pending ({})",
            DenyReason::FrameTooLarge.as_str()
        )));
    }
    if rejected_owned_gate {
        shared.list_busy.store(false, Ordering::SeqCst);
    }
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
    .await
}
