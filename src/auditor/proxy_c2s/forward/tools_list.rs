//! Client-facing `tools/list` arming for the C2S direction: the bounded
//! pending-id set, the busy gate, and the request template / original
//! capture the verified emit on the S2C side needs.

use std::sync::atomic::Ordering;

use super::super::C2S;
use crate::auditor::checker;
use crate::auditor::proxy_rpc;
use crate::auditor::proxy_state::{MAX_ORIGINAL_TOOLS_LIST_BYTES, ProxyShared};
use crate::auditor::proxy_wire::{build_jsonrpc_error, write_client_frame};
use crate::auditor::session::RpcId;
use crate::error::AuditorError;
use crate::policy::mcp::{DenyReason, McpVerdict};
use crate::protocol::SupportedProtocolVersion;
/// Arm the client-facing tracking a forwarded `tools/list` needs on the
/// response side: the bounded pending-id set, the busy gate, and the
/// original request keyed by raw id (the verified emit and internal
/// pagination rebuild from that, not from `last_list_template`).
/// Returns `true` when armed. `false` always means the request must not
/// be forwarded, but not that the client was answered: real contention
/// unwinds the entry, audits the refusal, and answers the client —
/// callers must not send a second reply — while a gate held by internal
/// work parks the request in `held_client_list` for the S2C side to
/// answer once that listing settles. The request template internal
/// revalidations rebuild from (`last_list_template`) is published inside
/// `register_and_forward` immediately before the request becomes
/// answerable — a refused or unwritten request can never seed it.
pub(super) async fn arm_tools_list<W>(
    shared: &ProxyShared<W>,
    view: &checker::VerifiedFrame<'_>,
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
    // Keyed by canonical RpcId — a canonically-equal response id in
    // a different spelling (`1` vs `1.0`) still resolves the entry.
    // The guard covers only the accounting: the audit write and the
    // client-facing refusal below run *after* it drops — holding the
    // originals map across a client write would stall every S2C site
    // that touches it (collection unwind, binding, cancel) behind a
    // slow client reader.
    let over_budget = {
        let originals = shared.original_tools_list.lock().await;
        let retained: usize = originals.values().map(|v| v.len()).sum();
        retained.saturating_add(view.frame().len()) > MAX_ORIGINAL_TOOLS_LIST_BYTES
    };
    if over_budget {
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
    shared
        .original_tools_list
        .lock()
        .await
        .insert(id.clone(), view.frame().to_string());
    // The pending entry is this listing's claim on the gate — a stray
    // response naming this id during the arm consumed it and already
    // answered the client, unwinding the bookkeeping this arm owns.
    // Forwarding now would double-answer the id and could strand the
    // gate with no pending entry left to drive its release. Treat the
    // consumed arm as a refusal: drop the just-published original and
    // kick so the S2C resume path resolves the gate. A bound
    // collection the stray created keeps `st` busy — resume leaves
    // its gate alone until that work settles.
    if !shared.pending_tools_list.lock().await.contains(id) {
        shared.original_tools_list.lock().await.remove(id);
        shared.list_kick.notify_one();
        return Ok(false);
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
/// drop the pending id and the stored request. `last_list_template`
/// needs no restore — the caller publishes it only after the forward
/// succeeds, so nothing here displaced it. `list_busy`
/// is not cleared here — only the S2C side ever releases the gate: a
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
