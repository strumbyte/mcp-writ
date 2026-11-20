//! Wire-table registration and the child write for the C2S direction:
//! the tracked request commits under the wire lock together with the
//! forward-time side effects, the decision record is send-ordered ahead
//! of the frame, and write failure is reconciled by what it proves —
//! proven non-delivery unwinds entry and side effects, while
//! `DeliveryUncertain` retains them (the complete frame may have
//! crossed) and the session ends on the propagated error.

use std::sync::atomic::Ordering;

use super::super::C2S;
use super::request_extra;
use crate::auditor::checker;
use crate::auditor::proxy_rpc::{self, ExtractedRequest, TrackedRequest};
use crate::auditor::proxy_state::ProxyShared;
use crate::auditor::proxy_wire::{
    build_jsonrpc_error, write_child_frame_epoch, write_client_frame,
};
use crate::auditor::session::RpcId;
use crate::error::AuditorError;
use crate::policy::mcp::{DenyReason, McpVerdict};
use crate::protocol::SupportedProtocolVersion;
/// Register in the wire table, apply forward-time side effects, write.
/// Side effects commit under the same lock as the registration so a
/// response that lands the instant the write completes already sees
/// them. `Ok(false)` means the request never left: registration refused
/// it (duplicate id / capacity), or the epoch-guarded recheck caught a
/// stale admission — including an entry a response already answered —
/// either way the registration is rolled back and the client got an
/// error, so callers with bookkeeping must unwind. `Err` from the write
/// is reconciled by what it proves: proven non-delivery (an incomplete
/// frame can never parse) rolls back the entry and its side effects;
/// `DeliveryUncertain` retains them — the complete frame may have
/// crossed — while the error still ends the session.
#[expect(clippy::too_many_arguments)]
pub(super) async fn register_and_forward<W>(
    shared: &ProxyShared<W>,
    view: &checker::VerifiedFrame<'_>,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    ext: &ExtractedRequest,
    expected_list_gen: Option<u64>,
) -> Result<bool, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    register_and_forward_impl(
        shared,
        view,
        method,
        id,
        raw_id,
        version,
        ext,
        true,
        Some(verdict),
        expected_list_gen,
    )
    .await
}

/// Dry-run forward of a denied request: tracked with `allowed: false`.
/// The caller commits the deny verdict's audit record *before* calling
/// here — the refusal must be durable ahead of delivery to the child,
/// not recorded once the forward result is known. `Ok(false)` has the
/// same refusal-or-stale-admission meaning as the allowed path. A
/// proven non-delivery write failure unwinds the registration without a
/// corrective record — the caller's committed decision already stands
/// as the request's fate — while `DeliveryUncertain` retains it because
/// the frame may still have crossed.
#[allow(clippy::too_many_arguments)]
pub(super) async fn register_and_forward_denied<W>(
    shared: &ProxyShared<W>,
    view: &checker::VerifiedFrame<'_>,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    ext: &ExtractedRequest,
    expected_list_gen: Option<u64>,
) -> Result<bool, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    register_and_forward_impl(
        shared,
        view,
        method,
        id,
        raw_id,
        version,
        ext,
        false,
        None,
        expected_list_gen,
    )
    .await
}

/// `audit_verdict` is `Some` only for policy-allowed forwards — the
/// decision (or a registration refusal) is recorded here. Denied
/// dry-run forwards pass `None`; their caller owns the audit record.
///
/// Outcomes: `Ok(true)` — the request crossed and is answerable.
/// `Ok(false)` — refused by registration or by the stale-admission
/// recheck (including an id a response already answered); the wire
/// entry is rolled back and the client already has an error. `Err` —
/// proven non-delivery rolls back entry and side effects;
/// `DeliveryUncertain` retains both and propagates.
#[expect(clippy::too_many_arguments)]
pub(super) async fn register_and_forward_impl<W>(
    shared: &ProxyShared<W>,
    view: &checker::VerifiedFrame<'_>,
    method: &str,
    id: &RpcId,
    raw_id: &str,
    version: SupportedProtocolVersion,
    ext: &ExtractedRequest,
    allowed: bool,
    audit_verdict: Option<McpVerdict>,
    expected_list_gen: Option<u64>,
) -> Result<bool, AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let undo = {
        let mut wire = shared.wire.lock().await;
        // Born undispatched: the entry exists for rollback ahead of the
        // write, but `answered`/`take` cannot see it — a frame naming
        // this id while the request still sits in the child-stdin pipe
        // is an anomaly that must not retire a request the server never
        // received. `mark_dispatched` runs when the write completes.
        let mut tracked =
            TrackedRequest::from_extracted(method, version, allowed, shared.dry_run, ext);
        tracked.dispatched = false;
        match wire.register(C2S, id.clone(), tracked) {
            Err(reason) => {
                drop(wire);
                if audit_verdict.is_some() {
                    // Registration refused an allowed request (duplicate
                    // id / capacity) — audit it like the S2C direction.
                    proxy_rpc::audit_decision(
                        &shared.audit,
                        C2S,
                        "request",
                        Some(method),
                        Some(raw_id),
                        version,
                        McpVerdict::Deny(DenyReason::Shape),
                        false,
                        shared.dry_run,
                        Some(format!("register={reason}")),
                    )?;
                }
                write_client_frame(
                    &shared.client_out,
                    &build_jsonrpc_error(raw_id, &format!("request denied ({reason})")),
                )
                .await?;
                return Ok(false);
            }
            Ok(()) => wire.on_request_forwarded(C2S, id, method, version, ext),
        }
    };
    // The decision record is send-ordered ahead of the frame — the
    // protected action must never cross ahead of its own authorization
    // record, so a saturated or dead sink refuses the forward here
    // rather than discovering the failure on the next frame.
    if let Some(verdict) = audit_verdict {
        proxy_rpc::audit_forwarded_decision(
            &shared.audit,
            C2S,
            "request",
            Some(method),
            Some(raw_id),
            version,
            verdict,
            shared.dry_run,
            request_extra(ext),
        )
        .await?;
    }
    shared.audit.ensure_available()?;
    // Verified-set recheck (F6/F10): the admission-time capture is
    // compared immediately before the child write. A `list_changed`
    // revalidation raises `list_busy` before it starts and bumps the
    // generation (with its advertised-name set) when it verifies, so a
    // stale admission is caught by either arm — unwind the registration
    // and deny rather than let the call execute against a tool set that
    // may have moved. `verified_tools` is authoritative: the names a
    // call was admitted against cannot change without its generation.
    //
    // The recheck and the write hold one `list_epoch` critical section:
    // every gate raise (`handle_list_changed` and the other S2C sites)
    // acquires the same guard first, so the gate can never flip between
    // this check and the dispatch. A raise queued behind us runs only
    // after the frame is written — the call legitimately predates the
    // revalidation — and a call queued behind a raise observes busy and
    // unwinds. Without the epoch a raise could land in the gap after
    // the check, letting a stale-generation call cross after
    // revalidation had already begun.
    //
    // The busy arm is `tools/call`-scoped: the same gate admission
    // consulted must not be crossed mid-dispatch even when list
    // verification is off — S2C producers (`handle_list_changed`,
    // rejected-listing unwinds) raise it independent of the verified
    // generation, so the recheck applies whenever this request is a
    // call rather than a listing. A `tools/list` legitimately owns the
    // raised gate it armed, and methods admission never gated stay
    // ungated here.
    //
    // The epoch-held write is bounded (`EPOCH_CHILD_WRITE_BUDGET`): the
    // raises this section serializes against run on the S2C task that
    // drains the child's stdout, so an unbounded write into a full
    // stdin pipe would deadlock — the write waits on the child reading,
    // the child on its stdout draining, the drain on this epoch. And
    // the stale-check's denial (wire rollback, corrective audit, client
    // error) runs only after the guard drops: a blocked client write or
    // wire lock must not stretch the critical section either.
    let dispatched = {
        let _epoch = shared.list_epoch.lock().await;
        let stale = (method == "tools/call" && shared.list_busy.load(Ordering::SeqCst))
            || expected_list_gen.is_some_and(|expected| {
                shared.verified_tools.lock().unwrap().generation != expected
            });
        if stale {
            // `None` records the stale verdict; the epoch drops before
            // the denial work below.
            None
        } else {
            match write_child_frame_epoch(&shared.child_stdin, view.frame()).await {
                Ok(()) => {
                    // A tools/list about to become answerable publishes
                    // its request params first: a response that lands at
                    // the mark, or a `list_changed` revalidation queued
                    // behind this epoch, must rebuild the probe from
                    // *this* request — never a prior listing's template.
                    // Only the write-success branch reaches here, so a
                    // refused or unwritten request still cannot seed it.
                    if method == "tools/list" && allowed {
                        *shared.last_list_template.lock().await = view.frame().to_string();
                    }
                    // The bytes crossed — the request is now answerable.
                    // Marking inside the epoch keeps the invisible
                    // window to wire-lock contention; no legitimate
                    // response can arrive before the write completes.
                    shared.wire.lock().await.mark_dispatched(C2S, id);
                    Some(Ok(()))
                }
                Err(e) => Some(Err(e)),
            }
        }
    };
    let Some(result) = dispatched else {
        shared.wire.lock().await.rollback_forwarded_request(undo);
        if let Some(verdict) = audit_verdict {
            // The pre-write record claimed `forwarded=true`; reconcile
            // the wire truth with a corrective not-forwarded record.
            proxy_rpc::audit_forward_failed(
                &shared.audit,
                C2S,
                "request",
                Some(method),
                Some(raw_id),
                version,
                verdict,
                shared.dry_run,
                request_extra(ext),
            );
        }
        write_client_frame(
            &shared.client_out,
            &build_jsonrpc_error(raw_id, "tools/list revalidation began during authorization"),
        )
        .await?;
        return Ok(false);
    };
    if let Some(verdict) = audit_verdict
        && result.is_err()
        && !matches!(result, Err(AuditorError::DeliveryUncertain(_)))
    {
        // The pre-write record claimed `forwarded=true`; reconcile the
        // wire truth with a corrective not-forwarded record. Skipped
        // for `DeliveryUncertain` — the complete frame may still have
        // crossed, so "not forwarded" is unprovable.
        proxy_rpc::audit_forward_failed(
            &shared.audit,
            C2S,
            "request",
            Some(method),
            Some(raw_id),
            version,
            verdict,
            shared.dry_run,
            request_extra(ext),
        );
    }
    match result {
        Ok(()) => Ok(true),
        Err(e) => {
            // Uncertain delivery — the complete frame may still have
            // crossed, so the registration and its side effects stay;
            // the error still ends the session. Proven non-delivery
            // (an incomplete frame never parses) unwinds normally.
            if !matches!(e, AuditorError::DeliveryUncertain(_)) {
                shared.wire.lock().await.rollback_forwarded_request(undo);
            }
            Err(e)
        }
    }
}
