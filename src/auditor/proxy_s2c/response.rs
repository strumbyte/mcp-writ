//! The server→client response path: correlation against a tracked
//! client→server request, tools/list pipeline handoff, `initialize`
//! revision pinning, MRTR `input_required` resolution, and the
//! post-forward session bookkeeping.

use std::sync::atomic::Ordering;

use super::{C2S, S2C, audit_malformed, route_tools_list};
use crate::auditor::checker;
use crate::auditor::proxy_list_state::S2cListState;
use crate::auditor::proxy_rpc::{self, TrackedRequest, WireState};
use crate::auditor::proxy_state::{self, ProxyShared};
use crate::auditor::proxy_tools_list;
use crate::auditor::proxy_wire::{
    build_jsonrpc_error, negotiated_version_value, rpc_id_from_raw_id, tools_call_result_succeeded,
    unsupported_version_message, write_client_frame,
};
use crate::auditor::session::{self, RpcId};
use crate::error::AuditorError;
use crate::policy::Policy;
use crate::policy::mcp::{
    AdditionalRequestMessage, AllowReason, DenyReason, McpVerdict, OriginalRequestFacts,
    TrafficMessage, UndecidedReason,
};
use crate::protocol::SupportedProtocolVersion;
use crate::protocol::fields::{self, SchemaField};
/// One server→client response — must answer a tracked client→server
/// request. tools/list responses route to the verification pipeline;
/// `initialize` responses additionally validate `result.protocolVersion`.
pub(super) async fn s2c_response<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    value: nojson::RawJsonValue<'_, '_>,
    line: &str,
    parsed: &Result<nojson::RawJson<'_>, nojson::JsonParseError>,
    id: &RpcId,
    raw_id: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ext = proxy_rpc::extract_response(value);
    let mut wire = shared.wire.lock().await;
    let mut answered = wire.answered(S2C, id);
    // A response can race its own request's dispatch: registration
    // precedes the forward write and `mark_dispatched` follows it, so a
    // fast answer can arrive while the entry still reads undispatched.
    // Wait on the dispatch outcome instead of rejecting — the mark
    // makes the entry answerable, and any removal (rollback, reclaim,
    // take) ends the wait the same way. The waiter registers while
    // this task still holds the wire lock, so the transition can never
    // be missed.
    //
    // The wait is bound to the registration it started on (`seq`): a
    // pre-write rollback frees the id, and a *new* request re-registering
    // it undispatched must neither keep this waiter parked nor resolve
    // through `answered` — the frame answers the removed registration,
    // never the replacement.
    let mut waited_seq = None;
    while answered.is_none()
        && let Some(entry) = wire.get(C2S, id)
        && !entry.dispatched
        && waited_seq.is_none_or(|seq| seq == entry.seq)
    {
        waited_seq = Some(entry.seq);
        let notify = wire.dispatch_changed();
        let notified = notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        drop(wire);
        notified.await;
        wire = shared.wire.lock().await;
        answered = wire.answered(S2C, id).filter(|a| Some(a.seq) == waited_seq);
    }
    let version = wire
        .get(C2S, id)
        .map(|e| e.version)
        .unwrap_or_else(|| wire.passive_version());
    let verdict = {
        let answered_facts = answered.as_ref().map(proxy_rpc::answered_facts);
        let msg = proxy_rpc::response_message(S2C, version, &ext, answered_facts);
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    // MRTR: `resultType=input_required` is decided by the additional
    // requests it carries — each `inputRequests` entry is judged against
    // the tracked original request's facts (never the frame's claims).
    let (verdict, additional_audits) = match verdict {
        McpVerdict::Undecided(UndecidedReason::InputRequired) => {
            resolve_input_required(&shared.policy, &wire, value, id, version)
        }
        verdict => (verdict, Vec::new()),
    };

    // The tools/list pipeline owns any tracked list id — even when the
    // policy denies the response, list bookkeeping must unwind. Pending
    // membership alone cannot admit a frame: the entry is inserted
    // before the forward's wire registration, so a stray response could
    // name an id whose request never crossed. Only the wire entry —
    // created at registration — proves the request left.
    let on_list_path = answered
        .as_ref()
        .map(|a| a.method == "tools/list")
        .unwrap_or(false)
        || st.is_internal_response(Some(id));

    // `deny_reason` is the wire-facing rejection; a dropped response
    // still rejects the waiter's correlation id but surfaces as the
    // generic `shape` error, while the audit record keeps the true
    // verdict (`Drop` keeps its real reason code).
    let deny_reason = match verdict {
        McpVerdict::Allow(_) => None,
        // `Undecided` was resolved above — the MRTR gate is the only
        // producer for S2C responses; anything left is fail-closed.
        McpVerdict::Undecided(_) => Some(DenyReason::ResultType),
        McpVerdict::Deny(reason) => Some(reason),
        McpVerdict::Drop(_) => Some(DenyReason::Shape),
    };

    // `initialize` result revision pinning — decide cannot express it.
    // Denied as `unsupported-version`, not `shape`: the envelope is
    // well-formed; the negotiated revision itself is the violation.
    // The session is left open — the denied response never establishes
    // a revision, `init` stays PendingInitialize, so a retried
    // `initialize` can still renegotiate while every other method keeps
    // failing init-order (PR-23 decision: diagnose, don't abort).
    // Auditor-internal `initialize` requests stay outside the pin: none
    // are issued today, and a rejected internal response already aborts
    // via `VerificationFailed` below — the pin exists to hand the
    // waiting *client* a diagnosable error, which internal traffic
    // never produces.
    let initialize_result = answered
        .as_ref()
        .map(|a| a.method == "initialize" && !a.internal)
        .unwrap_or(false)
        && ext.has_result
        && !ext.is_error;
    let unsupported_negotiation = deny_reason.is_none()
        && initialize_result
        && !proxy_rpc::WireState::initialize_result_version_ok(&ext);
    let (audit_verdict, deny_reason) = if unsupported_negotiation {
        (
            McpVerdict::Deny(DenyReason::UnsupportedVersion),
            Some(DenyReason::UnsupportedVersion),
        )
    } else {
        (verdict, deny_reason)
    };

    // PR-23: record the version the server actually returned on every
    // external `initialize` result — allowed or denied — so the
    // negotiated revision is never lost when another denial reason wins
    // first (`revision=` is the judged wire revision, never the
    // negotiated one). `supported=` marks the unsupported-version
    // denial itself.
    let negotiated_extra = initialize_result.then(|| {
        let mut extra = format!(
            "server_protocol_version={}",
            negotiated_version_value(ext.initialize_protocol_version.as_deref())
        );
        if unsupported_negotiation {
            extra.push_str(&format!(
                " supported={}",
                crate::protocol::SUPPORTED_INITIALIZE_VERSIONS.join(",")
            ));
        }
        extra
    });

    // A late response to a cancelled client `tools/list` is dead
    // traffic: the cancel already released its pending id, so only the
    // wire entry still ties it to the verification pipeline — where a
    // tools-shaped payload could resurrect a listing nobody awaits,
    // interleave into a live collection, or trip a queued revalidation
    // into an abort. Consume the wire entry, record the anomaly, and
    // drop it — in every mode, including dry-run.
    if answered
        .as_ref()
        .is_some_and(|a| a.method == "tools/list" && !a.internal)
        && !shared.pending_tools_list.lock().await.contains(id)
        && !st.is_internal_response(Some(id))
    {
        wire.take(C2S, id);
        drop(wire);
        audit_additional_requests(shared, &additional_audits, raw_id, version, false).await?;
        proxy_rpc::audit_decision(
            &shared.audit,
            S2C,
            "response",
            Some("tools/list"),
            Some(raw_id),
            version,
            audit_verdict,
            false,
            shared.dry_run,
            None,
        )?;
        audit_malformed(shared, Some(raw_id), "response to cancelled tools/list").await?;
        return Ok(());
    }

    match deny_reason {
        None => {
            let is_result = ext.has_result && !ext.is_error;
            // A `subscriptions/listen` entry outlives its *result*
            // response — the subscription keeps resolving under the same
            // id. An error response means the subscription never started.
            let is_listen = answered
                .as_ref()
                .is_some_and(|a| a.method == "subscriptions/listen");
            // Consume only the registration the `waited_seq`-bound
            // probe resolved — a stale frame the policy happens to
            // allow must not retire a same-id replacement (or an
            // already-answered subscription) sitting under the id.
            let entry = if answered.is_none() {
                None
            } else if is_listen && is_result {
                wire.mark_responded(C2S, id)
            } else {
                wire.take(C2S, id)
            };
            if let Some(ref e) = entry {
                wire.on_response_forwarded(S2C, e, &ext, is_result);
            }
            let method_label = answered
                .as_ref()
                .map(|a| a.method.clone())
                .or_else(|| entry.as_ref().map(|e| e.method.clone()));
            let internal = answered.as_ref().map(|a| a.internal).unwrap_or(false);
            drop(wire);
            // The `forwarded=true` records below claim this frame and
            // each additional request inside it crossed — every failure
            // before the frame write reconciles the records that
            // actually enqueued, through one argument set so the
            // corrective records cannot drift. A mid-loop failure
            // inside `audit_additional_requests` appends corrections
            // for its own written prefix; the response's own record
            // failure leaves only the additional set outstanding.
            let audit_response_forward_failed = |response_recorded: bool| {
                if response_recorded {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        S2C,
                        "response",
                        method_label.as_deref(),
                        Some(raw_id),
                        version,
                        audit_verdict,
                        shared.dry_run,
                        negotiated_extra.clone(),
                    );
                }
                for entry in &additional_audits {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        S2C,
                        "additional-request",
                        entry.method.as_deref(),
                        Some(raw_id),
                        version,
                        entry.verdict,
                        shared.dry_run,
                        additional_request_extra(entry),
                    );
                }
            };
            audit_additional_requests(shared, &additional_audits, raw_id, version, true).await?;
            if let Err(e) = proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                S2C,
                "response",
                method_label.as_deref(),
                Some(raw_id),
                version,
                audit_verdict,
                shared.dry_run,
                negotiated_extra.clone(),
            )
            .await
            {
                // The response's own record never enqueued — only the
                // additional requests' records claim a crossing that
                // now never happens.
                audit_response_forward_failed(false);
                return Err(e);
            }
            if on_list_path || internal {
                let result = route_tools_list(shared, st, line, parsed, value, None).await;
                // Skipped when delivery is not provably false:
                // `DeliveryUncertain` means the frame may have crossed,
                // and `PostDeliveryFailure` means it did — the pipeline
                // already reconciled the later failure itself.
                if let Err(e) = &result
                    && !matches!(
                        e,
                        AuditorError::DeliveryUncertain(_) | AuditorError::PostDeliveryFailure(_)
                    )
                {
                    audit_response_forward_failed(true);
                }
                return result;
            }
            apply_response_session_updates(shared, value, id, entry.as_ref()).await;
            match write_client_frame(&shared.client_out, line).await {
                Ok(()) => {
                    // When verification is enforced, open the initial
                    // internal tools/list right after `initialize`
                    // completes — `tools/call` stays fail closed until a
                    // verified generation publishes. The busy gate is
                    // raised first so no call can race the write. The
                    // probe only fires when the result advertised a
                    // `tools` capability: a server without one has no
                    // list to verify and its error would abort the
                    // session over a listing nobody needed.
                    if is_result
                        && entry.as_ref().is_some_and(|e| e.method == "initialize")
                        && ext
                            .initialize_server_capabilities
                            .iter()
                            .any(|cap| cap == "tools")
                        && proxy_state::list_verification_required(&shared.policy, shared.fail_on)
                        && shared.list_generation.load(Ordering::SeqCst) == 0
                        && st.idle()
                        && !shared.raise_list_gate().await
                    {
                        proxy_tools_list::begin_revalidation(shared, st, false).await?;
                    }
                    Ok(())
                }
                Err(e) => {
                    // Skipped for `DeliveryUncertain` — the complete
                    // frame may still have crossed, so "not forwarded"
                    // is unprovable (same rule as the request path).
                    if !matches!(e, AuditorError::DeliveryUncertain(_)) {
                        audit_response_forward_failed(true);
                    }
                    Err(e)
                }
            }
        }
        Some(reason) => {
            // Consume the answered entry — but never a `responded`
            // `subscriptions/listen` entry: the subscription keeps
            // resolving ack/notification/cancel traffic under the same
            // id, so a rejected late response must not take the live
            // subscription tracking (and id-retirement) down with it.
            let entry = if answered.is_some() {
                wire.take(C2S, id)
            } else {
                None
            };
            let method_label = entry
                .as_ref()
                .map(|e| e.method.clone())
                .or_else(|| wire.get(C2S, id).map(|e| e.method.clone()));
            let internal = entry.as_ref().map(|e| e.internal).unwrap_or(false);
            let had_answered = answered.is_some();
            drop(wire);
            audit_additional_requests(shared, &additional_audits, raw_id, version, false).await?;
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "response",
                method_label.as_deref(),
                Some(raw_id),
                version,
                audit_verdict,
                false,
                shared.dry_run,
                negotiated_extra,
            )?;
            // A denied response still terminates the original RPC for
            // the client — release the session bookkeeping a forwarded
            // tools/call registered (the trajectory pending call and the
            // deputy pending list). The release is unverified: a refused
            // response means the call reached the server and may have
            // run, but it is no proven success either — it feeds
            // trajectory deny candidates without touching the verified
            // marker. A retry arrives under a new id.
            if let Some(ref e) = entry
                && e.method == "tools/call"
                && let Some(ref session) = shared.session
            {
                let mut state = session.lock().await;
                state.take_pending_list(id);
                state.release_pending_tool_call_unverified(id);
            }
            if internal {
                // Our own request got a rejected answer — the listing can
                // never verify; fail closed.
                let block_reason = format!(
                    "internal tools/list response rejected ({})",
                    reason.as_str()
                );
                st.discard_pages();
                shared.raise_list_gate().await;
                // A client listing coalesced behind this internal one —
                // held, or still in transit in the C2S pipe — is
                // answered with this reason by the abort drain.
                *shared.internal_list_failure.lock().await =
                    Some((reason.as_str().to_string(), false));
                shared.abort_tx.send(true).ok();
                return Err(AuditorError::VerificationFailed(block_reason));
            }
            if on_list_path {
                // Unwind the client-facing pending state for this id —
                // but the bound collection may belong to a *different*
                // listing: a response naming another pending id must
                // leave that collection alone. `release_collection_for`
                // binds `client_id` against `id` and unwinds only on a
                // match — clearing the collection and yielding the
                // in-flight internal pagination id so its wire
                // registration can retire before a late page correlates
                // into freed state (same posture as the oversize path).
                // Peek the bound id first: a non-matching reply owes the
                // error to the response's own id, not the bound listing.
                // Gate ownership needs more than pending membership: an
                // arm inserts its pending id BEFORE the gate CAS, so a
                // response naming an id whose CAS lost — transiently
                // pending while the gate belongs to the listing that
                // beat it — could otherwise consume the entry and clear
                // a gate it never owned. An armed listing publishes its
                // original only after winning the CAS, so `originals`
                // membership separates owner from transient.
                let was_pending = shared.pending_tools_list.lock().await.remove(id);
                let owned_unbound =
                    was_pending && shared.original_tools_list.lock().await.contains_key(id);
                let bound_id = st.client_id().map(str::to_string);
                let bound = bound_id
                    .as_deref()
                    .and_then(rpc_id_from_raw_id)
                    .is_some_and(|cid| cid == *id);
                if let Some(internal) = st.release_collection_for(id) {
                    shared.wire.lock().await.take(C2S, &internal);
                }
                {
                    // Keys are canonical `RpcId`s: the response's id and
                    // the bound client id resolve to the same entry. The
                    // bound listing's original goes only when this
                    // response was for it.
                    let mut originals = shared.original_tools_list.lock().await;
                    originals.remove(id);
                    if bound
                        && let Some(client_id) = bound_id.as_deref().and_then(rpc_id_from_raw_id)
                    {
                        originals.remove(&client_id);
                    }
                }
                // The gate drops when the rejected listing owned it:
                // the bound collection naming it, OR an armed but
                // unbound listing — its stored original proves it won
                // the gate CAS, so a denial that never reached the
                // pipeline still owns the gate it armed at admission,
                // and leaving it raised would refuse every later
                // listing forever. A collection bound to a *different*
                // id, or a transient pending id that lost the CAS,
                // keeps the real owner's gate latched.
                let rejected_owned_gate = bound || owned_unbound;
                // The reply echoes the bound listing's own id spelling
                // when the response was for it — otherwise the rejected
                // response's own id, so a foreign pending id's denial
                // never lands on the surviving collection's client. In
                // the abort path the bound listing dies with the
                // session either way, so the same choice holds.
                let client_id = if bound {
                    bound_id.unwrap_or_else(|| raw_id.to_string())
                } else {
                    raw_id.to_string()
                };
                if st.requires_abort_on_error() {
                    // A revalidation or held list_changed outlives this
                    // listing — dropping the gate now would admit
                    // tools/call against a tool set the server already
                    // moved past, and nothing else re-drives the queue.
                    // Fail the session like an in-flight revalidation
                    // error, keeping the gate latched until the abort.
                    let block_reason = format!(
                        "tools/list response rejected while a revalidation is pending ({})",
                        reason.as_str()
                    );
                    shared.raise_list_gate().await;
                    // The bound client listing dies with the session —
                    // answer it on its own id first: it already crossed
                    // C2S, so the abort drain cannot correlate it (it is
                    // neither held nor in transit in the pipe).
                    write_client_frame(
                        &shared.client_out,
                        &build_jsonrpc_error(
                            &client_id,
                            &format!("tools/list response rejected ({})", reason.as_str()),
                        ),
                    )
                    .await?;
                    // A client listing held behind the pending
                    // revalidation is answered by the abort drain; the
                    // inline reply marks the failure already-answered.
                    *shared.internal_list_failure.lock().await =
                        Some((reason.as_str().to_string(), true));
                    shared.abort_tx.send(true).ok();
                    return Err(AuditorError::VerificationFailed(block_reason));
                }
                if rejected_owned_gate {
                    shared.list_busy.store(false, Ordering::SeqCst);
                }
                write_client_frame(
                    &shared.client_out,
                    &build_jsonrpc_error(
                        &client_id,
                        &format!("tools/list response rejected ({})", reason.as_str()),
                    ),
                )
                .await?;
                return Ok(());
            }
            if had_answered {
                // The client is waiting on this request — answer with an
                // error rather than leave it hanging.
                let msg = if unsupported_negotiation {
                    // PR-23: the same negotiated/supported pair goes to
                    // stderr so the cause reads identically on all three
                    // surfaces (client error, stderr, audit details).
                    let cause =
                        unsupported_version_message(ext.initialize_protocol_version.as_deref());
                    tracing::error!("server→client: {cause}");
                    format!("response rejected ({}): {cause}", reason.as_str())
                } else {
                    format!("response rejected ({})", reason.as_str())
                };
                write_client_frame(&shared.client_out, &build_jsonrpc_error(raw_id, &msg)).await?;
            }
            Ok(())
        }
    }
}

/// CDP path recording + trajectory completion for a forwarded response —
/// only meaningful for tracked `tools/call` answers. `id` is the
/// canonical id `classify_frame` already resolved for the frame — the
/// consumed wire entry cannot re-derive it, and the line is never
/// reparsed here.
async fn apply_response_session_updates<W>(
    shared: &ProxyShared<W>,
    value: nojson::RawJsonValue<'_, '_>,
    id: &RpcId,
    entry: Option<&TrackedRequest>,
) where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Some(ref session) = shared.session else {
        return;
    };
    let Some(entry) = entry else { return };
    if entry.method != "tools/call" {
        return;
    }
    // The entry was consumed by `take`; a null id never registered one.
    if matches!(id, RpcId::Null) {
        return;
    }
    // Discovery state seeds only from a correlated **success**: JSON-RPC
    // errors, `result.isError=true`, and MRTR `input_required` interim
    // results release the pending entry without recording a single path.
    let succeeded = tools_call_result_succeeded(value);
    let mut state = session.lock().await;
    if let Some(pending) = state.take_pending_list(id)
        && succeeded
    {
        let paths = session::extract_paths_for_pending(value, pending.rules());
        if !paths.is_empty() {
            tracing::debug!(
                tool = %crate::termutil::sanitize_for_terminal(pending.tool()),
                count = paths.len(),
                "Session: recorded paths from discovery response"
            );
            state.record_paths(&paths);
        }
    }
    if shared.policy.trajectory {
        // `succeeded=false` leaves partial side effects possible: a
        // JSON-RPC `error` (an internal error may follow partial work),
        // `result.isError=true`, a malformed verdict — and an MRTR
        // `input_required` suspend. Nothing enforces pre-suspend
        // purity on the tool: a call may have done work before asking
        // for more input, and the suspend only proves the id will not
        // complete — not that nothing ran. Keep the unverified
        // candidate so a following trajectory decision still prices in
        // the call's `after` effect; only a completed `result` or a
        // registration rollback is a definite verdict.
        if succeeded {
            state.complete_pending_tool_call(id, true);
        } else {
            state.release_pending_tool_call_unverified(id);
        }
    }
}

/// One `inputRequests` entry's decision — emitted as its own audit record
/// under the original request's correlation id.
struct AdditionalRequestAudit {
    /// Server-assigned map key under `inputRequests` (the retry's
    /// `inputResponses` answers under the same key).
    request_key: Option<String>,
    /// Entry `method` — `None` when the descriptor failed the shape gate.
    method: Option<String>,
    verdict: McpVerdict,
}

/// The `request_key` detail shared by an additional request's forwarded
/// record and its corrective `forward_failed` record — both describe the
/// same embedded request, so the extra is computed once. `request_key`
/// is server-controlled — percent-encode so it cannot forge additional
/// `k=v` members in the flat `details` field, then bound like other
/// attacker-controlled values.
fn additional_request_extra(entry: &AdditionalRequestAudit) -> Option<String> {
    entry.request_key.as_deref().map(|k| {
        format!(
            "request_key={}",
            proxy_rpc::truncate_for_audit(&crate::audit_log::encode_audit_field_value(k))
        )
    })
}

/// Emit one `mcp_message.*` record per decided `inputRequests` entry.
/// `forwarded` tracks the frame's disposition (true when the interim
/// result crossed to the client; `dry_run` on a denied forward). On the
/// forwarded path the records are send-ordered ahead of the frame, same
/// as the response's own decision record.
///
/// A mid-loop failure reconciles the prefix already enqueued — those
/// `forwarded=true` records claim a crossing that now never happens —
/// before the error propagates, so the session still fails closed.
async fn audit_additional_requests<W>(
    shared: &ProxyShared<W>,
    entries: &[AdditionalRequestAudit],
    raw_id: &str,
    version: SupportedProtocolVersion,
    forwarded: bool,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    for (i, entry) in entries.iter().enumerate() {
        let extra = additional_request_extra(entry);
        let result = if forwarded {
            proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                S2C,
                "additional-request",
                entry.method.as_deref(),
                Some(raw_id),
                version,
                entry.verdict,
                shared.dry_run,
                extra,
            )
            .await
        } else {
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "additional-request",
                entry.method.as_deref(),
                Some(raw_id),
                version,
                entry.verdict,
                false,
                shared.dry_run,
                extra,
            )
        };
        if let Err(e) = result {
            if forwarded {
                for enqueued in &entries[..i] {
                    proxy_rpc::audit_forward_failed(
                        &shared.audit,
                        S2C,
                        "additional-request",
                        enqueued.method.as_deref(),
                        Some(raw_id),
                        version,
                        enqueued.verdict,
                        shared.dry_run,
                        additional_request_extra(enqueued),
                    );
                }
            }
            return Err(e);
        }
    }
    Ok(())
}

/// Resolve a `resultType=input_required` interim result to a final verdict
/// by judging every `inputRequests` entry against the tracked original
/// request. Capabilities and the pass-time allow verdict come from
/// `WireState` tracking — never from the frame's own claims.
///
/// One denied or malformed entry rejects the whole response: the set is
/// the server's unit of continuation, and forwarding a subset would
/// rewrite what the client is being asked. With no usable `inputRequests`
/// the interim result must still carry a `requestState` string — a bare
/// `input_required` holds no continuation and fails closed.
fn resolve_input_required(
    policy: &Policy,
    wire: &WireState,
    value: nojson::RawJsonValue<'_, '_>,
    id: &RpcId,
    version: SupportedProtocolVersion,
) -> (McpVerdict, Vec<AdditionalRequestAudit>) {
    // `decide` emitted `Undecided` only for a correlated answer; the
    // tracked entry is re-read rather than trusting that ordering.
    let Some(tracked) = wire.get(C2S, id) else {
        return (McpVerdict::Deny(DenyReason::Uncorrelated), Vec::new());
    };
    let original = OriginalRequestFacts {
        method: tracked.method.as_str(),
        // The raw `allowed` flag — a dry-run forward of a denied request
        // is not a normal pass, and its additional requests stay denied.
        allowed: tracked.allowed,
        client_capabilities: tracked.client_capabilities.as_slice(),
    };
    let Some(result) = value.to_member("result").ok().and_then(|m| m.optional()) else {
        return (McpVerdict::Deny(DenyReason::Shape), Vec::new());
    };
    // `requestState` is an opaque string when present — any other type is
    // malformed outright (never parsed, never trusted), and the same size
    // cap as retry requests applies: the client echoes the blob back in
    // `params.requestState`.
    let oversized_state = result
        .to_member("requestState")
        .ok()
        .and_then(|m| m.optional())
        .is_some_and(|v| checker::request_state_byte_len(v) > checker::REQUEST_STATE_MAX_BYTES);
    if fields::request_state(result) == SchemaField::Invalid || oversized_state {
        return (McpVerdict::Deny(DenyReason::Shape), Vec::new());
    }
    let entries = match fields::input_requests(result) {
        fields::InputRequests::Absent => Vec::new(),
        fields::InputRequests::Map(entries) => entries,
        // A map over the protocol bound is refused as a unit — one
        // aggregate record, not one audit write per rejected entry.
        fields::InputRequests::Overrun => {
            return (
                McpVerdict::Deny(DenyReason::Shape),
                vec![AdditionalRequestAudit {
                    request_key: None,
                    method: None,
                    verdict: McpVerdict::Deny(DenyReason::Shape),
                }],
            );
        }
        // A non-map `inputRequests` (e.g. an array) cannot even be
        // iterated — the client has nothing it could lawfully answer.
        fields::InputRequests::Malformed => {
            return (
                McpVerdict::Deny(DenyReason::Shape),
                vec![AdditionalRequestAudit {
                    request_key: None,
                    method: None,
                    verdict: McpVerdict::Deny(DenyReason::Shape),
                }],
            );
        }
    };
    if entries.is_empty() {
        // `requestState`-only is the other valid interim form; with no
        // carrier at all the interim result is indistinguishable from a
        // malformed one.
        return match fields::request_state(result) {
            SchemaField::Valid => (McpVerdict::Allow(AllowReason::ProtocolPass), Vec::new()),
            _ => (McpVerdict::Deny(DenyReason::Shape), Vec::new()),
        };
    }
    let mut audits = Vec::with_capacity(entries.len());
    let mut first_deny = None;
    for entry in &entries {
        let verdict = match entry.method.as_deref() {
            Some(method) => policy.decide_mcp(
                &TrafficMessage::AdditionalRequest(AdditionalRequestMessage {
                    version,
                    method,
                    original,
                }),
                &wire.session_facts(),
            ),
            None => McpVerdict::Deny(DenyReason::Shape),
        };
        if first_deny.is_none() && !matches!(verdict, McpVerdict::Allow(_)) {
            first_deny = Some(verdict);
        }
        audits.push(AdditionalRequestAudit {
            request_key: Some(entry.key.clone()),
            method: entry.method.clone(),
            verdict,
        });
    }
    (
        first_deny.unwrap_or(McpVerdict::Allow(AllowReason::RuleAllow)),
        audits,
    )
}
