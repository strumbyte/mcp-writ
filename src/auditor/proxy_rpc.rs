//! Bidirectional MCP wire enforcement for `run_proxy` (PR-10).
//!
//! One `WireState` per session tracks the established protocol revision,
//! the 2025-11-25 lifecycle, negotiated capabilities, and a bounded table
//! of in-flight requests keyed by (direction, `RpcId`). Both relay halves
//! classify every parsed frame, hand it to `Policy::decide_mcp` with the
//! facts resolved here, and forward, reject, or drop accordingly.
//!
//! No I/O lives here: the loops extract, decide, then act. A request is
//! registered only once it is actually forwarded; a denied request never
//! enters the table. Dry-run forwards of denied requests register with
//! `allowed: false` so an answering frame cannot pose as a genuine
//! completion.

use std::collections::{HashMap, HashSet};
use std::mem::size_of;

use uuid::Uuid;

use super::session::{MAX_RPC_ID_BYTES, RpcId, rpc_id_bytes};
use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::policy::mcp::{
    AnsweredFacts, CancelFacts, DenyReason, InitStage, McpVerdict, MessageCorrelation,
    NotificationMessage, ProgressCorrelation, RequestMessage, RequestParams, ResponseMessage,
    SessionFacts, SubscriptionFacts, SubscriptionState, TrafficMessage,
};
use crate::protocol::fields::{
    self, InitializeShape, ListenFilters, META_SUBSCRIPTION_ID, RequestMeta, SchemaField,
    SubscriptionFilter,
};
use crate::protocol::{
    META_PROTOCOL_VERSION, MessageDirection, SUPPORTED_INITIALIZE_VERSIONS,
    SupportedProtocolVersion,
};

const V25: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2025November25;
const V26: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2026July28;
const C2S: MessageDirection = MessageDirection::ClientToServer;
const S2C: MessageDirection = MessageDirection::ServerToClient;

/// In-flight requests tracked across both directions. Sized like the
/// tools/list pending cap; a request at capacity is denied rather than
/// evicting an unanswered one.
pub(crate) const MAX_IN_FLIGHT_REQUESTS: usize = 128;
/// Ids retired by capacity reclaim of cancelled requests — bounded like
/// the table; once full, reclaim is impossible and new requests deny.
pub(crate) const MAX_RETIRED_REQUEST_IDS: usize = MAX_IN_FLIGHT_REQUESTS;
/// Active 2025 `resources/subscribe` URIs per session.
pub(crate) const MAX_RESOURCE_SUBSCRIPTIONS: usize = 256;
/// URL-mode `elicitationId`s awaiting `notifications/elicitation/complete`.
/// Sized like the subscription cap; an id beyond it never correlates, so
/// its completion notification drops rather than evicting a pending flow.
pub(crate) const MAX_PENDING_ELICITATIONS: usize = 256;
/// `-32042` — `URL_ELICITATION_REQUIRED` (2025-11-25).
const URL_ELICITATION_REQUIRED_CODE: i64 = -32042;
/// Recorded capability names per direction per negotiation.
pub(crate) const MAX_CAPABILITY_NAMES: usize = 512;
/// Byte cap on each peer-controlled string retained by [`WireState`]
/// (URIs, capability names, log levels, elicitation ids, subscription
/// filter URIs). Canonical JSON-RPC ids carry their own tighter cap —
/// [`crate::auditor::session::rpc_id::MAX_RPC_ID_BYTES`].
pub(crate) const MAX_RETAINED_VALUE_BYTES: usize = 1024;
/// Aggregate serialized-byte budget across every retained `WireState`
/// collection and both protocol directions — charged before insertion
/// and refunded on every removal, so peer-controlled strings cannot
/// grow the ledger without bound.
const MAX_WIRE_STATE_BYTES: usize = 4 * 1024 * 1024;

/// Drop peer strings over the per-value cap from a list before it is
/// retained — an oversized name is simply never recorded, so lookups
/// against it fail closed.
fn bounded_names(names: Vec<String>) -> Vec<String> {
    names
        .into_iter()
        .filter(|n| n.len() <= MAX_RETAINED_VALUE_BYTES)
        .collect()
}

fn opposite(direction: MessageDirection) -> MessageDirection {
    match direction {
        C2S => S2C,
        S2C => C2S,
    }
}

// ── Frame classification ──────────────────────────────────────────────

/// Classification of one parsed JSON-RPC frame. The request /
/// notification / response split drives which decision inputs apply.
#[derive(Debug)]
pub(crate) enum WireFrame {
    /// `method` + `id`.
    Request {
        method: String,
        id: RpcId,
        raw_id: String,
    },
    /// `method`, no `id`.
    Notification { method: String },
    /// `result`/`error` + `id`, no `method`.
    Response { id: RpcId, raw_id: String },
    /// Not a usable JSON-RPC envelope — never forwarded. `raw_id` echoes
    /// the `id` member when one was readable so request-shaped failures
    /// can still be answered.
    Malformed {
        reason: &'static str,
        raw_id: Option<String>,
    },
}

/// Member access: `Some` whenever the member exists — including a `null`
/// value, which JSON-RPC distinguishes from an absent member.
fn member<'a>(
    value: nojson::RawJsonValue<'a, 'a>,
    name: &str,
) -> Option<nojson::RawJsonValue<'a, 'a>> {
    value.to_member(name).ok().and_then(|m| m.optional())
}

fn params_value<'a>(value: nojson::RawJsonValue<'a, 'a>) -> Option<nojson::RawJsonValue<'a, 'a>> {
    member(value, "params")
}

fn meta_value<'a>(
    params: Option<nojson::RawJsonValue<'a, 'a>>,
) -> Option<nojson::RawJsonValue<'a, 'a>> {
    params.and_then(|p| member(p, "_meta"))
}

fn rpc_id_member(params: Option<nojson::RawJsonValue<'_, '_>>, name: &str) -> Option<RpcId> {
    params
        .and_then(|p| member(p, name))
        .and_then(RpcId::parse_from_json)
}

/// Classify a parsed frame. Anything that is not a well-formed
/// request / notification / response envelope is `Malformed` — the caller
/// fails closed rather than forwarding it.
pub(crate) fn classify_frame(value: nojson::RawJsonValue<'_, '_>) -> WireFrame {
    fn bad(reason: &'static str, raw_id: Option<String>) -> WireFrame {
        WireFrame::Malformed { reason, raw_id }
    }
    if value.kind() != nojson::JsonValueKind::Object {
        return bad("frame is not a JSON object", None);
    }
    let id_value = member(value, "id");
    let raw_id = id_value.map(|v| v.as_raw_str().to_string());
    // `jsonrpc: "2.0"` is a required member on every frame.
    let jsonrpc_ok = member(value, "jsonrpc")
        .and_then(|v| v.as_string_str().ok())
        .is_some_and(|v| v == "2.0");
    if !jsonrpc_ok {
        return bad("missing or invalid jsonrpc member", raw_id);
    }
    let method = member(value, "method");
    let has_result = member(value, "result").is_some();
    let has_error = member(value, "error").is_some();
    // `id: null` parses to `RpcId::Null`; an absent `id` is `None`.
    let rpc_id = id_value.and_then(RpcId::parse_from_json);

    if let Some(method_value) = method {
        let Ok(method) = method_value.to_unquoted_string_str() else {
            return bad("method is not a string", raw_id);
        };
        // `method` coexisting with `result`/`error` is not a usable
        // envelope: a peer that dispatches on `result`/`id` before
        // `method` could read the frame as a forged answer to a pending
        // request — the same parse-divergence class duplicate keys hit.
        if has_result || has_error {
            return bad("method and result/error members mixed", raw_id);
        }
        if id_value.is_some() {
            match rpc_id {
                Some(id) => WireFrame::Request {
                    method: method.into_owned(),
                    id,
                    raw_id: raw_id.unwrap_or_else(|| "null".to_string()),
                },
                None => bad("request id must be a string, number, or null", raw_id),
            }
        } else {
            WireFrame::Notification {
                method: method.into_owned(),
            }
        }
    } else if has_result && has_error {
        // `result` and `error` are mutually exclusive in JSON-RPC — a
        // frame carrying both is ambiguous about success downstream.
        bad("response carries both result and error", raw_id)
    } else if has_result || has_error {
        match rpc_id {
            Some(id) => WireFrame::Response {
                id,
                raw_id: raw_id.unwrap_or_else(|| "null".to_string()),
            },
            None => bad("response id missing or invalid", raw_id),
        }
    } else {
        bad("frame has no method, result, or error member", raw_id)
    }
}

/// True when a parsed frame carries `result`/`error` response members,
/// regardless of envelope validity. [`classify_frame`] rejects some of
/// these (a mixed `method` member, both `result` and `error`, a missing
/// `jsonrpc` member, …), but one bearing a tracked tools/list id must
/// still reach the verification pipeline's fail-closed handling rather
/// than leave a pending listing hung.
pub(crate) fn has_response_members(value: nojson::RawJsonValue<'_, '_>) -> bool {
    member(value, "result").is_some() || member(value, "error").is_some()
}

// ── Per-frame extraction (owned values; the parse tree dies with the line) ──

/// Request-frame inputs for the decision model and registration.
#[derive(Debug, Default)]
pub(crate) struct ExtractedRequest {
    /// `params._meta` — `Some` also for a present-but-malformed `_meta`.
    pub meta: Option<RequestMeta>,
    /// The `protocolVersion` member exists under `params._meta` (any
    /// value — the frame claims a 2026 envelope even when malformed).
    pub meta_declares_version: bool,
    /// `initialize` params shape.
    pub initialize: InitializeShape,
    /// Flattened `params.capabilities` of an `initialize` request.
    pub initialize_client_capabilities: Vec<String>,
    /// `params.uri` (`resources/*`).
    pub uri: Option<String>,
    /// `params.level` (`logging/setLevel`).
    pub level: Option<String>,
    /// `params.notifications` (`subscriptions/listen`) — `None` when the
    /// member is absent so the decision sees a missing filter set.
    pub notifications: Option<ListenFilters>,
    /// `params._meta.progressToken`.
    pub progress_token: Option<RpcId>,
    /// `params.elicitationId` (`elicitation/create` URL mode).
    pub elicitation_id: Option<String>,
}

impl ExtractedRequest {
    /// Borrowed view for `RequestMessage::params`.
    pub(crate) fn params(&self) -> RequestParams<'_> {
        RequestParams {
            initialize: self.initialize,
            uri: self.uri.as_deref(),
            level: self.level.as_deref(),
            notifications: self.notifications.as_ref(),
        }
    }
}

pub(crate) fn extract_request(
    value: nojson::RawJsonValue<'_, '_>,
    method: &str,
) -> ExtractedRequest {
    let params = params_value(value);
    let meta = params.and_then(fields::request_meta);
    let meta_member = meta_value(params);
    let meta_declares_version =
        meta_member.is_some_and(|m| member(m, META_PROTOCOL_VERSION).is_some());
    let initialize_client_capabilities = if method == "initialize" {
        params
            .and_then(|p| member(p, "capabilities"))
            .map(|v| {
                let mut caps = fields::capability_names(v);
                caps.truncate(MAX_CAPABILITY_NAMES);
                caps
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let notifications = if method == "subscriptions/listen"
        && params.is_some_and(|p| member(p, "notifications").is_some())
    {
        Some(fields::listen_filters(params))
    } else {
        None
    };
    let progress_token = meta_member
        .and_then(|m| member(m, "progressToken"))
        .and_then(RpcId::parse_from_json);
    ExtractedRequest {
        meta,
        meta_declares_version,
        initialize: fields::initialize_shape(params),
        initialize_client_capabilities,
        uri: fields::string_param(params, "uri"),
        level: fields::string_param(params, "level"),
        notifications,
        progress_token,
        elicitation_id: (method == "elicitation/create")
            .then(|| fields::string_param(params, "elicitationId"))
            .flatten(),
    }
}

/// Notification-frame inputs for the decision model.
#[derive(Debug, Default)]
pub(crate) struct ExtractedNotification {
    /// `params.uri` (`notifications/resources/updated`).
    pub uri: Option<String>,
    /// `params.level` (`notifications/message`).
    pub level: Option<String>,
    /// `params.notifications` (`notifications/subscriptions/acknowledged`)
    /// — `None` when the member is absent (malformed ack shape).
    pub ack_filters: Option<ListenFilters>,
    /// `params.requestId` (`notifications/cancelled`), canonicalised.
    pub cancel_id: Option<RpcId>,
    /// `params.progressToken` (`notifications/progress`), canonicalised.
    pub progress_token: Option<RpcId>,
    /// `params._meta["io.modelcontextprotocol/subscriptionId"]` (2026).
    pub subscription_id: Option<RpcId>,
    /// `params.elicitationId` (`notifications/elicitation/complete`, 2025
    /// URL mode) — the string id the `elicitation/create` request named.
    pub elicitation_id: Option<String>,
}

pub(crate) fn extract_notification(
    value: nojson::RawJsonValue<'_, '_>,
    method: &str,
) -> ExtractedNotification {
    let params = params_value(value);
    let ack_filters = if method == "notifications/subscriptions/acknowledged"
        && params.is_some_and(|p| member(p, "notifications").is_some())
    {
        Some(fields::listen_filters(params))
    } else {
        None
    };
    let subscription_id = meta_value(params)
        .and_then(|m| member(m, META_SUBSCRIPTION_ID))
        .and_then(RpcId::parse_from_json);
    ExtractedNotification {
        uri: fields::string_param(params, "uri"),
        level: fields::string_param(params, "level"),
        ack_filters,
        cancel_id: rpc_id_member(params, "requestId"),
        progress_token: rpc_id_member(params, "progressToken"),
        subscription_id,
        elicitation_id: (method == "notifications/elicitation/complete")
            .then(|| fields::string_param(params, "elicitationId"))
            .flatten(),
    }
}

/// Response-frame inputs for the decision model.
#[derive(Debug, Default)]
pub(crate) struct ExtractedResponse {
    pub is_error: bool,
    pub has_result: bool,
    /// `result.resultType` verbatim.
    pub result_type: Option<String>,
    pub ttl_ms: SchemaField,
    pub cache_scope: SchemaField,
    /// `result.inputRequests` member present (MRTR interim; PR-11 input).
    pub input_requests: bool,
    /// `result.protocolVersion` of an `initialize` result.
    pub initialize_protocol_version: Option<String>,
    /// Flattened `result.capabilities` of an `initialize` result.
    pub initialize_server_capabilities: Vec<String>,
    /// `elicitationId`s carried by a `-32042`
    /// (`URL_ELICITATION_REQUIRED`) error's `data.elicitations[]` — each
    /// out-of-band flow completes via `notifications/elicitation/complete`.
    pub elicitation_ids: Vec<String>,
}

pub(crate) fn extract_response(value: nojson::RawJsonValue<'_, '_>) -> ExtractedResponse {
    let result = member(value, "result");
    let error = member(value, "error");
    let is_error = error.is_some();
    let has_result = result.is_some();
    let elicitation_ids = error
        .filter(|e| {
            member(*e, "code")
                .and_then(|c| c.as_number_str().ok())
                .and_then(|n| n.parse::<i64>().ok())
                .is_some_and(|n| n == URL_ELICITATION_REQUIRED_CODE)
        })
        .and_then(|e| member(e, "data"))
        .and_then(|d| member(d, "elicitations"))
        .and_then(|l| l.to_array().ok())
        .map(|els| {
            els.filter_map(|el| fields::string_param(Some(el), "elicitationId"))
                .take(MAX_PENDING_ELICITATIONS)
                .collect()
        })
        .unwrap_or_default();
    ExtractedResponse {
        is_error,
        has_result,
        result_type: result.and_then(fields::result_type),
        ttl_ms: result.map(fields::ttl_ms).unwrap_or_default(),
        cache_scope: result.map(fields::cache_scope).unwrap_or_default(),
        input_requests: result.is_some_and(|r| member(r, "inputRequests").is_some()),
        initialize_protocol_version: result
            .and_then(|r| fields::string_param(Some(r), "protocolVersion")),
        initialize_server_capabilities: result
            .and_then(|r| member(r, "capabilities"))
            .map(|v| {
                let mut caps = fields::capability_names(v);
                caps.truncate(MAX_CAPABILITY_NAMES);
                caps
            })
            .unwrap_or_default(),
        elicitation_ids,
    }
}

// ── Tracked state ─────────────────────────────────────────────────────

/// Lifecycle of a tracked 2026 `subscriptions/listen` request.
#[derive(Debug)]
pub(crate) struct SubTracker {
    pub state: SubscriptionState,
    /// `params.notifications` of the listen request.
    pub requested: ListenFilters,
    /// Filters the forwarded ack granted.
    pub acked: Vec<SubscriptionFilter>,
    /// URIs granted under `resourceSubscriptions`.
    pub acked_uris: Vec<String>,
}

/// One in-flight request — registered at forward time, consumed when its
/// response forwards, the session ends, or a cancellation resolves it.
#[derive(Debug)]
pub(crate) struct TrackedRequest {
    pub method: String,
    pub version: SupportedProtocolVersion,
    /// The request was policy-allowed when forwarded. Dry-run forwards of
    /// denied requests keep `allowed: false` so downstream checks (MRTR
    /// `input_required` origin) still see the policy verdict.
    pub allowed: bool,
    /// Forwarded under `--dry-run`. A dry-run forward genuinely reached
    /// the peer, so its answering response correlates — it is not an
    /// orphan even though `allowed` stays false.
    pub dry_run: bool,
    /// Auditor-emitted request (tools/list revalidation / pagination) —
    /// its id must never leak downstream.
    pub internal: bool,
    /// `params._meta.progressToken` the requester declared.
    pub progress_token: Option<RpcId>,
    /// `params._meta` logLevel (2026 request-scoped logging).
    pub log_level: Option<String>,
    /// `params._meta` clientCapabilities (flattened) — the MRTR
    /// `input_required` gate compares each additional request against
    /// these, never the response's own claims.
    pub client_capabilities: Vec<String>,
    /// `params.uri` — `resources/subscribe` / `unsubscribe`.
    pub uri: Option<String>,
    /// `params.level` — `logging/setLevel`.
    pub level: Option<String>,
    /// A `notifications/cancelled` for this request was forwarded; the
    /// entry stays so a late response still correlates to it.
    pub cancelled: bool,
    /// A response to this request already correlated and forwarded. Only
    /// set for `subscriptions/listen` — the subscription (keyed by the
    /// same id) must keep resolving ack/notification/cancel traffic after
    /// the request itself completes; `responded` keeps a second response
    /// from correlating again.
    pub responded: bool,
    /// 2026 `subscriptions/listen` bookkeeping.
    pub subscription: Option<SubTracker>,
}

impl TrackedRequest {
    /// A forwarded wire request. `allowed` is `false` only for dry-run
    /// forwards of denied requests.
    pub(crate) fn from_extracted(
        method: &str,
        version: SupportedProtocolVersion,
        allowed: bool,
        dry_run: bool,
        ext: &ExtractedRequest,
    ) -> Self {
        let subscription = (method == "subscriptions/listen").then(|| SubTracker {
            state: SubscriptionState::PendingAck,
            requested: ext.notifications.clone().unwrap_or_default(),
            acked: Vec::new(),
            acked_uris: Vec::new(),
        });
        Self {
            method: method.to_string(),
            version,
            allowed,
            dry_run,
            internal: false,
            progress_token: ext.progress_token.clone(),
            log_level: ext.meta.as_ref().and_then(|m| m.log_level.clone()),
            client_capabilities: ext
                .meta
                .as_ref()
                .map(|m| m.client_capabilities.clone())
                .unwrap_or_default(),
            uri: ext.uri.clone(),
            level: ext.level.clone(),
            cancelled: false,
            responded: false,
            subscription,
        }
    }

    /// An Auditor-emitted internal `tools/list` request.
    pub(crate) fn internal_list(version: SupportedProtocolVersion) -> Self {
        Self {
            method: "tools/list".to_string(),
            version,
            allowed: true,
            dry_run: false,
            internal: true,
            progress_token: None,
            log_level: None,
            client_capabilities: Vec::new(),
            uri: None,
            level: None,
            cancelled: false,
            responded: false,
            subscription: None,
        }
    }
}

/// The response-side facts of a tracked request — what `decide` needs to
/// correlate an answering frame.
pub(crate) struct AnsweredRequest {
    /// Direction the answered request travelled.
    pub request_direction: MessageDirection,
    pub method: String,
    /// Correlation truth — the request genuinely reached the peer: a
    /// dry-run forward of a denied request did, even though the raw
    /// `allowed` verdict on `TrackedRequest` stays false (PR-11's
    /// `input_required` gate reads that raw value, not this one).
    pub reached_peer: bool,
    pub internal: bool,
}

mod wire;
pub(crate) use wire::WireState;

// ── Decision audit ────────────────────────────────────────────────────

/// Record one MCP traffic decision. Every frame that reached `decide` is
/// logged — direction, kind, method, revision, verdict reason, and whether
/// the frame was actually forwarded. Dry-run forwards of violations are
/// `Observed`, never `Allowed`.
#[expect(clippy::too_many_arguments)]
/// Record the frame's decision and surface audit unavailability to
/// the caller. `log()` marks the logger failed under fail-closed when
/// the channel saturates or the writer is dead — returning the
/// `ensure_available` verdict makes the *current* frame subject to
/// that failure instead of letting it cross the wire unaudited while
/// the flag is only noticed on the next loop pass.
pub(crate) fn audit_decision(
    audit: &AuditLogger,
    direction: MessageDirection,
    kind: &str,
    method: Option<&str>,
    request_id: Option<&str>,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    forwarded: bool,
    dry_run: bool,
    extra: Option<String>,
) -> Result<(), crate::error::AuditorError> {
    let event = decision_event(
        direction, kind, method, request_id, version, verdict, forwarded, dry_run, extra,
    );
    audit.log(event);
    audit.ensure_available()
}
/// The decision record for a frame about to cross to the peer — enqueued
/// *before* the write so the protected action never proceeds ahead of
/// its own authorization record. Fail-closed routes through
/// [`AuditLogger::log_ordered`]: saturation is backpressure and a dead
/// sink refuses the forward here rather than letting the frame cross
/// unrecorded. `forwarded=true` is the enforced decision; a failed
/// write reconciles the wire truth with [`audit_forward_failed`].
#[expect(clippy::too_many_arguments)]
pub(crate) async fn audit_forwarded_decision(
    audit: &AuditLogger,
    direction: MessageDirection,
    kind: &str,
    method: Option<&str>,
    request_id: Option<&str>,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    dry_run: bool,
    extra: Option<String>,
) -> Result<(), crate::error::AuditorError> {
    let event = decision_event(
        direction, kind, method, request_id, version, verdict, true, dry_run, extra,
    );
    audit.log_ordered(event).await
}

/// Reconcile the wire truth after a frame whose pre-write decision
/// claimed `forwarded=true` failed its write: append the corrective
/// not-forwarded record. Best-effort — the caller is already on an
/// error path; a dead sink poisons the session regardless.
#[expect(clippy::too_many_arguments)]
pub(crate) fn audit_forward_failed(
    audit: &AuditLogger,
    direction: MessageDirection,
    kind: &str,
    method: Option<&str>,
    request_id: Option<&str>,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    dry_run: bool,
    extra: Option<String>,
) {
    let extra = Some(match extra {
        Some(e) => format!("{e} write_failed"),
        None => "write_failed".to_string(),
    });
    let _ = audit_decision(
        audit, direction, kind, method, request_id, version, verdict, false, dry_run, extra,
    );
}

#[expect(clippy::too_many_arguments)]
fn decision_event(
    direction: MessageDirection,
    kind: &str,
    method: Option<&str>,
    request_id: Option<&str>,
    version: SupportedProtocolVersion,
    verdict: McpVerdict,
    forwarded: bool,
    dry_run: bool,
    extra: Option<String>,
) -> AuditEvent {
    let (event_type, severity, outcome) = match verdict {
        McpVerdict::Allow(_) => (
            EventType::McpMessageAllowed,
            Severity::Info,
            Outcome::Success,
        ),
        McpVerdict::Undecided(_) => (
            EventType::McpMessageUndecided,
            Severity::Medium,
            Outcome::Success,
        ),
        McpVerdict::Drop(_) => (
            EventType::McpMessageDropped,
            Severity::Medium,
            Outcome::Failure,
        ),
        McpVerdict::Deny(_) => (
            EventType::McpMessageDenied,
            Severity::High,
            Outcome::Failure,
        ),
    };
    let action = if !forwarded {
        Action::Denied
    } else if dry_run && !matches!(verdict, McpVerdict::Allow(_)) {
        Action::Observed
    } else {
        Action::Allowed
    };
    // `revision=` is the wire revision the frame was judged under — never
    // a peer-claimed `protocolVersion` (the negotiated version a server
    // returns travels in `server_protocol_version=`, PR-23).
    let mut details = format!(
        "dir={} kind={kind} revision={} verdict={} reason={} forwarded={forwarded}",
        direction.as_str(),
        version.as_str(),
        verdict.outcome(),
        verdict.reason_code(),
    );
    if let Some(extra) = extra {
        details.push_str(&format!(" {extra}"));
    }
    let mut event = AuditEvent::new(Uuid::now_v7(), event_type, severity, outcome, action);
    if let Some(method) = method {
        event.target_tool = Some(truncate_for_audit(method));
    }
    event.request_id = request_id.map(truncate_for_audit);
    event.details = Some(details);
    event
}

/// Keep attacker-controlled strings bounded in audit records.
pub(crate) fn truncate_for_audit(value: &str) -> String {
    const MAX: usize = 128;
    let mut it = value.chars().take(MAX).collect::<String>();
    if it.len() < value.len() {
        it.push('…');
    }
    it
}

/// Build the `TrafficMessage::Request` decision input.
///
/// `params()` returns a temporary `RequestParams` — it must not outlive
/// `ext`, which is why the message is built inside the locked scope that
/// also runs `decide`.
pub(crate) fn request_message<'a>(
    version: SupportedProtocolVersion,
    direction: MessageDirection,
    method: &'a str,
    ext: &'a ExtractedRequest,
    params: &'a RequestParams<'a>,
) -> TrafficMessage<'a> {
    TrafficMessage::Request(RequestMessage {
        version,
        direction,
        method,
        meta: ext.meta.as_ref(),
        params: Some(params),
    })
}

/// Build the `TrafficMessage::Notification` decision input. Correlation
/// fields are resolved from `WireState` by the caller under the lock.
#[expect(clippy::too_many_arguments)]
pub(crate) fn notification_message<'a>(
    version: SupportedProtocolVersion,
    direction: MessageDirection,
    method: &'a str,
    ext: &'a ExtractedNotification,
    cancel_target: CancelFacts,
    progress: ProgressCorrelation,
    message_for: Option<MessageCorrelation<'a>>,
    subscription: Option<SubscriptionFacts<'a>>,
) -> TrafficMessage<'a> {
    TrafficMessage::Notification(NotificationMessage {
        version,
        direction,
        method,
        uri: ext.uri.as_deref(),
        level: ext.level.as_deref(),
        ack_filters: ext.ack_filters.as_ref(),
        elicitation_id: ext.elicitation_id.as_deref(),
        cancel_target,
        progress,
        message_for,
        subscription,
    })
}

/// Borrowed `AnsweredFacts` view of an [`AnsweredRequest`].
pub(crate) fn answered_facts(answered: &AnsweredRequest) -> AnsweredFacts<'_> {
    AnsweredFacts {
        request_direction: answered.request_direction,
        method: answered.method.as_str(),
        allowed: answered.reached_peer,
    }
}

/// Build the `TrafficMessage::Response` decision input.
pub(crate) fn response_message<'a>(
    direction: MessageDirection,
    version: SupportedProtocolVersion,
    ext: &'a ExtractedResponse,
    answered: Option<AnsweredFacts<'a>>,
) -> TrafficMessage<'a> {
    TrafficMessage::Response(ResponseMessage {
        version,
        direction,
        is_error: ext.is_error,
        has_result: ext.has_result,
        result_type: ext.result_type.as_deref(),
        ttl_ms: ext.ttl_ms,
        cache_scope: ext.cache_scope,
        input_requests: ext.input_requests,
        answered,
    })
}
