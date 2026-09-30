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

use std::collections::{HashMap, HashSet, VecDeque};

use uuid::Uuid;

use super::session::RpcId;
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
    MCP_VERSION_2025_11_25, META_PROTOCOL_VERSION, MessageDirection, SupportedProtocolVersion,
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
/// Recorded capability names per direction per negotiation.
pub(crate) const MAX_CAPABILITY_NAMES: usize = 512;

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
}

pub(crate) fn extract_response(value: nojson::RawJsonValue<'_, '_>) -> ExtractedResponse {
    let result = member(value, "result");
    let is_error = member(value, "error").is_some();
    let has_result = result.is_some();
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

/// What [`WireState::on_request_forwarded`] overwrote — handed back to
/// the caller so a failed forward write can restore the exact prior
/// state together with the registration.
#[derive(Debug)]
pub(crate) struct RequestForwardUndo {
    direction: MessageDirection,
    id: RpcId,
    version: Option<SupportedProtocolVersion>,
    pending_init_capabilities: Option<Vec<String>>,
    elicitation_pending: bool,
}

/// Session-wide wire state shared by both relay directions.
///
/// Every fact handed to `decide` is resolved here from forwarded traffic —
/// a message can only reference state the Auditor already recorded, never
/// its own claims.
#[derive(Debug, Default)]
pub(crate) struct WireState {
    /// Established revision — set when the first request forwards. Before
    /// that, unknown envelopes default to 2025-11-25 handling.
    version: Option<SupportedProtocolVersion>,
    /// 2025-11-25 lifecycle stage.
    init: InitStage,
    /// Client capabilities of an in-flight `initialize` request, committed
    /// when its response forwards.
    pending_init_capabilities: Option<Vec<String>>,
    client_capabilities: Vec<String>,
    server_capabilities: Vec<String>,
    /// Active `resources/subscribe` URIs (2025).
    resource_subscriptions: Vec<String>,
    /// A server `elicitation/create` request is pending completion.
    elicitation_pending: bool,
    /// Session log threshold (`logging/setLevel`, 2025).
    log_level: Option<String>,
    /// In-flight requests keyed by (direction, id). Opposite-direction
    /// same-id requests are distinct keys — a response only ever matches
    /// the opposing-direction entry.
    requests: HashMap<(MessageDirection, RpcId), TrackedRequest>,
    /// Ids of cancelled requests evicted under capacity pressure. The
    /// tracking entry is gone but the id stays retired while held here:
    /// `register` refuses its reuse so a late response can never
    /// correlate to a different request carrying the same id.
    retired_ids: HashSet<(MessageDirection, RpcId)>,
    /// Insertion order of `retired_ids`. When the set is full the oldest
    /// id is evicted — a bounded FIFO so a steady stream of cancelled
    /// requests cannot permanently block new registrations.
    retired_order: VecDeque<(MessageDirection, RpcId)>,
}

impl WireState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// The established wire revision, once any request has forwarded.
    pub(crate) fn wire_version(&self) -> Option<SupportedProtocolVersion> {
        self.version
    }

    /// Revision for frames without a tracked request (notifications,
    /// server requests, uncorrelated responses): the established wire,
    /// defaulting to 2025-11-25 before anything forwards.
    pub(crate) fn passive_version(&self) -> SupportedProtocolVersion {
        self.version.unwrap_or(V25)
    }

    /// Select the revision an incoming C2S request is judged under.
    ///
    /// - An established 2026 wire keeps every frame at 2026.
    /// - `initialize` is 2025-only.
    /// - A `params._meta` `protocolVersion` member claims 2026; on an
    ///   established 2025 wire that is a mid-session switch → denied.
    /// - Otherwise the frame is 2025-11-25.
    pub(crate) fn request_version(
        &self,
        method: &str,
        meta_declares_version: bool,
    ) -> Result<SupportedProtocolVersion, DenyReason> {
        if self.version == Some(V26) {
            return Ok(V26);
        }
        if method == "initialize" {
            return Ok(V25);
        }
        if meta_declares_version {
            return match self.version {
                Some(V25) => Err(DenyReason::MetaVersion),
                _ => Ok(V26),
            };
        }
        Ok(V25)
    }

    pub(crate) fn session_facts(&self) -> SessionFacts<'_> {
        SessionFacts {
            init: self.init,
            client_capabilities: &self.client_capabilities,
            server_capabilities: &self.server_capabilities,
            resource_subscriptions: &self.resource_subscriptions,
            elicitation_pending: self.elicitation_pending,
            log_level: self.log_level.as_deref(),
        }
    }

    /// Register a request that is about to be forwarded. Errors (null id,
    /// same direction+id collision, capacity) keep the table unchanged —
    /// the caller must deny the request instead of evicting an unanswered
    /// one. At capacity a cancelled, non-subscription entry is reclaimed;
    /// its id moves to `retired_ids` so a late response can never
    /// correlate to a later request that reuses the id.
    pub(crate) fn register(
        &mut self,
        direction: MessageDirection,
        id: RpcId,
        entry: TrackedRequest,
    ) -> Result<(), &'static str> {
        if matches!(id, RpcId::Null) {
            return Err("request id must not be null");
        }
        let key = (direction, id);
        if self.requests.contains_key(&key) {
            return Err("duplicate in-flight request id");
        }
        if self.retired_ids.contains(&key) {
            return Err("request id retired after cancelled-entry reclaim");
        }
        if self.requests.len() >= MAX_IN_FLIGHT_REQUESTS {
            // Reclaim a cancelled, non-subscription entry — a forwarded
            // cancel must not permanently consume capacity. Its late
            // response loses correlation; a cancelled subscription entry
            // stays because it still resolves ack/notification traffic.
            // The retired set is bounded FIFO: when full, the oldest id
            // is evicted so reclamation itself cannot wedge the session.
            let reclaim = self
                .requests
                .iter()
                .find(|(_, e)| e.cancelled && e.subscription.is_none())
                .map(|(k, _)| k.clone());
            let Some(victim) = reclaim else {
                return Err("in-flight request limit reached");
            };
            self.requests.remove(&victim);
            if self.retired_ids.len() >= MAX_RETIRED_REQUEST_IDS
                && let Some(oldest) = self.retired_order.pop_front()
            {
                self.retired_ids.remove(&oldest);
            }
            self.retired_ids.insert(victim.clone());
            self.retired_order.push_back(victim);
        }
        self.requests.insert(key, entry);
        Ok(())
    }

    /// Drop a registration (e.g. the forward write failed).
    pub(crate) fn unregister(&mut self, direction: MessageDirection, id: &RpcId) {
        self.requests.remove(&(direction, id.clone()));
    }

    /// Inspect a tracked request without consuming it.
    pub(crate) fn get(&self, direction: MessageDirection, id: &RpcId) -> Option<&TrackedRequest> {
        self.requests.get(&(direction, id.clone()))
    }

    /// Consume the tracked request a response answers.
    pub(crate) fn take(
        &mut self,
        direction: MessageDirection,
        id: &RpcId,
    ) -> Option<TrackedRequest> {
        self.requests.remove(&(direction, id.clone()))
    }

    /// Look up the request a response answers without consuming it.
    /// Entries whose response already correlated (`responded` — the
    /// 2026 `subscriptions/listen` case) cannot be answered twice.
    pub(crate) fn answered(
        &self,
        response_direction: MessageDirection,
        id: &RpcId,
    ) -> Option<AnsweredRequest> {
        self.requests
            .get(&(opposite(response_direction), id.clone()))
            .filter(|e| !e.responded)
            .map(|e| AnsweredRequest {
                request_direction: opposite(response_direction),
                method: e.method.clone(),
                // Correlation asks "did this request genuinely reach the
                // peer": a dry-run forward did, even when policy denied
                // it. The raw `allowed` verdict stays on `TrackedRequest`
                // for PR-11's `input_required` gate.
                reached_peer: e.allowed || e.dry_run,
                internal: e.internal,
            })
    }

    /// `notifications/cancelled` correlation: in-flight request travelling
    /// in the notification's own direction; for 2026 S2C cancels, a live
    /// `subscriptions/listen` the subscription id resolved from.
    pub(crate) fn cancel_facts(
        &self,
        direction: MessageDirection,
        id: &RpcId,
        version: SupportedProtocolVersion,
    ) -> CancelFacts {
        if version == V26 && direction == S2C {
            return match self
                .requests
                .get(&(C2S, id.clone()))
                .and_then(|e| e.subscription.as_ref().map(|s| s.state))
            {
                Some(SubscriptionState::PendingAck | SubscriptionState::Active) => {
                    CancelFacts::Subscription
                }
                _ => CancelFacts::Unrelated,
            };
        }
        match self.requests.get(&(direction, id.clone())) {
            Some(_) => CancelFacts::OwnedRequest,
            None => CancelFacts::Unrelated,
        }
    }

    /// `notifications/progress` correlation: the token must belong to an
    /// in-flight request travelling **opposite** the notification — the
    /// responder reports progress to the requester.
    pub(crate) fn progress(
        &self,
        direction: MessageDirection,
        token: &RpcId,
    ) -> ProgressCorrelation {
        let requester = opposite(direction);
        let matched = self
            .requests
            .iter()
            .any(|((d, _), e)| *d == requester && e.progress_token.as_ref() == Some(token));
        if matched {
            ProgressCorrelation::Matched
        } else {
            ProgressCorrelation::Unmatched
        }
    }

    /// 2026 `notifications/message` correlation. stdio has no response
    /// stream to lean on, so resolution order is: `subscriptionId` → the
    /// listen request; `progressToken` → the request carrying it; finally
    /// exactly one in-flight C2S request that declared a `logLevel`.
    /// Anything ambiguous yields `None` — the notification drops.
    pub(crate) fn message_correlation(
        &self,
        subscription_id: Option<&RpcId>,
        progress_token: Option<&RpcId>,
    ) -> Option<MessageCorrelation<'_>> {
        if let Some(id) = subscription_id
            && let Some(entry) = self.requests.get(&(C2S, id.clone()))
            && entry.subscription.is_some()
        {
            return Some(MessageCorrelation {
                log_level: entry.log_level.as_deref(),
            });
        }
        if let Some(token) = progress_token
            && let Some(entry) = self
                .requests
                .iter()
                .find(|((d, _), e)| *d == C2S && e.progress_token.as_ref() == Some(token))
                .map(|(_, e)| e)
        {
            return Some(MessageCorrelation {
                log_level: entry.log_level.as_deref(),
            });
        }
        let mut candidates = self
            .requests
            .iter()
            .filter(|((d, _), e)| *d == C2S && e.log_level.is_some());
        match (candidates.next(), candidates.next()) {
            (Some((_, entry)), None) => Some(MessageCorrelation {
                log_level: entry.log_level.as_deref(),
            }),
            _ => None,
        }
    }

    /// Resolved subscription for a 2026 subscription notification /
    /// ack / cancel.
    pub(crate) fn subscription_facts(&self, id: &RpcId) -> Option<SubscriptionFacts<'_>> {
        let entry = self.requests.get(&(C2S, id.clone()))?;
        let sub = entry.subscription.as_ref()?;
        Some(SubscriptionFacts {
            state: sub.state,
            requested: &sub.requested,
            acked: &sub.acked,
            acked_uris: &sub.acked_uris,
        })
    }

    /// Side effects of a request about to be forwarded, applied under the
    /// same lock as [`register`](Self::register) so a response that lands
    /// the instant the write completes already sees them: establishes the
    /// wire revision on the first C2S request, stashes `initialize`
    /// client capabilities until the response commits them, and marks a
    /// forwarded server `elicitation/create` pending. The returned token
    /// lets [`rollback_forwarded_request`](Self::rollback_forwarded_request)
    /// restore everything when the write fails.
    pub(crate) fn on_request_forwarded(
        &mut self,
        direction: MessageDirection,
        id: &RpcId,
        method: &str,
        version: SupportedProtocolVersion,
        ext: &ExtractedRequest,
    ) -> RequestForwardUndo {
        let undo = RequestForwardUndo {
            direction,
            id: id.clone(),
            version: self.version,
            pending_init_capabilities: self.pending_init_capabilities.clone(),
            elicitation_pending: self.elicitation_pending,
        };
        if direction == C2S {
            if self.version.is_none() {
                self.version = Some(version);
            }
            if method == "initialize" {
                self.pending_init_capabilities = Some(ext.initialize_client_capabilities.clone());
            }
        } else if method == "elicitation/create" {
            self.elicitation_pending = true;
        }
        undo
    }

    /// Roll back a request whose forward write failed: drop the
    /// registration and restore the side-effect state the token captured.
    pub(crate) fn rollback_forwarded_request(&mut self, undo: RequestForwardUndo) {
        self.unregister(undo.direction, &undo.id);
        self.version = undo.version;
        self.pending_init_capabilities = undo.pending_init_capabilities;
        self.elicitation_pending = undo.elicitation_pending;
    }

    /// Side effects of a forwarded notification.
    pub(crate) fn on_notification_forwarded(
        &mut self,
        direction: MessageDirection,
        version: SupportedProtocolVersion,
        method: &str,
        ext: &ExtractedNotification,
    ) {
        match (direction, method) {
            (C2S, "notifications/initialized") => {
                self.init = InitStage::Operational;
            }
            (_, "notifications/cancelled") => {
                if let Some(id) = &ext.cancel_id {
                    if version == V26 && direction == S2C {
                        self.end_subscription(id);
                    } else {
                        // Cancelling a completed (`responded`) request —
                        // the subscription-cancel case for a 2026 listen —
                        // retires the entry outright; an in-flight request
                        // keeps its entry so a late response correlates.
                        let responded = self
                            .requests
                            .get(&(direction, id.clone()))
                            .is_some_and(|e| e.responded);
                        if responded {
                            self.requests.remove(&(direction, id.clone()));
                        } else if let Some(entry) = self.requests.get_mut(&(direction, id.clone()))
                        {
                            entry.cancelled = true;
                            if let Some(sub) = entry.subscription.as_mut() {
                                sub.state = SubscriptionState::Ended;
                            }
                        }
                    }
                }
            }
            (S2C, "notifications/subscriptions/acknowledged") => {
                if let Some(id) = &ext.subscription_id
                    && let Some(sub) = self
                        .requests
                        .get_mut(&(C2S, id.clone()))
                        .and_then(|e| e.subscription.as_mut())
                {
                    sub.state = SubscriptionState::Active;
                    if let Some(filters) = &ext.ack_filters {
                        sub.acked = filters.enabled();
                        sub.acked_uris = filters.resource_subscriptions.clone().unwrap_or_default();
                    }
                }
            }
            (S2C, "notifications/elicitation/complete") => {
                self.elicitation_pending = false;
            }
            _ => {}
        }
    }

    /// Side effects of a forwarded response: commits negotiated
    /// capabilities, the 2025 lifecycle stage, URI subscriptions, and the
    /// log threshold.
    ///
    /// `entry` is the tracked request the response answered (already
    /// consumed by [`take`](Self::take)). `is_result` marks a
    /// non-error completion.
    pub(crate) fn on_response_forwarded(
        &mut self,
        response_direction: MessageDirection,
        entry: &TrackedRequest,
        ext: &ExtractedResponse,
        is_result: bool,
    ) {
        if response_direction == C2S {
            if entry.method == "elicitation/create" {
                self.elicitation_pending = false;
            }
            return;
        }
        if !is_result {
            return;
        }
        match entry.method.as_str() {
            "initialize" => {
                self.client_capabilities =
                    self.pending_init_capabilities.take().unwrap_or_default();
                self.server_capabilities = ext.initialize_server_capabilities.clone();
                self.init = InitStage::AwaitingInitialized;
            }
            "resources/subscribe" => {
                if let Some(uri) = &entry.uri
                    && !self.resource_subscriptions.contains(uri)
                    && self.resource_subscriptions.len() < MAX_RESOURCE_SUBSCRIPTIONS
                {
                    self.resource_subscriptions.push(uri.clone());
                }
            }
            "resources/unsubscribe" => {
                if let Some(uri) = &entry.uri {
                    self.resource_subscriptions.retain(|u| u != uri);
                }
            }
            "logging/setLevel" => {
                if let Some(level) = &entry.level {
                    self.log_level = Some(level.clone());
                }
            }
            _ => {}
        }
    }

    /// Mark a 2026 subscription ended (a forwarded
    /// `notifications/cancelled` carrying the subscription id). When the
    /// listen request already completed the entry is removed; when it is
    /// still in flight the `Ended` state lets its late response correlate
    /// while new subscription traffic drops.
    fn end_subscription(&mut self, id: &RpcId) {
        let key = (C2S, id.clone());
        let responded = self.requests.get(&key).is_some_and(|e| e.responded);
        if responded {
            self.requests.remove(&key);
            return;
        }
        if let Some(sub) = self
            .requests
            .get_mut(&key)
            .and_then(|e| e.subscription.as_mut())
        {
            sub.state = SubscriptionState::Ended;
        }
    }

    /// A response to a `subscriptions/listen` request correlated and is
    /// about to forward: the request completes but the subscription —
    /// keyed by the same id — keeps the entry for ack / notification /
    /// cancel resolution. A second response no longer correlates.
    /// A subscription already `Ended` (cancel forwarded first) frees the
    /// entry, which is returned for the caller's audit bookkeeping.
    pub(crate) fn mark_responded(
        &mut self,
        direction: MessageDirection,
        id: &RpcId,
    ) -> Option<TrackedRequest> {
        let key = (direction, id.clone());
        let entry = self.requests.get_mut(&key)?;
        entry.responded = true;
        let ended = entry
            .subscription
            .as_ref()
            .is_some_and(|s| s.state == SubscriptionState::Ended);
        if ended || entry.cancelled {
            return self.requests.remove(&key);
        }
        None
    }

    /// `initialize` result check the decision model cannot express: the
    /// negotiated `protocolVersion` must be exactly `2025-11-25`.
    pub(crate) fn initialize_result_version_ok(ext: &ExtractedResponse) -> bool {
        ext.initialize_protocol_version.as_deref() == Some(MCP_VERSION_2025_11_25)
    }
}

// ── Decision audit ────────────────────────────────────────────────────

/// Record one MCP traffic decision. Every frame that reached `decide` is
/// logged — direction, kind, method, revision, verdict reason, and whether
/// the frame was actually forwarded. Dry-run forwards of violations are
/// `Observed`, never `Allowed`.
#[allow(clippy::too_many_arguments)]
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
) {
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
    let mut details = format!(
        "dir={} kind={kind} version={} verdict={} reason={} forwarded={forwarded}",
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
    audit.log(event);
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
#[allow(clippy::too_many_arguments)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str) -> TrackedRequest {
        TrackedRequest::from_extracted(method, V25, true, false, &ExtractedRequest::default())
    }

    fn num(n: u64) -> RpcId {
        RpcId::from_u64(n)
    }

    fn cancel(wire: &mut WireState, direction: MessageDirection, id: RpcId) {
        wire.on_notification_forwarded(
            direction,
            V25,
            "notifications/cancelled",
            &ExtractedNotification {
                cancel_id: Some(id),
                ..Default::default()
            },
        );
    }

    /// At capacity a cancelled entry frees its slot, but its id stays
    /// retired: reuse is refused and a late response never correlates.
    #[test]
    fn capacity_reclaim_retires_cancelled_id() {
        let mut wire = WireState::new();
        for n in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
            wire.register(C2S, num(n), req("ping")).unwrap();
        }
        cancel(&mut wire, C2S, num(7));

        wire.register(C2S, num(128), req("ping")).unwrap();

        assert_eq!(
            wire.register(S2C, num(200), req("ping")),
            Err("in-flight request limit reached")
        );
        // The reclaimed id is refused for reuse in its direction, and a
        // late response to it no longer correlates.
        assert!(wire.register(C2S, num(7), req("ping")).is_err());
        assert!(wire.answered(S2C, &num(7)).is_none());
        // The evicted entry is gone from the live table.
        assert!(!wire.requests.contains_key(&(C2S, num(7))));
    }

    /// A cancelled `subscriptions/listen` keeps its subscription facts —
    /// it is not reclaimable, so the table stays full.
    #[test]
    fn cancelled_subscription_is_not_reclaimed() {
        let mut wire = WireState::new();
        wire.register(S2C, num(0), req("ping")).unwrap();
        for n in 1..MAX_IN_FLIGHT_REQUESTS as u64 {
            wire.register(C2S, num(n), req("ping")).unwrap();
        }
        // Cancel a C2S entry that carries subscription state.
        let listen_id = num(1);
        wire.unregister(C2S, &listen_id);
        wire.register(C2S, listen_id.clone(), req("subscriptions/listen"))
            .unwrap();
        cancel(&mut wire, C2S, listen_id.clone());

        assert_eq!(
            wire.register(C2S, num(200), req("ping")),
            Err("in-flight request limit reached")
        );
        // Cancel the reclaimable S2C entry instead: it frees a slot.
        cancel(&mut wire, S2C, num(0));
        wire.register(C2S, num(200), req("ping")).unwrap();
    }

    /// A full retired set evicts its oldest id FIFO — a long stream of
    /// cancels must not permanently block new registrations once
    /// `retired_ids` reaches the cap.
    #[test]
    fn retired_ids_evict_oldest_fifo() {
        let mut wire = WireState::new();
        for n in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
            wire.register(C2S, num(n), req("ping")).unwrap();
        }
        // Reclaim the whole table once: retired_ids fills in id order.
        for n in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
            cancel(&mut wire, C2S, num(n));
            wire.register(C2S, num(MAX_IN_FLIGHT_REQUESTS as u64 + n), req("ping"))
                .unwrap();
        }
        assert_eq!(wire.retired_ids.len(), MAX_RETIRED_REQUEST_IDS);
        // The next reclaim evicts the oldest retired id (0), so it is
        // reusable — while an id still retired (5) stays refused.
        cancel(&mut wire, C2S, num(128));
        wire.register(C2S, num(256), req("ping")).unwrap();
        cancel(&mut wire, C2S, num(129));
        wire.register(C2S, num(0), req("ping")).unwrap();
        assert_eq!(
            wire.register(C2S, num(5), req("ping")),
            Err("request id retired after cancelled-entry reclaim")
        );
    }

    fn classify(line: &str) -> WireFrame {
        let json = nojson::RawJson::parse(line).expect("parse test frame");
        classify_frame(json.value())
    }

    /// A `method`+`result`/`error` hybrid is not a usable envelope — a
    /// peer dispatching on `result`/`id` first could read a forged
    /// answer to a pending request.
    #[test]
    fn mixed_envelope_is_malformed() {
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"ping","error":{"code":-32000,"message":"x"}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/progress","result":{}}"#,
        ] {
            assert!(
                matches!(classify(line), WireFrame::Malformed { .. }),
                "{line} must classify as malformed"
            );
        }
        // A response carrying both `result` and `error` is ambiguous too.
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}"#),
            WireFrame::Malformed { .. }
        ));
        // Clean envelopes are unaffected.
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
            WireFrame::Request { .. }
        ));
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
            WireFrame::Notification { .. }
        ));
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
            WireFrame::Response { .. }
        ));
        assert!(matches!(
            classify(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}"#),
            WireFrame::Response { .. }
        ));
    }
}
