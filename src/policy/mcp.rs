//! MCP passage rules (`mcp` blocks) and the per-message decision model.
//!
//! This module is the judgment model only — it defines the policy surface
//! and `decide()`; enforcement on the live wire (direction plumbing,
//! correlation tables, subscription bookkeeping, MRTR result dispatch)
//! belongs to the Auditor and is not enabled here.
//!
//! KDL schema v2 only: `mcp` rule blocks appear under `server` and are
//! parsed by `kdl_parse::parse_server_mcp_rules`, rejected under `policy
//! version=1`. Public load paths still gate `version != 1` in
//! `policy::validator`, so v2 rules cannot be activated externally until
//! the version gate flips.
//!
//! Rule key = (protocol revision, direction, kind, method). A rule is an
//! `allow`/`deny` effect over the rule-key atoms a method name expands
//! to. Unknown methods have no atoms and cannot be targeted — on the wire
//! they fail closed the same way.
//!
//! # Default passage profile (no `mcp` rules, including version 1)
//!
//! Only protocol machinery passes: `initialize` + `initialized` (2025),
//! `ping` (2025), `tools/list`, `tools/call`, `server/discover` (2026),
//! `subscriptions/listen` limited to the free `toolsListChanged` filter
//! (2026), correlated `cancelled`/`progress`, `subscriptions/acknowledged`
//! when it grants nothing extra, correlated error/result responses, and
//! every direction-legal frame a deny rule did not cover. Explicit-rule
//! methods — `resources/*`, `prompts/*`, `completion/*`, `logging/*`,
//! `sampling/*`, `roots/*`, `elicitation/*`, subscription filters beyond
//! `toolsListChanged`, and additional-request methods — are denied.

use std::collections::{BTreeMap, BTreeSet};

use crate::protocol::fields::{
    InitializeShape, ListenFilters, RequestMeta, SchemaField, SubscriptionFilter, rfc5424_rank,
};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

use super::Policy;

// ── Rule model ────────────────────────────────────────────────────────

/// The `kind` component of a rule key — where in the wire traffic a
/// method name may legally appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleKind {
    /// JSON-RPC request frames.
    Request,
    /// JSON-RPC notification frames (no `id`).
    Notification,
    /// MRTR additional requests: `inputRequests[]` entries inside an
    /// `input_required` result. On the wire they travel as ordinary
    /// server→client request descriptors inside a result — never as
    /// top-level frames — so this kind exists only in rule keys.
    AdditionalRequest,
}

impl RuleKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Notification => "notification",
            Self::AdditionalRequest => "additional-request",
        }
    }
}

/// `allow` / `deny` effect of one `mcp` rule node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleEffect {
    Allow,
    Deny,
}

/// One rule-key slot a method name can legally occupy:
/// (revision, direction, kind) — all three implied by the method itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MethodSlot {
    pub version: SupportedProtocolVersion,
    pub direction: MessageDirection,
    pub kind: RuleKind,
}

const V25: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2025November25;
const V26: SupportedProtocolVersion = SupportedProtocolVersion::Mcp2026July28;
const C2S: MessageDirection = MessageDirection::ClientToServer;
const S2C: MessageDirection = MessageDirection::ServerToClient;

const REQ: RuleKind = RuleKind::Request;
const NOTIF: RuleKind = RuleKind::Notification;
const ADDL: RuleKind = RuleKind::AdditionalRequest;

const fn slot(
    version: SupportedProtocolVersion,
    direction: MessageDirection,
    kind: RuleKind,
) -> MethodSlot {
    MethodSlot {
        version,
        direction,
        kind,
    }
}

/// The closed ledger of MCP method names the rule engine understands.
///
/// An `mcp` rule may only target methods listed here — anything else is a
/// load error. On the wire, unlisted methods get no rule atom and fall to
/// `unknown-method` (fail closed), which is also where MCP extensions
/// land until the ledger grows.
pub const METHOD_LEDGER: &[(&str, &[MethodSlot])] = &[
    ("initialize", &[slot(V25, C2S, REQ)]),
    ("ping", &[slot(V25, C2S, REQ), slot(V25, S2C, REQ)]),
    ("tools/list", &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)]),
    ("tools/call", &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)]),
    (
        "resources/list",
        &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)],
    ),
    (
        "resources/templates/list",
        &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)],
    ),
    (
        "resources/read",
        &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)],
    ),
    ("resources/subscribe", &[slot(V25, C2S, REQ)]),
    ("resources/unsubscribe", &[slot(V25, C2S, REQ)]),
    ("prompts/list", &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)]),
    ("prompts/get", &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)]),
    (
        "completion/complete",
        &[slot(V25, C2S, REQ), slot(V26, C2S, REQ)],
    ),
    ("logging/setLevel", &[slot(V25, C2S, REQ)]),
    ("server/discover", &[slot(V26, C2S, REQ)]),
    ("subscriptions/listen", &[slot(V26, C2S, REQ)]),
    // Server-originated requests (2025) and MRTR additional requests (2026).
    (
        "sampling/createMessage",
        &[slot(V25, S2C, REQ), slot(V26, S2C, ADDL)],
    ),
    ("roots/list", &[slot(V25, S2C, REQ), slot(V26, S2C, ADDL)]),
    (
        "elicitation/create",
        &[slot(V25, S2C, REQ), slot(V26, S2C, ADDL)],
    ),
    ("notifications/initialized", &[slot(V25, C2S, NOTIF)]),
    (
        "notifications/cancelled",
        &[
            slot(V25, C2S, NOTIF),
            slot(V25, S2C, NOTIF),
            slot(V26, C2S, NOTIF),
            slot(V26, S2C, NOTIF),
        ],
    ),
    (
        "notifications/progress",
        &[
            slot(V25, C2S, NOTIF),
            slot(V25, S2C, NOTIF),
            slot(V26, S2C, NOTIF),
        ],
    ),
    ("notifications/roots/list_changed", &[slot(V25, C2S, NOTIF)]),
    (
        "notifications/message",
        &[slot(V25, S2C, NOTIF), slot(V26, S2C, NOTIF)],
    ),
    (
        "notifications/tools/list_changed",
        &[slot(V25, S2C, NOTIF), slot(V26, S2C, NOTIF)],
    ),
    (
        "notifications/resources/list_changed",
        &[slot(V25, S2C, NOTIF), slot(V26, S2C, NOTIF)],
    ),
    (
        "notifications/prompts/list_changed",
        &[slot(V25, S2C, NOTIF), slot(V26, S2C, NOTIF)],
    ),
    (
        "notifications/resources/updated",
        &[slot(V25, S2C, NOTIF), slot(V26, S2C, NOTIF)],
    ),
    (
        "notifications/elicitation/complete",
        &[slot(V25, S2C, NOTIF)],
    ),
    (
        "notifications/subscriptions/acknowledged",
        &[slot(V26, S2C, NOTIF)],
    ),
];

/// Slots of a registered method; empty for anything not in the ledger.
pub fn method_slots(method: &str) -> &'static [MethodSlot] {
    METHOD_LEDGER
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(_, slots)| *slots)
        .unwrap_or(&[])
}

/// The ledger's canonical name for `method` — `None` outside the ledger.
/// Lets a [`RuleKey`] stay borrow-only: stored keys carry this `'static`
/// name, so lookups never allocate.
fn ledger_name(method: &str) -> Option<&'static str> {
    METHOD_LEDGER
        .iter()
        .find(|(name, _)| *name == method)
        .map(|(name, _)| *name)
}

/// A fully-qualified rule key. `McpRule` entries expand into atoms of
/// this shape; merge and decision both operate at atom granularity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RuleKey {
    pub version: SupportedProtocolVersion,
    pub direction: MessageDirection,
    pub kind: RuleKind,
    /// Canonical method name from [`METHOD_LEDGER`].
    pub method: &'static str,
}

/// One `allow`/`deny` node inside an `mcp` block, as parsed.
///
/// `versions` empty means "every slot of the method"; `direction` `None`
/// means the method's canonical direction. Both are restrictions — the
/// rule still expands over the method's own slots, never outside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRule {
    pub effect: RuleEffect,
    pub method: String,
    /// `protocol="..."` restrictions; empty = all the method's revisions.
    pub versions: Vec<SupportedProtocolVersion>,
    /// `direction="..."` restriction; `None` = canonical direction.
    pub direction: Option<MessageDirection>,
    /// `uri` children — resource URIs for `resources/read`,
    /// `resources/subscribe`, `resources/unsubscribe`, and the
    /// `resourceSubscriptions` range of `subscriptions/listen`. Compared
    /// verbatim; never normalised as host paths.
    pub uris: Vec<String>,
    /// `filter` children — only meaningful on `subscriptions/listen`.
    pub filters: Vec<SubscriptionFilter>,
}

impl McpRule {
    /// Expand this rule into the rule-key atoms it covers.
    pub fn atoms(&self) -> Vec<RuleKey> {
        let Some(&(method, slots)) = METHOD_LEDGER.iter().find(|(name, _)| *name == self.method)
        else {
            return Vec::new();
        };
        slots
            .iter()
            .filter(|s| self.versions.is_empty() || self.versions.contains(&s.version))
            .filter(|s| self.direction.is_none_or(|d| d == s.direction))
            .map(|s| RuleKey {
                version: s.version,
                direction: s.direction,
                kind: s.kind,
                method,
            })
            .collect()
    }
}

/// An atom after merging: one rule key with its effective value.
///
/// Effect is deny-sticky; `uris`/`filters` union only while the atom
/// stays allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRule {
    pub effect: RuleEffect,
    pub uris: Vec<String>,
    pub filters: Vec<SubscriptionFilter>,
}

/// Atom-normalised rules per server — what `decide` consults and what
/// the emitter writes. Stored pre-resolved in [`ServerMcpRules`].
type RuleMap = BTreeMap<RuleKey, ResolvedRule>;

/// `mcp` rules bound to one `server` identity.
///
/// `resolved` is computed once at construction and refreshed by every
/// rule-list mutation, so `decide` performs no per-message resolution.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerMcpRules {
    pub server_name: Option<String>,
    rules: Vec<McpRule>,
    resolved: RuleMap,
}

impl ServerMcpRules {
    /// Bind `rules` to a server identity and resolve their atoms once.
    pub fn new(server_name: Option<String>, rules: Vec<McpRule>) -> Self {
        let resolved = resolve_atoms(&rules);
        Self {
            server_name,
            rules,
            resolved,
        }
    }

    /// The declared rules, pre-resolution.
    pub fn rules(&self) -> &[McpRule] {
        &self.rules
    }

    /// Consume the entry into its declared rules.
    pub fn into_rules(self) -> Vec<McpRule> {
        self.rules
    }

    /// Union additional rules (include / `when` merges) and re-resolve.
    pub fn extend_rules(&mut self, extra: impl IntoIterator<Item = McpRule>) {
        self.rules.extend(extra);
        self.resolved = resolve_atoms(&self.rules);
    }

    /// Replace the declared rules and re-resolve.
    pub fn set_rules(&mut self, rules: Vec<McpRule>) {
        self.rules = rules;
        self.resolved = resolve_atoms(&self.rules);
    }
}

/// Merge rule entries into atom-normalised form. Deny wins over allow on
/// the same atom; allow parameters union. The result is what `decide`
/// consults and what the emitter writes.
pub fn resolve_atoms(rules: &[McpRule]) -> BTreeMap<RuleKey, ResolvedRule> {
    let mut map: BTreeMap<RuleKey, ResolvedRule> = BTreeMap::new();
    for rule in rules {
        for key in rule.atoms() {
            match map.get_mut(&key) {
                Some(existing) => match (existing.effect, rule.effect) {
                    (_, RuleEffect::Deny) => {
                        existing.effect = RuleEffect::Deny;
                        existing.uris.clear();
                        existing.filters.clear();
                    }
                    (RuleEffect::Deny, RuleEffect::Allow) => {}
                    (RuleEffect::Allow, RuleEffect::Allow) => {
                        for u in &rule.uris {
                            if !existing.uris.contains(u) {
                                existing.uris.push(u.clone());
                            }
                        }
                        for f in &rule.filters {
                            if !existing.filters.contains(f) {
                                existing.filters.push(*f);
                            }
                        }
                    }
                },
                None => {
                    map.insert(
                        key,
                        ResolvedRule {
                            effect: rule.effect,
                            uris: rule.uris.clone(),
                            filters: rule.filters.clone(),
                        },
                    );
                }
            }
        }
    }
    for resolved in map.values_mut() {
        resolved.uris.sort();
        resolved.uris.dedup();
        resolved.filters.sort();
        resolved.filters.dedup();
    }
    map
}

/// Check one server's rule list for intra-document atom collisions.
/// Two rules covering the same atom — same effect or not — are a load
/// error: the author must restate the intent in non-overlapping rules.
pub fn validate_rule_set(server_name: Option<&str>, rules: &[McpRule]) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for rule in rules {
        for atom in rule.atoms() {
            if !seen.insert(atom.clone()) {
                let server = server_name.unwrap_or("<unnamed>");
                return Err(format!(
                    "conflicting mcp rules in server '{server}': method \"{}\" \
                     (protocol \"{}\", direction \"{}\") is covered more than once",
                    atom.method,
                    atom.version.as_str(),
                    atom.direction.as_str()
                ));
            }
        }
    }
    Ok(())
}

// ── Decision inputs ───────────────────────────────────────────────────

/// 2025-11-25 lifecycle stage; ignored for 2026-07-28 messages.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum InitStage {
    /// No `initialize` response seen yet.
    #[default]
    PendingInitialize,
    /// `initialize` answered; `notifications/initialized` not yet seen.
    AwaitingInitialized,
    /// `notifications/initialized` observed; steady state.
    Operational,
}

/// What `notifications/cancelled`'s `requestId` resolved to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CancelFacts {
    /// No tracked in-flight request (or subscription) matched.
    #[default]
    Unrelated,
    /// A tracked in-flight request travelling in this notification's
    /// direction matched (including a 2026 `subscriptions/listen`).
    OwnedRequest,
    /// A tracked 2026 subscription id matched — only meaningful for the
    /// server→client `notifications/cancelled` (subscription cancel).
    Subscription,
}

/// `notifications/progress` correlation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ProgressCorrelation {
    /// No in-flight same-direction request carried this progressToken.
    #[default]
    Unmatched,
    /// The token belongs to a tracked in-flight same-direction request.
    Matched,
}

/// Correlation for `2026-07-28` `notifications/message`.
#[derive(Debug, Clone, Copy)]
pub struct MessageCorrelation<'a> {
    /// `_meta` `logLevel` the tracked request asked for. `None` means the
    /// request did not ask for log messages — the server MUST NOT emit on
    /// its stream.
    pub log_level: Option<&'a str>,
}

/// Lifecycle of a tracked 2026 subscription.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionState {
    /// `subscriptions/listen` accepted; `subscriptions/acknowledged` not
    /// yet seen as the first message on this subscription.
    PendingAck,
    /// Acknowledged; normal notification flow.
    Active,
    /// Gracefully closed (`notifications/cancelled` with the
    /// subscription id).
    Ended,
}

/// A resolved 2026 subscription for one subscription notification.
#[derive(Debug)]
pub struct SubscriptionFacts<'a> {
    pub state: SubscriptionState,
    /// Parsed `params.notifications` of the tracked listen request.
    pub requested: &'a ListenFilters,
    /// Filters the ack granted (Active subscriptions).
    pub acked: &'a [SubscriptionFilter],
    /// URIs the ack granted under `resourceSubscriptions`.
    pub acked_uris: &'a [String],
}

/// Pre-extracted request params relevant to the decision.
#[derive(Debug, Default)]
pub struct RequestParams<'a> {
    /// `initialize` params shape (2025).
    pub initialize: InitializeShape,
    /// `params.uri` verbatim (`resources/*`).
    pub uri: Option<&'a str>,
    /// `params.level` (`logging/setLevel`, 2025).
    pub level: Option<&'a str>,
    /// `params.notifications` (`subscriptions/listen`, 2026).
    pub notifications: Option<&'a ListenFilters>,
}

/// One JSON-RPC request frame.
pub struct RequestMessage<'a> {
    pub version: SupportedProtocolVersion,
    pub direction: MessageDirection,
    pub method: &'a str,
    /// `params._meta` — required on every 2026-07-28 request.
    pub meta: Option<&'a RequestMeta>,
    pub params: Option<&'a RequestParams<'a>>,
}

/// One JSON-RPC notification frame. Correlation fields are resolved by
/// the Auditor's tracking tables — never trusted from the frame itself.
pub struct NotificationMessage<'a> {
    pub version: SupportedProtocolVersion,
    pub direction: MessageDirection,
    pub method: &'a str,
    /// `params.uri` (`notifications/resources/updated`).
    pub uri: Option<&'a str>,
    /// `params.level` (`notifications/message`).
    pub level: Option<&'a str>,
    /// `params.notifications` (`notifications/subscriptions/acknowledged`).
    pub ack_filters: Option<&'a ListenFilters>,
    /// What `params.requestId` resolved to (`notifications/cancelled`).
    pub cancel_target: CancelFacts,
    /// `params.progressToken` correlation (`notifications/progress`).
    pub progress: ProgressCorrelation,
    /// Correlation for `notifications/message` (2026): the tracked
    /// request on whose response stream this message rides.
    pub message_for: Option<MessageCorrelation<'a>>,
    /// Resolved subscription for 2026 subscription notifications.
    pub subscription: Option<SubscriptionFacts<'a>>,
}

/// The tracked request an `input_required` result answered — context for
/// judging each `inputRequests[]` additional request.
#[derive(Debug, Clone, Copy)]
pub struct OriginalRequestFacts<'a> {
    /// Method of the tracked original request.
    pub method: &'a str,
    /// It was policy-allowed at pass time.
    pub allowed: bool,
    /// `clientCapabilities` its `_meta` declared (flattened names).
    pub client_capabilities: &'a [String],
}

/// One MRTR additional request — an `inputRequests[]` entry inside an
/// `input_required` result, judged against the original request.
pub struct AdditionalRequestMessage<'a> {
    /// Only `Mcp2026July28` carries MRTR.
    pub version: SupportedProtocolVersion,
    /// `method` of the inputRequests entry.
    pub method: &'a str,
    /// The original request this interim result answered.
    pub original: OriginalRequestFacts<'a>,
}

/// The tracked request a response answers (id correlation resolved).
#[derive(Debug, Clone, Copy)]
pub struct AnsweredFacts<'a> {
    /// Direction the answered request travelled; must oppose the
    /// response's direction.
    pub request_direction: MessageDirection,
    /// The tracked request's method.
    pub method: &'a str,
    /// The request was policy-allowed at pass time.
    pub allowed: bool,
}

/// One JSON-RPC response frame.
pub struct ResponseMessage<'a> {
    pub version: SupportedProtocolVersion,
    pub direction: MessageDirection,
    /// JSON-RPC `error` member present.
    pub is_error: bool,
    /// JSON-RPC `result` member present — a well-formed response carries
    /// exactly one of `result` / `error`.
    pub has_result: bool,
    /// `result.resultType` verbatim (`complete`, `input_required`, …).
    pub result_type: Option<&'a str>,
    /// `result.ttlMs` schema check (CacheableResult only).
    pub ttl_ms: SchemaField,
    /// `result.cacheScope` schema check (CacheableResult only).
    pub cache_scope: SchemaField,
    /// `result.inputRequests` member present.
    pub input_requests: bool,
    /// The tracked request this response answers.
    pub answered: Option<AnsweredFacts<'a>>,
}

/// One message presented to the decision model.
pub enum TrafficMessage<'a> {
    Request(RequestMessage<'a>),
    Notification(NotificationMessage<'a>),
    AdditionalRequest(AdditionalRequestMessage<'a>),
    Response(ResponseMessage<'a>),
}

/// Session/correlation state the Auditor supplies to `decide`.
///
/// Every field is tracking-table output, not frame claims: a message can
/// only reference state the Auditor already recorded.
#[derive(Debug, Default)]
pub struct SessionFacts<'a> {
    /// 2025-11-25 lifecycle stage.
    pub init: InitStage,
    /// Negotiated client capabilities, flattened (2025 only — 2026 reads
    /// capabilities from each request's `_meta`).
    pub client_capabilities: &'a [String],
    /// Negotiated server capabilities, flattened (2025 only).
    pub server_capabilities: &'a [String],
    /// URIs the client is currently subscribed to via
    /// `resources/subscribe` (2025 only).
    pub resource_subscriptions: &'a [String],
    /// A server `elicitation/create` request is pending completion
    /// (2025 `notifications/elicitation/complete` gate).
    pub elicitation_pending: bool,
    /// Threshold set by the client's last `logging/setLevel` (2025
    /// `notifications/message` gate).
    pub log_level: Option<&'a str>,
}

// ── Verdict and stable reason codes ───────────────────────────────────

/// Why a message passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowReason {
    /// Protocol machinery — no explicit rule required.
    ProtocolPass,
    /// An `allow` rule atom matched.
    RuleAllow,
    /// A tracked 2026 subscription granted this notification.
    SubscriptionMatched,
}

/// Why a notification is silently dropped (never answered).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Method unknown to the ledger / this revision.
    UnknownMethod,
    /// Method exists but not in this revision.
    VersionRemoved,
    /// Frame kind illegal in this direction for this revision.
    VersionDirection,
    /// No `allow` atom and the behavior requires one.
    NoRule,
    /// A `deny` atom matched.
    RuleDeny,
    /// 2025 lifecycle ordering violated.
    InitOrder,
    /// Required capability was not negotiated/declared.
    Capability,
    /// Correlation failed (id / token / subscription / elicitationId).
    Uncorrelated,
    /// Subscription lifecycle forbids this message.
    SubscriptionState,
    /// Malformed required field (level, uri shape, filter member type).
    Shape,
    /// Filter name outside the schema set.
    FilterUnknown,
    /// Filter not granted by rules / not requested.
    FilterNotAllowed,
    /// URI outside the granted subscription/filter set.
    UriNotAllowed,
    /// Message level below the requested threshold.
    LevelRange,
}

/// Why a request/response is denied (error surfaced to the originator).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    UnknownMethod,
    VersionRemoved,
    VersionDirection,
    NoRule,
    RuleDeny,
    InitOrder,
    Capability,
    /// `_meta` object or a required `_meta` member absent on a 2026 request.
    MetaMissing,
    /// `_meta` `protocolVersion` missing or not `"2026-07-28"`.
    MetaVersion,
    /// `_meta` or a required `_meta` member present but malformed
    /// (not an object).
    MetaMalformed,
    /// Required field malformed (initialize params, level, uri presence,
    /// response `result`/`error` exclusivity).
    Shape,
    /// `uri` outside the rule's `uri` set.
    UriNotAllowed,
    FilterUnknown,
    FilterNotAllowed,
    /// Response (or notification) without a matching tracked request.
    Uncorrelated,
    /// `resultType` missing/unknown, or `inputRequests` on a `complete` result.
    ResultType,
    /// `ttlMs`/`cacheScope` missing or invalid on a CacheableResult.
    CacheFields,
    /// `input_required` on a method that may not emit it.
    InputRequiredTarget,
    LevelRange,
}

/// A judgment the MRTR layer must complete (PR-11 enforcement surface).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndecidedReason {
    /// `resultType=input_required` on an eligible original request — the
    /// pass/fail of its `inputRequests[]` decides the whole result.
    InputRequired,
}

/// The decision for one message. Outcome is the enum variant; the payload
/// is the stable reason code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpVerdict {
    /// Forward the message.
    Allow(AllowReason),
    /// Discard without answering (notifications only).
    Drop(DropReason),
    /// Reject with an error to the originator.
    Deny(DenyReason),
    /// Cannot be decided by this layer alone.
    Undecided(UndecidedReason),
}

impl AllowReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolPass => "protocol-pass",
            Self::RuleAllow => "rule-allow",
            Self::SubscriptionMatched => "subscription-matched",
        }
    }
}

impl DropReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownMethod => "unknown-method",
            Self::VersionRemoved => "version-removed",
            Self::VersionDirection => "version-direction",
            Self::NoRule => "no-rule",
            Self::RuleDeny => "rule-deny",
            Self::InitOrder => "init-order",
            Self::Capability => "capability",
            Self::Uncorrelated => "uncorrelated",
            Self::SubscriptionState => "subscription-state",
            Self::Shape => "shape",
            Self::FilterUnknown => "filter-unknown",
            Self::FilterNotAllowed => "filter-not-allowed",
            Self::UriNotAllowed => "uri-not-allowed",
            Self::LevelRange => "level-range",
        }
    }
}

impl DenyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownMethod => "unknown-method",
            Self::VersionRemoved => "version-removed",
            Self::VersionDirection => "version-direction",
            Self::NoRule => "no-rule",
            Self::RuleDeny => "rule-deny",
            Self::InitOrder => "init-order",
            Self::Capability => "capability",
            Self::MetaMissing => "meta-missing",
            Self::MetaVersion => "meta-version",
            Self::MetaMalformed => "meta-malformed",
            Self::Shape => "shape",
            Self::UriNotAllowed => "uri-not-allowed",
            Self::FilterUnknown => "filter-unknown",
            Self::FilterNotAllowed => "filter-not-allowed",
            Self::Uncorrelated => "uncorrelated",
            Self::ResultType => "result-type",
            Self::CacheFields => "cache-fields",
            Self::InputRequiredTarget => "input-required-target",
            Self::LevelRange => "level-range",
        }
    }
}

impl UndecidedReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputRequired => "input-required",
        }
    }
}

impl McpVerdict {
    /// Outcome label — `allow`, `drop`, `deny`, or `undecided`.
    pub const fn outcome(self) -> &'static str {
        match self {
            Self::Allow(_) => "allow",
            Self::Drop(_) => "drop",
            Self::Deny(_) => "deny",
            Self::Undecided(_) => "undecided",
        }
    }

    /// Stable reason code (e.g. `"uri-not-allowed"`), unique per reason.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Allow(r) => r.as_str(),
            Self::Drop(r) => r.as_str(),
            Self::Deny(r) => r.as_str(),
            Self::Undecided(r) => r.as_str(),
        }
    }
}

impl std::fmt::Display for McpVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}({})", self.outcome(), self.reason_code())
    }
}

// ── Behavior classification ───────────────────────────────────────────

enum RequestBehavior {
    Unknown,
    RemovedInVersion,
    /// Request direction is impossible in this revision.
    IllegalDirection,
    /// `initialize` (2025) — init ordering + params shape.
    Initialize,
    /// Protocol machinery — passes without an explicit rule.
    ProtocolPass,
    /// Requires an `allow` atom; `cap` is the negotiated capability name
    /// (server capabilities for C2S, client capabilities for S2C, 2025).
    Rule {
        cap: Option<&'static str>,
    },
    /// `resources/read` — allow atom + `uri` within the rule's uri set.
    RuleUri {
        cap: Option<&'static str>,
    },
    /// `resources/subscribe` / `resources/unsubscribe` (2025).
    ResourceSubscribe {
        unsubscribe: bool,
    },
    /// `subscriptions/listen` (2026) — filter-gated.
    SubscriptionListen,
    /// `logging/setLevel` (2025) — allow atom + RFC-5424 level.
    LogLevelSet,
}

fn request_behavior(v: SupportedProtocolVersion, d: MessageDirection, m: &str) -> RequestBehavior {
    use RequestBehavior::*;
    match (v, d) {
        // 2026-07-28 carries no server→client request frames.
        (SupportedProtocolVersion::Mcp2026July28, MessageDirection::ServerToClient) => {
            IllegalDirection
        }
        (SupportedProtocolVersion::Mcp2026July28, MessageDirection::ClientToServer) => match m {
            "server/discover" | "tools/list" | "tools/call" => ProtocolPass,
            "subscriptions/listen" => SubscriptionListen,
            "resources/list"
            | "resources/templates/list"
            | "prompts/list"
            | "prompts/get"
            | "completion/complete" => Rule { cap: None },
            "resources/read" => RuleUri { cap: None },
            "initialize"
            | "ping"
            | "logging/setLevel"
            | "resources/subscribe"
            | "resources/unsubscribe" => RemovedInVersion,
            _ => Unknown,
        },
        (SupportedProtocolVersion::Mcp2025November25, MessageDirection::ClientToServer) => {
            match m {
                "initialize" => Initialize,
                "ping" | "tools/list" | "tools/call" => ProtocolPass,
                "resources/list" | "resources/templates/list" => Rule {
                    cap: Some("resources"),
                },
                "resources/read" => RuleUri {
                    cap: Some("resources"),
                },
                "resources/subscribe" => ResourceSubscribe { unsubscribe: false },
                "resources/unsubscribe" => ResourceSubscribe { unsubscribe: true },
                "prompts/list" | "prompts/get" => Rule {
                    cap: Some("prompts"),
                },
                "completion/complete" => Rule {
                    cap: Some("completions"),
                },
                "logging/setLevel" => LogLevelSet,
                _ => Unknown,
            }
        }
        (SupportedProtocolVersion::Mcp2025November25, MessageDirection::ServerToClient) => {
            match m {
                "ping" => ProtocolPass,
                "sampling/createMessage" => Rule {
                    cap: Some("sampling"),
                },
                "roots/list" => Rule { cap: Some("roots") },
                "elicitation/create" => Rule {
                    cap: Some("elicitation"),
                },
                _ => Unknown,
            }
        }
    }
}

enum NotificationBehavior {
    Unknown,
    RemovedInVersion,
    /// `notifications/initialized` (2025) — init ordering only.
    Initialized,
    /// `notifications/cancelled` — correlation only (either revision,
    /// either direction except the 2026 S2C subscription-cancel).
    Cancel,
    /// 2026 S2C `notifications/cancelled` — must reference a live
    /// subscription id.
    CancelSubscription,
    /// `notifications/progress` — progressToken correlation only.
    Progress,
    /// Allow atom required; `cap` also checked when `Some`.
    Rule {
        cap: Option<&'static str>,
    },
    /// Capability-only gate (2025 `tools/list_changed`).
    CapGate {
        cap: &'static str,
    },
    /// `notifications/resources/updated` (2025): rule + `resources.subscribe`
    /// capability + URI in the client's subscription set.
    ResourceUpdated,
    /// `notifications/message` (2025): rule + `logging` cap + level.
    LogMessage25,
    /// `notifications/message` (2026): rule + request correlation + level.
    LogMessage26,
    /// `notifications/elicitation/complete` (2025): rule + pending elicitation.
    ElicitationComplete,
    /// 2026 subscription notification gated on an acknowledged filter.
    SubNotify {
        filter: SubscriptionFilter,
    },
    /// `notifications/subscriptions/acknowledged` (2026).
    SubscriptionAck,
}

fn notification_behavior(
    v: SupportedProtocolVersion,
    d: MessageDirection,
    m: &str,
) -> NotificationBehavior {
    use NotificationBehavior::*;
    match (v, d) {
        (SupportedProtocolVersion::Mcp2025November25, MessageDirection::ClientToServer) => {
            match m {
                "notifications/initialized" => Initialized,
                "notifications/cancelled" => Cancel,
                "notifications/progress" => Progress,
                "notifications/roots/list_changed" => Rule {
                    cap: Some("roots.listChanged"),
                },
                _ => Unknown,
            }
        }
        (SupportedProtocolVersion::Mcp2025November25, MessageDirection::ServerToClient) => {
            match m {
                "notifications/cancelled" => Cancel,
                "notifications/progress" => Progress,
                "notifications/message" => LogMessage25,
                "notifications/tools/list_changed" => CapGate {
                    cap: "tools.listChanged",
                },
                "notifications/resources/list_changed" => Rule {
                    cap: Some("resources.listChanged"),
                },
                "notifications/prompts/list_changed" => Rule {
                    cap: Some("prompts.listChanged"),
                },
                "notifications/resources/updated" => ResourceUpdated,
                "notifications/elicitation/complete" => ElicitationComplete,
                _ => Unknown,
            }
        }
        (SupportedProtocolVersion::Mcp2026July28, MessageDirection::ClientToServer) => match m {
            "notifications/cancelled" => Cancel,
            "notifications/initialized"
            | "notifications/roots/list_changed"
            | "notifications/elicitation/complete" => RemovedInVersion,
            _ => Unknown,
        },
        (SupportedProtocolVersion::Mcp2026July28, MessageDirection::ServerToClient) => match m {
            "notifications/cancelled" => CancelSubscription,
            "notifications/progress" => Progress,
            "notifications/message" => LogMessage26,
            "notifications/subscriptions/acknowledged" => SubscriptionAck,
            "notifications/tools/list_changed" => SubNotify {
                filter: SubscriptionFilter::ToolsListChanged,
            },
            "notifications/prompts/list_changed" => SubNotify {
                filter: SubscriptionFilter::PromptsListChanged,
            },
            "notifications/resources/list_changed" => SubNotify {
                filter: SubscriptionFilter::ResourcesListChanged,
            },
            "notifications/resources/updated" => SubNotify {
                filter: SubscriptionFilter::ResourceSubscriptions,
            },
            "notifications/initialized"
            | "notifications/roots/list_changed"
            | "notifications/elicitation/complete" => RemovedInVersion,
            _ => Unknown,
        },
    }
}

/// `resultType` values 2026-07-28 defines.
const RESULT_TYPE_COMPLETE: &str = "complete";
const RESULT_TYPE_INPUT_REQUIRED: &str = "input_required";

/// Methods whose results are `CacheableResult` under 2026-07-28 —
/// `ttlMs` and `cacheScope` are then required members.
const CACHEABLE_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    "tools/call",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "prompts/list",
    "prompts/get",
];

/// Methods a 2026 `input_required` interim result may answer.
const INPUT_REQUIRED_METHODS: &[&str] = &["tools/call", "resources/read", "prompts/get"];

/// The additional-request method allowed for an MRTR capability.
fn additional_request_capability(method: &str) -> Option<&'static str> {
    match method {
        "elicitation/create" => Some("elicitation"),
        "sampling/createMessage" => Some("sampling"),
        "roots/list" => Some("roots"),
        _ => None,
    }
}

// ── The decision ──────────────────────────────────────────────────────

impl ServerMcpRules {
    /// Pre-resolved atom view of this server's rules (deny-sticky).
    pub fn resolved(&self) -> &RuleMap {
        &self.resolved
    }

    /// Decide one message. `msg` carries pre-extracted leaf facts; `facts`
    /// carries Auditor tracking state. Pure — performs no I/O.
    pub fn decide(&self, msg: &TrafficMessage<'_>, facts: &SessionFacts<'_>) -> McpVerdict {
        let rules = self.resolved();
        match msg {
            TrafficMessage::Request(m) => decide_request(rules, m, facts),
            TrafficMessage::Notification(m) => decide_notification(rules, m, facts),
            TrafficMessage::AdditionalRequest(m) => decide_additional(rules, m),
            TrafficMessage::Response(m) => decide_response(rules, m),
        }
    }
}

fn rule_atom<'a>(
    rules: &'a RuleMap,
    version: SupportedProtocolVersion,
    direction: MessageDirection,
    kind: RuleKind,
    method: &str,
) -> Option<&'a ResolvedRule> {
    rules.get(&RuleKey {
        version,
        direction,
        kind,
        method: ledger_name(method)?,
    })
}

/// Filters the `subscriptions/listen` allow atoms grant, plus the URIs of
/// the `resourceSubscriptions` filter. `toolsListChanged` is free.
fn allowed_listen_filters(rules: &RuleMap) -> (BTreeSet<SubscriptionFilter>, BTreeSet<String>) {
    let mut filters = BTreeSet::from([SubscriptionFilter::ToolsListChanged]);
    let mut uris = BTreeSet::new();
    for (key, rule) in rules {
        if key.version == V26
            && key.direction == C2S
            && key.kind == RuleKind::Request
            && key.method == "subscriptions/listen"
            && rule.effect == RuleEffect::Allow
        {
            filters.extend(rule.filters.iter().copied());
            uris.extend(rule.uris.iter().cloned());
        }
    }
    (filters, uris)
}

fn has_capability(capabilities: &[String], cap: &str) -> bool {
    capabilities.iter().any(|c| c == cap)
}

fn meta_check(meta: Option<&RequestMeta>) -> Result<(), DenyReason> {
    let meta = meta.ok_or(DenyReason::MetaMissing)?;
    if meta.malformed {
        return Err(DenyReason::MetaMalformed);
    }
    match meta.protocol_version.as_deref() {
        Some(crate::protocol::MCP_VERSION_2026_07_28) => {}
        _ => return Err(DenyReason::MetaVersion),
    }
    match meta.client_capabilities_shape {
        SchemaField::Valid => Ok(()),
        SchemaField::Absent => Err(DenyReason::MetaMissing),
        SchemaField::Invalid => Err(DenyReason::MetaMalformed),
    }
}

fn decide_request(rules: &RuleMap, m: &RequestMessage<'_>, facts: &SessionFacts<'_>) -> McpVerdict {
    let behavior = request_behavior(m.version, m.direction, m.method);
    match behavior {
        RequestBehavior::Unknown => return McpVerdict::Deny(DenyReason::UnknownMethod),
        RequestBehavior::RemovedInVersion => return McpVerdict::Deny(DenyReason::VersionRemoved),
        RequestBehavior::IllegalDirection => {
            return McpVerdict::Deny(DenyReason::VersionDirection);
        }
        _ => {}
    }

    // A deny atom always wins — even on protocol machinery.
    let atom = rule_atom(rules, m.version, m.direction, RuleKind::Request, m.method);
    if atom.is_some_and(|r| r.effect == RuleEffect::Deny) {
        return McpVerdict::Deny(DenyReason::RuleDeny);
    }

    match m.version {
        SupportedProtocolVersion::Mcp2026July28 => {
            if let Err(reason) = meta_check(m.meta) {
                return McpVerdict::Deny(reason);
            }
        }
        SupportedProtocolVersion::Mcp2025November25 => {
            // Lifecycle ordering: before `initialize` answers, only
            // `initialize` and `ping` may travel C2S; server→client
            // requests are `ping`-only until the session is operational.
            match m.method {
                "initialize" => {
                    if facts.init != InitStage::PendingInitialize {
                        return McpVerdict::Deny(DenyReason::InitOrder);
                    }
                }
                "ping" => {}
                _ => {
                    if facts.init == InitStage::PendingInitialize {
                        return McpVerdict::Deny(DenyReason::InitOrder);
                    }
                    if m.direction == MessageDirection::ServerToClient
                        && facts.init != InitStage::Operational
                    {
                        return McpVerdict::Deny(DenyReason::InitOrder);
                    }
                }
            }
        }
    }

    match behavior {
        RequestBehavior::Initialize => {
            let complete = m.params.map(|p| p.initialize.complete()).unwrap_or(false);
            if complete {
                McpVerdict::Allow(AllowReason::ProtocolPass)
            } else {
                McpVerdict::Deny(DenyReason::Shape)
            }
        }
        RequestBehavior::ProtocolPass => McpVerdict::Allow(AllowReason::ProtocolPass),
        RequestBehavior::Rule { cap } => {
            if atom.is_none() {
                return McpVerdict::Deny(DenyReason::NoRule);
            }
            if let Some(cap) = cap {
                let caps = match m.direction {
                    MessageDirection::ClientToServer => facts.server_capabilities,
                    MessageDirection::ServerToClient => facts.client_capabilities,
                };
                if !has_capability(caps, cap) {
                    return McpVerdict::Deny(DenyReason::Capability);
                }
            }
            McpVerdict::Allow(AllowReason::RuleAllow)
        }
        RequestBehavior::RuleUri { cap } => {
            let Some(rule) = atom else {
                return McpVerdict::Deny(DenyReason::NoRule);
            };
            if let Some(cap) = cap
                && !has_capability(facts.server_capabilities, cap)
            {
                return McpVerdict::Deny(DenyReason::Capability);
            }
            let Some(uri) = m.params.and_then(|p| p.uri) else {
                return McpVerdict::Deny(DenyReason::Shape);
            };
            if !rule.uris.iter().any(|u| u == uri) {
                return McpVerdict::Deny(DenyReason::UriNotAllowed);
            }
            McpVerdict::Allow(AllowReason::RuleAllow)
        }
        RequestBehavior::ResourceSubscribe { unsubscribe } => {
            let Some(rule) = atom else {
                return McpVerdict::Deny(DenyReason::NoRule);
            };
            if !has_capability(facts.server_capabilities, "resources.subscribe") {
                return McpVerdict::Deny(DenyReason::Capability);
            }
            let Some(uri) = m.params.and_then(|p| p.uri) else {
                return McpVerdict::Deny(DenyReason::Shape);
            };
            if unsubscribe {
                // Unsubscribing needs a live subscription, not a rule range.
                if !facts.resource_subscriptions.iter().any(|u| u == uri) {
                    return McpVerdict::Deny(DenyReason::Uncorrelated);
                }
            } else if !rule.uris.iter().any(|u| u == uri) {
                return McpVerdict::Deny(DenyReason::UriNotAllowed);
            }
            McpVerdict::Allow(AllowReason::RuleAllow)
        }
        RequestBehavior::SubscriptionListen => {
            let Some(filters) = m.params.and_then(|p| p.notifications) else {
                return McpVerdict::Deny(DenyReason::Shape);
            };
            if !filters.unknown.is_empty() {
                return McpVerdict::Deny(DenyReason::FilterUnknown);
            }
            let (allowed_filters, allowed_uris) = allowed_listen_filters(rules);
            for f in filters.enabled() {
                if f == SubscriptionFilter::ResourceSubscriptions {
                    continue;
                }
                if !allowed_filters.contains(&f) {
                    return McpVerdict::Deny(DenyReason::FilterNotAllowed);
                }
            }
            if let Some(uris) = filters.resource_subscriptions.as_ref() {
                if !allowed_filters.contains(&SubscriptionFilter::ResourceSubscriptions) {
                    return McpVerdict::Deny(DenyReason::FilterNotAllowed);
                }
                if uris.iter().any(|u| !allowed_uris.contains(u)) {
                    return McpVerdict::Deny(DenyReason::UriNotAllowed);
                }
            }
            McpVerdict::Allow(if filters.only_free_filters() && atom.is_none() {
                AllowReason::ProtocolPass
            } else {
                AllowReason::RuleAllow
            })
        }
        RequestBehavior::LogLevelSet => {
            if atom.is_none() {
                return McpVerdict::Deny(DenyReason::NoRule);
            }
            match m.params.and_then(|p| p.level) {
                Some(level) if rfc5424_rank(level).is_some() => {
                    McpVerdict::Allow(AllowReason::RuleAllow)
                }
                _ => McpVerdict::Deny(DenyReason::Shape),
            }
        }
        RequestBehavior::Unknown
        | RequestBehavior::RemovedInVersion
        | RequestBehavior::IllegalDirection => unreachable!("handled above"),
    }
}

fn decide_notification(
    rules: &RuleMap,
    m: &NotificationMessage<'_>,
    facts: &SessionFacts<'_>,
) -> McpVerdict {
    let behavior = notification_behavior(m.version, m.direction, m.method);
    match behavior {
        NotificationBehavior::Unknown => return McpVerdict::Drop(DropReason::UnknownMethod),
        NotificationBehavior::RemovedInVersion => {
            return McpVerdict::Drop(DropReason::VersionRemoved);
        }
        _ => {}
    }

    let atom = rule_atom(
        rules,
        m.version,
        m.direction,
        RuleKind::Notification,
        m.method,
    );
    if atom.is_some_and(|r| r.effect == RuleEffect::Deny) {
        return McpVerdict::Drop(DropReason::RuleDeny);
    }

    match behavior {
        NotificationBehavior::Initialized => {
            if facts.init == InitStage::AwaitingInitialized {
                McpVerdict::Allow(AllowReason::ProtocolPass)
            } else {
                McpVerdict::Drop(DropReason::InitOrder)
            }
        }
        NotificationBehavior::Cancel => match m.cancel_target {
            CancelFacts::OwnedRequest => McpVerdict::Allow(AllowReason::ProtocolPass),
            _ => McpVerdict::Drop(DropReason::Uncorrelated),
        },
        NotificationBehavior::CancelSubscription => match m.cancel_target {
            CancelFacts::Subscription => McpVerdict::Allow(AllowReason::ProtocolPass),
            _ => McpVerdict::Drop(DropReason::Uncorrelated),
        },
        NotificationBehavior::Progress => match m.progress {
            ProgressCorrelation::Matched => McpVerdict::Allow(AllowReason::ProtocolPass),
            ProgressCorrelation::Unmatched => McpVerdict::Drop(DropReason::Uncorrelated),
        },
        NotificationBehavior::Rule { cap } => {
            if atom.is_none() {
                return McpVerdict::Drop(DropReason::NoRule);
            }
            if let Some(cap) = cap {
                let caps = match m.direction {
                    MessageDirection::ClientToServer => facts.client_capabilities,
                    MessageDirection::ServerToClient => facts.server_capabilities,
                };
                if !has_capability(caps, cap) {
                    return McpVerdict::Drop(DropReason::Capability);
                }
            }
            McpVerdict::Allow(AllowReason::RuleAllow)
        }
        NotificationBehavior::CapGate { cap } => {
            if has_capability(facts.server_capabilities, cap) {
                McpVerdict::Allow(AllowReason::ProtocolPass)
            } else {
                McpVerdict::Drop(DropReason::Capability)
            }
        }
        NotificationBehavior::ResourceUpdated => {
            if atom.is_none() {
                return McpVerdict::Drop(DropReason::NoRule);
            }
            if !has_capability(facts.server_capabilities, "resources.subscribe") {
                return McpVerdict::Drop(DropReason::Capability);
            }
            let Some(uri) = m.uri else {
                return McpVerdict::Drop(DropReason::Shape);
            };
            if !facts.resource_subscriptions.iter().any(|u| u == uri) {
                return McpVerdict::Drop(DropReason::Uncorrelated);
            }
            McpVerdict::Allow(AllowReason::RuleAllow)
        }
        NotificationBehavior::LogMessage25 => {
            if atom.is_none() {
                return McpVerdict::Drop(DropReason::NoRule);
            }
            if !has_capability(facts.server_capabilities, "logging") {
                return McpVerdict::Drop(DropReason::Capability);
            }
            log_level_gate(m.level, facts.log_level)
        }
        NotificationBehavior::LogMessage26 => {
            if atom.is_none() {
                return McpVerdict::Drop(DropReason::NoRule);
            }
            let Some(corr) = m.message_for else {
                return McpVerdict::Drop(DropReason::Uncorrelated);
            };
            let Some(requested) = corr.log_level else {
                return McpVerdict::Drop(DropReason::Uncorrelated);
            };
            log_level_gate(m.level, Some(requested))
        }
        NotificationBehavior::ElicitationComplete => {
            if atom.is_none() {
                return McpVerdict::Drop(DropReason::NoRule);
            }
            if !facts.elicitation_pending {
                return McpVerdict::Drop(DropReason::Uncorrelated);
            }
            McpVerdict::Allow(AllowReason::RuleAllow)
        }
        NotificationBehavior::SubNotify { filter } => {
            let Some(sub) = &m.subscription else {
                return McpVerdict::Drop(DropReason::Uncorrelated);
            };
            if sub.state != SubscriptionState::Active {
                return McpVerdict::Drop(DropReason::SubscriptionState);
            }
            if !sub.acked.contains(&filter) {
                return McpVerdict::Drop(DropReason::FilterNotAllowed);
            }
            if filter == SubscriptionFilter::ResourceSubscriptions {
                let Some(uri) = m.uri else {
                    return McpVerdict::Drop(DropReason::Shape);
                };
                if !sub.acked_uris.iter().any(|u| u == uri) {
                    return McpVerdict::Drop(DropReason::UriNotAllowed);
                }
            }
            McpVerdict::Allow(AllowReason::SubscriptionMatched)
        }
        NotificationBehavior::SubscriptionAck => {
            let Some(sub) = &m.subscription else {
                return McpVerdict::Drop(DropReason::Uncorrelated);
            };
            if sub.state != SubscriptionState::PendingAck {
                return McpVerdict::Drop(DropReason::SubscriptionState);
            }
            let Some(ack) = m.ack_filters else {
                return McpVerdict::Drop(DropReason::Shape);
            };
            if !ack.unknown.is_empty() {
                return McpVerdict::Drop(DropReason::FilterUnknown);
            }
            let requested = sub.requested.enabled();
            let (allowed_filters, allowed_uris) = allowed_listen_filters(rules);
            for f in ack.enabled() {
                if !requested.contains(&f) {
                    // Server acked a filter the client never asked for.
                    return McpVerdict::Drop(DropReason::Uncorrelated);
                }
                if !allowed_filters.contains(&f) {
                    return McpVerdict::Drop(DropReason::FilterNotAllowed);
                }
            }
            if let Some(uris) = ack.resource_subscriptions.as_ref() {
                let requested_uris = sub
                    .requested
                    .resource_subscriptions
                    .as_deref()
                    .unwrap_or(&[]);
                for uri in uris {
                    if !requested_uris.iter().any(|u| u == uri) {
                        return McpVerdict::Drop(DropReason::Uncorrelated);
                    }
                    if !allowed_uris.contains(uri) {
                        return McpVerdict::Drop(DropReason::UriNotAllowed);
                    }
                }
            }
            McpVerdict::Allow(AllowReason::SubscriptionMatched)
        }
        NotificationBehavior::Unknown | NotificationBehavior::RemovedInVersion => {
            unreachable!("handled above")
        }
    }
}

/// Log-level gate shared by the 2025 session threshold and the 2026
/// per-request threshold paths.
fn log_level_gate(message_level: Option<&str>, requested: Option<&str>) -> McpVerdict {
    let Some(level) = message_level else {
        return McpVerdict::Drop(DropReason::Shape);
    };
    let Some(msg_rank) = rfc5424_rank(level) else {
        return McpVerdict::Drop(DropReason::Shape);
    };
    if let Some(req) = requested {
        match rfc5424_rank(req) {
            Some(req_rank) if msg_rank >= req_rank => {}
            _ => return McpVerdict::Drop(DropReason::LevelRange),
        }
    }
    McpVerdict::Allow(AllowReason::RuleAllow)
}

fn decide_additional(rules: &RuleMap, m: &AdditionalRequestMessage<'_>) -> McpVerdict {
    if m.version != SupportedProtocolVersion::Mcp2026July28 {
        return McpVerdict::Deny(DenyReason::VersionDirection);
    }
    let Some(cap) = additional_request_capability(m.method) else {
        return McpVerdict::Deny(DenyReason::UnknownMethod);
    };

    let atom = rule_atom(rules, V26, S2C, RuleKind::AdditionalRequest, m.method);
    if atom.is_some_and(|r| r.effect == RuleEffect::Deny) {
        return McpVerdict::Deny(DenyReason::RuleDeny);
    }

    if !m.original.allowed || !INPUT_REQUIRED_METHODS.contains(&m.original.method) {
        return McpVerdict::Deny(DenyReason::InputRequiredTarget);
    }
    if !has_capability(m.original.client_capabilities, cap) {
        return McpVerdict::Deny(DenyReason::Capability);
    }
    if atom.is_none() {
        return McpVerdict::Deny(DenyReason::NoRule);
    }
    McpVerdict::Allow(AllowReason::RuleAllow)
}

fn decide_response(_rules: &RuleMap, m: &ResponseMessage<'_>) -> McpVerdict {
    // 2026-07-28 has no client→server request frames, hence no
    // client→server responses either.
    if m.version == SupportedProtocolVersion::Mcp2026July28
        && m.direction == MessageDirection::ClientToServer
    {
        return McpVerdict::Deny(DenyReason::VersionDirection);
    }

    let Some(answered) = m.answered else {
        return McpVerdict::Deny(DenyReason::Uncorrelated);
    };
    if answered.request_direction == m.direction {
        return McpVerdict::Deny(DenyReason::Uncorrelated);
    }
    // A request denied at pass time never reached the peer — a response
    // claiming to answer it cannot be a genuine completion.
    if !answered.allowed {
        return McpVerdict::Deny(DenyReason::Uncorrelated);
    }

    // JSON-RPC allows exactly one of `result` / `error` — a frame with
    // both or neither is malformed, not a completion.
    if m.is_error == m.has_result {
        return McpVerdict::Deny(DenyReason::Shape);
    }

    // JSON-RPC errors are regular completions — every tracked request may
    // resolve with one.
    if m.is_error {
        return McpVerdict::Allow(AllowReason::ProtocolPass);
    }

    match m.version {
        // `resultType` and `inputRequests` are 2026-07-28 inventions —
        // either on a 2025-11-25 result is an undefined extension for
        // that revision.
        SupportedProtocolVersion::Mcp2025November25 => {
            if m.result_type.is_some() || m.input_requests {
                McpVerdict::Deny(DenyReason::ResultType)
            } else {
                McpVerdict::Allow(AllowReason::ProtocolPass)
            }
        }
        SupportedProtocolVersion::Mcp2026July28 => match m.result_type {
            Some(RESULT_TYPE_COMPLETE) => {
                if m.input_requests {
                    return McpVerdict::Deny(DenyReason::ResultType);
                }
                if CACHEABLE_METHODS.contains(&answered.method)
                    && (m.ttl_ms != SchemaField::Valid || m.cache_scope != SchemaField::Valid)
                {
                    return McpVerdict::Deny(DenyReason::CacheFields);
                }
                McpVerdict::Allow(AllowReason::ProtocolPass)
            }
            Some(RESULT_TYPE_INPUT_REQUIRED) => {
                if !INPUT_REQUIRED_METHODS.contains(&answered.method) {
                    return McpVerdict::Deny(DenyReason::InputRequiredTarget);
                }
                McpVerdict::Undecided(UndecidedReason::InputRequired)
            }
            _ => McpVerdict::Deny(DenyReason::ResultType),
        },
    }
}

// ── Policy integration ────────────────────────────────────────────────

impl Policy {
    /// Decide one message against the bound server's `mcp` rules.
    ///
    /// Callers must have already selected a server ([`Policy::bind_to_server`]):
    /// with zero or several [`ServerMcpRules`] entries the decision runs on
    /// an empty rule set — the fail-closed default profile.
    pub fn decide_mcp(&self, msg: &TrafficMessage<'_>, facts: &SessionFacts<'_>) -> McpVerdict {
        static EMPTY: ServerMcpRules = ServerMcpRules {
            server_name: None,
            rules: Vec::new(),
            resolved: BTreeMap::new(),
        };
        let rules = if self.mcp_rules.len() == 1 {
            &self.mcp_rules[0]
        } else {
            &EMPTY
        };
        rules.decide(msg, facts)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::MCP_VERSION_2026_07_28;
    use crate::protocol::fields::SubscriptionFilter as SF;

    // ── builders ──

    fn rule(effect: RuleEffect, method: &str) -> McpRule {
        McpRule {
            effect,
            method: method.to_string(),
            versions: Vec::new(),
            direction: None,
            uris: Vec::new(),
            filters: Vec::new(),
        }
    }

    fn allow(method: &str) -> McpRule {
        rule(RuleEffect::Allow, method)
    }

    fn deny(method: &str) -> McpRule {
        rule(RuleEffect::Deny, method)
    }

    fn rules(rs: Vec<McpRule>) -> ServerMcpRules {
        ServerMcpRules::new(Some("srv".to_string()), rs)
    }

    fn facts() -> SessionFacts<'static> {
        SessionFacts {
            init: InitStage::Operational,
            ..SessionFacts::default()
        }
    }

    fn meta26() -> RequestMeta {
        RequestMeta {
            malformed: false,
            protocol_version: Some(MCP_VERSION_2026_07_28.to_string()),
            client_capabilities_shape: SchemaField::Valid,
            client_capabilities: Vec::new(),
            log_level: None,
            subscription_id: None,
        }
    }

    fn req<'a>(
        v: SupportedProtocolVersion,
        d: MessageDirection,
        method: &'a str,
        meta: Option<&'a RequestMeta>,
        params: Option<&'a RequestParams<'a>>,
    ) -> TrafficMessage<'a> {
        TrafficMessage::Request(RequestMessage {
            version: v,
            direction: d,
            method,
            meta,
            params,
        })
    }

    fn req26(r: &ServerMcpRules, f: &SessionFacts, method: &str) -> McpVerdict {
        let meta = meta26();
        let params = RequestParams::default();
        r.decide(&req(V26, C2S, method, Some(&meta), Some(&params)), f)
    }

    fn notif<'a>(
        v: SupportedProtocolVersion,
        d: MessageDirection,
        method: &'a str,
    ) -> NotificationMessage<'a> {
        NotificationMessage {
            version: v,
            direction: d,
            method,
            uri: None,
            level: None,
            ack_filters: None,
            cancel_target: CancelFacts::Unrelated,
            progress: ProgressCorrelation::Unmatched,
            message_for: None,
            subscription: None,
        }
    }

    fn resp<'a>(
        v: SupportedProtocolVersion,
        d: MessageDirection,
        answered_method: &'a str,
    ) -> ResponseMessage<'a> {
        ResponseMessage {
            version: v,
            direction: d,
            is_error: false,
            has_result: true,
            result_type: None,
            ttl_ms: SchemaField::Absent,
            cache_scope: SchemaField::Absent,
            input_requests: false,
            answered: Some(AnsweredFacts {
                request_direction: match d {
                    C2S => S2C,
                    S2C => C2S,
                },
                method: answered_method,
                allowed: true,
            }),
        }
    }

    const A_PROTOCOL: McpVerdict = McpVerdict::Allow(AllowReason::ProtocolPass);
    const A_RULE: McpVerdict = McpVerdict::Allow(AllowReason::RuleAllow);
    const A_SUB: McpVerdict = McpVerdict::Allow(AllowReason::SubscriptionMatched);

    // ── 2026-07-28 requests (C2S) ──

    #[test]
    fn v26_protocol_requests_pass_without_rules() {
        let r = rules(vec![]);
        let f = facts();
        for m in ["server/discover", "tools/list", "tools/call"] {
            assert_eq!(req26(&r, &f, m), A_PROTOCOL, "{m}");
        }
    }

    #[test]
    fn v26_removed_methods_deny() {
        let r = rules(vec![]);
        let f = facts();
        for m in [
            "initialize",
            "ping",
            "logging/setLevel",
            "resources/subscribe",
            "resources/unsubscribe",
        ] {
            assert_eq!(
                req26(&r, &f, m),
                McpVerdict::Deny(DenyReason::VersionRemoved),
                "{m}"
            );
        }
    }

    #[test]
    fn v26_explicit_rule_methods() {
        let f = facts();
        let bare = rules(vec![]);
        for m in [
            "resources/list",
            "resources/templates/list",
            "resources/read",
            "prompts/list",
            "prompts/get",
            "completion/complete",
        ] {
            assert_eq!(
                req26(&bare, &f, m),
                McpVerdict::Deny(DenyReason::NoRule),
                "{m} without rule"
            );
        }
        let with = rules(vec![
            allow("resources/list"),
            allow("prompts/get"),
            allow("completion/complete"),
            deny("resources/templates/list"),
        ]);
        assert_eq!(req26(&with, &f, "resources/list"), A_RULE);
        assert_eq!(req26(&with, &f, "prompts/get"), A_RULE);
        assert_eq!(req26(&with, &f, "completion/complete"), A_RULE);
        assert_eq!(
            req26(&with, &f, "resources/templates/list"),
            McpVerdict::Deny(DenyReason::RuleDeny)
        );
        // A deny rule denies even protocol machinery.
        let d = rules(vec![deny("tools/list")]);
        assert_eq!(
            req26(&d, &f, "tools/list"),
            McpVerdict::Deny(DenyReason::RuleDeny)
        );
    }

    #[test]
    fn v26_resources_read_uri_gate() {
        let f = facts();
        let mut read = allow("resources/read");
        read.uris = vec!["file:///docs/a".to_string()];
        let r = rules(vec![read]);
        let meta = meta26();

        let params = RequestParams {
            uri: Some("file:///docs/a"),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(
                &req(V26, C2S, "resources/read", Some(&meta), Some(&params)),
                &f
            ),
            A_RULE
        );

        let params = RequestParams {
            uri: Some("file:///etc/passwd"),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(
                &req(V26, C2S, "resources/read", Some(&meta), Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::UriNotAllowed)
        );

        let params = RequestParams::default();
        assert_eq!(
            r.decide(
                &req(V26, C2S, "resources/read", Some(&meta), Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::Shape)
        );
    }

    #[test]
    fn v26_meta_is_mandatory() {
        let r = rules(vec![]);
        let f = facts();
        let params = RequestParams::default();
        // No _meta at all.
        assert_eq!(
            r.decide(&req(V26, C2S, "tools/list", None, Some(&params)), &f),
            McpVerdict::Deny(DenyReason::MetaMissing)
        );
        // Wrong declared version.
        let meta = RequestMeta {
            protocol_version: Some("2026-08-01".to_string()),
            ..meta26()
        };
        assert_eq!(
            r.decide(&req(V26, C2S, "tools/list", Some(&meta), Some(&params)), &f),
            McpVerdict::Deny(DenyReason::MetaVersion)
        );
        // Missing clientCapabilities member.
        let meta = RequestMeta {
            client_capabilities_shape: SchemaField::Absent,
            ..meta26()
        };
        assert_eq!(
            r.decide(&req(V26, C2S, "tools/list", Some(&meta), Some(&params)), &f),
            McpVerdict::Deny(DenyReason::MetaMissing)
        );
        // Present-but-malformed members deny differently than missing ones.
        let meta = RequestMeta {
            malformed: true,
            ..meta26()
        };
        assert_eq!(
            r.decide(&req(V26, C2S, "tools/list", Some(&meta), Some(&params)), &f),
            McpVerdict::Deny(DenyReason::MetaMalformed)
        );
        let meta = RequestMeta {
            client_capabilities_shape: SchemaField::Invalid,
            ..meta26()
        };
        assert_eq!(
            r.decide(&req(V26, C2S, "tools/list", Some(&meta), Some(&params)), &f),
            McpVerdict::Deny(DenyReason::MetaMalformed)
        );
    }

    #[test]
    fn v26_no_s2c_requests() {
        let r = rules(vec![allow("elicitation/create")]);
        let f = facts();
        for m in ["elicitation/create", "ping", "exotic/thing"] {
            assert_eq!(
                r.decide(&req(V26, S2C, m, None, None), &f),
                McpVerdict::Deny(DenyReason::VersionDirection),
                "{m}"
            );
        }
    }

    #[test]
    fn v26_subscriptions_listen_gates() {
        let f = facts();
        let meta = meta26();

        // toolsListChanged only → free.
        let filters = ListenFilters {
            tools_list_changed: Some(true),
            ..ListenFilters::default()
        };
        let params = RequestParams {
            notifications: Some(&filters),
            ..RequestParams::default()
        };
        let bare = rules(vec![]);
        assert_eq!(
            bare.decide(
                &req(V26, C2S, "subscriptions/listen", Some(&meta), Some(&params)),
                &f
            ),
            A_PROTOCOL
        );

        // promptsListChanged needs a rule filter.
        let filters = ListenFilters {
            prompts_list_changed: Some(true),
            ..ListenFilters::default()
        };
        let params = RequestParams {
            notifications: Some(&filters),
            ..RequestParams::default()
        };
        assert_eq!(
            bare.decide(
                &req(V26, C2S, "subscriptions/listen", Some(&meta), Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::FilterNotAllowed)
        );

        // Unknown filter member fails closed.
        let filters = ListenFilters {
            unknown: vec!["exoticFilter".to_string()],
            ..ListenFilters::default()
        };
        let params = RequestParams {
            notifications: Some(&filters),
            ..RequestParams::default()
        };
        assert_eq!(
            bare.decide(
                &req(V26, C2S, "subscriptions/listen", Some(&meta), Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::FilterUnknown)
        );

        // Rule-granted filters and URIs pass.
        let mut lr = allow("subscriptions/listen");
        lr.filters = vec![SF::PromptsListChanged, SF::ResourceSubscriptions];
        lr.uris = vec!["file:///a".to_string()];
        let r = rules(vec![lr]);
        let filters = ListenFilters {
            prompts_list_changed: Some(true),
            resource_subscriptions: Some(vec!["file:///a".to_string()]),
            ..ListenFilters::default()
        };
        let params = RequestParams {
            notifications: Some(&filters),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(
                &req(V26, C2S, "subscriptions/listen", Some(&meta), Some(&params)),
                &f
            ),
            A_RULE
        );

        // URI outside the rule set → deny.
        let filters = ListenFilters {
            resource_subscriptions: Some(vec!["file:///b".to_string()]),
            ..ListenFilters::default()
        };
        let params = RequestParams {
            notifications: Some(&filters),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(
                &req(V26, C2S, "subscriptions/listen", Some(&meta), Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::UriNotAllowed)
        );

        // A deny rule blocks even a free-filter listen.
        let d = rules(vec![deny("subscriptions/listen")]);
        let filters = ListenFilters {
            tools_list_changed: Some(true),
            ..ListenFilters::default()
        };
        let params = RequestParams {
            notifications: Some(&filters),
            ..RequestParams::default()
        };
        assert_eq!(
            d.decide(
                &req(V26, C2S, "subscriptions/listen", Some(&meta), Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::RuleDeny)
        );
    }

    // ── 2025-11-25 requests ──

    #[test]
    fn v25_init_ordering() {
        let r = rules(vec![allow("resources/list")]);
        let mut f = facts();
        let params = RequestParams::default();

        // Before initialize answers: initialize + ping only.
        f.init = InitStage::PendingInitialize;
        assert_eq!(
            r.decide(&req(V25, C2S, "tools/call", None, Some(&params)), &f),
            McpVerdict::Deny(DenyReason::InitOrder)
        );
        assert_eq!(r.decide(&req(V25, C2S, "ping", None, None), &f), A_PROTOCOL);
        let init_params = RequestParams {
            initialize: InitializeShape {
                has_protocol_version: true,
                has_capabilities: true,
                has_client_info: true,
            },
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(&req(V25, C2S, "initialize", None, Some(&init_params)), &f),
            A_PROTOCOL
        );
        // Malformed initialize params.
        assert_eq!(
            r.decide(&req(V25, C2S, "initialize", None, Some(&params)), &f),
            McpVerdict::Deny(DenyReason::Shape)
        );

        // After initialize answered, before initialized: C2S requests OK,
        // S2C requests still ping-only; a second initialize is denied.
        f.init = InitStage::AwaitingInitialized;
        assert_eq!(
            r.decide(&req(V25, C2S, "initialize", None, Some(&init_params)), &f),
            McpVerdict::Deny(DenyReason::InitOrder)
        );
        assert_eq!(
            r.decide(&req(V25, S2C, "sampling/createMessage", None, None), &f),
            McpVerdict::Deny(DenyReason::InitOrder)
        );
        assert_eq!(r.decide(&req(V25, S2C, "ping", None, None), &f), A_PROTOCOL);
        assert_eq!(
            r.decide(&req(V25, C2S, "tools/call", None, Some(&params)), &f),
            A_PROTOCOL
        );
    }

    #[test]
    fn v25_explicit_rules_need_capabilities() {
        let f = facts();
        let r = rules(vec![
            allow("resources/list"),
            allow("prompts/list"),
            allow("completion/complete"),
        ]);
        let params = RequestParams::default();
        // No negotiated server capabilities → capability deny.
        for m in ["resources/list", "prompts/list", "completion/complete"] {
            assert_eq!(
                r.decide(&req(V25, C2S, m, None, Some(&params)), &f),
                McpVerdict::Deny(DenyReason::Capability),
                "{m}"
            );
        }
        let caps = vec!["resources".to_string(), "prompts".to_string()];
        let f = SessionFacts {
            server_capabilities: &caps,
            ..facts()
        };
        assert_eq!(
            r.decide(&req(V25, C2S, "resources/list", None, Some(&params)), &f),
            A_RULE
        );
        assert_eq!(
            r.decide(&req(V25, C2S, "prompts/list", None, Some(&params)), &f),
            A_RULE
        );
        assert_eq!(
            r.decide(
                &req(V25, C2S, "completion/complete", None, Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::Capability)
        );
    }

    #[test]
    fn v25_resources_read_and_subscriptions() {
        let caps = vec!["resources".to_string(), "resources.subscribe".to_string()];
        let subs = vec!["file:///watched".to_string()];
        let f = SessionFacts {
            server_capabilities: &caps,
            resource_subscriptions: &subs,
            ..facts()
        };
        let mut read = allow("resources/read");
        read.uris = vec!["file:///docs/a".to_string()];
        let mut sub = allow("resources/subscribe");
        sub.uris = vec!["file:///watched".to_string()];
        let r = rules(vec![read, sub, allow("resources/unsubscribe")]);

        let params = RequestParams {
            uri: Some("file:///docs/a"),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(&req(V25, C2S, "resources/read", None, Some(&params)), &f),
            A_RULE
        );
        let params = RequestParams {
            uri: Some("file:///watched"),
            ..RequestParams::default()
        };
        // subscribe URI must be within the rule's uri set.
        assert_eq!(
            r.decide(
                &req(V25, C2S, "resources/subscribe", None, Some(&params)),
                &f
            ),
            A_RULE
        );
        // unsubscribe correlates with the live subscription, not the rule set.
        assert_eq!(
            r.decide(
                &req(V25, C2S, "resources/unsubscribe", None, Some(&params)),
                &f
            ),
            A_RULE
        );
        let params = RequestParams {
            uri: Some("file:///never-subscribed"),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(
                &req(V25, C2S, "resources/unsubscribe", None, Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::Uncorrelated)
        );
        assert_eq!(
            r.decide(
                &req(V25, C2S, "resources/subscribe", None, Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::UriNotAllowed)
        );
    }

    #[test]
    fn v25_s2c_requests_rules_and_caps() {
        let f = facts();
        let r = rules(vec![
            allow("sampling/createMessage"),
            allow("roots/list"),
            deny("elicitation/create"),
        ]);
        assert_eq!(
            r.decide(&req(V25, S2C, "sampling/createMessage", None, None), &f),
            McpVerdict::Deny(DenyReason::Capability)
        );
        assert_eq!(
            r.decide(&req(V25, S2C, "elicitation/create", None, None), &f),
            McpVerdict::Deny(DenyReason::RuleDeny)
        );
        assert_eq!(
            r.decide(&req(V25, S2C, "exotic/req", None, None), &f),
            McpVerdict::Deny(DenyReason::UnknownMethod)
        );
        let client_caps = vec!["sampling".to_string(), "roots".to_string()];
        let f = SessionFacts {
            client_capabilities: &client_caps,
            ..facts()
        };
        assert_eq!(
            r.decide(&req(V25, S2C, "sampling/createMessage", None, None), &f),
            A_RULE
        );
        assert_eq!(
            r.decide(&req(V25, S2C, "roots/list", None, None), &f),
            A_RULE
        );
    }

    #[test]
    fn v25_logging_set_level() {
        let f = facts();
        let r = rules(vec![allow("logging/setLevel")]);
        let params = RequestParams {
            level: Some("warning"),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(&req(V25, C2S, "logging/setLevel", None, Some(&params)), &f),
            A_RULE
        );
        let params = RequestParams {
            level: Some("chatty"),
            ..RequestParams::default()
        };
        assert_eq!(
            r.decide(&req(V25, C2S, "logging/setLevel", None, Some(&params)), &f),
            McpVerdict::Deny(DenyReason::Shape)
        );
        let bare = rules(vec![]);
        assert_eq!(
            bare.decide(&req(V25, C2S, "logging/setLevel", None, Some(&params)), &f),
            McpVerdict::Deny(DenyReason::NoRule)
        );
    }

    // ── notifications ──

    #[test]
    fn v25_notifications() {
        let r = rules(vec![
            allow("notifications/roots/list_changed"),
            allow("notifications/resources/list_changed"),
            deny("notifications/prompts/list_changed"),
        ]);
        let mut f = facts();
        f.init = InitStage::AwaitingInitialized;
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V25, C2S, "notifications/initialized")),
                &f
            ),
            A_PROTOCOL
        );
        f.init = InitStage::Operational;
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V25, C2S, "notifications/initialized")),
                &f
            ),
            McpVerdict::Drop(DropReason::InitOrder)
        );

        // cancelled correlates on tracked requests only.
        let mut n = notif(V25, C2S, "notifications/cancelled");
        n.cancel_target = CancelFacts::OwnedRequest;
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_PROTOCOL);
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V25, S2C, "notifications/cancelled")),
                &f
            ),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );

        // progress correlates on tracked tokens only.
        let mut n = notif(V25, S2C, "notifications/progress");
        n.progress = ProgressCorrelation::Matched;
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_PROTOCOL);

        // roots/list_changed: rule + client roots.listChanged capability.
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V25, C2S, "notifications/roots/list_changed")),
                &f
            ),
            McpVerdict::Drop(DropReason::Capability)
        );
        let client_caps = vec!["roots.listChanged".to_string()];
        let f2 = SessionFacts {
            client_capabilities: &client_caps,
            ..facts()
        };
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V25, C2S, "notifications/roots/list_changed")),
                &f2
            ),
            A_RULE
        );
        // Deny wins on notifications too.
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(
                    V25,
                    S2C,
                    "notifications/prompts/list_changed"
                )),
                &f2
            ),
            McpVerdict::Drop(DropReason::RuleDeny)
        );
        // Unknown notification drops.
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V25, S2C, "notifications/exotic")),
                &f2
            ),
            McpVerdict::Drop(DropReason::UnknownMethod)
        );
    }

    #[test]
    fn v25_server_notifications() {
        let caps = vec![
            "logging".to_string(),
            "tools.listChanged".to_string(),
            "resources.subscribe".to_string(),
        ];
        let subs = vec!["file:///watched".to_string()];
        let f = SessionFacts {
            server_capabilities: &caps,
            resource_subscriptions: &subs,
            log_level: Some("warning"),
            elicitation_pending: false,
            ..facts()
        };
        let r = rules(vec![
            allow("notifications/message"),
            allow("notifications/resources/updated"),
            allow("notifications/elicitation/complete"),
        ]);

        // tools/list_changed: capability-only gate.
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V25, S2C, "notifications/tools/list_changed")),
                &f
            ),
            A_PROTOCOL
        );

        // message: rule + logging cap + level >= threshold.
        let mut n = notif(V25, S2C, "notifications/message");
        n.level = Some("error");
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_RULE);
        let mut n = notif(V25, S2C, "notifications/message");
        n.level = Some("info");
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::LevelRange)
        );
        let mut n = notif(V25, S2C, "notifications/message");
        n.level = Some("chatty");
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::Shape)
        );

        // resources/updated needs a subscribed URI.
        let mut n = notif(V25, S2C, "notifications/resources/updated");
        n.uri = Some("file:///watched");
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_RULE);
        let mut n = notif(V25, S2C, "notifications/resources/updated");
        n.uri = Some("file:///other");
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );

        // elicitation/complete needs a pending elicitation request.
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(
                    V25,
                    S2C,
                    "notifications/elicitation/complete"
                )),
                &f
            ),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );
        let f2 = SessionFacts {
            elicitation_pending: true,
            ..f
        };
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(
                    V25,
                    S2C,
                    "notifications/elicitation/complete"
                )),
                &f2
            ),
            A_RULE
        );

        // resources/list_changed without negotiated capability.
        let r2 = rules(vec![allow("notifications/resources/list_changed")]);
        assert_eq!(
            r2.decide(
                &TrafficMessage::Notification(notif(
                    V25,
                    S2C,
                    "notifications/resources/list_changed"
                )),
                &f2
            ),
            McpVerdict::Drop(DropReason::Capability)
        );
    }

    #[test]
    fn v26_notifications() {
        let requested = ListenFilters {
            tools_list_changed: Some(true),
            prompts_list_changed: Some(true),
            ..ListenFilters::default()
        };
        let acked = [SF::ToolsListChanged, SF::PromptsListChanged];
        let f = facts();
        let r = rules(vec![allow("notifications/tools/list_changed")]);

        // Removed-in-2026 notifications drop.
        for m in [
            "notifications/initialized",
            "notifications/roots/list_changed",
            "notifications/elicitation/complete",
        ] {
            for d in [C2S, S2C] {
                assert_eq!(
                    r.decide(&TrafficMessage::Notification(notif(V26, d, m)), &f),
                    McpVerdict::Drop(DropReason::VersionRemoved),
                    "{m} {d}"
                );
            }
        }

        // C2S cancel correlates to a tracked request (incl. a listen).
        let mut n = notif(V26, C2S, "notifications/cancelled");
        n.cancel_target = CancelFacts::OwnedRequest;
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_PROTOCOL);
        // S2C cancel must reference a subscription.
        let mut n = notif(V26, S2C, "notifications/cancelled");
        n.cancel_target = CancelFacts::Subscription;
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_PROTOCOL);
        let mut n = notif(V26, S2C, "notifications/cancelled");
        n.cancel_target = CancelFacts::OwnedRequest;
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );

        // S2C progress correlates.
        let mut n = notif(V26, S2C, "notifications/progress");
        n.progress = ProgressCorrelation::Matched;
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_PROTOCOL);

        // list_changed notifications ride an active subscription.
        let sub = SubscriptionFacts {
            state: SubscriptionState::Active,
            requested: &requested,
            acked: &acked,
            acked_uris: &[],
        };
        let mut n = notif(V26, S2C, "notifications/tools/list_changed");
        n.subscription = Some(sub);
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_SUB);
        // PendingAck → drop; missing subscription → drop.
        let sub = SubscriptionFacts {
            state: SubscriptionState::PendingAck,
            requested: &requested,
            acked: &[],
            acked_uris: &[],
        };
        let mut n = notif(V26, S2C, "notifications/tools/list_changed");
        n.subscription = Some(sub);
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::SubscriptionState)
        );
        assert_eq!(
            r.decide(
                &TrafficMessage::Notification(notif(V26, S2C, "notifications/tools/list_changed")),
                &f
            ),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );
        // A notification for a filter never acknowledged drops.
        let sub = SubscriptionFacts {
            state: SubscriptionState::Active,
            requested: &requested,
            acked: &acked,
            acked_uris: &[],
        };
        let mut n = notif(V26, S2C, "notifications/resources/list_changed");
        n.subscription = Some(sub);
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::FilterNotAllowed)
        );
    }

    #[test]
    fn v26_subscription_ack() {
        let requested = ListenFilters {
            tools_list_changed: Some(true),
            prompts_list_changed: Some(true),
            resource_subscriptions: Some(vec!["file:///a".to_string()]),
            ..ListenFilters::default()
        };
        let ack_filters = ListenFilters {
            tools_list_changed: Some(true),
            prompts_list_changed: Some(true),
            resource_subscriptions: Some(vec!["file:///a".to_string()]),
            ..ListenFilters::default()
        };
        let f = facts();
        let mut lr = allow("subscriptions/listen");
        lr.filters = vec![SF::PromptsListChanged, SF::ResourceSubscriptions];
        lr.uris = vec!["file:///a".to_string()];
        let r = rules(vec![lr]);

        let sub = SubscriptionFacts {
            state: SubscriptionState::PendingAck,
            requested: &requested,
            acked: &[],
            acked_uris: &[],
        };
        let mut n = notif(V26, S2C, "notifications/subscriptions/acknowledged");
        n.ack_filters = Some(&ack_filters);
        n.subscription = Some(sub);
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_SUB);

        // A second ack on an active subscription drops.
        let sub = SubscriptionFacts {
            state: SubscriptionState::Active,
            requested: &requested,
            acked: &[],
            acked_uris: &[],
        };
        let mut n = notif(V26, S2C, "notifications/subscriptions/acknowledged");
        n.ack_filters = Some(&ack_filters);
        n.subscription = Some(sub);
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::SubscriptionState)
        );

        // Ack granting a filter the client never requested drops.
        let ack = ListenFilters {
            resources_list_changed: Some(true),
            ..ListenFilters::default()
        };
        let sub = SubscriptionFacts {
            state: SubscriptionState::PendingAck,
            requested: &requested,
            acked: &[],
            acked_uris: &[],
        };
        let mut n = notif(V26, S2C, "notifications/subscriptions/acknowledged");
        n.ack_filters = Some(&ack);
        n.subscription = Some(sub);
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );
    }

    #[test]
    fn v26_message_needs_request_correlation() {
        let f = facts();
        let r = rules(vec![allow("notifications/message")]);
        // No correlation → drop.
        let mut n = notif(V26, S2C, "notifications/message");
        n.level = Some("error");
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );
        // Request did not ask for logs → drop.
        let mut n = notif(V26, S2C, "notifications/message");
        n.level = Some("error");
        n.message_for = Some(MessageCorrelation { log_level: None });
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::Uncorrelated)
        );
        // Level below requested → drop; at-or-above → allow.
        let mut n = notif(V26, S2C, "notifications/message");
        n.level = Some("info");
        n.message_for = Some(MessageCorrelation {
            log_level: Some("warning"),
        });
        assert_eq!(
            r.decide(&TrafficMessage::Notification(n), &f),
            McpVerdict::Drop(DropReason::LevelRange)
        );
        let mut n = notif(V26, S2C, "notifications/message");
        n.level = Some("alert");
        n.message_for = Some(MessageCorrelation {
            log_level: Some("warning"),
        });
        assert_eq!(r.decide(&TrafficMessage::Notification(n), &f), A_RULE);
    }

    // ── additional requests (MRTR) ──

    fn orig<'a>(method: &'a str, caps: &'a [String]) -> OriginalRequestFacts<'a> {
        OriginalRequestFacts {
            method,
            allowed: true,
            client_capabilities: caps,
        }
    }

    fn add<'a>(method: &'a str, o: OriginalRequestFacts<'a>) -> TrafficMessage<'a> {
        TrafficMessage::AdditionalRequest(AdditionalRequestMessage {
            version: V26,
            method,
            original: o,
        })
    }

    #[test]
    fn additional_requests() {
        let f = facts();
        let r = rules(vec![
            allow("elicitation/create"),
            deny("sampling/createMessage"),
        ]);
        let caps = vec!["elicitation".to_string(), "sampling".to_string()];

        assert_eq!(
            r.decide(&add("elicitation/create", orig("tools/call", &caps)), &f),
            A_RULE
        );
        // deny atom wins.
        assert_eq!(
            r.decide(
                &add("sampling/createMessage", orig("tools/call", &caps)),
                &f
            ),
            McpVerdict::Deny(DenyReason::RuleDeny)
        );
        // Method not in the additional-request ledger.
        assert_eq!(
            r.decide(&add("tools/call", orig("tools/call", &caps)), &f),
            McpVerdict::Deny(DenyReason::UnknownMethod)
        );
        // Original request not input_required-eligible.
        assert_eq!(
            r.decide(
                &add("elicitation/create", orig("resources/list", &caps)),
                &f
            ),
            McpVerdict::Deny(DenyReason::InputRequiredTarget)
        );
        // Original request was denied.
        let mut o = orig("tools/call", &caps);
        o.allowed = false;
        assert_eq!(
            r.decide(&add("elicitation/create", o), &f),
            McpVerdict::Deny(DenyReason::InputRequiredTarget)
        );
        // Missing capability on the original request's _meta.
        let no_caps: Vec<String> = vec![];
        let o = OriginalRequestFacts {
            method: "tools/call",
            allowed: true,
            client_capabilities: &no_caps,
        };
        assert_eq!(
            r.decide(&add("elicitation/create", o), &f),
            McpVerdict::Deny(DenyReason::Capability)
        );
        // roots/list with no allow rule → no-rule (the original request must
        // still carry the matching capability, checked before rule lookup).
        let root_caps = vec!["roots".to_string()];
        let o = OriginalRequestFacts {
            method: "resources/read",
            allowed: true,
            client_capabilities: &root_caps,
        };
        assert_eq!(
            r.decide(&add("roots/list", o), &f),
            McpVerdict::Deny(DenyReason::NoRule)
        );
        // Additional requests exist only in 2026.
        let bad_version = TrafficMessage::AdditionalRequest(AdditionalRequestMessage {
            version: V25,
            method: "elicitation/create",
            original: o,
        });
        assert_eq!(
            r.decide(&bad_version, &f),
            McpVerdict::Deny(DenyReason::VersionDirection)
        );
    }

    // ── responses ──

    #[test]
    fn responses() {
        let f = facts();
        let r = rules(vec![]);

        // Uncorrelated response.
        let mut m = resp(V25, S2C, "tools/call");
        m.answered = None;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::Uncorrelated)
        );

        // Direction sanity: a "response" answering a same-direction request.
        let mut m = resp(V25, S2C, "tools/call");
        if let Some(ref mut a) = m.answered {
            a.request_direction = S2C;
        }
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::Uncorrelated)
        );

        // A denied request never reached the peer — a response answering
        // it denies, and the error fast-path must not bypass that.
        let mut m = resp(V25, S2C, "tools/call");
        if let Some(ref mut a) = m.answered {
            a.allowed = false;
        }
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::Uncorrelated)
        );
        let mut m = resp(V25, S2C, "tools/call");
        m.is_error = true;
        m.has_result = false;
        if let Some(ref mut a) = m.answered {
            a.allowed = false;
        }
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::Uncorrelated)
        );

        // Error responses pass on correlation alone (either revision).
        let mut m = resp(V26, S2C, "tools/call");
        m.is_error = true;
        m.has_result = false;
        assert_eq!(r.decide(&TrafficMessage::Response(m), &f), A_PROTOCOL);

        // A frame carrying both `error` and `result` — or neither — is
        // malformed, not a completion.
        let mut m = resp(V25, S2C, "tools/call");
        m.is_error = true;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::Shape)
        );
        let mut m = resp(V26, S2C, "tools/call");
        m.has_result = false;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::Shape)
        );

        // 2025 success results pass; a resultType on 2025 is undefined.
        assert_eq!(
            r.decide(&TrafficMessage::Response(resp(V25, S2C, "tools/call")), &f),
            A_PROTOCOL
        );
        let mut m = resp(V25, S2C, "tools/call");
        m.result_type = Some("complete");
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::ResultType)
        );
        // inputRequests is a 2026-only member too.
        let mut m = resp(V25, S2C, "tools/call");
        m.input_requests = true;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::ResultType)
        );

        // 2026 complete on a cacheable method needs valid ttlMs+cacheScope.
        let mut m = resp(V26, S2C, "tools/call");
        m.result_type = Some("complete");
        m.ttl_ms = SchemaField::Valid;
        m.cache_scope = SchemaField::Valid;
        assert_eq!(r.decide(&TrafficMessage::Response(m), &f), A_PROTOCOL);
        let mut m = resp(V26, S2C, "tools/call");
        m.result_type = Some("complete");
        m.ttl_ms = SchemaField::Absent;
        m.cache_scope = SchemaField::Valid;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::CacheFields)
        );
        let mut m = resp(V26, S2C, "tools/call");
        m.result_type = Some("complete");
        m.ttl_ms = SchemaField::Invalid;
        m.cache_scope = SchemaField::Valid;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::CacheFields)
        );

        // Non-cacheable answered methods don't need the fields.
        let mut m = resp(V26, S2C, "subscriptions/listen");
        m.result_type = Some("complete");
        assert_eq!(r.decide(&TrafficMessage::Response(m), &f), A_PROTOCOL);

        // inputRequests on a complete result is malformed.
        let mut m = resp(V26, S2C, "tools/call");
        m.result_type = Some("complete");
        m.ttl_ms = SchemaField::Valid;
        m.cache_scope = SchemaField::Valid;
        m.input_requests = true;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::ResultType)
        );

        // input_required: eligible methods defer to the MRTR layer.
        let mut m = resp(V26, S2C, "tools/call");
        m.result_type = Some("input_required");
        m.input_requests = true;
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Undecided(UndecidedReason::InputRequired)
        );
        for method in ["resources/read", "prompts/get"] {
            let mut m = resp(V26, S2C, method);
            m.result_type = Some("input_required");
            assert_eq!(
                r.decide(&TrafficMessage::Response(m), &f),
                McpVerdict::Undecided(UndecidedReason::InputRequired),
                "{method}"
            );
        }
        // Ineligible original → deny.
        let mut m = resp(V26, S2C, "tools/list");
        m.result_type = Some("input_required");
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::InputRequiredTarget)
        );
        // Unknown/missing resultType.
        let mut m = resp(V26, S2C, "tools/call");
        m.result_type = Some("streaming");
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            McpVerdict::Deny(DenyReason::ResultType)
        );
        assert_eq!(
            r.decide(&TrafficMessage::Response(resp(V26, S2C, "tools/call")), &f),
            McpVerdict::Deny(DenyReason::ResultType)
        );

        // No C2S responses exist in 2026.
        assert_eq!(
            r.decide(&TrafficMessage::Response(resp(V26, C2S, "x")), &f),
            McpVerdict::Deny(DenyReason::VersionDirection)
        );
        // But 2025 C2S responses (answering S2C requests) pass.
        assert_eq!(
            r.decide(
                &TrafficMessage::Response(resp(V25, C2S, "elicitation/create")),
                &f
            ),
            A_PROTOCOL
        );
    }

    // ── rule model ──

    #[test]
    fn atoms_expand_over_method_slots() {
        let atoms = allow("notifications/cancelled").atoms();
        assert_eq!(atoms.len(), 4);
        assert!(atoms.iter().any(|a| a.version == V26 && a.direction == S2C));
        assert!(atoms.iter().all(|a| a.kind == RuleKind::Notification));

        let mut scoped = allow("tools/list");
        scoped.versions = vec![V25];
        let atoms = scoped.atoms();
        assert_eq!(atoms.len(), 1);
        assert_eq!(atoms[0].version, V25);

        let mut wrong_dir = allow("initialize");
        wrong_dir.direction = Some(S2C);
        assert!(wrong_dir.atoms().is_empty());

        assert!(allow("unknown/method").atoms().is_empty());
    }

    #[test]
    fn resolve_atoms_is_deny_sticky() {
        let resolved = resolve_atoms(&[
            allow("resources/read"),
            deny("resources/read"),
            allow("elicitation/create"),
        ]);
        let key = |v, d, k, m: &'static str| RuleKey {
            version: v,
            direction: d,
            kind: k,
            method: m,
        };
        assert_eq!(
            resolved[&key(V25, C2S, RuleKind::Request, "resources/read")].effect,
            RuleEffect::Deny
        );
        assert_eq!(
            resolved[&key(V26, S2C, RuleKind::AdditionalRequest, "elicitation/create")].effect,
            RuleEffect::Allow
        );
        assert_eq!(
            resolved[&key(V25, S2C, RuleKind::Request, "elicitation/create")].effect,
            RuleEffect::Allow
        );
    }

    #[test]
    fn validate_rule_set_rejects_atom_overlap() {
        let mut a = allow("tools/list");
        a.versions = vec![V25, V26];
        let mut b = deny("tools/list");
        b.versions = vec![V26];
        assert!(validate_rule_set(Some("s"), &[a.clone(), b]).is_err());
        // Same effect overlap is still an error.
        let c = allow("tools/list");
        assert!(validate_rule_set(Some("s"), &[a, c]).is_err());
    }

    #[test]
    fn default_profile_is_closed() {
        // An empty rule set (what a v1 policy resolves to) only passes
        // protocol machinery.
        let r = rules(vec![]);
        let f = facts();
        assert_eq!(req26(&r, &f, "tools/list"), A_PROTOCOL);
        assert_eq!(
            req26(&r, &f, "prompts/get"),
            McpVerdict::Deny(DenyReason::NoRule)
        );
        let params = RequestParams::default();
        assert_eq!(
            r.decide(
                &req(V25, S2C, "sampling/createMessage", None, Some(&params)),
                &f
            ),
            McpVerdict::Deny(DenyReason::NoRule)
        );
    }

    #[test]
    fn verdict_codes_are_stable() {
        assert_eq!(
            McpVerdict::Deny(DenyReason::UriNotAllowed).reason_code(),
            "uri-not-allowed"
        );
        assert_eq!(
            McpVerdict::Undecided(UndecidedReason::InputRequired).to_string(),
            "undecided(input-required)"
        );
        assert_eq!(A_SUB.outcome(), "allow");
        assert_eq!(A_SUB.reason_code(), "subscription-matched");
    }
}
