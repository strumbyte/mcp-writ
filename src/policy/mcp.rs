//! MCP passage rules (`mcp` blocks) and the per-message decision model.
//!
//! This module is the judgment model only — it defines the policy surface
//! and `decide()`; enforcement on the live wire (direction plumbing,
//! correlation tables, subscription bookkeeping, MRTR result dispatch)
//! belongs to the Auditor.
//!
//! KDL schema v2 only: `mcp` rule blocks appear under `server` and are
//! parsed by `kdl_parse::parse_server_mcp_rules`, rejected under `policy
//! version=1`. Public load paths accept `version` 1 or 2 in
//! `policy::validator`; without `mcp` rules both run the same fail-closed
//! default passage profile.
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
    InitializeShape, ListenFilters, RequestMeta, SchemaField, SubscriptionFilter,
};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

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
/// means every direction of the method (`atoms` filters slots with
/// `is_none_or`). Both are restrictions — the rule still expands over
/// the method's own slots, never outside them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpRule {
    pub effect: RuleEffect,
    pub method: String,
    /// `protocol="..."` restrictions; empty = all the method's revisions.
    pub versions: Vec<SupportedProtocolVersion>,
    /// `direction="..."` restriction; `None` = every direction of the
    /// method's slots.
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
    /// `params.elicitationId` (`notifications/elicitation/complete`).
    pub elicitation_id: Option<&'a str>,
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
    /// The request genuinely reached the peer — policy-allowed at pass
    /// time, or forwarded anyway under `--dry-run`.
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
    /// URL-mode `elicitationId`s pending completion — registered by a
    /// forwarded `elicitation/create` or `-32042` error (2025
    /// `notifications/elicitation/complete` gate).
    pub pending_elicitations: &'a [String],
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

mod decide;

#[cfg(test)]
mod tests;
