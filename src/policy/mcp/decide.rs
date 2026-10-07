//! The per-message decision engine: method-to-behavior tables and the
//! `decide_*` functions. Reached only through `ServerMcpRules::decide`
//! and `Policy::decide_mcp`; the rule model and verdict types live in
//! the parent module.

use std::collections::{BTreeMap, BTreeSet};

use super::{
    AdditionalRequestMessage, AllowReason, C2S, CancelFacts, DenyReason, DropReason, InitStage,
    McpVerdict, NotificationMessage, ProgressCorrelation, RequestMessage, ResolvedRule,
    ResponseMessage, RuleEffect, RuleKey, RuleKind, RuleMap, S2C, ServerMcpRules, SessionFacts,
    SubscriptionState, TrafficMessage, UndecidedReason, V26, ledger_name,
};
use crate::policy::Policy;
use crate::protocol::fields::{RequestMeta, SchemaField, SubscriptionFilter, rfc5424_rank};
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

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
    /// `notifications/elicitation/complete` (2025): rule + pending
    /// `elicitationId` correlation.
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
/// `ttlMs` and `cacheScope` are then required members. `tools/call` and
/// `prompts/get` produce ordinary (non-cacheable) results, so their
/// `complete` responses carry no cache fields.
const CACHEABLE_METHODS: &[&str] = &[
    "server/discover",
    "tools/list",
    "resources/list",
    "resources/templates/list",
    "resources/read",
    "prompts/list",
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
            if !has_capability(facts.server_capabilities, "logging") {
                return McpVerdict::Deny(DenyReason::Capability);
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
            // The notification must name a pending elicitation — the
            // `elicitationId` a forwarded `elicitation/create` or `-32042`
            // error registered. Absent or unknown ids never correlate.
            let Some(el_id) = m.elicitation_id else {
                return McpVerdict::Drop(DropReason::Shape);
            };
            if !facts.pending_elicitations.iter().any(|e| e == el_id) {
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
            // A 2026-07-28 `result` MUST declare `resultType`. The spec's
            // absent-means-complete rule exists for servers implementing
            // *earlier* revisions — those are judged under the 2025
            // branch, not here — so on this wire an absent member is a
            // violation, and unknown values still deny.
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
