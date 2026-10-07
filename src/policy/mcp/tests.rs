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
        elicitation_id: None,
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
    let caps = vec!["logging".to_string()];
    let f = SessionFacts {
        server_capabilities: &caps,
        ..facts()
    };
    let r = rules(vec![allow("logging/setLevel")]);
    let params = RequestParams {
        level: Some("warning"),
        ..RequestParams::default()
    };
    assert_eq!(
        r.decide(&req(V25, C2S, "logging/setLevel", None, Some(&params)), &f),
        A_RULE
    );
    // The allow rule alone is not enough — the server must have
    // negotiated the `logging` capability in initialize.
    assert_eq!(
        r.decide(
            &req(V25, C2S, "logging/setLevel", None, Some(&params)),
            &facts()
        ),
        McpVerdict::Deny(DenyReason::Capability)
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
            &TrafficMessage::Notification(notif(V25, S2C, "notifications/prompts/list_changed")),
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

    // elicitation/complete needs a pending `elicitationId` it names.
    let mut n = notif(V25, S2C, "notifications/elicitation/complete");
    n.elicitation_id = Some("el-1");
    assert_eq!(
        r.decide(&TrafficMessage::Notification(n), &f),
        McpVerdict::Drop(DropReason::Uncorrelated)
    );
    let pending = vec!["el-1".to_string(), "el-2".to_string()];
    let f2 = SessionFacts {
        pending_elicitations: &pending,
        ..f
    };
    let mut n = notif(V25, S2C, "notifications/elicitation/complete");
    n.elicitation_id = Some("el-2");
    assert_eq!(r.decide(&TrafficMessage::Notification(n), &f2), A_RULE);
    // A missing or unknown id never correlates a pending one.
    let mut n = notif(V25, S2C, "notifications/elicitation/complete");
    n.elicitation_id = Some("el-9");
    assert_eq!(
        r.decide(&TrafficMessage::Notification(n), &f2),
        McpVerdict::Drop(DropReason::Uncorrelated)
    );
    assert_eq!(
        r.decide(
            &TrafficMessage::Notification(notif(V25, S2C, "notifications/elicitation/complete")),
            &f2
        ),
        McpVerdict::Drop(DropReason::Shape)
    );

    // resources/list_changed without negotiated capability.
    let r2 = rules(vec![allow("notifications/resources/list_changed")]);
    assert_eq!(
        r2.decide(
            &TrafficMessage::Notification(notif(V25, S2C, "notifications/resources/list_changed")),
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
    let mut m = resp(V26, S2C, "tools/list");
    m.result_type = Some("complete");
    m.ttl_ms = SchemaField::Valid;
    m.cache_scope = SchemaField::Valid;
    assert_eq!(r.decide(&TrafficMessage::Response(m), &f), A_PROTOCOL);
    let mut m = resp(V26, S2C, "tools/list");
    m.result_type = Some("complete");
    m.ttl_ms = SchemaField::Absent;
    m.cache_scope = SchemaField::Valid;
    assert_eq!(
        r.decide(&TrafficMessage::Response(m), &f),
        McpVerdict::Deny(DenyReason::CacheFields)
    );
    let mut m = resp(V26, S2C, "tools/list");
    m.result_type = Some("complete");
    m.ttl_ms = SchemaField::Invalid;
    m.cache_scope = SchemaField::Valid;
    assert_eq!(
        r.decide(&TrafficMessage::Response(m), &f),
        McpVerdict::Deny(DenyReason::CacheFields)
    );

    // Non-cacheable answered methods don't need the fields —
    // tools/call and prompts/get return ordinary results.
    for method in ["subscriptions/listen", "tools/call", "prompts/get"] {
        let mut m = resp(V26, S2C, method);
        m.result_type = Some("complete");
        assert_eq!(
            r.decide(&TrafficMessage::Response(m), &f),
            A_PROTOCOL,
            "{method}"
        );
    }

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
    // An omitted resultType denies too — a 2026 result MUST declare
    // it; only earlier-revision servers may omit it.
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
