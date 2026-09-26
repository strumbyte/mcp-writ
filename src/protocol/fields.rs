//! Leaf-level JSON-RPC / MCP field extraction.
//!
//! These helpers pull member values out of a parsed frame so the Auditor
//! can build `policy::mcp` decision inputs. They return plain values plus
//! protocol enums — never policy types — so `protocol` stays dependency
//! free of `policy`. Correlation lookups (pending request ids, progress
//! tokens, subscription ids) are the Auditor's job; this module only reads
//! the wire fields those lookups key on.

use crate::protocol::{META_CLIENT_CAPABILITIES, META_PROTOCOL_VERSION};

/// `params._meta` / `result._meta` key that correlates a subscription
/// notification with the owning `subscriptions/listen` request id
/// (`2026-07-28`).
pub const META_SUBSCRIPTION_ID: &str = "io.modelcontextprotocol/subscriptionId";

/// `params._meta` key carrying the log level a `2026-07-28` request asked
/// to receive `notifications/message` for.
pub const META_LOG_LEVEL: &str = "io.modelcontextprotocol/logLevel";

/// A scalar wire field checked against the revision schema.
///
/// Used for `resultType` neighbours (`ttlMs`, `cacheScope`) and the
/// `_meta` `clientCapabilities` member, where the policy decision only
/// needs presence/validity, not the value itself.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SchemaField {
    /// Member absent or `null`.
    #[default]
    Absent,
    /// Member present but wrong type or outside the schema value set.
    Invalid,
    /// Member present and schema-valid.
    Valid,
}

/// `2026-07-28` `subscriptions/listen` filter names, exactly as they
/// appear in `params.notifications`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SubscriptionFilter {
    ToolsListChanged,
    PromptsListChanged,
    ResourcesListChanged,
    /// Gate for `resourceSubscriptions` URI entries; the URIs themselves
    /// are carried separately.
    ResourceSubscriptions,
}

impl SubscriptionFilter {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolsListChanged => "toolsListChanged",
            Self::PromptsListChanged => "promptsListChanged",
            Self::ResourcesListChanged => "resourcesListChanged",
            Self::ResourceSubscriptions => "resourceSubscriptions",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "toolsListChanged" => Some(Self::ToolsListChanged),
            "promptsListChanged" => Some(Self::PromptsListChanged),
            "resourcesListChanged" => Some(Self::ResourcesListChanged),
            "resourceSubscriptions" => Some(Self::ResourceSubscriptions),
            _ => None,
        }
    }

    /// The notification `method` this filter gates, if it maps to one.
    pub const fn notification_method(self) -> &'static str {
        match self {
            Self::ToolsListChanged => "notifications/tools/list_changed",
            Self::PromptsListChanged => "notifications/prompts/list_changed",
            Self::ResourcesListChanged => "notifications/resources/list_changed",
            Self::ResourceSubscriptions => "notifications/resources/updated",
        }
    }
}

/// Parsed `params.notifications` filter set of a `subscriptions/listen`
/// request or a `notifications/subscriptions/acknowledged` notification.
///
/// `Option<bool>` members keep the three-way distinction the spec needs:
/// absent, present-false, and present-true are different facts.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ListenFilters {
    pub tools_list_changed: Option<bool>,
    pub prompts_list_changed: Option<bool>,
    pub resources_list_changed: Option<bool>,
    /// URI strings verbatim — never normalised as host paths.
    pub resource_subscriptions: Option<Vec<String>>,
    /// Member names not in the schema, or known members with a malformed
    /// value (wrong type). Non-empty means fail closed.
    pub unknown: Vec<String>,
}

impl ListenFilters {
    /// Filters explicitly enabled (`true`, or a present URI list).
    pub fn enabled(&self) -> Vec<SubscriptionFilter> {
        let mut out = Vec::new();
        if self.tools_list_changed == Some(true) {
            out.push(SubscriptionFilter::ToolsListChanged);
        }
        if self.prompts_list_changed == Some(true) {
            out.push(SubscriptionFilter::PromptsListChanged);
        }
        if self.resources_list_changed == Some(true) {
            out.push(SubscriptionFilter::ResourcesListChanged);
        }
        if self.resource_subscriptions.is_some() {
            out.push(SubscriptionFilter::ResourceSubscriptions);
        }
        out
    }

    /// True when the filter set requests nothing beyond the free
    /// `toolsListChanged` filter (possibly none at all).
    pub fn only_free_filters(&self) -> bool {
        self.prompts_list_changed != Some(true)
            && self.resources_list_changed != Some(true)
            && self.resource_subscriptions.is_none()
    }
}

/// `params._meta` claims attached to a `2026-07-28` request.
#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    /// The `_meta` member itself was present but not an object — the
    /// member is malformed, not missing; all other fields stay empty.
    pub malformed: bool,
    /// `io.modelcontextprotocol/protocolVersion` verbatim; `None` when
    /// absent or not a string.
    pub protocol_version: Option<String>,
    /// `io.modelcontextprotocol/clientCapabilities` member state —
    /// required as an object on every `2026-07-28` request; `Invalid`
    /// distinguishes "present but not an object" from absent.
    pub client_capabilities_shape: SchemaField,
    /// Capability names flattened one level: `{"roots":{"listChanged":true}}`
    /// becomes `["roots", "roots.listChanged"]`. Only `true` nested
    /// members flatten; deeper objects keep the parent name only.
    /// Empty unless `client_capabilities_shape` is `Valid`.
    pub client_capabilities: Vec<String>,
    /// `io.modelcontextprotocol/logLevel` the request asked for.
    pub log_level: Option<String>,
    /// `io.modelcontextprotocol/subscriptionId` raw member text — the
    /// Auditor compares it (type + value) to the tracked listen request id.
    pub subscription_id: Option<String>,
}

/// `2025-11-25` `initialize` params shape check.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InitializeShape {
    pub has_protocol_version: bool,
    pub has_capabilities: bool,
    pub has_client_info: bool,
}

impl InitializeShape {
    pub const fn complete(self) -> bool {
        self.has_protocol_version && self.has_capabilities && self.has_client_info
    }
}

/// Read `params._meta` claims of a request/notification/result object.
///
/// `params_or_result` is the member holding `_meta` (`params` on a
/// request/notification, `result` on a response). Returns `None` when
/// `_meta` is absent; a present-but-non-object `_meta` yields `Some`
/// with `malformed` set so callers can distinguish it from missing.
pub fn request_meta(holder: nojson::RawJsonValue<'_, '_>) -> Option<RequestMeta> {
    let meta = holder.to_member("_meta").ok()?.optional()?;
    if meta.to_object().is_err() {
        return Some(RequestMeta {
            malformed: true,
            ..RequestMeta::default()
        });
    }
    let protocol_version = meta
        .to_member(META_PROTOCOL_VERSION)
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.as_string_str().ok())
        .map(str::to_string);
    let caps_member = meta
        .to_member(META_CLIENT_CAPABILITIES)
        .ok()
        .and_then(|m| m.optional());
    let client_capabilities_shape = match caps_member {
        None => SchemaField::Absent,
        Some(c) if c.to_object().is_err() => SchemaField::Invalid,
        Some(_) => SchemaField::Valid,
    };
    let client_capabilities = caps_member.map(flatten_capabilities).unwrap_or_default();
    let log_level = meta
        .to_member(META_LOG_LEVEL)
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.as_string_str().ok())
        .map(str::to_string);
    let subscription_id = meta
        .to_member(META_SUBSCRIPTION_ID)
        .ok()
        .and_then(|m| m.optional())
        .map(|v| v.as_raw_str().to_string());
    Some(RequestMeta {
        malformed: false,
        protocol_version,
        client_capabilities_shape,
        client_capabilities,
        log_level,
        subscription_id,
    })
}

/// Flatten a capability object one level: each member name is a
/// capability; a member whose value is an object contributes
/// `name.subName` for every nested `true` member.
fn flatten_capabilities(caps: nojson::RawJsonValue<'_, '_>) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(members) = caps.to_object() else {
        return out;
    };
    for (key, value) in members {
        let Ok(name) = key.to_unquoted_string_str() else {
            continue;
        };
        let name = name.into_owned();
        out.push(name.clone());
        if let Ok(nested) = value.to_object() {
            for (sub_key, sub_value) in nested {
                let Ok(sub_name) = sub_key.to_unquoted_string_str() else {
                    continue;
                };
                if sub_value.as_boolean_str().ok() == Some("true") {
                    out.push(format!("{name}.{}", sub_name.into_owned()));
                }
            }
        }
    }
    out
}

/// `2025-11-25` `initialize` params required-member check.
pub fn initialize_shape(params: Option<nojson::RawJsonValue<'_, '_>>) -> InitializeShape {
    let Some(params) = params else {
        return InitializeShape::default();
    };
    let has_protocol_version = params
        .to_member("protocolVersion")
        .ok()
        .and_then(|m| m.optional())
        .is_some_and(|v| v.as_string_str().is_ok());
    let has_capabilities = params
        .to_member("capabilities")
        .ok()
        .and_then(|m| m.optional())
        .is_some_and(|v| v.to_object().is_ok());
    let has_client_info = params
        .to_member("clientInfo")
        .ok()
        .and_then(|m| m.optional())
        .is_some_and(|v| v.to_object().is_ok());
    InitializeShape {
        has_protocol_version,
        has_capabilities,
        has_client_info,
    }
}

/// Parse `params.notifications` of a `subscriptions/listen` request or a
/// `notifications/subscriptions/acknowledged` notification.
///
/// A missing `notifications` member yields the default (empty) set.
/// Non-object `notifications`, non-boolean flag members, and a
/// non-string-array `resourceSubscriptions` all land in `unknown`.
pub fn listen_filters(params: Option<nojson::RawJsonValue<'_, '_>>) -> ListenFilters {
    let Some(params) = params else {
        return ListenFilters::default();
    };
    let Some(notifications) = params
        .to_member("notifications")
        .ok()
        .and_then(|m| m.optional())
    else {
        return ListenFilters::default();
    };
    let Ok(members) = notifications.to_object() else {
        return ListenFilters {
            unknown: vec!["notifications".to_string()],
            ..ListenFilters::default()
        };
    };
    let mut out = ListenFilters::default();
    for (key, value) in members {
        let Ok(name) = key.to_unquoted_string_str() else {
            continue;
        };
        let name = name.into_owned();
        match SubscriptionFilter::parse(&name) {
            Some(SubscriptionFilter::ResourceSubscriptions) => {
                out.resource_subscriptions = Some(parse_uri_list(value, &name, &mut out.unknown));
            }
            Some(flag) => {
                let target = match flag {
                    SubscriptionFilter::ToolsListChanged => &mut out.tools_list_changed,
                    SubscriptionFilter::PromptsListChanged => &mut out.prompts_list_changed,
                    SubscriptionFilter::ResourcesListChanged => &mut out.resources_list_changed,
                    SubscriptionFilter::ResourceSubscriptions => unreachable!(),
                };
                match value.as_boolean_str().ok() {
                    Some("true") => *target = Some(true),
                    Some("false") => *target = Some(false),
                    _ => out.unknown.push(name),
                }
            }
            None => out.unknown.push(name),
        }
    }
    out
}

fn parse_uri_list(
    value: nojson::RawJsonValue<'_, '_>,
    name: &str,
    unknown: &mut Vec<String>,
) -> Vec<String> {
    let Ok(items) = value.to_array() else {
        unknown.push(name.to_string());
        return Vec::new();
    };
    let mut uris = Vec::new();
    for item in items {
        match item.as_string_str() {
            Ok(uri) => uris.push(uri.to_string()),
            Err(_) => {
                unknown.push(name.to_string());
                return Vec::new();
            }
        }
    }
    uris
}

/// A string `params` member (`uri`, `level`, `reason`, ...). `None` when
/// absent, `null`, or not a string.
pub fn string_param(params: Option<nojson::RawJsonValue<'_, '_>>, name: &str) -> Option<String> {
    params
        .and_then(|p| p.to_member(name).ok())
        .and_then(|m| m.optional())
        .and_then(|v| v.as_string_str().ok())
        .map(str::to_string)
}

/// `params.requestId` of `notifications/cancelled`, as raw JSON text —
/// the Auditor canonicalises it like a request `id`.
pub fn request_id_param(params: Option<nojson::RawJsonValue<'_, '_>>) -> Option<String> {
    params
        .and_then(|p| p.to_member("requestId").ok())
        .and_then(|m| m.optional())
        .map(|v| v.as_raw_str().to_string())
}

/// `params.progressToken` of `notifications/progress`, raw JSON text.
pub fn progress_token_param(params: Option<nojson::RawJsonValue<'_, '_>>) -> Option<String> {
    params
        .and_then(|p| p.to_member("progressToken").ok())
        .and_then(|m| m.optional())
        .map(|v| v.as_raw_str().to_string())
}

/// `params._meta` of a `subscriptions/listen` request: the minted
/// `subscriptionId`, raw JSON text (present only on listen requests).
pub fn listen_subscription_id(params: Option<nojson::RawJsonValue<'_, '_>>) -> Option<String> {
    let params = params?;
    let meta = params.to_member("_meta").ok()?.optional()?;
    meta.to_member(META_SUBSCRIPTION_ID)
        .ok()
        .and_then(|m| m.optional())
        .map(|v| v.as_raw_str().to_string())
}

/// `result.resultType` verbatim (`complete`, `input_required`, ...).
pub fn result_type(result: nojson::RawJsonValue<'_, '_>) -> Option<String> {
    result
        .to_member("resultType")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.as_string_str().ok())
        .map(str::to_string)
}

/// `result.ttlMs` — valid when a non-negative integer.
pub fn ttl_ms(result: nojson::RawJsonValue<'_, '_>) -> SchemaField {
    let Some(value) = result.to_member("ttlMs").ok().and_then(|m| m.optional()) else {
        return SchemaField::Absent;
    };
    match value.kind() {
        nojson::JsonValueKind::Integer => match value.as_raw_str().parse::<i64>() {
            Ok(v) if v >= 0 => SchemaField::Valid,
            _ => SchemaField::Invalid,
        },
        _ => SchemaField::Invalid,
    }
}

/// `result.cacheScope` — valid when `"public"` or `"private"`.
pub fn cache_scope(result: nojson::RawJsonValue<'_, '_>) -> SchemaField {
    let Some(value) = result
        .to_member("cacheScope")
        .ok()
        .and_then(|m| m.optional())
    else {
        return SchemaField::Absent;
    };
    match value.as_string_str() {
        Ok("public") | Ok("private") => SchemaField::Valid,
        _ => SchemaField::Invalid,
    }
}

/// True when `result.inputRequests` is a present array (MRTR interim).
pub fn has_input_requests(result: nojson::RawJsonValue<'_, '_>) -> bool {
    result
        .to_member("inputRequests")
        .ok()
        .and_then(|m| m.optional())
        .is_some_and(|v| v.to_array().is_ok())
}

/// `method` strings of `result.inputRequests[]`, skipping malformed items.
pub fn input_request_methods(result: nojson::RawJsonValue<'_, '_>) -> Vec<String> {
    let Some(value) = result
        .to_member("inputRequests")
        .ok()
        .and_then(|m| m.optional())
    else {
        return Vec::new();
    };
    let Ok(items) = value.to_array() else {
        return Vec::new();
    };
    items
        .filter_map(|item| {
            item.to_member("method")
                .ok()
                .and_then(|m| m.optional())
                .and_then(|v| v.as_string_str().ok())
                .map(str::to_string)
        })
        .collect()
}

/// RFC 5424 severity rank for an MCP log level name; `None` for any
/// other string. Higher rank means more severe; a request for `warning`
/// subscribes to rank >= 3.
pub fn rfc5424_rank(level: &str) -> Option<u8> {
    match level {
        "debug" => Some(0),
        "info" => Some(1),
        "notice" => Some(2),
        "warning" => Some(3),
        "error" => Some(4),
        "critical" => Some(5),
        "alert" => Some(6),
        "emergency" => Some(7),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{MessageDirection, MessageKind};

    fn parse(line: &str) -> nojson::RawJson<'_> {
        nojson::RawJson::parse(line).unwrap()
    }

    fn member<'a>(
        value: nojson::RawJsonValue<'a, 'a>,
        name: &str,
    ) -> Option<nojson::RawJsonValue<'a, 'a>> {
        value.to_member(name).ok().and_then(|m| m.optional())
    }

    #[test]
    fn direction_and_kind_labels() {
        assert_eq!(MessageDirection::ClientToServer.as_str(), "c2s");
        assert_eq!(MessageDirection::ServerToClient.as_str(), "s2c");
        assert_eq!(
            MessageDirection::parse("c2s"),
            Some(MessageDirection::ClientToServer)
        );
        assert_eq!(
            MessageDirection::parse("s2c"),
            Some(MessageDirection::ServerToClient)
        );
        assert_eq!(MessageDirection::parse("sideways"), None);
        assert_ne!(MessageKind::Request, MessageKind::Notification);
    }

    #[test]
    fn request_meta_reads_reserved_keys() {
        let json = parse(
            r#"{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{"roots":{"listChanged":true},"sampling":{}},"io.modelcontextprotocol/logLevel":"warning"}}"#,
        );
        let meta = request_meta(json.value()).unwrap();
        assert!(!meta.malformed);
        assert_eq!(meta.protocol_version.as_deref(), Some("2026-07-28"));
        assert_eq!(meta.client_capabilities_shape, SchemaField::Valid);
        assert_eq!(
            meta.client_capabilities,
            vec!["roots", "roots.listChanged", "sampling"]
        );
        assert_eq!(meta.log_level.as_deref(), Some("warning"));
        assert_eq!(meta.subscription_id, None);
    }

    #[test]
    fn request_meta_missing_meta_is_none() {
        let json = parse(r#"{"uri":"file:///a"}"#);
        assert!(request_meta(json.value()).is_none());
    }

    #[test]
    fn request_meta_distinguishes_malformed_from_missing() {
        // A non-object `_meta` is malformed, not absent.
        let json = parse(r#"{"_meta":"none"}"#);
        let meta = request_meta(json.value()).unwrap();
        assert!(meta.malformed);

        // A non-object `clientCapabilities` member is Invalid — present
        // but unusable, distinct from an absent one.
        let json = parse(
            r#"{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":"yes"}}"#,
        );
        let meta = request_meta(json.value()).unwrap();
        assert!(!meta.malformed);
        assert_eq!(meta.client_capabilities_shape, SchemaField::Invalid);
        assert!(meta.client_capabilities.is_empty());

        let json = parse(r#"{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}"#);
        let meta = request_meta(json.value()).unwrap();
        assert_eq!(meta.client_capabilities_shape, SchemaField::Absent);
    }

    #[test]
    fn initialize_shape_needs_three_members() {
        let full = parse(
            r#"{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"x"}}"#,
        );
        assert!(
            initialize_shape(member(full.value(), "x").or_else(|| Some(full.value()))).complete()
        );
        let thin = parse(r#"{"protocolVersion":"2025-11-25"}"#);
        let shape = initialize_shape(Some(thin.value()));
        assert!(!shape.complete());
        assert!(shape.has_protocol_version);
        assert!(!shape.has_capabilities);
    }

    #[test]
    fn listen_filters_parse_flags_and_uris() {
        let json = parse(
            r#"{"notifications":{"toolsListChanged":true,"promptsListChanged":false,"resourceSubscriptions":["file:///a","file:///b"]}}"#,
        );
        let filters = listen_filters(Some(json.value()));
        assert_eq!(filters.tools_list_changed, Some(true));
        assert_eq!(filters.prompts_list_changed, Some(false));
        assert_eq!(filters.resources_list_changed, None);
        assert_eq!(
            filters.resource_subscriptions.as_deref(),
            Some(&["file:///a".to_string(), "file:///b".to_string()][..])
        );
        assert!(filters.unknown.is_empty());
        assert_eq!(
            filters.enabled(),
            vec![
                SubscriptionFilter::ToolsListChanged,
                SubscriptionFilter::ResourceSubscriptions
            ]
        );
    }

    #[test]
    fn listen_filters_fail_closed_on_unknown() {
        let json = parse(r#"{"notifications":{"exotic":true,"toolsListChanged":"yes"}}"#);
        let filters = listen_filters(Some(json.value()));
        assert_eq!(filters.unknown, vec!["exotic", "toolsListChanged"]);
        assert_eq!(filters.tools_list_changed, None);
    }

    #[test]
    fn result_scalar_fields_validate() {
        let json = parse(
            r#"{"resultType":"complete","ttlMs":3600000,"cacheScope":"private","inputRequests":[{"method":"elicitation/create"}]}"#,
        );
        assert_eq!(result_type(json.value()).as_deref(), Some("complete"));
        assert_eq!(ttl_ms(json.value()), SchemaField::Valid);
        assert_eq!(cache_scope(json.value()), SchemaField::Valid);
        assert!(has_input_requests(json.value()));
        assert_eq!(
            input_request_methods(json.value()),
            vec!["elicitation/create".to_string()]
        );
    }

    #[test]
    fn result_scalar_fields_reject_bad_types() {
        let json = parse(r#"{"resultType":"complete","ttlMs":-1,"cacheScope":"global"}"#);
        assert_eq!(ttl_ms(json.value()), SchemaField::Invalid);
        assert_eq!(cache_scope(json.value()), SchemaField::Invalid);
        let json = parse(r#"{"ttlMs":"3600"}"#);
        assert_eq!(ttl_ms(json.value()), SchemaField::Invalid);
    }

    #[test]
    fn rfc5424_ordering() {
        assert!(rfc5424_rank("warning") > rfc5424_rank("info"));
        assert_eq!(rfc5424_rank("debug"), Some(0));
        assert_eq!(rfc5424_rank("emergency"), Some(7));
        assert_eq!(rfc5424_rank("chatty"), None);
    }
}
