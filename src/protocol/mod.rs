//! MCP protocol-version helpers and `tools/list` wire parsing.
//!
//! Layer-0 module shared by the Auditor proxy, the Legislator discovery
//! client, and the Verifier baseline loader.
//!
//! This implementation supports exactly two revisions at the same time:
//! - `2026-07-28`: per-request `_meta`, no `initialize`.
//! - `2025-11-25`: `initialize` handshake.
//!
//! Stdio version selection follows the `2026-07-28` probe flow. A disposable
//! process receives `server/discover` for `2026-07-28`; a non-`2026-07-28`
//! response or timeout causes a fresh process to try `2025-11-25`. Advertised
//! future revisions are never treated as implicitly supported.
//!
//! Sources:
//! - <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>
//! - <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio>
//! - <https://ts.sdk.modelcontextprotocol.io/v2/migration/support-2026-07-28>

pub mod tools_list;

use std::fmt;

/// Supported revision using per-request `_meta` and `server/discover`.
pub const MCP_VERSION_2026_07_28: &str = "2026-07-28";

/// Supported revision using the `initialize` handshake.
pub const MCP_VERSION_2025_11_25: &str = "2025-11-25";

/// Revisions implemented and tested by this crate.
pub const SUPPORTED_PROTOCOL_VERSIONS: [&str; 2] = [MCP_VERSION_2026_07_28, MCP_VERSION_2025_11_25];

/// Client identity stamped in `2026-07-28` `_meta` and `2025-11-25` `clientInfo`.
pub const CLIENT_NAME: &str = "mcp-writ";

/// `io.modelcontextprotocol/protocolVersion` reserved `_meta` key.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";

/// `io.modelcontextprotocol/clientCapabilities` reserved `_meta` key.
pub const META_CLIENT_CAPABILITIES: &str = "io.modelcontextprotocol/clientCapabilities";

/// `io.modelcontextprotocol/clientInfo` reserved `_meta` key.
pub const META_CLIENT_INFO: &str = "io.modelcontextprotocol/clientInfo";

/// JSON-RPC `UnsupportedProtocolVersion` (`-32022`).
pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;

/// Inclusive low bound of the MCP-spec reserved error range.
const MCP_SPEC_ERROR_LO: i64 = -32099;

/// Inclusive high bound of the MCP-spec reserved error range.
const MCP_SPEC_ERROR_HI: i64 = -32020;

/// MCP revisions implemented and tested by mcp-writ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedProtocolVersion {
    /// Per-request `_meta`; no `initialize` handshake.
    Mcp2026July28,
    /// `initialize` followed by `notifications/initialized`.
    Mcp2025November25,
}

impl SupportedProtocolVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mcp2026July28 => MCP_VERSION_2026_07_28,
            Self::Mcp2025November25 => MCP_VERSION_2025_11_25,
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            MCP_VERSION_2026_07_28 => Some(Self::Mcp2026July28),
            MCP_VERSION_2025_11_25 => Some(Self::Mcp2025November25),
            _ => None,
        }
    }
}

impl fmt::Display for SupportedProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Step of the Legislator tools-list conversation (for errors and logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolStep {
    /// Disposable-sibling `server/discover` probe.
    Probe,
    /// MCP `2025-11-25` `initialize` request.
    Initialize,
    /// MCP `2025-11-25` `notifications/initialized`.
    Initialized,
    /// `tools/list` request for either supported revision.
    ToolsList,
}

impl fmt::Display for ProtocolStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Probe => write!(f, "server/discover probe"),
            Self::Initialize => write!(f, "initialize"),
            Self::Initialized => write!(f, "notifications/initialized"),
            Self::ToolsList => write!(f, "tools/list"),
        }
    }
}

/// Classification of a stdio `server/discover` probe response line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeClassification {
    /// Server returned a `DiscoverResult` to a `2026-07-28` request.
    Mcp2026July28Discover { supported_versions: Vec<String> },
    /// Server returned an MCP-reserved JSON-RPC error to a `2026-07-28` request.
    Mcp2026July28Error {
        code: i64,
        supported: Vec<String>,
        requested: Option<String>,
    },
    /// Try an `initialize` handshake for exactly `2025-11-25` on a fresh child.
    TryMcp2025November25,
}

/// Outcome of the stdio version probe, ready to drive the real child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionProbeOutcome {
    UseMcp2026July28,
    TryMcp2025November25,
    Unsupported { server_versions: Vec<String> },
}

/// Parsed JSON-RPC error object (code / message / optional `data.supported`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub supported: Vec<String>,
    pub requested: Option<String>,
}

impl JsonRpcError {
    /// Human-readable form for protocol error details.
    pub fn display_detail(&self) -> String {
        if self.supported.is_empty() {
            format!("{} ({})", self.message, self.code)
        } else {
            format!(
                "{} ({}); supported={:?}",
                self.message, self.code, self.supported
            )
        }
    }
}

/// True when `code` is in the MCP-spec reserved range (`-32020..=-32099`).
pub fn is_mcp_reserved_error(code: i64) -> bool {
    (MCP_SPEC_ERROR_LO..=MCP_SPEC_ERROR_HI).contains(&code)
}

fn includes_2026_07_28(versions: &[String]) -> bool {
    versions
        .iter()
        .any(|version| version == MCP_VERSION_2026_07_28)
}

fn includes_2025_11_25(versions: &[String]) -> bool {
    versions
        .iter()
        .any(|version| version == MCP_VERSION_2025_11_25)
}

/// Classify a single stdout line from a `server/discover` probe.
pub fn classify_probe_line(line: &str) -> ProbeClassification {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return ProbeClassification::TryMcp2025November25;
    }
    let Ok(json) = nojson::RawJson::parse(trimmed) else {
        return ProbeClassification::TryMcp2025November25;
    };

    if let Some(err) = jsonrpc_error_from_value(json.value()) {
        if is_mcp_reserved_error(err.code) {
            return ProbeClassification::Mcp2026July28Error {
                code: err.code,
                supported: err.supported,
                requested: err.requested,
            };
        }
        return ProbeClassification::TryMcp2025November25;
    }

    let Ok(result_member) = json.value().to_member("result") else {
        return ProbeClassification::TryMcp2025November25;
    };
    let Some(result) = result_member.optional() else {
        return ProbeClassification::TryMcp2025November25;
    };

    let supported_versions = result
        .to_member("supportedVersions")
        .ok()
        .and_then(|m| m.optional())
        .map(parse_string_array)
        .unwrap_or_default();

    ProbeClassification::Mcp2026July28Discover { supported_versions }
}

/// Convert a probe classification into an exact supported-version decision.
pub fn classification_to_outcome(classification: ProbeClassification) -> VersionProbeOutcome {
    match classification {
        ProbeClassification::Mcp2026July28Discover { supported_versions } => {
            // An empty `supportedVersions` (or a `result` without one) is
            // not an endorsement of 2026-07-28 — only an explicit mention is.
            if includes_2026_07_28(&supported_versions) {
                VersionProbeOutcome::UseMcp2026July28
            } else if supported_versions.is_empty() || includes_2025_11_25(&supported_versions) {
                VersionProbeOutcome::TryMcp2025November25
            } else {
                VersionProbeOutcome::Unsupported {
                    server_versions: supported_versions,
                }
            }
        }
        ProbeClassification::Mcp2026July28Error {
            code, supported, ..
        } => {
            // Only -32022 (UnsupportedProtocolVersion) negotiates versions:
            // `data.supported` on any other MCP-reserved error does not
            // endorse 2026-07-28, so the probe is inconclusive and falls
            // back to the legacy initialize on a fresh child.
            if code != UNSUPPORTED_PROTOCOL_VERSION {
                VersionProbeOutcome::TryMcp2025November25
            } else if includes_2026_07_28(&supported) {
                VersionProbeOutcome::UseMcp2026July28
            } else if supported.is_empty() || includes_2025_11_25(&supported) {
                // An absent/empty `data.supported` is inconclusive — like
                // an empty `supportedVersions`, it endorses neither
                // revision, so fall back to the legacy initialize.
                VersionProbeOutcome::TryMcp2025November25
            } else {
                VersionProbeOutcome::Unsupported {
                    server_versions: supported,
                }
            }
        }
        ProbeClassification::TryMcp2025November25 => VersionProbeOutcome::TryMcp2025November25,
    }
}

/// Parse a JSON-RPC error object from a response line, if present.
pub fn parse_jsonrpc_error(line: &str) -> Option<JsonRpcError> {
    let json = nojson::RawJson::parse(line.trim()).ok()?;
    jsonrpc_error_from_value(json.value())
}

/// True when the line is a JSON-RPC notification (has `method`, no `id`).
pub fn is_jsonrpc_notification(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line.trim()) else {
        return false;
    };
    let has_method = json
        .value()
        .to_member("method")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    let has_id = json
        .value()
        .to_member("id")
        .ok()
        .and_then(|m| m.optional())
        .is_some();
    has_method && !has_id
}

/// Extract a numeric JSON-RPC `id`, if the line has one that parses as `i64`.
pub fn jsonrpc_id_as_i64(line: &str) -> Option<i64> {
    let json = nojson::RawJson::parse(line.trim()).ok()?;
    let id = json.value().to_member("id").ok()?.optional()?;
    id.as_raw_str().parse().ok()
}

/// True when a parsed value carries `name` as a member.
pub fn value_has_member(value: nojson::RawJsonValue<'_, '_>, name: &str) -> bool {
    value
        .to_member(name)
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

/// True when the line has a non-null `result` member.
pub fn jsonrpc_has_result(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line.trim()) else {
        return false;
    };
    value_has_member(json.value(), "result")
}

/// True when a parsed value is a JSON-RPC response (`result` or `error`, no `method`).
///
/// Server-originated requests also carry an `id` and `method`; they are not
/// completions of a client `tools/call`.
pub fn value_is_response(value: nojson::RawJsonValue<'_, '_>) -> bool {
    if value_has_member(value, "method") {
        return false;
    }
    value_has_member(value, "result") || value_has_member(value, "error")
}

/// True when the line is a JSON-RPC response (`result` or `error`, no `method`).
///
/// Server-originated requests also carry an `id` and `method`; they are not
/// completions of a client `tools/call`.
pub fn jsonrpc_is_response(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line.trim()) else {
        return false;
    };
    value_is_response(json.value())
}

/// MCP tool-call execution failure: `result.isError === true`.
///
/// This is not a JSON-RPC `error`. The call completed, but the tool reported
/// failure and must not be treated as a successful side-effect.
pub fn mcp_call_result_is_error(value: nojson::RawJsonValue<'_, '_>) -> bool {
    let Some(result) = value.to_member("result").ok().and_then(|m| m.optional()) else {
        return false;
    };
    result
        .to_member("isError")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.as_boolean_str().ok())
        == Some("true")
}

/// Read `result.protocolVersion` from a `2025-11-25` `initialize` result.
pub fn parse_initialize_protocol_version(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line.trim()).ok()?;
    let result = json.value().to_member("result").ok()?.optional()?;
    result
        .to_member("protocolVersion")
        .ok()?
        .optional()?
        .as_string_str()
        .ok()
        .map(str::to_string)
}

/// Build a `2026-07-28` JSON-RPC request with required `_meta`.
///
/// `clientInfo` is included (SHOULD per spec). `clientCapabilities` is `{}`.
pub fn build_mcp_2026_07_28_request(id: i64, method: &str) -> String {
    build_mcp_2026_07_28_request_with_cursor(id, method, None)
}

/// Build a `2026-07-28` JSON-RPC request with optional pagination `cursor`.
pub fn build_mcp_2026_07_28_request_with_cursor(
    id: i64,
    method: &str,
    cursor: Option<&str>,
) -> String {
    build_meta_request_with_cursor(id, method, cursor, MCP_VERSION_2026_07_28)
}

/// Build a `_meta`-envelope JSON-RPC request for an arbitrary declared revision.
///
/// Same shape as [`build_mcp_2026_07_28_request_with_cursor`], but
/// `protocol_version` is emitted verbatim. The Auditor uses this when it
/// re-emits a request on the client's behalf (tools/list pagination,
/// list_changed revalidation) so a declared `_meta` revision is preserved
/// instead of being rewritten to `2026-07-28`.
pub fn build_meta_request_with_cursor(
    id: i64,
    method: &str,
    cursor: Option<&str>,
    protocol_version: &str,
) -> String {
    nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", id)?;
        f.member("method", method)?;
        f.member(
            "params",
            nojson::object(|p| {
                if let Some(c) = cursor {
                    p.member("cursor", c)?;
                }
                p.member(
                    "_meta",
                    nojson::object(|m| {
                        m.member(META_PROTOCOL_VERSION, protocol_version)?;
                        m.member(META_CLIENT_CAPABILITIES, nojson::object(|_c| Ok(())))?;
                        m.member(
                            META_CLIENT_INFO,
                            nojson::object(|info| {
                                info.member("name", CLIENT_NAME)?;
                                info.member("version", env!("CARGO_PKG_VERSION"))
                            }),
                        )
                    }),
                )
            }),
        )
    })
    .to_string()
}

/// Build a `2025-11-25` `initialize` request.
pub fn build_mcp_2025_11_25_initialize(id: i64) -> String {
    nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", id)?;
        f.member("method", "initialize")?;
        f.member(
            "params",
            nojson::object(|p| {
                p.member("protocolVersion", MCP_VERSION_2025_11_25)?;
                p.member("capabilities", nojson::object(|_c| Ok(())))?;
                p.member(
                    "clientInfo",
                    nojson::object(|info| {
                        info.member("name", CLIENT_NAME)?;
                        info.member("version", env!("CARGO_PKG_VERSION"))
                    }),
                )
            }),
        )
    })
    .to_string()
}

/// Build the `2025-11-25` `notifications/initialized` notification.
pub fn build_initialized_notification() -> String {
    nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("method", "notifications/initialized")
    })
    .to_string()
}

/// Build a `2025-11-25` `tools/list` request (no `_meta`, no params).
pub fn build_mcp_2025_11_25_tools_list(id: i64) -> String {
    build_mcp_2025_11_25_tools_list_with_cursor(id, None)
}

/// Build a `2025-11-25` `tools/list` request with optional pagination `cursor`.
pub fn build_mcp_2025_11_25_tools_list_with_cursor(id: i64, cursor: Option<&str>) -> String {
    nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", id)?;
        f.member("method", "tools/list")?;
        if let Some(c) = cursor {
            f.member("params", nojson::object(|p| p.member("cursor", c)))?;
        }
        Ok(())
    })
    .to_string()
}

pub fn jsonrpc_error_from_value(value: nojson::RawJsonValue<'_, '_>) -> Option<JsonRpcError> {
    let error = value.to_member("error").ok()?.optional()?;
    let code = error
        .to_member("code")
        .ok()?
        .optional()?
        .as_raw_str()
        .parse::<i64>()
        .ok()?;
    let message = error
        .to_member("message")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.as_string_str().ok())
        .unwrap_or("error")
        .to_string();
    let data = error.to_member("data").ok().and_then(|m| m.optional());
    let supported = data
        .and_then(|d| d.to_member("supported").ok())
        .and_then(|m| m.optional())
        .map(parse_string_array)
        .unwrap_or_default();
    let requested = data
        .and_then(|d| d.to_member("requested").ok())
        .and_then(|m| m.optional())
        .and_then(|v| v.as_string_str().ok())
        .map(str::to_string);
    Some(JsonRpcError {
        code,
        message,
        supported,
        requested,
    })
}

fn parse_string_array(value: nojson::RawJsonValue<'_, '_>) -> Vec<String> {
    let Ok(arr) = value.to_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        if let Ok(s) = item.as_string_str() {
            out.push(s.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_versions_are_explicit() {
        assert_eq!(SUPPORTED_PROTOCOL_VERSIONS, ["2026-07-28", "2025-11-25"]);
        assert_eq!(
            SupportedProtocolVersion::parse("2026-07-28"),
            Some(SupportedProtocolVersion::Mcp2026July28)
        );
        assert_eq!(
            SupportedProtocolVersion::parse("2025-11-25"),
            Some(SupportedProtocolVersion::Mcp2025November25)
        );
    }

    #[test]
    fn unknown_versions_are_not_implicitly_supported() {
        assert_eq!(SupportedProtocolVersion::parse("2026-08-01"), None);
        assert_eq!(SupportedProtocolVersion::parse("2025-06-18"), None);
    }

    #[test]
    fn test_mcp_reserved_error_range() {
        assert!(is_mcp_reserved_error(-32022));
        assert!(is_mcp_reserved_error(-32020));
        assert!(is_mcp_reserved_error(-32099));
        assert!(!is_mcp_reserved_error(-32601));
        assert!(!is_mcp_reserved_error(-32602));
        assert!(!is_mcp_reserved_error(-32001));
        assert!(!is_mcp_reserved_error(-32019));
    }

    #[test]
    fn test_classify_discover_result() {
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"capabilities":{"tools":{}},"ttlMs":0,"cacheScope":"private"}}"#;
        match classify_probe_line(line) {
            ProbeClassification::Mcp2026July28Discover { supported_versions } => {
                assert_eq!(supported_versions, vec!["2026-07-28".to_string()]);
            }
            other => panic!("expected Mcp2026July28Discover, got {other:?}"),
        }
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::UseMcp2026July28
        );
    }

    #[test]
    fn test_classify_minus_32022_for_2026_07_28() {
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28"],"requested":"1900-01-01"}}}"#;
        match classify_probe_line(line) {
            ProbeClassification::Mcp2026July28Error {
                code,
                supported,
                requested,
            } => {
                assert_eq!(code, UNSUPPORTED_PROTOCOL_VERSION);
                assert_eq!(supported, vec!["2026-07-28".to_string()]);
                assert_eq!(requested.as_deref(), Some("1900-01-01"));
            }
            other => panic!("expected Mcp2026July28Error, got {other:?}"),
        }
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::UseMcp2026July28
        );
    }

    #[test]
    fn test_empty_supported_versions_falls_back_to_2025_11_25() {
        // A bare `{"result":{}}` carries no supportedVersions — that is not
        // an endorsement of 2026-07-28, so the probe falls back to 2025-11-25.
        assert_eq!(
            classification_to_outcome(classify_probe_line(
                r#"{"jsonrpc":"2.0","id":1,"result":{}}"#
            )),
            VersionProbeOutcome::TryMcp2025November25
        );
        // An explicit empty list behaves the same way.
        assert_eq!(
            classification_to_outcome(classify_probe_line(
                r#"{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":[]}}"#
            )),
            VersionProbeOutcome::TryMcp2025November25
        );
    }

    #[test]
    fn test_future_version_is_not_implicitly_supported() {
        let line = r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"complete","supportedVersions":["2026-08-01"]}}"#;
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::Unsupported {
                server_versions: vec!["2026-08-01".to_string()]
            }
        );
    }

    #[test]
    fn test_error_without_supported_list_falls_back_to_2025_11_25() {
        // A -32022 carrying no `data.supported` is inconclusive, matching
        // the empty `supportedVersions` handling in the discover branch.
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version"}}"#;
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::TryMcp2025November25
        );
        // An explicit empty list behaves the same way.
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":[]}}}"#;
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::TryMcp2025November25
        );
    }

    #[test]
    fn test_probe_can_select_explicit_2025_11_25_support() {
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2025-11-25"],"requested":"2026-07-28"}}}"#;
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::TryMcp2025November25
        );
    }

    #[test]
    fn test_classify_method_not_found_tries_2025_11_25() {
        let line =
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"Method not found"}}"#;
        assert_eq!(
            classify_probe_line(line),
            ProbeClassification::TryMcp2025November25
        );
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::TryMcp2025November25
        );
    }

    #[test]
    fn test_reserved_error_without_32022_falls_back() {
        // An MCP-reserved error that is not UnsupportedProtocolVersion
        // carries no negotiated version data — even when `data.supported`
        // mentions 2026-07-28, it must not select that revision.
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32030,"message":"Unknown MCP error","data":{"supported":["2026-07-28"]}}}"#;
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::TryMcp2025November25
        );
    }

    #[test]
    fn test_unsupported_version_with_unknown_versions_is_unsupported() {
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-08-01"],"requested":"2026-07-28"}}}"#;
        assert_eq!(
            classification_to_outcome(classify_probe_line(line)),
            VersionProbeOutcome::Unsupported {
                server_versions: vec!["2026-08-01".to_string()]
            }
        );
    }

    #[test]
    fn test_classify_invalid_params_tries_2025_11_25() {
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"Invalid params"}}"#;
        assert_eq!(
            classify_probe_line(line),
            ProbeClassification::TryMcp2025November25
        );
    }

    #[test]
    fn test_classify_garbage_tries_2025_11_25() {
        assert_eq!(
            classify_probe_line("not json"),
            ProbeClassification::TryMcp2025November25
        );
        assert_eq!(
            classify_probe_line(""),
            ProbeClassification::TryMcp2025November25
        );
    }

    #[test]
    fn test_build_2026_07_28_request_has_required_meta() {
        let req = build_mcp_2026_07_28_request(1, "server/discover");
        assert!(req.contains("\"method\":\"server/discover\""));
        assert!(req.contains(META_PROTOCOL_VERSION));
        assert!(req.contains(MCP_VERSION_2026_07_28));
        assert!(req.contains(META_CLIENT_CAPABILITIES));
        assert!(req.contains(META_CLIENT_INFO));
        assert!(req.contains(CLIENT_NAME));
        let parsed = nojson::RawJson::parse(&req).expect("valid JSON");
        let params = parsed
            .value()
            .to_member("params")
            .unwrap()
            .required()
            .unwrap();
        let meta = params.to_member("_meta").unwrap().required().unwrap();
        let caps = meta
            .to_member(META_CLIENT_CAPABILITIES)
            .unwrap()
            .required()
            .unwrap();
        assert!(caps.to_object().is_ok());
    }

    #[test]
    fn test_build_2025_11_25_initialize_shape() {
        let req = build_mcp_2025_11_25_initialize(1);
        assert!(req.contains("\"method\":\"initialize\""));
        assert!(req.contains(MCP_VERSION_2025_11_25));
        assert!(req.contains("clientInfo"));
        assert!(!req.contains(META_PROTOCOL_VERSION));
    }

    #[test]
    fn test_build_initialized_is_notification() {
        let n = build_initialized_notification();
        assert!(is_jsonrpc_notification(&n));
        assert!(n.contains("notifications/initialized"));
        assert!(!n.contains("\"id\""));
    }

    #[test]
    fn test_build_2025_11_25_tools_list_has_no_meta() {
        let req = build_mcp_2025_11_25_tools_list(2);
        assert!(req.contains("\"method\":\"tools/list\""));
        assert!(!req.contains("_meta"));
    }

    #[test]
    fn test_parse_jsonrpc_error_supported() {
        let line = r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-08-01"],"requested":"2026-07-28"}}}"#;
        let err = parse_jsonrpc_error(line).expect("error");
        assert_eq!(err.code, UNSUPPORTED_PROTOCOL_VERSION);
        assert_eq!(err.supported, vec!["2026-08-01".to_string()]);
        assert_eq!(err.requested.as_deref(), Some("2026-07-28"));
    }

    #[test]
    fn test_jsonrpc_id_and_result_helpers() {
        let result_line = r#"{"jsonrpc":"2.0","id":7,"result":{"protocolVersion":"2025-11-25"}}"#;
        assert_eq!(jsonrpc_id_as_i64(result_line), Some(7));
        assert!(jsonrpc_has_result(result_line));
        assert_eq!(
            parse_initialize_protocol_version(result_line).as_deref(),
            Some("2025-11-25")
        );
        let notif = r#"{"jsonrpc":"2.0","method":"notifications/progress"}"#;
        assert!(is_jsonrpc_notification(notif));
        assert_eq!(jsonrpc_id_as_i64(notif), None);
    }

    #[test]
    fn version_and_step_display_and_exhaustive() {
        for version in [
            SupportedProtocolVersion::Mcp2026July28,
            SupportedProtocolVersion::Mcp2025November25,
        ] {
            match version {
                SupportedProtocolVersion::Mcp2026July28 => {
                    assert_eq!(version.to_string(), "2026-07-28");
                }
                SupportedProtocolVersion::Mcp2025November25 => {
                    assert_eq!(version.to_string(), "2025-11-25");
                }
            }
        }
        for step in [
            ProtocolStep::Probe,
            ProtocolStep::Initialize,
            ProtocolStep::Initialized,
            ProtocolStep::ToolsList,
        ] {
            match step {
                ProtocolStep::Probe => assert!(step.to_string().contains("probe")),
                ProtocolStep::Initialize => assert_eq!(step.to_string(), "initialize"),
                ProtocolStep::Initialized => {
                    assert_eq!(step.to_string(), "notifications/initialized");
                }
                ProtocolStep::ToolsList => assert_eq!(step.to_string(), "tools/list"),
            }
        }
    }
}
