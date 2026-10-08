use super::schema_validator;
use super::session::SessionState;
use crate::policy::{InputResponsesMode, Policy, ResolvedInputResponses, SideEffect, ToolPolicy};
use crate::protocol::{MCP_VERSION_2025_11_25, MCP_VERSION_2026_07_28, META_PROTOCOL_VERSION};

mod sub_policy;
mod targets;

pub use targets::{extract_deputy_use_targets, extract_fs_targets, request_has_host_or_url};

/// Maximum accepted `params.requestState` UTF-8 byte length.
///
/// `requestState` is an opaque client-echoed blob
/// ([MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)).
/// The Auditor never parses HMAC/AEAD or other structure. Oversized values are
/// rejected fail-secure so a retry cannot DoS the proxy.
pub const REQUEST_STATE_MAX_BYTES: usize = 65_536;

/// Represents a policy violation when a tool call is not allowed.
#[derive(Debug)]
pub struct PolicyViolation {
    pub tool_name: String,
    pub reason: String,
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tool '{}': {}", self.tool_name, self.reason)
    }
}

impl PolicyViolation {
    /// The user-space validation category this violation belongs to, if
    /// the refusal came from input validation rather than a policy rule:
    /// `validation.path_traversal` for the session/schema path checks,
    /// `validation.argument_invalid` for `args_schema` rejections. The
    /// classification keys on the reason prefixes this module and
    /// [`super::schema_validator`] produce — it is a schema-side
    /// labeling of our own strings, not a guess at upstream text.
    pub fn validation_kind(&self) -> Option<crate::audit_log::EventType> {
        if self.reason.contains("path traversal") {
            Some(crate::audit_log::EventType::ValidationPathTraversal)
        } else if self.reason.starts_with("schema validation failed:") {
            Some(crate::audit_log::EventType::ValidationArgumentInvalid)
        } else {
            None
        }
    }
}
/// Result of a successful policy check, carrying sub-policy metadata.
#[derive(Debug, Default)]
pub struct CheckPass {
    /// Which sub-policy was applied (e.g. `"tool:read_file"` when a tool-specific
    /// policy matched, or `None` for global-only / non-tools/call).
    pub sub_policy: Option<String>,
    /// Audit-only notes (MRTR `requestState` presence, `_meta` version, inspect).
    /// Never used as policy input.
    pub audit_notes: Vec<String>,
}

/// Maximum JSON nesting depth accepted by the Auditor.
pub const MAX_JSON_NESTING: u32 = 64;

/// Recursively check for duplicate object keys in a RawJsonValue.
pub(crate) fn check_duplicate_keys_recursively(
    val: nojson::RawJsonValue<'_, '_>,
) -> Result<(), PolicyViolation> {
    check_duplicate_keys_at_depth(val, 0)
}

fn check_duplicate_keys_at_depth(
    val: nojson::RawJsonValue<'_, '_>,
    depth: u32,
) -> Result<(), PolicyViolation> {
    if depth > MAX_JSON_NESTING {
        return Err(PolicyViolation {
            tool_name: "<unknown>".to_string(),
            reason: format!("JSON nesting exceeds {MAX_JSON_NESTING} levels"),
        });
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            let mut seen = std::collections::HashSet::new();
            let obj_iter = val.to_object().map_err(|e| PolicyViolation {
                tool_name: "<unknown>".to_string(),
                reason: format!("failed to parse JSON object members: {e}"),
            })?;
            for (k, v) in obj_iter {
                let key = k
                    .to_unquoted_string_str()
                    .map_err(|e| PolicyViolation {
                        tool_name: "<unknown>".to_string(),
                        reason: format!("invalid object key encoding: {e}"),
                    })?
                    .into_owned();

                if !seen.insert(key.clone()) {
                    return Err(PolicyViolation {
                        tool_name: "<unknown>".to_string(),
                        reason: format!("duplicate key '{key}' in JSON-RPC request"),
                    });
                }
                check_duplicate_keys_at_depth(v, depth + 1)?;
            }
        }
        nojson::JsonValueKind::Array => {
            let arr_iter = val.to_array().map_err(|e| PolicyViolation {
                tool_name: "<unknown>".to_string(),
                reason: format!("failed to parse JSON array: {e}"),
            })?;
            for elem in arr_iter {
                check_duplicate_keys_at_depth(elem, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Whether `policy.tools` lists `name` with `allowed` set.
///
/// This single predicate drives both `tools/call` admission in
/// [`check_request`] and the `tools/list` visibility filter in
/// `proxy_tools_list`: a tool the client may not call is a tool the client
/// must not see.
pub fn tool_is_allowed(policy: &Policy, name: &str) -> bool {
    policy.tools.iter().any(|t| t.name == name && t.allowed)
}

/// Check a JSON-RPC request line against the policy.
///
/// - If the line is not valid JSON, it is rejected as a policy violation.
/// - If the method is not `"tools/call"`, it passes through (`Ok(CheckPass)`).
///   That includes MCP `2025-11-25` `initialize`, MCP `2026-07-28` `_meta`
///   envelopes, and non-tools methods.
/// - If the method is `"tools/call"`, checks `params.name` against `policy.tools`.
///   MRTR retries use a new JSON-RPC `id` but the same method + tool name, so
///   they hit this path again (allowlist is never skipped).
/// - Tool-specific sub-policies (fs, network) are checked against request arguments.
/// - `params.requestState` is never interpreted; only an optional size cap applies.
/// - `params.inputResponses` is gated by [`InputResponsesMode`] (secure default
///   denies when `args_schema` is configured).
/// - Unknown tools (not in policy) are denied (fail-secure default deny).
pub fn check_request(line: &str, policy: &Policy) -> Result<CheckPass, PolicyViolation> {
    let json = match nojson::RawJson::parse(line) {
        Ok(j) => j,
        Err(e) => {
            return Err(PolicyViolation {
                tool_name: "<unknown>".to_string(),
                reason: format!("invalid JSON: {e}"),
            });
        }
    };

    // Envelope validation: Must be a JSON Object (reject batch requests / non-objects)
    if json.value().kind() != nojson::JsonValueKind::Object {
        return Err(PolicyViolation {
            tool_name: "<unknown>".to_string(),
            reason: "request must be a JSON object (batch requests are not supported)".to_string(),
        });
    }

    // Check for duplicate keys in all nested objects across the entire JSON-RPC request
    check_duplicate_keys_recursively(json.value())?;

    // Iterate through object members to extract method
    let mut method_opt: Option<String> = None;

    let obj_iter = json.value().to_object().map_err(|e| PolicyViolation {
        tool_name: "<unknown>".to_string(),
        reason: format!("failed to parse JSON object members: {e}"),
    })?;

    for (k_val, v_val) in obj_iter {
        let key = k_val
            .to_unquoted_string_str()
            .map_err(|e| PolicyViolation {
                tool_name: "<unknown>".to_string(),
                reason: format!("invalid object key encoding: {e}"),
            })?
            .into_owned();

        if key == "method" {
            let m_str = v_val
                .to_unquoted_string_str()
                .map_err(|_| PolicyViolation {
                    tool_name: "<unknown>".to_string(),
                    reason: "'method' field must be a valid JSON string".to_string(),
                })?
                .into_owned();
            method_opt = Some(m_str);
        }
    }

    let mut audit_notes = protocol_version_audit_notes(&json);

    // Step 1: Check method field
    let is_tools_call = method_opt.as_deref() == Some("tools/call");

    if !is_tools_call {
        return Ok(CheckPass {
            sub_policy: None,
            audit_notes,
        });
    }

    // Step 2: Extract params.name as an owned String
    let tool_name = extract_tool_name(&json)?;

    // Step 3-6: Check against policy (including MRTR retries with a new JSON-RPC id)
    if !tool_is_allowed(policy, &tool_name) {
        let reason = if policy.tools.iter().any(|t| t.name == tool_name) {
            "tool is not allowed"
        } else {
            "tool not found in policy (default deny)"
        };
        return Err(PolicyViolation {
            tool_name,
            reason: reason.to_string(),
        });
    }

    let tool = match policy
        .tools
        .iter()
        .find(|t| t.name == tool_name && t.allowed)
    {
        Some(tool) => tool,
        // Unreachable: `tool_is_allowed` just proved a listed, allowed entry
        // exists (duplicate tool names are rejected at policy load).
        None => {
            return Err(PolicyViolation {
                tool_name,
                reason: "tool not found in policy (default deny)".to_string(),
            });
        }
    };

    // Step 4: Schema validation (if args_schema is defined)
    if let Some(ref schema_ref) = tool.args_schema {
        validate_tool_args(&json, &tool_name, schema_ref)?;
    }

    // Step 5: MRTR siblings of `arguments` — never feed requestState to schema
    check_request_state(&json, &tool_name, &mut audit_notes)?;
    check_input_responses(&json, tool, &tool_name, &mut audit_notes)?;

    // Step 6: Tool-specific sub-policy checks (fs, network)
    let has_sub_policy = sub_policy::check_tool_sub_policy(&json, tool, policy)?;

    let sub_policy = if has_sub_policy {
        Some(format!("tool:{}", tool_name))
    } else {
        None
    };

    Ok(CheckPass {
        sub_policy,
        audit_notes,
    })
}

/// Exact protocol-version classification for audit visibility only.
/// The Auditor never rewrites `_meta` or `initialize` and does not reject an
/// otherwise allowed request solely because the version is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestProtocolVersion {
    Mcp2026July28,
    Mcp2025November25,
    Other,
    Unspecified,
}

/// Classify a client→server line without mutating it.
pub fn classify_request_protocol_version(line: &str) -> RequestProtocolVersion {
    let Ok(json) = nojson::RawJson::parse(line) else {
        return RequestProtocolVersion::Unspecified;
    };
    match declared_protocol_version(&json) {
        Some(MCP_VERSION_2026_07_28) => RequestProtocolVersion::Mcp2026July28,
        Some(MCP_VERSION_2025_11_25) => RequestProtocolVersion::Mcp2025November25,
        Some(_) => RequestProtocolVersion::Other,
        None => RequestProtocolVersion::Unspecified,
    }
}

fn declared_protocol_version<'a>(json: &'a nojson::RawJson<'a>) -> Option<&'a str> {
    params_member(json, "_meta")
        .and_then(|meta| meta.to_member(META_PROTOCOL_VERSION).ok()?.optional())
        .and_then(|value| value.as_string_str().ok())
        .or_else(|| {
            params_member(json, "protocolVersion").and_then(|value| value.as_string_str().ok())
        })
}

fn protocol_version_audit_notes(json: &nojson::RawJson<'_>) -> Vec<String> {
    let mut notes = Vec::new();
    if let Some(version) = declared_protocol_version(json) {
        notes.push(format!("protocolVersion={version}"));
    }
    notes
}

fn params_member<'a>(
    json: &'a nojson::RawJson<'a>,
    key: &str,
) -> Option<nojson::RawJsonValue<'a, 'a>> {
    json.value()
        .to_member("params")
        .ok()?
        .optional()?
        .to_member(key)
        .ok()?
        .optional()
}

/// Size-cap only. Contents are never parsed as structured policy input.
fn check_request_state(
    json: &nojson::RawJson<'_>,
    tool_name: &str,
    audit_notes: &mut Vec<String>,
) -> Result<(), PolicyViolation> {
    let Some(value) = params_member(json, "requestState") else {
        return Ok(());
    };

    let size = request_state_byte_len(value);
    if size > REQUEST_STATE_MAX_BYTES {
        return Err(PolicyViolation {
            tool_name: tool_name.to_string(),
            reason: format!(
                "requestState exceeds size cap ({size} > {REQUEST_STATE_MAX_BYTES} bytes)"
            ),
        });
    }

    audit_notes.push(format!("requestState present ({size} bytes)"));
    Ok(())
}

/// `params.requestState` byte length when it exceeds
/// [`REQUEST_STATE_MAX_BYTES`]; `None` when absent or within the cap.
/// The generic request path applies the cap to methods `check_request`
/// never sees (MRTR retries on `resources/read` / `prompts/get`, …).
pub(crate) fn request_state_over_cap(line: &str) -> Option<usize> {
    let json = nojson::RawJson::parse(line.trim()).ok()?;
    let size = request_state_byte_len(params_member(&json, "requestState")?);
    (size > REQUEST_STATE_MAX_BYTES).then_some(size)
}

/// Byte length of a `requestState` member — the string content, or the
/// raw JSON text when the value is not a string.
pub(crate) fn request_state_byte_len(value: nojson::RawJsonValue<'_, '_>) -> usize {
    if let Ok(s) = value.as_string_str() {
        s.len()
    } else {
        // Unexpected type: still do not interpret; cap the raw JSON text.
        value.as_raw_str().len()
    }
}

fn check_input_responses(
    json: &nojson::RawJson<'_>,
    tool: &ToolPolicy,
    tool_name: &str,
    audit_notes: &mut Vec<String>,
) -> Result<(), PolicyViolation> {
    if params_member(json, "inputResponses").is_none() {
        return Ok(());
    }

    let resolved = tool.input_responses.resolve(tool.has_security_contract());
    match resolved {
        ResolvedInputResponses::Deny => Err(PolicyViolation {
            tool_name: tool_name.to_string(),
            reason: input_responses_denied_reason(tool.input_responses),
        }),
        ResolvedInputResponses::Allow => Ok(()),
        ResolvedInputResponses::Inspect => {
            audit_notes.push("inputResponses present (inspect)".to_string());
            Ok(())
        }
    }
}

fn input_responses_denied_reason(mode: InputResponsesMode) -> String {
    match mode {
        InputResponsesMode::Auto => {
            "inputResponses denied by secure default (tool has a security contract; \
             set input_responses=\"allow\" or \"inspect\" to opt in)"
                .to_string()
        }
        InputResponsesMode::Deny => "inputResponses denied by tool policy".to_string(),
        InputResponsesMode::Allow | InputResponsesMode::Inspect => {
            "inputResponses denied".to_string()
        }
    }
}
/// Opt-in trajectory check. No-op when `policy.trajectory` is false / omitted.
///
/// Uses the last successful `tools/call` side_effect from `session`. Does not
/// read MRTR `requestState`.
pub fn check_trajectory(
    line: &str,
    policy: &Policy,
    session: &SessionState,
) -> Result<(), PolicyViolation> {
    if !policy.trajectory {
        return Ok(());
    }
    let json = match nojson::RawJson::parse(line) {
        Ok(j) => j,
        Err(e) => {
            return Err(PolicyViolation {
                tool_name: "<unknown>".to_string(),
                reason: format!("invalid JSON: {e}"),
            });
        }
    };
    let tool_name = extract_tool_name(&json)?;
    let next_side_effect = policy
        .tools
        .iter()
        .find(|t| t.name == tool_name)
        .and_then(|t| t.side_effect.as_deref())
        .and_then(|raw| SideEffect::parse(raw).ok());
    let has_host_or_url = request_has_host_or_url(line);
    session
        .check_trajectory(
            &policy.trajectory_rules,
            &tool_name,
            next_side_effect,
            has_host_or_url,
        )
        .map_err(|reason| PolicyViolation { tool_name, reason })
}

/// Look up a tool's documented `side_effect` for trajectory bookkeeping.
pub fn tool_side_effect(policy: &Policy, tool_name: &str) -> Option<SideEffect> {
    policy
        .tools
        .iter()
        .find(|t| t.name == tool_name)
        .and_then(|t| t.side_effect.as_deref())
        .and_then(|raw| SideEffect::parse(raw).ok())
}
fn validate_tool_args(
    json: &nojson::RawJson<'_>,
    tool_name: &str,
    schema_ref: &str,
) -> Result<(), PolicyViolation> {
    let schema_str = schema_validator::resolve_schema(schema_ref).map_err(|e| PolicyViolation {
        tool_name: tool_name.to_string(),
        reason: e,
    })?;

    let arguments = json
        .value()
        .to_member("params")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|p| p.to_member("arguments").ok())
        .and_then(|m| m.optional())
        .ok_or_else(|| PolicyViolation {
            tool_name: tool_name.to_string(),
            reason: "tools/call missing params.arguments for schema validation".to_string(),
        })?;

    schema_validator::validate_arguments(arguments, &schema_str).map_err(|e| PolicyViolation {
        tool_name: tool_name.to_string(),
        reason: format!("schema validation failed: {e}"),
    })
}

fn extract_tool_name(json: &nojson::RawJson<'_>) -> Result<String, PolicyViolation> {
    let params = json
        .value()
        .to_member("params")
        .ok()
        .and_then(|m| m.optional())
        .ok_or_else(|| PolicyViolation {
            tool_name: "<unknown>".to_string(),
            reason: "tools/call without params".to_string(),
        })?;

    let name_str = params
        .to_member("name")
        .ok()
        .and_then(|m| m.optional())
        .ok_or_else(|| PolicyViolation {
            tool_name: "<unknown>".to_string(),
            reason: "tools/call without params.name".to_string(),
        })?
        .to_unquoted_string_str()
        .map_err(|_| PolicyViolation {
            tool_name: "<unknown>".to_string(),
            reason: "params.name is not a string".to_string(),
        })?;

    Ok(name_str.into_owned())
}

#[cfg(test)]
mod tests;
