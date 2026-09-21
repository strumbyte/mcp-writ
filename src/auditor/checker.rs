use super::schema_validator;
use super::session::SessionState;
use crate::legislator::protocol::{
    MCP_VERSION_2025_11_25, MCP_VERSION_2026_07_28, META_PROTOCOL_VERSION,
};
use crate::policy::host::{extract_host_from_url, normalize_policy_host};
use crate::policy::{InputResponsesMode, Policy, ResolvedInputResponses, SideEffect, ToolPolicy};

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

fn reject_if_secret_overlay(tool: &ToolPolicy, path: &str) -> Result<(), PolicyViolation> {
    match super::secret_paths::overlay_denies(path) {
        Ok(()) => Ok(()),
        Err(reason) => Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason,
        }),
    }
}

fn apply_secret_overlay(
    tool: &ToolPolicy,
    extracted: &ExtractedTargets,
) -> Result<(), PolicyViolation> {
    for path in &extracted.paths {
        reject_if_secret_overlay(tool, path)?;
    }
    for url in &extracted.urls {
        if secret_overlay_applies_to_url(url) {
            reject_if_secret_overlay(tool, url)?;
        }
    }
    Ok(())
}

/// Overlay is for filesystem arguments (`file:`, opaque `file:`, dirty
/// schemes, non-network strings). Ordinary `http(s):` URLs stay on the
/// network policy path.
fn secret_overlay_applies_to_url(url: &str) -> bool {
    crate::pathutil::starts_with_file_scheme(url)
        || crate::pathutil::is_opaque_file_uri(url)
        || crate::pathutil::uri_scheme_slot_is_dirty(url)
        || !crate::pathutil::looks_like_network_target(url)
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
    let has_sub_policy = check_tool_sub_policy(&json, tool, policy)?;

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

fn request_state_byte_len(value: nojson::RawJsonValue<'_, '_>) -> usize {
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

/// Check tool-specific sub-policies (fs paths, network hosts) against request arguments,
/// and enforce global network denials.
/// Returns `true` if any sub-policy was evaluated.
fn check_tool_sub_policy(
    json: &nojson::RawJson<'_>,
    tool: &ToolPolicy,
    policy: &Policy,
) -> Result<bool, PolicyViolation> {
    let mut has_sub = false;
    let extracted = collect_argument_targets(json);

    if crate::policy::SideEffect::parse(tool.side_effect.as_deref().unwrap_or("")).ok()
        == Some(crate::policy::SideEffect::ReadOnly)
        && (!extracted.hosts.is_empty() || !extracted.urls.is_empty())
    {
        return Err(PolicyViolation {
            tool_name: tool.name.clone(),
            reason: "side_effect=\"read_only\" forbids host/URL arguments".to_string(),
        });
    }

    if let Some(ref fs_policy) = tool.fs {
        has_sub = true;
        let fs_restricted = fs_policy.allow_specified
            || fs_policy.require_path.is_some()
            || !fs_policy.allowed_paths.is_empty()
            || !fs_policy.denied_paths.is_empty();
        if fs_restricted {
            if extracted.paths.is_empty() && !fs_policy.allows_pathless_call() {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: "filesystem-restricted tool is missing a path target \
                             (checked path/file/uri and nested string fields)"
                        .to_string(),
                });
            }
            for path in &extracted.paths {
                authorize_one_path(tool, fs_policy, path)?;
            }
        }
    }
    // Overlay beats explicit allow. Also inspect URL-classified values:
    // percent-encoded `file:` (`%66ile://…`) must not skip path extraction.
    if policy.fs.secret_overlay {
        apply_secret_overlay(tool, &extracted)?;
        if !extracted.paths.is_empty() || !extracted.urls.is_empty() {
            has_sub = true;
        }
    }

    let mut hosts: Vec<String> = extracted.hosts.clone();
    for url in &extracted.urls {
        match extract_host_from_url(url) {
            Some(h) => hosts.push(h),
            None => {
                if tool.network.is_some()
                    || !policy.network.outbound.denied_hosts.is_empty()
                    || policy.network.outbound.deny_all_others
                    || !policy.network.outbound.allowed.is_empty()
                {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!(
                            "invalid or unparseable URL '{url}' in network-restricted tool"
                        ),
                    });
                }
            }
        }
    }

    for host in &hosts {
        for denied in &policy.network.outbound.denied_hosts {
            if host_matches(host, denied) {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' denied by global network policy"),
                });
            }
        }
        if policy.network.outbound.deny_all_others && !policy.network.outbound.allowed.is_empty() {
            let allowed = policy
                .network
                .outbound
                .allowed
                .iter()
                .any(|a| host_matches(host, a));
            if !allowed {
                return Err(PolicyViolation {
                    tool_name: tool.name.clone(),
                    reason: format!("host '{host}' not in global outbound allow list"),
                });
            }
        }
    }

    if let Some(ref net_policy) = tool.network {
        has_sub = true;
        // A closed inherited allow-list (deny_all_others, empty allowed) must
        // reject hosts that appear, but must not demand a host on FS-only calls.
        let requires_host_target =
            !net_policy.allowed_hosts.is_empty() || !net_policy.denied_hosts.is_empty();
        if requires_host_target && hosts.is_empty() {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: "network-restricted tool is missing a url/host target \
                         (checked url/host/uri and nested string fields)"
                    .to_string(),
            });
        }
        for host in &hosts {
            for denied in &net_policy.denied_hosts {
                if host_matches(host, denied) {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!("host '{host}' denied by tool network sub-policy"),
                    });
                }
            }
            if net_policy.allow_specified || !net_policy.allowed_hosts.is_empty() {
                let allowed = net_policy
                    .allowed_hosts
                    .iter()
                    .any(|a| host_matches(host, a));
                if !allowed {
                    return Err(PolicyViolation {
                        tool_name: tool.name.clone(),
                        reason: format!("host '{host}' not in tool network allowed hosts"),
                    });
                }
            }
        }
    } else if !hosts.is_empty() && !policy.network.outbound.denied_hosts.is_empty() {
        has_sub = true;
    }

    if tool.syscalls.is_some() {
        has_sub = true;
    }

    Ok(has_sub)
}

struct ExtractedTargets {
    paths: Vec<String>,
    urls: Vec<String>,
    hosts: Vec<String>,
}

/// Filesystem targets from `arguments` and `inputResponses` for deputy checks.
pub fn extract_fs_targets(line: &str) -> Vec<String> {
    let Ok(json) = nojson::RawJson::parse(line) else {
        return Vec::new();
    };
    collect_argument_targets(&json).paths
}

/// True when Auditor host/URL extraction finds a network target in the request.
///
/// Reused by trajectory `deny-next="network"` (same walk as side_effect enforcement).
pub fn request_has_host_or_url(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line) else {
        return false;
    };
    let extracted = collect_argument_targets(&json);
    !extracted.hosts.is_empty() || !extracted.urls.is_empty()
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

fn collect_argument_targets(json: &nojson::RawJson<'_>) -> ExtractedTargets {
    let mut out = ExtractedTargets {
        paths: Vec::new(),
        urls: Vec::new(),
        hosts: Vec::new(),
    };
    if let Some(args) = json
        .value()
        .to_member("params")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|p| p.to_member("arguments").ok()?.optional())
    {
        walk_json_targets(args, "", 0, &mut out);
    }
    if let Some(input_responses) = params_member(json, "inputResponses") {
        walk_json_targets(input_responses, "", 0, &mut out);
    }
    out
}

fn walk_json_targets(
    val: nojson::RawJsonValue<'_, '_>,
    key: &str,
    depth: u32,
    out: &mut ExtractedTargets,
) {
    if depth > MAX_JSON_NESTING {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            if let Ok(obj) = val.to_object() {
                for (k, v) in obj {
                    let key_owned = k
                        .to_unquoted_string_str()
                        .map(|s| s.into_owned())
                        .unwrap_or_default();
                    walk_json_targets(v, &key_owned, depth + 1, out);
                }
            }
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for elem in arr {
                    walk_json_targets(elem, key, depth + 1, out);
                }
            }
        }
        _ => {
            if let Ok(s) = val.to_unquoted_string_str() {
                classify_target_string(key, s.as_ref(), out);
            }
        }
    }
}

fn classify_target_string(key: &str, value: &str, out: &mut ExtractedTargets) {
    // Same Auditor-time normalize as overlay (bounded percent-decode + WHATWG
    // C0 strip + file: → path) so `file\t://` / `%66ile%0A://` become paths.
    let normalized = match crate::pathutil::normalize_fs_argument(value) {
        Ok(n) => n,
        Err(_) => {
            out.paths.push(value.to_string());
            return;
        }
    };

    if crate::pathutil::starts_with_file_scheme(&normalized)
        || crate::pathutil::looks_like_path(&normalized)
    {
        out.paths.push(normalized);
        return;
    }
    // URL-shaped values (including on path/target keys) are network targets.
    // Otherwise `path=https://…` would skip the read_only host/URL check.
    if crate::pathutil::looks_like_network_target(&normalized) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.hosts
                .push(crate::policy::canonicalize_policy_host(&normalized));
        } else {
            out.urls.push(value.to_string());
        }
        return;
    }
    if crate::pathutil::is_path_field_name(key) || crate::pathutil::looks_like_path(value) {
        out.paths.push(normalized);
        return;
    }
    if crate::pathutil::is_network_field_name(key) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.hosts
                .push(crate::policy::canonicalize_policy_host(value));
        } else {
            out.urls.push(value.to_string());
        }
    }
}

fn authorize_one_path(
    tool: &ToolPolicy,
    fs_policy: &crate::policy::FsToolPolicy,
    path: &str,
) -> Result<(), PolicyViolation> {
    let effective = match crate::pathutil::normalize_fs_argument(path) {
        Ok(normalized) => normalized,
        Err(e) => {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!("path '{path}' could not be normalized: {e}"),
            });
        }
    };
    let resolved =
        crate::pathutil::resolve_for_authorization(&effective).map_err(|e| PolicyViolation {
            tool_name: tool.name.clone(),
            reason: format!("path '{path}' could not be resolved: {e}"),
        })?;

    let matches_pattern = |pattern: &str| -> Result<bool, PolicyViolation> {
        let pattern =
            crate::pathutil::resolve_policy_pattern(pattern).map_err(|e| PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!("policy path '{pattern}' could not be resolved: {e}"),
            })?;
        Ok(crate::pathutil::path_matches_lexical(&resolved, &pattern))
    };

    for denied in &fs_policy.denied_paths {
        if matches_pattern(denied)? {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!(
                    "path '{path}' (resolved '{resolved}') denied by tool fs sub-policy"
                ),
            });
        }
    }
    if fs_policy.allow_specified || !fs_policy.allowed_paths.is_empty() {
        let mut allowed = false;
        for pattern in &fs_policy.allowed_paths {
            if matches_pattern(pattern)? {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Err(PolicyViolation {
                tool_name: tool.name.clone(),
                reason: format!(
                    "path '{path}' (resolved '{resolved}') not in tool fs allowed paths"
                ),
            });
        }
    }
    Ok(())
}

/// Normalize a path string by resolving `.` and `..` segments.
#[cfg(test)]
fn normalize_path(path: &str) -> String {
    crate::pathutil::lexical_normalize_str(path)
}

/// Check if a file path matches a policy path pattern.
#[cfg(test)]
fn path_matches(path: &str, pattern: &str) -> bool {
    crate::pathutil::path_matches(path, pattern)
}

/// Check if a hostname matches a policy host pattern.
/// Supports exact match, wildcard suffix (e.g. "*.example.com" matches "sub.example.com"),
/// and normalizes URL/port-formatted patterns (e.g. "https://api.example.com" or "api.example.com:443").
fn host_matches(host: &str, pattern: &str) -> bool {
    let host_lower = crate::policy::canonicalize_policy_host(&normalize_policy_host(host));
    let pat_lower = crate::policy::canonicalize_policy_host(pattern);

    if pat_lower == "*" {
        return true;
    }

    let pat_host = crate::policy::canonicalize_policy_host(&normalize_policy_host(&pat_lower));

    if host_lower == pat_host {
        return true;
    }
    if let Some(suffix) = pat_host.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return host_lower.ends_with(&with_dot);
    }
    false
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
mod tests {
    use super::*;
    use crate::policy::ToolPolicy;

    fn test_policy() -> Policy {
        Policy {
            tools: vec![
                ToolPolicy {
                    name: "read_file".to_string(),
                    allowed: true,
                    args_schema: None,
                    side_effect: None,
                    server: None,
                    fs: None,
                    syscalls: None,
                    network: None,
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
                ToolPolicy {
                    name: "exec_shell".to_string(),
                    allowed: false,
                    args_schema: None,
                    side_effect: None,
                    server: None,
                    fs: None,
                    syscalls: None,
                    network: None,
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn test_allowed_tool_passes() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
        assert!(check_request(line, &policy).is_ok());
    }

    #[test]
    fn test_denied_tool_rejected() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec_shell","arguments":{}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "exec_shell");
    }

    #[test]
    fn test_unknown_tool_rejected() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unknown_tool","arguments":{}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "unknown_tool");
    }

    #[test]
    fn test_non_tools_call_passes_through() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}"#;
        assert!(check_request(line, &policy).is_ok());
    }

    #[test]
    fn test_invalid_json_rejected() {
        let policy = test_policy();
        let err = check_request("not json at all", &policy).unwrap_err();
        assert_eq!(err.tool_name, "<unknown>");
        assert!(err.reason.contains("invalid JSON"));
    }

    #[test]
    fn test_notification_without_method_passes() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","result":{}}"#;
        assert!(check_request(line, &policy).is_ok());
    }

    #[test]
    fn test_tools_call_missing_params() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call"}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "<unknown>");
        assert!(err.reason.contains("without params"));
    }

    #[test]
    fn test_tools_call_missing_params_name() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"arguments":{}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "<unknown>");
        assert!(err.reason.contains("params.name"));
    }

    #[test]
    fn test_tools_call_name_not_string() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":123}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "<unknown>");
        assert!(err.reason.contains("not a string"));
    }

    #[test]
    fn test_empty_policy_denies_all_tools() {
        let policy = Policy::default(); // no tools defined
        let line =
            r#"{"jsonrpc":"2.0","id":13,"method":"tools/call","params":{"name":"anything"}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(err.reason.contains("default deny"));
    }

    #[test]
    fn test_empty_line_rejected() {
        let policy = test_policy();
        let err = check_request("", &policy).unwrap_err();
        assert_eq!(err.tool_name, "<unknown>");
        assert!(err.reason.contains("invalid JSON"));
    }

    // --- Schema validation tests ---

    fn schema_policy() -> Policy {
        Policy {
            tools: vec![
                ToolPolicy {
                    name: "read_file".to_string(),
                    allowed: true,
                    args_schema: Some(
                        r#"{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}"#.to_string()
                    ),
                    side_effect: None,
                    server: None,
                    fs: None,
                    syscalls: None,
                    network: None,
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
                ToolPolicy {
                    name: "no_schema".to_string(),
                    allowed: true,
                    args_schema: None,
                    side_effect: None,
                    server: None,
                    fs: None,
                    syscalls: None,
                    network: None,
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn test_schema_valid_args_pass() {
        let policy = schema_policy();
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/f.txt"}}}"#;
        assert!(check_request(line, &policy).is_ok());
    }

    #[test]
    fn test_schema_missing_required_rejected() {
        let policy = schema_policy();
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("schema validation failed"),
            "got: {}",
            err.reason
        );
        assert!(err.reason.contains("path"), "got: {}", err.reason);
    }

    #[test]
    fn test_schema_wrong_type_rejected() {
        let policy = schema_policy();
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":123}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("should be string"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_schema_additional_property_rejected() {
        let policy = schema_policy();
        let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp","extra":"bad"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("additional property"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_no_schema_still_passes_name_check_only() {
        let policy = schema_policy();
        let line = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"no_schema","arguments":{"anything":"goes"}}}"#;
        assert!(check_request(line, &policy).is_ok());
    }

    #[test]
    fn test_schema_missing_arguments_rejected() {
        let policy = schema_policy();
        let line =
            r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"read_file"}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("params.arguments"),
            "got: {}",
            err.reason
        );
    }

    // --- Tool sub-policy tests ---

    use crate::policy::{FsToolPolicy, ToolNetworkPolicy, ToolSyscallPolicy};

    fn sub_policy_policy() -> Policy {
        Policy {
            tools: vec![
                // Tool with fs sub-policy: only /workspace allowed, /etc denied
                ToolPolicy {
                    name: "read_file".to_string(),
                    allowed: true,
                    args_schema: None,
                    side_effect: None,
                    server: None,
                    fs: Some(FsToolPolicy::new(
                        vec!["/workspace".to_string()],
                        vec!["/etc/secrets".to_string()],
                    )),
                    syscalls: None,
                    network: None,
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
                // Tool with network sub-policy
                ToolPolicy {
                    name: "fetch_url".to_string(),
                    allowed: true,
                    args_schema: None,
                    side_effect: None,
                    server: None,
                    fs: None,
                    syscalls: None,
                    network: Some(ToolNetworkPolicy {
                        allowed_hosts: vec!["api.example.com".to_string()],
                        denied_hosts: vec!["evil.com".to_string()],
                        allow_specified: true,
                    }),
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
                // Tool with no sub-policy (global defaults only)
                ToolPolicy {
                    name: "list_files".to_string(),
                    allowed: true,
                    args_schema: None,
                    side_effect: None,
                    server: None,
                    fs: None,
                    syscalls: None,
                    network: None,
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
                // Tool with syscall sub-policy (metadata only, no request-level check)
                ToolPolicy {
                    name: "exec_cmd".to_string(),
                    allowed: true,
                    args_schema: None,
                    side_effect: None,
                    server: None,
                    fs: None,
                    syscalls: Some(ToolSyscallPolicy {
                        allowed: vec!["read".to_string(), "write".to_string()],
                        denied: vec!["execve".to_string()],
                    }),
                    network: None,
                    input_responses: InputResponsesMode::Auto,
                    input_responses_specified: false,
                    fs_explicit: false,
                    network_explicit: false,
                    syscalls_explicit: false,
                    process_exec_allowed: false,
                    process_explicit: false,
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn test_fs_sub_policy_allowed_path_passes() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/src/main.rs"}}}"#;
        let result = check_request(line, &policy).unwrap();
        assert_eq!(result.sub_policy, Some("tool:read_file".to_string()));
    }

    #[test]
    fn test_fs_sub_policy_denied_path_rejected() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/secrets/key.pem"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("denied by tool fs sub-policy"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_fs_sub_policy_unallowed_path_rejected() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/other.txt"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(
            err.reason.contains("not in tool fs allowed paths"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_fs_sub_policy_no_path_arg_denied() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"content":"hello"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(
            err.reason.contains("missing a path target"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_fs_sub_policy_nested_and_alternate_fields() {
        let policy = sub_policy_policy();
        let nested = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"file":{"path":"/etc/passwd"}}}}"#;
        let err = check_request(nested, &policy).unwrap_err();
        assert!(
            err.reason.contains("not in tool fs allowed paths"),
            "got: {}",
            err.reason
        );

        let allowed = r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"file":"/workspace/ok.txt"}}}"#;
        assert!(check_request(allowed, &policy).is_ok());
    }

    #[test]
    fn test_file_uri_single_slash_is_stripped() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"file:/tmp/a"}}}"#;
        assert_eq!(extract_fs_targets(line), vec!["/tmp/a".to_string()]);

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"FILE:///workspace/ok.txt"}}}"#;
        assert_eq!(
            extract_fs_targets(line),
            vec!["/workspace/ok.txt".to_string()]
        );
    }

    #[test]
    fn test_network_sub_policy_allowed_host_passes() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://api.example.com/data"}}}"#;
        let result = check_request(line, &policy).unwrap();
        assert_eq!(result.sub_policy, Some("tool:fetch_url".to_string()));
    }

    #[test]
    fn test_network_sub_policy_denied_host_rejected() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.com/steal"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "fetch_url");
        assert!(
            err.reason.contains("denied by tool network sub-policy"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_network_sub_policy_unallowed_host_rejected() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://random.io/api"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "fetch_url");
        assert!(
            err.reason.contains("not in tool network allowed hosts"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_network_sub_policy_host_argument_fallback() {
        let policy = sub_policy_policy();
        // Uses "host" argument instead of URL
        let line = r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"fetch_url","arguments":{"host":"api.example.com"}}}"#;
        assert!(check_request(line, &policy).is_ok());
    }

    #[test]
    fn test_no_sub_policy_returns_none() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"list_files","arguments":{}}}"#;
        let result = check_request(line, &policy).unwrap();
        assert_eq!(result.sub_policy, None);
    }

    #[test]
    fn test_sub_policy_metadata_only_returns_sub_policy_tag() {
        // Tool with syscalls sub-policy (no request-level checks, but has_sub = true)
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"exec_cmd","arguments":{"command":"ls"}}}"#;
        let result = check_request(line, &policy).unwrap();
        assert_eq!(result.sub_policy, Some("tool:exec_cmd".to_string()));
    }

    #[test]
    fn test_non_tools_call_returns_no_sub_policy() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}"#;
        let result = check_request(line, &policy).unwrap();
        assert_eq!(result.sub_policy, None);
    }

    // --- Helper function tests ---

    #[test]
    fn test_path_matches_exact() {
        assert!(path_matches("/workspace", "/workspace"));
    }

    #[test]
    fn test_path_matches_prefix() {
        assert!(path_matches("/workspace/src/main.rs", "/workspace"));
    }

    #[test]
    fn test_path_matches_no_partial() {
        // "/workspace2" should NOT match "/workspace"
        assert!(!path_matches("/workspace2", "/workspace"));
    }

    #[test]
    fn test_path_matches_no_match() {
        assert!(!path_matches("/tmp/file", "/workspace"));
    }

    #[test]
    fn test_path_matches_glob_recursive() {
        assert!(path_matches("/workspace/test.txt", "/workspace/**"));
        assert!(path_matches("/workspace/src/main.rs", "/workspace/**"));
        assert!(path_matches("/workspace", "/workspace/**"));
        assert!(!path_matches("/tmp/file", "/workspace/**"));
        assert!(!path_matches("/workspace2/file", "/workspace/**"));
    }

    #[test]
    fn test_path_matches_single_wildcard() {
        assert!(path_matches("/home/user/.ssh/id_rsa", "/home/*/.ssh/**"));
        assert!(path_matches(
            "/home/root/.ssh/known_hosts",
            "/home/*/.ssh/**"
        ));
        assert!(!path_matches("/home/.ssh/id_rsa", "/home/*/.ssh/**"));
    }

    #[test]
    fn test_path_matches_traversal_blocked() {
        // Path traversal: /workspace/../../etc/passwd normalizes to /etc/passwd
        // which must NOT match /workspace
        assert!(!path_matches("/workspace/../../etc/passwd", "/workspace"));
        assert!(!path_matches(
            "/workspace/../../etc/passwd",
            "/workspace/**"
        ));
    }

    #[test]
    fn test_path_matches_traversal_double_dot() {
        // /workspace/../tmp/evil normalizes to /tmp/evil
        assert!(!path_matches("/workspace/../tmp/evil", "/workspace"));
        assert!(!path_matches("/workspace/../tmp/evil", "/workspace/**"));
    }

    #[test]
    fn test_path_matches_traversal_with_dot() {
        // Current dir "." should be ignored
        assert!(path_matches("/workspace/./src/main.rs", "/workspace"));
        assert!(path_matches("/workspace/./src/main.rs", "/workspace/**"));
    }

    #[test]
    fn test_path_matches_traversal_deep() {
        // Deep traversal that escapes allowed directory
        assert!(!path_matches(
            "/workspace/a/b/../../../../etc/shadow",
            "/workspace"
        ));
    }

    #[test]
    fn test_normalize_path_basic() {
        assert_eq!(normalize_path("/workspace/../../etc/passwd"), "/etc/passwd");
        assert_eq!(normalize_path("/workspace/../tmp"), "/tmp");
        assert_eq!(normalize_path("/workspace/./src"), "/workspace/src");
        assert_eq!(normalize_path("/a/b/c/../../d"), "/a/d");
        assert_eq!(normalize_path("/.."), "/");
    }

    #[test]
    fn test_host_matches_exact() {
        assert!(host_matches("example.com", "example.com"));
    }

    #[test]
    fn test_host_matches_wildcard() {
        assert!(host_matches("sub.example.com", "*.example.com"));
    }

    #[test]
    fn test_host_matches_wildcard_no_bare() {
        // "example.com" should NOT match "*.example.com"
        assert!(!host_matches("example.com", "*.example.com"));
    }

    #[test]
    fn test_host_matches_no_match() {
        assert!(!host_matches("other.com", "example.com"));
    }

    #[test]
    fn test_host_matches_wildcard_subdomain_boundary() {
        // CRITICAL: "evilexample.com" must NOT match "*.example.com"
        assert!(!host_matches("evilexample.com", "*.example.com"));
        // But legitimate subdomains should still match
        assert!(host_matches("api.example.com", "*.example.com"));
        assert!(host_matches("deep.sub.example.com", "*.example.com"));
    }

    #[test]
    fn test_fs_denied_takes_priority_over_allowed() {
        // Path matches both allowed and denied - denied should win
        let policy = Policy {
            tools: vec![ToolPolicy {
                name: "read_file".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: Some(FsToolPolicy::new(
                    vec!["/workspace".to_string()],
                    vec!["/workspace/secret".to_string()],
                )),
                syscalls: None,
                network: None,
                input_responses: InputResponsesMode::Auto,
                input_responses_specified: false,
                fs_explicit: false,
                network_explicit: false,
                syscalls_explicit: false,
                process_exec_allowed: false,
                process_explicit: false,
            }],
            ..Default::default()
        };
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/secret/key.pem"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(err.reason.contains("denied"), "got: {}", err.reason);
    }

    #[test]
    fn test_network_wildcard_denied_host() {
        let policy = Policy {
            tools: vec![ToolPolicy {
                name: "fetch_url".to_string(),
                allowed: true,
                args_schema: None,
                side_effect: None,
                server: None,
                fs: None,
                syscalls: None,
                network: Some(ToolNetworkPolicy {
                    allowed_hosts: Vec::new(),
                    denied_hosts: vec!["*.evil.com".to_string()],
                    allow_specified: false,
                }),
                input_responses: InputResponsesMode::Auto,
                input_responses_specified: false,
                fs_explicit: false,
                network_explicit: false,
                syscalls_explicit: false,
                process_exec_allowed: false,
                process_explicit: false,
            }],
            ..Default::default()
        };
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://api.evil.com/steal"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(err.reason.contains("denied"), "got: {}", err.reason);
    }

    // --- MCP 2026-07-28 + 2025-11-25 / MRTR ---

    fn fixture(name: &str) -> String {
        let path = format!("{}/tests/fixtures/mrtr/{name}", env!("CARGO_MANIFEST_DIR"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
    }

    #[test]
    fn test_input_responses_mode_resolve_exhaustive() {
        for mode in [
            InputResponsesMode::Auto,
            InputResponsesMode::Deny,
            InputResponsesMode::Allow,
            InputResponsesMode::Inspect,
        ] {
            let with_schema = mode.resolve(true);
            let without_schema = mode.resolve(false);
            match mode {
                InputResponsesMode::Auto => {
                    assert_eq!(with_schema, ResolvedInputResponses::Deny);
                    assert_eq!(without_schema, ResolvedInputResponses::Allow);
                }
                InputResponsesMode::Deny => {
                    assert_eq!(with_schema, ResolvedInputResponses::Deny);
                    assert_eq!(without_schema, ResolvedInputResponses::Deny);
                }
                InputResponsesMode::Allow => {
                    assert_eq!(with_schema, ResolvedInputResponses::Allow);
                    assert_eq!(without_schema, ResolvedInputResponses::Allow);
                }
                InputResponsesMode::Inspect => {
                    assert_eq!(with_schema, ResolvedInputResponses::Inspect);
                    assert_eq!(without_schema, ResolvedInputResponses::Inspect);
                }
            }
        }
    }

    #[test]
    fn test_mrtr_retry_denied_tool_still_denied() {
        let policy = test_policy();
        let line = fixture("retry_denied_tool.json");
        let err = check_request(&line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "exec_shell");
        assert!(err.reason.contains("not allowed"), "got: {}", err.reason);
    }

    #[test]
    fn test_mrtr_retry_unknown_tool_still_denied() {
        let policy = test_policy();
        let line = r#"{"jsonrpc":"2.0","id":99,"method":"tools/call","params":{"name":"not_listed","arguments":{},"inputResponses":{"e":{"action":"accept"}},"requestState":"opaque"}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(err.reason.contains("default deny"), "got: {}", err.reason);
    }

    #[test]
    fn test_mrtr_retry_allowed_tool_without_schema_passes() {
        let policy = test_policy();
        let line = fixture("mcp_2026_07_28_tools_call_retry.json");
        let pass = check_request(&line, &policy).unwrap();
        assert!(
            pass.audit_notes
                .iter()
                .any(|n| n.contains("requestState present")),
            "notes: {:?}",
            pass.audit_notes
        );
        assert!(
            pass.audit_notes
                .iter()
                .any(|n| n.contains("protocolVersion=2026-07-28")),
            "notes: {:?}",
            pass.audit_notes
        );
    }

    #[test]
    fn test_input_responses_denied_when_args_schema_auto() {
        let policy = schema_policy();
        let line = fixture("mcp_2026_07_28_tools_call_with_input_responses.json");
        let err = check_request(&line, &policy).unwrap_err();
        assert_eq!(err.tool_name, "read_file");
        assert!(err.reason.contains("secure default"), "got: {}", err.reason);
    }

    #[test]
    fn test_input_responses_opt_in_allow_with_schema() {
        let mut policy = schema_policy();
        policy.tools[0].input_responses = InputResponsesMode::Allow;
        let line = fixture("mcp_2026_07_28_tools_call_with_input_responses.json");
        assert!(check_request(&line, &policy).is_ok());
    }

    #[test]
    fn test_input_responses_inspect_with_schema() {
        let mut policy = schema_policy();
        policy.tools[0].input_responses = InputResponsesMode::Inspect;
        let line = fixture("mcp_2026_07_28_tools_call_with_input_responses.json");
        let pass = check_request(&line, &policy).unwrap();
        assert!(
            pass.audit_notes
                .iter()
                .any(|n| n.contains("inputResponses present (inspect)")),
            "notes: {:?}",
            pass.audit_notes
        );
    }

    #[test]
    fn test_input_responses_explicit_deny_without_schema() {
        let mut policy = test_policy();
        policy.tools[0].input_responses = InputResponsesMode::Deny;
        let line = r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":{},"inputResponses":{"e":{"action":"accept"}}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(err.reason.contains("tool policy"), "got: {}", err.reason);
    }

    #[test]
    fn test_request_state_opaque_passthrough_under_cap() {
        let policy = test_policy();
        let line = fixture("mcp_2026_07_28_tools_call_with_request_state.json");
        let pass = check_request(&line, &policy).unwrap();
        assert!(
            pass.audit_notes
                .iter()
                .any(|n| n.contains("requestState present")),
            "notes: {:?}",
            pass.audit_notes
        );
        // Contents must not be treated as a filesystem path / structured input.
        assert!(pass.sub_policy.is_none());
    }

    #[test]
    fn test_request_state_over_size_cap_rejected() {
        let policy = test_policy();
        let huge = "x".repeat(REQUEST_STATE_MAX_BYTES + 1);
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{{"name":"read_file","arguments":{{}},"requestState":"{huge}"}}}}"#
        );
        let err = check_request(&line, &policy).unwrap_err();
        assert!(err.reason.contains("size cap"), "got: {}", err.reason);
    }

    #[test]
    fn test_request_state_does_not_bypass_fs_sub_policy() {
        let policy = sub_policy_policy();
        let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/secrets/key.pem"},"requestState":"eyJwYXRoIjoiL3dvcmtzcGFjZS9va2F5In0"}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(
            err.reason.contains("denied by tool fs sub-policy"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_classify_request_protocol_version() {
        let mcp_2026_07_28 = fixture("mcp_2026_07_28_tools_call_retry.json");
        assert_eq!(
            classify_request_protocol_version(&mcp_2026_07_28),
            RequestProtocolVersion::Mcp2026July28
        );
        assert_eq!(
            classify_request_protocol_version(
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#
            ),
            RequestProtocolVersion::Mcp2025November25
        );
        assert_eq!(
            classify_request_protocol_version(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#),
            RequestProtocolVersion::Unspecified
        );
        assert_eq!(
            classify_request_protocol_version(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-08-01"}}}"#
            ),
            RequestProtocolVersion::Other
        );
    }

    #[test]
    fn test_2025_11_25_initialize_and_2026_07_28_meta_passthrough() {
        let policy = test_policy();
        let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#;
        let init_pass = check_request(init, &policy).unwrap();
        assert!(
            init_pass
                .audit_notes
                .iter()
                .any(|n| n.contains("protocolVersion=2025-11-25")),
            "notes: {:?}",
            init_pass.audit_notes
        );
        let mcp_2026_07_28_list = r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
        let pass = check_request(mcp_2026_07_28_list, &policy).unwrap();
        assert!(
            pass.audit_notes
                .iter()
                .any(|n| n.contains("protocolVersion=2026-07-28")),
            "notes: {:?}",
            pass.audit_notes
        );
    }

    #[test]
    fn test_request_protocol_version_exhaustive() {
        for version in [
            RequestProtocolVersion::Mcp2026July28,
            RequestProtocolVersion::Mcp2025November25,
            RequestProtocolVersion::Other,
            RequestProtocolVersion::Unspecified,
        ] {
            match version {
                RequestProtocolVersion::Mcp2026July28 => {
                    assert_eq!(version, RequestProtocolVersion::Mcp2026July28);
                }
                RequestProtocolVersion::Mcp2025November25 => {
                    assert_eq!(version, RequestProtocolVersion::Mcp2025November25);
                }
                RequestProtocolVersion::Other => {
                    assert_eq!(version, RequestProtocolVersion::Other);
                }
                RequestProtocolVersion::Unspecified => {
                    assert_eq!(version, RequestProtocolVersion::Unspecified);
                }
            }
        }
    }

    #[test]
    fn test_escaped_tools_call_caught() {
        let mut policy = Policy::default();
        policy.tools.push(ToolPolicy::named("exec_shell", false));

        // Unescaped denied method
        let r1 = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"exec_shell","arguments":{}}}"#;
        assert!(check_request(r1, &policy).is_err());

        // Escaped slash
        let r2 = r#"{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"exec_shell","arguments":{}}}"#;
        assert!(check_request(r2, &policy).is_err());

        // Unicode escaped slash
        let r3 = r#"{"jsonrpc":"2.0","id":1,"method":"tools\u002fcall","params":{"name":"exec_shell","arguments":{}}}"#;
        assert!(check_request(r3, &policy).is_err());
    }

    #[test]
    fn test_batch_request_rejected() {
        let policy = test_policy();
        let batch = r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}]"#;
        let err = check_request(batch, &policy).unwrap_err();
        assert!(
            err.reason.contains("batch requests are not supported"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_duplicate_key_rejected() {
        let policy = test_policy();
        let dup = r#"{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"read_file","arguments":{}}}"#;
        let err = check_request(dup, &policy).unwrap_err();
        assert!(err.reason.contains("duplicate key"), "got: {}", err.reason);
    }

    #[test]
    fn test_escaped_arguments_path() {
        let mut policy = Policy::default();
        let mut read = ToolPolicy::named("read_file", true);
        read.fs = Some(FsToolPolicy::new(
            // Narrower than cwd so a Windows drive path joined to cwd cannot
            // accidentally match when the suite is run from `/workspace`.
            vec!["/workspace/src/**".into()],
            vec![],
        ));
        policy.tools = vec![read];

        // Escaped outside path: /etc/\u0070asswd -> /etc/passwd (should be denied)
        let r1 = r#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/\u0070asswd"}}}"#;
        assert!(check_request(r1, &policy).is_err());

        // Escaped windows outside path: C:\\secret.txt (should be denied)
        let r2 = r#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"C:\\secret.txt"}}}"#;
        assert!(check_request(r2, &policy).is_err());
    }

    #[test]
    fn test_url_userinfo_and_wildcards() {
        let mut policy = Policy::default();
        let mut fetch = ToolPolicy::named("fetch", true);
        fetch.network = Some(ToolNetworkPolicy {
            allowed_hosts: vec!["api.example.com".into()],
            denied_hosts: vec![],
            allow_specified: true,
        });
        policy.tools = vec![fetch];

        // Userinfo spoofing: destination is evil.test, should be denied
        let r1 = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://api.example.com:password@evil.test/file"}}}"#;
        assert!(check_request(r1, &policy).is_err());

        // Protocol-relative outside host: evil.test, should be denied
        let r2 = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"//evil.test/file"}}}"#;
        assert!(check_request(r2, &policy).is_err());

        // Single wildcard deny="*"
        policy.tools[0].network = Some(ToolNetworkPolicy {
            allowed_hosts: vec![],
            denied_hosts: vec!["*".into()],
            allow_specified: false,
        });
        let r3 = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://evil.test/file"}}}"#;
        assert!(check_request(r3, &policy).is_err());
    }

    #[test]
    fn test_nested_duplicate_key_rejected() {
        let policy = test_policy();
        // duplicate name in params
        let dup1 = r#"{"method":"tools/call","params":{"name":"read_file","name":"exec_shell","arguments":{}}}"#;
        let err1 = check_request(dup1, &policy).unwrap_err();
        assert!(
            err1.reason.contains("duplicate key 'name'"),
            "got: {}",
            err1.reason
        );

        // duplicate path in arguments
        let dup2 = r#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/file","path":"/etc/passwd"}}}"#;
        let err2 = check_request(dup2, &policy).unwrap_err();
        assert!(
            err2.reason.contains("duplicate key 'path'"),
            "got: {}",
            err2.reason
        );
    }

    #[test]
    fn test_r02_empty_allow_after_deny_blocks_other_resources() {
        let mut policy = Policy::default();
        let mut read = ToolPolicy::named("read_file", true);
        read.fs = Some(FsToolPolicy {
            allowed_paths: vec![],
            read_only_paths: vec![],
            read_write_paths: vec![],
            denied_paths: vec!["/allowed/**".into()],
            allow_specified: true, // Specified but emptied by deny
            require_path: None,
        });
        policy.tools = vec![read];

        let req = r#"{"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/other/file"}}}"#;
        let err = check_request(req, &policy).unwrap_err();
        assert!(
            err.reason.contains("not in tool fs allowed paths"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_r05_url_backslash_host_spoofing() {
        let mut policy = Policy::default();
        let mut fetch = ToolPolicy::named("fetch", true);
        fetch.network = Some(ToolNetworkPolicy {
            allowed_hosts: vec!["api.example.com".into()],
            denied_hosts: vec![],
            allow_specified: true,
        });
        policy.tools = vec![fetch];

        // evil.test\@api.example.com - backslash must not fool host parsing into api.example.com
        let req = r#"{"method":"tools/call","params":{"name":"fetch","arguments":{"url":"https://evil.test\\@api.example.com/"}}}"#;
        assert!(check_request(req, &policy).is_err());
    }

    #[test]
    fn test_r20_host_matches_with_url_and_port() {
        assert!(host_matches("api.example.com", "https://api.example.com"));
        assert!(host_matches("api.example.com", "api.example.com:443"));
        assert!(host_matches("::1", "[::1]"));
        assert!(host_matches("::1", "::1"));
        assert!(host_matches("::1", "https://[::1]/"));
        assert!(!host_matches("1", "::1"));
        assert!(host_matches("sub.example.com", "*.example.com"));
        assert!(!host_matches("evil.test", "https://api.example.com"));
    }

    #[test]
    fn test_s08_url_percent_encoding_and_control_characters() {
        let mut policy = Policy::default();
        let mut fetch = ToolPolicy::named("fetch", true);
        fetch.network = Some(ToolNetworkPolicy {
            allowed_hosts: vec![],
            denied_hosts: vec!["blocked.example".into()],
            allow_specified: false,
        });
        policy.tools = vec![fetch];

        for (url_raw, url_json) in [
            ("https://blocked.example/", "https://blocked.example/"),
            ("https://%62locked.example/", "https://%62locked.example/"),
            ("https://blo\tcked.example/", "https://blo\\tcked.example/"),
            ("https://blo\rcked.example/", "https://blo\\rcked.example/"),
            ("https://blo\ncked.example/", "https://blo\\ncked.example/"),
        ] {
            let req = format!(
                r#"{{"method":"tools/call","params":{{"name":"fetch","arguments":{{"url":"{url_json}"}}}}}}"#
            );
            let err = check_request(&req, &policy).unwrap_err();
            assert!(
                err.reason.contains("denied by tool network sub-policy"),
                "URL '{url_raw}' should be denied by tool network policy, got error: {}",
                err.reason
            );
        }
    }

    #[test]
    fn test_read_only_side_effect_rejects_url_in_path_key() {
        let mut policy = Policy::default();
        let mut tool = ToolPolicy::named("read_file", true);
        tool.side_effect = Some("read_only".to_string());
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"https://evil.example/x"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(
            err.reason.contains("read_only") && err.reason.contains("host/URL"),
            "URL-shaped path key must trigger side_effect reject, got: {}",
            err.reason
        );
    }

    #[test]
    fn test_read_only_side_effect_rejects_url_argument() {
        let mut policy = Policy::default();
        let mut tool = ToolPolicy::named("read_file", true);
        tool.side_effect = Some("read_only".to_string());
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"url":"https://evil.example/x"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(
            err.reason.contains("read_only") && err.reason.contains("host/URL"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_secret_overlay_rejects_uncreated_ssh_under_allow() {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = true;
        let mut tool = ToolPolicy::named("read_file", true);
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/.ssh/id_rsa"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_secret_overlay_rejects_percent_encoded_ssh() {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = true;
        let mut tool = ToolPolicy::named("read_file", true);
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];

        for path in [
            "/workspace/%2essh/id_rsa",
            "/workspace/.%73sh/id_rsa",
            "/workspace/%252essh/id_rsa",
        ] {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{path}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "percent-encoded secret must be denied, path={path} got: {}",
                err.reason
            );
        }
    }

    #[test]
    fn test_secret_overlay_rejects_file_uri_localhost_passwd() {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = true;
        let mut tool = ToolPolicy::named("read_file", true);
        // Allow the reserved file so glob would pass; overlay must still deny.
        tool.fs = Some(FsToolPolicy::new(
            vec!["/workspace/**".into(), "/etc/passwd".into()],
            vec![],
        ));
        policy.tools = vec![tool];

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"file://localhost/etc/passwd"}}}"#;
        let err = check_request(line, &policy).unwrap_err();
        assert!(
            err.reason.contains("secret-path overlay"),
            "file://localhost/etc/passwd must hit overlay, got: {}",
            err.reason
        );
    }

    #[test]
    fn test_file_uri_localhost_extracts_as_fs_path() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"file://localhost/etc/passwd"}}}"#;
        assert_eq!(extract_fs_targets(line), vec!["/etc/passwd".to_string()]);
    }

    fn overlay_on_no_fs_policy() -> Policy {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = true;
        policy.tools = vec![ToolPolicy::named("read_file", true)];
        policy
    }

    #[test]
    fn test_secret_overlay_rejects_percent_encoded_file_scheme_without_fs() {
        let policy = overlay_on_no_fs_policy();
        for uri in [
            "%66ile://localhost/etc/passwd",
            "%66ile://127.0.0.1/etc/passwd",
            "%66ile://localhost/workspace/.ssh/id_rsa",
        ] {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "encoded file: URI must hit overlay (no fs sub-policy), uri={uri} got: {}",
                err.reason
            );
        }
        assert_eq!(
            extract_fs_targets(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"%66ile://localhost/etc/passwd"}}}"#
            ),
            vec!["/etc/passwd".to_string()]
        );
    }

    #[test]
    fn test_secret_overlay_rejects_whatwg_c0_split_file_scheme_without_fs() {
        let policy = overlay_on_no_fs_policy();
        // JSON `\t`/`\n`/`\r` become TAB/LF/CR in the parsed URI.
        let json_escaped = [
            r#"file\t://localhost/etc/passwd"#,
            r#"file\n://localhost/etc/passwd"#,
            r#"file\r://localhost/etc/passwd"#,
        ];
        let literal_or_percent = [
            "file%0A://localhost/etc/passwd",
            "file%09://localhost/etc/passwd",
            "file%0D://localhost/etc/passwd",
            "%66ile%0A://localhost/etc/passwd",
            "file%0B://localhost/etc/passwd",
            "file%0C://localhost/etc/passwd",
            "file%250B://localhost/etc/passwd",
            "file%C2%85://localhost/etc/passwd",
        ];
        for uri in json_escaped.into_iter().chain(literal_or_percent) {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "C0-split file: URI must hit overlay (no fs sub-policy), uri={uri} got: {}",
                err.reason
            );
        }
        assert_eq!(
            extract_fs_targets(
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"uri":"file\t://localhost/etc/passwd"}}}"#
            ),
            vec!["/etc/passwd".to_string()]
        );
    }

    #[test]
    fn test_secret_overlay_rejects_vtab_ff_nel_line_sep_file_scheme_without_fs() {
        let policy = overlay_on_no_fs_policy();
        let uris = [
            "file%0B://localhost/etc/passwd",
            "file%0C://localhost/etc/passwd",
            "file%250B://localhost/etc/passwd",
            "file%C2%85://localhost/etc/passwd",
            "file\u{2028}://localhost/etc/passwd",
            "file\u{2029}://localhost/etc/passwd",
        ];
        for uri in uris {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "extended control/separator file: URI must hit overlay, uri={uri:?} got: {}",
                err.reason
            );
        }
    }

    #[test]
    fn test_secret_overlay_rejects_whitespace_and_nfkc_file_scheme_without_fs() {
        let policy = overlay_on_no_fs_policy();
        let uris = [
            "file\u{00A0}://localhost/etc/passwd",
            "file%C2%A0://localhost/etc/passwd",
            "file%E2%80%82://localhost/etc/passwd",
            "file ://localhost/etc/passwd",
            "file%20://localhost/etc/passwd",
            "\u{FB01}le://localhost/etc/passwd",
            "%EF%BD%86ile://localhost/etc/passwd",
        ];
        for uri in uris {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "whitespace/NFKC file: URI must hit overlay, uri={uri:?} got: {}",
                err.reason
            );
        }
    }

    #[test]
    fn test_secret_overlay_rejects_file_uri_backslash_passwd_without_fs() {
        let policy = overlay_on_no_fs_policy();
        // JSON-escaped `\\` so the parsed URI contains a real backslash.
        let json_uris = [
            r"file://localhost\\etc\\passwd",
            r"file://\\etc\\passwd",
            r"%66ile://localhost\\etc\\passwd",
            r"file://localhost%5Cetc%5Cpasswd",
        ];
        for uri in json_uris {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "backslash file: URI must hit overlay, uri={uri:?} got: {}",
                err.reason
            );
        }
    }

    #[test]
    fn test_secret_overlay_rejects_opaque_file_uri_passwd_without_fs() {
        let policy = overlay_on_no_fs_policy();
        // JSON-escaped `\\` so `file:etc\passwd` is the parsed URI.
        let json_uris = [
            "file:etc/passwd",
            r"file:etc\\passwd",
            "file:./etc/passwd",
            "file:../etc/passwd",
        ];
        for uri in json_uris {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-path overlay"),
                "opaque file: URI must hit overlay (no fs sub-policy), uri={uri:?} got: {}",
                err.reason
            );
        }
        for (json_uri, label) in [
            ("file:etc/passwd", "slash"),
            (r"file:etc\\passwd", "backslash"),
            ("file:./etc/passwd", "dot"),
            ("file:../etc/passwd", "dotdot"),
        ] {
            let extracted = extract_fs_targets(&format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{json_uri}"}}}}}}"#
            ));
            assert_eq!(
                extracted,
                vec!["/etc/passwd".to_string()],
                "opaque file: ({label}) must extract as /etc/passwd, got {extracted:?}"
            );
        }
    }

    #[test]
    fn test_secret_overlay_rejects_non_ascii_scheme_slot_without_fs() {
        let policy = overlay_on_no_fs_policy();
        let uris = [
            "f\u{0456}le://localhost/etc/passwd",
            "f%D1%96le://localhost/etc/passwd",
            "f\u{03B9}le://localhost/etc/passwd",
            "fil\u{0435}://localhost/etc/passwd",
            "file\u{FE00}://localhost/etc/passwd",
            "file\u{FE0F}://localhost/etc/passwd",
        ];
        for uri in uris {
            let line = format!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
            );
            let err = check_request(&line, &policy).unwrap_err();
            assert!(
                err.reason.contains("secret-overlay") || err.reason.contains("secret-path overlay"),
                "non-ASCII scheme slot must hit overlay, uri={uri:?} got: {}",
                err.reason
            );
        }
    }

    #[test]
    fn test_file_scheme_zwsp_does_not_panic_and_is_denied() {
        let policy = overlay_on_no_fs_policy();
        let uri = "file\u{200b}://localhost/etc/passwd";
        let line = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"uri":"{uri}"}}}}}}"#
        );
        let result = std::panic::catch_unwind(|| check_request(&line, &policy));
        let err = result
            .expect("ZWSP in file scheme must not panic")
            .expect_err("ZWSP file URI must be denied or fail closed");
        assert!(
            err.reason.contains("secret-path overlay")
                || err.reason.contains("invisible Unicode")
                || err.reason.contains("read_only"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn test_secret_overlay_allows_ordinary_new_file() {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = true;
        let mut tool = ToolPolicy::named("read_file", true);
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/notes.txt"}}}"#;
        assert!(check_request(line, &policy).is_ok());
    }

    #[test]
    fn test_secret_overlay_false_falls_back_to_glob() {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = false;
        let mut tool = ToolPolicy::named("read_file", true);
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];

        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/.ssh/id_rsa"}}}"#;
        assert!(
            check_request(line, &policy).is_ok(),
            "overlay off must honor the allow glob"
        );
    }

    #[test]
    fn test_secret_overlay_follows_symlink() {
        let dir = tempfile::tempdir().unwrap();
        match crate::auditor::secret_paths::try_create_secret_symlink(dir.path()) {
            Ok(link) => {
                let mut policy = Policy::default();
                policy.fs.secret_overlay = true;
                let mut tool = ToolPolicy::named("read_file", true);
                let directory =
                    crate::pathutil::resolve_for_authorization(&dir.path().to_string_lossy())
                        .unwrap();
                // Allow both the link location and the follow target so glob
                // authorization would pass; overlay must still deny.
                tool.fs = Some(FsToolPolicy::new(
                    vec![format!("{directory}/**"), "/etc/passwd".into()],
                    vec![],
                ));
                policy.tools = vec![tool];
                let path = link.to_string_lossy().replace('\\', "\\\\");
                let line = format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"read_file","arguments":{{"path":"{path}"}}}}}}"#
                );
                let err = check_request(&line, &policy).unwrap_err();
                assert!(
                    err.reason.contains("secret-path overlay"),
                    "got: {}",
                    err.reason
                );
            }
            Err(e) => {
                eprintln!("secret overlay symlink test skipped: {e}");
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn test_denied_policy_alias_matches_resolved_request() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir_all(real.join("blocked")).unwrap();
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let tool = ToolPolicy::named("read_file", true);
        let fs = FsToolPolicy::new(
            vec![format!("{}/**", alias.display())],
            vec![format!("{}/blocked/**", alias.display())],
        );
        let err = authorize_one_path(&tool, &fs, &real.join("blocked/key").to_string_lossy())
            .unwrap_err();
        assert!(
            err.reason.contains("denied by tool fs sub-policy"),
            "{err:?}"
        );
        assert!(authorize_one_path(&tool, &fs, &real.join("notes").to_string_lossy()).is_ok());
    }

    #[test]
    fn test_https_url_ending_with_etc_passwd_is_not_secret_overlay() {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = true;
        policy.network.outbound.deny_all_others = false;
        let mut tool = ToolPolicy::named("fetch_url", true);
        tool.side_effect = Some("network".into());
        policy.tools = vec![tool];
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://example.com/etc/passwd"}}}"#;
        match check_request(line, &policy) {
            Ok(_) => {}
            Err(err) => {
                assert!(
                    !err.reason.contains("secret-path overlay"),
                    "https URL must not be denied by secret overlay, got: {}",
                    err.reason
                );
            }
        }
    }

    #[test]
    fn test_nested_etc_passwd_path_is_not_secret_overlay() {
        let mut policy = Policy::default();
        policy.fs.secret_overlay = true;
        let mut tool = ToolPolicy::named("read_file", true);
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/mirror/etc/passwd"}}}"#;
        assert!(
            check_request(line, &policy).is_ok(),
            "nested .../etc/passwd must not match reserved /etc/passwd"
        );
    }

    #[test]
    fn test_nul_path_still_rejected() {
        let mut policy = Policy::default();
        let mut tool = ToolPolicy::named("read_file", true);
        tool.fs = Some(FsToolPolicy::new(vec!["/workspace/**".into()], vec![]));
        policy.tools = vec![tool];
        let line = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/workspace/a\\u0000b\"}}}";
        let err = check_request(line, &policy).unwrap_err();
        assert!(
            err.reason.contains("NUL") || err.reason.contains("could not be resolved"),
            "got: {}",
            err.reason
        );
    }

    fn trajectory_policy(enabled: bool) -> Policy {
        let mut read = ToolPolicy::named("read_file", true);
        read.side_effect = Some("read_only".into());
        let mut fetch = ToolPolicy::named("fetch_url", true);
        fetch.side_effect = Some("network".into());
        let trajectory_rules = if enabled {
            vec![crate::policy::TrajectoryRule {
                after_side_effect: SideEffect::ReadOnly,
                deny_next: SideEffect::Network,
            }]
        } else {
            Vec::new()
        };
        Policy {
            trajectory: enabled,
            trajectory_rules,
            tools: vec![read, fetch],
            network: crate::policy::NetworkPolicy {
                outbound: crate::policy::OutboundPolicy {
                    deny_all_others: false,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn tools_call(id: u32, name: &str, arguments: &str) -> String {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"{name}","arguments":{arguments}}}}}"#
        )
    }

    #[test]
    fn test_trajectory_omitted_leaves_behavior_unchanged() {
        let policy = trajectory_policy(false);
        let mut session = SessionState::new();
        session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
        let fetch = tools_call(2, "fetch_url", r#"{"url":"https://example.com/x"}"#);
        assert!(check_request(&fetch, &policy).is_ok());
        assert!(check_trajectory(&fetch, &policy, &session).is_ok());
    }

    #[test]
    fn test_trajectory_on_denies_network_after_successful_read_only() {
        let policy = trajectory_policy(true);
        let mut session = SessionState::new();
        let read = tools_call(1, "read_file", r#"{"path":"/workspace/a.txt"}"#);
        assert!(check_request(&read, &policy).is_ok());
        assert!(check_trajectory(&read, &policy, &session).is_ok());
        session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));

        let fetch = tools_call(2, "fetch_url", r#"{"url":"https://example.com/x"}"#);
        assert!(check_request(&fetch, &policy).is_ok());
        let err = check_trajectory(&fetch, &policy, &session).unwrap_err();
        assert_eq!(err.tool_name, "fetch_url");
        assert!(err.reason.contains("trajectory"), "{}", err.reason);
    }

    #[test]
    fn test_trajectory_off_allows_read_only_then_network() {
        let policy = trajectory_policy(false);
        let mut session = SessionState::new();
        session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
        let fetch = tools_call(2, "fetch_url", r#"{"url":"https://example.com/x"}"#);
        assert!(check_request(&fetch, &policy).is_ok());
        assert!(check_trajectory(&fetch, &policy, &session).is_ok());
    }

    #[test]
    fn test_trajectory_denies_url_argument_even_without_network_side_effect() {
        let mut policy = trajectory_policy(true);
        policy.tools.push(ToolPolicy::named("post_note", true));
        let mut session = SessionState::new();
        session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
        let post = tools_call(3, "post_note", r#"{"url":"https://evil.example/exfil"}"#);
        assert!(request_has_host_or_url(&post));
        let err = check_trajectory(&post, &policy, &session).unwrap_err();
        assert!(err.reason.contains("trajectory"), "{}", err.reason);
    }

    #[test]
    fn test_trajectory_mrtr_retry_ignores_request_state() {
        let policy = trajectory_policy(true);
        let mut session = SessionState::new();
        session.record_successful_tool_call("read_file", Some(SideEffect::ReadOnly));
        let retry = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://example.com/x"},"requestState":"opaque-retry-blob"}}"#;
        assert!(check_request(retry, &policy).is_ok());
        let err = check_trajectory(retry, &policy, &session).unwrap_err();
        assert!(err.reason.contains("trajectory"), "{}", err.reason);
        assert!(!err.reason.contains("requestState"), "{}", err.reason);
    }

    #[test]
    fn test_request_has_host_or_url_matches_side_effect_extractor() {
        assert!(request_has_host_or_url(&tools_call(
            1,
            "fetch_url",
            r#"{"url":"https://example.com/x"}"#
        )));
        assert!(!request_has_host_or_url(&tools_call(
            1,
            "read_file",
            r#"{"path":"/workspace/a.txt"}"#
        )));
    }
}
