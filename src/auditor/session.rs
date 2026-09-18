use std::collections::{HashMap, HashSet};

use crate::policy::{SideEffect, TrajectoryRule};

/// Canonical JSON-RPC id (string/number/null) for request correlation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RpcId {
    Null,
    Number(String),
    String(String),
}

/// Canonical decimal form of a JSON number so mathematically equal
/// spellings (`1`, `1.0`, `10e-1`, `0.5e1`) correlate to the same `RpcId`.
/// No floating-point conversion: the coefficient stays a digit string and
/// the exponent an i128, so large integers and out-of-f64-range exponents
/// keep full precision and distinct values never collapse. Malformed input
/// or exponents beyond i128 fall back to the trimmed raw text.
fn canonicalize_json_number(raw: &str) -> String {
    let t = raw.trim();
    let (neg, unsigned) = match t.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, t),
    };
    let (mantissa, exp_lit) = match unsigned.find(['e', 'E']) {
        Some(i) => (&unsigned[..i], &unsigned[i + 1..]),
        None => (unsigned, "0"),
    };
    let Ok(exp) = exp_lit.parse::<i128>() else {
        return t.to_string();
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if (int_part.is_empty() && frac_part.is_empty())
        || !int_part.bytes().all(|b| b.is_ascii_digit())
        || !frac_part.bytes().all(|b| b.is_ascii_digit())
    {
        return t.to_string();
    }
    let digits = format!("{int_part}{frac_part}");
    let sig = digits.trim_start_matches('0');
    if sig.is_empty() {
        return "0".to_string();
    }
    let sig = sig.trim_end_matches('0');
    let trailing = (digits.trim_start_matches('0').len() - sig.len()) as i128;
    let Some(exp) = exp
        .checked_sub(frac_part.len() as i128)
        .and_then(|e| e.checked_add(trailing))
    else {
        return t.to_string();
    };
    format!("{}{}e{}", if neg { "-" } else { "" }, sig, exp)
}

impl RpcId {
    pub fn parse_from_json(id: nojson::RawJsonValue<'_, '_>) -> Option<Self> {
        match id.kind() {
            nojson::JsonValueKind::Null => Some(Self::Null),
            nojson::JsonValueKind::Integer | nojson::JsonValueKind::Float => {
                Some(Self::Number(canonicalize_json_number(id.as_raw_str())))
            }
            nojson::JsonValueKind::String => id
                .to_unquoted_string_str()
                .ok()
                .map(|s| Self::String(s.into_owned())),
            _ => None,
        }
    }

    pub fn from_line(line: &str) -> Option<Self> {
        let json = nojson::RawJson::parse(line).ok()?;
        let id = json.value().to_member("id").ok()?.optional()?;
        Self::parse_from_json(id)
    }
}

/// Tracks file paths discovered during a **process-local** Confused Deputy check.
///
/// When enabled, `read_file` requests are only allowed for paths that were previously
/// discovered via `list_files` or `list_directory` calls. Path traversal (`../`) is
/// always blocked regardless of known paths.
///
/// # Process scope vs MCP session (2026-07-28)
///
/// MCP revision 2026-07-28 is **stateless**: a stdio process MUST NOT be treated
/// as a protocol session
/// ([base spec](https://modelcontextprotocol.io/specification/2026-07-28/basic/)).
/// This type is a **v1 product feature**, not a spec session:
///
/// - One `SessionState` is shared for the child process (the Auditor proxy).
/// - It is **not** keyed on MCP session ids (retired) or on MRTR `requestState`
///   (server-minted, attacker-controlled, must stay opaque).
/// - Interleaved clients on the same stdio child share `known_paths` (they can
///   poison each other's deputy set). Enable only when you accept
///   “one client, one child, process = deputy”.
///
/// MRTR retries of `read_file` use a new JSON-RPC `id` and may carry
/// `requestState`; access is still decided by **path ∈ known_paths**, never by
/// those fields.
#[derive(Debug, Default)]
pub struct SessionState {
    /// File paths discovered via list_files/list_directory responses.
    known_paths: HashSet<String>,
    /// Pending listing operations keyed by canonical JSON-RPC id.
    pending_list_requests: HashMap<RpcId, PendingList>,
    known_path_bytes: usize,
    pending_id_bytes: usize,
    /// Last **successful** `tools/call` side_effect (process-local trajectory).
    /// Separate from Confused Deputy `known_paths`. Never keyed on `requestState`.
    last_successful_side_effect: Option<SideEffect>,
    /// Tool name of that last successful call (cross-tool chaining only).
    last_successful_tool: Option<String>,
    /// In-flight `tools/call` awaiting a success/error response.
    pending_tool_calls: HashMap<RpcId, PendingToolCall>,
    pending_tool_id_bytes: usize,
}

#[derive(Debug, Clone)]
struct PendingList;

#[derive(Debug, Clone)]
struct PendingToolCall {
    tool_name: String,
    side_effect: Option<SideEffect>,
}

const MAX_KNOWN_PATHS: usize = 4096;
const MAX_KNOWN_PATH_BYTES: usize = 1_048_576;
const MAX_PENDING_LISTS: usize = 128;
const MAX_PENDING_ID_BYTES: usize = 65_536;
const MAX_PENDING_TOOL_CALLS: usize = 128;
const MAX_PATH_BYTES: usize = 4096;

impl SessionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request ID as a pending list operation for `tool`.
    /// Returns an error when quotas are exceeded or the id is already in flight.
    pub fn record_pending_list(&mut self, request_id: RpcId, tool: &str) -> Result<(), String> {
        if matches!(request_id, RpcId::Null) {
            return Err("JSON-RPC id must not be null".to_string());
        }
        if self.pending_list_requests.contains_key(&request_id) {
            return Err("duplicate in-flight JSON-RPC id".to_string());
        }
        if self.pending_list_requests.len() >= MAX_PENDING_LISTS {
            return Err("too many pending list requests".to_string());
        }
        let id_bytes = match &request_id {
            RpcId::Null => 4,
            RpcId::Number(n) | RpcId::String(n) => n.len(),
        };
        if self.pending_id_bytes.saturating_add(id_bytes) > MAX_PENDING_ID_BYTES {
            return Err("pending list id budget exceeded".to_string());
        }
        self.pending_id_bytes += id_bytes;
        let _ = tool;
        self.pending_list_requests.insert(request_id, PendingList);
        Ok(())
    }

    /// Check if a request ID is a pending list operation and remove it.
    pub fn take_pending_list(&mut self, request_id: &RpcId) -> bool {
        if self.pending_list_requests.remove(request_id).is_some() {
            let id_bytes = match request_id {
                RpcId::Null => 4,
                RpcId::Number(n) | RpcId::String(n) => n.len(),
            };
            self.pending_id_bytes = self.pending_id_bytes.saturating_sub(id_bytes);
            true
        } else {
            false
        }
    }

    /// Record discovered file paths from a list response.
    pub fn record_paths(&mut self, paths: &[String]) {
        for path in paths {
            if self.known_paths.len() >= MAX_KNOWN_PATHS {
                tracing::warn!(
                    cap = MAX_KNOWN_PATHS,
                    "known_paths quota reached; ignoring further list identifiers"
                );
                break;
            }
            let trimmed = path.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_PATH_BYTES {
                continue;
            }
            if self.known_path_bytes.saturating_add(trimmed.len()) > MAX_KNOWN_PATH_BYTES {
                tracing::warn!("known_paths byte budget reached");
                break;
            }
            if self.known_paths.insert(trimmed.to_string()) {
                self.known_path_bytes += trimmed.len();
            }
        }
    }

    /// Check if a file access is allowed.
    ///
    /// Returns `Err` with a reason if blocked:
    /// - Path traversal (`../`) is always rejected.
    /// - Paths not in the known set are rejected.
    pub fn check_access(&self, path: &str) -> Result<(), String> {
        if path.contains("../") || path.contains("..\\") {
            return Err(format!("path traversal detected in '{path}'",));
        }

        // Detect URL-encoded path traversal.
        // We must catch partial encoding (%2e./, .%2e/, %2e%2e/) as well as
        // fully-encoded variants.  Decode all %XX sequences once, then check
        // the result for literal traversal patterns.
        let lower = path.to_ascii_lowercase();
        if lower.contains('%') {
            let decoded_once = percent_decode_once(&lower);
            if decoded_once.contains("../") || decoded_once.contains("..\\") {
                return Err(format!("URL-encoded path traversal detected in '{path}'",));
            }

            // Double-encoding: decode a second time and re-check.
            if decoded_once.contains('%') {
                let decoded_twice = percent_decode_once(&decoded_once);
                if decoded_twice.contains("../") || decoded_twice.contains("..\\") {
                    return Err(format!(
                        "double URL-encoded path traversal detected in '{path}'",
                    ));
                }
            }
        }

        if !self.known_paths.contains(path) {
            return Err(format!(
                "path '{path}' was not discovered via list_files/list_directory",
            ));
        }

        Ok(())
    }

    /// Returns the number of known paths (for testing/logging).
    pub fn known_path_count(&self) -> usize {
        self.known_paths.len()
    }

    /// Side-effect of the last successful `tools/call`, if any.
    pub fn last_successful_side_effect(&self) -> Option<SideEffect> {
        self.last_successful_side_effect
    }

    /// Tool name of the last successful `tools/call`, if any.
    pub fn last_successful_tool(&self) -> Option<&str> {
        self.last_successful_tool.as_deref()
    }

    /// Record an authorized `tools/call` until its JSON-RPC response arrives.
    ///
    /// Correlation is by JSON-RPC `id` only — never `requestState`.
    pub fn record_pending_tool_call(
        &mut self,
        request_id: RpcId,
        tool_name: &str,
        side_effect: Option<SideEffect>,
    ) -> Result<(), String> {
        if matches!(request_id, RpcId::Null) {
            return Err("JSON-RPC id must not be null".to_string());
        }
        if self.pending_tool_calls.contains_key(&request_id) {
            return Err("duplicate in-flight JSON-RPC id".to_string());
        }
        if self.pending_tool_calls.len() >= MAX_PENDING_TOOL_CALLS {
            return Err("too many pending tool calls".to_string());
        }
        let id_bytes = match &request_id {
            RpcId::Null => 4,
            RpcId::Number(n) | RpcId::String(n) => n.len(),
        };
        if self.pending_tool_id_bytes.saturating_add(id_bytes) > MAX_PENDING_ID_BYTES {
            return Err("pending tool-call id budget exceeded".to_string());
        }
        self.pending_tool_id_bytes += id_bytes;
        self.pending_tool_calls.insert(
            request_id,
            PendingToolCall {
                tool_name: tool_name.to_string(),
                side_effect,
            },
        );
        Ok(())
    }

    /// Complete a pending `tools/call`. On success, store its side_effect.
    ///
    /// `succeeded` is true only for a JSON-RPC **response** with a completed
    /// `result`. JSON-RPC `error`, MCP `result.isError=true`, and MRTR
    /// `input_required` must be passed as `false` and do not replace the
    /// last successful side_effect.
    pub fn complete_pending_tool_call(&mut self, request_id: &RpcId, succeeded: bool) {
        let Some(pending) = self.pending_tool_calls.remove(request_id) else {
            return;
        };
        let id_bytes = match request_id {
            RpcId::Null => 4,
            RpcId::Number(n) | RpcId::String(n) => n.len(),
        };
        self.pending_tool_id_bytes = self.pending_tool_id_bytes.saturating_sub(id_bytes);
        if succeeded {
            self.last_successful_tool = Some(pending.tool_name);
            self.last_successful_side_effect = pending.side_effect;
        }
    }

    /// Record a successful `tools/call` directly (unit tests / already-correlated).
    pub fn record_successful_tool_call(
        &mut self,
        tool_name: &str,
        side_effect: Option<SideEffect>,
    ) {
        self.last_successful_tool = Some(tool_name.to_string());
        self.last_successful_side_effect = side_effect;
    }

    /// When trajectory is enabled, deny the next cross-tool call if a rule matches.
    ///
    /// Same-tool sequences are skipped unless the next call sneaks a host/URL
    /// on a non-network tool. Matching uses tool name + side_effect + extracted
    /// host/URL only.
    pub fn check_trajectory(
        &self,
        rules: &[TrajectoryRule],
        next_tool: &str,
        next_side_effect: Option<SideEffect>,
        has_host_or_url: bool,
    ) -> Result<(), String> {
        let Some(prev_se) = self.last_successful_side_effect else {
            return Ok(());
        };
        if self.last_successful_tool.as_deref() == Some(next_tool) {
            let sneak_url = has_host_or_url && next_side_effect != Some(SideEffect::Network);
            if !sneak_url {
                return Ok(());
            }
        }
        for rule in rules {
            if rule.after_side_effect != prev_se {
                continue;
            }
            let deny = match rule.deny_next {
                SideEffect::Network => {
                    next_side_effect == Some(SideEffect::Network) || has_host_or_url
                }
                SideEffect::ReadOnly | SideEffect::Write | SideEffect::Execute => {
                    next_side_effect == Some(rule.deny_next)
                }
            };
            if deny {
                return Err(format!(
                    "trajectory: after side_effect=\"{}\" deny-next=\"{}\"",
                    rule.after_side_effect.as_str(),
                    rule.deny_next.as_str()
                ));
            }
        }
        Ok(())
    }
}

/// Decode a single layer of percent-encoding (%XX → byte).
///
/// Only decodes valid two-hex-digit sequences; malformed sequences are left as-is.
fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push(hi << 4 | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Manages session states for connections.
///
/// Unused on the stdio v1 proxy path (`run_proxy` keeps one process-local
/// [`SessionState`]). Do **not** bind keys to MCP session ids or `requestState`.
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<String, SessionState>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get or create a session state for the given session ID.
    pub fn get_or_create(&mut self, session_id: &str) -> &mut SessionState {
        self.sessions.entry(session_id.to_string()).or_default()
    }
}

/// Extract all JSON string values from raw JSON text.
///
/// Handles JSON escape sequences (`\"`, `\\`, `\n`, `\t`, `\r`, `\/`, `\b`, `\f`).
/// Iterates over Unicode scalar values (chars) to correctly handle multi-byte
/// UTF-8 sequences in string contents.
#[cfg(test)]
fn extract_all_json_strings(json: &str) -> Vec<String> {
    let mut strings = Vec::new();
    let mut chars = json.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '"' {
            let mut s = String::new();
            loop {
                match chars.next() {
                    None | Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some('n') => s.push('\n'),
                        Some('t') => s.push('\t'),
                        Some('r') => s.push('\r'),
                        Some('"') => s.push('"'),
                        Some('\\') => s.push('\\'),
                        Some('/') => s.push('/'),
                        Some('b') => s.push('\x08'),
                        Some('f') => s.push('\x0C'),
                        Some('u') => {
                            // Parse \uXXXX Unicode escape (BMP only, no surrogate pairs)
                            let hex: String = chars.by_ref().take(4).collect();
                            if hex.len() == 4 {
                                match u32::from_str_radix(&hex, 16) {
                                    Ok(code_point) => {
                                        if let Some(ch) = char::from_u32(code_point) {
                                            s.push(ch);
                                        } else {
                                            tracing::debug!(
                                                "invalid unicode code point: \\u{:04X}",
                                                code_point
                                            );
                                        }
                                    }
                                    Err(_) => {
                                        tracing::debug!("invalid unicode escape: \\u{}", hex);
                                    }
                                }
                            }
                        }
                        Some(other) => {
                            s.push('\\');
                            s.push(other);
                        }
                        None => break,
                    },
                    Some(ch) => s.push(ch),
                }
            }
            strings.push(s);
        }
    }

    strings
}

/// Extract file identifiers from a list-style JSON-RPC response.
///
/// Only typed fields are accepted:
/// - `result.content[].text` (newline-separated paths)
/// - `result.content[].resource.uri`
/// - `result.resources[].uri`
/// - `result.roots[].uri`
/// - `result.files[].path`
///
/// Object keys and unrelated strings never enter `known_paths`.
pub fn extract_paths_from_response(line: &str) -> Vec<String> {
    let json = match nojson::RawJson::parse(line) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };

    let Some(result) = json
        .value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
    else {
        return Vec::new();
    };

    let mut out = Vec::new();
    push_content_identifiers(result, &mut out);
    push_array_string_field(result, "resources", "uri", &mut out);
    push_array_string_field(result, "roots", "uri", &mut out);
    push_array_string_field(result, "files", "path", &mut out);
    out.truncate(MAX_KNOWN_PATHS);
    out
}

fn json_string_field(value: nojson::RawJsonValue<'_, '_>, name: &str) -> Option<String> {
    let member = value.to_member(name).ok()?.optional()?;
    member.to_unquoted_string_str().ok().map(|s| s.into_owned())
}

fn push_content_identifiers(result: nojson::RawJsonValue<'_, '_>, out: &mut Vec<String>) {
    let Some(content) = result.to_member("content").ok().and_then(|m| m.optional()) else {
        return;
    };
    let Ok(items) = content.to_array() else {
        return;
    };
    for item in items {
        if let Some(text) = json_string_field(item, "text") {
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.len() > 1 {
                    out.push(trimmed.to_string());
                }
            }
        }
        if let Some(resource) = item.to_member("resource").ok().and_then(|m| m.optional())
            && let Some(uri) = json_string_field(resource, "uri")
            && uri.len() > 1
        {
            out.push(uri);
        }
    }
}

fn push_array_string_field(
    result: nojson::RawJsonValue<'_, '_>,
    array_name: &str,
    field: &str,
    out: &mut Vec<String>,
) {
    let Some(arr) = result.to_member(array_name).ok().and_then(|m| m.optional()) else {
        return;
    };
    let Ok(items) = arr.to_array() else {
        return;
    };
    for item in items {
        if let Some(value) = json_string_field(item, field)
            && value.len() > 1
        {
            out.push(value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- SessionState ---

    #[test]
    fn test_new_session_has_no_known_paths() {
        let state = SessionState::new();
        assert_eq!(state.known_path_count(), 0);
    }

    #[test]
    fn test_record_and_check_access() {
        let mut state = SessionState::new();
        state.record_paths(&[
            "/workspace/file1.txt".to_string(),
            "/workspace/file2.txt".to_string(),
        ]);
        assert!(state.check_access("/workspace/file1.txt").is_ok());
        assert!(state.check_access("/workspace/file2.txt").is_ok());
    }

    #[test]
    fn test_unknown_path_blocked() {
        let mut state = SessionState::new();
        state.record_paths(&["/workspace/file1.txt".to_string()]);
        let err = state.check_access("/etc/passwd").unwrap_err();
        assert!(err.contains("not discovered"));
        assert!(err.contains("/etc/passwd"));
    }

    #[test]
    fn test_empty_known_paths_blocks_all() {
        let state = SessionState::new();
        let err = state.check_access("/workspace/file.txt").unwrap_err();
        assert!(err.contains("not discovered"));
    }

    #[test]
    fn test_path_traversal_forward_slash() {
        let mut state = SessionState::new();
        state.record_paths(&["/workspace/../../etc/passwd".to_string()]);
        let err = state
            .check_access("/workspace/../../etc/passwd")
            .unwrap_err();
        assert!(err.contains("path traversal"));
    }

    #[test]
    fn test_path_traversal_backslash() {
        let state = SessionState::new();
        let err = state
            .check_access("C:\\workspace\\..\\..\\etc\\passwd")
            .unwrap_err();
        assert!(err.contains("path traversal"));
    }

    #[test]
    fn test_path_traversal_detected_even_when_known() {
        let mut state = SessionState::new();
        // Even if ../path is somehow in known_paths, traversal is blocked
        state.known_paths.insert("/workspace/../secret".to_string());
        let err = state.check_access("/workspace/../secret").unwrap_err();
        assert!(err.contains("path traversal"));
    }

    #[test]
    fn test_record_paths_trims_whitespace() {
        let mut state = SessionState::new();
        state.record_paths(&["  /workspace/file.txt  ".to_string()]);
        assert!(state.check_access("/workspace/file.txt").is_ok());
    }

    #[test]
    fn test_record_paths_ignores_empty() {
        let mut state = SessionState::new();
        state.record_paths(&[String::new(), "  ".to_string()]);
        assert_eq!(state.known_path_count(), 0);
    }

    #[test]
    fn test_duplicate_paths_deduplicated() {
        let mut state = SessionState::new();
        state.record_paths(&[
            "/workspace/a.txt".to_string(),
            "/workspace/a.txt".to_string(),
        ]);
        assert_eq!(state.known_path_count(), 1);
    }

    // --- pending list requests ---

    #[test]
    fn test_pending_list_record_and_take() {
        let mut state = SessionState::new();
        state
            .record_pending_list(RpcId::Number("1".into()), "list_files")
            .unwrap();
        assert!(state.take_pending_list(&RpcId::Number("1".into())));
        assert!(!state.take_pending_list(&RpcId::Number("1".into()))); // already taken
    }

    #[test]
    fn test_rpc_id_number_spellings_canonicalize() {
        let int_id = RpcId::from_line(r#"{"id":1}"#).unwrap();
        let float_id = RpcId::from_line(r#"{"id":1.0}"#).unwrap();
        let exp_id = RpcId::from_line(r#"{"id":1e0}"#).unwrap();
        let neg_zero = RpcId::from_line(r#"{"id":-0}"#).unwrap();
        let zero = RpcId::from_line(r#"{"id":0}"#).unwrap();
        assert_eq!(int_id, float_id);
        assert_eq!(int_id, exp_id);
        assert_eq!(neg_zero, zero);
        assert_ne!(int_id, RpcId::from_line(r#"{"id":2}"#).unwrap());
        // String and number ids never collide.
        assert_ne!(int_id, RpcId::from_line(r#"{"id":"1"}"#).unwrap());
    }

    #[test]
    fn test_pending_correlation_across_number_spellings() {
        let mut state = SessionState::new();
        let req = RpcId::from_line(r#"{"id":7}"#).unwrap();
        let resp = RpcId::from_line(r#"{"id":7.0}"#).unwrap();
        state.record_pending_list(req, "list_files").unwrap();
        assert!(state.take_pending_list(&resp));
        assert!(!state.take_pending_list(&resp));
    }

    #[test]
    fn test_rpc_id_number_canonicalization_preserves_precision() {
        // f64 collapses these pairs; decimal canonicalization must not.
        let pairs = [
            (r#"{"id":9007199254740992}"#, r#"{"id":9007199254740993}"#),
            (r#"{"id":1}"#, r#"{"id":1.0000000000000001}"#),
            (
                r#"{"id":18446744073709551616}"#,
                r#"{"id":18446744073709551617}"#,
            ),
            (r#"{"id":0.1}"#, r#"{"id":0.100000000000000000001}"#),
        ];
        for (a, b) in pairs {
            assert_ne!(RpcId::from_line(a), RpcId::from_line(b), "{a} vs {b}");
        }
    }

    #[test]
    fn test_rpc_id_number_out_of_range_exponents() {
        // Beyond f64 range: mathematically equal spellings still correlate.
        let big = RpcId::from_line(r#"{"id":1e400}"#);
        for line in [
            r#"{"id":10e399}"#,
            r#"{"id":0.01e402}"#,
            r#"{"id":100E398}"#,
        ] {
            assert_eq!(RpcId::from_line(line), big, "{line}");
        }
        let tiny = RpcId::from_line(r#"{"id":5e-400}"#);
        for line in [r#"{"id":0.5e-399}"#, r#"{"id":50e-401}"#] {
            assert_eq!(RpcId::from_line(line), tiny, "{line}");
        }
        // Exponent literal beyond i128: raw fallback, no panic, still stable.
        let huge = r#"{"id":1e999999999999999999999999999999999999999}"#;
        assert_eq!(RpcId::from_line(huge), RpcId::from_line(huge));
    }

    #[test]
    fn test_rpc_id_number_exponent_arithmetic_overflow_falls_back() {
        // exp_lit at i128 edges: fraction-digit subtraction and
        // trailing-zero addition must not overflow — falls back to raw.
        let at_min = r#"{"id":0.1e-170141183460469231731687303715884105728}"#;
        let at_max = r#"{"id":10e170141183460469231731687303715884105727}"#;
        assert_eq!(RpcId::from_line(at_min), RpcId::from_line(at_min));
        assert_eq!(RpcId::from_line(at_max), RpcId::from_line(at_max));
        assert_ne!(RpcId::from_line(at_min), RpcId::from_line(at_max));
        // Exactly at the i128 edges the arithmetic still fits and correlates.
        assert_eq!(
            RpcId::from_line(r#"{"id":1e-170141183460469231731687303715884105728}"#),
            RpcId::from_line(r#"{"id":0.001e-170141183460469231731687303715884105725}"#)
        );
        assert_eq!(
            RpcId::from_line(r#"{"id":1e170141183460469231731687303715884105727}"#),
            RpcId::from_line(r#"{"id":100e170141183460469231731687303715884105725}"#)
        );
        // In-range exponents keep normal canonicalization.
        assert_eq!(
            RpcId::from_line(r#"{"id":2.5e3}"#),
            RpcId::from_line(r#"{"id":2500}"#)
        );
    }

    #[test]
    fn test_record_pending_list_rejects_null_id() {
        let mut state = SessionState::new();
        let err = state
            .record_pending_list(RpcId::Null, "list_files")
            .unwrap_err();
        assert!(err.contains("null"), "got: {err}");
        assert!(!state.take_pending_list(&RpcId::Null));
    }

    #[test]
    fn test_take_pending_nonexistent() {
        let mut state = SessionState::new();
        assert!(!state.take_pending_list(&RpcId::Number("42".into())));
    }

    // --- SessionManager ---

    #[test]
    fn test_session_manager_independent_sessions() {
        let mut mgr = SessionManager::new();
        mgr.get_or_create("session-a")
            .record_paths(&["/a/file.txt".to_string()]);
        mgr.get_or_create("session-b")
            .record_paths(&["/b/file.txt".to_string()]);

        assert!(
            mgr.get_or_create("session-a")
                .check_access("/a/file.txt")
                .is_ok()
        );
        assert!(
            mgr.get_or_create("session-a")
                .check_access("/b/file.txt")
                .is_err()
        );
        assert!(
            mgr.get_or_create("session-b")
                .check_access("/b/file.txt")
                .is_ok()
        );
        assert!(
            mgr.get_or_create("session-b")
                .check_access("/a/file.txt")
                .is_err()
        );
    }

    // --- URL-encoded path traversal ---

    #[test]
    fn test_path_traversal_url_encoded_lowercase() {
        let mut state = SessionState::new();
        state.record_paths(&["/workspace/%2e%2e/etc/passwd".to_string()]);
        let err = state
            .check_access("/workspace/%2e%2e/etc/passwd")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"));
    }

    #[test]
    fn test_path_traversal_url_encoded_uppercase() {
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%2E%2E/etc/passwd")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"));
    }

    #[test]
    fn test_path_traversal_url_encoded_mixed_case() {
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%2e%2E/etc/passwd")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"));
    }

    #[test]
    fn test_path_traversal_url_encoded_mixed_case_2() {
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%2E%2e/etc/passwd")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"));
    }

    // --- Partial URL-encoded path traversal ---

    #[test]
    fn test_path_traversal_first_dot_encoded() {
        // %2e./ — only the first dot is URL-encoded
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%2e./etc/passwd")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"), "got: {err}");
    }

    #[test]
    fn test_path_traversal_second_dot_encoded() {
        // .%2e/ — only the second dot is URL-encoded
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/.%2e/etc/passwd")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"), "got: {err}");
    }

    #[test]
    fn test_path_traversal_dots_encoded_slash_literal() {
        // %2e%2e/ — both dots encoded, slash literal
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%2e%2e/etc/passwd")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"), "got: {err}");
    }

    #[test]
    fn test_path_traversal_backslash_partial_encoded() {
        // .%2e\ — partial encoding with backslash
        let state = SessionState::new();
        let err = state
            .check_access("C:\\workspace\\.%2e\\secret")
            .unwrap_err();
        assert!(err.contains("URL-encoded path traversal"), "got: {err}");
    }

    // --- Double URL-encoded path traversal ---

    #[test]
    fn test_path_traversal_double_url_encoded() {
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%252e%252e/etc/passwd")
            .unwrap_err();
        assert!(err.contains("double URL-encoded path traversal"));
    }

    #[test]
    fn test_path_traversal_double_url_encoded_uppercase() {
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%252E%252E/etc/passwd")
            .unwrap_err();
        assert!(err.contains("double URL-encoded path traversal"));
    }

    #[test]
    fn test_path_traversal_double_url_encoded_mixed() {
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%252e%252E/etc/passwd")
            .unwrap_err();
        assert!(err.contains("double URL-encoded path traversal"));
    }

    #[test]
    fn test_path_traversal_double_url_encoded_with_slash() {
        let state = SessionState::new();
        // %252e%252e%252f decodes to %2e%2e%2f which decodes to ../
        let err = state
            .check_access("/workspace/%252e%252e%252fetc/passwd")
            .unwrap_err();
        assert!(err.contains("double URL-encoded path traversal"));
    }

    #[test]
    fn test_path_traversal_double_partial_encoded() {
        // %252e./ — first dot double-encoded, second literal
        let state = SessionState::new();
        let err = state
            .check_access("/workspace/%252e./etc/passwd")
            .unwrap_err();
        assert!(
            err.contains("URL-encoded path traversal")
                || err.contains("double URL-encoded path traversal"),
            "got: {err}"
        );
    }

    #[test]
    fn test_no_false_positive_on_percent25_without_traversal() {
        let mut state = SessionState::new();
        let path = "/workspace/%2520safe_file.txt";
        state.record_paths(&[path.to_string()]);
        // %2520 decodes to %20 (space), no traversal
        assert!(state.check_access(path).is_ok());
    }

    // --- extract_all_json_strings ---

    #[test]
    fn test_extract_strings_simple() {
        let json = r#"{"key":"value","other":"data"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"key".to_string()));
        assert!(strings.contains(&"value".to_string()));
        assert!(strings.contains(&"other".to_string()));
        assert!(strings.contains(&"data".to_string()));
    }

    #[test]
    fn test_extract_strings_with_escapes() {
        let json = r#"{"path":"\/workspace\/file.txt"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"/workspace/file.txt".to_string()));
    }

    #[test]
    fn test_extract_strings_with_newlines() {
        let json = r#"{"text":"/a.txt\n/b.txt\n/c.txt"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"/a.txt\n/b.txt\n/c.txt".to_string()));
    }

    #[test]
    fn test_extract_strings_backspace_escape() {
        let json = r#"{"val":"a\bb"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"a\x08b".to_string()));
    }

    #[test]
    fn test_extract_strings_formfeed_escape() {
        let json = r#"{"val":"a\fb"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"a\x0Cb".to_string()));
    }

    #[test]
    fn test_extract_strings_unicode_escape_basic() {
        // \u0041 = 'A'
        let json = r#"{"val":"\u0041\u0042\u0043"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"ABC".to_string()));
    }

    #[test]
    fn test_extract_strings_unicode_escape_japanese() {
        // \u3042 = 'あ'
        let json = r#"{"val":"\u3042"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"あ".to_string()));
    }

    #[test]
    fn test_extract_strings_unicode_escape_mixed() {
        // Mix of unicode escapes and regular text
        let json = r#"{"path":"\/workspace\/\u0066ile.txt"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"/workspace/file.txt".to_string()));
    }

    #[test]
    fn test_extract_strings_unicode_escape_invalid_hex_skipped() {
        // \uZZZZ is not valid hex — silently skipped
        let json = r#"{"val":"\uZZZZ"}"#;
        let strings = extract_all_json_strings(json);
        // Should not crash; the result won't contain the invalid escape as a char
        assert_eq!(strings.len(), 2); // "val" and whatever remains
    }

    #[test]
    fn test_extract_strings_raw_multibyte_utf8() {
        // Raw multi-byte UTF-8 in JSON strings (e.g., Japanese directory names)
        let json = r#"{"path":"/workspace/日本語/file.txt"}"#;
        let strings = extract_all_json_strings(json);
        assert!(strings.contains(&"/workspace/日本語/file.txt".to_string()));
    }

    #[test]
    fn test_extract_strings_empty_input() {
        let strings = extract_all_json_strings("");
        assert!(strings.is_empty());
    }

    // --- extract_paths_from_response ---

    #[test]
    fn test_extract_paths_from_list_response() {
        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"/workspace/a.txt\n/workspace/b.txt"}]}}"#;
        let paths = extract_paths_from_response(response);
        assert!(paths.contains(&"/workspace/a.txt".to_string()));
        assert!(paths.contains(&"/workspace/b.txt".to_string()));
    }

    #[test]
    fn test_extract_paths_from_resource_response() {
        let response = r#"{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"resource","resource":{"uri":"file:///workspace/file.txt","text":"contents"}}]}}"#;
        let paths = extract_paths_from_response(response);
        assert!(paths.contains(&"file:///workspace/file.txt".to_string()));
    }

    #[test]
    fn test_extract_paths_no_result() {
        let response = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"fail"}}"#;
        let paths = extract_paths_from_response(response);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_paths_invalid_json() {
        let paths = extract_paths_from_response("not json");
        assert!(paths.is_empty());
    }

    #[test]
    fn test_extract_paths_filters_short_strings() {
        let response =
            r#"{"jsonrpc":"2.0","id":1,"result":{"x":"a","path":"/workspace/long_path.txt"}}"#;
        let paths = extract_paths_from_response(response);
        assert!(!paths.contains(&"a".to_string()));
        // Top-level `path` is not a typed list identifier.
        assert!(!paths.contains(&"/workspace/long_path.txt".to_string()));
    }

    #[test]
    fn test_extract_paths_ignores_object_keys_and_metadata() {
        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"path":"/etc/passwd","metadata":{"note":"/secret.txt"},"content":[{"type":"text","text":"/workspace/real.txt"}]}}"#;
        let paths = extract_paths_from_response(response);
        assert!(paths.contains(&"/workspace/real.txt".to_string()));
        assert!(!paths.contains(&"/etc/passwd".to_string()));
        assert!(!paths.contains(&"/secret.txt".to_string()));
        assert!(!paths.contains(&"path".to_string()));
    }

    #[test]
    fn test_extract_paths_from_files_array() {
        let response =
            r#"{"jsonrpc":"2.0","id":1,"result":{"files":[{"path":"/workspace/a.txt"}]}}"#;
        let paths = extract_paths_from_response(response);
        assert_eq!(paths, vec!["/workspace/a.txt".to_string()]);
    }

    // --- End-to-end flow ---

    #[test]
    fn test_full_confused_deputy_flow() {
        let mut state = SessionState::new();

        // Step 1: list_files request goes through, record pending
        state
            .record_pending_list(RpcId::Number("1".into()), "list_files")
            .unwrap();

        // Step 2: list_files response comes back with paths
        let response = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"/workspace/a.txt\n/workspace/b.txt"}]}}"#;
        assert!(state.take_pending_list(&RpcId::Number("1".into())));
        let paths = extract_paths_from_response(response);
        state.record_paths(&paths);

        // Step 3: read_file for discovered path → allowed
        assert!(state.check_access("/workspace/a.txt").is_ok());
        assert!(state.check_access("/workspace/b.txt").is_ok());

        // Step 4: read_file for undiscovered path → blocked
        assert!(state.check_access("/etc/shadow").is_err());

        // Step 5: path traversal → always blocked
        assert!(state.check_access("/workspace/../../etc/passwd").is_err());
    }

    #[test]
    fn test_interleaved_list_read_shares_process_scope() {
        let mut state = SessionState::new();
        state
            .record_pending_list(RpcId::Number("1".into()), "list_files")
            .unwrap();
        state
            .record_pending_list(RpcId::Number("2".into()), "list_files")
            .unwrap();

        assert!(state.take_pending_list(&RpcId::Number("1".into())));
        state.record_paths(&["/client-a/file.txt".to_string()]);

        assert!(state.take_pending_list(&RpcId::Number("2".into())));
        state.record_paths(&["/client-b/file.txt".to_string()]);

        // Process-scope: interleaved list responses share one known_paths set.
        assert!(state.check_access("/client-a/file.txt").is_ok());
        assert!(state.check_access("/client-b/file.txt").is_ok());
        assert!(state.check_access("/client-c/unlisted.txt").is_err());
    }

    #[test]
    fn test_read_file_mrtr_retry_still_subject_to_known_paths() {
        let mut state = SessionState::new();
        state.record_paths(&["/workspace/a.txt".to_string()]);

        // First tools/call (id=1)
        assert!(state.check_access("/workspace/a.txt").is_ok());
        // MRTR retry: new JSON-RPC id, same path — still allowed
        assert!(state.check_access("/workspace/a.txt").is_ok());
        // requestState / new id must not grant an undiscovered path
        assert!(state.check_access("/etc/passwd").is_err());
    }

    fn read_only_then_network_rule() -> Vec<crate::policy::TrajectoryRule> {
        vec![crate::policy::TrajectoryRule {
            after_side_effect: crate::policy::SideEffect::ReadOnly,
            deny_next: crate::policy::SideEffect::Network,
        }]
    }

    #[test]
    fn test_trajectory_empty_last_allows_network() {
        let state = SessionState::new();
        assert!(
            state
                .check_trajectory(
                    &read_only_then_network_rule(),
                    "fetch_url",
                    Some(crate::policy::SideEffect::Network),
                    false,
                )
                .is_ok()
        );
        assert!(state.last_successful_side_effect().is_none());
        assert!(state.last_successful_tool().is_none());
    }

    #[test]
    fn test_trajectory_denies_network_after_successful_read_only() {
        let mut state = SessionState::new();
        state
            .record_pending_tool_call(
                RpcId::Number("1".into()),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
            )
            .unwrap();
        state.complete_pending_tool_call(&RpcId::Number("1".into()), true);
        assert_eq!(
            state.last_successful_side_effect(),
            Some(crate::policy::SideEffect::ReadOnly)
        );

        let err = state
            .check_trajectory(
                &read_only_then_network_rule(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
                false,
            )
            .unwrap_err();
        assert!(err.contains("trajectory"), "{err}");
        assert!(err.contains("deny-next=\"network\""), "{err}");
    }

    #[test]
    fn test_trajectory_denies_extractable_host_after_read_only() {
        let mut state = SessionState::new();
        state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
        let err = state
            .check_trajectory(
                &read_only_then_network_rule(),
                "post_data",
                Some(crate::policy::SideEffect::Write),
                true,
            )
            .unwrap_err();
        assert!(err.contains("deny-next=\"network\""), "{err}");
    }

    #[test]
    fn test_trajectory_failed_call_does_not_update_last() {
        let mut state = SessionState::new();
        state
            .record_pending_tool_call(
                RpcId::Number("1".into()),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
            )
            .unwrap();
        state.complete_pending_tool_call(&RpcId::Number("1".into()), false);
        assert!(state.last_successful_side_effect().is_none());
        assert!(
            state
                .check_trajectory(
                    &read_only_then_network_rule(),
                    "fetch_url",
                    Some(crate::policy::SideEffect::Network),
                    false,
                )
                .is_ok()
        );
    }

    #[test]
    fn test_trajectory_failed_write_does_not_clear_successful_read() {
        let mut state = SessionState::new();
        state
            .record_pending_tool_call(
                RpcId::Number("1".into()),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
            )
            .unwrap();
        state.complete_pending_tool_call(&RpcId::Number("1".into()), true);
        state
            .record_pending_tool_call(
                RpcId::Number("2".into()),
                "fail_write",
                Some(crate::policy::SideEffect::Write),
            )
            .unwrap();
        state.complete_pending_tool_call(&RpcId::Number("2".into()), false);
        assert_eq!(
            state.last_successful_side_effect(),
            Some(crate::policy::SideEffect::ReadOnly)
        );
        let err = state
            .check_trajectory(
                &read_only_then_network_rule(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
                false,
            )
            .unwrap_err();
        assert!(err.contains("trajectory"), "{err}");
    }

    #[test]
    fn test_trajectory_same_tool_is_not_denied() {
        let mut state = SessionState::new();
        state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
        assert!(
            state
                .check_trajectory(
                    &read_only_then_network_rule(),
                    "read_file",
                    Some(crate::policy::SideEffect::Network),
                    true,
                )
                .is_ok()
        );
    }

    #[test]
    fn test_trajectory_same_tool_extra_url_is_denied() {
        let mut state = SessionState::new();
        state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
        let err = state
            .check_trajectory(
                &read_only_then_network_rule(),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
                true,
            )
            .unwrap_err();
        assert!(err.contains("trajectory"), "{err}");
    }

    #[test]
    fn test_trajectory_same_tool_path_only_is_allowed() {
        let mut state = SessionState::new();
        state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
        assert!(
            state
                .check_trajectory(
                    &read_only_then_network_rule(),
                    "read_file",
                    Some(crate::policy::SideEffect::ReadOnly),
                    false,
                )
                .is_ok()
        );
    }

    #[test]
    fn test_trajectory_mrtr_retry_uses_tool_and_side_effect_only() {
        let mut state = SessionState::new();
        state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
        // New JSON-RPC id + requestState must not change the rule.
        state
            .record_pending_tool_call(
                RpcId::Number("99".into()),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
            )
            .unwrap();
        let err = state
            .check_trajectory(
                &read_only_then_network_rule(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
                false,
            )
            .unwrap_err();
        assert!(err.contains("trajectory"), "{err}");
    }
}
