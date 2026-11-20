//! Wire-level helpers for the auditor proxy: JSON-RPC frame I/O, error
//! response construction, field extraction, and S2C classification.
//!
//! Pure functions only — no proxy control flow lives here.

use tokio::io::AsyncWriteExt;

use super::session::RpcId;
use crate::error::AuditorError;
use crate::framing::{self, BoundedFrame, FramingError, OversizeFrame};

/// A raw JSON literal that outputs directly without additional quoting.
/// Used to embed a pre-existing JSON value (like a request id) into a built JSON object.
pub(crate) struct RawLiteral(String);

impl nojson::DisplayJson for RawLiteral {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "{}", self.0)
    }
}

/// True when a parsed JSON-RPC response has a `result` object containing `tools`.
///
/// This is used only as a fallback when a tools/list request id was not tracked.
/// A bare substring match on `"tools"` or `"nextCursor"` is not sufficient, so
/// tools/call responses are not classified as tools/list.
pub(crate) fn response_result_has_tools_field(value: nojson::RawJsonValue<'_, '_>) -> bool {
    let Ok(result_member) = value.to_member("result") else {
        return false;
    };
    let Some(result) = result_member.optional() else {
        return false;
    };
    result
        .to_member("tools")
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

/// True when a JSON-RPC response is a completed (non-interim) successful `result`.
///
/// JSON-RPC `error`, MRTR `input_required`, and MCP `result.isError=true` are
/// not successes and must not update trajectory state.
pub(crate) fn tools_call_result_succeeded(value: nojson::RawJsonValue<'_, '_>) -> bool {
    if !crate::protocol::value_is_response(value) {
        return false;
    }
    if crate::protocol::mcp_call_result_is_error(value) {
        return false;
    }
    match classify_s2c(value) {
        S2cKind::InputRequired => false,
        S2cKind::Other => {
            let has_error = value
                .to_member("error")
                .ok()
                .and_then(|m| m.optional())
                .is_some();
            let has_result = value
                .to_member("result")
                .ok()
                .and_then(|m| m.optional())
                .is_some();
            has_result && !has_error
        }
    }
}

/// Extract the `method` field from a JSON-RPC message line.
#[cfg(test)]
pub(crate) fn extract_method(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line).ok()?;
    let method = json
        .value()
        .to_member("method")
        .ok()?
        .optional()?
        .to_unquoted_string_str()
        .ok()?;
    Some(method.into_owned())
}

/// Extract the tool name (`params.name`) from a JSON-RPC tools/call request.
#[cfg(test)]
pub(crate) fn extract_tool_name_from_line(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line).ok()?;
    extract_tool_name_from_json(&json)
}

/// `extract_tool_name_from_line` on an already-parsed frame — the
/// product paths reuse the gate's `RawJson` instead of reparsing the
/// line for every tool-name lookup.
pub(crate) fn extract_tool_name_from_json(json: &nojson::RawJson<'_>) -> Option<String> {
    let name = json
        .value()
        .to_member("params")
        .ok()?
        .optional()?
        .to_member("name")
        .ok()?
        .optional()?
        .to_unquoted_string_str()
        .ok()?;
    Some(name.into_owned())
}

/// Extract `params.arguments.path` from a JSON-RPC tools/call request.
#[cfg(test)]
pub(crate) fn extract_argument_path(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line).ok()?;
    let path = json
        .value()
        .to_member("params")
        .ok()?
        .optional()?
        .to_member("arguments")
        .ok()?
        .optional()?
        .to_member("path")
        .ok()?
        .optional()?
        .to_unquoted_string_str()
        .ok()?;
    Some(path.into_owned())
}

/// Extract the raw JSON `id` field from a JSON-RPC message line.
/// Returns the raw text representation (e.g. `1` for a number, `"abc"` for a string).
#[cfg(test)]
pub(crate) fn extract_raw_id(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line).ok()?;
    extract_raw_id_json(&json)
}

/// `extract_raw_id` on an already-parsed frame — same member lookup
/// against the shared `RawJson`, no second parse.
pub(crate) fn extract_raw_id_json(json: &nojson::RawJson<'_>) -> Option<String> {
    let id = json.value().to_member("id").ok()?.optional()?;
    Some(id.as_raw_str().to_string())
}

/// Parse a raw `id` literal — the verbatim text of a message's `id`
/// member (`70`, `"abc"`, `70.0`) — into the canonical [`RpcId`] the
/// request tracker keys by. Bookkeeping such as `original_tools_list`
/// is keyed by this canonical id directly — raw spellings resolve
/// through this conversion at the lookup site. `None` for malformed
/// input.
pub(crate) fn rpc_id_from_raw_id(raw: &str) -> Option<RpcId> {
    RpcId::from_line(&format!("{{\"id\":{raw}}}"))
}

/// mcp-writ application error for policy denials.
///
/// MCP `2025-11-25` implementation-defined range; new codes must not use it.
/// This is **not** an MCP-reserved code: `-32020..=-32099` is reserved by
/// 2026-07-28 (`HeaderMismatch` is `-32020`, not `-32001`). Receivers MUST NOT
/// treat `-32001` as `HeaderMismatch`. Kept this phase (docs + this comment);
/// no renumber unless a later phase moves it outside `-32768..=-32000`.
///
/// <https://modelcontextprotocol.io/specification/2026-07-28/basic/>
pub(crate) const POLICY_VIOLATION_ERROR_CODE: i32 = -32001;

/// Server→client frame classification; tools/list verification is handled separately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S2cKind {
    /// MRTR interim result — completes the RPC but is not a tool success
    /// (trajectory bookkeeping only; passage is decided upstream).
    InputRequired,
    Other,
}

pub(crate) fn classify_s2c(value: nojson::RawJsonValue<'_, '_>) -> S2cKind {
    match extract_result_type(value).as_deref() {
        Some("input_required") => S2cKind::InputRequired,
        _ => S2cKind::Other,
    }
}

fn extract_result_type(value: nojson::RawJsonValue<'_, '_>) -> Option<String> {
    let result = value.to_member("result").ok()?.optional()?;
    result
        .to_member("resultType")
        .ok()?
        .optional()?
        .as_string_str()
        .ok()
        .map(str::to_string)
}

pub(crate) fn join_audit_details(sub_policy: Option<&str>, notes: &[String]) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(sp) = sub_policy {
        parts.push(format!("sub_policy: {sp}"));
    }
    parts.extend(notes.iter().cloned());
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// Build a JSON-RPC error response for a policy violation.
/// Uses nojson builder to construct the JSON (no manual string concatenation).
/// `tool_denied` is true only for a tool-level authorization refusal;
/// every other refusal (argument target out of scope, session state,
/// validation) uses the call-denied lead so the message never claims
/// an allowed tool is prohibited.
pub(crate) fn build_error_response(
    id_raw: &str,
    tool_name: &str,
    reason: &str,
    tool_denied: bool,
) -> String {
    let message = if tool_denied {
        format!("Policy violation: tool '{tool_name}' is not allowed ({reason})")
    } else {
        format!("Policy violation: call to tool '{tool_name}' was denied ({reason})")
    };
    let id_literal = RawLiteral(id_raw.to_string());
    let result = nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", &id_literal)?;
        f.member(
            "error",
            nojson::object(|ef| {
                ef.member("code", POLICY_VIOLATION_ERROR_CODE)?;
                ef.member("message", message.as_str())
            }),
        )
    });
    result.to_string()
}

pub(crate) fn build_jsonrpc_error(id_raw: &str, message: &str) -> String {
    let id_literal = RawLiteral(id_raw.to_string());
    let result = nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", &id_literal)?;
        f.member(
            "error",
            nojson::object(|ef| {
                ef.member("code", POLICY_VIOLATION_ERROR_CODE)?;
                ef.member("message", message)
            }),
        )
    });
    result.to_string()
}

/// Choose the id for a client-facing frame.
///
/// `raw_id` is the id of the response that triggered the action. When that
/// response answered an internally emitted request (`answered_internal` —
/// a pagination follow-up or list_changed revalidation), `raw_id` is an
/// internal request id that must not leak downstream, so only the original
/// client request id is used. Returns `None` when no id can be correlated
/// back to a client request.
pub(crate) fn client_facing_id<'a>(
    collecting_client_id: Option<&'a str>,
    raw_id: Option<&'a str>,
    answered_internal: bool,
) -> Option<&'a str> {
    if answered_internal {
        collecting_client_id
    } else {
        collecting_client_id.or(raw_id)
    }
}

/// The client-facing `tools/list` failure. The message is a constant:
/// the real reason can carry server-advertised tool names — including
/// tools the policy hides from this client — and internal verification
/// detail neither belongs on the wire nor is needed there (the caller
/// records it to the audit channel through `internal_list_failure` /
/// the verification-failed error).
pub(crate) fn build_tools_list_error_response(id_raw: &str) -> String {
    let message = "tools/list verification failed";
    let id_literal = RawLiteral(id_raw.to_string());
    let result = nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", &id_literal)?;
        f.member(
            "error",
            nojson::object(|ef| {
                ef.member("code", POLICY_VIOLATION_ERROR_CODE)?;
                ef.member("message", message)
            }),
        )
    });
    result.to_string()
}

fn io_err(e: std::io::Error) -> AuditorError {
    AuditorError::Io(e)
}

fn framing_err(e: FramingError) -> AuditorError {
    match e {
        FramingError::Io(e) => AuditorError::Io(e),
        FramingError::TooLarge { bytes, limit } => AuditorError::FrameTooLarge { bytes, limit },
    }
}

/// Read one JSON-RPC frame under `max_bytes`.
///
/// `Ok(Some(BoundedFrame::Oversize))` is a *recoverable* condition —
/// the frame was already consumed through its terminating newline (or
/// to EOF), so the caller applies per-request handling and the loop
/// continues on the next frame instead of dropping the session.
pub(crate) async fn read_proxy_frame<R: tokio::io::AsyncBufRead + Unpin>(
    reader: &mut R,
    max_bytes: usize,
) -> Result<Option<BoundedFrame>, AuditorError> {
    framing::read_frame_bounded(reader, max_bytes)
        .await
        .map_err(framing_err)
}

/// The client-facing message for a frame refused on size. The
/// `frame-too-large` suffix is the stable reason code the audit record
/// carries, so diagnostics and the wire error stay searchable together.
pub(crate) fn frame_too_large_message(kind: &str, limit: usize) -> String {
    format!("{kind} exceeds the {limit}-byte frame cap (frame-too-large)")
}

/// Client-facing text for a `Deny` verdict whose reason carries an
/// explanation — `request denied (<code>): <explain(method, direction)>`.
/// `direction` is the denied frame's direction so the explanation can
/// address the peer that actually mis-ordered (PR-35). Reasons without
/// an explanation return `None` and keep the caller's generic
/// `<message> (<reason>)` format.
pub(crate) fn deny_explanation(
    reason: crate::policy::mcp::DenyReason,
    method: &str,
    direction: crate::protocol::MessageDirection,
) -> Option<String> {
    reason
        .explain(method, direction)
        .map(|e| format!("request denied ({}): {e}", reason.as_str()))
}

/// The negotiated `result.protocolVersion` rendered for human-facing
/// surfaces: quoted, terminal-safe, bounded to the audit field budget.
/// `<absent>` when the server returned no usable member. Shared by the
/// client error, the stderr diagnostic, and the audit `details` extra so
/// all three read the same value (PR-23).
pub(crate) fn negotiated_version_label(negotiated: Option<&str>) -> String {
    match negotiated {
        Some(_) => format!("\"{}\"", negotiated_version_value(negotiated)),
        None => "<absent>".to_string(),
    }
}

/// The same negotiated version as a flat audit `details` value —
/// percent-encoded and bounded like every other `k=v` field, unquoted
/// so the raw JSONL stays greppable
/// (`server_protocol_version=2025-06-18`). A server-controlled value
/// carries no whitespace or `=`/`;` into the field, so it cannot forge
/// additional `k=v` members. `<absent>` when the server returned no
/// usable member (PR-23).
pub(crate) fn negotiated_version_value(negotiated: Option<&str>) -> String {
    match negotiated {
        Some(v) => {
            super::proxy_rpc::truncate_for_audit(&crate::audit_log::encode_audit_field_value(v))
        }
        None => "<absent>".to_string(),
    }
}

/// The cause string for an `initialize` result that negotiated a protocol
/// revision mcp-writ does not implement: the server's negotiated version
/// plus the versions an `initialize` result may negotiate — `2025-11-25`
/// only; `2026-07-28` is not acceptable here and must not be presented as
/// supported. Written identically into the client-facing JSON-RPC error
/// and the one-line stderr diagnostic (PR-23).
pub(crate) fn unsupported_version_message(negotiated: Option<&str>) -> String {
    format!(
        "server negotiated unsupported protocol version {} (supported: {})",
        negotiated_version_label(negotiated),
        crate::protocol::SUPPORTED_INITIALIZE_VERSIONS.join(", ")
    )
}

/// Cap on the number of member candidates scanned per retained window —
/// an attacker can pack thousands of `"id"` members into the windows;
/// correlation only ever needs the first few plausible ones.
const MAX_MEMBER_CANDIDATES: usize = 16;

/// Scan a retained window for `"<name>":<scalar>` member literals —
/// the head window forward in document order, the tail window backward
/// (last member first) when `reverse`.
///
/// This is a *recovery* scan over a raw byte window, not a parse: the
/// frame it inspects was already refused for size, and the candidates
/// it returns are only trusted once they resolve against the tracked
/// request table or validate as a complete `id` literal. A string
/// member's inner contents are never decoded — the raw literal is what
/// downstream echoes back.
///
/// Only members at JSON depth 1 — the envelope level where `id` and
/// `method` legitimately live — are accepted. Depth is tracked with
/// string and escape awareness: the head window begins at depth 0 so
/// its scan is always anchored, while the tail window anchors at the
/// frame's own close — its last non-whitespace byte must be `}`/`]`,
/// since an unterminated tail (a string cut off by EOF) leaves depth
/// unestablished and yields no candidates. A nested `result.id` or
/// `params.method` therefore cannot shadow the envelope member and
/// mis-correlate another in-flight request.
///
/// Provenance caveat: only head-window hits are *provably* depth-1 —
/// the forward scan counts depth from the frame's first byte. The
/// tail's backward scan anchors on whatever `}`/`]` closes the
/// retained region; when the frame's real root close is not retained
/// (truncation, an unterminated tail that happens to end in `}`) or
/// the frame is malformed, that anchor can be a nested close that
/// promotes a nested `result.id` to apparent envelope depth. A caller
/// whose candidates will retire a live request must use
/// [`recover_id_candidates_proven`] instead.
///
/// Caveat on malformed frames: the frame never passed the
/// duplicate-key gate, so a sender can plant a second depth-1 member
/// the scan reaches first (e.g. a forged tail-side `"id"` naming a
/// victim's in-flight request). The consequence is bounded to
/// releasing that request's tracking entry and delivering its id a
/// `frame-too-large` error — the same unverified-release posture a
/// denied response takes — never to forwarding uninspected content.
/// Candidate scalar literals for `name`. `following` is the byte
/// stream immediately after `buf` inside the frame: the tail's
/// overlap-trimmed prefix when the retained windows meet, the
/// retained lookahead byte when the dropped middle otherwise leaves
/// `buf`'s last byte unresolvable, and `Some(&[])` at the frame's own
/// end. A number or keyword literal that runs to the window edge is
/// a candidate only when its end is proven — a lookahead byte in the
/// token's class proves it *is* a prefix, and a missing lookahead
/// leaves it a possible prefix.
fn member_literal_candidates(buf: &[u8], following: Option<&[u8]>, name: &str) -> Vec<String> {
    // Positions are the byte just past each member name's closing
    // quote — `member_value_literal` re-verifies the `:` and extracts
    // the scalar. The head scan yields colon-proven, decoded member
    // names directly.
    let hits: Vec<usize> = head_member_positions(buf, name, following);
    hits.iter()
        .filter_map(|&at| member_value_literal(buf, at, following))
        .collect()
}

/// Whether an unquoted literal scanned to `buf`'s end may stand as a
/// candidate: `None` (middle omitted) or a continuation byte in the
/// token's class both mean the recovered text is at best a prefix.
fn literal_ends_proven(following: Option<&[u8]>, token_char: impl Fn(u8) -> bool) -> bool {
    match following {
        None => false,
        Some(f) => f.first().is_none_or(|&b| !token_char(b)),
    }
}

/// Member-name positions at JSON depth 1, scanning forward from the
/// frame's first byte — the head window always begins at depth 0, so
/// depth is established unconditionally. A nested member is never a
/// candidate.
///
/// Each hit is the byte just past a member name's closing quote where
/// `ws* ':'` is proven — inside the window or by the retained
/// lookahead byte (`following`, `Some(&[])` at the frame's own end
/// never supplies it). Names compare *decoded*: `"i\u0064"` is `id`
/// and `"j\u0073onrpc"` is `jsonrpc`, so an escape-spelled envelope
/// member still counts — while a depth-1 string that is not a member
/// (`{"x":"id"}`) is skipped as one literal and can never consume the
/// candidate bound ahead of later members.
///
/// The scan proceeds only when the first non-whitespace byte opens the
/// root object (`{`): a scalar root (`123`, `"x"`, `true`) never opens
/// or closes depth, so without the gate a *second* root's `{"id":…}`
/// would scan as a depth-1 member of "the" frame. An array root is
/// excluded the same way — array elements sit at depth 1 as values,
/// and a malformed `["id":5]` must not yield a member literal. An
/// incomplete `{`-root prefix still recovers normally: the gate only
/// reads the first byte.
fn head_member_positions(buf: &[u8], name: &str, following: Option<&[u8]>) -> Vec<usize> {
    let mut hits = Vec::new();
    let mut i = 0usize;
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    if buf.get(i) != Some(&b'{') {
        return hits;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    // Member-key position at the root's depth: `true` after `{` opens
    // the root and after each `,`, `false` after `:` and after any
    // complete depth-1 string (which consumed its own slot — a name
    // expects `:` next, a value expects `,`/`}`). Without it a
    // malformed frame such as `{"a":"id":5}` would credit the *value*
    // `"id"` as an envelope member on closing quote + colon alone.
    let mut expect_member = true;
    while i < buf.len() && hits.len() < MAX_MEMBER_CANDIDATES {
        let b = buf[i];
        if !in_string && b == b'"' {
            // An odd backslash run means this `"` is escaped interior
            // content — inside a string by escape math even though the
            // scan is nominally outside one (malformed input) — and the
            // in-string walker takes over from the next byte.
            if !preceding_slashes(buf, i).is_multiple_of(2) {
                in_string = true;
                i += 1;
                continue;
            }
            // Whole-literal handling: the string is skipped atomically
            // so interior bytes never perturb depth or the string
            // state, and its decoded inner bytes are the member-name
            // comparison — an escape-spelled name still resolves.
            let (inner, after, closed) = string_literal(buf, i);
            if closed
                && depth == 1
                && expect_member
                && json_name_eq(inner, name)
                && colon_after(buf, after, following)
            {
                hits.push(after);
            }
            if depth == 1 {
                // Whatever slot this string filled, it is gone now.
                expect_member = false;
            }
            i = after;
            continue;
        }
        if in_string {
            match b {
                // `\` escapes exactly one byte for the purpose of
                // finding the close quote (`\u` hex digits cannot
                // contain a quote or backslash).
                b'\\' => i += 2,
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        match b {
            b'{' | b'[' => depth += 1,
            b'}' | b']' => {
                if depth == 1 {
                    // The first JSON root closed — members of a second
                    // root must never combine with this one's into a
                    // single frame's evidence.
                    break;
                }
                depth = depth.saturating_sub(1);
            }
            b',' if depth == 1 => expect_member = true,
            b':' if depth == 1 => expect_member = false,
            _ => {}
        }
        i += 1;
    }
    hits
}

/// The string literal opened at `open` (`buf[open] == '"'`): its inner
/// bytes, the position just past the closing quote — `buf.len()` when
/// the literal runs unterminated to the window edge — and whether that
/// closing quote was found at all. An unterminated name is at best a
/// prefix (the window may have cut a longer name, or the document may
/// carry no closing quote before its `:`), so it is never member-name
/// evidence.
fn string_literal(buf: &[u8], open: usize) -> (&[u8], usize, bool) {
    let mut j = open + 1;
    while j < buf.len() {
        match buf[j] {
            b'\\' => j += 2,
            b'"' => return (&buf[open + 1..j], j + 1, true),
            _ => j += 1,
        }
    }
    (&buf[open + 1..], buf.len(), false)
}

/// A member name's inner bytes equal `name`: byte-for-byte when no
/// escapes appear, else compared decoded — `\uXXXX` and the
/// single-character escapes resolve first, so `"i\u0064"` is `id`.
/// A name that fails decode can never equal the ASCII vocabulary the
/// callers probe (`id`, `method`, `result`, `error`, `jsonrpc`).
fn json_name_eq(inner: &[u8], name: &str) -> bool {
    if !inner.contains(&b'\\') {
        return inner == name.as_bytes();
    }
    decode_member_name(inner).is_some_and(|d| d == name.as_bytes())
}

/// Decode a JSON string's inner bytes — `\"` `\\` `\/` `\b` `\f` `\n`
/// `\r` `\t` and `\uXXXX`. `None` on malformed escapes, truncated
/// `\uXXXX`, or a surrogate half (a lone surrogate cannot spell an
/// ASCII member name).
fn decode_member_name(inner: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(inner.len());
    let mut i = 0usize;
    while i < inner.len() {
        if inner[i] == b'\\' {
            let esc = *inner.get(i + 1)?;
            match esc {
                b'"' => out.push(b'"'),
                b'\\' => out.push(b'\\'),
                b'/' => out.push(b'/'),
                b'b' => out.push(0x08),
                b'f' => out.push(0x0C),
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'u' => {
                    let hex = inner.get(i + 2..i + 6)?;
                    let cp = u16::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
                    let ch = char::from_u32(cp as u32)?;
                    let mut enc = [0u8; 4];
                    out.extend_from_slice(ch.encode_utf8(&mut enc).as_bytes());
                    i += 4;
                }
                _ => return None,
            }
            i += 2;
        } else {
            out.push(inner[i]);
            i += 1;
        }
    }
    Some(out)
}

/// `ws* ':'` proven at `after` — inside the window, or by the retained
/// lookahead byte when the literal ends at the window's edge.
fn colon_after(buf: &[u8], after: usize, following: Option<&[u8]>) -> bool {
    let mut j = after;
    while j < buf.len() && buf[j].is_ascii_whitespace() {
        j += 1;
    }
    match buf.get(j) {
        Some(&b) => b == b':',
        None => following.is_some_and(|f| f.first() == Some(&b':')),
    }
}

/// Member-name positions (the byte just past each name's closing
/// quote) for members of the frame's *last* complete root — the root
/// whose close is the retained last byte. `whole` is the reassembled
/// frame, so `whole[0]` is the frame's own first byte; `tail_start` is
/// the offset inside it where the retained tail window begins, and
/// only members ending inside the tail window are reported — members
/// before it already went through the head scan's own adjudication,
/// so the tail scan must not resurrect a literal the head rejected.
///
/// A `}`/`]` at the frame's end is not by itself evidence of a root
/// close — `{"result":{…,"id":5}` ends on a nested `}` the same scan
/// would anchor on, and a preceding `}`/`]` may itself close a nested
/// value. The backward pass therefore only *locates* the depth-1 open
/// the last byte could close, then proves it is a root by walking the
/// remaining prefix: whitespace and complete root documents only, all
/// the way to `whole[0]`. A `:`/`,`/literal/`"` between roots, an
/// unclosed earlier root, or no anchored open at all leaves the close's
/// root membership unproven, and no candidate is returned. With the
/// root proven, the candidates are the *forward* scan's member hits
/// inside it — the same member-key evidence the head scan requires —
/// so a phantom name the backward scan would have credited (a closing
/// quote of an earlier string reading as `"id"` on raw bytes) can
/// never be attributed.
fn tail_member_positions(whole: &[u8], tail_start: usize, name: &str) -> Vec<usize> {
    let Some((root_open, _)) = last_root_span(whole) else {
        return Vec::new();
    };
    head_member_positions(&whole[root_open..], name, Some(&[]))
        .into_iter()
        .map(|at| root_open + at)
        .filter(|&at| at >= tail_start)
        .rev()
        .collect()
}

/// The frame's last complete root document, as its opening byte's
/// position, when the retained last byte provably *is* that root's
/// close: the forward scan — authoritative about string boundaries in
/// a way backward pairing can never be on malformed input — must see
/// depth return to 0 exactly at the last non-whitespace byte, and only
/// whitespace or complete earlier roots may precede it. A `}`/`]` at
/// the frame's end is not by itself evidence of a root close:
/// `{"result":{…,"id":5}` ends on a nested `}` (the forward scan still
/// sits at depth 1 there, so it yields `None`), and garbage between
/// roots or a never-opened root is rejected the same way.
fn last_root_span(whole: &[u8]) -> Option<(usize, usize)> {
    let mut end = whole.len();
    while end > 0 && whole[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    if end == 0 || !matches!(whole[end - 1], b'}' | b']') {
        return None;
    }
    let mut depth = 0usize;
    let mut in_string = false;
    // The `{`/`[` the current root region opened with — meaningful
    // only while `depth > 0`.
    let mut open = None;
    let mut i = 0usize;
    while i < end {
        let b = whole[i];
        if in_string {
            match b {
                b'\\' => i += 2,
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        match b {
            b'"' => {
                // Even or odd backslash run, the bytes ahead lie inside
                // a string: an unescaped `"` opens one, and an escaped
                // `\"` can only appear *inside* one. The in-string arm
                // walks to the real close (it skips `\\` escapes), so
                // a phantom member name cannot shift the pairing.
                in_string = true;
                i += 1;
            }
            b'{' | b'[' => {
                if depth == 0 {
                    open = Some(i);
                }
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 && i == end - 1 {
                    return Some((open?, i));
                }
                i += 1;
            }
            _ => {
                // Between roots only whitespace may appear — anything
                // else makes the trailing close's root membership
                // unprovable.
                if depth == 0 && !b.is_ascii_whitespace() {
                    return None;
                }
                i += 1;
            }
        }
    }
    None
}

/// Count the backslash run ending just before `at` — an odd run means
/// the byte at `at` is escaped.
fn preceding_slashes(buf: &[u8], at: usize) -> usize {
    let mut slashes = 0usize;
    let mut i = at;
    while i > 0 && buf[i - 1] == b'\\' {
        slashes += 1;
        i -= 1;
    }
    slashes
}

/// After a member name at `name_end`, require `ws* ':' ws*` then return
/// the scalar literal (string, number, `true`/`false`/`null`) verbatim.
/// Structured values (`{`/`[` openers) and unterminated strings yield
/// `None` — an `id`/`method` is never one of those on a well-formed
/// frame. An unquoted literal reaching `buf`'s end also yields `None`
/// unless `following` proves the token ended there.
fn member_value_literal(buf: &[u8], name_end: usize, following: Option<&[u8]>) -> Option<String> {
    let mut i = name_end;
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    if buf.get(i) != Some(&b':') {
        return None;
    }
    i += 1;
    while i < buf.len() && buf[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    match *buf.get(i)? {
        b'"' => {
            i += 1;
            while i < buf.len() {
                match buf[i] {
                    b'"' => {
                        // Strict UTF-8, never lossy: the oversized reader
                        // retains raw bytes with no upstream validation,
                        // so a quoted id holding invalid bytes would
                        // otherwise surface as a candidate spelled with
                        // U+FFFD — replacement text that never appeared
                        // on the wire and could alias a tracked id that
                        // legitimately contains U+FFFD (EF BF BD stays
                        // valid here).
                        return std::str::from_utf8(&buf[start..=i]).ok().map(str::to_owned);
                    }
                    // `\` escapes exactly one byte for the purpose of
                    // finding the close quote (`\u` hex digits cannot
                    // contain a quote or backslash).
                    b'\\' => i += 2,
                    _ => i += 1,
                }
            }
            None
        }
        b'-' | b'0'..=b'9' => {
            while i < buf.len() && matches!(buf[i], b'0'..=b'9' | b'.' | b'+' | b'-' | b'e' | b'E')
            {
                i += 1;
            }
            // A numeric literal at the window edge may be a prefix of a
            // longer token (`42` of `421`) — keep it only when the
            // following byte stream proves the token ended.
            if i == buf.len()
                && !literal_ends_proven(following, |b| {
                    matches!(b, b'0'..=b'9' | b'.' | b'+' | b'-' | b'e' | b'E')
                })
            {
                return None;
            }
            Some(String::from_utf8_lossy(&buf[start..i]).into_owned())
        }
        b't' | b'f' | b'n' => {
            while i < buf.len() && buf[i].is_ascii_lowercase() {
                i += 1;
            }
            if i == buf.len() && !literal_ends_proven(following, |b| b.is_ascii_lowercase()) {
                return None;
            }
            Some(String::from_utf8_lossy(&buf[start..i]).into_owned())
        }
        _ => None,
    }
}

/// Candidate `id` literals recovered from an oversized frame's retained
/// head/tail windows. Emitters disagree on member order — a request
/// writes `id` near the top (ahead of `params`/`method`), while the TS
/// SDK serializes a *response's* `id` as the last member — so
/// `prefer_tail` picks which edge's hits come first: tail hits are
/// returned in reverse document order (the last member first), head
/// hits in document order. Only envelope-depth (`depth 1`) members are
/// candidates at all — a nested `params.id`/`result.id` cannot alias an
/// in-flight request — and callers still resolve every candidate
/// against `WireState` (S2C) or shape-validate it (C2S) before trusting
/// it, so a depth-1 `id` that names no in-flight request is inert. A
/// sender can still *choose* which genuine envelope `id` the recovery
/// sees first on a duplicate-key-malformed frame (see
/// [`member_literal_candidates`]); a candidate that aliases another
/// in-flight request only releases tracking — it cannot fabricate or
/// forward verified content.
pub(crate) fn recover_id_candidates(frame: &OversizeFrame, prefer_tail: bool) -> Vec<String> {
    let head = member_literal_candidates(&frame.head, head_continuation(frame), "id");
    // The tail scan needs the reassembled frame: it locates the open
    // the last byte may close and must validate complete roots all the
    // way back to the frame's first byte before any member under that
    // close counts. On a disjoint tail the frame start is unreachable,
    // so no tail candidate carries root-boundary evidence.
    let whole = reassembled_frame(frame);
    let tail: Vec<String> = whole
        .as_deref()
        .map(|whole| {
            tail_member_positions(whole, frame.head.len(), "id")
                .into_iter()
                .filter_map(|at| member_value_literal(whole, at, Some(&[])))
                .collect()
        })
        .unwrap_or_default();
    let mut out: Vec<String> = if prefer_tail {
        tail.into_iter().chain(head).collect()
    } else {
        head.into_iter().chain(tail).collect()
    };
    out.dedup();
    out
}

/// The whole frame, reassembled, when the head and tail windows cover
/// every byte between them (`covered >= frame.bytes`): overlapping
/// windows are trimmed at the seam. `None` while a middle span is
/// dropped — the tail's anchor is then unprovable. Reassembly lets the
/// forward scan anchor at the frame's real first byte, so tail-side
/// members get proven depth.
fn reassembled_frame(frame: &OversizeFrame) -> Option<Vec<u8>> {
    let covered = frame.head.len().saturating_add(frame.tail.len());
    if covered < frame.bytes {
        return None;
    }
    let overlap = covered - frame.bytes;
    let mut whole = Vec::with_capacity(frame.bytes);
    whole.extend_from_slice(&frame.head);
    whole.extend_from_slice(&frame.tail[overlap..]);
    Some(whole)
}

/// `id` candidates that provably name an envelope member. The forward
/// scan counts depth from the frame's first byte, so when the retained
/// windows cover the whole frame every hit is exact; when the middle
/// is omitted only head-window hits count — a disjoint tail's backward
/// scan anchors on the retained region's own closing `}`/`]`, which a
/// nested `result.id` can impersonate when the frame's real root close
/// is not visible (truncation) or never existed (malformed input).
/// These are the only candidates trusted to complete a client RPC;
/// tail hits remain available to [`recover_id_candidates`] for
/// echo-back, where a wrong guess costs a stray id on an error frame.
pub(crate) fn recover_id_candidates_proven(frame: &OversizeFrame) -> Vec<String> {
    if let Some(whole) = reassembled_frame(frame) {
        member_literal_candidates(&whole, Some(&[]), "id")
    } else {
        member_literal_candidates(&frame.head, head_continuation(frame), "id")
    }
}

/// `true` when the retained windows *prove* the frame carries
/// response shape — a `result` or `error` member name at envelope
/// depth with its `:` visible inside the window or via the retained
/// lookahead byte. When head and tail together cover the whole frame
/// the reassembled scan anchors depth at the frame's real first byte,
/// so a member beginning past the head window counts too; with a
/// dropped middle only head hits count, since a tail hit could be a
/// nested member promoted by a dropped opener. A server *request*
/// carries neither member at the top level, so proven evidence is
/// what separates an oversized response — whose `id` may legitimately
/// complete a client RPC — from a request whose `method` fell into
/// the omitted middle.
pub(crate) fn recover_response_evidence(frame: &OversizeFrame) -> bool {
    if let Some(whole) = reassembled_frame(frame) {
        // The reassembled frame is complete — a `result`/`error`
        // member only proves response shape inside a *valid* envelope,
        // which must also carry `jsonrpc: "2.0"`. A member-named frame
        // without it is not a response completion anything may retire
        // on; incomplete frames (below) keep the head-only check since
        // the `jsonrpc` member can legitimately sit in the dropped
        // middle. The value compares *decoded* — escape spellings such
        // as `"2\u002e0"` resolve to the same `2.0`.
        return envelope_response_member(&whole, Some(&[]))
            && member_literal_candidates(&whole, Some(&[]), "jsonrpc")
                .iter()
                .any(|lit| {
                    lit.strip_prefix('"')
                        .and_then(|s| s.strip_suffix('"'))
                        .is_some_and(|inner| json_name_eq(inner.as_bytes(), "2.0"))
                });
    }
    envelope_response_member(&frame.head, head_continuation(frame))
}

/// `true` when the retained windows prove the frame is
/// response-*shaped* — a `result`/`error` member at envelope depth —
/// whether or not the envelope is otherwise valid. A response-shaped
/// frame still consumed a response slot: the request it answered
/// would wait forever if the frame were simply dropped, so
/// attribution and fail-closed settlement run on shape, while
/// [`recover_response_evidence`] — which additionally requires a
/// valid `jsonrpc` member on a fully retained frame — decides what
/// may complete an RPC outright.
pub(crate) fn recover_response_shape(frame: &OversizeFrame) -> bool {
    if let Some(whole) = reassembled_frame(frame) {
        return envelope_response_member(&whole, Some(&[]));
    }
    envelope_response_member(&frame.head, head_continuation(frame))
}

/// A `result`/`error` member at envelope depth — the shape a frame
/// must show to have consumed a response slot, regardless of whether
/// its envelope is otherwise valid.
fn envelope_response_member(buf: &[u8], following: Option<&[u8]>) -> bool {
    envelope_member_named(buf, following, "result")
        || envelope_member_named(buf, following, "error")
}

/// A member `name` at head-window depth 1 whose `:` is proven — inside
/// the window, or by the byte the reader retained immediately after it
/// (`Some(&[])` at the frame's own end is not a `:`).
fn envelope_member_named(buf: &[u8], following: Option<&[u8]>, name: &str) -> bool {
    !head_member_positions(buf, name, following).is_empty()
}

/// The byte stream immediately after the head window inside the frame:
/// the tail's overlap-trimmed prefix when the two windows cover the
/// whole frame, else the one lookahead byte the bounded reader retains
/// for exactly this proof — `None` only when the frame itself ended at
/// the head boundary.
fn head_continuation(frame: &OversizeFrame) -> Option<&[u8]> {
    let covered = frame.head.len().saturating_add(frame.tail.len());
    if covered >= frame.bytes {
        Some(&frame.tail[covered - frame.bytes..])
    } else {
        frame.head_next.as_ref().map(std::slice::from_ref)
    }
}

/// Audit detail shared by both directions' oversized-frame handling:
/// byte counts, never payload content — the refused frame is
/// attacker-controlled, so only bounded metadata reaches the log.
pub(crate) fn oversize_extra(frame: &OversizeFrame, limit: usize) -> String {
    let mut s = format!("frame_bytes={} frame_limit={limit}", frame.bytes);
    if !frame.terminated {
        s.push_str(" unterminated");
    }
    s
}

/// The `method` member of an oversized frame, when it survived in the
/// retained windows — head first (every emitter writes `method` near
/// the top), then tail for completeness. `None` means the frame is
/// treated as a response (requests always carry `method`).
pub(crate) fn recover_method(frame: &OversizeFrame) -> Option<String> {
    let whole = reassembled_frame(frame);
    let tail = whole
        .as_deref()
        .map(|whole| {
            tail_member_positions(whole, frame.head.len(), "method")
                .into_iter()
                .filter_map(|at| member_value_literal(whole, at, Some(&[])))
        })
        .into_iter()
        .flatten();
    for lit in member_literal_candidates(&frame.head, head_continuation(frame), "method")
        .into_iter()
        .chain(tail)
    {
        // Wrap the literal in an object so a bare scalar parses as a
        // member value (the same trick `rpc_id_from_raw_id` uses).
        if let Ok(json) = nojson::RawJson::parse(&format!("{{\"m\":{lit}}}"))
            && let Ok(member) = json.value().to_member("m")
            && let Some(v) = member.optional()
            && let Ok(s) = v.as_string_str()
        {
            return Some(s.to_string());
        }
    }
    None
}

pub(crate) async fn write_client_frame<W: tokio::io::AsyncWrite + Unpin>(
    out: &tokio::sync::Mutex<W>,
    line: &str,
) -> Result<(), AuditorError> {
    let mut buf = Vec::with_capacity(line.len() + 1);
    buf.extend_from_slice(line.as_bytes());
    buf.push(b'\n');
    let mut guard = out.lock().await;
    guard.write_all(&buf).await.map_err(io_err)?;
    // Every byte committed — a flush failure cannot prove the frame
    // never crossed, so the outcome is unprovable rather than a
    // clean non-delivery.
    guard
        .flush()
        .await
        .map_err(AuditorError::DeliveryUncertain)?;
    Ok(())
}

/// The frame bytes themselves — newline-terminated JSON. Shared by the
/// unbounded and epoch-bounded writers so both serialize identically.
async fn write_frame_bytes<W: tokio::io::AsyncWrite + Unpin>(
    writer: &mut W,
    line: &str,
) -> Result<(), AuditorError> {
    writer.write_all(line.as_bytes()).await.map_err(io_err)?;
    // The document bytes committed — a newline-write failure cannot
    // prove non-delivery: a reader that accepts a trailing unterminated
    // document at EOF (as `read_frame_bounded` does) may still dispatch
    // it when the pipe dies, so the outcome is unprovable either way.
    writer
        .write_all(b"\n")
        .await
        .map_err(AuditorError::DeliveryUncertain)?;
    // Every byte committed — a flush failure cannot prove the frame
    // never crossed, so the outcome is unprovable rather than a
    // clean non-delivery.
    writer
        .flush()
        .await
        .map_err(AuditorError::DeliveryUncertain)?;
    Ok(())
}

/// Lock `out`, fail closed when the writer is gone, and write the
/// frame. Kept small so the epoch variant can hold the same guard
/// across a bounded write and a poisoning `take` in one critical
/// section.
fn locked_child_writer<'a, W: tokio::io::AsyncWrite + Unpin>(
    guard: &'a mut tokio::sync::MutexGuard<'_, Option<W>>,
) -> Result<&'a mut W, AuditorError> {
    guard.as_mut().ok_or_else(|| {
        io_err(std::io::Error::new(
            std::io::ErrorKind::BrokenPipe,
            "child stdin is closed",
        ))
    })
}

pub(crate) async fn write_child_frame<W: tokio::io::AsyncWrite + Unpin>(
    out: &tokio::sync::Mutex<Option<W>>,
    line: &str,
) -> Result<(), AuditorError> {
    let mut guard = out.lock().await;
    write_frame_bytes(locked_child_writer(&mut guard)?, line).await
}

/// Hard bound on a child-stdin write that runs inside the `list_epoch`
/// dispatch critical section — a deadlock bound, not a latency target.
/// The S2C raises this section serializes against live on the task that
/// drains the child's stdout (`raise_list_gate` takes the epoch): an
/// unbounded write into a full stdin pipe would wait on the child
/// reading, the child on its stdout draining, and the drain on this
/// epoch — a cycle. On expiry the call unwinds like any write error; a
/// partially-written frame makes the stream untrustworthy anyway.
pub(crate) const EPOCH_CHILD_WRITE_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);

/// `write_child_frame` bounded by [`EPOCH_CHILD_WRITE_BUDGET`] — for the
/// epoch-held `tools/call` dispatch path only; every other caller
/// keeps the unbounded form.
///
/// The `out` guard is held across the bounded write *and* the timeout
/// cleanup, in one critical section: a cancelled write may have
/// committed a partial frame, so on timeout the writer is taken while
/// still locked — a writer already queued on the mutex then wakes to
/// `None` and fails closed instead of appending onto corrupt bytes
/// before the session abort unwinds.
pub(crate) async fn write_child_frame_epoch<W: tokio::io::AsyncWrite + Unpin>(
    out: &tokio::sync::Mutex<Option<W>>,
    line: &str,
) -> Result<(), AuditorError> {
    let mut guard = out.lock().await;
    let result = {
        let writer = locked_child_writer(&mut guard)?;
        tokio::time::timeout(EPOCH_CHILD_WRITE_BUDGET, write_frame_bytes(writer, line)).await
    };
    match result {
        Ok(r) => r,
        Err(_) => {
            guard.take();
            // The cancelled write may have committed the complete frame
            // before expiry — the bytes that crossed are unprovable
            // either way, so the request's arrival is uncertain rather
            // than established non-delivery.
            Err(AuditorError::DeliveryUncertain(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "child stdin write stalled inside the list epoch",
            )))
        }
    }
}

/// Declared `params._meta["io.modelcontextprotocol/protocolVersion"]` of a
/// stored request line, when present as a string.
///
/// Internally re-emitted requests (pagination, list_changed revalidation)
/// must re-declare the client's revision verbatim — an unknown version is
/// preserved, not rewritten to `2026-07-28`.
fn declared_meta_protocol_version(line: &str) -> Option<String> {
    let json = nojson::RawJson::parse(line).ok()?;
    json.value()
        .to_member("params")
        .ok()?
        .optional()?
        .to_member("_meta")
        .ok()?
        .optional()?
        .to_member(crate::protocol::META_PROTOCOL_VERSION)
        .ok()?
        .optional()?
        .as_string_str()
        .ok()
        .map(str::to_string)
}

/// The `id` the wire emits for internal request sequence `n` — the
/// reserved-namespace string [`session::internal_id_str`] produces and
/// [`session::RpcId::internal`] keys tracking on, so a client numeric id
/// can never alias an internal request's correlation entry.
pub(crate) fn build_internal_tools_list_request(template: &str, internal_id: u64) -> String {
    let id = super::session::internal_id_str(internal_id);
    if let Some(version) = declared_meta_protocol_version(template) {
        crate::protocol::build_meta_request_with_str_id(&id, "tools/list", None, &version)
    } else {
        nojson::object(|f| {
            f.member("jsonrpc", "2.0")?;
            f.member("id", id.as_str())?;
            f.member("method", "tools/list")?;
            f.member("params", nojson::object(|_| Ok(())))
        })
        .to_string()
    }
}

pub(crate) fn build_pagination_request(original: &str, internal_id: u64, cursor: &str) -> String {
    let id = super::session::internal_id_str(internal_id);
    if let Some(version) = declared_meta_protocol_version(original) {
        crate::protocol::build_meta_request_with_str_id(&id, "tools/list", Some(cursor), &version)
    } else {
        nojson::object(|f| {
            f.member("jsonrpc", "2.0")?;
            f.member("id", id.as_str())?;
            f.member("method", "tools/list")?;
            f.member("params", nojson::object(|p| p.member("cursor", cursor)))
        })
        .to_string()
    }
}

pub(crate) fn build_verified_tools_list_response(
    id_raw: &str,
    tools: &[crate::tool_def::ToolDefinition],
    result_extras: &[(String, String)],
) -> String {
    let id_literal = RawLiteral(id_raw.to_string());
    nojson::object(|f| {
        f.member("jsonrpc", "2.0")?;
        f.member("id", &id_literal)?;
        f.member(
            "result",
            nojson::object(|r| {
                r.member(
                    "tools",
                    nojson::array(|a| {
                        for tool in tools {
                            // Rebuild from hash-v4 / scanned fields only.
                            a.element(RawLiteral(
                                crate::protocol::tools_list::verified_tool_json(tool),
                            ))?;
                        }
                        Ok(())
                    }),
                )?;
                // Only explicitly approved result metadata forwards.
                // `tools` fields are rebuilt from hash-v4 / scanned data,
                // but result-level members are not covered by the manifest
                // scan or the advertised-set hash — forwarding `_meta` or
                // vendor keys verbatim would relay uninspected content to
                // the client, and `RawLiteral` splices values verbatim so
                // even allowlisted members are shape-checked first.
                // `nextCursor` stays consumed by pagination.
                for (name, raw) in result_extras {
                    if FORWARDED_RESULT_MEMBERS.contains(&name.as_str())
                        && forwarded_result_value_valid(name.as_str(), raw.as_str())
                    {
                        r.member(name.as_str(), RawLiteral(raw.clone()))?;
                    }
                }
                Ok(())
            }),
        )
    })
    .to_string()
}

/// Result-level members the verified `tools/list` response may forward —
/// the revision-defined listing metadata. Members outside this set
/// (`_meta`, vendor keys) are dropped: they bypass the manifest scan and
/// the advertised-set hash, so they must not reach the client until the
/// scan and hash paths cover them.
const FORWARDED_RESULT_MEMBERS: &[&str] = &["resultType", "ttlMs", "cacheScope"];

/// Shape check for an allowlisted result member before it goes through
/// `RawLiteral` verbatim: `resultType`/`cacheScope` accept only short
/// identifier strings (no escapes, so nothing inside can re-enter the
/// JSON structure), `ttlMs` only a non-negative integer. Anything else
/// is dropped.
fn forwarded_result_value_valid(name: &str, raw: &str) -> bool {
    match name {
        "resultType" | "cacheScope" => raw
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .is_some_and(|inner| {
                !inner.is_empty()
                    && inner.len() <= 64
                    && inner
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            }),
        "ttlMs" => raw.parse::<u64>().is_ok(),
        _ => false,
    }
}

#[cfg(test)]
mod tests;
