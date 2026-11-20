use super::schema_validator;
use super::session::SessionState;
use crate::policy::prepared::{ToolHit, ToolIndex};
use crate::policy::{InputResponsesMode, Policy, ResolvedInputResponses, SideEffect};
use crate::protocol::{MCP_VERSION_2025_11_25, MCP_VERSION_2026_07_28, META_PROTOCOL_VERSION};

mod sub_policy;
mod targets;

pub use targets::{extract_deputy_use_targets, extract_fs_targets, request_has_host_or_url};
pub(crate) use targets::{extract_deputy_use_targets_rc, request_has_host_or_url_json};

/// Maximum accepted `params.requestState` UTF-8 byte length.
///
/// `requestState` is an opaque client-echoed blob
/// ([MRTR](https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr)).
/// The Auditor never parses HMAC/AEAD or other structure. Oversized values are
/// rejected fail-secure so a retry cannot DoS the proxy.
pub const REQUEST_STATE_MAX_BYTES: usize = 65_536;

/// The tools/call denial reason for a listed-but-disallowed tool —
/// and the single wire string [`PolicyViolation::client_reason`]
/// collapses both authorization refusals into, so the two cannot be
/// told apart by the client.
pub(crate) const REASON_TOOL_NOT_ALLOWED: &str = "tool is not allowed";
/// The tools/call denial reason for a name with no policy entry at
/// all. Distinct in the audit record; identical on the wire.
const REASON_TOOL_NOT_FOUND: &str = "tool not found in policy (default deny)";

/// What a `PolicyViolation` refusal *is* — declared by the producer at
/// construction and read by the classifiers, never re-derived from
/// `reason`. A user-controlled path or host spelling that happens to
/// contain a denial phrase (`path traversal`, an existing reason's
/// suffix) must not steer the audit event type, the wire collapse, or
/// the widening-candidate selection.
///
/// The variants cover the refusal families the checker produces:
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DenialKind {
    /// Tool-level authorization refusal — the call names no allowed
    /// tool. `listed` distinguishes the audit detail: `true` for a
    /// listed-but-denied entry, `false` for a name the policy never
    /// declared. The wire collapses both into
    /// [`REASON_TOOL_NOT_ALLOWED`] so the client cannot probe which
    /// tool names exist in the policy.
    Authorization { listed: bool },
    /// User-space validation refusal — a traversal attempt or an
    /// `args_schema` rejection — earning a typed `validation.*` audit
    /// event alongside the deny record.
    Validation(ValidationKind),
    /// A target the call's arguments name was refused by a policy
    /// rule: the tool fs allow/deny sub-policy or the global/per-tool
    /// network host/egress rules. `correction_candidates
    /// .denied_targets` reports these as widening candidates.
    DeniedTarget,
    /// The secret-path overlay refused the argument.
    /// `reserved_match` marks the reserved-set hit — the one overlay
    /// refusal naming a denied *target* a wider allow could grant;
    /// the other overlay refusals reject the *spelling* (normalize
    /// failure, invisible Unicode, dirty URI scheme, opaque `file:`
    /// URI) and are never widening candidates.
    SecretOverlay { reserved_match: bool },
    /// Session-state refusal (`trajectory:` / `confused deputy:`).
    Session,
    /// Request-shape, contract-shape, and target-*spelling* refusals
    /// that name no denied target — JSON parse/shape errors,
    /// `requestState` and `inputResponses` contract violations,
    /// missing/non-canonical/unresolvable targets, extraction-budget
    /// failures, and policy-side resolution errors.
    Other,
}

/// Which `validation.*` audit event a [`DenialKind::Validation`]
/// refusal earns — the two shapes `validation_kind` emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ValidationKind {
    /// `EventType::ValidationPathTraversal` — a `..` escape in a
    /// use-side path or an `args_schema` file reference resolving
    /// outside the working directory.
    PathTraversal,
    /// `EventType::ValidationArgumentInvalid` — the tool's
    /// `args_schema` rejected the arguments.
    ArgumentInvalid,
}

impl ValidationKind {
    fn event_type(self) -> crate::audit_log::EventType {
        match self {
            Self::PathTraversal => crate::audit_log::EventType::ValidationPathTraversal,
            Self::ArgumentInvalid => crate::audit_log::EventType::ValidationArgumentInvalid,
        }
    }
}

/// Represents a policy violation when a tool call is not allowed.
#[derive(Debug)]
pub struct PolicyViolation {
    pub tool_name: String,
    /// Display/audit text — composed by the producer. No classifier
    /// reads meaning back out of it; a refusal's semantics live in
    /// `kind`.
    pub reason: String,
    /// What the refusal *is*, decided where it is produced.
    pub(crate) kind: DenialKind,
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tool '{}': {}", self.tool_name, self.reason)
    }
}

impl PolicyViolation {
    /// `kind` is the refusal's declared meaning — the classifiers read
    /// it; `reason` stays display/audit text only.
    pub(crate) fn new(
        tool_name: impl Into<String>,
        kind: DenialKind,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            tool_name: tool_name.into(),
            reason: reason.into(),
            kind,
        }
    }

    /// The user-space validation category this violation belongs to, if
    /// the refusal came from input validation rather than a policy rule:
    /// `validation.path_traversal` for the session/schema path checks,
    /// `validation.argument_invalid` for `args_schema` rejections. The
    /// producer declares the category through `DenialKind::Validation`;
    /// nothing re-parses the reason text.
    pub fn validation_kind(&self) -> Option<crate::audit_log::EventType> {
        match self.kind {
            DenialKind::Validation(v) => Some(v.event_type()),
            _ => None,
        }
    }

    /// The reason text a client may see. The authorization refusal keeps
    /// one wire string whether the name is an unallowed policy entry or
    /// absent entirely — answering differently would turn `tools/call`
    /// errors into an oracle for hidden tool names. The distinguishing
    /// reason is preserved in `self.reason` for the audit record.
    pub fn client_reason(&self) -> &str {
        match self.kind {
            DenialKind::Authorization { .. } => REASON_TOOL_NOT_ALLOWED,
            _ => &self.reason,
        }
    }

    /// Whether this refusal is a tool-level authorization refusal — the
    /// tool is unallowed or absent from the policy — rather than any
    /// other refusal of the call. The wire message uses this to
    /// distinguish the two, so it never claims an allowed tool is
    /// prohibited when only the call was denied.
    pub fn is_authorization_denial(&self) -> bool {
        matches!(self.kind, DenialKind::Authorization { .. })
    }

    /// Whether this refusal is a target-policy denial — a target the
    /// call's arguments name was refused by a policy rule: the tool
    /// fs allow/deny sub-policy, the secret-path overlay's reserved
    /// match, or the global/per-tool network host/egress rules — which
    /// is exactly what `correction_candidates.denied_targets` reports
    /// as widening candidates. Everything else stays out: tool-level
    /// authorization refusals, `args_schema` and path-traversal
    /// validation failures, session-state refusals (`trajectory:` /
    /// `confused deputy:`), contract-shape refusals (`inputResponses
    /// denied …`, a missing path/URL target, a non-canonical spelling,
    /// an extraction-budget or `requestState` cap failure), and the
    /// refusals of a *spelling* rather than a target — an
    /// unnormalizable or unresolvable path and the non-reserved
    /// overlay rejections — none names a denied target a wider grant
    /// could answer.
    pub fn is_denied_target(&self) -> bool {
        matches!(
            self.kind,
            DenialKind::DeniedTarget
                | DenialKind::SecretOverlay {
                    reserved_match: true
                }
        )
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

/// A client frame whose JSON was parsed and structurally verified once
/// at the C2S gate — the type downstream consumers receive so the same
/// request is never reparsed per consumer.
///
/// The only constructor is [`VerifiedFrame::parse_and_verify`]: the
/// syntax parse and the duplicate-key / nesting-depth walk must both
/// have run on *this* text, so no caller can build a view over
/// unverified input. Functions that need the gate's guarantee take
/// `&VerifiedFrame`; functions that only need the shared parse take
/// [`nojson::RawJson`], which the view hands out.
///
/// `json` borrows `frame`'s text, so the view lives only as long as the
/// frame buffer — the relay keeps that buffer for verbatim forwarding,
/// and nothing retains the borrow across a session-lock acquisition
/// longer than the synchronous check that uses it.
#[derive(Debug)]
pub(crate) struct VerifiedFrame<'text> {
    /// The original frame text — what the relay forwards verbatim.
    frame: &'text str,
    /// The one parse of `frame` every downstream consumer shares.
    json: nojson::RawJson<'text>,
}

/// Why a frame failed the structural gate. `Parse` carries nothing —
/// invalid JSON has no members to echo; `Checked` keeps the parsed
/// index so the denial can still recover the request's `id` member.
#[derive(Debug)]
pub(crate) enum FrameReject<'text> {
    /// `RawJson::parse` failed — no usable structure at all.
    Parse,
    /// The duplicate-key / nesting-depth walk refused the frame.
    Checked {
        json: nojson::RawJson<'text>,
        /// The checker-produced refusal text (client-facing).
        reason: String,
    },
}

impl<'text> VerifiedFrame<'text> {
    /// The single construction site: parse `frame`, then run the
    /// duplicate-key / depth walk over it. A `FrameReject` hands the
    /// partial result back so the gate can still report the failure —
    /// it is not a way to obtain the verified view.
    pub(crate) fn parse_and_verify(frame: &'text str) -> Result<Self, FrameReject<'text>> {
        #[cfg(feature = "measure")]
        crate::measure::incr(&crate::measure::JSON_PARSE_CALLS, 1);
        // Parse the original text — `RawJson` skips only the four JSON
        // whitespace characters, so a Unicode "space" like U+00A0 around
        // the frame is a parse rejection, not a silent normalization.
        let json = nojson::RawJson::parse(frame).map_err(|_| FrameReject::Parse)?;
        match check_duplicate_keys_recursively(json.value()) {
            Ok(()) => Ok(Self { frame, json }),
            Err(v) => Err(FrameReject::Checked {
                json,
                reason: v.reason,
            }),
        }
    }

    /// The original frame text — forwarded verbatim on an allow.
    pub(crate) fn frame(&self) -> &'text str {
        self.frame
    }

    /// The shared parse of `frame` — every consumer reuses this
    /// index rather than running `RawJson::parse` again.
    pub(crate) fn json(&self) -> &nojson::RawJson<'text> {
        &self.json
    }

    /// Root value of the shared parse.
    pub(crate) fn value(&self) -> nojson::RawJsonValue<'text, '_> {
        self.json.value()
    }
}

/// Maximum JSON nesting depth accepted by the Auditor.
pub const MAX_JSON_NESTING: u32 = 64;

/// Recursively check for duplicate object keys in a RawJsonValue.
pub(crate) fn check_duplicate_keys_recursively(
    val: nojson::RawJsonValue<'_, '_>,
) -> Result<(), PolicyViolation> {
    #[cfg(feature = "measure")]
    crate::measure::incr(&crate::measure::DUPKEY_SCAN_CALLS, 1);
    check_duplicate_keys_at_depth(val, 0)
}

fn check_duplicate_keys_at_depth(
    val: nojson::RawJsonValue<'_, '_>,
    depth: u32,
) -> Result<(), PolicyViolation> {
    if depth > MAX_JSON_NESTING {
        return Err(PolicyViolation::new(
            "<unknown>",
            DenialKind::Other,
            format!("JSON nesting exceeds {MAX_JSON_NESTING} levels"),
        ));
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            #[cfg(feature = "measure")]
            crate::measure::incr(&crate::measure::DUPKEY_OBJECT_NODES, 1);
            let mut seen = std::collections::HashSet::new();
            let obj_iter = val.to_object().map_err(|e| {
                PolicyViolation::new(
                    "<unknown>",
                    DenialKind::Other,
                    format!("failed to parse JSON object members: {e}"),
                )
            })?;
            for (k, v) in obj_iter {
                let key = k
                    .to_unquoted_string_str()
                    .map_err(|e| {
                        PolicyViolation::new(
                            "<unknown>",
                            DenialKind::Other,
                            format!("invalid object key encoding: {e}"),
                        )
                    })?
                    .into_owned();

                if !seen.insert(key.clone()) {
                    return Err(PolicyViolation::new(
                        "<unknown>",
                        DenialKind::Other,
                        format!("duplicate key '{key}' in JSON-RPC request"),
                    ));
                }
                check_duplicate_keys_at_depth(v, depth + 1)?;
            }
        }
        nojson::JsonValueKind::Array => {
            let arr_iter = val.to_array().map_err(|e| {
                PolicyViolation::new(
                    "<unknown>",
                    DenialKind::Other,
                    format!("failed to parse JSON array: {e}"),
                )
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
pub fn tool_is_allowed<L: ToolIndex + ?Sized>(index: &L, name: &str) -> bool {
    index.tool_allowed(name)
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
    #[cfg(feature = "measure")]
    crate::measure::incr(&crate::measure::JSON_PARSE_CALLS, 1);
    let json = match nojson::RawJson::parse(line) {
        Ok(j) => j,
        Err(e) => {
            return Err(PolicyViolation::new(
                "<unknown>",
                DenialKind::Other,
                format!("invalid JSON: {e}"),
            ));
        }
    };

    // Envelope validation: Must be a JSON Object (reject batch requests / non-objects)
    if json.value().kind() != nojson::JsonValueKind::Object {
        return Err(PolicyViolation::new(
            "<unknown>",
            DenialKind::Other,
            "request must be a JSON object (batch requests are not supported)",
        ));
    }

    // Check for duplicate keys in all nested objects across the entire JSON-RPC request
    check_duplicate_keys_recursively(json.value())?;

    check_request_inner(&json, policy)
}

/// `check_request` on a frame the C2S gate already verified — the
/// product path enters here so a request's parse and duplicate-key walk
/// run once, not once per consumer. The `VerifiedFrame` type is proof
/// the structural gate ran; standalone callers keep using
/// [`check_request`], which performs its own checks.
pub(crate) fn check_request_verified<L: ToolIndex + ?Sized>(
    view: &VerifiedFrame<'_>,
    index: &L,
) -> Result<CheckPass, PolicyViolation> {
    // The gate verified structure (duplicate keys / nesting depth), not
    // envelope kind — the object check stays part of this entry so a
    // non-object view can never become a malformed `tools/call` denial.
    if view.value().kind() != nojson::JsonValueKind::Object {
        return Err(PolicyViolation::new(
            "<unknown>",
            DenialKind::Other,
            "request must be a JSON object (batch requests are not supported)",
        ));
    }
    check_request_inner(view.json(), index)
}

/// The M2 request-time façade for the `bench` package: runs the same
/// verified-frame + prepared-policy path the product relay uses, so a
/// benchmark can time the request path against the prepared index
/// without driving the relay. Feature-gated like the `fuzz` /
/// `measure` façades — not part of the shipped API surface.
#[cfg(feature = "measure")]
#[doc(hidden)]
pub fn check_request_prepared(
    line: &str,
    prepared: &crate::policy::prepared::PreparedPolicy,
) -> Result<CheckPass, PolicyViolation> {
    let view = match VerifiedFrame::parse_and_verify(line) {
        Ok(view) => view,
        // `FrameReject::Parse` drops the parse detail by design, so the
        // message mirrors the relay's `deny_malformed` wording rather
        // than `check_request`'s "invalid JSON: {e}".
        Err(FrameReject::Parse) => {
            return Err(PolicyViolation::new(
                "<unknown>",
                DenialKind::Other,
                "invalid JSON".to_string(),
            ));
        }
        Err(FrameReject::Checked { reason, .. }) => {
            return Err(PolicyViolation::new("<unknown>", DenialKind::Other, reason));
        }
    };
    check_request_verified(&view, prepared)
}

/// The shared body of [`check_request`] / [`check_request_verified`] —
/// everything downstream of parse, envelope-shape, and the duplicate-key
/// walk, which each entry runs (or proves already ran) first. Tool
/// lookups run through the caller's index — the session's prepared
/// rules on the product path, the same linear scans a bare `&Policy`
/// answers with on the standalone path.
fn check_request_inner<L: ToolIndex + ?Sized>(
    json: &nojson::RawJson<'_>,
    index: &L,
) -> Result<CheckPass, PolicyViolation> {
    // Iterate through object members to extract method
    let mut method_opt: Option<String> = None;

    let obj_iter = json.value().to_object().map_err(|e| {
        PolicyViolation::new(
            "<unknown>",
            DenialKind::Other,
            format!("failed to parse JSON object members: {e}"),
        )
    })?;

    for (k_val, v_val) in obj_iter {
        let key = k_val
            .to_unquoted_string_str()
            .map_err(|e| {
                PolicyViolation::new(
                    "<unknown>",
                    DenialKind::Other,
                    format!("invalid object key encoding: {e}"),
                )
            })?
            .into_owned();

        if key == "method" {
            let m_str = v_val
                .to_unquoted_string_str()
                .map_err(|_| {
                    PolicyViolation::new(
                        "<unknown>",
                        DenialKind::Other,
                        "'method' field must be a valid JSON string",
                    )
                })?
                .into_owned();
            method_opt = Some(m_str);
        }
    }

    let mut audit_notes = protocol_version_audit_notes(json);
    let policy = index.document();

    // Step 1: Check method field
    let is_tools_call = method_opt.as_deref() == Some("tools/call");

    if !is_tools_call {
        return Ok(CheckPass {
            sub_policy: None,
            audit_notes,
        });
    }

    // Step 2: Extract params.name as an owned String
    let tool_name = extract_tool_name(json)?;

    // Step 3-6: Check against policy (including MRTR retries with a new JSON-RPC id)
    if !index.tool_allowed(&tool_name) {
        let listed = index.tool_listed(&tool_name);
        let reason = if listed {
            REASON_TOOL_NOT_ALLOWED
        } else {
            REASON_TOOL_NOT_FOUND
        };
        return Err(PolicyViolation::new(
            tool_name,
            DenialKind::Authorization { listed },
            reason,
        ));
    }

    let hit = match index.tool_named_allowed(&tool_name) {
        Some(hit) => hit,
        // Unreachable: `tool_allowed` just proved a listed, allowed entry
        // exists (duplicate tool names are rejected at policy load).
        None => {
            return Err(PolicyViolation::new(
                tool_name,
                DenialKind::Authorization { listed: false },
                REASON_TOOL_NOT_FOUND,
            ));
        }
    };

    // Step 4: Schema validation (if args_schema is defined)
    if hit.tool.args_schema.is_some() {
        validate_tool_args(json, &tool_name, &hit)?;
    }

    // Step 5: MRTR siblings of `arguments` — never feed requestState to schema
    check_request_state(json, &tool_name, &mut audit_notes)?;
    check_input_responses(json, &hit, &tool_name, &mut audit_notes)?;

    // Step 6: Tool-specific sub-policy checks (fs, network)
    let outcome = sub_policy::check_tool_sub_policy(json, hit, policy)?;
    if outcome.opaque_fields > 0 {
        // How many of the tool's `arguments { opaque }` declared fields
        // carried a value past the unrecognized-argument refusal —
        // a `0` stays silent so ordinary calls see no new detail.
        audit_notes.push(format!("opaque_fields={}", outcome.opaque_fields));
    }

    let sub_policy = if outcome.sub_policy {
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
    #[cfg(feature = "measure")]
    crate::measure::incr(&crate::measure::JSON_PARSE_CALLS, 1);
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
        // Client-declared — percent-encode so a value cannot forge
        // additional `k=v` members or `; `-joined notes in `details`.
        notes.push(format!(
            "protocolVersion={}",
            crate::audit_log::encode_audit_field_value(version)
        ));
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
        return Err(PolicyViolation::new(
            tool_name,
            DenialKind::Other,
            format!("requestState exceeds size cap ({size} > {REQUEST_STATE_MAX_BYTES} bytes)"),
        ));
    }

    audit_notes.push(format!("requestState present ({size} bytes)"));
    Ok(())
}

/// `params.requestState` byte length when it exceeds
/// [`REQUEST_STATE_MAX_BYTES`]; `None` when absent or within the cap.
/// The generic request path applies the cap to methods `check_request`
/// never sees (MRTR retries on `resources/read` / `prompts/get`, …).
/// The product path passes the gate's shared `RawJson` — the frame is
/// never reparsed for this lookup.
pub(crate) fn request_state_over_cap_json(json: &nojson::RawJson<'_>) -> Option<usize> {
    let size = request_state_byte_len(params_member(json, "requestState")?);
    (size > REQUEST_STATE_MAX_BYTES).then_some(size)
}

/// Line-parsing wrapper of [`request_state_over_cap_json`] for the
/// standalone unit tests — an unparseable input reports `None`, as it
/// always has.
#[cfg(test)]
pub(crate) fn request_state_over_cap(line: &str) -> Option<usize> {
    #[cfg(feature = "measure")]
    crate::measure::incr(&crate::measure::JSON_PARSE_CALLS, 1);
    let json = nojson::RawJson::parse(line.trim()).ok()?;
    request_state_over_cap_json(&json)
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
    hit: &ToolHit<'_>,
    tool_name: &str,
    audit_notes: &mut Vec<String>,
) -> Result<(), PolicyViolation> {
    if params_member(json, "inputResponses").is_none() {
        return Ok(());
    }

    match hit.resolved_input_responses() {
        ResolvedInputResponses::Deny => Err(PolicyViolation::new(
            tool_name,
            DenialKind::Other,
            input_responses_denied_reason(hit.tool.input_responses),
        )),
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
    #[cfg(feature = "measure")]
    crate::measure::incr(&crate::measure::JSON_PARSE_CALLS, 1);
    let json = match nojson::RawJson::parse(line) {
        Ok(j) => j,
        Err(e) => {
            return Err(PolicyViolation::new(
                "<unknown>",
                DenialKind::Other,
                format!("invalid JSON: {e}"),
            ));
        }
    };
    check_trajectory_json(&json, policy, session)
}

/// `check_trajectory` on an already-parsed frame — the product session
/// gate shares the C2S gate's `RawJson` rather than reparsing the line.
/// The `policy.trajectory` opt-out still short-circuits so a caller that
/// did not pre-check it sees the same no-op contract as the wrapper.
pub(crate) fn check_trajectory_json<L: ToolIndex + ?Sized>(
    json: &nojson::RawJson<'_>,
    index: &L,
    session: &SessionState,
) -> Result<(), PolicyViolation> {
    let policy = index.document();
    if !policy.trajectory {
        return Ok(());
    }
    let tool_name = extract_tool_name(json)?;
    let next_side_effect = index
        .tool_named(&tool_name)
        .and_then(|hit| hit.side_effect());
    let has_host_or_url = request_has_host_or_url_json(json);
    session
        .check_trajectory(
            &policy.trajectory_rules,
            &tool_name,
            next_side_effect,
            has_host_or_url,
        )
        .map_err(|reason| PolicyViolation::new(tool_name, DenialKind::Session, reason))
}

/// Look up a tool's documented `side_effect` for trajectory bookkeeping.
pub fn tool_side_effect<L: ToolIndex + ?Sized>(index: &L, tool_name: &str) -> Option<SideEffect> {
    index
        .tool_named(tool_name)
        .and_then(|hit| hit.side_effect())
}

fn validate_tool_args(
    json: &nojson::RawJson<'_>,
    tool_name: &str,
    hit: &ToolHit<'_>,
) -> Result<(), PolicyViolation> {
    let schema_ref = hit
        .tool
        .args_schema
        .as_deref()
        .expect("caller only invokes on a tool carrying args_schema");

    // Pick the evaluation document for this request:
    // - `Inline` (every KDL-loaded policy — the parser inlines `@file`
    //   at load): the document `PreparedPolicy` parsed once is shared
    //   by the session; no I/O ever happens here.
    // - `File` (a `@path` spelling that reached a prepared view — only
    //   programmatically built policies produce one): `resolve_schema`
    //   still runs per call — the cwd-scoped, no-follow read is the
    //   contract — and the `File` memo keys on the resolved *bytes*,
    //   so identical content reuses one parse while a rewrite plans
    //   fresh. Never keyed on the path itself.
    // - bare `Policy` lookup (the standalone path): a transient
    //   document per call — the per-request parse it always ran.
    let resolved;
    let transient;
    let cached;
    let prepared: &crate::schema_spec::prepared::PreparedSchema = match hit.schema_plan() {
        Some(crate::policy::prepared::ToolSchema::Inline(schema)) => schema,
        Some(plan @ crate::policy::prepared::ToolSchema::File(_)) => {
            resolved = resolve_schema_ref(schema_ref, tool_name)?;
            cached = plan.file_plan(&resolved);
            &cached
        }
        None => {
            resolved = resolve_schema_ref(schema_ref, tool_name)?;
            transient = crate::schema_spec::prepared::PreparedSchema::new(resolved);
            &transient
        }
    };

    // MCP allows omitting `params.arguments` — the schema sees the empty
    // object, so a `required` list still fails closed while an
    // all-optional schema accepts the omission.
    let empty_args;
    let arguments = match params_member(json, "arguments") {
        Some(v) => v,
        None => {
            empty_args = nojson::RawJson::parse("{}").expect("empty object literal parses");
            empty_args.value()
        }
    };

    schema_validator::validate_prepared(arguments, prepared).map_err(|e| {
        PolicyViolation::new(
            tool_name,
            DenialKind::Validation(ValidationKind::ArgumentInvalid),
            format!("schema validation failed: {e}"),
        )
    })
}

fn resolve_schema_ref(schema_ref: &str, tool_name: &str) -> Result<String, PolicyViolation> {
    schema_validator::resolve_schema(schema_ref).map_err(|e| {
        let kind = match &e {
            schema_validator::SchemaRefError::PathTraversal(_) => {
                DenialKind::Validation(ValidationKind::PathTraversal)
            }
            _ => DenialKind::Other,
        };
        PolicyViolation::new(tool_name, kind, e.into_reason())
    })
}

fn extract_tool_name(json: &nojson::RawJson<'_>) -> Result<String, PolicyViolation> {
    let params = json
        .value()
        .to_member("params")
        .ok()
        .and_then(|m| m.optional())
        .ok_or_else(|| {
            PolicyViolation::new("<unknown>", DenialKind::Other, "tools/call without params")
        })?;

    let name_str = params
        .to_member("name")
        .ok()
        .and_then(|m| m.optional())
        .ok_or_else(|| {
            PolicyViolation::new(
                "<unknown>",
                DenialKind::Other,
                "tools/call without params.name",
            )
        })?
        .to_unquoted_string_str()
        .map_err(|_| {
            PolicyViolation::new(
                "<unknown>",
                DenialKind::Other,
                "params.name is not a string",
            )
        })?;

    Ok(name_str.into_owned())
}

#[cfg(test)]
mod tests;
