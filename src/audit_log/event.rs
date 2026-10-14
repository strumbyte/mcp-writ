//! The audit event model: OCSF-compatible event taxonomy, severity /
//! outcome / action enums, policy context, and the `AuditEvent` record
//! every sink serializes.

use uuid::Uuid;

use super::emit::now_iso8601_millis;

// ═══════════════════════════════════════════════════════════════════════════════
// Event Type Taxonomy (OCSF-compatible)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    // policy_enforcement
    ToolCallAllowed,
    ToolCallDenied,
    ToolCallModified,
    ToolsListFiltered,
    McpMessageAllowed,
    McpMessageDenied,
    McpMessageDropped,
    McpMessageUndecided,
    // sandbox
    SandboxFileDenied,
    SandboxNetworkAllowed,
    SandboxNetworkDenied,
    SandboxNetworkResolved,
    SandboxProcessDenied,
    // validation
    ValidationPathTraversal,
    ValidationArgumentInvalid,
    // system
    GuardStarted,
    GuardStopped,
    // configuration
    PolicyLoaded,
    PolicyReloaded,
    PolicyError,
    // session
    SessionStarted,
    SessionEnded,
    // server
    ServerConnected,
    ServerDisconnected,
    ServerError,
    // supply_chain
    HashVerified,
    HashMismatch,
    ToolsListChanged,
    ToolsListVerified,
    ManifestFinding,
}

impl EventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ToolCallAllowed => "tool_call.allowed",
            Self::ToolCallDenied => "tool_call.denied",
            Self::ToolCallModified => "tool_call.modified",
            Self::ToolsListFiltered => "tools_list.filtered",
            Self::McpMessageAllowed => "mcp_message.allowed",
            Self::McpMessageDenied => "mcp_message.denied",
            Self::McpMessageDropped => "mcp_message.dropped",
            Self::McpMessageUndecided => "mcp_message.undecided",
            Self::SandboxFileDenied => "sandbox.file_denied",
            Self::SandboxNetworkAllowed => "sandbox.network_allowed",
            Self::SandboxNetworkDenied => "sandbox.network_denied",
            Self::SandboxNetworkResolved => "sandbox.network_resolved",
            Self::SandboxProcessDenied => "sandbox.process_denied",
            Self::ValidationPathTraversal => "validation.path_traversal",
            Self::ValidationArgumentInvalid => "validation.argument_invalid",
            Self::GuardStarted => "guard.started",
            Self::GuardStopped => "guard.stopped",
            Self::PolicyLoaded => "policy.loaded",
            Self::PolicyReloaded => "policy.reloaded",
            Self::PolicyError => "policy.error",
            Self::SessionStarted => "session.started",
            Self::SessionEnded => "session.ended",
            Self::ServerConnected => "server.connected",
            Self::ServerDisconnected => "server.disconnected",
            Self::ServerError => "server.error",
            Self::HashVerified => "hash.verified",
            Self::HashMismatch => "hash.mismatch",
            Self::ToolsListChanged => "tools_list.changed",
            Self::ToolsListVerified => "tools_list.verified",
            Self::ManifestFinding => "manifest.finding",
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            Self::ToolCallAllowed
            | Self::ToolCallDenied
            | Self::ToolCallModified
            | Self::ToolsListFiltered
            | Self::McpMessageAllowed
            | Self::McpMessageDenied
            | Self::McpMessageDropped
            | Self::McpMessageUndecided => "policy_enforcement",
            Self::SandboxFileDenied
            | Self::SandboxNetworkAllowed
            | Self::SandboxNetworkDenied
            | Self::SandboxNetworkResolved
            | Self::SandboxProcessDenied => "sandbox",
            Self::ValidationPathTraversal | Self::ValidationArgumentInvalid => "validation",
            Self::GuardStarted | Self::GuardStopped => "system",
            Self::PolicyLoaded | Self::PolicyReloaded | Self::PolicyError => "configuration",
            Self::SessionStarted | Self::SessionEnded => "session",
            Self::ServerConnected | Self::ServerDisconnected | Self::ServerError => "server",
            Self::HashVerified
            | Self::HashMismatch
            | Self::ToolsListChanged
            | Self::ToolsListVerified
            | Self::ManifestFinding => "supply_chain",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Severity / Outcome / Action
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 1,
    Low = 2,
    Medium = 3,
    High = 4,
    Critical = 5,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn id(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Allowed,
    Denied,
    Observed,
    Modified,
}

impl Action {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Observed => "observed",
            Self::Modified => "modified",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Policy Audit Context
// ═══════════════════════════════════════════════════════════════════════════════

/// Policy identity stamped on audit events and launch reports. `id` is
/// the bound server name (or `default` for a server-less policy) — not a
/// file identifier; `hash` binds the record to the policy's effective
/// KDL form (see `Policy::audit_context`).
#[derive(Debug, Clone)]
pub struct PolicyAuditContext {
    pub id: String,
    pub version: String,
    pub hash: String,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Audit Event
// ═══════════════════════════════════════════════════════════════════════════════

/// The audit JSONL schema version stamped on every record. Adding a
/// member (e.g. `enforcement`) or an `event_type` value is backward
/// compatible within the version — readers must tolerate unknown
/// members — so this bumps only on a breaking shape change (a renamed
/// or removed member, or a respelled value), recorded in the migration
/// guide.
pub const AUDIT_SCHEMA_VERSION: &str = "1.0";

/// Byte ceiling for a single string member copied into an audit record
/// from wire data — tool names, request ids, violation detail. Client
/// frames can reach 1 MiB; without a per-field bound a denied request's
/// cloned values would inflate the count-bounded queue into a memory
/// exhaust. Longer values keep a bounded UTF-8 prefix plus the original
/// length, so the evidence records that truncation happened.
pub const MAX_AUDIT_FIELD_BYTES: usize = 1024;

/// Bound `text` to [`MAX_AUDIT_FIELD_BYTES`]: a UTF-8-safe prefix plus
/// a `…[truncated N bytes]` marker recording the original length.
/// Applied by the logger to every free-form string member at enqueue —
/// the single chokepoint all producers pass through, so no caller can
/// bypass the bound by constructing an oversized field.
pub fn bound_audit_field(text: &str) -> String {
    if text.len() <= MAX_AUDIT_FIELD_BYTES {
        return text.to_string();
    }
    let mut cut = MAX_AUDIT_FIELD_BYTES;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…[truncated {} bytes]", &text[..cut], text.len())
}

/// A complete JSON object embedded verbatim into a record member — the
/// payload type of [`AuditEvent::enforcement`]. The held text is
/// private and `EmbeddedJson::new` is crate-visible, so the member
/// can be filled only by an in-crate producer that serialized it —
/// today `EnforcementSummary::to_json` (`crate::enforcement`). An
/// arbitrary `String` cannot be spliced into the JSONL line.
#[derive(Debug, Clone)]
pub struct EmbeddedJson(String);

impl EmbeddedJson {
    /// Wrap already-serialized JSON object text. `pub(crate)` keeps the
    /// member mintable only inside this crate; debug builds verify the
    /// text is a complete JSON object.
    pub(crate) fn new(json: String) -> Self {
        debug_assert!(
            nojson::RawJson::parse(&json)
                .is_ok_and(|j| j.value().kind() == nojson::JsonValueKind::Object),
            "EmbeddedJson must hold a complete JSON object"
        );
        Self(json)
    }

    /// The serialized object text — a complete JSON object.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub struct AuditEvent {
    pub timestamp: String,
    pub event_id: Uuid,
    pub correlation_id: Uuid,
    pub parent_event_id: Option<Uuid>,
    pub event_type: EventType,
    pub severity: Severity,
    pub outcome: Outcome,
    pub action: Action,
    pub target_server: Option<String>,
    pub target_tool: Option<String>,
    /// Raw JSON-RPC `id` of the client request this event answers, when the
    /// event is tied to a specific request. Lets a `tool_call.denied`
    /// record be correlated with the request it responded to. The stored
    /// value is the verbatim JSON token from the request — a string id
    /// keeps its quotes (`"\"req-42\""` in JSONL), a numeric id stays bare
    /// (`"12"`). Consumers must parse the stored string as a JSON value to
    /// recover the typed id.
    pub request_id: Option<String>,
    pub policy_context: Option<PolicyAuditContext>,
    pub details: Option<String>,
    /// Structured `enforcement` member — a verbatim JSON object produced
    /// by `EnforcementSummary::to_json` (`crate::enforcement`), set on
    /// launch records (`server.connected`, `server.error`) so the audit
    /// stream carries the backend/control/grant digest next to the
    /// flat `details` string. The digest is a launch-time snapshot: it
    /// mirrors the report's `plan`/`observations` as emitted — `result`
    /// finalizes at session end, but no observation is appended after
    /// emit. `None` serializes as `"enforcement":null`.
    pub enforcement: Option<EmbeddedJson>,
    /// Audit JSONL schema version — always [`AUDIT_SCHEMA_VERSION`].
    pub schema_version: &'static str,
}

impl AuditEvent {
    pub fn new(
        correlation_id: Uuid,
        event_type: EventType,
        severity: Severity,
        outcome: Outcome,
        action: Action,
    ) -> Self {
        Self {
            timestamp: now_iso8601_millis(),
            event_id: Uuid::now_v7(),
            correlation_id,
            parent_event_id: None,
            event_type,
            severity,
            outcome,
            action,
            target_server: None,
            target_tool: None,
            request_id: None,
            policy_context: None,
            details: None,
            enforcement: None,
            schema_version: AUDIT_SCHEMA_VERSION,
        }
    }

    /// Truncate every free-form string member to
    /// [`MAX_AUDIT_FIELD_BYTES`]. Called by the logger at enqueue —
    /// bounding here rather than at each producer means a future call
    /// site cannot accidentally queue an unbounded attacker-controlled
    /// field. `enforcement` is exempt: it holds a complete JSON object
    /// whose structure truncation would corrupt (the queue's byte
    /// budget still accounts its size).
    pub(crate) fn bound_wire_fields(&mut self) {
        for field in [
            self.target_server.as_mut(),
            self.target_tool.as_mut(),
            self.request_id.as_mut(),
            self.details.as_mut(),
        ]
        .into_iter()
        .flatten()
        {
            if field.len() > MAX_AUDIT_FIELD_BYTES {
                *field = bound_audit_field(field);
            }
        }
        if let Some(ctx) = self.policy_context.as_mut() {
            if ctx.id.len() > MAX_AUDIT_FIELD_BYTES {
                ctx.id = bound_audit_field(&ctx.id);
            }
            if ctx.version.len() > MAX_AUDIT_FIELD_BYTES {
                ctx.version = bound_audit_field(&ctx.version);
            }
            if ctx.hash.len() > MAX_AUDIT_FIELD_BYTES {
                ctx.hash = bound_audit_field(&ctx.hash);
            }
        }
    }

    /// Approximate serialized size — the share of the queue's byte
    /// budget this record consumes while queued. Not a billing meter:
    /// the sum must track the string members so an oversized payload
    /// cannot slip past the aggregate bound that count-based
    /// `CHANNEL_CAPACITY` misses.
    pub(crate) fn wire_size(&self) -> usize {
        let mut n = 256usize; // fixed members, names, punctuation
        for field in [
            self.target_server.as_deref(),
            self.target_tool.as_deref(),
            self.request_id.as_deref(),
            self.details.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            n += field.len();
        }
        if let Some(ctx) = &self.policy_context {
            n += ctx.id.len() + ctx.version.len() + ctx.hash.len();
        }
        if let Some(j) = &self.enforcement {
            n += j.as_str().len();
        }
        n
    }
}
