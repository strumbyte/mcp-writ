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
    SandboxNetworkDenied,
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
            Self::SandboxNetworkDenied => "sandbox.network_denied",
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
            Self::SandboxFileDenied | Self::SandboxNetworkDenied | Self::SandboxProcessDenied => {
                "sandbox"
            }
            Self::ValidationPathTraversal | Self::ValidationArgumentInvalid => "validation",
            Self::GuardStarted | Self::GuardStopped => "system",
            Self::PolicyLoaded | Self::PolicyReloaded | Self::PolicyError => "configuration",
            Self::SessionStarted | Self::SessionEnded => "session",
            Self::ServerConnected | Self::ServerDisconnected | Self::ServerError => "server",
            Self::HashVerified
            | Self::HashMismatch
            | Self::ToolsListChanged
            | Self::ManifestFinding => "supply_chain",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Severity / Outcome / Action
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// flat `details` string. `None` serializes as `"enforcement":null`.
    pub enforcement: Option<String>,
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
            schema_version: "1.0",
        }
    }
}
