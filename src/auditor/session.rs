use std::collections::{HashMap, HashSet};

use crate::policy::deputy::DeputyRule;
use crate::policy::{SideEffect, TrajectoryRule};

mod extract;
mod rpc_id;

pub use extract::{extract_paths_for_pending, extract_paths_from_response};
pub use rpc_id::RpcId;
pub(crate) use rpc_id::internal_id_str;
use rpc_id::rpc_id_bytes;

/// Tracks file paths discovered during a **process-local** Confused Deputy check.
///
/// Opt-in (`confused_deputy_protection`, default off). Which tools count as
/// path discovery vs path use comes from `deputy::deputy_binding`: an
/// explicit `deputy` block on the tool wins, and tools without one keep
/// the compatibility mapping — `list_files` / `list_directory` are
/// discovery (the call's id is pended and a **successful** forwarded
/// response to it seeds `known_paths`), `read_file` is the use side
/// (allowed only for paths already discovered). Any tool bound to no
/// role gets no check from this feature (its ordinary policy gates still
/// apply). Path traversal (`../`) is always blocked regardless of known
/// paths.
///
/// The fixed-name defaults exist because `side_effect` cannot distinguish
/// a path-discovering call from a path-using one — both are typically
/// `read_only`. Explicit roles (`deputy role="discover"|"use"|"none"`)
/// are the generalization; they share this single state — they are not
/// session or state separation.
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
    /// Canonicalized file paths seeded by successful discovery-role
    /// responses (`record_paths` applies `normalize_fs_argument`, so a
    /// `file:` URI in a payload records the filesystem path).
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
    /// `tools/call`s released **without an execution verdict** —
    /// forwarded cancels and policy-refused responses — kept as
    /// per-call tombstones until the call's own definitive response
    /// resolves it or the session ends. Cancellation is advisory and a
    /// refused response still reached the server, so each tombstone is
    /// a *candidate* for the true last executed call in trajectory deny
    /// matching. Candidates never replace the verified marker: recording
    /// an unproven "success" would let a client launder `after=X` rules
    /// away by cancelling a call that may never have run — and the
    /// same-tool exemption is justified only while every candidate is
    /// provably that same tool. Tombstones are **not** cleared by an
    /// unrelated verified success: a different call completing proves
    /// nothing about whether the cancelled call ran — only the call's
    /// own response resolves it. A cancelled call whose late response
    /// completes successfully becomes the verified marker itself.
    /// Bounded by `MAX_UNVERIFIED_TOOL_CALLS` / `MAX_UNVERIFIED_ID_BYTES`.
    unverified_tool_calls: HashMap<RpcId, PendingToolCall>,
    unverified_id_bytes: usize,
    /// Side effects of unverified calls that overflowed the tombstone
    /// cap. Per-call attribution is lost, but the coarse set keeps
    /// `after` matching over-approximate (fail closed) instead of
    /// silently forgetting the candidate. Bounded by the `SideEffect`
    /// variant count.
    unverified_overflow_effects: HashSet<SideEffect>,
    /// Latched when an unverified-completion tombstone overflows the
    /// cap: once candidates had to be dropped the same-tool exemption
    /// can never be proven again — a later verified success cannot
    /// restore information already lost, so the latch is permanent for
    /// the session.
    unverified_untrusted: bool,
    /// In-flight `tools/call` awaiting a success/error response.
    pending_tool_calls: HashMap<RpcId, PendingToolCall>,
    pending_tool_id_bytes: usize,
}

/// A discovery call in flight: the extraction rules its successful,
/// correlated response must seed `known_paths` with. Snapshotted at
/// request time so a later policy view cannot change what an in-flight
/// response records.
#[derive(Debug, Clone)]
pub(crate) struct PendingList {
    tool: String,
    rules: Vec<DeputyRule>,
}

impl PendingList {
    /// The discover-role tool the pending call invoked — kept for
    /// audit/debug attribution when its response seeds `known_paths`.
    pub fn tool(&self) -> &str {
        &self.tool
    }

    pub fn rules(&self) -> &[DeputyRule] {
        &self.rules
    }
}

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
/// Bounds on the unverified-completion tombstone set. Tombstones
/// accumulate across a session (a server may simply never answer a
/// cancelled call), so overflow folds the call's side effect into a
/// coarse set and latches the exemption proof off — never a silent
/// truncation.
const MAX_UNVERIFIED_TOOL_CALLS: usize = 256;
const MAX_UNVERIFIED_ID_BYTES: usize = 65_536;

impl SessionState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request ID as a pending discovery operation, snapshotting
    /// the extraction `rules` its response will seed `known_paths` with.
    /// Returns an error when quotas are exceeded or the id is already in flight.
    pub(crate) fn record_pending_list(
        &mut self,
        request_id: RpcId,
        tool: &str,
        rules: &[DeputyRule],
    ) -> Result<(), String> {
        if matches!(request_id, RpcId::Null) {
            return Err("JSON-RPC id must not be null".to_string());
        }
        if self.pending_list_requests.contains_key(&request_id) {
            return Err("duplicate in-flight JSON-RPC id".to_string());
        }
        if self.pending_list_requests.len() >= MAX_PENDING_LISTS {
            return Err("too many pending list requests".to_string());
        }
        let id_bytes = rpc_id_bytes(&request_id);
        if self.pending_id_bytes.saturating_add(id_bytes) > MAX_PENDING_ID_BYTES {
            return Err("pending list id budget exceeded".to_string());
        }
        self.pending_id_bytes += id_bytes;
        self.pending_list_requests.insert(
            request_id,
            PendingList {
                tool: tool.to_string(),
                rules: rules.to_vec(),
            },
        );
        Ok(())
    }

    /// Check if a request ID is a pending discovery operation; on a hit,
    /// remove it and return its snapshot (rules it may seed with). Failed
    /// responses consume the entry the same way — pending bookkeeping is
    /// always released.
    pub(crate) fn take_pending_list(&mut self, request_id: &RpcId) -> Option<PendingList> {
        let pending = self.pending_list_requests.remove(request_id)?;
        self.pending_id_bytes = self
            .pending_id_bytes
            .saturating_sub(rpc_id_bytes(request_id));
        Some(pending)
    }

    /// Record discovered file paths from a discovery-role response.
    /// Values are canonicalized with the same `normalize_fs_argument` the
    /// use side applies to tool arguments (percent-decode, `file:` URI to
    /// path, NFKC), so a discovery payload that names its targets as URIs
    /// still matches a use call that passes the filesystem path. Values
    /// that cannot normalize are dropped — no use call can produce them
    /// either. Traversal stays deny-first on the use side, so recording a
    /// `..` or percent-encoded `..` string can never let it through.
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
            let normalized = match crate::pathutil::normalize_fs_argument(trimmed) {
                Ok(n) => n,
                Err(_) => continue,
            };
            if normalized.is_empty() || normalized.len() > MAX_PATH_BYTES {
                continue;
            }
            if self.known_path_bytes.saturating_add(normalized.len()) > MAX_KNOWN_PATH_BYTES {
                tracing::warn!("known_paths byte budget reached");
                break;
            }
            if self.known_paths.insert(normalized.clone()) {
                self.known_path_bytes += normalized.len();
            }
        }
    }

    /// Check if a file access is allowed. `path` is the canonicalized
    /// target — callers pass what the use-side extraction normalized via
    /// `normalize_fs_argument` (never re-normalize here: a second decode
    /// pass would diverge from the seed form).
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
                "path '{path}' was not discovered by a discovery-role tool call",
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
        // The retained bytes are id + tool name — an unbudgeted name
        // would let a client grow the map past the byte cap.
        let entry_bytes = rpc_id_bytes(&request_id).saturating_add(tool_name.len());
        if self.pending_tool_id_bytes.saturating_add(entry_bytes) > MAX_PENDING_ID_BYTES {
            return Err("pending tool-call id budget exceeded".to_string());
        }
        self.pending_tool_id_bytes += entry_bytes;
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
    ///
    /// A response arriving for an id with no pending entry may still
    /// resolve an unverified tombstone — the wire's definitive verdict
    /// for a cancelled call arrives under the same id, so a completed
    /// `result` proves the call ran (it becomes the verified marker)
    /// and an error proves it did not.
    pub fn complete_pending_tool_call(&mut self, request_id: &RpcId, succeeded: bool) {
        if let Some(pending) = self.remove_pending_tool_call(request_id) {
            if succeeded {
                self.record_verified_success(pending.tool_name, pending.side_effect);
            }
            return;
        }
        if let Some(tombstone) = self.take_unverified(request_id)
            && succeeded
        {
            self.record_verified_success(tombstone.tool_name, tombstone.side_effect);
        }
    }

    /// Release a pending `tools/call` that ended **without an execution
    /// verdict**: a forwarded `notifications/cancelled`, or a response the
    /// policy refused to relay. Both mean the call reached the server and
    /// may have run — unlike a delivered `error` / `isError` result, which
    /// is a definite failure verdict and completes `succeeded=false`.
    ///
    /// The entry joins the unverified tombstones: its side_effect can
    /// satisfy the `after` side of a trajectory deny rule, but the verified
    /// marker is never overwritten — an unproven "success" must not disarm
    /// `after=X` rules keyed on the real predecessor, nor unlock the
    /// same-tool exemption for a different tool. The tombstone resolves
    /// only on the call's own definitive response — a cancelled call's
    /// late reply — or persists to session end.
    pub fn release_pending_tool_call_unverified(&mut self, request_id: &RpcId) {
        let Some(pending) = self.remove_pending_tool_call(request_id) else {
            return;
        };
        // Charge the tombstone for everything it retains: the id plus
        // the tool name, not the id alone.
        let entry_bytes = rpc_id_bytes(request_id).saturating_add(pending.tool_name.len());
        if self.unverified_tool_calls.len() >= MAX_UNVERIFIED_TOOL_CALLS
            || self.unverified_id_bytes.saturating_add(entry_bytes) > MAX_UNVERIFIED_ID_BYTES
        {
            // Fail closed: keep the side-effect contribution for deny
            // matching and permanently disarm the exemption proof —
            // the dropped call's tool name is unknowable from then on.
            self.unverified_untrusted = true;
            if let Some(se) = pending.side_effect {
                self.unverified_overflow_effects.insert(se);
            }
            return;
        }
        self.unverified_id_bytes += entry_bytes;
        self.unverified_tool_calls
            .insert(request_id.clone(), pending);
    }

    /// Remove an unverified tombstone and refund its retained budget.
    fn take_unverified(&mut self, request_id: &RpcId) -> Option<PendingToolCall> {
        let tombstone = self.unverified_tool_calls.remove(request_id)?;
        self.unverified_id_bytes = self
            .unverified_id_bytes
            .saturating_sub(rpc_id_bytes(request_id) + tombstone.tool_name.len());
        Some(tombstone)
    }

    /// Remove a pending `tools/call` and refund its retained budget.
    fn remove_pending_tool_call(&mut self, request_id: &RpcId) -> Option<PendingToolCall> {
        let pending = self.pending_tool_calls.remove(request_id)?;
        self.pending_tool_id_bytes = self
            .pending_tool_id_bytes
            .saturating_sub(rpc_id_bytes(request_id) + pending.tool_name.len());
        Some(pending)
    }

    /// Record the only completion that proves execution: a forwarded
    /// JSON-RPC response with a completed `result`. The marker is
    /// last-wins by observed completion. Unverified tombstones are
    /// **not** cleared: a different call completing proves nothing about
    /// whether a cancelled call ran — each tombstone resolves only on
    /// its own definitive response (or session end).
    fn record_verified_success(&mut self, tool_name: String, side_effect: Option<SideEffect>) {
        self.last_successful_tool = Some(tool_name);
        self.last_successful_side_effect = side_effect;
    }

    /// Record a successful `tools/call` directly (unit tests / already-correlated).
    pub fn record_successful_tool_call(
        &mut self,
        tool_name: &str,
        side_effect: Option<SideEffect>,
    ) {
        self.record_verified_success(tool_name.to_string(), side_effect);
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
        // Candidates for the last executed call: the verified marker plus
        // every tombstoned call released without an execution verdict
        // (its cancel or denied response may still mean it ran). With no
        // candidate there is no predecessor for an `after` rule to key on.
        let unverified_effects = || {
            self.unverified_tool_calls
                .values()
                .filter_map(|c| c.side_effect)
                .chain(self.unverified_overflow_effects.iter().copied())
        };
        if self.last_successful_side_effect.is_none() && unverified_effects().next().is_none() {
            return Ok(());
        }
        // The same-tool exemption applies only when every candidate is
        // provably that same tool: an unverified call of another tool may
        // be the true last execution, making this a cross-tool chain.
        let same_tool = self
            .last_successful_tool
            .as_deref()
            .is_none_or(|t| t == next_tool)
            && !self.unverified_untrusted
            && self
                .unverified_tool_calls
                .values()
                .all(|c| c.tool_name == next_tool);
        if same_tool {
            let sneak_url = has_host_or_url && next_side_effect != Some(SideEffect::Network);
            if !sneak_url {
                return Ok(());
            }
        }
        for rule in rules {
            let matches_after = self.last_successful_side_effect == Some(rule.after_side_effect)
                || unverified_effects().any(|se| se == rule.after_side_effect);
            if !matches_after {
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

#[cfg(test)]
mod tests;
