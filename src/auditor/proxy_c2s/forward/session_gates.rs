//! Per-request session gates for an allowed `tools/call`: the
//! trajectory check, the Confused Deputy gate, and the pending-call /
//! pending-list bookkeeping recorded on `SessionState`.

use crate::auditor::checker;
use crate::auditor::proxy_state::ProxyShared;
use crate::auditor::session::{RpcId, SessionState};
use crate::policy::opaque::OpaqueMatcher;
use crate::policy::prepared::ToolIndex;
/// The legacy per-session gates for an allowed `tools/call`: trajectory
/// check, then the name-fixed Confused Deputy gate, then pending-call
/// registration. Mirrors the pre-PR-10 ordering. The session lock covers
/// the checks only — the verified frame's `RawJson` is borrowed *into*
/// the locked scope, never retained past it, so the borrow adds nothing
/// to the lock's hold time.
pub(super) async fn apply_session_gates<W>(
    shared: &ProxyShared<W>,
    check_result: Result<checker::CheckPass, checker::PolicyViolation>,
    view: &checker::VerifiedFrame<'_>,
    id: &RpcId,
    tool: Option<&str>,
) -> Result<checker::CheckPass, checker::PolicyViolation>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let Ok(check_pass) = check_result else {
        return check_result;
    };
    let Some(ref session) = shared.session else {
        return Ok(check_pass);
    };
    let mut state = session.lock().await;
    if shared.policy.trajectory
        && let Err(violation) = checker::check_trajectory_json(view.json(), &shared.policy, &state)
    {
        return Err(violation);
    }
    // Did the deputy gate record a pending list *for this request*?
    // Only then may the rollback remove it — under a reused id the
    // entry belongs to the earlier in-flight call, whose discovery
    // credit a duplicate's refusal must not consume. The gate's own
    // report is authoritative: it is false whenever protection is
    // disabled or no insertion happens, so the predicate can never
    // drift from the actual bookkeeping.
    let inserted_pending_list =
        apply_confused_deputy_c2s(&shared.policy, &mut state, view.json(), Some(id), tool)?;
    if shared.policy.trajectory {
        let se = tool.and_then(|name| checker::tool_side_effect(&shared.policy, name));
        if let Err(reason) =
            state.record_pending_tool_call(id.clone(), tool.unwrap_or("<unknown>"), se)
        {
            // Roll back only the pending list this request registered —
            // a duplicate id failure means an earlier call's discovery
            // bookkeeping lives under this id and stays untouched.
            if inserted_pending_list {
                state.take_pending_list(id);
            }
            return Err(checker::PolicyViolation::new(
                tool.unwrap_or("<unknown>"),
                checker::DenialKind::Session,
                format!("trajectory: {reason}"),
            ));
        }
    }
    Ok(check_pass)
}

/// Opt-in Confused Deputy gate (`confused_deputy_protection`, default
/// off). The tool's role comes from `deputy::deputy_binding` — an
/// explicit `deputy` block wins, else the fixed-name compatibility
/// mapping applies:
///
/// - `Discover` (`deputy role="discover"`, or compat `list_files` /
///   `list_directory`): register the call's id, snapshotting the
///   extraction rules its **successful** correlated response may seed
///   `known_paths` with.
/// - `Use` (`deputy role="use"`, or compat `read_file`): every path the
///   tool's rules extract must already be in `known_paths`. A call whose
///   rules extract nothing — or whose extraction fails (bad JSON,
///   pointer value-bound overflow) — is denied; a `use` call never
///   passes unchecked. `../` traversal (incl. percent-encoded forms) is
///   always denied.
/// - `None` (`deputy role="none"` or no role bound): no check here — the
///   tool's ordinary policy gates (allowlist / `args_schema` /
///   `side_effect` / fs / net / trajectory) apply unchanged.
///
/// `known_paths` is process-local to this child — interleaved clients
/// share the set; configurable roles are not session separation.
///
/// The `Ok` value reports whether this call inserted a pending list:
/// `true` only on the `Discover` arm with a usable (non-null, present)
/// envelope id whose `record_pending_list` succeeded — `false` when
/// protection is disabled, no tool bound, a `use`/`none` binding, or
/// a `None` envelope id — so rollback ownership mirrors the actual
/// insertion.
pub(super) fn apply_confused_deputy_c2s<L: ToolIndex + ?Sized>(
    index: &L,
    state: &mut SessionState,
    json: &nojson::RawJson<'_>,
    envelope_id: Option<&RpcId>,
    tool: Option<&str>,
) -> Result<bool, checker::PolicyViolation> {
    if !index.document().confused_deputy_protection {
        return Ok(false);
    }
    let Some(tool_name) = tool else {
        return Ok(false);
    };
    let hit = index.tool_named(tool_name);
    match crate::policy::deputy::deputy_binding_tool(hit.map(|h| h.tool), tool_name) {
        crate::policy::deputy::DeputyBinding::Discover(rules) => {
            if matches!(envelope_id, Some(&RpcId::Null)) {
                return Err(checker::PolicyViolation::new(
                    tool_name,
                    checker::DenialKind::Session,
                    "confused deputy: JSON-RPC id must not be null",
                ));
            }
            if let Some(id) = envelope_id
                && let Err(reason) = state.record_pending_list(id.clone(), tool_name, rules)
            {
                return Err(checker::PolicyViolation::new(
                    tool_name,
                    checker::DenialKind::Session,
                    format!("confused deputy: {reason}"),
                ));
            }
            Ok(envelope_id.is_some())
        }
        crate::policy::deputy::DeputyBinding::Use(rules) => {
            // The tool's `arguments { opaque }` declarations apply to the
            // closed-contract check exactly as they do to the tool's own
            // sub-policy — the name lookup above already found this
            // tool; the session's prepared matcher comes along with it
            // (the standalone path rebuilds from the declarations, as
            // it always did).
            let built;
            let opaque = match hit.and_then(|h| h.prepared) {
                Some(p) => p.opaque.as_ref(),
                None => {
                    built = hit.and_then(|h| OpaqueMatcher::build(&h.tool.opaque_fields));
                    built.as_ref()
                }
            };
            let paths =
                checker::extract_deputy_use_targets_rc(json, rules, opaque).map_err(|reason| {
                    checker::PolicyViolation::new(
                        tool_name,
                        checker::DenialKind::Session,
                        format!("confused deputy: {reason}"),
                    )
                })?;
            if paths.is_empty() {
                return Err(checker::PolicyViolation::new(
                    tool_name,
                    checker::DenialKind::Session,
                    format!(
                        "confused deputy: tool '{tool_name}' is missing a resolvable path target"
                    ),
                ));
            }
            for path in &paths {
                if let Err(denial) = state.check_access(path) {
                    // A `..` escape found by the session gate is a real
                    // traversal attempt — the `validation.path_traversal`
                    // audit event applies even wrapped in the deputy
                    // reason. Everything else is a session-state refusal.
                    let kind = match &denial {
                        crate::auditor::session::AccessDenial::PathTraversal(_) => {
                            checker::DenialKind::Validation(checker::ValidationKind::PathTraversal)
                        }
                        crate::auditor::session::AccessDenial::NotDiscovered(_) => {
                            checker::DenialKind::Session
                        }
                    };
                    return Err(checker::PolicyViolation::new(
                        tool_name,
                        kind,
                        format!("confused deputy: {}", denial.reason()),
                    ));
                }
            }
            Ok(false)
        }
        crate::policy::deputy::DeputyBinding::None => Ok(false),
    }
}
