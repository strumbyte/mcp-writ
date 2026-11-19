//! Per-request session gates for an allowed `tools/call`: the
//! trajectory check, the Confused Deputy gate, and the pending-call /
//! pending-list bookkeeping recorded on `SessionState`.

use crate::auditor::checker;
use crate::auditor::proxy_state::ProxyShared;
use crate::auditor::session::{RpcId, SessionState};
use crate::policy::Policy;
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
    // Does the deputy gate below record a pending list *for this
    // request*? Only then may the rollback remove it — under a reused
    // id the entry belongs to the earlier in-flight call, whose
    // discovery credit a duplicate's refusal must not consume.
    // `record_pending_list` refuses duplicates itself, so this
    // predicate mirrors the gate: a Discover binding plus a usable
    // (non-null) envelope id.
    let records_pending_list = !matches!(id, RpcId::Null)
        && tool.is_some_and(|name| {
            matches!(
                crate::policy::deputy::deputy_binding(&shared.policy, name),
                crate::policy::deputy::DeputyBinding::Discover(_)
            )
        });
    apply_confused_deputy_c2s(&shared.policy, &mut state, view.json(), Some(id), tool)?;
    if shared.policy.trajectory {
        let se = tool.and_then(|name| checker::tool_side_effect(&shared.policy, name));
        if let Err(reason) =
            state.record_pending_tool_call(id.clone(), tool.unwrap_or("<unknown>"), se)
        {
            // Roll back only the pending list this request registered —
            // a duplicate id failure means an earlier call's discovery
            // bookkeeping lives under this id and stays untouched.
            if records_pending_list {
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
pub(super) fn apply_confused_deputy_c2s(
    policy: &Policy,
    state: &mut SessionState,
    json: &nojson::RawJson<'_>,
    envelope_id: Option<&RpcId>,
    tool: Option<&str>,
) -> Result<(), checker::PolicyViolation> {
    if !policy.confused_deputy_protection {
        return Ok(());
    }
    let Some(tool_name) = tool else {
        return Ok(());
    };
    match crate::policy::deputy::deputy_binding(policy, tool_name) {
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
            Ok(())
        }
        crate::policy::deputy::DeputyBinding::Use(rules) => {
            // The tool's `arguments { opaque }` declarations apply to the
            // closed-contract check exactly as they do to the tool's own
            // sub-policy — the deputy binding lookup already found this
            // tool by name.
            let opaque_fields = policy
                .tools
                .iter()
                .find(|t| t.name == tool_name)
                .map(|t| t.opaque_fields.as_slice())
                .unwrap_or(&[]);
            let paths = checker::extract_deputy_use_targets_rc(json, rules, opaque_fields)
                .map_err(|reason| {
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
            Ok(())
        }
        crate::policy::deputy::DeputyBinding::None => Ok(()),
    }
}
