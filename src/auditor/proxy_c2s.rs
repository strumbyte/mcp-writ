//! Client→server direction of `run_proxy`: request inspection, policy
//! checks, trajectory / Confused Deputy session accounting, and forwarding.

use std::sync::atomic::Ordering;

use tokio::io::BufReader;

use uuid::Uuid;

use super::audit_log::{Action, AuditEvent, EventType, Outcome, Severity};
use super::checker;
use super::proxy_state::ProxyShared;
use super::proxy_wire::{
    build_error_response, build_jsonrpc_error, extract_method, extract_raw_id,
    extract_tool_name_from_line, join_audit_details, read_proxy_line, write_child_frame,
    write_client_frame,
};
use super::session::{RpcId, SessionState};
use crate::error::AuditorError;
use crate::policy::Policy;

/// Client → Server direction.
///
/// Each stdin line is parsed with nojson and checked by the policy checker.
/// Allowed messages are forwarded to the server; denied tools/call messages
/// produce a JSON-RPC error response to the client. All tools/call requests
/// are recorded in the audit log.
pub(crate) async fn c2s_loop<W>(
    shared: ProxyShared<W>,
    mut abort_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(tokio::io::stdin());

    loop {
        shared.audit.ensure_available()?;
        let next_line_future = read_proxy_line(&mut reader);
        let line_opt = tokio::select! {
            res = abort_rx.changed() => {
                if res.is_ok() && *abort_rx.borrow() {
                    tracing::error!("session aborted due to S2C verification failure; stopping C2S immediately");
                    return Err(AuditorError::VerificationFailed("session aborted on server→client verification".to_string()));
                }
                continue;
            }
            res = next_line_future => res?
        };

        match line_opt {
            Some(line) => {
                let method = extract_method(&line);
                let is_tools_call = method.as_deref() == Some("tools/call");
                let is_tools_list = method.as_deref() == Some("tools/list");
                let envelope_id = RpcId::from_line(&line);

                if is_tools_call && shared.list_busy.load(Ordering::SeqCst) {
                    let id_str = extract_raw_id(&line).unwrap_or_else(|| "null".into());
                    let tool =
                        extract_tool_name_from_line(&line).unwrap_or_else(|| "<unknown>".into());
                    let reason = "tools/list revalidation in progress";
                    let error_response = build_error_response(&id_str, &tool, reason);
                    write_client_frame(&shared.client_out, &error_response).await?;
                    let correlation_id = Uuid::now_v7();
                    let mut event = AuditEvent::new(
                        correlation_id,
                        EventType::ToolCallDenied,
                        Severity::High,
                        Outcome::Failure,
                        Action::Denied,
                    );
                    event.target_tool = Some(tool);
                    event.request_id = Some(id_str);
                    event.details = Some(reason.to_string());
                    shared.audit.log(event);
                    continue;
                }

                let check_result = checker::check_request(&line, &shared.policy);

                if is_tools_list && check_result.is_ok() {
                    if matches!(envelope_id, Some(RpcId::Null)) {
                        let error_response = build_jsonrpc_error(
                            &extract_raw_id(&line).unwrap_or_else(|| "null".into()),
                            "tools/list requires a non-null JSON-RPC id",
                        );
                        write_client_frame(&shared.client_out, &error_response).await?;
                        continue;
                    }
                    if let Some(ref id) = envelope_id {
                        if shared.list_busy.load(Ordering::SeqCst) {
                            let error_response = build_jsonrpc_error(
                                &extract_raw_id(&line).unwrap_or_else(|| "null".into()),
                                "tools/list already in progress",
                            );
                            write_client_frame(&shared.client_out, &error_response).await?;
                            continue;
                        }
                        let accepted = shared
                            .pending_tools_list
                            .lock()
                            .await
                            .try_insert(id.clone());
                        if accepted {
                            shared.list_busy.store(true, Ordering::SeqCst);
                            *shared.last_list_template.lock().await = line.clone();
                            if let Some(raw) = extract_raw_id(&line) {
                                shared
                                    .original_tools_list
                                    .lock()
                                    .await
                                    .insert(raw, line.clone());
                            }
                        } else {
                            tracing::warn!(
                                "rejecting tools/list: duplicate or too many unanswered ids"
                            );
                            let error_response = build_jsonrpc_error(
                                &extract_raw_id(&line).unwrap_or_else(|| "null".into()),
                                "duplicate or too many unanswered tools/list requests",
                            );
                            write_client_frame(&shared.client_out, &error_response).await?;
                            continue;
                        }
                    }
                }

                // Process-local session checks (trajectory, then Confused Deputy)
                let check_result = match (check_result, is_tools_call) {
                    (Ok(check_pass), true) => {
                        if let Some(ref session) = shared.session {
                            let mut state = session.lock().await;
                            let tool = extract_tool_name_from_line(&line);
                            let trajectory_result = if shared.policy.trajectory {
                                checker::check_trajectory(&line, &shared.policy, &state)
                            } else {
                                Ok(())
                            };
                            match trajectory_result {
                                Err(violation) => Err(violation),
                                Ok(()) => {
                                    let deputy_result = apply_confused_deputy_c2s(
                                        &shared.policy,
                                        &mut state,
                                        &line,
                                        envelope_id.as_ref(),
                                        tool.as_deref(),
                                    );
                                    match deputy_result {
                                        Err(violation) => Err(violation),
                                        Ok(()) => {
                                            if shared.policy.trajectory {
                                                if matches!(envelope_id, Some(RpcId::Null)) {
                                                    return_trajectory_null_id_error(tool.as_deref())
                                                } else if let Some(ref id) = envelope_id {
                                                    let se = tool.as_deref().and_then(|name| {
                                                        checker::tool_side_effect(
                                                            &shared.policy,
                                                            name,
                                                        )
                                                    });
                                                    if let Err(reason) = state
                                                        .record_pending_tool_call(
                                                            id.clone(),
                                                            tool.as_deref().unwrap_or("<unknown>"),
                                                            se,
                                                        )
                                                    {
                                                        Err(checker::PolicyViolation {
                                                            tool_name: tool.clone().unwrap_or_else(
                                                                || "<unknown>".into(),
                                                            ),
                                                            reason: format!("trajectory: {reason}"),
                                                        })
                                                    } else {
                                                        Ok(check_pass)
                                                    }
                                                } else {
                                                    Ok(check_pass)
                                                }
                                            } else {
                                                Ok(check_pass)
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            Ok(check_pass)
                        }
                    }
                    (result, _) => result,
                };

                match check_result {
                    Ok(check_pass) => {
                        if is_tools_call {
                            let tool = extract_tool_name_from_line(&line);
                            let correlation_id = Uuid::now_v7();
                            let mut event = AuditEvent::new(
                                correlation_id,
                                EventType::ToolCallAllowed,
                                Severity::Info,
                                Outcome::Success,
                                Action::Allowed,
                            );
                            event.target_tool = tool;
                            event.details = join_audit_details(
                                check_pass.sub_policy.as_deref(),
                                &check_pass.audit_notes,
                            );
                            shared.audit.log_committed(event).await?;
                        }
                        write_child_frame(&shared.child_stdin, &line).await?;
                    }
                    Err(violation) => {
                        let request_id = extract_raw_id(&line);
                        if shared.dry_run {
                            tracing::warn!(
                                tool = %violation.tool_name,
                                reason = %violation.reason,
                                "[DRY-RUN] Policy violation detected, forwarding request"
                            );
                            write_child_frame(&shared.child_stdin, &line).await?;
                        } else {
                            tracing::warn!(
                                tool = %violation.tool_name,
                                reason = %violation.reason,
                                "Policy violation: blocking tools/call"
                            );
                            let id_str = match request_id.clone() {
                                Some(id) => id,
                                None => {
                                    tracing::warn!("failed to extract JSON-RPC id, using null");
                                    "null".to_string()
                                }
                            };
                            let error_response = build_error_response(
                                &id_str,
                                &violation.tool_name,
                                &violation.reason,
                            );
                            write_client_frame(&shared.client_out, &error_response).await?;
                        }

                        // Audit log: record violation
                        let correlation_id = Uuid::now_v7();
                        let action = if shared.dry_run {
                            Action::Observed
                        } else {
                            Action::Denied
                        };
                        let mut event = AuditEvent::new(
                            correlation_id,
                            EventType::ToolCallDenied,
                            Severity::High,
                            Outcome::Failure,
                            action,
                        );
                        event.target_tool = Some(violation.tool_name.clone());
                        event.request_id = request_id;
                        event.details = Some(violation.reason.clone());
                        shared.audit.log(event);
                        shared.audit.ensure_available()?;
                    }
                }
            }
            None => {
                // AsyncWrite::shutdown is only a flush for tokio::fs::File
                // (Windows pipes). Drop the writer to deliver EOF instead.
                shared.child_stdin.lock().await.take();
                break;
            }
        }
    }
    Ok(())
}

fn return_trajectory_null_id_error(
    tool: Option<&str>,
) -> Result<checker::CheckPass, checker::PolicyViolation> {
    Err(checker::PolicyViolation {
        tool_name: tool.unwrap_or("<unknown>").to_string(),
        reason: "trajectory: JSON-RPC id must not be null".to_string(),
    })
}

fn apply_confused_deputy_c2s(
    policy: &Policy,
    state: &mut SessionState,
    line: &str,
    envelope_id: Option<&RpcId>,
    tool: Option<&str>,
) -> Result<(), checker::PolicyViolation> {
    if !policy.confused_deputy_protection {
        return Ok(());
    }
    match tool {
        Some("list_files") | Some("list_directory") => {
            if matches!(envelope_id, Some(&RpcId::Null)) {
                return Err(checker::PolicyViolation {
                    tool_name: tool.unwrap_or("list_files").to_string(),
                    reason: "confused deputy: JSON-RPC id must not be null".to_string(),
                });
            }
            if let Some(id) = envelope_id
                && let Err(reason) =
                    state.record_pending_list(id.clone(), tool.unwrap_or("list_files"))
            {
                return Err(checker::PolicyViolation {
                    tool_name: tool.unwrap_or("list_files").to_string(),
                    reason: format!("confused deputy: {reason}"),
                });
            }
            Ok(())
        }
        Some("read_file") => {
            let paths = checker::extract_fs_targets(line);
            if paths.is_empty() {
                return Err(checker::PolicyViolation {
                    tool_name: "read_file".to_string(),
                    reason: "confused deputy: read_file is missing a resolvable path target"
                        .to_string(),
                });
            }
            for path in &paths {
                if let Err(reason) = state.check_access(path) {
                    return Err(checker::PolicyViolation {
                        tool_name: "read_file".to_string(),
                        reason: format!("confused deputy: {reason}"),
                    });
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}
