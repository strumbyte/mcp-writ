//! The server→client notification path: capability / subscription /
//! correlation gates, then forward or drop.

use super::S2C;
use crate::auditor::proxy_list_state::S2cListState;
use crate::auditor::proxy_rpc;
use crate::auditor::proxy_state::ProxyShared;
use crate::auditor::proxy_tools_list;
use crate::auditor::proxy_wire::write_client_frame;
use crate::error::AuditorError;
use crate::policy::mcp::McpVerdict;
/// One server→client notification: decide (capability / subscription /
/// correlation gates), then forward or drop.
pub(super) async fn s2c_notification<W>(
    shared: &ProxyShared<W>,
    st: &mut S2cListState,
    value: nojson::RawJsonValue<'_, '_>,
    line: &str,
    method: &str,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let ext = proxy_rpc::extract_notification(value, method);
    let mut wire = shared.wire.lock().await;
    let version = wire.passive_version();
    let verdict = {
        let cancel_target = ext
            .cancel_id
            .as_ref()
            .map(|id| wire.cancel_facts(S2C, id, version))
            .unwrap_or_default();
        let progress = ext
            .progress_token
            .as_ref()
            .map(|t| wire.progress(S2C, t))
            .unwrap_or_default();
        let message_for = (method == "notifications/message")
            .then(|| {
                wire.message_correlation(ext.subscription_id.as_ref(), ext.progress_token.as_ref())
            })
            .flatten();
        let subscription = ext
            .subscription_id
            .as_ref()
            .and_then(|id| wire.subscription_facts(id));
        let msg = proxy_rpc::notification_message(
            version,
            S2C,
            method,
            &ext,
            cancel_target,
            progress,
            message_for,
            subscription,
        );
        shared.policy.decide_mcp(&msg, &wire.session_facts())
    };
    match verdict {
        McpVerdict::Allow(_) => {
            wire.on_notification_forwarded(S2C, version, method, &ext);
            drop(wire);
            proxy_rpc::audit_forwarded_decision(
                &shared.audit,
                S2C,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                shared.dry_run,
                None,
            )
            .await?;
            let result = if method == "notifications/tools/list_changed" {
                proxy_tools_list::handle_list_changed(shared, st, line).await
            } else {
                write_client_frame(&shared.client_out, line).await
            };
            match result {
                Ok(()) => Ok(()),
                Err(e) => {
                    // Skipped for `DeliveryUncertain` — the complete
                    // frame may still have crossed, so "not forwarded"
                    // is unprovable — except for list_changed:
                    // `handle_list_changed` holds the notification in
                    // `st.held_list_changed` and its only writes are
                    // the internal probe's child-bound one, so a
                    // `DeliveryUncertain` there describes the probe's
                    // delivery, never this notification's — the
                    // notification provably never crossed.
                    let suppress = matches!(e, AuditorError::DeliveryUncertain(_))
                        && method != "notifications/tools/list_changed";
                    if !suppress {
                        proxy_rpc::audit_forward_failed(
                            &shared.audit,
                            S2C,
                            "notification",
                            Some(method),
                            None,
                            version,
                            verdict,
                            shared.dry_run,
                            None,
                        );
                    }
                    Err(e)
                }
            }
        }
        _ => {
            // Drop or (defensively) deny/undecided — notifications are
            // never answered and never forwarded: server authorization
            // stays enforced in dry-run exactly as it does when
            // enforcing.
            drop(wire);
            proxy_rpc::audit_decision(
                &shared.audit,
                S2C,
                "notification",
                Some(method),
                None,
                version,
                verdict,
                false,
                shared.dry_run,
                None,
            )?;
            Ok(())
        }
    }
}
