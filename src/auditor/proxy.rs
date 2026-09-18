use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use super::audit_log::AuditLogger;
use super::proxy_c2s;
use super::proxy_s2c;
use super::proxy_state::{PendingToolsList, ProxyShared};
use super::session::SessionState;
use crate::error::AuditorError;
use crate::policy::Policy;
use crate::verifier::fail_on::FailOn;

/// Run the bidirectional JSON-RPC proxy between client (our stdin/stdout) and
/// server (child process stdin/stdout).
///
/// Client→Server: each line is parsed with nojson, checked by the policy checker.
///   - Allowed messages are forwarded to the server.
///   - Denied tools/call messages produce a JSON-RPC error response to the client.
///
/// Server→Client: lines are forwarded to the client, except tools/list
///   traffic, which is collected, verified, and re-emitted via
///   `proxy_tools_list` (responses to internally emitted pagination /
///   list_changed revalidation requests are consumed, never echoed).
///
/// All tools/call requests are recorded in the audit log.
pub async fn run_proxy<W, R>(
    policy: &Policy,
    dry_run: bool,
    fail_on: FailOn,
    audit_logger: Arc<AuditLogger>,
    child_stdin: W,
    child_stdout: R,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    // Cancellation signal shared between S2C and C2S to immediately abort session
    let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);

    let shared = ProxyShared {
        policy: policy.clone(),
        dry_run,
        fail_on,
        audit: audit_logger,
        // Process-local session: Confused Deputy and/or trajectory (never requestState).
        session: if policy.confused_deputy_protection || policy.trajectory {
            Some(Arc::new(tokio::sync::Mutex::new(SessionState::new())))
        } else {
            None
        },
        pending_tools_list: Arc::new(tokio::sync::Mutex::new(PendingToolsList::new())),
        client_out: Arc::new(tokio::sync::Mutex::new(tokio::io::stdout())),
        // Both relay directions can write (internal tools/list requests use S2C).
        // Option lets client EOF close the actual pipe even while S2C holds an Arc.
        child_stdin: Arc::new(tokio::sync::Mutex::new(Some(child_stdin))),
        original_tools_list: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::<
            String,
            String,
        >::new())),
        list_busy: Arc::new(AtomicBool::new(false)),
        last_list_template: Arc::new(tokio::sync::Mutex::new(String::new())),
        next_internal_id: Arc::new(AtomicU64::new(910_001)),
        abort_tx: abort_tx.clone(),
    };

    let shared_c2s = shared.clone();
    let shared_s2c = shared;

    // Client → Server direction
    let client_to_server = proxy_c2s::c2s_loop(shared_c2s, abort_rx);

    // Server → Client direction
    let server_to_client = proxy_s2c::s2c_loop(shared_s2c, child_stdout);

    tokio::pin!(client_to_server);
    tokio::pin!(server_to_client);

    // Bi-directional abort propagation via tokio::select!
    let (c2s_result, s2c_result) = tokio::select! {
        res = &mut server_to_client => {
            match res {
                Ok(()) => {
                    // Normal server completion is not a policy violation.
                    (Ok(()), Ok(()))
                }
                Err(e) => {
                    if matches!(e, AuditorError::PolicyViolation(_)) {
                        abort_tx.send(true).ok();
                    }
                    (Ok(()), Err(e))
                }
            }
        }
        res = &mut client_to_server => {
            match res {
                Ok(()) => {
                    let s2c_res = server_to_client.await;
                    (Ok(()), s2c_res)
                }
                Err(e) => {
                    abort_tx.send(true).ok();
                    (Err(e), Ok(()))
                }
            }
        }
    };

    // When both c2s (client→server) and s2c (server→client) fail,
    // if s2c is a policy violation, prioritize reporting the policy violation.
    match (c2s_result, s2c_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(e), Ok(())) => Err(e),
        (Ok(()), Err(e)) => Err(e),
        (Err(c2s_err), Err(s2c_err)) => {
            if matches!(s2c_err, AuditorError::PolicyViolation(_)) {
                Err(s2c_err)
            } else {
                tracing::error!("server→client also failed: {s2c_err}");
                Err(c2s_err)
            }
        }
    }
}
