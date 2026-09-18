//! Server→client direction of `run_proxy`: passthrough forwarding, session
//! accounting (CDP list paths / trajectory completion), and delegation of
//! tools/list traffic to the verification pipeline in `proxy_tools_list`.

use std::sync::atomic::Ordering;

use tokio::io::BufReader;

use super::proxy_list_state::S2cListState;
use super::proxy_state::ProxyShared;
use super::proxy_tools_list::{self, ListFlow, S2cFrame};
use super::proxy_wire::{
    S2cKind, classify_s2c, read_proxy_line, tools_call_result_succeeded, write_client_frame,
};
use super::session::{self, RpcId};
use crate::error::AuditorError;

/// Server → Client direction.
///
/// Lines are passed through to the client, except tools/list traffic which is
/// collected, verified, and re-emitted via [`proxy_tools_list`]. MRTR
/// `input_required` interim results are forwarded unchanged.
pub(crate) async fn s2c_loop<W, R>(
    shared: ProxyShared<W>,
    child_stdout: R,
) -> Result<(), AuditorError>
where
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
    R: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(child_stdout);
    let mut st = S2cListState::new();

    loop {
        shared.audit.ensure_available()?;
        match read_proxy_line(&mut reader).await {
            Ok(Some(line)) => {
                // Parse once per line; the S2C classification flow below
                // reuses this value instead of reparsing the text.
                let parsed_line = nojson::RawJson::parse(line.trim());
                let parsed_value = parsed_line.as_ref().ok().map(|j| j.value());
                let method = parsed_value
                    .and_then(|v| v.to_member("method").ok())
                    .and_then(|m| m.optional())
                    .and_then(|v| v.to_unquoted_string_str().ok())
                    .map(|s| s.into_owned());
                if method.as_deref() == Some("notifications/tools/list_changed") {
                    proxy_tools_list::handle_list_changed(&shared, &mut st, &line).await?;
                    continue;
                }

                // S2C is passthrough-only: `resultType: "input_required"` is
                // never converted to a policy error (MRTR interim result).
                match parsed_value.map(classify_s2c).unwrap_or(S2cKind::Other) {
                    S2cKind::InputRequired => {
                        tracing::debug!("S2C passthrough: resultType=input_required");
                    }
                    S2cKind::Other => {}
                }

                // Process-local session: list paths (CDP) and last successful tools/call
                let id_member = parsed_value
                    .and_then(|v| v.to_member("id").ok())
                    .and_then(|m| m.optional());
                let raw_id = id_member.map(|v| v.as_raw_str().to_string());
                let rpc_id = id_member.and_then(RpcId::parse_from_json);
                // Pending state is consumed only by JSON-RPC responses;
                // a same-id server-initiated request must not consume it.
                let is_response =
                    parsed_value.is_some_and(crate::legislator::protocol::value_is_response);
                if let Some(ref session) = shared.session
                    && let Some(ref id) = rpc_id
                    && !matches!(id, RpcId::Null)
                {
                    let mut state = session.lock().await;
                    if is_response && state.take_pending_list(id) {
                        let paths = session::extract_paths_from_response(&line);
                        if !paths.is_empty() {
                            tracing::debug!(
                                count = paths.len(),
                                "Session: recorded paths from list response"
                            );
                            state.record_paths(&paths);
                        }
                    }
                    if shared.policy.trajectory && is_response {
                        let succeeded = parsed_value.is_some_and(tools_call_result_succeeded);
                        state.complete_pending_tool_call(id, succeeded);
                    }
                }

                match proxy_tools_list::handle_tools_list_response(
                    &shared,
                    &mut st,
                    S2cFrame {
                        line: &line,
                        parsed: &parsed_line,
                        rpc_id: rpc_id.as_ref(),
                        raw_id: raw_id.as_deref(),
                        has_method: method.is_some(),
                        is_response,
                    },
                )
                .await?
                {
                    ListFlow::Handled => continue,
                    ListFlow::ForwardRaw => {}
                }

                write_client_frame(&shared.client_out, &line).await?;
            }
            Ok(None) => {
                if st.has_incomplete_listing() || shared.list_busy.load(Ordering::SeqCst) {
                    return Err(AuditorError::PolicyViolation(
                        "server closed stdout before tools/list verification completed".into(),
                    ));
                }
                break;
            }
            Err(e) => {
                tracing::error!("server→client: read error: {e}");
                return Err(e);
            }
        }
    }
    Ok(())
}
