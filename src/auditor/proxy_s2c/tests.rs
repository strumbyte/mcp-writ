//! End-to-end `s2c_response` coverage: bare `S2cKind` comparisons prove
//! nothing about the response path, so fixtures go through the real
//! handler — tracked request, policy decision, additional-request
//! audits, and the forward disposition itself.

use super::*;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64};

use crate::auditor::proxy_rpc::{self, ExtractedRequest, TrackedRequest};
use crate::auditor::proxy_state::{CallTally, PendingToolsList, VerifiedToolSet};
use crate::policy::Policy;
use crate::policy::mcp::{McpRule, RuleEffect, ServerMcpRules};
use crate::protocol::fields::{RequestMeta, SchemaField};
use tokio::sync::{Mutex, watch};

/// A `ProxyShared` matching the `forward::tests` wiring. `client_out`
/// is a duplex the test drains — what the client actually receives is
/// asserted on the emitted bytes, not inferred from bookkeeping.
fn shared_for_test() -> (
    ProxyShared<tokio::io::DuplexStream>,
    watch::Receiver<bool>,
    tokio::io::DuplexStream,
) {
    let (abort_tx, abort_rx) = watch::channel(false);
    // The read halves must outlive the test — a dropped reader makes
    // the matching writer fail with BrokenPipe.
    let (_child_read, child_write) = tokio::io::duplex(64 * 1024);
    let (client_read, client_write) = tokio::io::duplex(64 * 1024);
    (
        ProxyShared {
            policy: Policy::default(),
            dry_run: false,
            fail_on: crate::verifier::fail_on::FailOn::None,
            max_frame_bytes: crate::framing::DEFAULT_MAX_FRAME_BYTES,
            audit: Arc::new(crate::audit_log::AuditLogger::to_tracing()),
            tally: std::sync::Arc::new(std::sync::Mutex::new(CallTally::default())),
            session: None,
            wire: Arc::new(Mutex::new(proxy_rpc::WireState::new())),
            pending_tools_list: Arc::new(Mutex::new(PendingToolsList::new())),
            client_out: Arc::new(Mutex::new(
                Box::new(client_write) as Box<dyn tokio::io::AsyncWrite + Unpin + Send>
            )),
            child_stdin: Arc::new(Mutex::new(Some(child_write))),
            original_tools_list: Arc::new(Mutex::new(
                std::collections::HashMap::<RpcId, String>::new(),
            )),
            list_busy: Arc::new(AtomicBool::new(false)),
            list_kick: Arc::new(tokio::sync::Notify::new()),
            cancelled_list_id: Arc::new(Mutex::new(None)),
            held_client_list: Arc::new(Mutex::new(None)),
            internal_list_failure: Arc::new(tokio::sync::Mutex::new(None)),
            list_epoch: Arc::new(tokio::sync::Mutex::new(())),
            list_generation: Arc::new(AtomicU64::new(0)),
            verified_tools: Arc::new(std::sync::Mutex::new(VerifiedToolSet {
                generation: 0,
                names: std::collections::HashSet::new(),
            })),
            last_list_template: Arc::new(Mutex::new(String::new())),
            next_internal_id: Arc::new(AtomicU64::new(910_001)),
            init_order_warned: Arc::new(AtomicBool::new(false)),
            abort_tx,
        },
        abort_rx,
        client_read,
    )
}

/// The `input_required` fixture through the real response path: a
/// tracked, allowed `tools/call` whose `_meta` declared the
/// `elicitation` capability gets its interim result decided entry by
/// entry — and the response forwards as the fixture's own result
/// under the original id, not as a policy error.
#[tokio::test]
async fn input_required_fixture_forwards_its_result_to_the_client() {
    let (mut shared, _rx, mut client_read) = shared_for_test();
    shared.policy.mcp_rules.push(ServerMcpRules::new(
        None,
        vec![McpRule {
            effect: RuleEffect::Allow,
            method: "elicitation/create".to_string(),
            versions: Vec::new(),
            direction: None,
            uris: Vec::new(),
            filters: Vec::new(),
        }],
    ));

    let path = format!(
        "{}/tests/fixtures/mrtr/input_required_result.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let line = std::fs::read_to_string(&path).expect("fixture");
    let line = line.trim_end();

    // The tools/call the interim result answers: allowed, tracked, and
    // carrying the client's declared `elicitation` capability in its
    // `_meta` — the facts `decide_additional` judges entries against.
    let id = RpcId::from_u64(2);
    let ext = ExtractedRequest {
        meta: Some(RequestMeta {
            malformed: false,
            protocol_version: None,
            client_capabilities_shape: SchemaField::Valid,
            client_capabilities: vec!["elicitation".to_string()],
            log_level: None,
            subscription_id: None,
        }),
        ..ExtractedRequest::default()
    };
    {
        let mut wire = shared.wire.lock().await;
        wire.register(
            C2S,
            id.clone(),
            TrackedRequest::from_extracted("tools/call", V26, true, false, &ext),
        )
        .expect("register the tracked tools/call");
        // Establish the 2026 revision the way a first C2S forward does.
        wire.on_request_forwarded(C2S, &id, "tools/call", V26, &ext);
    }

    let parsed = nojson::RawJson::parse(line);
    let value = parsed.as_ref().expect("fixture parses").value();
    let mut st = S2cListState::new();
    response::s2c_response(&shared, &mut st, value, line, &parsed, &id, "2")
        .await
        .expect("an allowed interim result must forward, not fail");

    // The forward path consumed the tracked request — a policy error
    // would have left it registered for the response's own denial.
    assert!(
        shared.wire.lock().await.get(C2S, &id).is_none(),
        "the forwarded response must complete its tracked request"
    );
    // What the client actually received: exactly the fixture plus the
    // framing newline — the proxy's emitted bytes, not fixture data.
    let expected = format!("{line}\n");
    let mut buf = vec![0u8; expected.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::io::AsyncReadExt::read_exact(&mut client_read, &mut buf),
    )
    .await
    .expect("the emitted frame must arrive within the bound")
    .expect("the client read must complete");
    assert_eq!(buf, expected.as_bytes());
    let emitted_json = nojson::RawJson::parse(std::str::from_utf8(&buf[..buf.len() - 1]).unwrap())
        .expect("the emitted frame parses");
    let emitted = emitted_json.value();
    assert_eq!(
        emitted
            .to_member("id")
            .unwrap()
            .required()
            .unwrap()
            .as_raw_str(),
        "2",
        "the result must arrive under the original request id"
    );
    assert!(
        emitted
            .to_member("result")
            .unwrap()
            .required()
            .unwrap()
            .to_member("resultType")
            .unwrap()
            .optional()
            .is_some_and(|v| v.as_string_str().ok() == Some("input_required")),
        "the client must receive the input_required result"
    );
    assert!(
        emitted.to_member("error").unwrap().optional().is_none(),
        "the forwarded frame must not be a policy error"
    );
}
