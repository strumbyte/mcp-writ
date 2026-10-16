use super::*;

fn req(method: &str) -> TrackedRequest {
    TrackedRequest::from_extracted(method, V25, true, false, &ExtractedRequest::default())
}

fn num(n: u64) -> RpcId {
    RpcId::from_u64(n)
}

fn cancel(wire: &mut WireState, direction: MessageDirection, id: RpcId) {
    wire.on_notification_forwarded(
        direction,
        V25,
        "notifications/cancelled",
        &ExtractedNotification {
            cancel_id: Some(id),
            ..Default::default()
        },
    );
}

/// At capacity a cancelled entry frees its slot, but its id stays
/// retired: reuse is refused and a late response never correlates.
#[test]
fn capacity_reclaim_retires_cancelled_id() {
    let mut wire = WireState::new();
    for n in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
        wire.register(C2S, num(n), req("ping")).unwrap();
    }
    cancel(&mut wire, C2S, num(7));

    wire.register(C2S, num(128), req("ping")).unwrap();

    assert_eq!(
        wire.register(S2C, num(200), req("ping")),
        Err("in-flight request limit reached")
    );
    // The reclaimed id is refused for reuse in its direction, and a
    // late response to it no longer correlates.
    assert!(wire.register(C2S, num(7), req("ping")).is_err());
    assert!(wire.answered(S2C, &num(7)).is_none());
    // The evicted entry is gone from the live table.
    assert!(!wire.requests.contains_key(&(C2S, num(7))));
}

/// A cancelled `subscriptions/listen` keeps its subscription facts —
/// it is not reclaimable, so the table stays full.
#[test]
fn cancelled_subscription_is_not_reclaimed() {
    let mut wire = WireState::new();
    wire.register(S2C, num(0), req("ping")).unwrap();
    for n in 1..MAX_IN_FLIGHT_REQUESTS as u64 {
        wire.register(C2S, num(n), req("ping")).unwrap();
    }
    // Cancel a C2S entry that carries subscription state.
    let listen_id = num(1);
    wire.unregister(C2S, &listen_id);
    wire.register(C2S, listen_id.clone(), req("subscriptions/listen"))
        .unwrap();
    cancel(&mut wire, C2S, listen_id.clone());

    assert_eq!(
        wire.register(C2S, num(200), req("ping")),
        Err("in-flight request limit reached")
    );
    // Cancel the reclaimable S2C entry instead: it frees a slot.
    cancel(&mut wire, S2C, num(0));
    wire.register(C2S, num(200), req("ping")).unwrap();
}

/// Retired ids are never evicted — the peer may still answer one,
/// so reuse stays refused permanently. Once the retirement budget is
/// also full, registrations that would need a reclaim fail closed
/// rather than evicting an id a stale response could still hit.
#[test]
fn retired_ids_never_evict_and_reclaim_fails_closed() {
    let mut wire = WireState::new();
    for n in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
        wire.register(C2S, num(n), req("ping")).unwrap();
    }
    // Reclaim the whole table once: retired_ids fills in id order.
    for n in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
        cancel(&mut wire, C2S, num(n));
        wire.register(C2S, num(MAX_IN_FLIGHT_REQUESTS as u64 + n), req("ping"))
            .unwrap();
    }
    assert_eq!(wire.retired_ids.len(), MAX_RETIRED_REQUEST_IDS);
    // The retired set is full: the next reclaim-dependent
    // registration is refused, and no retired id is evicted.
    cancel(&mut wire, C2S, num(128));
    assert_eq!(
        wire.register(C2S, num(256), req("ping")),
        Err("retired request id budget exhausted")
    );
    // A normally completed entry frees its slot without retiring —
    // registrations that need no reclaim still succeed.
    wire.take(C2S, &num(129)).unwrap();
    wire.register(C2S, num(256), req("ping")).unwrap();
    // Every retired id stays refused — an evicted entry could be
    // answered late and complete the wrong request.
    for n in [0u64, 5, 127] {
        assert_eq!(
            wire.register(C2S, num(n), req("ping")),
            Err("request id retired after cancelled-entry reclaim")
        );
    }
}

/// A request retaining a peer string over the per-value cap is
/// denied at registration — the ledger never holds it.
#[test]
fn oversized_retained_value_denies_registration() {
    let mut wire = WireState::new();
    let mut entry = req("resources/subscribe");
    entry.uri = Some("u".repeat(MAX_RETAINED_VALUE_BYTES + 1));
    assert_eq!(
        wire.register(C2S, num(1), entry),
        Err("request retains an oversized peer-controlled value")
    );
    // A just-at-cap value registers fine.
    let mut entry = req("resources/subscribe");
    entry.uri = Some("u".repeat(MAX_RETAINED_VALUE_BYTES));
    wire.register(C2S, num(1), entry).unwrap();
}

/// The aggregate ledger budget caps total retained bytes across the
/// table — a few fat entries exhaust it long before the count cap,
/// and a normal removal refunds enough to register again.
#[test]
fn wire_byte_budget_denies_and_refunds() {
    let mut wire = WireState::new();
    let fat = "c".repeat(MAX_RETAINED_VALUE_BYTES);
    let mut registered = 0usize;
    for n in 0..MAX_IN_FLIGHT_REQUESTS as u64 {
        let mut entry = req("ping");
        entry.client_capabilities = vec![fat.clone(); MAX_CAPABILITY_NAMES];
        match wire.register(C2S, num(n), entry) {
            Ok(()) => registered += 1,
            Err(msg) => {
                assert_eq!(msg, "wire ledger byte budget exhausted");
                break;
            }
        }
    }
    assert!(registered < MAX_IN_FLIGHT_REQUESTS);
    // Removing one entry refunds its bytes — the next registration
    // succeeds.
    wire.take(C2S, &num(0)).unwrap();
    let mut entry = req("ping");
    entry.client_capabilities = vec![fat.clone(); MAX_CAPABILITY_NAMES];
    wire.register(C2S, num(999), entry).unwrap();
}

/// An elicitation id over the per-value cap is never tracked — its
/// completion notification then fails correlation (fail closed).
#[test]
fn oversized_elicitation_id_not_tracked() {
    let mut wire = WireState::new();
    let big = "e".repeat(MAX_RETAINED_VALUE_BYTES + 1);
    assert!(!wire.track_elicitation(&big));
    assert!(wire.track_elicitation("fine"));
    wire.drop_elicitation("fine");
    assert!(wire.pending_elicitations.is_empty());
}

/// Ids beyond the serialized-byte cap are unparseable — the frame
/// gate fails closed before any ledger state is touched.
#[test]
fn oversized_request_id_is_unparseable() {
    let big = "i".repeat(MAX_RPC_ID_BYTES + 1);
    let line = format!(r#"{{"id":"{big}","method":"ping"}}"#);
    assert!(RpcId::from_line(&line).is_none());
    let ok = "i".repeat(MAX_RPC_ID_BYTES);
    let line = format!(r#"{{"id":"{ok}","method":"ping"}}"#);
    assert!(RpcId::from_line(&line).is_some());
}

fn classify(line: &str) -> WireFrame {
    let json = nojson::RawJson::parse(line).expect("parse test frame");
    classify_frame(json.value())
}

/// A `method`+`result`/`error` hybrid is not a usable envelope — a
/// peer dispatching on `result`/`id` first could read a forged
/// answer to a pending request.
#[test]
fn mixed_envelope_is_malformed() {
    for line in [
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","result":{}}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"ping","error":{"code":-32000,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/progress","result":{}}"#,
    ] {
        assert!(
            matches!(classify(line), WireFrame::Malformed { .. }),
            "{line} must classify as malformed"
        );
    }
    // A response carrying both `result` and `error` is ambiguous too.
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"x"}}"#),
        WireFrame::Malformed { .. }
    ));
    // Clean envelopes are unaffected.
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#),
        WireFrame::Request { .. }
    ));
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#),
        WireFrame::Notification { .. }
    ));
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","id":1,"result":{}}"#),
        WireFrame::Response { .. }
    ));
    assert!(matches!(
        classify(r#"{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}"#),
        WireFrame::Response { .. }
    ));
}

fn elicit_req(id: &str) -> ExtractedRequest {
    ExtractedRequest {
        elicitation_id: Some(id.to_string()),
        ..Default::default()
    }
}

fn elicit_complete(id: &str) -> ExtractedNotification {
    ExtractedNotification {
        elicitation_id: Some(id.to_string()),
        ..Default::default()
    }
}

/// A forwarded URL-mode `elicitation/create` registers its
/// `elicitationId`; the client's answer only acknowledges consent —
/// completion is the `notifications/elicitation/complete` that names
/// the pending id, and only that id is consumed.
#[test]
fn elicitation_id_lifecycle() {
    let mut wire = WireState::new();
    wire.register(S2C, num(1), req("elicitation/create"))
        .unwrap();
    wire.on_request_forwarded(S2C, &num(1), "elicitation/create", V25, &elicit_req("el-1"));
    assert_eq!(wire.pending_elicitations, ["el-1".to_string()]);

    // The client's accept/decline/cancel answer does not complete the
    // out-of-band flow — the pending id stays.
    let entry = wire.take(S2C, &num(1)).unwrap();
    wire.on_response_forwarded(
        C2S,
        &entry,
        &ExtractedResponse {
            has_result: true,
            ..Default::default()
        },
        true,
    );
    assert_eq!(wire.pending_elicitations, ["el-1".to_string()]);

    // An unmatched id leaves the pending set alone; the matching one
    // is consumed on forward.
    wire.on_notification_forwarded(
        S2C,
        V25,
        "notifications/elicitation/complete",
        &elicit_complete("el-9"),
    );
    assert_eq!(wire.pending_elicitations, ["el-1".to_string()]);
    wire.on_notification_forwarded(
        S2C,
        V25,
        "notifications/elicitation/complete",
        &elicit_complete("el-1"),
    );
    assert!(wire.pending_elicitations.is_empty());
}

/// Concurrent elicitations are independent: completing one leaves
/// the other pending.
#[test]
fn elicitation_ids_are_independent() {
    let mut wire = WireState::new();
    for (n, el) in [(1, "el-1"), (2, "el-2")] {
        wire.register(S2C, num(n), req("elicitation/create"))
            .unwrap();
        wire.on_request_forwarded(S2C, &num(n), "elicitation/create", V25, &elicit_req(el));
    }
    wire.on_notification_forwarded(
        S2C,
        V25,
        "notifications/elicitation/complete",
        &elicit_complete("el-1"),
    );
    assert_eq!(wire.pending_elicitations, ["el-2".to_string()]);
}

/// A failed forward write rolls back exactly the id it inserted —
/// a duplicate insert registers nothing, so its rollback removes
/// nothing.
#[test]
fn elicitation_forward_rollback() {
    let mut wire = WireState::new();
    wire.register(S2C, num(1), req("elicitation/create"))
        .unwrap();
    wire.on_request_forwarded(S2C, &num(1), "elicitation/create", V25, &elicit_req("el-1"));

    wire.register(S2C, num(2), req("elicitation/create"))
        .unwrap();
    let undo =
        wire.on_request_forwarded(S2C, &num(2), "elicitation/create", V25, &elicit_req("el-2"));
    wire.rollback_forwarded_request(undo);
    assert_eq!(wire.pending_elicitations, ["el-1".to_string()]);

    wire.register(S2C, num(3), req("elicitation/create"))
        .unwrap();
    let undo =
        wire.on_request_forwarded(S2C, &num(3), "elicitation/create", V25, &elicit_req("el-1"));
    wire.rollback_forwarded_request(undo);
    assert_eq!(wire.pending_elicitations, ["el-1".to_string()]);
}

/// A `-32042` URL_ELICITATION_REQUIRED error registers every
/// `data.elicitations[].elicitationId` it carries.
#[test]
fn elicitation_ids_from_required_error() {
    let mut wire = WireState::new();
    wire.on_response_forwarded(
        S2C,
        &req("tools/call"),
        &ExtractedResponse {
            is_error: true,
            elicitation_ids: vec!["el-a".to_string(), "el-b".to_string()],
            ..Default::default()
        },
        false,
    );
    assert_eq!(
        wire.pending_elicitations,
        ["el-a".to_string(), "el-b".to_string()]
    );
}

#[test]
fn pending_elicitations_bounded_and_deduped() {
    let mut wire = WireState::new();
    for n in 0..MAX_PENDING_ELICITATIONS {
        assert!(wire.track_elicitation(&format!("el-{n}")));
    }
    assert!(!wire.track_elicitation("el-overflow"));
    assert!(!wire.track_elicitation("el-0"));
}

/// Extraction: only a `-32042` error yields `data.elicitations[]`
/// `.elicitationId` members; other errors and missing members
/// produce none.
#[test]
fn extract_url_elicitation_required_ids() {
    let ext = extract_response(
            nojson::RawJson::parse(
                r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32042,"message":"x","data":{"elicitations":[{"mode":"url","elicitationId":"el-1","url":"https://x"},{"mode":"url","elicitationId":"el-2","url":"https://y"}]}}}"#,
            )
            .expect("parse")
            .value(),
        );
    assert_eq!(
        ext.elicitation_ids,
        ["el-1".to_string(), "el-2".to_string()]
    );

    for line in [
        r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"x","data":{"elicitations":[{"elicitationId":"el-1"}]}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32042,"message":"x"}}"#,
        r#"{"jsonrpc":"2.0","id":2,"error":{"code":-32042,"message":"x","data":{"elicitations":[{"mode":"url"}]}}}"#,
        r#"{"jsonrpc":"2.0","id":2,"result":{"action":"accept"}}"#,
    ] {
        let ext = extract_response(nojson::RawJson::parse(line).expect("parse").value());
        assert!(ext.elicitation_ids.is_empty(), "{line}");
    }
}

/// `can_register` mirrors `register`'s refusal reasons — null,
/// duplicate, retired, un-reclaimable capacity — without mutating
/// the table.
#[test]
fn can_register_mirrors_register() {
    let mut wire = WireState::new();
    assert_eq!(
        wire.can_register(C2S, &RpcId::Null),
        Err("request id must not be null")
    );
    wire.register(C2S, num(1), req("ping")).unwrap();
    assert_eq!(
        wire.can_register(C2S, &num(1)),
        Err("duplicate in-flight request id")
    );
    assert_eq!(wire.requests.len(), 1);

    for n in 1..MAX_IN_FLIGHT_REQUESTS as u64 {
        wire.register(C2S, num(n + 1), req("ping")).unwrap();
    }
    // Full with no reclaimable victim — refused.
    assert_eq!(
        wire.can_register(C2S, &num(999)),
        Err("in-flight request limit reached")
    );
    // A cancelled non-subscription entry is reclaimable — eligible.
    cancel(&mut wire, C2S, num(5));
    assert!(wire.can_register(C2S, &num(999)).is_ok());
    assert_eq!(wire.requests.len(), MAX_IN_FLIGHT_REQUESTS);

    // Reclaim retires the victim id; both refuse its reuse alike.
    wire.register(C2S, num(999), req("ping")).unwrap();
    assert_eq!(
        wire.can_register(C2S, &num(5)),
        Err("request id retired after cancelled-entry reclaim")
    );
}
