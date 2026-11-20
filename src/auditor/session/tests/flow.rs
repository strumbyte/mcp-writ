use super::super::*;

use super::DISCOVER_RULES;

// --- End-to-end flow ---

#[test]
fn test_full_confused_deputy_flow() {
    let mut state = SessionState::new();

    // Step 1: list_files request goes through, record pending under the
    // canonical id the C2S forward registers.
    state
        .record_pending_list(RpcId::from_u64(1), "list_files", DISCOVER_RULES)
        .unwrap();

    // Step 2: list_files response comes back with paths — consumed the
    // way the production response handler does: resolve the pending
    // entry by the id the response itself carries, then run the exact
    // response through the rules it snapshotted, so a response the
    // rules reject records nothing.
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"/workspace/a.txt\n/workspace/b.txt"}]}}"#;
    let json = nojson::RawJson::parse(response).expect("response parses");
    let response_id = RpcId::from_line(response).expect("the response id resolves");
    let pending = state
        .take_pending_list(&response_id)
        .expect("the pending list entry must be consumed");
    let paths = extract_paths_for_pending(json.value(), pending.rules());
    state.record_paths(&paths);

    // Step 3: read_file for discovered path → allowed
    assert!(state.check_access("/workspace/a.txt").is_ok());
    assert!(state.check_access("/workspace/b.txt").is_ok());

    // Step 4: read_file for undiscovered path → blocked
    assert!(state.check_access("/etc/shadow").is_err());

    // Step 5: path traversal → always blocked
    assert!(state.check_access("/workspace/../../etc/passwd").is_err());
}

#[test]
fn test_interleaved_list_read_shares_process_scope() {
    let mut state = SessionState::new();
    state
        .record_pending_list(RpcId::Number("1".into()), "list_files", DISCOVER_RULES)
        .unwrap();
    state
        .record_pending_list(RpcId::Number("2".into()), "list_files", DISCOVER_RULES)
        .unwrap();

    assert!(
        state
            .take_pending_list(&RpcId::Number("1".into()))
            .is_some()
    );
    state.record_paths(&["/client-a/file.txt".to_string()]);

    assert!(
        state
            .take_pending_list(&RpcId::Number("2".into()))
            .is_some()
    );
    state.record_paths(&["/client-b/file.txt".to_string()]);

    // Process-scope: interleaved list responses share one known_paths set.
    assert!(state.check_access("/client-a/file.txt").is_ok());
    assert!(state.check_access("/client-b/file.txt").is_ok());
    assert!(state.check_access("/client-c/unlisted.txt").is_err());
}

// The MRTR-retry gate lives at the request handler — a retry is a new
// `tools/call` id carrying `requestState`/`inputResponses`, and the
// deputy rules still extract its path. See
// `forward::tests::mrtr_retry_still_passes_the_deputy_gate` for the
// request-level exercise; the state-level invariant it relies on is
// simply that `known_paths` persists across ids.
#[test]
fn test_known_paths_are_not_keyed_on_request_id() {
    let mut state = SessionState::new();
    state.record_paths(&["/workspace/a.txt".to_string()]);
    assert!(state.check_access("/workspace/a.txt").is_ok());
    assert!(state.check_access("/etc/passwd").is_err());
}

fn read_only_then_network_rule() -> Vec<crate::policy::TrajectoryRule> {
    vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::ReadOnly,
        deny_next: crate::policy::SideEffect::Network,
    }]
}

#[test]
fn test_trajectory_empty_last_allows_network() {
    let state = SessionState::new();
    assert!(
        state
            .check_trajectory(
                &read_only_then_network_rule(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
                false,
            )
            .is_ok()
    );
    assert!(state.last_successful_side_effect().is_none());
    assert!(state.last_successful_tool().is_none());
}

#[test]
fn test_trajectory_denies_network_after_successful_read_only() {
    let mut state = SessionState::new();
    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("1".into()), true);
    assert_eq!(
        state.last_successful_side_effect(),
        Some(crate::policy::SideEffect::ReadOnly)
    );

    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
    assert!(err.contains("deny-next=\"network\""), "{err}");
}

#[test]
fn test_trajectory_denies_extractable_host_after_read_only() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "post_data",
            Some(crate::policy::SideEffect::Write),
            true,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"network\""), "{err}");
}

#[test]
fn test_trajectory_failed_call_does_not_update_last() {
    let mut state = SessionState::new();
    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("1".into()), false);
    assert!(state.last_successful_side_effect().is_none());
    assert!(
        state
            .check_trajectory(
                &read_only_then_network_rule(),
                "fetch_url",
                Some(crate::policy::SideEffect::Network),
                false,
            )
            .is_ok()
    );
}

#[test]
fn test_trajectory_failed_write_does_not_clear_successful_read() {
    let mut state = SessionState::new();
    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("1".into()), true);
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "fail_write",
            Some(crate::policy::SideEffect::Write),
        )
        .unwrap();
    state.complete_pending_tool_call(&RpcId::Number("2".into()), false);
    assert_eq!(
        state.last_successful_side_effect(),
        Some(crate::policy::SideEffect::ReadOnly)
    );
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
}

#[test]
fn test_trajectory_same_tool_is_not_denied() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    assert!(
        state
            .check_trajectory(
                &read_only_then_network_rule(),
                "read_file",
                Some(crate::policy::SideEffect::Network),
                true,
            )
            .is_ok()
    );
}

#[test]
fn test_trajectory_same_tool_extra_url_is_denied() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
            true,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
}

#[test]
fn test_trajectory_same_tool_path_only_is_allowed() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    // Under a deny-next-ReadOnly rule the same-tool exemption holds:
    // the checked call is the same tool as the verified call.
    assert!(
        state
            .check_trajectory(
                &read_only_then_read_only_rule(),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
                false,
            )
            .is_ok()
    );
    // A different ReadOnly tool does not share that exemption — the
    // rule still denies it.
    let err = state
        .check_trajectory(
            &read_only_then_read_only_rule(),
            "other_reader",
            Some(crate::policy::SideEffect::ReadOnly),
            false,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
}

/// The pending-call invariant: recording a `tools/call` as in-flight —
/// including an MRTR retry under a new JSON-RPC id — must not replace
/// the verified ReadOnly marker. Only a definitive response may move
/// it. The request-level MRTR assertion lives in
/// `forward::tests::mrtr_retry_still_runs_the_trajectory_gate`.
#[test]
fn test_pending_network_call_does_not_replace_verified_read_only() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    // New JSON-RPC id + requestState must not change the rule.
    state
        .record_pending_tool_call(
            RpcId::Number("99".into()),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("trajectory"), "{err}");
}

fn network_then_execute_rule() -> Vec<crate::policy::TrajectoryRule> {
    vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::Network,
        deny_next: crate::policy::SideEffect::Execute,
    }]
}

fn read_only_then_read_only_rule() -> Vec<crate::policy::TrajectoryRule> {
    vec![crate::policy::TrajectoryRule {
        after_side_effect: crate::policy::SideEffect::ReadOnly,
        deny_next: crate::policy::SideEffect::ReadOnly,
    }]
}

#[test]
fn test_trajectory_unverified_release_feeds_deny_matching() {
    let mut state = SessionState::new();
    // Releasing an id that was never pended is a no-op.
    state.release_pending_tool_call_unverified(&RpcId::Number("9".into()));
    assert!(
        state
            .check_trajectory(
                &network_then_execute_rule(),
                "run_cmd",
                Some(crate::policy::SideEffect::Execute),
                false,
            )
            .is_ok()
    );

    state
        .record_pending_tool_call(
            RpcId::Number("1".into()),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("1".into()));
    // The cancelled call may have run server-side: its side_effect is
    // a deny-match candidate even though nothing was proven successful.
    let err = state
        .check_trajectory(
            &network_then_execute_rule(),
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"execute\""), "{err}");
    // The verified marker is untouched.
    assert!(state.last_successful_side_effect().is_none());
    assert!(state.last_successful_tool().is_none());
}

#[test]
fn test_trajectory_cancelled_call_cannot_launder_verified_marker() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    // A cancelled benign call must not overwrite the verified marker —
    // if it counted as a success, `after=read_only deny-next=network`
    // would be disarmed just by cancelling a harmless call.
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "stat_file",
            Some(crate::policy::SideEffect::Write),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"network\""), "{err}");
    assert_eq!(
        state.last_successful_side_effect(),
        Some(crate::policy::SideEffect::ReadOnly)
    );
    assert_eq!(state.last_successful_tool(), Some("read_file"));
}

#[test]
fn test_trajectory_unverified_other_tool_breaks_same_tool_exemption() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "other_tool",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    // Without the intervening cancel, read_file → read_file is exempt.
    // The possibly-executed other_tool may be the true last call, so
    // the chain is provably cross-tool and the after rule applies.
    let err = state
        .check_trajectory(
            &read_only_then_read_only_rule(),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"read_only\""), "{err}");
}

#[test]
fn test_trajectory_unverified_same_tool_keeps_exemption() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    // Every candidate is provably read_file, so the same-tool
    // exemption still holds even under a rule that denies
    // read_only → read_only.
    assert!(
        state
            .check_trajectory(
                &read_only_then_read_only_rule(),
                "read_file",
                Some(crate::policy::SideEffect::ReadOnly),
                false,
            )
            .is_ok()
    );
}

#[test]
fn test_trajectory_verified_success_keeps_unverified_candidates() {
    let mut state = SessionState::new();
    state.record_successful_tool_call("read_file", Some(crate::policy::SideEffect::ReadOnly));
    state
        .record_pending_tool_call(
            RpcId::Number("2".into()),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
        )
        .unwrap();
    state.release_pending_tool_call_unverified(&RpcId::Number("2".into()));
    // An unrelated verified success proves nothing about whether
    // the cancelled call ran — the Network tombstone still
    // satisfies `after=network` and denies a following Execute.
    state.record_successful_tool_call("write_file", Some(crate::policy::SideEffect::Write));
    let err = state
        .check_trajectory(
            &network_then_execute_rule(),
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"execute\""), "{err}");
    // An MRTR `input_required` suspend is ambiguous — the response
    // path resolves it through `release_pending_tool_call_unverified`,
    // never a `succeeded=false` completion: that transition is
    // reserved for proven non-execution (a registration rollback),
    // which only ever applies to a live pending entry. Even issuing it
    // against this id cannot resolve the tombstone — the Network
    // candidate still denies Execute while the verified Write marker
    // continues to govern.
    state.complete_pending_tool_call(&RpcId::Number("2".into()), false);
    let err = state
        .check_trajectory(
            &network_then_execute_rule(),
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"execute\""), "{err}");
    let err = state
        .check_trajectory(
            &[crate::policy::TrajectoryRule {
                after_side_effect: crate::policy::SideEffect::Write,
                deny_next: crate::policy::SideEffect::Execute,
            }],
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"execute\""), "{err}");
}

#[test]
fn test_trajectory_maybe_tool_name_overflow_disables_exemption() {
    let mut state = SessionState::new();
    // Tombstone bytes are id + retained tool name — verified marker,
    // retained candidates, and the checked call all use the same wide
    // name so the only variable is the tombstone budget.
    let wide = "x".repeat(33_000);
    state.record_successful_tool_call(&wide, Some(crate::policy::SideEffect::ReadOnly));
    let first = RpcId::Number("1".into());
    state
        .record_pending_tool_call(first.clone(), &wide, None)
        .unwrap();
    state.release_pending_tool_call_unverified(&first);
    // Below the budget cap the same-tool exemption still holds: every
    // retained candidate is provably this tool.
    assert!(
        state
            .check_trajectory(
                &read_only_then_read_only_rule(),
                &wide,
                Some(crate::policy::SideEffect::ReadOnly),
                false,
            )
            .is_ok()
    );
    // A second retained candidate pushes id+name bytes over the cap —
    // the latch drops the candidate and the exemption is unreachable.
    let second = RpcId::Number("2".into());
    state
        .record_pending_tool_call(second.clone(), &wide, None)
        .unwrap();
    state.release_pending_tool_call_unverified(&second);
    let err = state
        .check_trajectory(
            &read_only_then_read_only_rule(),
            &wide,
            Some(crate::policy::SideEffect::ReadOnly),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"read_only\""), "{err}");
}

#[test]
fn test_trajectory_tombstoned_id_cannot_be_rearmed() {
    let mut state = SessionState::new();
    let id = RpcId::Number("9".into());
    state
        .record_pending_tool_call(
            id.clone(),
            "read_file",
            Some(crate::policy::SideEffect::ReadOnly),
        )
        .unwrap();
    // Released without a verdict — the id now carries a tombstone.
    state.release_pending_tool_call_unverified(&id);
    // A second call under the same id is refused before it can
    // forward: recording it would overwrite the first candidate on
    // release, and the refusal charges nothing.
    let err = state
        .record_pending_tool_call(
            id.clone(),
            "run_cmd",
            Some(crate::policy::SideEffect::Execute),
        )
        .unwrap_err();
    assert!(err.contains("unverified"), "{err}");
    // The first tombstone still counts for `after` matching — a
    // different tool's network call is denied under after=read_only.
    let err = state
        .check_trajectory(
            &read_only_then_network_rule(),
            "fetch_url",
            Some(crate::policy::SideEffect::Network),
            false,
        )
        .unwrap_err();
    assert!(err.contains("deny-next=\"network\""), "{err}");
    // The tombstone's own definitive verdict still resolves it — the
    // id frees once the late reply completes the cancelled call.
    state.complete_pending_tool_call(&id, true);
    state
        .record_pending_tool_call(id, "run_cmd", Some(crate::policy::SideEffect::Execute))
        .unwrap();
}
