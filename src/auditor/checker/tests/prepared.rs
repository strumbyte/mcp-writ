//! RF05a: the session's prepared index answers every check the bare
//! `&Policy` linear path does — same allows, same denials, same
//! `listed` bit — over requests exercising opaque declarations,
//! duplicate names, `side_effect`, and the MRTR siblings.

use super::*;
use crate::policy::ToolPolicy;
use crate::policy::opaque::OpaqueField;
use crate::policy::prepared::PreparedPolicy;

fn mixed_policy() -> Policy {
    let mut policy = Policy::default();
    policy.tools.push(ToolPolicy::named("memo", true));
    policy.tools.push(ToolPolicy::named("denied_tool", false));
    // A denied entry shadowing an allowed duplicate — `find` picks the
    // denied entry, admission picks the allowed one; both paths must
    // preserve the asymmetry. The entries carry *different*
    // side_effects so a prepared-rule pairing bug is observable:
    // admission must see the allowed entry's `read_only` (refusing a
    // URL argument) while the trajectory-style `find` keeps the first
    // entry's `network` metadata.
    policy.tools.push({
        let mut t = ToolPolicy::named("dup", false);
        t.side_effect = Some("network".to_string());
        t
    });
    policy.tools.push({
        let mut t = ToolPolicy::named("dup", true);
        t.side_effect = Some("read_only".to_string());
        t
    });
    policy.tools.push({
        let mut t = ToolPolicy::named("opaque_tool", true);
        t.opaque_fields = vec![
            OpaqueField::parse("note").unwrap(),
            OpaqueField::parse("/params/arguments/entities/name").unwrap(),
        ];
        t.side_effect = Some("read_only".to_string());
        t
    });
    // An fs-only contract: no schema/side_effect/network, but the
    // restricted filesystem policy still counts as a security
    // contract, so `Auto` inputResponses resolves to Deny.
    policy.tools.push({
        let mut t = ToolPolicy::named("fs_tool", true);
        t.fs = Some(crate::policy::FsToolPolicy::new(
            vec!["/workspace/**".to_string()],
            vec![],
        ));
        t
    });
    policy
}

fn assert_same_verdict(line: &str, policy: &Policy, prepared: &PreparedPolicy) {
    let standalone = check_request(line, policy);
    let view = VerifiedFrame::parse_and_verify(line).expect("test line verifies");
    let indexed = check_request_verified(&view, prepared);
    match (standalone, indexed) {
        (Ok(a), Ok(b)) => {
            assert_eq!(a.sub_policy, b.sub_policy, "sub_policy: {line}");
            assert_eq!(a.audit_notes, b.audit_notes, "audit_notes: {line}");
        }
        (Err(a), Err(b)) => {
            assert_eq!(a.tool_name, b.tool_name, "tool_name: {line}");
            assert_eq!(a.kind, b.kind, "kind: {line}");
            assert_eq!(a.reason, b.reason, "reason: {line}");
        }
        (a, b) => panic!("verdict mismatch on {line}: {a:?} vs {b:?}"),
    }
}

#[test]
fn prepared_index_answers_every_request_the_linear_path_does() {
    let policy = mixed_policy();
    let prepared = PreparedPolicy::new(policy.clone());
    let call = |name: &str, args: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"{name}","arguments":{args}}}}}"#
        )
    };
    for line in [
        call("memo", "{}"),
        call("dup", "{}"),
        // The allowed duplicate's own prepared rules apply: its
        // `read_only` refuses the URL — pairing it with the denied
        // first entry's `network` side_effect would wrongly pass.
        call("dup", r#"{"url":"https://example.com/x"}"#),
        call("denied_tool", "{}"),
        call("unlisted", "{}"),
        // Opaque members exempt free-form values from the
        // unclassified-argument refusal under `read_only`.
        call("opaque_tool", r#"{"note":"anything at all"}"#),
        call(
            "opaque_tool",
            r#"{"entities":{"name":"free form","type":"x"}}"#,
        ),
        // A resource-shaped value under an opaque member still
        // classifies — `read_only` refuses the URL.
        call("opaque_tool", r#"{"note":"https://evil.example/x"}"#),
        // Undeclared members still face the refusal.
        call("opaque_tool", r#"{"other":"free text"}"#),
        // inputResponses denied by secure default (side_effect = a
        // security contract).
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"opaque_tool","arguments":{},"inputResponses":{"k":{"x":1}}}}"#.to_string(),
        // fs-only contract — the prepared `resolved_input_responses`
        // sees the same `has_security_contract()` the linear path
        // derives per call; Auto still refuses on both.
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"fs_tool","arguments":{"path":"/workspace/a.txt"},"inputResponses":{"k":{"x":1}}}}"#.to_string(),
        // Unrestricted Auto tool passes inputResponses through.
        r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"memo","arguments":{},"inputResponses":{"k":{"x":1}}}}"#.to_string(),
        // requestState passes through untouched.
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"memo","arguments":{},"requestState":"e30"}}"#.to_string(),
        // Non-tools/call methods pass through.
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":5,"method":"notifications/cancelled","params":{}}"#.to_string(),
    ] {
        assert_same_verdict(&line, &policy, &prepared);
    }

    // `tool_named` keeps first-entry behavior for trajectory metadata:
    // the denied duplicate's `network`, not admission's `read_only`.
    assert_eq!(
        tool_side_effect(&prepared, "dup"),
        Some(SideEffect::Network)
    );
    assert_eq!(
        tool_side_effect(&prepared, "dup"),
        tool_side_effect(&policy, "dup"),
        "prepared `find` must answer the same first entry as the linear scan"
    );
}

#[test]
fn prepared_index_answers_trajectory_and_side_effect_the_same() {
    let mut policy = Policy::default();
    policy.trajectory = true;
    policy.trajectory_rules = vec![crate::policy::TrajectoryRule {
        after_side_effect: SideEffect::ReadOnly,
        deny_next: SideEffect::Network,
    }];
    policy.tools.push({
        let mut t = ToolPolicy::named("fetch_url", true);
        t.side_effect = Some("network".to_string());
        t
    });
    let prepared = PreparedPolicy::new(policy.clone());

    // `tool_side_effect` — first-match lookup parity.
    for (name, expected) in [("fetch_url", Some(SideEffect::Network)), ("unlisted", None)] {
        assert_eq!(tool_side_effect(&policy, name), expected, "{name}");
        assert_eq!(tool_side_effect(&prepared, name), expected, "{name}");
    }

    // `check_trajectory_json` — same gate, same verdict: after a
    // ReadOnly success the Network call is refused on both paths.
    let mut state = SessionState::new();
    state.record_successful_tool_call("memo", Some(SideEffect::ReadOnly));
    let line = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{}}}"#;
    let json = nojson::RawJson::parse(line).unwrap();
    let linear = check_trajectory_json(&json, &policy, &state);
    let indexed = check_trajectory_json(&json, &prepared, &state);
    assert_eq!(linear.unwrap_err().reason, indexed.unwrap_err().reason);
}
