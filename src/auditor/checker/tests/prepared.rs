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

/// RF05b: a tool's `args_schema` rides the prepared view — the
/// shared document answers the same verdicts and reasons as the
/// per-request parse the bare `Policy` path still runs.
#[test]
fn prepared_inline_schema_answers_like_the_per_request_path() {
    let mut policy = Policy::default();
    policy.tools.push({
        let mut t = ToolPolicy::named("memo", true);
        t.args_schema = Some(
            r##"{"$defs":{"s":{"type":"string","minLength":1,"pattern":"^[a-z]+$"}},
                 "type":"object",
                 "properties":{"name":{"$ref":"#/$defs/s"},"n":{"type":"integer"}},
                 "required":["name"],"additionalProperties":false}"##
                .to_string(),
        );
        t
    });
    policy.tools.push(ToolPolicy::named("unschemaed", true));
    let prepared = PreparedPolicy::new(policy.clone());
    let call = |args: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"memo","arguments":{args}}}}}"#
        )
    };
    for line in [
        call(r#"{"name":"ok","n":3}"#),
        call(r#"{"name":"OK!"}"#),              // pattern mismatch
        call(r#"{"name":"a","extra":1}"#),      // additional property
        call(r#"{"name":""}"#),                 // $ref'd minLength
        call(r#"{"n":1}"#),                     // missing required
        call("1"),                              // non-object arguments
        call("\"x\""),                          // string where object expected
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"memo"}}"#.to_string(), // missing arguments → {}
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"unschemaed","arguments":{}}}"#.to_string(),
    ] {
        assert_same_verdict(&line, &policy, &prepared);
    }
}

/// RF05b: a `@file` spelling that reaches a prepared view still
/// resolves per request — same content reuses one plan, a rewrite is
/// visible on the very next call, and every step agrees with the bare
/// `Policy` path's uncached resolution.
#[test]
fn prepared_file_schema_resolves_per_request_on_resolved_bytes() {
    // A unique scratch dir under the CWD (the `@file` read is
    // cwd-scoped) — `TempDir` removes itself on drop, panic or pass.
    let base = std::env::current_dir()
        .unwrap()
        .join("target")
        .join("mcp_writ_test_prepared_schema");
    std::fs::create_dir_all(&base).unwrap();
    let dir = tempfile::Builder::new()
        .prefix("run_")
        .tempdir_in(&base)
        .unwrap();
    let path = dir.path().join("schema.json");
    let write = |content: &str| std::fs::write(&path, content).unwrap();
    write(r#"{"type":"object","required":["a"]}"#);

    let mut policy = Policy::default();
    policy.tools.push({
        let mut t = ToolPolicy::named("file_tool", true);
        t.args_schema = Some(format!("@{}", path.display()));
        t
    });
    let prepared = PreparedPolicy::new(policy.clone());
    let call = |args: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"file_tool","arguments":{args}}}}}"#
        )
    };
    // The prepared-path verdict alone, for the explicit assertions
    // `assert_same_verdict` leaves implicit.
    let indexed = |line: &str| {
        let view = VerifiedFrame::parse_and_verify(line).expect("test line verifies");
        check_request_verified(&view, &prepared)
    };

    // Original content: "a" required — the schema accepts {"a":1} and
    // rejects a request missing it.
    assert_same_verdict(&call(r#"{"a":1}"#), &policy, &prepared);
    assert_same_verdict(&call(r#"{}"#), &policy, &prepared);
    assert!(indexed(&call(r#"{"a":1}"#)).is_ok());
    // Rewrite → the next request evaluates the new schema on both
    // paths (the cache keys on bytes, so identical text would still
    // have hit).
    write(r#"{"type":"object","required":["b"]}"#);
    assert_same_verdict(&call(r#"{"b":1}"#), &policy, &prepared);
    assert_same_verdict(&call(r#"{"a":1}"#), &policy, &prepared);
    assert!(indexed(&call(r#"{"b":1}"#)).is_ok());
    let err = indexed(&call(r#"{"a":1}"#)).unwrap_err();
    assert!(
        err.reason.contains("at 'b': missing required field"),
        "the rewritten schema must name its missing 'b': {}",
        err.reason
    );
    // Invalid schema text fails at evaluation, per call, with the
    // same message both paths produce.
    write("not json");
    assert_same_verdict(&call(r#"{"a":1}"#), &policy, &prepared);
    let err = indexed(&call(r#"{"a":1}"#)).unwrap_err();
    assert!(
        err.reason.contains("invalid args_schema JSON"),
        "unparseable schema text must surface its parse error: {}",
        err.reason
    );
}
