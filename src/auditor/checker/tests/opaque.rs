use super::*;

// --- `arguments { opaque }` declarations: the named members stay out
//     of the unrecognized-argument refusal while every other
//     classification gate (secrets, resource shapes, fs/network
//     contracts, read_only) still applies ---

use crate::policy::opaque::OpaqueField;

fn opaque_policy(fields: &[&str]) -> Policy {
    let mut mem = ToolPolicy::named("memory_add", true);
    // A restricted contract — the fs allow is what makes
    // selector-plausible strings under unrecognized keys refuse.
    mem.fs = Some(FsToolPolicy::new(vec![ws()], Vec::new()));
    mem.opaque_fields = fields
        .iter()
        .map(|f| OpaqueField::parse(f).unwrap())
        .collect();
    let mut policy = Policy {
        tools: vec![mem],
        ..Default::default()
    };
    policy.network.outbound.deny_all_others = false;
    policy
}

fn memory_args(name: &str, observations: &str) -> String {
    format!(
        r#"{{"path":"{}","name":"{name}","observations":{observations}}}"#,
        ws_at("notes.txt")
    )
}

#[test]
fn test_opaque_free_form_values_refused_without_declaration() {
    // B-04 reproduction: the same values the declaration covers are
    // selector-plausible under the restricted contract — "Acme Corp.",
    // "Joined in 2021.", "contact alice@example.com" all carry '.'/'@'.
    let policy = opaque_policy(&[]);
    let args = memory_args(
        "Acme Corp.",
        r#"["Joined in 2021.","contact alice@example.com"]"#,
    );
    let err = check_request(&tools_call(1, "memory_add", &args), &policy).unwrap_err();
    assert!(
        err.reason.contains("unrecognized argument"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_opaque_free_form_values_pass_with_declaration() {
    let policy = opaque_policy(&["name", "observations"]);
    let args = memory_args(
        "Acme Corp.",
        r#"["Joined in 2021.","contact alice@example.com"]"#,
    );
    let result = check_request(&tools_call(1, "memory_add", &args), &policy).unwrap();
    assert_eq!(result.sub_policy, Some("tool:memory_add".to_string()));
    // The declaration count lands in the audit details.
    assert!(
        result.audit_notes.iter().any(|n| n == "opaque_fields=3"),
        "got: {:?}",
        result.audit_notes
    );
}

#[test]
fn test_opaque_declaration_still_refuses_secret_spellings() {
    // Reserved secret spellings classify under any key — the
    // declaration waives only the unrecognized-argument refusal.
    let policy = opaque_policy(&["name", "observations"]);
    for lit in [".env", ".ssh/id_rsa", ".aws/credentials"] {
        let args = memory_args(lit, r#"["ok"]"#);
        let err = check_request(&tools_call(2, "memory_add", &args), &policy).unwrap_err();
        assert!(
            err.reason.contains("secret")
                || err.reason.contains("overlay")
                || err.reason.contains("not in tool fs allowed paths")
                || err.reason.contains("denied by tool fs sub-policy")
                || err.reason.contains("could not be resolved"),
            "literal {lit} must stay refused, got: {}",
            err.reason
        );
    }
}

#[test]
fn test_opaque_declaration_still_refuses_resource_shapes() {
    // Clearly resource-shaped values classify under any key — the
    // declaration does not turn a URL or path into opaque text.
    let mut policy = opaque_policy(&["name", "observations"]);
    // read_only makes the URL contract explicit: host/URL arguments
    // are refused outright.
    policy.tools[0].side_effect = Some("read_only".into());
    policy.tools[0].fs = None;
    let args = memory_args("https://evil.example/x", r#"["ok"]"#);
    let err = check_request(&tools_call(3, "memory_add", &args), &policy).unwrap_err();
    assert!(
        err.reason.contains("read_only"),
        "URL under a declared field must stay refused, got: {}",
        err.reason
    );
    // A filesystem path under the declared field still reaches the fs
    // contract — outside the allow scope it refuses.
    let policy = opaque_policy(&["name", "observations"]);
    let args = memory_args("/etc/passwd", r#"["ok"]"#);
    let err = check_request(&tools_call(4, "memory_add", &args), &policy).unwrap_err();
    assert!(
        err.reason.contains("not in tool fs allowed paths")
            || err.reason.contains("could not be resolved"),
        "path under a declared field must face the fs contract, got: {}",
        err.reason
    );
}

#[test]
fn test_opaque_declaration_does_not_cover_undeclared_fields() {
    // The declaration names fields — a plausible selector under an
    // undeclared key still refuses.
    let policy = opaque_policy(&["name", "observations"]);
    let args = format!(
        r#"{{"path":"{}","name":"Acme Corp.","mystery":"sneaky.example"}}"#,
        ws_at("notes.txt")
    );
    let err = check_request(&tools_call(5, "memory_add", &args), &policy).unwrap_err();
    assert!(
        err.reason.contains("unrecognized argument"),
        "got: {}",
        err.reason
    );
}

#[test]
fn test_opaque_declaration_covers_the_declared_subtree() {
    // A bare name on a container member declares the whole subtree —
    // every scalar under it is free-form, so a memory server's
    // `entities` list needs only `opaque "entities"`.
    let policy = opaque_policy(&["entities"]);
    let args = format!(
        r#"{{"path":"{}","entities":[{{"name":"Acme Corp.","observations":["contact alice@example.com"]}}]}}"#,
        ws_at("notes.txt")
    );
    assert!(
        check_request(&tools_call(8, "memory_add", &args), &policy).is_ok(),
        "a container declaration must cover its subtree"
    );
}

#[test]
fn test_opaque_pointer_form_covers_nested_members() {
    // `/params/arguments/entities/name` — arrays stay transparent, so
    // every element's `name` is declared; a sibling member is not.
    let policy = opaque_policy(&["/params/arguments/entities/name"]);
    let args = format!(
        r#"{{"path":"{}","entities":[{{"name":"Acme Corp."}},{{"name":"alice@example.com"}}]}}"#,
        ws_at("notes.txt")
    );
    assert!(
        check_request(&tools_call(6, "memory_add", &args), &policy).is_ok(),
        "declared nested names must pass"
    );
    let args = format!(
        r#"{{"path":"{}","entities":[{{"name":"ok","ref":"sneaky.example"}}]}}"#,
        ws_at("notes.txt")
    );
    let err = check_request(&tools_call(7, "memory_add", &args), &policy).unwrap_err();
    assert!(
        err.reason.contains("unrecognized argument"),
        "sibling of a declared member must stay refused, got: {}",
        err.reason
    );
}
