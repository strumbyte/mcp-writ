//! RF01 (docs/refactoring-pr-guide-2026-11.ja.md §RF01): typed refusal
//! classification for `PolicyViolation`. The fixture in
//! `tests/fixtures/refactoring/rf01/` runs through
//! `checker::check_request` with the working directory switched to a
//! write-restricted root the test prepares: the audit event type, the
//! wire collapse, and the `correction_candidates.denied_targets`
//! selection must follow the refusal's declared kind — never the
//! reason text a user-controlled path spelling can shape.
//!
//! `requests.jsonl` line 3 is the regression shape: an ordinary
//! out-of-scope path whose spelling contains `path traversal` used to
//! emit a `validation.path_traversal` event and drop out of the
//! widening candidates; it must now stay an ordinary denied target.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use mcp_writ::audit_log::EventType;
use mcp_writ::auditor::{checker, session};
use mcp_writ::policy::{FsPolicy, FsToolPolicy, Policy, ToolPolicy};

/// Serializes the working-directory switch the fixture requires —
/// `cwd` is process-global, so the whole fixture sequence runs under
/// one lock inside this dedicated test binary.
static CWD_LOCK: Mutex<()> = Mutex::new(());

/// Restore the original working directory on drop — a panicking
/// fixture must not leak the switched `cwd` into this binary's other
/// tests.
struct CwdGuard(PathBuf);

impl CwdGuard {
    fn enter(dir: &Path) -> Self {
        let saved = std::env::current_dir().expect("cwd must be readable");
        std::env::set_current_dir(dir).expect("chdir into fixture root");
        Self(saved)
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/refactoring/rf01")
}

fn member<'j>(v: nojson::RawJsonValue<'j, 'j>, key: &str) -> Option<nojson::RawJsonValue<'j, 'j>> {
    v.to_member(key).ok().and_then(|m| m.optional())
}

fn str_of(v: nojson::RawJsonValue<'_, '_>) -> String {
    v.to_unquoted_string_str().unwrap().into_owned()
}

fn str_list(v: Option<nojson::RawJsonValue<'_, '_>>) -> Vec<String> {
    match v {
        Some(v) => v.to_array().unwrap().map(str_of).collect(),
        None => Vec::new(),
    }
}

fn flag(v: Option<nojson::RawJsonValue<'_, '_>>, default: bool) -> bool {
    v.map(|v| v.as_boolean_str().unwrap() == "true")
        .unwrap_or(default)
}

/// The fixture policy template `policy.json` parsed into a `Policy`:
/// `${ROOT}` placeholders are substituted with the prepared root's
/// policy spelling first. `FsToolPolicy::new` mirrors what a KDL
/// `fs { allow "…"; deny "…" }` block builds — `allowed_paths` also
/// seed `read_only_paths` and `allow_specified`.
fn fixture_policy(root: &Path) -> Policy {
    let root_str = common::policy_path_str(root);
    let src = std::fs::read_to_string(fixture_dir().join("policy.json"))
        .expect("fixture policy.json")
        .replace("${ROOT}", &root_str);
    let json = nojson::RawJson::parse(&src).expect("fixture policy parses");

    let mut tools = Vec::new();
    for t in member(json.value(), "tools").unwrap().to_array().unwrap() {
        let mut tool = ToolPolicy::named(
            str_of(member(t, "name").unwrap()),
            flag(member(t, "allowed"), false),
        );
        if let Some(schema) = member(t, "args_schema") {
            tool.args_schema = Some(str_of(schema));
        }
        if let Some(fs) = member(t, "fs") {
            let mut fs_policy = FsToolPolicy::new(
                str_list(member(fs, "allowed_paths")),
                str_list(member(fs, "denied_paths")),
            );
            fs_policy.allow_specified =
                flag(member(fs, "allow_specified"), fs_policy.allow_specified);
            tool.fs = Some(fs_policy);
        }
        tools.push(tool);
    }

    let mut policy = Policy {
        tools,
        ..Default::default()
    };
    if let Some(fs) = member(json.value(), "fs") {
        policy.fs = FsPolicy {
            read_only: str_list(member(fs, "read_only")),
            read_write: str_list(member(fs, "read_write")),
            denied_paths: str_list(member(fs, "denied_paths")),
            allow_specified: flag(member(fs, "allow_specified"), false),
            secret_overlay: flag(member(fs, "secret_overlay"), true),
            ..Default::default()
        };
    }
    if let Some(outbound) = member(json.value(), "outbound") {
        // The fixture grants an explicit allow list — open posture.
        policy.network.outbound = mcp_writ::policy::OutboundPolicy {
            allowed: str_list(member(outbound, "allowed_hosts")),
            deny_all_others: false,
            ..Default::default()
        };
    }
    policy
}

/// `check_request` classification over `requests.jsonl`: the audit
/// event type and the widening-candidate bit follow the declared
/// kind — a user-controlled spelling can no longer steer either.
#[test]
fn rf01_fixture_classification() {
    let _lock = CWD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(root) = common::restricted_tempdir() else {
        common::skip_e2e_test("denial classification needs a write-restricted root");
        return;
    };
    let _cwd = CwdGuard::enter(root.path());
    let policy = fixture_policy(root.path());
    let requests =
        std::fs::read_to_string(fixture_dir().join("requests.jsonl")).expect("fixture requests");
    let lines: Vec<&str> = requests
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 11, "fixture contract changed");

    // 1 — baseline: an in-scope path under the allowed root passes.
    assert!(
        checker::check_request(lines[0], &policy).is_ok(),
        "line 1 must pass"
    );

    // 2 — ordinary out-of-scope path (a `..` fold inside the allowed
    // spelling): a real target denial, no validation event.
    let err = checker::check_request(lines[1], &policy).unwrap_err();
    assert!(err.is_denied_target(), "line 2: {}", err.reason);
    assert_eq!(err.validation_kind(), None, "line 2: {}", err.reason);
    assert!(
        err.reason.contains("not in tool fs allowed paths"),
        "line 2: {}",
        err.reason
    );

    // 3 — the RF01 regression case: the path *spelling* contains
    // "path traversal" but the refusal is an ordinary out-of-scope
    // target denial. `contains("path traversal")` used to emit a
    // `validation.path_traversal` event and drop the candidate; the
    // typed kind keeps both verdicts.
    let err = checker::check_request(lines[2], &policy).unwrap_err();
    assert!(err.is_denied_target(), "line 3: {}", err.reason);
    assert_eq!(
        err.validation_kind(),
        None,
        "line 3 spelling must not steer the audit event: {}",
        err.reason
    );
    assert!(
        err.reason.contains("not in tool fs allowed paths"),
        "line 3: {}",
        err.reason
    );

    // 4 — a quote inside the `path '…'` wrapper must not break the
    // target-denial recognition either.
    let err = checker::check_request(lines[3], &policy).unwrap_err();
    assert!(err.is_denied_target(), "line 4: {}", err.reason);
    assert_eq!(err.validation_kind(), None, "line 4: {}", err.reason);

    // 5 / 6 — embedded denial suffixes in the spelling cannot fake a
    // different refusal kind.
    for (i, line) in lines[4..6].iter().enumerate() {
        let err = checker::check_request(line, &policy).unwrap_err();
        let n = i + 5;
        assert!(err.is_denied_target(), "line {n}: {}", err.reason);
        assert_eq!(err.validation_kind(), None, "line {n}: {}", err.reason);
        assert!(
            err.reason.contains("not in tool fs allowed paths"),
            "line {n}: {}",
            err.reason
        );
    }

    // 7 — the genuinely denied secret path: a `denied by` target
    // denial, still a widening candidate.
    let err = checker::check_request(lines[6], &policy).unwrap_err();
    assert!(err.is_denied_target(), "line 7: {}", err.reason);
    assert_eq!(err.validation_kind(), None, "line 7: {}", err.reason);
    assert!(
        err.reason.contains("denied by tool fs sub-policy"),
        "line 7: {}",
        err.reason
    );

    // 8 — an escape spelling resolving outside the allow root stays an
    // ordinary out-of-scope denial, not a traversal *event*.
    let err = checker::check_request(lines[7], &policy).unwrap_err();
    assert!(err.is_denied_target(), "line 8: {}", err.reason);
    assert_eq!(err.validation_kind(), None, "line 8: {}", err.reason);
    assert!(
        err.reason.contains("not in tool fs allowed paths"),
        "line 8: {}",
        err.reason
    );

    // 9 — the args_schema type mismatch: `validation.argument_invalid`,
    // never a widening candidate.
    let err = checker::check_request(lines[8], &policy).unwrap_err();
    assert_eq!(
        err.validation_kind(),
        Some(EventType::ValidationArgumentInvalid),
        "line 9: {}",
        err.reason
    );
    assert!(!err.is_denied_target(), "line 9: {}", err.reason);
    assert!(
        err.reason.starts_with("schema validation failed:"),
        "line 9: {}",
        err.reason
    );

    // 10 / 11 — absent and listed-but-denied names share one client
    // reason while the audit detail stays distinct.
    let unknown = checker::check_request(lines[9], &policy).unwrap_err();
    let denied = checker::check_request(lines[10], &policy).unwrap_err();
    assert!(
        unknown.is_authorization_denial() && denied.is_authorization_denial(),
        "lines 10/11"
    );
    assert_eq!(unknown.client_reason(), denied.client_reason());
    assert_eq!(unknown.client_reason(), "tool is not allowed");
    assert!(
        unknown.reason.contains("not found in policy"),
        "line 10: {}",
        unknown.reason
    );
    assert_eq!(denied.reason, "tool is not allowed", "line 11");
    assert!(
        !unknown.is_denied_target() && !denied.is_denied_target(),
        "lines 10/11"
    );
    assert!(
        unknown.validation_kind().is_none() && denied.validation_kind().is_none(),
        "lines 10/11"
    );

    // True-positive comparators behind the session/schema-file entry
    // points — genuine traversal still earns `validation.path_traversal`.
    let state = session::SessionState::new();
    let err = state.check_access("../escape/passwd").unwrap_err();
    assert!(
        matches!(err, session::AccessDenial::PathTraversal(_)),
        "session gate must tag traversal: {err}"
    );
    assert!(
        err.reason().contains("path traversal detected"),
        "{}",
        err.reason()
    );
    let err = state.check_access("tree/allowed/ok.txt").unwrap_err();
    assert!(
        matches!(err, session::AccessDenial::NotDiscovered(_)),
        "undiscovered path is not a traversal: {err}"
    );

    // `args_schema = "@file"` resolving outside cwd — the loader entry
    // point produces the traversal; the checker labels it.
    let outside = common::real_tempdir();
    let schema_file = outside.path().join("schema.json");
    std::fs::write(&schema_file, r#"{"type":"object"}"#).unwrap();
    let mut policy = fixture_policy(root.path());
    let schema_ref = format!("@{}", common::policy_path_str(&schema_file));
    for tool in &mut policy.tools {
        if tool.name == "read_file" {
            tool.args_schema = Some(schema_ref.clone());
        }
    }
    let line = r#"{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"tree/allowed/ok.txt"}}}"#;
    let err = checker::check_request(line, &policy).unwrap_err();
    assert_eq!(
        err.validation_kind(),
        Some(EventType::ValidationPathTraversal),
        "schema-file traversal must keep the event: {}",
        err.reason
    );
    assert!(
        err.reason.contains("path traversal: schema file"),
        "{}",
        err.reason
    );
    assert!(!err.is_denied_target(), "{}", err.reason);
}
