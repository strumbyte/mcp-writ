use super::*;

// RF01: a `PolicyViolation` carries its refusal kind as structured type
// information decided where the refusal is produced — the audit event
// type, the wire collapse, and `correction_candidates.denied_targets`
// all read `kind`, never the reason text. These tests pin the mapping
// and the fixture-level guarantee that a target *spelling* containing
// denial phrases cannot steer the classification.

#[test]
fn authorization_denials_share_one_client_reason() {
    // `listed` distinguishes the audit record; the wire sees one
    // reason either way — `tools/call` errors cannot probe which tool
    // names exist in the policy.
    let listed = PolicyViolation::new(
        "exec_shell",
        DenialKind::Authorization { listed: true },
        REASON_TOOL_NOT_ALLOWED,
    );
    let unknown = PolicyViolation::new(
        "nope",
        DenialKind::Authorization { listed: false },
        REASON_TOOL_NOT_FOUND,
    );
    assert_eq!(listed.client_reason(), unknown.client_reason());
    assert_eq!(listed.client_reason(), REASON_TOOL_NOT_ALLOWED);
    assert!(listed.is_authorization_denial() && unknown.is_authorization_denial());
    assert!(!listed.is_denied_target() && !unknown.is_denied_target());
    assert!(listed.validation_kind().is_none() && unknown.validation_kind().is_none());
    // Audit detail stays distinct.
    assert_ne!(listed.reason, unknown.reason);
}

#[test]
fn denied_target_with_traversal_text_stays_a_target_denial() {
    // The RF01 regression shape: an ordinary out-of-scope path whose
    // spelling contains "path traversal" (and even a whole denial
    // suffix) is still an ordinary target denial — no validation
    // event, still a widening candidate.
    for spelled in [
        "path 'tree/path traversal report/x.txt' (resolved '/r/tree/path traversal report/x.txt') not in tool fs allowed paths",
        "path 'x') denied by tool fs sub-policy' (resolved '/r/x') denied by tool fs sub-policy') not in tool fs allowed paths",
    ] {
        let v = PolicyViolation::new("read_file", DenialKind::DeniedTarget, spelled);
        assert!(v.is_denied_target(), "{spelled}");
        assert_eq!(v.validation_kind(), None, "{spelled}");
        assert!(!v.is_authorization_denial(), "{spelled}");
    }
}

#[test]
fn session_and_shape_denials_are_never_targets_or_validation() {
    // Trajectory/deputy refusals and shape/contract/spelling refusals
    // must not be widening candidates even when their display text
    // mentions a path.
    for (kind, reason) in [
        (
            DenialKind::Session,
            "trajectory: after side_effect=read_only deny network",
        ),
        (
            DenialKind::Session,
            "confused deputy: path '/w/x' was not discovered by a discovery-role tool call",
        ),
        (
            DenialKind::Other,
            "filesystem-restricted tool is missing a path target",
        ),
        (
            DenialKind::Other,
            "path '/w/../x' could not be resolved: not found",
        ),
        (
            DenialKind::Other,
            "path argument '/w/%2e%2e/x' is not in canonical form",
        ),
        (DenialKind::Other, "inputResponses denied by tool policy"),
        (DenialKind::Other, "unrecognized argument 'x' …"),
    ] {
        let v = PolicyViolation::new("t", kind, reason);
        assert!(!v.is_denied_target(), "{reason}");
        assert_eq!(v.validation_kind(), None, "{reason}");
        assert!(!v.is_authorization_denial(), "{reason}");
    }
}

#[test]
fn secret_overlay_only_reserved_match_is_a_target() {
    // The overlay's reserved-set hit names a denied target a wider
    // allow could grant; its spelling refusals do not.
    let reserved = PolicyViolation::new(
        "read_file",
        DenialKind::SecretOverlay {
            reserved_match: true,
        },
        "path '/w/.ssh/id_rsa' matches the secret-path overlay (beats explicit allow)",
    );
    assert!(reserved.is_denied_target());
    for reason in [
        "path '/w/\u{200B}x' contains invisible Unicode and is rejected by secret-overlay",
        "path 'file:etc/passwd' is an opaque file: URI and is rejected by the secret-path overlay",
    ] {
        let v = PolicyViolation::new(
            "read_file",
            DenialKind::SecretOverlay {
                reserved_match: false,
            },
            reason,
        );
        assert!(!v.is_denied_target(), "{reason}");
        assert_eq!(v.validation_kind(), None, "{reason}");
    }
}

#[test]
fn schema_mismatch_is_validation_not_target() {
    // `args_schema` rejecting the arguments earns
    // `validation.argument_invalid` — and stays out of the widening
    // candidates: granting a path cannot fix a type mismatch.
    let policy = schema_policy();
    let line = tools_call(3, "read_file", r#"{"path":42}"#);
    let err = check_request(&line, &policy).unwrap_err();
    assert_eq!(
        err.validation_kind(),
        Some(crate::audit_log::EventType::ValidationArgumentInvalid),
        "{}",
        err.reason
    );
    assert!(err.reason.starts_with("schema validation failed:"));
    assert!(!err.is_denied_target());
    assert!(!err.is_authorization_denial());
}

#[test]
fn schema_file_traversal_is_validation_not_target() {
    // An `args_schema = "@path"` resolving outside the working
    // directory is a genuine `validation.path_traversal` — tagged by
    // the loader, not by matching the reason text.
    let dir = tempfile::tempdir().unwrap();
    let schema_file = dir.path().join("schema.json");
    std::fs::write(&schema_file, r#"{"type":"object"}"#).unwrap();
    let mut policy = schema_policy();
    for tool in &mut policy.tools {
        if tool.name == "read_file" {
            tool.args_schema = Some(format!("@{}", schema_file.display()));
        }
    }
    let line = tools_call(4, "read_file", r#"{"path":"/tmp/f.txt"}"#);
    let err = check_request(&line, &policy).unwrap_err();
    assert_eq!(
        err.validation_kind(),
        Some(crate::audit_log::EventType::ValidationPathTraversal),
        "{}",
        err.reason
    );
    assert!(err.reason.contains("path traversal"), "{}", err.reason);
    assert!(!err.is_denied_target());
}
