use super::*;

// ── REVIEW markers (PR-14) ──────────────────────────────────

#[test]
fn review_markers_collected_across_extends_include_and_entry() {
    let dir = make_test_dir("review_markers");
    std::fs::write(
        dir.join("base.kdl"),
        "// REVIEW: base pin needs a decision\npolicy version=1\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("extra.kdl"),
        "policy version=1\nserver \"s\" {\n  tool \"t\"\n}\n/* REVIEW: include note */\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("policy.kdl"),
        "extends \"base.kdl\"\ninclude \"extra.kdl\"\npolicy version=1\n// REVIEW: entry marker\n",
    )
    .unwrap();

    let (_policy, diagnostics) = crate::policy::kdl_loader::load_kdl_policy_for_target_scanned(
        &dir.join("policy.kdl"),
        "",
        &crate::execution::ExecutionTarget::native(),
    )
    .unwrap();
    let markers = &diagnostics.review_markers;
    assert_eq!(markers.len(), 3, "got: {markers:?}");
    let by_file: std::collections::HashMap<_, _> = markers
        .iter()
        .map(|m| {
            (
                m.path.file_name().unwrap().to_string_lossy().into_owned(),
                m.line,
            )
        })
        .collect();
    assert_eq!(by_file.get("base.kdl"), Some(&1));
    assert_eq!(by_file.get("extra.kdl"), Some(&5));
    assert_eq!(by_file.get("policy.kdl"), Some(&4));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn review_markers_absent_for_clean_policy() {
    let dir = make_test_dir("review_none");
    std::fs::write(
        dir.join("policy.kdl"),
        "policy version=1\n// operator note, not a marker\nserver \"s\" {\n  tool \"t\"\n}\n",
    )
    .unwrap();
    let (_policy, diagnostics) = crate::policy::kdl_loader::load_kdl_policy_for_target_scanned(
        &dir.join("policy.kdl"),
        "",
        &crate::execution::ExecutionTarget::native(),
    )
    .unwrap();
    assert!(diagnostics.review_markers.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn review_mode_enforce_refuse_and_warn() {
    use crate::policy::review::{ReviewMarker, ReviewMode};
    let markers = vec![ReviewMarker {
        path: std::path::PathBuf::from("policy.kdl"),
        line: 3,
        text: "REVIEW: x".to_string(),
    }];
    // Refuse fails the load; Warn/Off leave it untouched; an empty list
    // is a no-op for every mode.
    assert!(matches!(
        ReviewMode::Refuse.enforce(&markers),
        Err(crate::error::PolicyError::Validation(_))
    ));
    assert!(ReviewMode::Warn.enforce(&markers).is_ok());
    assert!(ReviewMode::Off.enforce(&markers).is_ok());
    assert!(ReviewMode::Refuse.enforce(&[]).is_ok());
}
