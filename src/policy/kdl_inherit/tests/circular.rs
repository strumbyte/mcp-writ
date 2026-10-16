use super::*;

// ── circular reference detection ────────────────────────────

#[test]
fn test_circular_extends_detected() {
    let dir = make_test_dir("circ_extends");
    std::fs::write(
        dir.join("a.kdl"),
        r#"
            extends "b.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("b.kdl"),
        r#"
            extends "a.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let err = load_kdl_policy(&dir.join("a.kdl")).unwrap_err();
    assert!(err.to_string().contains("circular reference"));
}

#[test]
fn test_circular_include_detected() {
    let dir = make_test_dir("circ_include");
    std::fs::write(
        dir.join("a.kdl"),
        r#"
            include "b.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("b.kdl"),
        r#"
            include "a.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let err = load_kdl_policy(&dir.join("a.kdl")).unwrap_err();
    assert!(err.to_string().contains("circular reference"));
}

#[test]
fn test_self_extends_detected() {
    let dir = make_test_dir("self_extends");
    std::fs::write(
        dir.join("self.kdl"),
        r#"
            extends "self.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let err = load_kdl_policy(&dir.join("self.kdl")).unwrap_err();
    assert!(err.to_string().contains("circular reference"));
}

#[test]
fn test_three_way_circular_extends() {
    let dir = make_test_dir("circ3");
    std::fs::write(
        dir.join("a.kdl"),
        r#"
            extends "b.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("b.kdl"),
        r#"
            extends "c.kdl"
            policy version=1
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("c.kdl"),
        r#"
            extends "a.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let err = load_kdl_policy(&dir.join("a.kdl")).unwrap_err();
    assert!(err.to_string().contains("circular reference"));
}
