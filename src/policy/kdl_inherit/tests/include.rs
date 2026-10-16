use super::*;

// ── include ─────────────────────────────────────────────────

#[test]
fn test_include_basic() {
    let dir = make_test_dir("include_basic");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=1
            server "extra" {
                tool "extra_tool"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "extra.kdl"
            policy version=1
            server "main" {
                tool "main_tool"
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
    assert!(policy.tools.iter().any(|t| t.name == "extra_tool"));
    assert!(policy.tools.iter().any(|t| t.name == "main_tool"));
}

#[test]
fn test_include_multiple_files() {
    let dir = make_test_dir("include_multi");
    std::fs::write(
        dir.join("a.kdl"),
        r#"
            policy version=1
            server "sa" {
                tool "tool_a"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("b.kdl"),
        r#"
            policy version=1
            server "sb" {
                tool "tool_b"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "a.kdl"
            include "b.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
    assert!(policy.tools.iter().any(|t| t.name == "tool_a"));
    assert!(policy.tools.iter().any(|t| t.name == "tool_b"));
}

#[test]
fn test_include_subdirectory_relative_path() {
    let dir = make_test_dir("include_subdir");
    let sub = dir.join("rules");
    std::fs::create_dir_all(&sub).unwrap();
    std::fs::write(
        sub.join("extra.kdl"),
        r#"
            policy version=1
            server "sub" {
                tool "sub_tool"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "rules/extra.kdl"
            policy version=1
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("main.kdl")).unwrap();
    assert!(policy.tools.iter().any(|t| t.name == "sub_tool"));
}
