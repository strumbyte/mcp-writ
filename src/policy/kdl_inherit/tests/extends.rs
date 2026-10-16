use super::*;

// ── extends ─────────────────────────────────────────────────

#[test]
fn test_extends_basic_inheritance() {
    let dir = make_test_dir("extends_basic");
    // base policy
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/base/ro"
                }
            }
        "#,
    )
    .unwrap();
    // child policy
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            defaults {
                filesystem {
                    allow "/child/rw" mode="write"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    // child inherits base read-only
    assert!(policy.fs.read_only.contains(&"/base/ro".to_string()));
    // child has its own read-write
    assert!(policy.fs.read_write.contains(&"/child/rw".to_string()));
}

#[test]
fn test_extends_filesystem_exec_merges() {
    let dir = make_test_dir("extends_fs_exec");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/base/toolchain" mode="exec"
                    allow "/base/ro"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            defaults {
                filesystem {
                    allow "/child/toolchain" mode="exec"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    // exec allows union across extends like the read/write lists.
    assert!(
        policy
            .fs
            .executable
            .contains(&"/base/toolchain".to_string())
    );
    assert!(
        policy
            .fs
            .executable
            .contains(&"/child/toolchain".to_string())
    );
    assert!(policy.fs.read_only.contains(&"/base/ro".to_string()));
}

#[test]
fn test_extends_filesystem_exec_narrowed_by_child_read() {
    // A child that re-declares an inherited exec path as `mode="read"`
    // narrows it — the explicit read spelling wins, mirroring the
    // write-vs-read convention.
    let dir = make_test_dir("extends_fs_exec_narrow");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/toolchain" mode="exec"
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            defaults {
                filesystem {
                    allow "/toolchain"
                }
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert!(policy.fs.read_only.contains(&"/toolchain".to_string()));
    assert!(policy.fs.executable.is_empty());
}

#[test]
fn test_extends_child_overrides_parent() {
    let dir = make_test_dir("extends_override");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            logging level="debug"
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            logging level="warn"
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    assert_eq!(policy.logging.level, "warn");
}

#[test]
fn test_extends_process_exec_merges_and_conflicts_with_side_effect() {
    let dir = make_test_dir("extends_process");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            server "s" {
                tool "t" side_effect="read_only"
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            server "s" {
                tool "t" {
                    process {
                        allow "echo"
                    }
                }
            }
        "#,
    )
    .unwrap();

    let combined = parse_kdl_policy(
        r#"
            policy version=1
            server "s" {
                tool "t" side_effect="read_only" {
                    process {
                        allow "echo"
                    }
                }
            }
        "#,
    )
    .unwrap();
    assert!(
        crate::policy::validator::validate_policy(&combined).is_err(),
        "same-file read_only + process allow must fail"
    );
    let err = load_kdl_policy(&dir.join("child.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("process execution") || err.to_string().contains("side_effect"),
        "extends must preserve process grant and fail the same check, got {err}"
    );
}

#[test]
fn test_include_process_exec_merges_and_conflicts_with_side_effect() {
    let dir = make_test_dir("include_process");
    std::fs::write(
        dir.join("extra.kdl"),
        r#"
            policy version=1
            server "s" {
                tool "t" {
                    process {
                        allow "echo"
                    }
                }
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("main.kdl"),
        r#"
            include "extra.kdl"
            policy version=1
            server "s" {
                tool "t" side_effect="read_only"
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("main.kdl")).unwrap_err();
    assert!(
        err.to_string().contains("process execution") || err.to_string().contains("side_effect"),
        "include must preserve process grant and fail the same check, got {err}"
    );
}

#[test]
fn test_extends_multi_level() {
    let dir = make_test_dir("extends_multi");
    // grandparent
    std::fs::write(
        dir.join("grandparent.kdl"),
        r#"
            policy version=1
            defaults {
                filesystem {
                    allow "/gp"
                }
            }
        "#,
    )
    .unwrap();
    // parent extends grandparent
    std::fs::write(
        dir.join("parent.kdl"),
        r#"
            extends "grandparent.kdl"
            policy version=1
            defaults {
                filesystem {
                    allow "/parent" mode="write"
                }
            }
        "#,
    )
    .unwrap();
    // child extends parent
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "parent.kdl"
            policy version=1
            logging level="error"
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    // grandparent's read-only inherited through parent
    assert!(policy.fs.read_only.contains(&"/gp".to_string()));
    // parent's read-write inherited
    assert!(policy.fs.read_write.contains(&"/parent".to_string()));
    assert_eq!(policy.logging.level, "error");
}

#[test]
fn test_extends_tools_merged() {
    let dir = make_test_dir("extends_tools");
    std::fs::write(
        dir.join("base.kdl"),
        r#"
            policy version=1
            server "s1" {
                tool "read_file"
                tool "exec" deny=#true
            }
        "#,
    )
    .unwrap();
    std::fs::write(
        dir.join("child.kdl"),
        r#"
            extends "base.kdl"
            policy version=1
            server "s1" {
                tool "exec"
                tool "write_file"
            }
        "#,
    )
    .unwrap();

    let policy = load_kdl_policy(&dir.join("child.kdl")).unwrap();
    // read_file from base preserved
    let rf = policy.tools.iter().find(|t| t.name == "read_file").unwrap();
    assert!(rf.allowed);
    // exec in base had deny=#true; child specified tool "exec" without deny
    // Deny is sticky across extends: exec remains denied!
    let exec = policy.tools.iter().find(|t| t.name == "exec").unwrap();
    assert!(!exec.allowed);
    // write_file added by child
    let wf = policy
        .tools
        .iter()
        .find(|t| t.name == "write_file")
        .unwrap();
    assert!(wf.allowed);
}
