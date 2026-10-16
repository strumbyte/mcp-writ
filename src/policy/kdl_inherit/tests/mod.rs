use super::*;
use crate::policy::kdl_loader::{load_kdl_policy, load_kdl_policy_with_env, parse_kdl_policy};

#[test]
fn test_load_example_kdl_file() {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
    let policy = load_kdl_policy(&path).expect("Failed to load policy.example.kdl");
    assert_eq!(policy.version, 2);
    assert_eq!(policy.tools.len(), 3);
    assert!(policy.tools[0].allowed);
    assert_eq!(policy.tools[0].name, "read_file");
    assert_eq!(policy.tools[0].side_effect.as_deref(), Some("read_only"));
    assert!(!policy.tools[2].allowed);
    assert_eq!(policy.tools[2].name, "exec_shell");
    assert!(policy.network.outbound.deny_all_others);
    assert_eq!(policy.fs.read_only.len(), 2); // /usr/lib/** and /etc/ssl/certs/**
    assert_eq!(policy.fs.read_write.len(), 1); // /workspace/**
    assert_eq!(policy.syscalls.allowed.len(), 20);
    assert!(policy.syscalls.allowed.iter().any(|s| s == "execve"));
    assert!(policy.syscalls.allowed.iter().any(|s| s == "execveat"));
}

// ================================================================
// extends / include / when / circular-reference tests
// ================================================================

/// Helper: create a temp directory with a unique name for test isolation.
fn make_test_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("mcp_writ_test").join(format!(
        "{}_{}",
        label,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_load_rejects_per_tool_syscalls() {
    let dir = make_test_dir("tool_syscalls_rejected");
    std::fs::write(
        dir.join("policy.kdl"),
        r#"
            policy version=1
            server "svc" {
                tool "x" {
                    syscalls {
                        allow "read"
                    }
                }
            }
        "#,
    )
    .unwrap();
    let err = load_kdl_policy(&dir.join("policy.kdl")).unwrap_err();
    assert!(err.to_string().contains("per-tool syscalls"), "got: {err}");
}

mod budgets;
mod circular;
mod deputy;
mod edges;
mod environment;
mod extends;
mod include;
mod mcp;
mod merge;
mod review;
mod when;
