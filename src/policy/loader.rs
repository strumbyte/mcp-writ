use std::path::Path;

use super::default_policy;
use crate::error::PolicyError;

/// Load a KDL policy file from disk, parse it, and validate.
pub fn load_policy(path: &Path) -> Result<super::Policy, PolicyError> {
    super::kdl_loader::load_kdl_policy(path)
}

pub fn load_policy_or_default(path: Option<&Path>) -> Result<super::Policy, PolicyError> {
    match path {
        Some(p) => load_policy(p),
        None => Ok(default_policy()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::TransportType;
    use std::path::PathBuf;

    #[test]
    fn test_load_policy_example_kdl() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        let policy = load_policy(&path).expect("Failed to load policy.example.kdl");
        assert_eq!(policy.version, 1);
        assert_eq!(policy.tools.len(), 3);
        assert!(policy.tools[0].allowed);
        assert_eq!(policy.tools[0].name, "read_file");
        assert!(!policy.tools[2].allowed);
        assert_eq!(policy.tools[2].name, "exec_shell");
        assert!(policy.network.outbound.deny_all_others);
    }

    #[test]
    fn test_default_policy_does_not_panic() {
        let policy = default_policy();
        assert_eq!(policy.version, 1);
        assert!(policy.tools.is_empty());
        assert!(policy.network.outbound.deny_all_others);
    }

    #[test]
    fn test_load_policy_or_default_none() {
        let policy = load_policy_or_default(None).expect("default should not fail");
        assert_eq!(policy.version, 1);
    }

    #[test]
    fn test_load_policy_or_default_some() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        let policy = load_policy_or_default(Some(&path)).expect("should load example");
        assert_eq!(policy.tools.len(), 3);
    }

    #[test]
    fn test_tool_fs_policy_parsed() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        let policy = load_policy(&path).expect("policy.example.kdl should load");

        let read_file = &policy.tools[0];
        assert_eq!(read_file.side_effect.as_deref(), Some("read_only"));
        let fs = read_file
            .fs
            .as_ref()
            .expect("read_file should have fs policy");
        assert_eq!(fs.allowed_paths, vec!["/workspace/**"]);
        assert_eq!(fs.denied_paths, vec!["/home/*/.ssh/**"]);

        let write_file = &policy.tools[1];
        let fs = write_file
            .fs
            .as_ref()
            .expect("write_file should have fs policy");
        assert_eq!(fs.allowed_paths, vec!["/workspace/output/**"]);
        assert!(fs.denied_paths.is_empty());

        let exec_shell = &policy.tools[2];
        assert_eq!(exec_shell.name, "exec_shell");
        assert!(!exec_shell.allowed);
        // In 4-stage merge, defaults.filesystem is inherited by tools
        let fs = exec_shell
            .fs
            .as_ref()
            .expect("exec_shell should have fs policy");
        assert!(fs.allowed_paths.contains(&"/workspace/**".to_string()));
    }

    #[test]
    fn test_syscalls_parsed() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("policy.example.kdl");
        let policy = load_policy(&path).expect("policy.example.kdl should load");
        assert!(policy.syscalls.allowed.contains(&"read".to_string()));
        assert!(policy.syscalls.allowed.contains(&"exit_group".to_string()));
        assert_eq!(policy.syscalls.allowed.len(), 20);
        assert!(policy.syscalls.allowed.iter().any(|s| s == "execve"));
    }

    #[test]
    fn test_load_nonexistent_file_returns_error() {
        let path = PathBuf::from("/tmp/__nonexistent_policy_file_12345__.kdl");
        let result = load_policy(&path);
        assert!(result.is_err());
        let err = result.expect_err("loading nonexistent file should fail");
        assert!(matches!(err, crate::error::PolicyError::FileRead(_)));
    }

    #[test]
    fn test_validate_unsupported_version() {
        let mut policy = default_policy();
        policy.version = 99;
        let err = policy
            .validate()
            .expect_err("unsupported version should fail validation");
        assert!(matches!(err, crate::error::PolicyError::Validation(_)));
    }

    #[test]
    fn test_validate_http_without_listen_addr() {
        let mut policy = default_policy();
        policy.transport.type_ = TransportType::Http;
        let err = policy
            .validate()
            .expect_err("HTTP without listen_addr should fail validation");
        assert!(matches!(err, crate::error::PolicyError::Validation(_)));
    }
}
