use std::path::{Path, PathBuf};

use crate::error::{ContainerError, McpWritError};

/// Determine the target architecture string for runner binary lookup.
///
/// Returns an error for unsupported architectures instead of silently
/// returning "unknown" which would lead to confusing error messages
/// about non-existent paths like "mcp-secure-runner-linux-unknown".
fn runner_arch() -> Result<&'static str, ContainerError> {
    runner_arch_aliases().map(|(primary, _)| primary)
}

fn runner_arch_aliases() -> Result<(&'static str, &'static str), ContainerError> {
    if cfg!(target_arch = "x86_64") {
        Ok(("amd64", "x86_64"))
    } else if cfg!(target_arch = "aarch64") {
        Ok(("arm64", "aarch64"))
    } else {
        Err(ContainerError::RunnerResolve(format!(
            "unsupported CPU architecture: {}. \
             mcp-secure-runner binaries are only available for amd64 and arm64",
            std::env::consts::ARCH,
        )))
    }
}

/// Check if a file has executable permission (Unix only).
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.exists()
}

/// Resolve the path to the mcp-secure-runner binary.
///
/// Priority:
/// 1. If `explicit_path` is `Some`, use that path (with existence + executable checks).
/// 2. If `MCP_SECURE_RUNNER_PATH` environment variable is set, use that path.
/// 3. Otherwise, look for `runners/mcp-secure-runner-linux-<arch>` next to the
///    current mcp-writ binary (accepting both amd64/x86_64).
/// 4. If not found, return an error with download instructions.
pub fn resolve_runner_binary(explicit_path: Option<&Path>) -> Result<PathBuf, McpWritError> {
    if let Some(path) = explicit_path {
        if !path.exists() {
            return Err(ContainerError::RunnerResolve(format!(
                "specified runner binary not found: {}",
                path.display(),
            ))
            .into());
        }
        if !is_executable(path) {
            return Err(ContainerError::RunnerResolve(format!(
                "specified runner binary is not executable: {}. Run: chmod +x {}",
                path.display(),
                path.display(),
            ))
            .into());
        }
        return Ok(path.to_path_buf());
    }

    // Check MCP_SECURE_RUNNER_PATH environment variable
    if let Ok(env_val) = std::env::var("MCP_SECURE_RUNNER_PATH") {
        let env_path = Path::new(env_val.trim());
        if !env_path.as_os_str().is_empty() {
            if !env_path.exists() {
                return Err(ContainerError::RunnerResolve(format!(
                    "runner binary specified by MCP_SECURE_RUNNER_PATH not found: {}",
                    env_path.display(),
                ))
                .into());
            }
            if !is_executable(env_path) {
                return Err(ContainerError::RunnerResolve(format!(
                    "runner binary specified by MCP_SECURE_RUNNER_PATH is not executable: {}. Run: chmod +x {}",
                    env_path.display(),
                    env_path.display(),
                ))
                .into());
            }
            return Ok(env_path.to_path_buf());
        }
    }

    // Auto-detect: look next to the current binary only.
    let current_exe = std::env::current_exe().map_err(|e| {
        ContainerError::RunnerResolve(format!("failed to determine current executable path: {e}"))
    })?;

    let exe_dir = current_exe.parent().ok_or_else(|| {
        ContainerError::RunnerResolve("current executable has no parent directory".to_string())
    })?;

    let (arch, alt_arch) = runner_arch_aliases()?;
    let candidate_dirs = [exe_dir.join("runners")];
    let candidate_names = [
        format!("mcp-secure-runner-linux-{arch}"),
        format!("mcp-secure-runner-linux-{alt_arch}"),
    ];

    for dir in &candidate_dirs {
        for name in &candidate_names {
            let p = dir.join(name);
            if p.exists() {
                if !is_executable(&p) {
                    return Err(ContainerError::RunnerResolve(format!(
                        "runner binary found but not executable: {}. Run: chmod +x {}",
                        p.display(),
                        p.display(),
                    ))
                    .into());
                }
                return Ok(p);
            }
        }
    }

    let default_runner_path = exe_dir.join("runners").join(&candidate_names[0]);
    // Not found - provide helpful error message
    Err(ContainerError::RunnerResolve(format!(
        "mcp-secure-runner binary not found.\n\
         Searched: {}\n\
         \n\
         To obtain it:\n\
         1. Download from GitHub Releases: https://github.com/strumbyte/mcp-writ/releases\n\
         2. Place the binary at: {}\n\
         3. Or specify explicitly: mcp-writ wrap-image --runner-binary /path/to/runner <image>\n\
         4. Or set MCP_SECURE_RUNNER_PATH environment variable",
        default_runner_path.display(),
        default_runner_path.display(),
    ))
    .into())
}

/// Build the expected runner binary path for a given exe directory (for testing/display).
///
/// Returns an error if the current architecture is not supported.
pub fn expected_runner_path(exe_dir: &Path) -> Result<PathBuf, ContainerError> {
    let arch = runner_arch()?;
    let runner_name = format!("mcp-secure-runner-linux-{arch}");
    Ok(exe_dir.join("runners").join(runner_name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a unique temporary directory under std::env::temp_dir().
    /// Returns the path. Caller is responsible for cleanup.
    fn make_temp_dir(label: &str) -> PathBuf {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mcp_writ_test_{label}_{id}_{ts}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -- runner_arch ----------------------------------------------------------

    #[test]
    fn test_runner_arch_returns_known_value() {
        let result = runner_arch();
        // On supported architectures (x86_64, aarch64), should return Ok
        // On unsupported architectures, should return Err with clear message
        match result {
            Ok(arch) => assert!(
                ["amd64", "arm64"].contains(&arch),
                "unexpected arch: {arch}"
            ),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("unsupported CPU architecture"),
                    "error should mention unsupported architecture: {msg}"
                );
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_runner_arch_x86_64() {
        assert_eq!(runner_arch().unwrap(), "amd64");
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_runner_arch_aarch64() {
        assert_eq!(runner_arch().unwrap(), "arm64");
    }

    // -- explicit path: exists and executable ---------------------------------

    #[test]
    fn test_explicit_path_exists_executable() {
        let dir = make_temp_dir("explicit_ok");
        let runner = dir.join("my-runner");
        fs::write(&runner, "#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let result = resolve_runner_binary(Some(&runner));
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), runner);

        let _ = fs::remove_dir_all(&dir);
    }

    // -- explicit path: not found ---------------------------------------------

    #[test]
    fn test_explicit_path_not_found() {
        let path = Path::new("/nonexistent/path/to/runner");
        let result = resolve_runner_binary(Some(path));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "error should mention 'not found': {err}"
        );
        assert!(
            err.contains("/nonexistent/path/to/runner"),
            "error should contain the path: {err}"
        );
    }

    // -- explicit path: not executable (Unix) ---------------------------------

    #[cfg(unix)]
    #[test]
    fn test_explicit_path_not_executable() {
        let dir = make_temp_dir("explicit_noexec");
        let runner = dir.join("my-runner");
        fs::write(&runner, "#!/bin/sh\n").unwrap();

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&runner, fs::Permissions::from_mode(0o644)).unwrap();

        let result = resolve_runner_binary(Some(&runner));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not executable"),
            "error should mention 'not executable': {err}"
        );
        assert!(
            err.contains("chmod +x"),
            "error should suggest chmod +x: {err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    // -- auto-detect: runner found in runners/ dir ----------------------------

    #[test]
    fn test_auto_detect_expected_path() {
        let dir = make_temp_dir("autodetect");
        let arch = runner_arch().expect("runner_arch should succeed on supported arch");
        let runners_dir = dir.join("runners");
        fs::create_dir_all(&runners_dir).unwrap();

        let runner_name = format!("mcp-secure-runner-linux-{arch}");
        let runner_path = runners_dir.join(&runner_name);
        fs::write(&runner_path, "#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runner_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Verify expected_runner_path returns the right path
        let expected = expected_runner_path(&dir)
            .expect("expected_runner_path should succeed on supported arch");
        assert_eq!(expected, runner_path);

        let _ = fs::remove_dir_all(&dir);
    }

    // -- auto-detect: not found → descriptive error ---------------------------

    #[test]
    fn test_auto_detect_not_found_error() {
        // When no explicit path is given and current_exe() is used,
        // the runner directory next to the test binary won't have it.
        let result = resolve_runner_binary(None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("not found"),
            "error should mention 'not found': {err}"
        );
        assert!(
            err.contains("mcp-secure-runner"),
            "error should mention binary name: {err}"
        );
        assert!(
            err.contains("Download from GitHub"),
            "error should include download instructions: {err}"
        );
        assert!(
            err.contains("--runner-binary"),
            "error should mention --runner-binary flag: {err}"
        );
    }

    // -- expected_runner_path -------------------------------------------------

    #[test]
    fn test_expected_runner_path_format() {
        let dir = Path::new("/usr/local/bin");
        let path = expected_runner_path(dir)
            .expect("expected_runner_path should succeed on supported arch");
        let arch = runner_arch().expect("runner_arch should succeed on supported arch");
        assert_eq!(
            path,
            PathBuf::from(format!(
                "/usr/local/bin/runners/mcp-secure-runner-linux-{arch}"
            ))
        );
    }

    // -- is_executable --------------------------------------------------------

    #[cfg(unix)]
    #[test]
    fn test_is_executable_true() {
        let dir = make_temp_dir("is_exec_true");
        let file = dir.join("exec_file");
        fs::write(&file, "#!/bin/sh\n").unwrap();

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(is_executable(&file));

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn test_is_executable_false() {
        let dir = make_temp_dir("is_exec_false");
        let file = dir.join("noexec_file");
        fs::write(&file, "data\n").unwrap();

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(!is_executable(&file));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_is_executable_nonexistent() {
        assert!(!is_executable(Path::new("/nonexistent/file")));
    }
}
