use std::path::{Path, PathBuf};

use crate::container::guest_layout::{self, GuestLayout};
use crate::error::{ContainerError, McpWritError};
use crate::execution::TargetArch;

/// Architecture spellings the runner lookup accepts, in search order —
/// the OCI-style tag is the released name, the Rust spelling the alias.
fn arch_aliases(arch: &TargetArch) -> Vec<String> {
    match arch {
        TargetArch::X86_64 => vec!["amd64".to_string(), "x86_64".to_string()],
        TargetArch::Aarch64 => vec!["arm64".to_string(), "aarch64".to_string()],
        TargetArch::Other(name) => vec![name.clone()],
    }
}

/// Candidate runner filenames for a guest layout/arch pair — the
/// released dist name first, then alias spellings. Empty when the pair
/// is one we do not name a runner for at all.
fn runner_candidate_names(layout: &GuestLayout, arch: &TargetArch) -> Vec<String> {
    arch_aliases(arch)
        .iter()
        .map(|a| format!("{}-{a}{}", layout.runner_stem, layout.exe_suffix))
        .collect()
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

/// Resolve the path to the mcp-secure-runner binary for a guest.
///
/// The runner executes *inside* the guest, so the lookup key is the
/// image's declared guest OS/arch — not the CLI host's: a Windows image
/// needs `mcp-secure-runner-windows-<arch>.exe` regardless of what OS
/// the build itself runs on.
///
/// Priority:
/// 1. If `explicit_path` is `Some`, use that path (with existence + executable checks).
/// 2. If `MCP_SECURE_RUNNER_PATH` environment variable is set, use that path.
/// 3. Otherwise, look for `runners/mcp-secure-runner-<os>-<arch>[.exe]` next to the
///    current mcp-writ binary (accepting both amd64/x86_64 spellings).
/// 4. If not found, return an error with download instructions.
pub fn resolve_runner_binary(
    explicit_path: Option<&Path>,
    layout: &GuestLayout,
    arch: &TargetArch,
) -> Result<PathBuf, McpWritError> {
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

    let candidate_names = runner_candidate_names(layout, arch);
    let Some(primary_name) = candidate_names.first() else {
        return Err(ContainerError::RunnerResolve(format!(
            "no runner is shipped for a {} guest on architecture '{}' — \
             provide a suitable binary with --runner-binary",
            layout.guest_os.name(),
            arch.name(),
        ))
        .into());
    };

    // Auto-detect: look next to the current binary only.
    let current_exe = std::env::current_exe().map_err(|e| {
        ContainerError::RunnerResolve(format!("failed to determine current executable path: {e}"))
    })?;

    let exe_dir = current_exe.parent().ok_or_else(|| {
        ContainerError::RunnerResolve("current executable has no parent directory".to_string())
    })?;

    let candidate_dirs = [exe_dir.join("runners")];

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

    let default_runner_path = exe_dir.join("runners").join(primary_name);
    // Not found - provide helpful error message
    Err(ContainerError::RunnerResolve(format!(
        "mcp-secure-runner binary for a {} guest ({}) not found.\n\
         Searched: {}\n\
         \n\
         To obtain it:\n\
         1. Download from GitHub Releases: https://github.com/strumbyte/mcp-writ/releases\n\
         2. Place the binary at: {}\n\
         3. Or specify explicitly: mcp-writ wrap-image --runner-binary /path/to/runner <image>\n\
         4. Or set MCP_SECURE_RUNNER_PATH environment variable",
        layout.guest_os.name(),
        arch.name(),
        default_runner_path.display(),
        default_runner_path.display(),
    ))
    .into())
}

/// Build the expected runner binary path for a given exe directory (for testing/display).
///
/// Returns the released dist name (`{stem}-{arch-tag}{ext}`); an
/// unshipped guest/arch pair is an error rather than a fabricated path.
pub fn expected_runner_path(
    exe_dir: &Path,
    layout: &GuestLayout,
    arch: &TargetArch,
) -> Result<PathBuf, ContainerError> {
    let name = guest_layout::runner_dist_name(layout, arch).ok_or_else(|| {
        ContainerError::RunnerResolve(format!(
            "no runner is shipped for a {} guest on architecture '{}'",
            layout.guest_os.name(),
            arch.name(),
        ))
    })?;
    Ok(exe_dir.join("runners").join(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::guest_layout::{LINUX, WINDOWS};
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

    fn host_arch() -> TargetArch {
        TargetArch::host()
    }

    // -- runner_candidate_names ------------------------------------------------

    #[test]
    fn candidate_names_linux() {
        let names = runner_candidate_names(&LINUX, &TargetArch::X86_64);
        assert_eq!(
            names,
            vec![
                "mcp-secure-runner-linux-amd64".to_string(),
                "mcp-secure-runner-linux-x86_64".to_string()
            ]
        );
        let arm = runner_candidate_names(&LINUX, &TargetArch::Aarch64);
        assert_eq!(
            arm,
            vec![
                "mcp-secure-runner-linux-arm64".to_string(),
                "mcp-secure-runner-linux-aarch64".to_string()
            ]
        );
    }

    #[test]
    fn candidate_names_windows_carry_exe() {
        let names = runner_candidate_names(&WINDOWS, &TargetArch::X86_64);
        assert_eq!(
            names,
            vec![
                "mcp-secure-runner-windows-amd64.exe".to_string(),
                "mcp-secure-runner-windows-x86_64.exe".to_string()
            ]
        );
    }

    #[test]
    fn candidate_names_other_arch_passthrough() {
        let names = runner_candidate_names(&LINUX, &TargetArch::Other("riscv64".to_string()));
        assert_eq!(names, vec!["mcp-secure-runner-linux-riscv64".to_string()]);
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

        let result = resolve_runner_binary(Some(&runner), &LINUX, &host_arch());
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
        assert_eq!(result.unwrap(), runner);

        let _ = fs::remove_dir_all(&dir);
    }

    // -- explicit path: not found ---------------------------------------------

    #[test]
    fn test_explicit_path_not_found() {
        let path = Path::new("/nonexistent/path/to/runner");
        let result = resolve_runner_binary(Some(path), &LINUX, &host_arch());
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

        let result = resolve_runner_binary(Some(&runner), &LINUX, &host_arch());
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
        let runners_dir = dir.join("runners");
        fs::create_dir_all(&runners_dir).unwrap();

        let runner_path = expected_runner_path(&dir, &LINUX, &host_arch())
            .expect("expected_runner_path should succeed on supported arch");
        fs::write(&runner_path, "#!/bin/sh\n").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&runner_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let name = runner_path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("mcp-secure-runner-linux-"), "got {name}");

        let _ = fs::remove_dir_all(&dir);
    }

    // -- auto-detect: not found → descriptive error ---------------------------

    #[test]
    fn test_auto_detect_not_found_error() {
        // When no explicit path is given and current_exe() is used,
        // the runner directory next to the test binary won't have it.
        let result = resolve_runner_binary(None, &LINUX, &host_arch());
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
        assert!(
            err.contains("linux"),
            "error names the guest OS it searched for: {err}"
        );
    }

    #[test]
    fn test_auto_detect_windows_names_windows_runner() {
        // The search must name the windows artifact — never a linux one —
        // when the guest is windows, even on a linux test host.
        let result = resolve_runner_binary(None, &WINDOWS, &TargetArch::X86_64);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("windows"),
            "error names the windows guest: {err}"
        );
        assert!(
            err.contains("mcp-secure-runner-windows-amd64.exe"),
            "error names the searched filename: {err}"
        );
        assert!(!err.contains("mcp-secure-runner-linux"), "got: {err}");
    }

    // -- expected_runner_path -------------------------------------------------

    #[test]
    fn test_expected_runner_path_format() {
        let dir = Path::new("/usr/local/bin");
        let path = expected_runner_path(dir, &LINUX, &TargetArch::X86_64)
            .expect("amd64 linux runner is shipped");
        assert_eq!(
            path,
            PathBuf::from("/usr/local/bin/runners/mcp-secure-runner-linux-amd64")
        );
    }

    #[test]
    fn test_expected_runner_path_windows() {
        let dir = Path::new("C:/Tools");
        let path = expected_runner_path(dir, &WINDOWS, &TargetArch::X86_64)
            .expect("amd64 windows runner is shipped");
        assert!(path.ends_with("runners/mcp-secure-runner-windows-amd64.exe"));
    }

    #[test]
    fn test_expected_runner_path_unshipped_pair() {
        let dir = Path::new("/usr/local/bin");
        assert!(
            expected_runner_path(dir, &WINDOWS, &TargetArch::Aarch64).is_err(),
            "windows/arm64 is not shipped"
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
