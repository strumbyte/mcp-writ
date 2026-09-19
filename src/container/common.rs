use std::path::{Path, PathBuf};

use crate::container::engine::{ContainerEngine, EngineKind, resolve_engine};
use crate::container::runner_resolve::resolve_runner_binary;
use crate::error::{ContainerError, McpWritError};

/// Result of copying a path into a build context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOutcome {
    /// The file or directory was copied.
    Copied,
    /// The path was a symlink and was not copied.
    SkippedSymlink,
}

/// Resolved build prerequisites shared by wrap-image and containerize.
pub struct BuildPrereqs {
    /// Path to the mcp-secure-runner binary on the host.
    pub runner_path: PathBuf,
    /// Name of the container engine CLI (e.g. "docker", "podman", "buildah").
    pub engine_name: String,
    /// Container engine trait object.
    pub engine: Box<dyn ContainerEngine>,
}

/// Resolve runner binary and container engine.
pub fn resolve_prereqs(
    runner_binary: Option<&Path>,
    engine_kind: Option<EngineKind>,
) -> Result<BuildPrereqs, McpWritError> {
    let runner_path = resolve_runner_binary(runner_binary)?;
    assert_static_runner(&runner_path)?;
    let engine = resolve_engine(engine_kind).map_err(|e| {
        ContainerError::BuildFailed(format!("failed to resolve container engine: {e}"))
    })?;
    let engine_name = engine.name().to_string();
    Ok(BuildPrereqs {
        runner_path,
        engine_name,
        engine,
    })
}

/// Fail closed when the runner is a dynamically linked ELF.
fn assert_static_runner(path: &Path) -> Result<(), McpWritError> {
    let data = std::fs::read(path).map_err(|e| {
        ContainerError::BuildFailed(format!(
            "failed to read runner binary '{}': {e}",
            path.display()
        ))
    })?;
    match goblin::elf::Elf::parse(&data) {
        Ok(elf) => {
            if elf.interpreter.is_some() {
                return Err(ContainerError::BuildFailed(format!(
                    "mcp-secure-runner '{}' must be a statically linked ELF (dynamic interpreter present)",
                    path.display()
                ))
                .into());
            }
            Ok(())
        }
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "runner is not an ELF; skipping static-link check"
            );
            Ok(())
        }
    }
}

/// Validate that a policy file exists on disk.
pub fn validate_policy_path(
    policy: Option<&Path>,
    default_name: &str,
) -> Result<PathBuf, ContainerError> {
    let policy_path = match policy {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(default_name),
    };
    if !policy_path.exists() {
        return Err(ContainerError::BuildFailed(format!(
            "policy file not found: {}\n\
             Specify a policy file with --policy <path> or create {} in the current directory",
            policy_path.display(),
            default_name,
        )));
    }
    Ok(policy_path)
}

/// A temporary build context directory that cleans up on drop.
pub struct BuildContext {
    dir: PathBuf,
}

impl BuildContext {
    /// Create a new temporary build context directory.
    pub fn new(label: &str) -> Result<Self, ContainerError> {
        let dir = crate::fspriv::create_private_tempdir(label).map_err(|e| {
            ContainerError::BuildFailed(format!("failed to create build context dir: {e}"))
        })?;
        Ok(Self { dir })
    }

    /// The path to the build context directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Copy the runner binary into the build context.
    pub fn copy_runner(&self, runner_path: &Path) -> Result<(), ContainerError> {
        let dst = self.dir.join("mcp-secure-runner");
        std::fs::copy(runner_path, &dst).map_err(|e| {
            ContainerError::BuildFailed(format!(
                "failed to copy runner binary to build context: {e}"
            ))
        })?;
        Ok(())
    }

    /// Export a self-contained effective policy into the build context as `policy.kdl`.
    pub fn copy_policy(&self, policy_path: &Path) -> Result<(), ContainerError> {
        self.copy_policy_for_server(policy_path, None)
    }

    /// Bind the policy to `server` before inlining it into the image.
    pub fn copy_policy_for_server(
        &self,
        policy_path: &Path,
        server: Option<&str>,
    ) -> Result<(), ContainerError> {
        let self_contained_kdl =
            crate::container::policy_export::export_self_contained_kdl(policy_path, server)
                .map_err(|e| ContainerError::BuildFailed(e.to_string()))?;
        let dst = self.dir.join("policy.kdl");
        std::fs::write(&dst, self_contained_kdl).map_err(|e| {
            ContainerError::BuildFailed(format!(
                "failed to write self-contained policy file to build context: {e}"
            ))
        })?;
        Ok(())
    }

    /// Copy an arbitrary file or directory into the build context.
    /// Symlinks are safely skipped to avoid leaking out-of-tree files.
    pub fn copy_file(&self, src: &Path, name: &str) -> Result<CopyOutcome, ContainerError> {
        let meta = std::fs::symlink_metadata(src).map_err(|e| {
            ContainerError::BuildFailed(format!(
                "failed to read metadata for '{}': {e}",
                src.display()
            ))
        })?;

        if meta.file_type().is_symlink() {
            tracing::warn!(
                "Skipping symlink '{}' to prevent path traversal into build context",
                src.display()
            );
            return Ok(CopyOutcome::SkippedSymlink);
        }

        let dst = self.dir.join(name);
        if meta.is_dir() {
            copy_dir_recursive(src, &dst)?;
        } else {
            std::fs::copy(src, &dst).map_err(|e| {
                ContainerError::BuildFailed(format!(
                    "failed to copy '{}' to build context: {e}",
                    src.display()
                ))
            })?;
        }
        Ok(CopyOutcome::Copied)
    }

    /// Write the Dockerfile content into the build context.
    pub fn write_dockerfile(&self, content: &str) -> Result<PathBuf, ContainerError> {
        let path = self.dir.join("Dockerfile");
        std::fs::write(&path, content)
            .map_err(|e| ContainerError::BuildFailed(format!("failed to write Dockerfile: {e}")))?;
        Ok(path)
    }

    /// Clean up the build context directory eagerly.
    ///
    /// This is optional — `Drop` will clean up automatically — but allows
    /// callers to reclaim disk space before continuing.
    pub fn cleanup(self) {
        // Drop impl handles the actual removal.
        drop(self);
    }
}

impl Drop for BuildContext {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Recursively copy a directory tree.
///
/// Symlinks are skipped to prevent:
/// - Infinite loops from circular symlinks
/// - Path traversal attacks via symlinks pointing outside the source tree
/// - Errors from broken (dangling) symlinks
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ContainerError> {
    std::fs::create_dir_all(dst).map_err(|e| {
        ContainerError::BuildFailed(format!(
            "failed to create directory '{}': {e}",
            dst.display()
        ))
    })?;

    let entries = std::fs::read_dir(src).map_err(|e| {
        ContainerError::BuildFailed(format!("failed to read directory '{}': {e}", src.display()))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            ContainerError::BuildFailed(format!("failed to read directory entry: {e}"))
        })?;

        // Skip symlinks to avoid circular links, traversal, and broken links
        let ft = entry.file_type().map_err(|e| {
            ContainerError::BuildFailed(format!(
                "failed to get file type for '{}': {e}",
                entry.path().display()
            ))
        })?;
        if ft.is_symlink() {
            continue;
        }

        let src_path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if crate::fspriv::should_skip_build_entry(&name_str) {
            continue;
        }
        let dst_path = dst.join(name);
        if ft.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path).map_err(|e| {
                ContainerError::BuildFailed(format!("failed to copy '{}': {e}", src_path.display()))
            })?;
        }
    }
    Ok(())
}

/// Returns the appropriate build subcommand for the given container engine.
/// - "buildah" -> "bud"
/// - "docker" / "podman" / others -> "build"
pub fn get_build_subcommand(engine_name: &str) -> &'static str {
    if engine_name == "buildah" {
        "bud"
    } else {
        "build"
    }
}

/// Build a container image using the specified engine, with optional `--no-cache`.
pub async fn build_image(
    engine_name: &str,
    dockerfile_path: &Path,
    tag: &str,
    context_dir: &Path,
    no_cache: bool,
) -> Result<(), ContainerError> {
    let build_subcmd = get_build_subcommand(engine_name);

    let mut cmd_args = vec![
        build_subcmd.to_string(),
        "-f".to_string(),
        dockerfile_path.display().to_string(),
        "-t".to_string(),
        tag.to_string(),
    ];

    if no_cache {
        cmd_args.push("--no-cache".to_string());
    }

    cmd_args.push(context_dir.display().to_string());

    let output = tokio::process::Command::new(engine_name)
        .args(&cmd_args)
        .output()
        .await
        .map_err(|e| {
            ContainerError::BuildFailed(format!(
                "failed to run '{engine_name} {build_subcmd}': {e}"
            ))
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ContainerError::BuildFailed(format!(
            "{stderr}\n\nTip: try '{engine_name} image prune' to free up disk space"
        )));
    }

    Ok(())
}

/// Write a Dockerfile to disk (for --output-dockerfile mode).
pub fn write_dockerfile_to_path(output_path: &Path, content: &str) -> Result<(), ContainerError> {
    std::fs::write(output_path, content).map_err(|e| {
        ContainerError::DockerfileGeneration(format!(
            "failed to write Dockerfile to '{}': {e}",
            output_path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_temp_dir(label: &str) -> PathBuf {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mcp_writ_common_test_{label}_{id}_{ts}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -- BuildContext ----------------------------------------------------------

    #[test]
    fn test_build_context_creates_dir() {
        let ctx = BuildContext::new("test_create").unwrap();
        assert!(ctx.dir().exists());
        ctx.cleanup();
    }

    #[test]
    fn test_build_context_write_dockerfile() {
        let ctx = BuildContext::new("test_df").unwrap();
        let content = "FROM alpine:3.19\nRUN echo hello\n";
        let path = ctx.write_dockerfile(content).unwrap();
        assert!(path.exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), content);
        ctx.cleanup();
    }

    #[test]
    fn test_build_context_copy_runner() {
        let tmp = make_temp_dir("copy_runner");
        let runner = tmp.join("fake-runner");
        fs::write(&runner, "binary data").unwrap();

        let ctx = BuildContext::new("test_cp_runner").unwrap();
        ctx.copy_runner(&runner).unwrap();
        assert!(ctx.dir().join("mcp-secure-runner").exists());

        ctx.cleanup();
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_build_context_copy_policy() {
        let tmp = make_temp_dir("copy_policy");
        let policy = tmp.join("test.kdl");
        fs::write(&policy, "policy version=1").unwrap();

        let ctx = BuildContext::new("test_cp_policy").unwrap();
        ctx.copy_policy(&policy).unwrap();
        assert!(ctx.dir().join("policy.kdl").exists());

        ctx.cleanup();
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_build_context_copy_file() {
        let tmp = make_temp_dir("copy_file");
        let src_file = tmp.join("app.js");
        fs::write(&src_file, "console.log('hello')").unwrap();

        let ctx = BuildContext::new("test_cp_file").unwrap();
        assert_eq!(
            ctx.copy_file(&src_file, "app.js").unwrap(),
            CopyOutcome::Copied
        );
        assert!(ctx.dir().join("app.js").exists());

        ctx.cleanup();
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_build_context_copy_dir() {
        let tmp = make_temp_dir("copy_dir");
        let src_dir = tmp.join("src");
        fs::create_dir_all(src_dir.join("sub")).unwrap();
        fs::write(src_dir.join("main.py"), "print('hi')").unwrap();
        fs::write(src_dir.join("sub/helper.py"), "pass").unwrap();

        let ctx = BuildContext::new("test_cp_dir").unwrap();
        assert_eq!(ctx.copy_file(&src_dir, "src").unwrap(), CopyOutcome::Copied);
        assert!(ctx.dir().join("src/main.py").exists());
        assert!(ctx.dir().join("src/sub/helper.py").exists());

        ctx.cleanup();
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_build_context_cleanup_removes_dir() {
        let ctx = BuildContext::new("test_cleanup").unwrap();
        let dir = ctx.dir().to_path_buf();
        assert!(dir.exists());
        ctx.cleanup();
        assert!(!dir.exists());
    }

    // -- assert_static_runner --------------------------------------------------

    // Minimal ELF64 (little-endian, x86-64) that goblin::elf::Elf::parse accepts.
    // With `interp`, one PT_INTERP program header is appended at e_phoff = 64,
    // which is how a dynamically linked ELF declares its interpreter.
    fn elf64_bytes(interp: Option<&[u8]>) -> Vec<u8> {
        let mut buf = Vec::new();
        // e_ident: magic, ELFCLASS64, ELFDATA2LSB, EV_CURRENT, ELFOSABI_NONE
        buf.extend_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0]);
        buf.extend_from_slice(&[0u8; 8]);
        // e_type: ET_EXEC, e_machine: EM_X86_64, e_version: EV_CURRENT
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&62u16.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes());
        // e_entry
        buf.extend_from_slice(&0u64.to_le_bytes());
        // e_phoff: program headers follow the 64-byte header when present
        buf.extend_from_slice(&(if interp.is_some() { 64u64 } else { 0 }).to_le_bytes());
        // e_shoff: no section headers
        buf.extend_from_slice(&0u64.to_le_bytes());
        // e_flags, e_ehsize, e_phentsize, e_phnum
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&64u16.to_le_bytes());
        buf.extend_from_slice(&56u16.to_le_bytes());
        buf.extend_from_slice(&(if interp.is_some() { 1u16 } else { 0 }).to_le_bytes());
        // e_shentsize, e_shnum, e_shstrndx
        buf.extend_from_slice(&64u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());

        if let Some(interp) = interp {
            // One PT_INTERP program header pointing at the interpreter path.
            let interp_offset = 64u64 + 56;
            buf.extend_from_slice(&3u32.to_le_bytes()); // p_type: PT_INTERP
            buf.extend_from_slice(&4u32.to_le_bytes()); // p_flags: R
            buf.extend_from_slice(&interp_offset.to_le_bytes()); // p_offset
            buf.extend_from_slice(&0u64.to_le_bytes()); // p_vaddr
            buf.extend_from_slice(&0u64.to_le_bytes()); // p_paddr
            buf.extend_from_slice(&(interp.len() as u64).to_le_bytes()); // p_filesz
            buf.extend_from_slice(&(interp.len() as u64).to_le_bytes()); // p_memsz
            buf.extend_from_slice(&1u64.to_le_bytes()); // p_align
            buf.extend_from_slice(interp);
        }
        buf
    }

    #[test]
    fn test_assert_static_runner_accepts_static_elf() {
        let tmp = make_temp_dir("static_runner_ok");
        let runner = tmp.join("runner");
        fs::write(&runner, elf64_bytes(None)).unwrap();

        assert!(assert_static_runner(&runner).is_ok());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_assert_static_runner_rejects_dynamic_elf() {
        let tmp = make_temp_dir("static_runner_dyn");
        let runner = tmp.join("runner");
        fs::write(&runner, elf64_bytes(Some(b"/lib64/ld-linux-x86-64.so.2\0"))).unwrap();

        let err = assert_static_runner(&runner).unwrap_err();
        assert!(err.to_string().contains("statically linked"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_assert_static_runner_warns_and_passes_non_elf() {
        let tmp = make_temp_dir("static_runner_nonelf");
        let runner = tmp.join("runner");
        fs::write(&runner, "#!/bin/sh\necho hi").unwrap();

        // Non-ELF input skips the check with a warning instead of failing,
        // so non-Linux runners keep working.
        assert!(assert_static_runner(&runner).is_ok());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_assert_static_runner_warns_and_passes_truncated_elf() {
        let tmp = make_temp_dir("static_runner_trunc");
        let runner = tmp.join("runner");
        fs::write(&runner, [0x7f, b'E', b'L', b'F', 2, 1]).unwrap();

        assert!(assert_static_runner(&runner).is_ok());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_assert_static_runner_missing_file_errors() {
        let err = assert_static_runner(Path::new("/nonexistent/mcp-secure-runner")).unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }

    // -- validate_policy_path -------------------------------------------------

    #[test]
    fn test_validate_policy_path_exists() {
        let tmp = make_temp_dir("validate_policy");
        let policy = tmp.join("policy.kdl");
        fs::write(&policy, "test").unwrap();

        let result = validate_policy_path(Some(&policy), "policy.kdl");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), policy);

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_validate_policy_path_not_found() {
        let result = validate_policy_path(Some(Path::new("/nonexistent/policy.kdl")), "policy.kdl");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found"));
    }

    // -- write_dockerfile_to_path ---------------------------------------------

    #[test]
    fn test_write_dockerfile_to_path() {
        let tmp = make_temp_dir("write_df_path");
        let out = tmp.join("Dockerfile");
        let result = write_dockerfile_to_path(&out, "FROM alpine\n");
        assert!(result.is_ok());
        assert_eq!(fs::read_to_string(&out).unwrap(), "FROM alpine\n");

        let _ = fs::remove_dir_all(&tmp);
    }

    // -- copy_dir_recursive: symlink handling ---------------------------------

    #[cfg(unix)]
    #[test]
    fn test_copy_dir_recursive_skips_symlinks() {
        let tmp = make_temp_dir("symlink_skip");
        let src = tmp.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("real.txt"), "real content").unwrap();

        // Create a symlink inside the source dir
        std::os::unix::fs::symlink("/etc/passwd", src.join("evil_link")).unwrap();

        let dst = tmp.join("dst");
        copy_dir_recursive(&src, &dst).unwrap();

        // Real file should be copied
        assert!(dst.join("real.txt").exists());
        // Symlink should be skipped
        assert!(!dst.join("evil_link").exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_dir_recursive_skips_circular_symlinks() {
        let tmp = make_temp_dir("circular_link");
        let src = tmp.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("file.txt"), "data").unwrap();

        // Create circular symlink: src/loop -> src
        std::os::unix::fs::symlink(&src, src.join("loop")).unwrap();

        let dst = tmp.join("dst");
        // Should succeed without infinite loop
        copy_dir_recursive(&src, &dst).unwrap();

        assert!(dst.join("file.txt").exists());
        assert!(!dst.join("loop").exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[cfg(unix)]
    #[test]
    fn test_copy_file_skips_symlink_at_root() {
        let tmp = make_temp_dir("copy_file_symlink");
        let ctx = BuildContext::new("copy_file_test").unwrap();
        let target_file = tmp.join("secret.txt");
        fs::write(&target_file, "secret").unwrap();

        let link_file = tmp.join("symlink_to_secret");
        std::os::unix::fs::symlink(&target_file, &link_file).unwrap();

        // Copy symlink directly via copy_file
        assert_eq!(
            ctx.copy_file(&link_file, "copied_link").unwrap(),
            CopyOutcome::SkippedSymlink
        );

        // Copied link should not exist in build context!
        assert!(!ctx.dir().join("copied_link").exists());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_copy_policy_exports_self_contained_kdl() {
        let tmp = make_temp_dir("copy_policy_self_contained");
        let parent_kdl = tmp.join("parent.kdl");
        fs::write(
            &parent_kdl,
            r#"policy version=1
defaults {
    filesystem {
        allow "/base/path" mode="read"
    }
}
server "test" {
    tool "parent_tool"
}
"#,
        )
        .unwrap();

        let schema_file = tmp.join("schema.json");
        fs::write(&schema_file, r#"{"type":"object"}"#).unwrap();

        let child_kdl = tmp.join("child.kdl");
        fs::write(
            &child_kdl,
            r#"policy version=1
extends "parent.kdl"
server "test" {
    tool "child_tool" args_schema="@schema.json"
}
"#,
        )
        .unwrap();

        let ctx = BuildContext::new("self_contained_test").unwrap();
        ctx.copy_policy(&child_kdl).unwrap();

        let generated_policy_file = ctx.dir().join("policy.kdl");
        assert!(generated_policy_file.exists());
        let content = fs::read_to_string(&generated_policy_file).unwrap();

        // Must not contain extends
        assert!(!content.contains("extends"));
        // Must contain parent_tool and child_tool
        assert!(content.contains("parent_tool"));
        assert!(content.contains("child_tool"));
        // Must contain inlined schema instead of @schema.json
        assert!(!content.contains("@schema.json"));
        assert!(content.contains(r#"{\"type\":\"object\"}"#));

        // It must be parseable by load_policy without parent.kdl or schema.json
        let loaded = crate::policy::loader::load_policy(&generated_policy_file).unwrap();
        assert_eq!(loaded.tools.len(), 2);
        assert_eq!(loaded.fs.read_only, vec!["/base/path"]);

        let _ = fs::remove_dir_all(&tmp);
    }
}
