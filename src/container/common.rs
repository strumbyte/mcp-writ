use std::path::{Path, PathBuf};

use crate::container::engine::{ContainerEngine, EngineKind, resolve_engine};
use crate::container::guest_layout::GuestLayout;
use crate::container::runner_resolve::resolve_runner_binary;
use crate::error::{ContainerError, McpWritError};
use crate::execution::{TargetArch, TargetOs};

/// Result of copying a path into a build context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOutcome {
    /// The file or directory was copied.
    Copied,
    /// The path was a symlink and was not copied.
    SkippedSymlink,
}

/// What the runner binary's executable format is — the guest OS it can
/// serve follows from the bytes, not the filename it was found under.
#[derive(Debug)]
pub enum RunnerFormat {
    /// A statically-linked ELF — the Linux guest contract. Dynamic
    /// ELFs are refused inside `analyze_runner_binary`, so reaching
    /// this variant means the static check already passed.
    Elf {
        /// The ELF header's machine architecture.
        arch: TargetArch,
    },
    /// A PE image — the Windows guest contract — plus the MSVC
    /// redistributable DLL names its import table depends on (the set
    /// the image must ship app-local; empty for crt-static/MinGW
    /// builds).
    Pe {
        /// The COFF header's machine architecture.
        arch: TargetArch,
        /// MSVC redist DLLs the image must carry next to the exe.
        redist_dlls: Vec<String>,
    },
    /// Neither ELF nor PE — the capability-marker scan still ran, but
    /// no guest OS can be proven from the bytes.
    Unknown,
}

/// Result of inspecting a runner binary on disk.
#[derive(Debug)]
pub struct RunnerAnalysis {
    /// The executable format the guest must match.
    pub format: RunnerFormat,
    /// Capability marker scanned from the binary. `None` means a
    /// pre-report-channel runner — recorded on the image env so
    /// `run-image` can tell a legacy build from a capable one instead
    /// of assuming either.
    pub caps: Option<crate::container::guest_report::RunnerCaps>,
}

/// Resolve the container engine for a build flow.
pub fn resolve_engine_for_build(
    engine_kind: Option<EngineKind>,
) -> Result<(String, Box<dyn ContainerEngine>), McpWritError> {
    let engine = resolve_engine(engine_kind).map_err(|e| {
        ContainerError::BuildFailed(format!("failed to resolve container engine: {e}"))
    })?;
    let engine_name = engine.name().to_string();
    Ok((engine_name, engine))
}

/// Resolve a runner binary for `layout`'s guest and check that what was
/// found can actually execute there: a Linux guest needs a static ELF,
/// a Windows guest a PE — a cross-format pick (or an arch mismatch
/// between the runner and the image) fails the build instead of
/// producing an image that dies in `execve`/`CreateProcess` at launch.
pub fn resolve_runner_checked(
    runner_binary: Option<&Path>,
    layout: &GuestLayout,
    guest_arch: &TargetArch,
) -> Result<(PathBuf, RunnerAnalysis), McpWritError> {
    let path = resolve_runner_binary(runner_binary, layout, guest_arch)?;
    let analysis = analyze_runner_binary(&path)?;
    check_runner_for_guest(&path, &analysis, layout, guest_arch)?;
    Ok((path, analysis))
}

/// The runner's format must match the guest it will serve. `Unknown`
/// format is not refused (the marker may still be embedded and the image
/// built) but is warned loudly — the launch path re-checks the runner
/// entrypoint either way.
fn check_runner_for_guest(
    path: &Path,
    analysis: &RunnerAnalysis,
    layout: &GuestLayout,
    guest_arch: &TargetArch,
) -> Result<(), McpWritError> {
    let runner_arch = match (&analysis.format, layout.guest_os) {
        (RunnerFormat::Elf { arch }, TargetOs::Linux) => arch,
        (RunnerFormat::Pe { arch, .. }, TargetOs::Windows) => arch,
        (RunnerFormat::Elf { .. }, other) => {
            return Err(ContainerError::BuildFailed(format!(
                "runner '{}' is an ELF but the image's guest OS is {} — \
                 that guest needs a {} runner; copy the right \
                 artifact or pass --runner-binary",
                path.display(),
                other.name(),
                other.name(),
            ))
            .into());
        }
        (RunnerFormat::Pe { .. }, other) => {
            return Err(ContainerError::BuildFailed(format!(
                "runner '{}' is a Windows PE but the image's guest OS is {} — \
                 that guest needs a {} runner; copy the right \
                 artifact or pass --runner-binary",
                path.display(),
                other.name(),
                other.name(),
            ))
            .into());
        }
        (RunnerFormat::Unknown, os) => {
            tracing::warn!(
                path = %path.display(),
                guest_os = %os.name(),
                "runner binary format unrecognized; cannot verify it \
                 matches the guest — the image may fail to launch"
            );
            return Ok(());
        }
    };
    // Known-vs-known arch mismatches are an exec failure waiting to
    // happen — refuse. An `Other` on either side warns but does not
    // block (e.g. an i386 PE is still loadable under amd64 WOW64).
    if !matches!(runner_arch, TargetArch::Other(_))
        && !matches!(guest_arch, TargetArch::Other(_))
        && runner_arch != guest_arch
    {
        return Err(ContainerError::BuildFailed(format!(
            "runner '{}' targets {} but the image's guest architecture is \
             {} — build or fetch a runner for the image arch",
            path.display(),
            runner_arch.name(),
            guest_arch.name(),
        ))
        .into());
    }
    if runner_arch != guest_arch {
        tracing::warn!(
            path = %path.display(),
            runner_arch = %runner_arch.name(),
            guest_arch = %guest_arch.name(),
            "runner/image architecture could not be fully matched \
             (unverified combination)"
        );
    }
    Ok(())
}

/// Read the runner binary once: fail closed on a dynamically linked
/// ELF, parse a PE for arch + redist imports, and scan for the
/// `MCP_WRIT_RUNNER_CAPS` capability marker. A missing marker is a
/// legacy runner, not an error.
pub fn analyze_runner_binary(path: &Path) -> Result<RunnerAnalysis, McpWritError> {
    let data = read_runner_binary(path)?;
    let caps = crate::container::guest_report::scan_runner_caps(&data);
    let format = if crate::container::elf_magic::looks_like_elf(path) {
        match goblin::elf::Elf::parse(&data) {
            Ok(elf) => {
                if elf.interpreter.is_some() {
                    return Err(ContainerError::BuildFailed(format!(
                        "mcp-secure-runner '{}' must be a statically linked ELF \
                         (dynamic interpreter present)",
                        path.display()
                    ))
                    .into());
                }
                RunnerFormat::Elf {
                    arch: elf_arch(elf.header.e_machine),
                }
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "runner has ELF magic but does not parse; format stays unknown"
                );
                RunnerFormat::Unknown
            }
        }
    } else if crate::container::pe_magic::looks_like_pe(path) {
        match goblin::pe::PE::parse(&data) {
            Ok(pe) => {
                let machine = pe.header.coff_header.machine;
                RunnerFormat::Pe {
                    arch: crate::container::pe_magic::pe_arch(&data).unwrap_or_else(|| {
                        TargetArch::Other(format!("pe-machine-0x{machine:04x}"))
                    }),
                    redist_dlls: crate::container::pe_magic::required_redist_dlls(&data)
                        .unwrap_or_default(),
                }
            }
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "runner has MZ magic but is not a parseable PE; format stays unknown"
                );
                RunnerFormat::Unknown
            }
        }
    } else {
        tracing::warn!(
            path = %path.display(),
            "runner is neither ELF nor PE; format stays unknown"
        );
        RunnerFormat::Unknown
    };
    Ok(RunnerAnalysis { format, caps })
}

/// ELF machine field → [`TargetArch`]; an unlisted machine keeps its
/// number so the record names what was actually found.
fn elf_arch(machine: u16) -> TargetArch {
    match machine {
        goblin::elf::header::EM_X86_64 => TargetArch::X86_64,
        goblin::elf::header::EM_AARCH64 => TargetArch::Aarch64,
        other => TargetArch::Other(format!("elf-machine-{other}")),
    }
}

fn read_runner_binary(path: &Path) -> Result<Vec<u8>, McpWritError> {
    std::fs::read(path).map_err(|e| {
        ContainerError::BuildFailed(format!(
            "failed to read runner binary '{}': {e}",
            path.display()
        ))
        .into()
    })
}

/// Decide which MSVC CRT DLLs (if any) a Windows-guest build must ship
/// app-local, and where each comes from. Returns the host paths to copy
/// into the build context — the generated Dockerfile `COPY`s each next
/// to the runner exe.
///
/// Resolution order per required DLL name:
/// 1. `explicit` paths given on the command line (`--crt-dll`, matched
///    by file name),
/// 2. `runners/crt/<name>` next to the current executable — the packaged
///    location a release artifact can carry,
/// 3. the host's `System32` copy (a Windows host that already runs the
///    MSVC-built runner has it).
///
/// A PE that needs a DLL none of these can supply fails the build —
/// shipping the image would produce a guest that dies in loader lock
/// (`STATUS_DLL_NOT_FOUND` on Server Core). Non-Windows guests and PEs
/// with no redist imports return empty.
pub fn stage_crt_dlls(
    layout: &GuestLayout,
    analysis: &RunnerAnalysis,
    explicit: &[PathBuf],
) -> Result<Vec<PathBuf>, ContainerError> {
    if layout.guest_os != TargetOs::Windows {
        if !explicit.is_empty() {
            return Err(ContainerError::BuildFailed(format!(
                "--crt-dll only applies to windows-guest images; this image's \
                 guest OS is '{}' — remove the option",
                layout.guest_os.name()
            )));
        }
        return Ok(Vec::new());
    }
    let needed = match &analysis.format {
        RunnerFormat::Pe { redist_dlls, .. } => redist_dlls.clone(),
        // An unrecognized runner format cannot be checked — warn rather
        // than assume it is self-contained.
        _ => {
            tracing::warn!(
                "runner format unverified for the windows guest; \
                 if it imports the MSVC CRT the image needs --crt-dll"
            );
            Vec::new()
        }
    };
    if needed.is_empty() {
        return Ok(Vec::new());
    }
    let mut staged: Vec<PathBuf> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for dll in &needed {
        if let Some(found) = find_crt_dll(dll, explicit) {
            staged.push(found);
        } else {
            missing.push(dll.clone());
        }
    }
    if !missing.is_empty() {
        return Err(ContainerError::BuildFailed(format!(
            "the windows runner imports {} but no copy is available — \
             provide each with --crt-dll <path>, or place them at \
             runners/crt/ next to the mcp-writ binary",
            missing.join(", "),
        )));
    }
    Ok(staged)
}

/// Locate one redistributable DLL by name: `explicit` first, then the
/// packaged `runners/crt/` drop, then the host's `System32`.
fn find_crt_dll(name: &str, explicit: &[PathBuf]) -> Option<PathBuf> {
    for p in explicit {
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
            && p.is_file()
        {
            return Some(p.clone());
        }
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let p = dir.join("runners").join("crt").join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    if cfg!(windows) {
        let p = Path::new(r"C:\Windows\System32").join(name);
        if p.is_file() {
            return Some(p);
        }
    }
    None
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

    /// Copy the runner binary into the build context under the name the
    /// guest layout's Dockerfile COPY instruction sources it as
    /// (`mcp-secure-runner` on Linux, `mcp-secure-runner.exe` on
    /// Windows — the generated Dockerfile and this name must agree).
    pub fn copy_runner(
        &self,
        runner_path: &Path,
        context_name: &str,
    ) -> Result<(), ContainerError> {
        let dst = self.dir.join(context_name);
        std::fs::copy(runner_path, &dst).map_err(|e| {
            ContainerError::BuildFailed(format!(
                "failed to copy runner binary to build context: {e}"
            ))
        })?;
        Ok(())
    }

    /// Export a self-contained effective policy into the build context as `policy.kdl`.
    ///
    /// `target` is the guest execution target the embedded policy is
    /// validated against (e.g. [`crate::execution::ExecutionTarget::linux_container`]);
    /// host-side file checks still apply to `policy_path` itself.
    pub fn copy_policy(
        &self,
        policy_path: &Path,
        target: &crate::execution::ExecutionTarget,
    ) -> Result<(), ContainerError> {
        self.copy_policy_for_server(policy_path, None, target)
    }

    /// Bind the policy to `server` before inlining it into the image.
    pub fn copy_policy_for_server(
        &self,
        policy_path: &Path,
        server: Option<&str>,
        target: &crate::execution::ExecutionTarget,
    ) -> Result<(), ContainerError> {
        let self_contained_kdl =
            crate::container::policy_export::export_self_contained_kdl(policy_path, server, target)
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

/// Build a container image using the resolved engine, with optional `--no-cache`.
///
/// The build spawns `engine.program()` — a resolved full path when the
/// CLI is not on PATH (wslc.exe lives in the WSL install dir) — while
/// error text names `engine.name()`. For wslc the produced image is the
/// success fact, verified by `image inspect`: the wslc CLI can print a
/// build error and still exit 0.
pub async fn build_image(
    engine: &dyn ContainerEngine,
    dockerfile_path: &Path,
    tag: &str,
    context_dir: &Path,
    no_cache: bool,
) -> Result<(), ContainerError> {
    let engine_name = engine.name();
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

    let output = tokio::process::Command::new(engine.program())
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

    if engine_name == "wslc" {
        // A wslc build failure can exit 0 — the produced image is the
        // success fact, verified by inspect rather than the status.
        engine.inspect(tag).await.map_err(|e| {
            ContainerError::BuildFailed(format!(
                "wslc build exited 0 but image '{tag}' did not materialize \
                 — treated as a failed build ({e})\n\nTip: try '{engine_name} \
                 image prune' to free up disk space"
            ))
        })?;
    }

    Ok(())
}

/// The wslc session VM runs Linux guests on the host's architecture —
/// a non-Linux guest contract has no wslc build path, so the build
/// flows refuse it at entry rather than producing an image that can
/// never launch under the same engine (a Windows guest's contract is
/// the docker/hyperv path, not wslc).
pub fn refuse_wslc_non_linux_guest(
    engine_name: &str,
    layout: &GuestLayout,
) -> Result<(), ContainerError> {
    if engine_name == "wslc" && layout.guest_os != TargetOs::Linux {
        return Err(ContainerError::BuildFailed(format!(
            "the wslc engine launches Linux guests only — a {} image has no \
             wslc guest contract (a Windows guest's validated path is docker \
             in Windows-containers mode, not wslc)",
            layout.guest_os.name()
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
        ctx.copy_runner(&runner, "mcp-secure-runner").unwrap();
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
        ctx.copy_policy(
            &policy,
            &crate::execution::ExecutionTarget::linux_container(None, None),
        )
        .unwrap();
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

    // -- analyze_runner_binary -------------------------------------------------

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
    fn test_analyze_runner_accepts_static_elf() {
        let tmp = make_temp_dir("static_runner_ok");
        let runner = tmp.join("runner");
        fs::write(&runner, elf64_bytes(None)).unwrap();

        let analysis = analyze_runner_binary(&runner).unwrap();
        match analysis.format {
            RunnerFormat::Elf { arch } => assert_eq!(arch, TargetArch::X86_64),
            other => panic!("expected Elf format, got {other:?}"),
        }
        assert!(analysis.caps.is_none());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_analyze_runner_rejects_dynamic_elf() {
        let tmp = make_temp_dir("static_runner_dyn");
        let runner = tmp.join("runner");
        fs::write(&runner, elf64_bytes(Some(b"/lib64/ld-linux-x86-64.so.2\0"))).unwrap();

        let err = analyze_runner_binary(&runner).unwrap_err();
        assert!(err.to_string().contains("statically linked"));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_analyze_runner_warns_and_passes_non_elf() {
        let tmp = make_temp_dir("static_runner_nonelf");
        let runner = tmp.join("runner");
        fs::write(&runner, "#!/bin/sh\necho hi").unwrap();

        // Unrecognized input is `Unknown` — warned, not failed — so a
        // runner we cannot type-check still gets its marker scanned.
        let analysis = analyze_runner_binary(&runner).unwrap();
        assert!(matches!(analysis.format, RunnerFormat::Unknown));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_analyze_runner_warns_and_passes_truncated_elf() {
        let tmp = make_temp_dir("static_runner_trunc");
        let runner = tmp.join("runner");
        fs::write(&runner, [0x7f, b'E', b'L', b'F', 2, 1]).unwrap();

        let analysis = analyze_runner_binary(&runner).unwrap();
        assert!(matches!(analysis.format, RunnerFormat::Unknown));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_analyze_runner_missing_file_errors() {
        let err = analyze_runner_binary(Path::new("/nonexistent/mcp-secure-runner")).unwrap_err();
        assert!(err.to_string().contains("failed to read"));
    }

    // -- check_runner_for_guest ------------------------------------------------

    /// A minimal synthetic PE for the cross-format checks — `pe_magic`'s
    /// own tests cover the parse details; this only needs MZ magic plus
    /// a parseable header, so reuse its constructor shape.
    fn synthetic_pe_bytes() -> Vec<u8> {
        // Same minimal layout as pe_magic::tests::synthetic_pe (x86_64,
        // no imports): DOS header, PE sig, COFF, PE32+ optional header.
        let e_lfanew: u32 = 0x80;
        let opt_size: u16 = 0xF0;
        let mut b = vec![0u8; 0x400];
        b[0] = b'M';
        b[1] = b'Z';
        b[0x3C..0x40].copy_from_slice(&e_lfanew.to_le_bytes());
        let coff = e_lfanew as usize + 4;
        b[e_lfanew as usize..coff].copy_from_slice(b"PE\0\0");
        b[coff..coff + 2].copy_from_slice(&0x8664u16.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes());
        b
    }

    #[test]
    fn check_runner_format_refuses_elf_for_windows() {
        let tmp = make_temp_dir("elf_for_windows");
        let runner = tmp.join("runner");
        fs::write(&runner, elf64_bytes(None)).unwrap();
        let analysis = analyze_runner_binary(&runner).unwrap();
        let err = check_runner_for_guest(
            &runner,
            &analysis,
            &crate::container::guest_layout::WINDOWS,
            &TargetArch::X86_64,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("ELF"),
            "expected ELF mismatch error, got: {err}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_runner_format_refuses_pe_for_linux() {
        let tmp = make_temp_dir("pe_for_linux");
        let runner = tmp.join("runner.exe");
        fs::write(&runner, synthetic_pe_bytes()).unwrap();
        let analysis = analyze_runner_binary(&runner).unwrap();
        assert!(matches!(analysis.format, RunnerFormat::Pe { .. }));
        let err = check_runner_for_guest(
            &runner,
            &analysis,
            &crate::container::guest_layout::LINUX,
            &TargetArch::X86_64,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("PE"),
            "expected PE mismatch error, got: {err}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_runner_format_accepts_pe_for_windows() {
        let tmp = make_temp_dir("pe_for_windows");
        let runner = tmp.join("runner.exe");
        fs::write(&runner, synthetic_pe_bytes()).unwrap();
        let analysis = analyze_runner_binary(&runner).unwrap();
        check_runner_for_guest(
            &runner,
            &analysis,
            &crate::container::guest_layout::WINDOWS,
            &TargetArch::X86_64,
        )
        .expect("amd64 PE must serve a windows/amd64 image");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_runner_format_refuses_arch_mismatch() {
        let tmp = make_temp_dir("arch_mismatch");
        let runner = tmp.join("runner.exe");
        fs::write(&runner, synthetic_pe_bytes()).unwrap(); // amd64 PE
        let analysis = analyze_runner_binary(&runner).unwrap();
        let err = check_runner_for_guest(
            &runner,
            &analysis,
            &crate::container::guest_layout::WINDOWS,
            &TargetArch::Aarch64,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("architecture"),
            "expected arch mismatch error, got: {err}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn check_runner_format_accepts_matching_elf() {
        let tmp = make_temp_dir("elf_for_linux");
        let runner = tmp.join("runner");
        fs::write(&runner, elf64_bytes(None)).unwrap();
        let analysis = analyze_runner_binary(&runner).unwrap();
        check_runner_for_guest(
            &runner,
            &analysis,
            &crate::container::guest_layout::LINUX,
            &TargetArch::X86_64,
        )
        .expect("amd64 ELF must serve a linux/amd64 image");
        let _ = fs::remove_dir_all(&tmp);
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
        ctx.copy_policy(
            &child_kdl,
            &crate::execution::ExecutionTarget::linux_container(None, None),
        )
        .unwrap();

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
