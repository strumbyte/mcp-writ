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

/// Largest artifact a staged launch/build will carry — generous
/// headroom over the ~20 MiB release binaries while refusing an
/// unbounded copy a hostile source could make us stage.
const ARTIFACT_MAX_BYTES: u64 = 256 * 1024 * 1024;

/// A binary artifact bound to the exact bytes validation read.
///
/// Runner, relay, and CRT paths were previously validated once and then
/// reopened by name for staging — a concurrent writer could swap the
/// path's object in between and ship bytes that never passed the
/// format/arch/marker checks. `BoundArtifact` closes that: the file is
/// opened once without following a final-component link, validation
/// runs on the returned buffer, and every staged copy is written from
/// that same buffer and re-hashed before the engine or sandbox sees it.
#[derive(Debug)]
pub struct BoundArtifact {
    /// Where `bytes` were read — diagnostic text only; never reopened.
    pub source: PathBuf,
    /// The validated content — staging writes exactly these bytes.
    pub bytes: std::sync::Arc<Vec<u8>>,
    /// Lowercase hex SHA-256 of `bytes`; compared against the staged
    /// copy before launch and against operator digest pins.
    pub digest: String,
}

impl BoundArtifact {
    /// Read `path` once — never following a final-component link — and
    /// bind the bytes. A link, non-regular entry, oversized file, or IO
    /// error is a hard failure: callers must never fall back to an
    /// unbound read.
    pub fn bind(path: &Path, label: &str) -> Result<Self, McpWritError> {
        let bytes = crate::fspriv::read_no_follow_bounded(path, ARTIFACT_MAX_BYTES)
            .map_err(|e| -> McpWritError {
                ContainerError::BuildFailed(format!(
                    "failed to read {label} '{}': {e}",
                    path.display()
                ))
                .into()
            })?
            .ok_or_else(|| -> McpWritError {
                ContainerError::BuildFailed(format!(
                    "{label} '{}' is a link or non-regular file — refusing to \
                     stage bytes that could escape validation",
                    path.display()
                ))
                .into()
            })?;
        Ok(Self::from_bytes(path.to_path_buf(), bytes))
    }

    /// [`bind`] plus the handle-bound containment proof
    /// [`crate::fspriv::safe_copy_file`] performs: the opened object's
    /// real path must resolve inside `canonical_root`.
    pub fn bind_in(path: &Path, label: &str, canonical_root: &Path) -> Result<Self, McpWritError> {
        let bytes =
            crate::fspriv::read_no_follow_bounded_in(path, ARTIFACT_MAX_BYTES, canonical_root)
                .map_err(|e| -> McpWritError {
                    ContainerError::BuildFailed(format!(
                        "failed to read {label} '{}': {e}",
                        path.display()
                    ))
                    .into()
                })?;
        Ok(Self::from_bytes(path.to_path_buf(), bytes))
    }

    /// Wrap already-read bytes — for tests and for callers that loaded
    /// the buffer through an equally binding channel.
    pub fn from_bytes(source: PathBuf, bytes: Vec<u8>) -> Self {
        let digest = sha256_hex(&bytes);
        Self {
            source,
            bytes: std::sync::Arc::new(bytes),
            digest,
        }
    }

    /// The source's basename — the name staged copies are written
    /// under (Dockerfile `COPY` names, app-local CRT placement).
    pub fn file_name(&self) -> String {
        self.source
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Write `bytes` to `dst` and prove the staged file still hashes to
    /// `digest` — a destination swapped or corrupted between write and
    /// read-back fails closed instead of reaching a build context,
    /// bind mount, or sandbox share.
    pub fn stage_to(&self, dst: &Path, executable: bool) -> Result<(), McpWritError> {
        if let Some(parent) = dst.parent() {
            std::fs::create_dir_all(parent).map_err(|e| -> McpWritError {
                ContainerError::BuildFailed(format!(
                    "failed to create staging dir for '{}': {e}",
                    dst.display()
                ))
                .into()
            })?;
        }
        // Atomic create-new+rename: a planted link at `dst` is replaced
        // outright rather than written through to an attacker-chosen
        // target.
        crate::fspriv::write_file_atomic(dst, &self.bytes[..]).map_err(|e| -> McpWritError {
            ContainerError::BuildFailed(format!("failed to stage '{}': {e}", dst.display())).into()
        })?;
        #[cfg(not(unix))]
        let _ = executable;
        #[cfg(unix)]
        if executable {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dst, std::fs::Permissions::from_mode(0o755)).map_err(
                |e| -> McpWritError {
                    ContainerError::BuildFailed(format!(
                        "failed to mark staged '{}' executable: {e}",
                        dst.display()
                    ))
                    .into()
                },
            )?;
        }
        let staged = std::fs::read(dst).map_err(|e| -> McpWritError {
            ContainerError::BuildFailed(format!(
                "failed to re-read staged '{}': {e}",
                dst.display()
            ))
            .into()
        })?;
        if sha256_hex(&staged) != self.digest {
            return Err(ContainerError::BuildFailed(format!(
                "staged '{}' does not match the validated artifact '{}' — \
                 the copy was swapped or corrupted before launch",
                dst.display(),
                self.source.display(),
            ))
            .into());
        }
        Ok(())
    }
}

/// Compute `bytes`' SHA-256 as lowercase hex — the bare `sha256sum`
/// spelling operator digest pins use.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        use std::fmt::Write;
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Refuse `artifact` when the operator set `env_name` to an approved
/// SHA-256 that the bound bytes don't match. The embedded
/// version/capability markers authenticate compatibility, not
/// provenance — anyone can stamp them into a forged binary — so a
/// configured digest pin is the cryptographic anchor. An unparsable or
/// mismatched pin fails closed; an unset variable skips the check.
pub fn check_digest_pin(artifact: &BoundArtifact, env_name: &str) -> Result<(), McpWritError> {
    let Some(raw) = std::env::var_os(env_name) else {
        return Ok(());
    };
    let text = raw.to_string_lossy();
    let pin = text.trim().trim_start_matches("sha256:");
    if pin.is_empty() {
        return Ok(());
    }
    let wellformed = pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit());
    if !wellformed || !pin.eq_ignore_ascii_case(&artifact.digest) {
        return Err(ContainerError::BuildFailed(format!(
            "'{}' digest {} does not match the {env_name} pin{}",
            artifact.source.display(),
            artifact.digest,
            if wellformed {
                String::new()
            } else {
                format!(" (the pin '{pin}' is not a 64-digit hex SHA-256)")
            },
        ))
        .into());
    }
    Ok(())
}

/// A runner binary bound to the bytes its analysis validated —
/// staging and mounts consume [`BoundArtifact::bytes`], never a
/// reopened path.
#[derive(Debug)]
pub struct BoundRunner {
    /// The bound runner bytes + identity.
    pub artifact: BoundArtifact,
    /// Format/capability analysis of `artifact.bytes`.
    pub analysis: RunnerAnalysis,
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
) -> Result<BoundRunner, McpWritError> {
    let path = resolve_runner_binary(runner_binary, layout, guest_arch)?;
    let artifact = BoundArtifact::bind(&path, "runner binary")?;
    let analysis = analyze_runner_bytes(&path, &artifact.bytes)?;
    check_runner_for_guest(&path, &analysis, layout, guest_arch)?;
    check_digest_pin(&artifact, "MCP_WRIT_RUNNER_SHA256")?;
    Ok(BoundRunner { artifact, analysis })
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

/// Read the runner binary once and analyze the bytes. Callers that
/// later stage the runner use [`resolve_runner_checked`] instead so the
/// staged copy provably carries these same bytes.
pub fn analyze_runner_binary(path: &Path) -> Result<RunnerAnalysis, McpWritError> {
    let artifact = BoundArtifact::bind(path, "runner binary")?;
    analyze_runner_bytes(path, &artifact.bytes)
}

/// Analyze runner `data` (read under `path`'s name, for diagnostics):
/// fail closed on a dynamically linked ELF, parse a PE for arch +
/// redist imports, and scan for the `MCP_WRIT_RUNNER_CAPS` capability
/// marker. A missing marker is a legacy runner, not an error.
pub fn analyze_runner_bytes(path: &Path, data: &[u8]) -> Result<RunnerAnalysis, McpWritError> {
    let caps = crate::container::guest_report::scan_runner_caps(data);
    let format = if data.starts_with(b"\x7fELF") {
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
    } else if data.starts_with(b"MZ") {
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

/// Decide which MSVC CRT DLLs (if any) a Windows-guest build must ship
/// app-local, and where each comes from. Each returned artifact is
/// bound to the bytes that passed validation — the generated
/// Dockerfile `COPY`s each next to the runner exe under its basename.
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
///
/// Every candidate is bound once under no-follow semantics and must
/// parse as a PE of the guest's architecture — a swapped-in script,
/// foreign-arch DLL, or link-to-secret never reaches the build
/// context; an explicit `--crt-dll` that fails those checks is a hard
/// error, a bundled/System32 candidate falls through to the next
/// location.
pub fn stage_crt_dlls(
    layout: &GuestLayout,
    analysis: &RunnerAnalysis,
    guest_arch: &TargetArch,
    explicit: &[PathBuf],
) -> Result<Vec<BoundArtifact>, ContainerError> {
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
    let mut staged: Vec<BoundArtifact> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for dll in &needed {
        match find_crt_dll(dll, explicit, guest_arch)? {
            Some(found) => staged.push(found),
            None => missing.push(dll.clone()),
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

/// Bind one CRT candidate and prove it is a PE of the guest's
/// architecture — the staged copy must carry exactly these bytes.
fn bind_crt_dll(path: &Path, guest_arch: &TargetArch) -> Result<BoundArtifact, ContainerError> {
    let bound = BoundArtifact::bind(path, "CRT redistributable")
        .map_err(|e| ContainerError::BuildFailed(e.to_string()))?;
    match crate::container::pe_magic::pe_arch(&bound.bytes) {
        Some(arch) if arch == *guest_arch => Ok(bound),
        Some(other) => Err(ContainerError::BuildFailed(format!(
            "CRT DLL '{}' targets {} but the guest architecture is {} — \
             the guest loader would refuse it",
            path.display(),
            other.name(),
            guest_arch.name(),
        ))),
        None => Err(ContainerError::BuildFailed(format!(
            "CRT DLL '{}' is not a parseable PE — refusing to stage \
             unverified bytes into the image",
            path.display(),
        ))),
    }
}

/// Locate one redistributable DLL by name: `explicit` first, then the
/// packaged `runners/crt/` drop, then the host's `System32`. Explicit
/// candidates that fail binding or PE validation are hard errors;
/// discovered candidates fall through to the next location.
fn find_crt_dll(
    name: &str,
    explicit: &[PathBuf],
    guest_arch: &TargetArch,
) -> Result<Option<BoundArtifact>, ContainerError> {
    for p in explicit {
        if p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
            && p.is_file()
        {
            return bind_crt_dll(p, guest_arch).map(Some);
        }
    }
    let mut discovered: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        discovered.push(dir.join("runners").join("crt").join(name));
    }
    if cfg!(windows) {
        discovered.push(Path::new(r"C:\Windows\System32").join(name));
    }
    for p in discovered {
        if p.is_file()
            && let Ok(bound) = bind_crt_dll(&p, guest_arch)
        {
            return Ok(Some(bound));
        }
    }
    Ok(None)
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
    /// The staged bytes are the ones `resolve_runner_checked`
    /// validated, and the staged digest is re-verified before return.
    pub fn copy_runner(
        &self,
        runner: &BoundRunner,
        context_name: &str,
    ) -> Result<(), ContainerError> {
        runner
            .artifact
            .stage_to(&self.dir.join(context_name), true)
            .map_err(|e| ContainerError::BuildFailed(e.to_string()))
    }

    /// Stage a bound artifact's validated bytes into the build context
    /// under `name` — used for the app-local CRT DLLs.
    pub fn stage_artifact(
        &self,
        artifact: &BoundArtifact,
        name: &str,
    ) -> Result<(), ContainerError> {
        artifact
            .stage_to(&self.dir.join(name), false)
            .map_err(|e| ContainerError::BuildFailed(e.to_string()))
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
/// Staging cannot be raced out of the source tree: each copied file is
/// opened without following a final-component link and proven to resolve
/// inside the canonicalized `src` before its bytes stream from that same
/// open handle (`fspriv::safe_copy_dir`). Links and other non-regular
/// entries are skipped — never followed — which also prevents:
/// - Infinite loops from circular symlinks
/// - Path traversal attacks via symlinks pointing outside the source tree
/// - Errors from broken (dangling) symlinks
/// Staging budgets for recursive source copies — 50k entries, 4 GiB
/// aggregate (charged on bytes actually streamed), 512 MiB per file.
const MAX_STAGE_ENTRIES: u64 = 50_000;
const MAX_STAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_STAGE_FILE_BYTES: u64 = 512 * 1024 * 1024;

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<(), ContainerError> {
    let root = crate::fspriv::canonical_root(src).map_err(|e| {
        ContainerError::BuildFailed(format!(
            "failed to canonicalize source directory '{}': {e}",
            src.display()
        ))
    })?;
    // Mandatory staging budgets: bounded entries, aggregate bytes
    // charged on actual copied length, and a per-file ceiling.
    let mut budget =
        crate::fspriv::CopyBudget::new(MAX_STAGE_ENTRIES, MAX_STAGE_BYTES, MAX_STAGE_FILE_BYTES);
    crate::fspriv::safe_copy_dir(
        src,
        dst,
        &root,
        0,
        &|name| crate::fspriv::should_skip_build_entry(name),
        &mut budget,
    )
    .map_err(|e| ContainerError::BuildFailed(format!("failed to stage '{}': {e}", src.display())))
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
/// The build goes through [`ContainerEngine::build`] — each engine owns
/// its subcommand dialect (`build`/`bud`) and spawned program (a
/// resolved full path when the CLI is not on PATH — wslc.exe lives in
/// the WSL install dir). The build lands on a fresh temporary tag no
/// earlier image can already carry: an engine whose CLI can print a
/// build error and still exit 0 (wslc) must never let a pre-existing
/// image under `tag` count as this build's output. The image under the
/// unique tag is the success fact — verified by `image inspect` — and
/// only then is it associated with the requested tag.
pub async fn build_image(
    engine: &dyn ContainerEngine,
    dockerfile_path: &Path,
    tag: &str,
    context_dir: &Path,
    no_cache: bool,
) -> Result<(), ContainerError> {
    let engine_name = engine.name();
    let build_tag = format!(
        "mcp-writ-build-{}:tmp",
        &uuid::Uuid::now_v7().simple().to_string()[..12]
    );
    engine
        .build(
            &dockerfile_path.display().to_string(),
            &build_tag,
            &context_dir.display().to_string(),
            no_cache,
        )
        .await
        .map_err(|e| match e {
            crate::container::engine::EngineError::Io(io) => ContainerError::BuildFailed(format!(
                "failed to run '{engine_name} {}': {io}",
                get_build_subcommand(engine_name)
            )),
            other => ContainerError::BuildFailed(format!(
                "{other}\n\nTip: try '{engine_name} image prune' to free up disk space"
            )),
        })?;

    // The image under the unique tag is the success fact — an exit-0
    // fake failure cannot fake a tag that never existed before. Every
    // failure path from here still drops the temporary name.
    let post_build = async {
        let built_json = engine.inspect(&build_tag).await.map_err(|e| {
            ContainerError::BuildFailed(format!(
                "{engine_name} build exited 0 but image '{build_tag}' did not \
                 materialize — treated as a failed build ({e})\n\nTip: try \
                 '{engine_name} image prune' to free up disk space"
            ))
        })?;
        // wslc's inspect answers an absent tag with `[]` at exit 0 — the
        // record must carry the produced image's `Id`, and that same `Id`
        // must appear under `tag` after tagging or a stale image answered.
        let built_id = if engine_name == "wslc" {
            Some(inspect_image_id(&built_json).ok_or_else(|| {
                ContainerError::BuildFailed(format!(
                    "wslc build exited 0 but image '{build_tag}' did not materialize \
                     — treated as a failed build\n\nTip: try '{engine_name} \
                     image prune' to free up disk space"
                ))
            })?)
        } else {
            None
        };

        engine.tag(&build_tag, tag).await.map_err(|e| {
            ContainerError::BuildFailed(format!(
                "{engine_name} image tag '{build_tag}' → '{tag}' failed: {e}"
            ))
        })?;

        if let Some(built_id) = built_id {
            let tagged_json = engine.inspect(tag).await.map_err(|e| {
                ContainerError::BuildFailed(format!(
                    "wslc image '{tag}' did not resolve after tagging: {e}"
                ))
            })?;
            if inspect_image_id(&tagged_json).as_deref() != Some(built_id.as_str()) {
                return Err(ContainerError::BuildFailed(format!(
                    "the image tagged '{tag}' is not this build's output (expected \
                     id {built_id}) — a stale image may answer for that tag"
                )));
            }
        }
        Ok(())
    }
    .await;

    // Drop the temporary name on every exit path — an untag, since
    // `tag` keeps the image under the requested name. Best-effort: a
    // removal failure reports only when nothing else failed, never
    // masking the original tagging or identity-mismatch error.
    let removed = engine.remove_image(&build_tag).await.map_err(|e| {
        ContainerError::BuildFailed(format!(
            "image built and tagged '{tag}', but removing temporary tag \
             '{build_tag}' failed: {e}"
        ))
    });
    post_build.and(removed)
}

/// The `[0].Id`/`Id` member of an `image inspect` answer — `None` when
/// the answer carries no record (wslc replies `[]` for an absent tag
/// at exit 0) or no `Id` member. Used to prove a build's image exists
/// and that a tag association landed on the same image.
fn inspect_image_id(json_str: &str) -> Option<String> {
    let json = nojson::RawJson::parse(json_str).ok()?;
    let root = json.value();
    // Docker/podman/wslc answer `[{...}]`; buildah a bare `{...}`.
    let record = match root.to_array() {
        Ok(mut arr) => arr.next()?,
        Err(_) => root,
    };
    record
        .to_member("Id")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok())
        .map(|s| s.into_owned())
}

/// Whether an `inspect` CLI error text specifically means "the
/// inspected reference does not exist" — the only failure that proves
/// a removal. The markers name the inspected *object kind* as absent;
/// anything broader would swallow unrelated failures — a missing
/// executable ("no such file or directory"), a daemon socket error
/// ("cannot find the file"), or a DNS failure ("host not known") —
/// and misreport them as confirmed deletion. Unknown errors stay
/// "not absent". Matched case-insensitively across the engines this
/// crate drives:
/// - docker: `Error: No such object: <id>`, `No such image`, `No such container`
/// - podman: `no such container`, `no such image`, `image not known`
/// - buildah: `error locating item`, `image not known`
/// - wslc: `WSLC_E_CONTAINER_NOT_FOUND` / `WSLC_E_IMAGE_NOT_FOUND`
pub(crate) fn inspect_error_is_absent(text: &str) -> bool {
    let text = text.to_lowercase();
    [
        "no such object",
        "no such container",
        "no such image",
        "image not known",
        "error locating item",
        "container_not_found",
        "image_not_found",
    ]
    .iter()
    .any(|marker| text.contains(marker))
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

    // -- inspect_error_is_absent -------------------------------------------------

    /// Engine-specific "the inspected reference does not exist" answers
    /// confirm removal — the only inspect outcomes allowed to.
    #[test]
    fn test_inspect_error_absent_engine_not_found() {
        // docker: object inspect + image inspect answers
        assert!(inspect_error_is_absent("Error: No such object: 4f2c"));
        assert!(inspect_error_is_absent(
            "Error response from daemon: No such image: img:latest"
        ));
        assert!(inspect_error_is_absent("Error: No such container: abc"));
        // podman
        assert!(inspect_error_is_absent("Error: no such container \"abc\""));
        assert!(inspect_error_is_absent("Error: no such image \"img\""));
        assert!(inspect_error_is_absent("Error: image not known"));
        // buildah
        assert!(inspect_error_is_absent(
            "error locating item named \"img\": image not known"
        ));
        // wslc
        assert!(inspect_error_is_absent("WSLC_E_CONTAINER_NOT_FOUND"));
        assert!(inspect_error_is_absent("WSLC_E_IMAGE_NOT_FOUND"));
    }

    /// Broad or unrelated failures must never be read as "gone" — a
    /// removal confirmed off these would claim teardown that never
    /// happened.
    #[test]
    fn test_inspect_error_absent_rejects_generic_failures() {
        for text in [
            // missing executable / shell-level spawn failure
            "sh: 1: docker: not found",
            "docker: no such file or directory",
            "executable file not found in $PATH",
            // daemon / socket connection failures
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
            "error during connect: open //./pipe/docker_engine: The system cannot find the file specified.",
            // dns / network
            "dial tcp: lookup registry: host not known",
            // permissions
            "Got permission denied while trying to connect",
            // generic non-zero without a not-found fact
            "",
            "Error: unknown flag: --inspect",
            "Error: invalid reference format",
        ] {
            assert!(
                !inspect_error_is_absent(text),
                "must not classify as absent: {text:?}"
            );
        }
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

    /// A [`BoundRunner`] over a test file — format checks are
    /// irrelevant to the staging contract being tested.
    fn bound_runner_for_test(path: &Path) -> BoundRunner {
        let artifact = BoundArtifact::bind(path, "runner binary").unwrap();
        let analysis = analyze_runner_bytes(path, &artifact.bytes).unwrap();
        BoundRunner { artifact, analysis }
    }

    #[test]
    fn test_build_context_copy_runner() {
        let tmp = make_temp_dir("copy_runner");
        let runner = tmp.join("fake-runner");
        fs::write(&runner, "binary data").unwrap();
        let runner = bound_runner_for_test(&runner);

        let ctx = BuildContext::new("test_cp_runner").unwrap();
        ctx.copy_runner(&runner, "mcp-secure-runner").unwrap();
        assert!(ctx.dir().join("mcp-secure-runner").exists());

        ctx.cleanup();
        let _ = fs::remove_dir_all(&tmp);
    }

    // -- BoundArtifact ------------------------------------------------------

    /// F65: bytes are bound at validation — swapping the source path's
    /// object afterwards cannot change what staging writes.
    #[test]
    fn test_bound_artifact_stages_validated_bytes_after_swap() {
        let tmp = make_temp_dir("bound_swap");
        let source = tmp.join("runner");
        fs::write(&source, b"validated bytes").unwrap();
        let bound = BoundArtifact::bind(&source, "runner binary").unwrap();
        assert_eq!(bound.digest, sha256_hex(b"validated bytes"));

        // The classic F65 race: the source is replaced between
        // validation and staging.
        fs::write(&source, b"substituted bytes").unwrap();
        let dst = tmp.join("staged").join("runner");
        bound.stage_to(&dst, true).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"validated bytes");

        let _ = fs::remove_dir_all(&tmp);
    }

    /// F65: a link at the source name is refused at bind time — the
    /// target's bytes must never be read into the staged copy.
    #[cfg(unix)]
    #[test]
    fn test_bound_artifact_refuses_symlink_source() {
        let tmp = make_temp_dir("bound_link");
        let secret = tmp.join("secret");
        fs::write(&secret, b"do not stage").unwrap();
        let link = tmp.join("runner");
        std::os::unix::fs::symlink(&secret, &link).unwrap();

        let err = BoundArtifact::bind(&link, "runner binary").unwrap_err();
        assert!(
            err.to_string().contains("link or non-regular"),
            "expected link refusal, got: {err}"
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    /// F65: the staged digest is re-verified — an unreadable staged
    /// copy fails closed rather than reaching the build context.
    #[test]
    fn test_bound_artifact_stage_into_missing_parent_ok() {
        let tmp = make_temp_dir("bound_stage");
        let bound = BoundArtifact::from_bytes(tmp.join("runner"), b"payload".to_vec());
        let dst = tmp.join("deep").join("nested").join("runner");
        bound.stage_to(&dst, false).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"payload");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            bound.stage_to(&dst, true).unwrap();
            assert_eq!(
                fs::metadata(&dst).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    // -- stage_crt_dlls -------------------------------------------------------

    /// Explicit `--crt-dll` bytes bind at resolve time: swapping the
    /// file afterwards cannot desync the staged copy.
    #[test]
    fn test_stage_crt_dlls_binds_explicit_bytes() {
        let tmp = make_temp_dir("crt_bind");
        let dll = tmp.join("vcruntime140.dll");
        fs::write(&dll, synthetic_pe_bytes()).unwrap();
        let analysis = RunnerAnalysis {
            format: RunnerFormat::Pe {
                arch: TargetArch::X86_64,
                redist_dlls: vec!["vcruntime140.dll".to_string()],
            },
            caps: None,
        };
        let staged = stage_crt_dlls(
            &crate::container::guest_layout::WINDOWS,
            &analysis,
            &TargetArch::X86_64,
            &[dll.clone()],
        )
        .unwrap();
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].file_name(), "vcruntime140.dll");
        assert_eq!(staged[0].bytes[..], synthetic_pe_bytes()[..]);

        // The F65 race — a swapped source still stages the validated bytes.
        fs::write(&dll, b"substituted").unwrap();
        let dst = tmp.join("out.dll");
        staged[0].stage_to(&dst, false).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), synthetic_pe_bytes());
        let _ = fs::remove_dir_all(&tmp);
    }

    /// A non-PE or wrong-arch DLL is refused — a script or foreign
    /// binary must never reach the build context under a CRT name.
    #[test]
    fn test_stage_crt_dlls_refuses_invalid_explicit() {
        let tmp = make_temp_dir("crt_bad");
        let analysis = RunnerAnalysis {
            format: RunnerFormat::Pe {
                arch: TargetArch::X86_64,
                redist_dlls: vec!["vcruntime140.dll".to_string()],
            },
            caps: None,
        };
        for (label, bytes, arch, expect) in [
            (
                "non-pe",
                b"MZ-nope".to_vec(),
                TargetArch::X86_64,
                "not a parseable PE",
            ),
            (
                "wrong-arch",
                synthetic_pe_bytes(),
                TargetArch::Aarch64,
                "targets x86_64",
            ),
        ] {
            let dll = tmp.join(format!("{label}.dll"));
            fs::write(&dll, &bytes).unwrap();
            // Rename to the required basename for the explicit match.
            let named = tmp.join("vcruntime140.dll");
            fs::rename(&dll, &named).unwrap();
            let err = stage_crt_dlls(
                &crate::container::guest_layout::WINDOWS,
                &analysis,
                &arch,
                std::slice::from_ref(&named),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains(expect),
                "{label}: expected '{expect}', got {err}"
            );
            fs::remove_file(&named).unwrap();
        }
        let _ = fs::remove_dir_all(&tmp);
    }

    /// F65: an explicit CRT path that is a link is refused outright —
    /// the secret it could point at is never staged.
    #[cfg(unix)]
    #[test]
    fn test_stage_crt_dlls_refuses_symlink() {
        let tmp = make_temp_dir("crt_link");
        let secret = tmp.join("secret.dll");
        fs::write(&secret, synthetic_pe_bytes()).unwrap();
        let link = tmp.join("vcruntime140.dll");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let analysis = RunnerAnalysis {
            format: RunnerFormat::Pe {
                arch: TargetArch::X86_64,
                redist_dlls: vec!["vcruntime140.dll".to_string()],
            },
            caps: None,
        };
        let err = stage_crt_dlls(
            &crate::container::guest_layout::WINDOWS,
            &analysis,
            &TargetArch::X86_64,
            &[link],
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("link or non-regular"),
            "expected link refusal, got: {err}"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    /// F78-shaped: a configured digest pin authenticates the bound
    /// bytes; a forged file with matching markers but different bytes
    /// is refused when the pin names the release digest.
    #[test]
    fn test_digest_pin_enforces_env() {
        let _env = crate::warden::lock_process_env();
        let tmp = make_temp_dir("pin_env");
        let genuine = tmp.join("runner");
        fs::write(&genuine, b"genuine").unwrap();
        let bound = BoundArtifact::bind(&genuine, "runner binary").unwrap();
        const PIN: &str = "MCP_WRIT_TEST_PIN";

        unsafe {
            std::env::set_var(PIN, sha256_hex(b"genuine"));
        }
        check_digest_pin(&bound, PIN).unwrap();

        unsafe {
            std::env::set_var(PIN, "a".repeat(64));
        }
        let err = check_digest_pin(&bound, PIN).unwrap_err();
        assert!(err.to_string().contains("does not match"), "got: {err}");

        // A malformed pin fails closed too — never silently skipped.
        unsafe {
            std::env::set_var(PIN, "not-hex");
        }
        assert!(check_digest_pin(&bound, PIN).is_err());
        unsafe {
            std::env::remove_var(PIN);
        }
        check_digest_pin(&bound, PIN).unwrap();

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
