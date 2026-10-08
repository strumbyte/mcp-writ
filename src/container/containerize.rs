use std::path::Path;

use crate::container::common::{
    BuildContext, build_image, refuse_wslc_non_linux_guest, resolve_engine_for_build,
    resolve_runner_checked, validate_policy_path, write_dockerfile_to_path,
};
use crate::container::containerize_dockerfile::{ContainerizeDockerfileTemplate, CopyEntry};
use crate::container::elf_magic::looks_like_elf;
use crate::container::guest_layout::{self, GuestLayout};
use crate::container::options::ContainerizeOptions;
use crate::container::presenter::{BuildOutcome, format_project_hints_stderr};
use crate::container::runtime_detect::RuntimeType;
use crate::error::ContainerError;
use crate::execution::{EngineName, TargetArch, TargetOs};

/// Execute the containerize flow: detect runtime → Dockerfile → build → tag.
///
/// Returns a [`BuildOutcome`] on success:
/// - For builds: `Built` carrying the output image tag.
/// - For `--output-dockerfile`: `DockerfileWritten` with the output path.
pub async fn containerize(options: &ContainerizeOptions) -> Result<BuildOutcome, ContainerError> {
    // 1. Validate source directory exists
    if !options.source_dir.exists() || !options.source_dir.is_dir() {
        return Err(ContainerError::BuildFailed(format!(
            "source directory not found or is not a directory: {}",
            options.source_dir.display()
        )));
    }

    // 2b. Analyze project for permission hints (advisory)
    let project_hint = crate::legislator::project_hints::analyze_project(&options.source_dir);
    let hints_stderr = format_project_hints_stderr(&project_hint);
    if !hints_stderr.is_empty() {
        eprint!("{hints_stderr}");
    }

    // --output-dockerfile: emit the contract and stop. No engine or
    // runner is resolved on this path — the Linux guest contract is the
    // generated default (windows guests need the engine's base-image
    // inspect to pick their layout; the build path below does that).
    if let Some(ref output_path) = options.output_dockerfile {
        // `--crt-dll` supplies MSVC redists for a *Windows* guest — a
        // contract this path can never emit. Refuse rather than
        // silently drop the copies the caller asked for.
        if !options.crt_dlls.is_empty() {
            return Err(ContainerError::DockerfileGeneration(
                "--crt-dll cannot be used with --output-dockerfile: the emit-only path \
                 always generates the Linux guest contract — the guest OS is only \
                 known once the engine inspects the base image on the build path"
                    .to_string(),
            ));
        }
        // `--server` binds the policy when it is materialized into the
        // build context — nothing is bound on the emit-only path.
        if let Some(ref server) = options.server {
            eprintln!(
                "[containerize] note: --server '{server}' has no effect with \
                 --output-dockerfile (no policy is bound on the emit-only path)"
            );
        }
        let layout = &guest_layout::LINUX;
        let runtime_info =
            detect_runtime_from_source(&options.source_dir, options.base_image.as_deref(), layout)?;
        let extra_copies = collect_source_copies(&options.source_dir, layout)?;
        let dockerfile_content =
            containerize_dockerfile(&runtime_info, extra_copies, "", layout, &[])?;
        write_dockerfile_to_path(output_path, &dockerfile_content)?;
        return Ok(BuildOutcome::DockerfileWritten {
            path: output_path.clone(),
        });
    }

    // 5. Runtime detection runs once against the Linux contract to pick
    //    the default base image; an explicit --base-image overrides it.
    //    The guest layout is then decided by *inspecting that base* —
    //    the generated image's contract follows the guest, not the
    //    build host.
    let (engine_name, engine) = resolve_engine_for_build(options.engine)
        .map_err(|e| ContainerError::BuildFailed(e.to_string()))?;

    let preliminary = detect_runtime_from_source(
        &options.source_dir,
        options.base_image.as_deref(),
        &guest_layout::LINUX,
    )?;
    let probe_base = preliminary.base_image.clone();

    // The base may not be pulled locally (the build resolves it): an
    // uninspectable base keeps the Linux default with the unverified
    // note — never an unverified pass.
    let (layout, guest_arch) =
        match crate::container::inspect::inspect_image(engine.as_ref(), &probe_base).await {
            Ok(meta) => {
                let layout = guest_layout::for_image_os(meta.os.as_deref())
                    .map_err(ContainerError::BuildFailed)?;
                let arch =
                    crate::container::guest_report::image_target_arch(meta.architecture.as_deref());
                (layout, arch)
            }
            Err(_) => {
                eprintln!(
                    "[containerize] note: base image '{}' is not available for local inspect; \
                 its guest OS is unverified — assuming the Linux contract (the build \
                 resolves the real base)",
                    probe_base
                );
                (&guest_layout::LINUX, TargetArch::host())
            }
        };
    // A Windows base re-runs detection under its own layout so native
    // PEs are found and command paths spell the guest's filesystem.
    let runtime_info = if layout.guest_os == TargetOs::Linux {
        preliminary
    } else {
        detect_runtime_from_source(&options.source_dir, options.base_image.as_deref(), layout)?
    };

    // 5b. The wslc session VM runs Linux guests only — a Windows base
    //     has no wslc guest contract, refused at entry.
    refuse_wslc_non_linux_guest(&engine_name, layout)?;

    // 6. Resolve + type-check the runner for *this* guest — a PE for a
    //    Windows image, a static ELF for a Linux one.
    let (runner_path, analysis) = resolve_runner_checked(None, layout, &guest_arch)
        .map_err(|e| ContainerError::BuildFailed(e.to_string()))?;
    let runner_caps = analysis
        .caps
        .as_ref()
        .map(|c| c.env_value())
        .unwrap_or_default();

    // 6b. A Windows guest whose runner imports the MSVC redist needs the
    //     DLLs app-local — Server Core ships none. `--crt-dll` supplies
    //     copies the packaged drop and System32 did not.
    let crt_dlls = crate::container::common::stage_crt_dlls(layout, &analysis, &options.crt_dlls)?;

    // 7. Validate policy path and bind it for the *guest's* OS — the
    //    substrate OS probe is skipped (the guest contract decides).
    let policy_path = validate_policy_path(Some(&options.policy), "policy.kdl")?;
    let guest_target = match layout.guest_os {
        TargetOs::Windows => crate::execution::ExecutionTarget::windows_vm_guest(
            EngineName::from_name(&engine_name),
            None,
            guest_arch.clone(),
        ),
        _ => crate::execution::ExecutionTarget::linux_container(
            EngineName::from_name(&engine_name),
            None,
        ),
    };

    let extra_copies = collect_source_copies(&options.source_dir, layout)?;

    // 8. Create build context and populate it
    let ctx = BuildContext::new("containerize")?;
    ctx.copy_runner(&runner_path, layout.runner_context_name)?;
    ctx.copy_policy_for_server(&policy_path, options.server.as_deref(), &guest_target)?;
    for dll in &crt_dlls {
        let name = dll.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            ContainerError::BuildFailed(format!("bad CRT filename '{}'", dll.display()))
        })?;
        ctx.copy_file(dll, name)?;
    }

    // Copy source directory contents into context
    copy_source_to_context(&options.source_dir, &ctx)?;

    let crt_names: Vec<String> = crt_dlls
        .iter()
        .map(|p| {
            p.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string()
        })
        .collect();
    let dockerfile_content = containerize_dockerfile(
        &runtime_info,
        extra_copies,
        &runner_caps,
        layout,
        &crt_names,
    )?;
    let dockerfile_path = ctx.write_dockerfile(&dockerfile_content)?;

    // 9. Determine output tag
    let tag = options
        .tag
        .clone()
        .unwrap_or_else(|| make_containerize_tag(&options.source_dir));

    // 10. Build image
    let build_result = build_image(
        engine.as_ref(),
        &dockerfile_path,
        &tag,
        ctx.dir(),
        false, // no --no-cache for containerize
    )
    .await;

    // 11. Clean up temp dir (runs on both success and failure)
    ctx.cleanup();
    build_result?;

    eprintln!(
        "{}",
        crate::container::wrap::runner_capability_note(&analysis.caps)
    );
    Ok(BuildOutcome::Built { tag })
}

/// Build the containerize Dockerfile text from the detected runtime info.
fn containerize_dockerfile(
    runtime_info: &SourceRuntimeInfo,
    extra_copies: Vec<CopyEntry>,
    runner_caps: &str,
    layout: &'static GuestLayout,
    crt_dlls: &[String],
) -> Result<String, ContainerError> {
    ContainerizeDockerfileTemplate {
        runtime_type: runtime_info.runtime_type.clone(),
        base_image: runtime_info.base_image.clone(),
        runner_path: layout.runner_context_name.to_string(),
        policy_path: "policy.kdl".to_string(),
        command: runtime_info.command.clone(),
        extra_copies,
        runner_caps: runner_caps.to_string(),
        guest: layout,
        crt_dlls: crt_dlls.to_vec(),
    }
    .generate()
}

/// Runtime detection result for source directory analysis.
#[derive(Debug)]
struct SourceRuntimeInfo {
    runtime_type: RuntimeType,
    base_image: String,
    command: Vec<String>,
}

/// Detect runtime from a source directory by examining its contents.
///
/// If `base_image_override` is provided, skip detection and use it
/// directly. `layout` controls the guest-side path spellings and which
/// binary format counts as "native" (ELF for a Linux guest, PE for a
/// Windows one) — a Windows-based image detects its workload exe
/// rather than silently producing `/app/…` paths.
fn detect_runtime_from_source(
    source_dir: &Path,
    base_image_override: Option<&str>,
    layout: &GuestLayout,
) -> Result<SourceRuntimeInfo, ContainerError> {
    // If base image is explicitly set, try to detect runtime type but use provided image
    if let Some(base) = base_image_override {
        let (rt, cmd) = infer_runtime_from_dir(source_dir, layout);
        return Ok(SourceRuntimeInfo {
            runtime_type: rt,
            base_image: base.to_string(),
            command: cmd,
        });
    }

    let (rt, cmd) = infer_runtime_from_dir(source_dir, layout);
    let base_image = match rt {
        RuntimeType::NodeJs => "node:22-slim".to_string(),
        RuntimeType::Python => "python:3.13-slim".to_string(),
        RuntimeType::Native => match layout.guest_os {
            // Windows guests have no curated runtime base — an MSVC/PE
            // workload needs an explicit Windows base (e.g. Server Core)
            // rather than a linux default that cannot run it.
            TargetOs::Windows => {
                return Err(ContainerError::RuntimeDetect(format!(
                    "source directory '{}' contains a native Windows binary; \
                     pass --base-image with a Windows Server Core image",
                    source_dir.display()
                )));
            }
            _ => "debian:bookworm-slim".to_string(),
        },
        RuntimeType::Unknown => {
            return Err(ContainerError::RuntimeDetect(format!(
                "cannot detect runtime for source directory '{}'; \
                 use --base-image to specify explicitly",
                source_dir.display()
            )));
        }
    };

    Ok(SourceRuntimeInfo {
        runtime_type: rt,
        base_image,
        command: cmd,
    })
}

/// Infer runtime type and default command from source directory contents.
/// `layout` supplies the guest-side app directory and the native-binary
/// magic (ELF vs PE) the guest can actually execute.
fn infer_runtime_from_dir(source_dir: &Path, layout: &GuestLayout) -> (RuntimeType, Vec<String>) {
    let app = layout.app_dir;
    // Check for Node.js indicators
    if source_dir.join("package.json").exists() {
        // Try to extract the main entry point from package.json
        let main_entry = read_package_json_main(source_dir);
        let cmd = match main_entry {
            Some(entry) => vec!["node".to_string(), format!("{app}/{entry}")],
            None => vec!["npx".to_string(), ".".to_string()],
        };
        return (RuntimeType::NodeJs, cmd);
    }

    // Check for Python indicators
    if source_dir.join("pyproject.toml").exists()
        || source_dir.join("setup.py").exists()
        || source_dir.join("requirements.txt").exists()
    {
        // Try to find a main entry module
        let entry = find_python_entry(source_dir);
        let cmd = match entry {
            Some(module) => vec!["python".to_string(), format!("{app}/{module}")],
            None => vec!["python".to_string(), "-m".to_string(), "app".to_string()],
        };
        return (RuntimeType::Python, cmd);
    }

    // Check for a native binary the guest can execute.
    if let Some(binary) = find_native_binary_in_dir(source_dir, layout.guest_os) {
        let name = binary
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("server");
        return (RuntimeType::Native, vec![format!("{app}/{name}")]);
    }

    (RuntimeType::Unknown, vec![])
}

/// Try to extract the "main" field from package.json without serde.
fn read_package_json_main(source_dir: &Path) -> Option<String> {
    let content = std::fs::read_to_string(source_dir.join("package.json")).ok()?;
    let json = nojson::RawJson::parse(&content).ok()?;
    let val = json.value();
    let main_val = val.to_member("main").ok()?.optional()?;
    let s = main_val.as_string_str().ok()?;
    Some(s.to_string())
}

/// Try to find a Python entry point in the source directory.
fn find_python_entry(source_dir: &Path) -> Option<String> {
    // Common entry point names
    for name in &["main.py", "app.py", "server.py", "__main__.py"] {
        if source_dir.join(name).exists() {
            return Some(name.to_string());
        }
    }
    None
}

/// Try to find a native binary the guest can execute in the source
/// directory (non-recursive): ELF for a Linux guest, PE for a Windows
/// one — a Windows workload is never pointed at an ELF it cannot run.
fn find_native_binary_in_dir(source_dir: &Path, guest_os: TargetOs) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(source_dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let matches = match guest_os {
            TargetOs::Windows => crate::container::pe_magic::looks_like_pe(&path),
            _ => looks_like_elf(&path),
        };
        if matches {
            return Some(path);
        }
    }
    None
}

/// Collect files from source directory into CopyEntry list.
fn collect_source_copies(
    source_dir: &Path,
    layout: &GuestLayout,
) -> Result<Vec<CopyEntry>, ContainerError> {
    let mut copies = Vec::new();

    let entries = std::fs::read_dir(source_dir).map_err(|e| {
        ContainerError::BuildFailed(format!(
            "failed to read source directory '{}': {e}",
            source_dir.display()
        ))
    })?;

    for entry in entries {
        let entry = entry.map_err(|e| {
            ContainerError::BuildFailed(format!("failed to read directory entry: {e}"))
        })?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();

        // Skip common build artifacts and hidden directories
        if crate::fspriv::should_skip_build_entry(&name_str) {
            continue;
        }

        // Only emit COPY instructions for paths that would actually be copied.
        // A skipped symlink must not produce a corresponding COPY line.
        if entry
            .path()
            .symlink_metadata()
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false)
        {
            continue;
        }

        copies.push(CopyEntry {
            src: format!("source/{name_str}"),
            dst: format!("{}/{name_str}", layout.app_dir),
        });
    }

    Ok(copies)
}

/// Copy the source directory contents into the build context under "source/".
///
/// The untrusted tree cannot redirect the copy mid-walk: each file is
/// opened without following its final-component link and proven to
/// resolve inside the canonicalized `source_dir` before its bytes are
/// read from that open handle (`fspriv::safe_copy_dir`).
fn copy_source_to_context(source_dir: &Path, ctx: &BuildContext) -> Result<(), ContainerError> {
    let ctx_source = ctx.dir().join("source");
    let root = crate::fspriv::canonical_root(source_dir).map_err(|e| {
        ContainerError::BuildFailed(format!(
            "failed to canonicalize source directory '{}': {e}",
            source_dir.display()
        ))
    })?;
    crate::fspriv::safe_copy_dir(
        source_dir,
        &ctx_source,
        &root,
        0,
        &|name| crate::fspriv::should_skip_build_entry(name),
        &mut |_| {},
    )
    .map_err(|e| {
        ContainerError::BuildFailed(format!(
            "failed to stage source directory '{}': {e}",
            source_dir.display()
        ))
    })
}

/// Generate a default tag for containerize: `<dir-name>-secured:latest`.
fn make_containerize_tag(source_dir: &Path) -> String {
    let name = source_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("mcp-server");
    format!("{name}-secured:latest")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_temp_dir(label: &str) -> std::path::PathBuf {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("mcp_writ_containerize_test_{label}_{id}_{ts}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // -- infer_runtime_from_dir -----------------------------------------------

    #[test]
    fn test_detect_nodejs_from_package_json() {
        let dir = make_temp_dir("detect_node");
        fs::write(
            dir.join("package.json"),
            r#"{"name":"test","main":"server.js"}"#,
        )
        .unwrap();

        let (rt, cmd) = infer_runtime_from_dir(&dir, &guest_layout::LINUX);
        assert_eq!(rt, RuntimeType::NodeJs);
        assert_eq!(cmd, vec!["node", "/app/server.js"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_nodejs_no_main() {
        let dir = make_temp_dir("detect_node_no_main");
        fs::write(dir.join("package.json"), r#"{"name":"test"}"#).unwrap();

        let (rt, cmd) = infer_runtime_from_dir(&dir, &guest_layout::LINUX);
        assert_eq!(rt, RuntimeType::NodeJs);
        assert_eq!(cmd, vec!["npx", "."]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_python_from_requirements() {
        let dir = make_temp_dir("detect_python_req");
        fs::write(dir.join("requirements.txt"), "flask\n").unwrap();
        fs::write(dir.join("app.py"), "print('hi')").unwrap();

        let (rt, cmd) = infer_runtime_from_dir(&dir, &guest_layout::LINUX);
        assert_eq!(rt, RuntimeType::Python);
        assert_eq!(cmd, vec!["python", "/app/app.py"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_python_from_pyproject() {
        let dir = make_temp_dir("detect_python_pyp");
        fs::write(dir.join("pyproject.toml"), "[project]\nname=\"test\"\n").unwrap();
        fs::write(dir.join("main.py"), "print('hi')").unwrap();

        let (rt, cmd) = infer_runtime_from_dir(&dir, &guest_layout::LINUX);
        assert_eq!(rt, RuntimeType::Python);
        assert_eq!(cmd, vec!["python", "/app/main.py"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_python_no_entry() {
        let dir = make_temp_dir("detect_python_no_entry");
        fs::write(dir.join("setup.py"), "").unwrap();

        let (rt, cmd) = infer_runtime_from_dir(&dir, &guest_layout::LINUX);
        assert_eq!(rt, RuntimeType::Python);
        assert_eq!(cmd, vec!["python", "-m", "app"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_native_elf() {
        let dir = make_temp_dir("detect_native");
        let mut data = vec![0x7f, b'E', b'L', b'F'];
        data.extend_from_slice(&[0u8; 60]);
        fs::write(dir.join("my-server"), &data).unwrap();

        let (rt, cmd) = infer_runtime_from_dir(&dir, &guest_layout::LINUX);
        assert_eq!(rt, RuntimeType::Native);
        assert_eq!(cmd, vec!["/app/my-server"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_unknown() {
        let dir = make_temp_dir("detect_unknown");
        fs::write(dir.join("README.md"), "hello").unwrap();

        let (rt, _cmd) = infer_runtime_from_dir(&dir, &guest_layout::LINUX);
        assert_eq!(rt, RuntimeType::Unknown);

        let _ = fs::remove_dir_all(&dir);
    }

    // -- detect_runtime_from_source -------------------------------------------

    #[test]
    fn test_detect_runtime_with_override() {
        let dir = make_temp_dir("detect_override");
        fs::write(dir.join("README.md"), "hello").unwrap();

        let result = detect_runtime_from_source(&dir, Some("custom:latest"), &guest_layout::LINUX);
        assert!(result.is_ok());
        let info = result.unwrap();
        assert_eq!(info.base_image, "custom:latest");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_detect_runtime_unknown_errors() {
        let dir = make_temp_dir("detect_unknown_err");
        fs::write(dir.join("README.md"), "hello").unwrap();

        let result = detect_runtime_from_source(&dir, None, &guest_layout::LINUX);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot detect runtime"));
        assert!(err.contains("--base-image"));

        let _ = fs::remove_dir_all(&dir);
    }

    // -- collect_source_copies ------------------------------------------------

    #[test]
    fn test_collect_source_copies_skips_hidden() {
        let dir = make_temp_dir("collect_skip");
        fs::write(dir.join("app.js"), "").unwrap();
        fs::write(dir.join(".env"), "SECRET=x").unwrap();
        fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        fs::write(dir.join("node_modules/pkg/index.js"), "").unwrap();

        let copies = collect_source_copies(&dir, &guest_layout::LINUX).unwrap();
        let names: Vec<&str> = copies.iter().map(|c| c.src.as_str()).collect();
        assert!(names.contains(&"source/app.js"));
        assert!(!names.iter().any(|n| n.contains(".env")));
        assert!(!names.iter().any(|n| n.contains("node_modules")));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_collect_source_copies_includes_files() {
        let dir = make_temp_dir("collect_files");
        fs::write(dir.join("server.py"), "").unwrap();
        fs::write(dir.join("config.yaml"), "").unwrap();

        let copies = collect_source_copies(&dir, &guest_layout::LINUX).unwrap();
        assert_eq!(copies.len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    // -- make_containerize_tag ------------------------------------------------

    #[test]
    fn test_make_containerize_tag() {
        let tag = make_containerize_tag(Path::new("/home/user/my-mcp-server"));
        assert_eq!(tag, "my-mcp-server-secured:latest");
    }

    #[test]
    fn test_make_containerize_tag_simple() {
        let tag = make_containerize_tag(Path::new("myapp"));
        assert_eq!(tag, "myapp-secured:latest");
    }

    // -- command_from_package_json --------------------------------------------

    #[test]
    fn test_read_package_json_main_exists() {
        let dir = make_temp_dir("pkg_main");
        fs::write(dir.join("package.json"), r#"{"main":"index.js"}"#).unwrap();
        assert_eq!(read_package_json_main(&dir), Some("index.js".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_package_json_main_missing() {
        let dir = make_temp_dir("pkg_no_main");
        fs::write(dir.join("package.json"), r#"{"name":"test"}"#).unwrap();
        assert_eq!(read_package_json_main(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_package_json_not_found() {
        let dir = make_temp_dir("pkg_not_found");
        assert_eq!(read_package_json_main(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }

    // -- looks_like_elf ---------------------------------------------------------

    #[test]
    fn test_looks_like_elf_true() {
        let dir = make_temp_dir("is_elf_true");
        let path = dir.join("binary");
        let mut data = vec![0x7f, b'E', b'L', b'F'];
        data.extend_from_slice(&[0u8; 60]);
        fs::write(&path, &data).unwrap();
        assert!(looks_like_elf(&path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_looks_like_elf_false() {
        let dir = make_temp_dir("is_elf_false");
        let path = dir.join("script.sh");
        fs::write(&path, "#!/bin/bash\n").unwrap();
        assert!(!looks_like_elf(&path));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_looks_like_elf_nonexistent() {
        assert!(!looks_like_elf(Path::new("/nonexistent/path")));
    }
}
