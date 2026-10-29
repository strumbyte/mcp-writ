//! Skip gates and evidence handling: `MCP_WRIT_REQUIRE_*`
//! fail-instead-of-skip gates, VM test roots, and symlink-safe
//! evidence copying for CI artifact upload.

use std::path::{Component, Path, PathBuf};

/// Local development may omit Docker. The release verification job must
/// fail when a prerequisite or fixture build is unavailable instead of
/// reporting an unexecuted container test as successful.
pub fn skip_container_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_CONTAINER_TESTS").as_deref() != Ok("1"),
        "container test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_CONTAINER_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// Evidence e2e tests (`path_resolution_e2e`, `environment_e2e`,
/// `workload_hash_e2e`, and `diagnostics_e2e` via
/// [`compiled_open_path_fixture`]) may skip when a prerequisite — the
/// rustc fixture build, a sandboxed spawn, an interpreter, symlink/junction
/// creation — is unavailable. The verification job that owns the test
/// (see `docs/test-matrix.md`) must fail instead of reporting an
/// unexecuted test as successful.
pub fn skip_e2e_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_E2E_TESTS").as_deref() != Ok("1"),
        "e2e test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_E2E_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A prerequisite for the pinned real-server tests is missing (fixture not
/// acquired, interpreter absent, sandboxed spawn unavailable). With
/// `MCP_WRIT_REQUIRE_SERVER_TESTS=1` the test fails; otherwise it skips.
pub fn skip_server_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_SERVER_TESTS").as_deref() != Ok("1"),
        "real-server test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_SERVER_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A prerequisite for the Kata VM validation is missing (no container
/// engine, no `kata` runtime, no /dev/kvm, no vhost-vsock, …). The Kata
/// host job (see `docs/validation/kata.md`) must fail instead of
/// reporting an unexecuted test as successful.
pub fn skip_kata_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_KATA_TESTS").as_deref() != Ok("1"),
        "kata test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_KATA_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A prerequisite for the Apple `container` VM validation is missing (no
/// `container` CLI, the system or builder not running, no aarch64-linux
/// fixture toolchain, …). The Apple container host job (see
/// `docs/validation/apple-container.md`) must fail instead of reporting
/// an unexecuted test as successful.
pub fn skip_apple_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_APPLE_TESTS").as_deref() != Ok("1"),
        "apple container test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_APPLE_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A prerequisite for the Hyper-V isolated Windows container validation
/// is missing (non-Windows host, no Windows-mode docker engine, no rustc
/// fixture build, …). The Hyper-V host job (see
/// `docs/validation/windows-hyperv.md`) must fail instead of reporting
/// an unexecuted test as successful — a process-isolated or skipped run
/// never counts as the VM boundary.
pub fn skip_hyperv_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_HYPERV_TESTS").as_deref() != Ok("1"),
        "hyperv test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_HYPERV_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A prerequisite for the Windows Sandbox stdio relay validation is
/// missing (non-Windows host, `WindowsSandbox.exe` absent — the
/// `Containers-DisposableClientVM` feature is not enabled —, no rustc
/// fixture build, …). The sandbox host job (see
/// `docs/validation/windows-sandbox.md`) must fail instead of reporting
/// an unexecuted test as successful — a skipped run never counts as the
/// VM boundary evidence.
pub fn skip_wsb_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_WSB_TESTS").as_deref() != Ok("1"),
        "windows-sandbox test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_WSB_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A prerequisite for the WSL Containers (`wslc`) validation is missing
/// (non-Windows host, WSL below the `wslc` floor, `wslc.exe` absent, no
/// musl fixture toolchain, …). The WSLC host job (see
/// `docs/validation/wslc.md`) must fail instead of reporting an
/// unexecuted test as successful — an ordinary `wsl.exe` distro or a
/// docker daemon is never a substitute for the `wslc` session substrate.
pub fn skip_wslc_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_WSLC_TESTS").as_deref() != Ok("1"),
        "wslc test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_WSLC_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A prerequisite for the Windows isolation-mechanism comparison probe
/// is missing (non-Windows host, no rustc fixture build, …). The host
/// job (see `docs/validation/windows-isolation.md`) must fail instead of
/// reporting an unexecuted test as successful — a skipped run never
/// counts as AppContainer/PSEC/IsolationSession evidence.
pub fn skip_winiso_test(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_WINISO_TESTS").as_deref() != Ok("1"),
        "winiso test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_WINISO_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// Root for a VM validation job's scratch directories: `$env_var` when
/// the method's manual job (`scripts/validate-<method>.*`, see
/// `docs/validation/manual-ci.md`) set one, else `target/<fallback>`
/// under the checkout. Always absolute; created on first use.
pub fn vm_test_root(env_var: &str, fallback: &str) -> PathBuf {
    vm_test_root_at(
        env_var,
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("target/{fallback}")),
    )
}

/// [`vm_test_root`] with an explicit default path — for runtimes whose
/// scratch directories must live on a filesystem shareable into the
/// guest (Kata's virtiofs cannot re-export WSL2 `/mnt/*` drvfs mounts),
/// the default is the system temp dir rather than the checkout.
pub fn vm_test_root_at(env_var: &str, default: PathBuf) -> PathBuf {
    let root = std::env::var_os(env_var)
        .map(PathBuf::from)
        .unwrap_or(default);
    assert!(root.is_absolute(), "{env_var} must be an absolute path");
    std::fs::create_dir_all(&root).expect("create VM test root");
    root
}

/// Copy allowlisted files from `src_dir` into the validation job's
/// evidence directory (`$env_var/<out_name>/`), preserving relative
/// paths; missing files are skipped. Credentials, staged executables,
/// and arbitrary RPC bodies are never copied — the caller's allowlist
/// is the boundary. Any symlink on the source path is rejected without
/// being followed: the guest shares these session dirs, so a planted
/// link must not redirect the copy onto a host file the allowlist
/// never named.
pub fn copy_evidence_files(env_var: &str, out_name: &str, src_dir: &Path, files: &[&str]) {
    let Some(root) = std::env::var_os(env_var) else {
        return;
    };
    let out = PathBuf::from(root).join(out_name);
    for file in files {
        let src = src_dir.join(file);
        // Non-following metadata: the entry itself must be a real file,
        // and no ancestor component may be a symlink.
        let real_file = std::fs::symlink_metadata(&src)
            .map(|md| md.file_type().is_file())
            .unwrap_or(false);
        if !real_file {
            continue;
        }
        let linked = src.ancestors().skip(1).any(|a| {
            std::fs::symlink_metadata(a)
                .map(|md| md.file_type().is_symlink())
                .unwrap_or(true)
        });
        if linked {
            eprintln!("evidence copy skipped (symlink in path): {}", src.display());
            continue;
        }
        if let Err(e) = copy_one(src_dir, file, &out.join(file)) {
            eprintln!("evidence copy failed: {e}");
        }
    }
}

/// Copy one allowlisted file: the source is resolved component-by-
/// component beneath an already-opened `src_dir` handle so a directory
/// swapped for a symlink between validation and opening cannot redirect
/// the read outside the approved session dir. The destination is
/// created fresh with restrictive permissions — it never clobbers or
/// follows an existing entry — and takes the source file's permissions
/// once the bytes land, mirroring what `fs::copy` preserved.
fn copy_one(src_dir: &Path, rel: &str, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut input = open_below_nofollow(src_dir, rel)?;
    let mut opt = std::fs::OpenOptions::new();
    opt.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opt.mode(0o600);
    }
    let mut output = opt.open(dst)?;
    std::io::copy(&mut input, &mut output)?;
    output.set_permissions(input.metadata()?.permissions())
}

/// Open `rel` (a relative path of allowlisted components) beneath `dir`,
/// resolving every component relative to an already-opened directory
/// descriptor and refusing symlinks — resolution stays confined to the
/// approved source root even if the guest swaps a mid-path component.
#[cfg(unix)]
fn open_below_nofollow(dir: &Path, rel: &str) -> std::io::Result<std::fs::File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::{FromRawFd, IntoRawFd};

    let mut fd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(dir)?
        .into_raw_fd();
    let comps: Vec<_> = Path::new(rel).components().collect();
    for (i, comp) in comps.iter().enumerate() {
        let last = i + 1 == comps.len();
        let Component::Normal(name) = comp else {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            unsafe { libc::close(fd) };
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "evidence path must contain only normal components",
            ));
        };
        let name = CString::new(name.as_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "nul in evidence path")
        })?;
        let flags = libc::O_RDONLY
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if last { 0 } else { libc::O_DIRECTORY };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        let next = unsafe { libc::openat(fd, name.as_ptr(), flags) };
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::close(fd) };
        if next < 0 {
            return Err(std::io::Error::last_os_error());
        }
        fd = next;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Windows has no `openat`; each component is opened without following
/// a reparse point and re-validated — a swapped-in link opens the link
/// object itself, which the attribute check rejects. The leaf's final
/// resolved path must equal the approved absolute path, so an ancestor
/// reparse point substituted mid-walk cannot redirect the read outside
/// the approved source root.
#[cfg(windows)]
fn open_below_nofollow(dir: &Path, rel: &str) -> std::io::Result<std::fs::File> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, VOLUME_NAME_DOS};

    // Backup semantics is required to open a directory handle at all;
    // reparse opens expose the link object instead of following it.
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

    let invalid = |msg: &str| std::io::Error::new(std::io::ErrorKind::InvalidInput, msg.to_owned());
    let mut expected = std::fs::canonicalize(dir)?;
    let mut cur = dir.to_path_buf();
    let comps: Vec<_> = Path::new(rel).components().collect();
    for (i, comp) in comps.iter().enumerate() {
        let Component::Normal(name) = comp else {
            return Err(invalid("evidence path must contain only normal components"));
        };
        cur.push(name);
        expected.push(name);
        let last = i + 1 == comps.len();
        let flags =
            FILE_FLAG_OPEN_REPARSE_POINT | if last { 0 } else { FILE_FLAG_BACKUP_SEMANTICS };
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(&cur)?;
        let md = f.metadata()?;
        if md.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid("evidence path component is a reparse point"));
        }
        let ty = md.file_type();
        if !last {
            if !ty.is_dir() {
                return Err(invalid("evidence path component is not a directory"));
            }
            continue;
        }
        if !ty.is_file() {
            return Err(invalid("evidence path leaf is not a file"));
        }
        // The open resolved every ancestor in one go: a reparse point
        // substituted mid-path makes the handle's final path land
        // outside the approved base.
        let mut buf = vec![0u16; 512];
        let len = loop {
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let n = unsafe {
                GetFinalPathNameByHandleW(HANDLE(f.as_raw_handle() as _), &mut buf, VOLUME_NAME_DOS)
            };
            if n == 0 {
                return Err(std::io::Error::last_os_error());
            }
            if (n as usize) < buf.len() {
                break n as usize;
            }
            buf.resize(n as usize + 1, 0);
        };
        if std::ffi::OsString::from_wide(&buf[..len]) != expected {
            return Err(invalid(
                "evidence path resolved outside the approved directory",
            ));
        }
        return Ok(f);
    }
    unreachable!("empty evidence path")
}

/// [`copy_evidence_files`] with the session root's own directory name —
/// one evidence directory per session tempdir.
pub fn copy_session_evidence(env_var: &str, session_root: &Path, files: &[&str]) {
    let Some(name) = session_root.file_name() else {
        return;
    };
    copy_evidence_files(env_var, &name.to_string_lossy(), session_root, files);
}

/// `Option<f64>` as a JSON number literal — `null` when absent, so an
/// unavailable measurement never masquerades as a recorded one.
pub fn json_num(v: Option<f64>) -> String {
    v.map(|f| format!("{f:.3}"))
        .unwrap_or_else(|| "null".into())
}
