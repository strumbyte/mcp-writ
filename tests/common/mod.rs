#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static AUDIT_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
static AUDIT_SEQ: AtomicU64 = AtomicU64::new(0);

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

/// Evidence e2e tests (`diagnostics_e2e`, `path_resolution_e2e`) may skip
/// when a prerequisite — the rustc fixture build, a sandboxed spawn,
/// symlink/junction creation — is unavailable. The release verification
/// job must fail instead of reporting an unexecuted test as successful.
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

/// Unique fail-closed audit log path for spawned `mcp-writ run` processes.
pub fn next_audit_log_path() -> PathBuf {
    let dir = AUDIT_DIR.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("mcp_writ_audit_")
            .tempdir()
            .expect("failed to create audit log temp directory")
    });
    dir.path().join(format!(
        "audit-{}.jsonl",
        AUDIT_SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Path to the compiled mcp-writ binary (from cargo build).
pub fn mcp_writ_bin() -> PathBuf {
    // cargo test puts the test binary in target/debug/deps/;
    // the main binary is in target/debug/
    let mut path = std::env::current_exe().unwrap();
    // Go up from deps/ to debug/
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    let exe_name = format!("mcp-writ{}", std::env::consts::EXE_SUFFIX);
    path.join(exe_name)
}

/// Argv for a Python interpreter plus a fixture script under `tests/`.
pub fn python3_script_argv(relative_script: &str) -> Vec<String> {
    let script = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_script);
    if cfg!(windows) {
        vec![
            "py".to_string(),
            "-3".to_string(),
            script.to_string_lossy().into_owned(),
        ]
    } else {
        vec!["python3".to_string(), script.to_string_lossy().into_owned()]
    }
}

/// Argv for a stdin→stdout echo process (mock MCP server).
///
/// Linux CI has `cat`. Windows developer machines often do not put Git's
/// `cat.exe` on PATH, so tests use the Python launcher instead.
pub fn echo_stdio_argv() -> Vec<String> {
    if cfg!(windows) {
        let script = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("echo_stdio.py");
        vec![
            "py".to_string(),
            "-3".to_string(),
            script.to_string_lossy().into_owned(),
        ]
    } else {
        vec!["cat".to_string()]
    }
}

/// Compile `tests/fixtures/mcp_servers/open_path_server.rs` once per test
/// binary with plain `rustc` (no cargo, no crates — same contract the
/// fixture file documents). `None` when rustc is unavailable or fails;
/// callers should skip with a diagnostic rather than fail.
pub fn compiled_open_path_fixture() -> Option<PathBuf> {
    static FIXTURE_EXE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE_EXE
        .get_or_init(|| {
            let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join("mcp_servers")
                .join("open_path_server.rs");
            let dir = match tempfile::Builder::new()
                .prefix("mcp_writ_open_path_build_")
                .tempdir()
            {
                Ok(d) => d,
                Err(e) => {
                    skip_e2e_test(&format!("fixture build tempdir failed: {e}"));
                    return None;
                }
            };
            let out = dir
                .path()
                .join(format!("open_path_server{}", std::env::consts::EXE_SUFFIX));
            let status = std::process::Command::new("rustc")
                .arg("-O")
                .arg("-o")
                .arg(&out)
                .arg(&src)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() && out.exists() => {
                    let kept = dir.keep();
                    Some(kept.join(format!("open_path_server{}", std::env::consts::EXE_SUFFIX)))
                }
                Ok(s) => {
                    skip_e2e_test(&format!("rustc -O open_path_server.rs failed: {s}"));
                    None
                }
                Err(e) => {
                    skip_e2e_test(&format!("rustc unavailable: {e}"));
                    None
                }
            }
        })
        .clone()
}

/// Check if Docker daemon is available and running.
///
/// Uses `docker info` (not `--version`) to verify daemon connectivity, because
/// `--version` only checks the CLI binary and succeeds even when the daemon is stopped.
/// Uses a 5-second timeout to avoid hanging if the daemon is unresponsive.
pub fn docker_available() -> bool {
    let child = Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    match child {
        Ok(mut child) => {
            let start = std::time::Instant::now();
            loop {
                match child.try_wait() {
                    Ok(Some(status)) => break status.success(),
                    Ok(None) => {
                        if start.elapsed().as_secs() > 5 {
                            let _ = child.kill();
                            let _ = child.wait(); // ゾンビプロセスを回避するためにプロセスを回収
                            break false;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(_) => break false,
                }
            }
        }
        Err(_) => false,
    }
}

// ─── sandboxed spawn helpers ─────────────────────────────────────────────
// Shared by `path_resolution_e2e` and `real_servers_e2e`. These never set
// `MCP_WRIT_SKIP_SANDBOX`, so the Warden actually applies.

/// `mcp-writ run` spawn helper for evidence runs. `dry_run` adds `--dry-run`
/// (Auditor/manifest checks still apply; the OS sandbox does not).
/// `cwd` sets the guard's working directory, which the spawned server
/// inherits — needed when a relative argument must resolve under a
/// controlled, ungranted directory.
///
/// Never sets `MCP_WRIT_SKIP_SANDBOX`, so a sandboxed run actually applies
/// the Warden.
pub fn spawn_guard(
    policy_path: &Path,
    audit_log: &Path,
    child_argv: &[String],
    extra_env: &[(&str, &str)],
    dry_run: bool,
    cwd: Option<&Path>,
) -> tokio::process::Child {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        policy_path.to_str().expect("policy path utf-8"),
        "--audit-log",
        audit_log.to_str().expect("audit path utf-8"),
    ]);
    if dry_run {
        cmd.arg("--dry-run");
    }
    cmd.arg("--");
    cmd.args(child_argv);
    // A parent-level skip var must not leak into the evidence run.
    cmd.env_remove("MCP_WRIT_SKIP_SANDBOX");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    cmd.stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary - did you run `cargo build`?")
}

/// `mcp-writ run` spawn helper for sandboxed evidence runs: no
/// `MCP_WRIT_SKIP_SANDBOX` so the Warden actually applies.
pub fn spawn_guard_sandboxed(
    policy_path: &Path,
    audit_log: &Path,
    child_argv: &[String],
    extra_env: &[(&str, &str)],
) -> tokio::process::Child {
    spawn_guard(policy_path, audit_log, child_argv, extra_env, false, None)
}

/// Filesystem grants for a sandboxed run, split by OS grant semantics:
/// Linux Landlock `PathBeneath` covers a whole subtree, while the Windows
/// AppContainer DACL grant is per-object (non-recursive) so individual
/// files must be named.
///
/// `unix_dirs` are directories covered by Landlock subtree grants;
/// `windows_objects` are the per-object DACL grants (the executable image,
/// directories for traversal, and each file the child must open). `exe` is
/// the child image; its parent directory is granted on Unix for the loader.
/// Entries must be literal paths — `/**` glob suffixes are not expanded by
/// the Windows DACL grant or the macOS SBPL `subpath` emitter.
pub fn sandbox_fs_allows(unix_dirs: &[&Path], windows_objects: &[&Path], exe: &Path) -> String {
    let f = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let mut out = String::new();
    if cfg!(unix) {
        // Landlock PathBeneath covers the whole subtree beneath a granted
        // directory. Runtime dirs are needed for the dynamically linked exe.
        for dir in unix_dirs {
            out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(dir)));
        }
        if let Some(exe_dir) = exe.parent() {
            out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(exe_dir)));
        }
        for dir in [
            "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev",
        ] {
            if Path::new(dir).exists() {
                out.push_str(&format!("        allow \"{dir}\" mode=\"read\"\n"));
            }
        }
    } else if cfg!(windows) {
        // Per-object DACL grants: the executable image, the directories for
        // traversal, and each file the child must actually open.
        for path in windows_objects {
            out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(path)));
        }
    }
    out
}

/// Linux seccomp baseline for the tests' own fixture executables (a `rustc`
/// -built image). Real Node/Python servers use the runtime files under
/// `examples/policies/runtime/` instead — `host_defaults_kdl` reads them.
const FIXTURE_SYSCALLS_KDL: &str = concat!(
    "    syscalls {\n",
    "        allow \"read\" \"write\" \"close\" \"openat\" \"open\" \"newfstatat\" \"stat\" ",
    "\"fstat\" \"lstat\" \"lseek\" \"mmap\" \"mprotect\" \"munmap\" \"brk\" ",
    "\"rt_sigaction\" \"rt_sigprocmask\" \"rt_sigreturn\" \"ioctl\" \"pread64\" ",
    "\"pwrite64\" \"readv\" \"writev\" \"getcwd\" \"chdir\" \"fcntl\" \"flock\" ",
    "\"fsync\" \"dup\" \"dup2\" \"dup3\" \"pipe\" \"pipe2\" \"clone\" \"clone3\" ",
    "\"execve\" \"exit\" \"exit_group\" \"wait4\" \"kill\" \"getpid\" \"getppid\" ",
    "\"getuid\" \"getgid\" \"geteuid\" \"getegid\" \"setsid\" \"sigaltstack\" ",
    "\"futex\" \"nanosleep\" \"clock_gettime\" \"clock_nanosleep\" \"getrandom\" ",
    "\"prctl\" \"arch_prctl\" \"set_tid_address\" \"set_robust_list\" ",
    "\"sched_getaffinity\" \"sched_yield\" \"madvise\" \"prlimit64\" \"rseq\" ",
    "\"getdents64\" \"access\" \"readlink\" \"epoll_create1\" \"epoll_ctl\" ",
    "\"epoll_pwait\" \"epoll_wait\" \"poll\" \"select\"\n",
    "    }\n"
);

/// Compose a minimal sandboxed policy: `defaults` with the given fs allow
/// lines plus the fixture syscall baseline (Unix), `logging`, and the
/// caller's `server` block verbatim.
pub fn sandboxed_policy(fs_allows: &str, server_kdl: &str) -> String {
    let syscalls = if cfg!(unix) { FIXTURE_SYSCALLS_KDL } else { "" };
    format!(
        "policy version=1\ndefaults {{\n    filesystem {{\n        secret-overlay #true\n{fs_allows}    }}\n{syscalls}}}\nlogging level=\"info\" fail_closed=#false\n{server_kdl}"
    )
}

// ─── real-server fixture layout ──────────────────────────────────────────

/// Root of the pinned real-server fixtures (`tests/fixtures/real_servers`).
/// `MCP_WRIT_REAL_SERVERS_DIR` overrides it so the missing-prerequisite
/// path is exercisable without touching the checkout.
pub fn real_servers_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("MCP_WRIT_REAL_SERVERS_DIR") {
        return PathBuf::from(dir);
    }
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/real_servers")
}

/// Read the syscall allowlist out of `examples/policies/runtime/<name>.kdl`
/// so the host `defaults` block and the runtime file share one source —
/// the observed lists are not duplicated in test code.
fn runtime_syscalls(runtime: &str) -> Vec<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("examples/policies/runtime")
        .join(format!("{runtime}.kdl"));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let mut names = Vec::new();
    let mut in_syscalls = false;
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("//") {
            continue;
        }
        if t.starts_with("syscalls") {
            in_syscalls = true;
            continue;
        }
        if in_syscalls {
            if t.starts_with('}') {
                break;
            }
            let mut chars = t.chars();
            loop {
                match chars.next() {
                    Some('"') => {
                        let name: String = chars.by_ref().take_while(|&c| c != '"').collect();
                        if !name.is_empty() {
                            names.push(name);
                        }
                    }
                    Some(_) => continue,
                    None => break,
                }
            }
        }
    }
    names
}

fn push_unique(dirs: &mut Vec<PathBuf>, p: PathBuf) {
    // Strip a `\\?\` verbatim prefix: the Windows DACL grant and `exists()`
    // checks in the sandbox path need a regular path spelling.
    let p = match p.to_string_lossy().strip_prefix(r"\\?\") {
        Some(rest) => PathBuf::from(rest),
        None => p,
    };
    if !dirs.contains(&p) {
        dirs.push(p);
    }
}

/// The `home =` line of a `pyvenv.cfg` names the base interpreter prefix —
/// needed on Windows where `Scripts\python.exe` is a copy, not a symlink,
/// so canonicalization alone does not reach the base installation.
fn pyvenv_home(venv_dir: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(venv_dir.join("pyvenv.cfg")).ok()?;
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("home")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            return Some(PathBuf::from(value.trim()));
        }
    }
    None
}

/// Build the host-specific `defaults { ... }` block for a real-server run.
///
/// `argv0` is the child argv[0]. The block grants, read-only:
/// - the directory containing `argv0` and its parent (the install prefix)
/// - the same for the resolved executable (`PATH` lookup + canonicalize,
///   which follows a Unix venv's `bin/python` symlink to the base image)
/// - for a Windows venv, the base interpreter prefix from `pyvenv.cfg`
/// - the pinned fixture package trees (`node_modules`, `.venv`)
/// - platform runtime dirs (Linux shared-library/config roots; macOS adds
///   the fixed system paths its SBPL profile also grants)
///
/// On Linux the `syscalls` block carries the observed baseline read from
/// `examples/policies/runtime/{node,python}.kdl` — single source, no
/// duplicated constants.
pub fn host_defaults_kdl(argv0: &str) -> String {
    let mut read_dirs: Vec<PathBuf> = Vec::new();

    // The path as given — covers a venv's bin/Scripts and the `.venv` root.
    let given = Path::new(argv0);
    if (given.is_absolute() || argv0.contains(['/', '\\']))
        && let Some(parent) = given.parent()
    {
        push_unique(&mut read_dirs, parent.to_path_buf());
        if let Some(prefix) = parent.parent() {
            push_unique(&mut read_dirs, prefix.to_path_buf());
        }
    }
    if let Ok(resolved) = mcp_writ::verifier::hash::resolve_command_path(argv0) {
        if let Some(parent) = resolved.parent() {
            push_unique(&mut read_dirs, parent.to_path_buf());
            if let Some(prefix) = parent.parent() {
                push_unique(&mut read_dirs, prefix.to_path_buf());
            }
        }
        // A Windows venv `Scripts\python.exe` is not a symlink; recover the
        // base interpreter prefix from pyvenv.cfg.
        for base in [given, resolved.as_path()] {
            for anc in base.ancestors() {
                if anc.file_name().is_some_and(|n| n == ".venv")
                    && let Some(home) = pyvenv_home(anc)
                {
                    if let Some(prefix) = home.parent() {
                        push_unique(&mut read_dirs, prefix.to_path_buf());
                    }
                    push_unique(&mut read_dirs, home);
                }
            }
        }
    }
    // The pinned package trees the server loads from (`node` also carries
    // the Windows realpath stub preloaded via `--require`).
    for sub in ["node", "python/.venv"] {
        let d = real_servers_dir().join(sub);
        if d.exists() {
            push_unique(&mut read_dirs, d);
        }
    }
    // Platform runtime dirs the interpreters touch.
    #[cfg(target_os = "linux")]
    for dir in [
        "/usr/lib",
        "/usr/bin",
        "/lib",
        "/lib64",
        "/usr/local/lib",
        "/etc/ssl",
        "/etc",
        "/proc",
        "/dev",
    ] {
        if Path::new(dir).exists() {
            push_unique(&mut read_dirs, PathBuf::from(dir));
        }
    }
    #[cfg(target_os = "macos")]
    for dir in [
        "/usr/lib",
        "/System/Library",
        "/usr/share",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
        "/usr/libexec",
        "/private/etc/ssl",
    ] {
        if Path::new(dir).exists() {
            push_unique(&mut read_dirs, PathBuf::from(dir));
        }
    }

    let f = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let mut out = String::from("defaults {\n    filesystem {\n");
    for dir in &read_dirs {
        // Literal directory paths only: Landlock covers the subtree, the
        // macOS SBPL emitter maps them to `subpath`, and the Windows DACL
        // grant skips nonexistent paths — a `/**` suffix never exists.
        out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(dir)));
    }
    // Interpreters open /dev/null O_RDWR (libuv stream setup, Python
    // subprocess stdio): a read grant alone cannot satisfy the write half.
    #[cfg(target_os = "linux")]
    if Path::new("/dev/null").exists() {
        out.push_str("        allow \"/dev/null\" mode=\"write\"\n");
    }
    out.push_str("    }\n");

    #[cfg(target_os = "linux")]
    {
        let runtime = match mcp_writ::legislator::source_bind::interpreter_from_command(argv0) {
            Some(mcp_writ::legislator::source_bind::InterpreterKind::Node) => Some("node"),
            Some(mcp_writ::legislator::source_bind::InterpreterKind::Python) => Some("python"),
            _ => None,
        };
        if let Some(runtime) = runtime {
            let names = runtime_syscalls(runtime);
            assert!(
                !names.is_empty(),
                "examples/policies/runtime/{runtime}.kdl carries no syscall allowlist"
            );
            out.push_str("    syscalls {\n        allow");
            for name in &names {
                out.push_str(&format!(" \"{name}\""));
            }
            out.push_str("\n    }\n");
        }
    }
    out.push_str("}\n");
    out
}
