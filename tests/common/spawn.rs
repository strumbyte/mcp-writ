//! Sandboxed spawn helpers and the fixture policy snippets that
//! authorize them.

use std::path::Path;

use super::paths::policy_path_str;

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
    // Fixture policy/audit paths live under %TEMP% — on hosts whose
    // temp ACL grants another principal replace access the guard's
    // ancestry gate would refuse them. That refusal is host-ACL
    // dependent and not what these tests exercise, so they opt out the
    // same way `tests/integration.rs` and `tool_enforcement_e2e` do.
    cmd.env("MCP_WRIT_ALLOW_REPLACEABLE_PATHS", "1");
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
    let f = |p: &Path| policy_path_str(p);
    // Schema-v2 rejects an identical `allow` twice in one `filesystem`
    // block — the probe living inside a granted dir (`exe.parent()` ∈
    // `unix_dirs`) or a caller dir overlapping the fixed runtime list
    // would emit the same line twice.
    let mut seen = std::collections::HashSet::new();
    let mut emit = |out: &mut String, line: String| {
        if seen.insert(line.clone()) {
            out.push_str(&line);
        }
    };
    let mut out = String::new();
    if cfg!(unix) {
        // Landlock PathBeneath covers the whole subtree beneath a granted
        // directory. Runtime dirs are needed for the dynamically linked exe.
        for dir in unix_dirs {
            emit(
                &mut out,
                format!("        allow \"{}\" mode=\"read\"\n", f(dir)),
            );
        }
        if let Some(exe_dir) = exe.parent() {
            emit(
                &mut out,
                format!("        allow \"{}\" mode=\"read\"\n", f(exe_dir)),
            );
        }
        for dir in [
            "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev",
        ] {
            if Path::new(dir).exists() {
                emit(&mut out, format!("        allow \"{dir}\" mode=\"read\"\n"));
            }
        }
    } else if cfg!(windows) {
        // Per-object DACL grants: the executable image, the directories for
        // traversal, and each file the child must actually open.
        for path in windows_objects {
            emit(
                &mut out,
                format!("        allow \"{}\" mode=\"read\"\n", f(path)),
            );
        }
    }
    out
}

/// Linux seccomp baseline for the tests' own fixture executables (a `rustc`
/// -built image). Real Node/Python servers use the runtime files under
/// `examples/policies/runtime/` instead — `host_defaults_kdl` reads them.
///
/// `pub` for policies that are not built by [`sandboxed_policy`] but must
/// still satisfy the Linux spawn-time requirement that `syscalls.allowed`
/// include `execve`.
pub const FIXTURE_SYSCALLS_KDL: &str = concat!(
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
