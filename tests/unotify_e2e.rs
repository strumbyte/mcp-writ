//! End-to-end tests for `unotify-run` — the PR-07 Linux IP-layer PoC
//! (improvement plan §1.3(a): seccomp user-notification supervision of
//! `connect(2)`).
//!
//! Each test spawns the real `mcp-writ` binary: policy load →
//! capability probe → supervised spawn (no_new_privs + Landlock +
//! notification filter + policy seccomp) → in-process supervisor →
//! audit/report assertions. The workload is
//! `tests/fixtures/unotify/connect_probe.rs`, compiled here with the
//! toolchain's `rustc` — no extra dependencies.
//!
//! Every test skips via `common::skip_e2e_test` when the kernel lacks
//! user notification / CONTINUE — `check_support()` is the same probe
//! the command runs, so a skip mirrors the command's own refusal path.
//! `MCP_WRIT_REQUIRE_E2E_TESTS=1` turns the skip into a failure, so a
//! mandatory run can never pass unexecuted.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

mod common;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// ─── fixture / policy helpers ────────────────────────────────────────

/// Compile `tests/fixtures/unotify/connect_probe.rs` once per test
/// binary — parallel tests must not compile to the same output path
/// concurrently, so the build runs under a `OnceLock` and every
/// caller gets the cached path.
fn fixture() -> PathBuf {
    static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/unotify-e2e");
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("connect_probe");
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/unotify/connect_probe.rs");
        let need = !bin.exists()
            || std::fs::metadata(&src).unwrap().modified().unwrap()
                > std::fs::metadata(&bin).unwrap().modified().unwrap();
        if need {
            let status = Command::new("rustc")
                .args(["-O", "-o"])
                .arg(&bin)
                .arg(&src)
                .status()
                .expect("rustc must exist — cargo test ran under a toolchain");
            assert!(status.success(), "fixture compile failed");
        }
        bin
    })
    .clone()
}

/// A workspace-private temp dir that survives a failed run for
/// inspection (next run truncates it).
fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mcp-writ-unotify-e2e-{}-{}",
        std::process::id(),
        tag
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fixture policy: `deny cidr="192.0.2.0/24"` + `deny host="*"`
/// (deny-all posture) — every allow the tests use comes from the
/// dynamic allowlist snapshot. The syscall list is the Landlock-era
/// baseline plus `socket`/`connect` — connect must be syscall-allowed
/// for the notification to ever fire (an ERRNO verdict from the policy
/// filter wins over USER_NOTIF).
fn write_policy(dir: &Path) -> PathBuf {
    let policy = dir.join("policy.kdl");
    let body = r#"policy version=1

defaults {
    filesystem {
        allow "/" mode="read"
    }
    syscalls {
        allow "read" "write" "open" "openat" "close" "fstat" "newfstatat"
        allow "stat" "lstat" "statx" "access" "faccessat" "faccessat2" "getcwd" "mmap" "munmap"
        allow "pread64" "rt_sigaction" "rt_sigprocmask" "rt_sigreturn"
        allow "brk" "exit_group" "readv" "writev" "lseek" "ioctl" "fcntl"
        allow "getdents64" "readlink" "readlinkat" "getrandom"
        allow "clone" "clone3" "fork" "execve" "execveat" "exit" "wait4" "pipe" "pipe2" "dup" "dup2" "dup3"
        allow "getpid" "getppid" "getuid" "getgid" "geteuid" "getegid"
        allow "mprotect" "madvise" "sigaltstack"
        allow "clock_gettime" "nanosleep" "set_tid_address" "set_robust_list" "rseq"
        allow "prlimit64" "prctl" "arch_prctl" "sched_getaffinity" "sched_yield"
        allow "socket" "connect" "setsockopt" "getsockopt"
    }
    network {
        deny cidr="192.0.2.0/24"
        deny host="*"
    }
    logging {
        fail_closed #false
    }
}

server "probe" {
}
"#;
    std::fs::write(&policy, body).unwrap();
    policy
}

/// Write a `DynamicAllowList::export_to`-shaped snapshot granting
/// `grants` (addr → name) with a fresh 300s TTL.
fn write_allowlist(dir: &Path, grants: &[(&str, &str)]) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let entries: Vec<String> = grants
        .iter()
        .map(|(name, addr)| {
            format!(
                r#"{{"name":"{name}","addr":"{addr}","expires_at_unix_secs":{}}}"#,
                now + 300
            )
        })
        .collect();
    let path = dir.join("allowlist.json");
    std::fs::write(
        &path,
        format!(
            r#"{{"schema_version":"1.0","generated_at_unix_secs":{now},"entries":[{}]}}"#,
            entries.join(",")
        ),
    )
    .unwrap();
    path
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run `mcp-writ unotify-run … -- <fixture> <addr>` with a hard
/// timeout — a wedged supervisor must surface as a failure, not a hang.
fn unotify_run(dir: &Path, policy: &Path, extra: &[&str], addr: &str) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["unotify-run", "--policy"])
        .arg(policy)
        .args(["--server", "probe"])
        .args(extra)
        .arg("--")
        .arg(fixture())
        .arg(addr)
        .current_dir(dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    run_with_timeout(&mut cmd)
}

fn run_with_timeout(cmd: &mut Command) -> Run {
    fn drain(mut pipe: impl std::io::Read + Send + 'static) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut s = String::new();
            std::io::Read::read_to_string(&mut pipe, &mut s).ok();
            s
        })
    }
    let mut child = cmd.spawn().expect("spawn mcp-writ");
    // Drain stdout/stderr on threads — a full pipe would block the
    // child's next write, wedge it alive, and trip a false timeout.
    let stdout_thr = drain(child.stdout.take().unwrap());
    let stderr_thr = drain(child.stderr.take().unwrap());
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() >= TEST_TIMEOUT {
            // Reap before panicking — an orphaned child keeps the
            // listener/pipe fds alive and can outlive the test.
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thr.join();
            let _ = stderr_thr.join();
            panic!("unotify-run exceeded {TEST_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Run {
        code: status.code().unwrap_or(-1),
        stdout: stdout_thr.join().unwrap_or_default(),
        stderr: stderr_thr.join().unwrap_or_default(),
    }
}

/// Every `sandbox.network_denied` record in the audit JSONL.
fn denied_records(audit: &Path) -> Vec<String> {
    let body = std::fs::read_to_string(audit).unwrap_or_default();
    body.lines()
        .filter(|l| l.contains("sandbox.network_denied"))
        .map(|l| l.to_string())
        .collect()
}

/// Whether the kernel runs the PoC. An unsupported kernel routes
/// through the common skip helper — `MCP_WRIT_REQUIRE_E2E_TESTS=1`
/// turns it into a failure instead of a silently-passing skip.
fn supported() -> bool {
    match mcp_writ::warden::unotify::check_support() {
        Ok(()) => true,
        Err(e) => {
            common::skip_e2e_test(&format!("kernel lacks unotify support: {e}"));
            false
        }
    }
}

// ─── tests ───────────────────────────────────────────────────────────

/// A direct-IP connect inside `deny cidr=` is refused at the IP layer
/// and audited as `layer=ip decision=deny-cidr` — the denied half of
/// the PoC contract.
#[test]
fn denied_cidr_connect_is_refused_and_audited() {
    if !supported() {
        return;
    }
    let dir = workdir("denied-cidr");
    let policy = write_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let run = unotify_run(
        &dir,
        &policy,
        &["--audit-log", audit_arg.as_str()],
        "192.0.2.1:9",
    );
    assert_eq!(run.code, 10, "stderr: {}", run.stderr);
    assert!(
        run.stdout.contains("errno=13"),
        "expected EACCES from the workload, got: {}",
        run.stdout
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().any(|l| l.contains("layer=ip")
            && l.contains("dest=192.0.2.1")
            && l.contains("decision=deny-cidr")),
        "audit must carry a layer=ip deny-cidr record; got {denied:?}"
    );
    assert!(
        denied.iter().all(|l| l.contains(r#""action":"denied""#)),
        "denial records must use action=denied"
    );
}

/// A connect with no matching rule is refused under deny-all as
/// `decision=not-allowed` — the same vocabulary the name layer emits.
#[test]
fn unmatched_connect_denied_under_deny_all() {
    if !supported() {
        return;
    }
    let dir = workdir("deny-all");
    let policy = write_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let run = unotify_run(
        &dir,
        &policy,
        &["--audit-log", audit_arg.as_str()],
        "127.0.0.1:9",
    );
    assert_eq!(run.code, 10, "stderr: {}", run.stderr);
    let denied = denied_records(&audit);
    assert!(
        denied
            .iter()
            .any(|l| l.contains("decision=not-allowed") && l.contains("dest=127.0.0.1")),
        "expected a not-allowed denial for 127.0.0.1; got {denied:?}"
    );
}

/// A TTL-scoped dynamic grant (the PR-06 contract, via the exported
/// snapshot file) allows a connect that deny-all would otherwise kill;
/// the continued syscall then meets the kernel's real ECONNREFUSED —
/// proving the connect actually ran.
#[test]
fn dynamic_grant_allows_connect() {
    if !supported() {
        return;
    }
    let dir = workdir("grant");
    let policy = write_policy(&dir);
    let allowlist = write_allowlist(&dir, &[("loopback.example", "127.0.0.1")]);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let allow_arg = allowlist.display().to_string();
    let run = unotify_run(
        &dir,
        &policy,
        &[
            "--audit-log",
            audit_arg.as_str(),
            "--allowlist",
            allow_arg.as_str(),
        ],
        "127.0.0.1:9",
    );
    // ECONNREFUSED (111) maps to exit 0 — the connect reached the kernel.
    assert_eq!(
        run.code, 0,
        "granted connect should continue to the kernel; stderr: {} stdout: {}",
        run.stderr, run.stdout
    );
    assert!(
        run.stdout.contains("errno=111") || run.stdout.contains("connected"),
        "expected kernel-side refusal, got: {}",
        run.stdout
    );
    // The grant path produces no denial record for the granted dest.
    let denied = denied_records(&audit);
    assert!(
        denied.iter().all(|l| !l.contains("dest=127.0.0.1")),
        "granted destination must not be denied; got {denied:?}"
    );
}

/// An expired snapshot entry is stale the moment it is written — the
/// supervisor's own clock decides, so a just-expired grant denies.
#[test]
fn expired_grant_denies() {
    if !supported() {
        return;
    }
    let dir = workdir("expired");
    let policy = write_policy(&dir);
    // Write a grant whose expiry is already in the past.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let allowlist = dir.join("allowlist.json");
    std::fs::write(
        &allowlist,
        format!(
            r#"{{"schema_version":"1.0","generated_at_unix_secs":{now},"entries":[{{"name":"stale.example","addr":"127.0.0.1","expires_at_unix_secs":{}}}]}}"#,
            now.saturating_sub(1)
        ),
    )
    .unwrap();
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let allow_arg = allowlist.display().to_string();
    let run = unotify_run(
        &dir,
        &policy,
        &[
            "--audit-log",
            audit_arg.as_str(),
            "--allowlist",
            allow_arg.as_str(),
        ],
        "127.0.0.1:9",
    );
    assert_eq!(run.code, 10, "stderr: {}", run.stderr);
    let denied = denied_records(&audit);
    assert!(
        denied
            .iter()
            .any(|l| l.contains("decision=not-allowed") && l.contains("dest=127.0.0.1")),
        "expired grant must not allow; got {denied:?}"
    );
}

/// `--report` carries the capability block, the honest two-layer
/// egress disposition, and the supervisor counters — the machine-
/// readable statement of what enforced what.
#[test]
fn report_records_capability_and_layers() {
    if !supported() {
        return;
    }
    let dir = workdir("report");
    let policy = write_policy(&dir);
    let report = dir.join("report.json");
    let report_arg = report.display().to_string();
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let run = unotify_run(
        &dir,
        &policy,
        &[
            "--audit-log",
            audit_arg.as_str(),
            "--report",
            report_arg.as_str(),
        ],
        "192.0.2.1:9",
    );
    assert_eq!(run.code, 10);
    let body = std::fs::read_to_string(&report).expect("report file");
    let parsed = nojson::RawJson::parse(&body).expect("report must parse");
    let cap = parsed
        .value()
        .to_member("capability")
        .unwrap()
        .required()
        .unwrap();
    assert_eq!(
        cap.to_member("mechanism")
            .unwrap()
            .required()
            .unwrap()
            .to_unquoted_string_str()
            .unwrap(),
        "seccomp-user-notif"
    );
    assert_eq!(
        cap.to_member("syscall")
            .unwrap()
            .required()
            .unwrap()
            .to_unquoted_string_str()
            .unwrap(),
        "connect"
    );
    let layers = parsed
        .value()
        .to_member("egress_layers")
        .unwrap()
        .required()
        .unwrap()
        .to_member("layers")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .collect::<Vec<_>>();
    assert_eq!(layers.len(), 2);
    let ip_os = layers[1]
        .to_member("os")
        .unwrap()
        .required()
        .unwrap()
        .to_unquoted_string_str()
        .unwrap();
    assert!(
        ip_os.contains("seccomp-user-notif"),
        "ip layer must name the mechanism: {ip_os}"
    );
    let stats = parsed
        .value()
        .to_member("supervisor_stats")
        .unwrap()
        .required()
        .unwrap();
    let denied: u64 = stats
        .to_member("denied")
        .unwrap()
        .required()
        .unwrap()
        .as_number_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(denied, 1, "one denied connect expected");
    // Limitations are always emitted — the report self-documents the
    // PoC's ceiling (TOCTOU, connect-only, supervisor-lifetime).
    let limitations = parsed
        .value()
        .to_member("limitations")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .count();
    assert!(limitations >= 5);
}

/// Denied connects also happen under `unotify-run` without `--server`
/// when the policy binds cleanly — smoke coverage that the launch
/// itself needs no MCP session.
#[test]
fn denied_without_explicit_server_binding() {
    if !supported() {
        return;
    }
    let dir = workdir("noserver");
    let policy = write_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["unotify-run", "--policy"])
        .arg(&policy)
        .args(["--audit-log", audit_arg.as_str()])
        .arg("--")
        .arg(fixture())
        .arg("192.0.2.1:9")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let run = run_with_timeout(&mut cmd);
    assert_eq!(run.code, 10, "stderr: {}", run.stderr);
}

/// `logging fail_closed #true` without `--audit-log` refuses before the
/// workload runs — the same contract `run`/`dns-gate` enforce.
#[test]
fn fail_closed_policy_requires_audit_log() {
    if !supported() {
        return;
    }
    let dir = workdir("failclosed");
    let policy = write_policy(&dir);
    // Flip the fixture policy's `fail_closed #false` to `#true`.
    let body = std::fs::read_to_string(&policy)
        .unwrap()
        .replace("fail_closed #false", "fail_closed #true");
    std::fs::write(&policy, body).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["unotify-run", "--policy"])
        .arg(&policy)
        .args(["--server", "probe"])
        .arg("--")
        .arg(fixture())
        .arg("192.0.2.1:9")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let run = run_with_timeout(&mut cmd);
    assert_eq!(run.code, 1, "stderr: {}", run.stderr);
    assert!(
        run.stderr.contains("--audit-log"),
        "expected the --audit-log requirement error, got: {}",
        run.stderr
    );
}

/// Usage error: no command after `--`.
#[test]
fn missing_command_is_a_parse_error() {
    let dir = workdir("nocommand");
    let policy = write_policy(&dir);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["unotify-run", "--policy"])
        .arg(&policy)
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let run = run_with_timeout(&mut cmd);
    assert_ne!(run.code, 0);
    assert!(
        run.stderr.contains("requires a command"),
        "stderr: {}",
        run.stderr
    );
}

/// The supervisor killing path: SIGTERM to `unotify-run` forwards to
/// the supervised group and exits with the conventional code.
#[test]
fn sigterm_terminates_supervised_child() {
    if !supported() {
        return;
    }
    let dir = workdir("sigterm");
    let policy = write_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    // The fixture connect is instant — use `sleep` as the workload so
    // the signal path is what we exercise. `sleep` needs no connect.
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["unotify-run", "--policy"])
        .arg(&policy)
        .args(["--server", "probe"])
        .args(["--audit-log", audit_arg.as_str()])
        .arg("--")
        .arg("/bin/sleep")
        .arg("30")
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    std::thread::sleep(Duration::from_millis(800));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(start.elapsed() < TEST_TIMEOUT, "SIGTERM never terminated");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.code(), Some(143), "conventional 128+SIGTERM");
}

/// Kernel-side fail closed: drop the listener with no supervisor and
/// every pending/future `connect` returns ENOSYS — the workload can
/// never connect unenforced. Exercises the layer below the command's
/// own kill-on-supervisor-loss handling.
#[test]
fn dropped_listener_makes_connects_enosys() {
    if !supported() {
        return;
    }
    let dir = workdir("suplost");
    let policy_path = write_policy(&dir);
    let policy = mcp_writ::policy::loader::load_policy_or_default_for_target(
        Some(&policy_path),
        &mcp_writ::execution::ExecutionTarget::native(),
    )
    .unwrap()
    .bind_to_server(Some("probe"))
    .unwrap();
    let spawned = mcp_writ::warden::unotify::spawn_supervised(
        &policy,
        &[fixture().display().to_string(), "127.0.0.1:9".to_string()],
    )
    .expect("spawn");
    let mut child = spawned.child;
    drop(spawned.listener);
    // No supervisor ever runs: the pending notification is answered
    // ENOSYS by the kernel on fd release → fixture exit 11.
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(5) {
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            child.wait().unwrap();
            panic!("child survived a dropped listener — connects escaped enforcement");
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(
        status.code(),
        Some(11),
        "expected ENOSYS (exit 11) from the un-answered connect"
    );
}
