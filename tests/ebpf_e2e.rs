//! End-to-end tests for `ebpf-run` — the PR-10 opt-in cgroup-eBPF
//! launch (improvement plan §1.3(b): in-kernel `INET4/6_CONNECT`
//! enforcement + ring-buffer deny observation).
//!
//! Each test spawns the real `mcp-writ` binary: policy load →
//! capability probe (`CAP_BPF`/`CAP_SYS_ADMIN` + `CAP_NET_ADMIN` +
//! writable cgroup v2 + `CONFIG_CGROUP_BPF`) → private-cgroup runtime
//! → supervised spawn → ring-buffer drain → audit/report assertions.
//! The workload is `tests/fixtures/unotify/connect_probe.rs` — a
//! connect-denied exit under this route is `EPERM` (errno=1) rather
//! than unotify's `EACCES`.
//!
//! Every test skips via `common::skip_e2e_test` when the environment
//! lacks the privileges/kernel support — `check_support()` is the
//! same probe the command runs, so a skip mirrors the command's own
//! refusal path. `MCP_WRIT_REQUIRE_E2E_TESTS=1` turns the skip into a
//! failure, so a mandatory run can never pass unexecuted.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

mod common;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

// ─── fixture / policy helpers ────────────────────────────────────────

/// Compile `tests/fixtures/unotify/connect_probe.rs` once per test
/// binary (cached under `target/ebpf-e2e`).
fn fixture() -> PathBuf {
    static BIN: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BIN.get_or_init(|| {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/ebpf-e2e");
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
    let dir =
        std::env::temp_dir().join(format!("mcp-writ-ebpf-e2e-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Fixture policy: `deny cidr="192.0.2.0/24"` + `deny host="*"`
/// (deny-all posture) — every allow comes from the dynamic allowlist
/// snapshot or an explicit rule, mirroring the unotify fixture.
fn write_policy(dir: &Path) -> PathBuf {
    write_policy_with(dir, "deny cidr=\"192.0.2.0/24\"\n        deny host=\"*\"")
}

fn write_policy_with(dir: &Path, network_rules: &str) -> PathBuf {
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
        allow "getpid" "getppid" "getuid" "getgid" "geteuid" "getegid" "gettid" "kill" "setsid"
        allow "mprotect" "madvise" "sigaltstack"
        allow "futex" "clock_gettime" "clock_nanosleep" "nanosleep" "set_tid_address" "set_robust_list" "rseq"
        allow "prlimit64" "prctl" "arch_prctl" "sched_getaffinity" "sched_yield"
        allow "epoll_create1" "epoll_ctl" "epoll_wait" "epoll_pwait" "poll" "select" "pselect6"
        allow "socket" "bind" "connect" "setsockopt" "getsockopt" "getsockname" "getpeername"
    }
    network {
        NETWORK_RULES
    }
}

logging fail_closed=#false
"#;
    let body = body.replace("NETWORK_RULES", network_rules);
    std::fs::write(&policy, body).unwrap();
    policy
}

/// Write a `DynamicAllowList`-shaped snapshot granting `grants`
/// (addr → name) with a fresh 300s TTL.
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

/// Run `mcp-writ ebpf-run … -- <fixture> <addr>` with a hard timeout.
fn ebpf_run(dir: &Path, policy: &Path, extra: &[&str], addr: &str) -> Run {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args(["ebpf-run", "--policy"])
        .arg(policy)
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
    let stdout_thr = drain(child.stdout.take().unwrap());
    let stderr_thr = drain(child.stderr.take().unwrap());
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if start.elapsed() >= TEST_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_thr.join();
            let _ = stderr_thr.join();
            panic!("ebpf-run exceeded {TEST_TIMEOUT:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    Run {
        code: status.code().unwrap_or(-1),
        stdout: stdout_thr.join().unwrap_or_default(),
        stderr: stderr_thr.join().unwrap_or_default(),
    }
}

/// The errno the fixture reported (`connect-error errno=N`), or None.
fn fixture_errno(stdout: &str) -> Option<i64> {
    let at = stdout.find("errno=")? + 6;
    let digits: String = stdout[at..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

/// Every `sandbox.network_denied` record in the audit JSONL.
fn denied_records(audit: &Path) -> Vec<String> {
    let body = std::fs::read_to_string(audit).unwrap_or_default();
    body.lines()
        .filter(|l| l.contains("sandbox.network_denied"))
        .map(|l| l.to_string())
        .collect()
}

/// Whether the environment runs the route — caps + cgroup v2 +
/// CONFIG_CGROUP_BPF. A skip mirrors the command's own refusal path.
fn supported() -> bool {
    match mcp_writ::warden::ebpf::check_support() {
        Ok(()) => true,
        Err(e) => {
            common::skip_e2e_test(&format!("kernel lacks cgroup-eBPF support: {e}"));
            false
        }
    }
}

// ─── tests ───────────────────────────────────────────────────────────

/// A direct-IP connect inside `deny cidr=` is refused in-kernel
/// (`EPERM` at the workload) and audited as
/// `layer=ip decision=deny-cidr` through the ring buffer.
#[test]
fn denied_cidr_connect_is_refused_and_audited() {
    if !supported() {
        return;
    }
    let dir = workdir("denied-cidr");
    let policy = write_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let run = ebpf_run(
        &dir,
        &policy,
        &["--audit-log", audit_arg.as_str()],
        "192.0.2.1:9",
    );
    // EPERM (errno 1) — the kernel-enforced cgroup verdict.
    assert_eq!(
        fixture_errno(&run.stdout),
        Some(1),
        "expected EPERM from the workload, got: {} (stderr: {})",
        run.stdout,
        run.stderr
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

/// A connect with no matching rule is denied under deny-all as
/// `decision=not-allowed` — the same vocabulary the unotify layer
/// emits for the policy default.
#[test]
fn unmatched_connect_denied_under_deny_all() {
    if !supported() {
        return;
    }
    let dir = workdir("deny-all");
    let policy = write_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let _run = ebpf_run(
        &dir,
        &policy,
        &["--audit-log", audit_arg.as_str()],
        "127.0.0.1:9",
    );
    let denied = denied_records(&audit);
    assert!(
        denied
            .iter()
            .any(|l| l.contains("decision=not-allowed") && l.contains("dest=127.0.0.1")),
        "expected a not-allowed denial for 127.0.0.1; got {denied:?}"
    );
}

/// A TTL-scoped dynamic grant loaded into the grant map lets the
/// connect pass the hooks — `ECONNREFUSED` (the connect reached the
/// network stack) is the proof it was not denied by eBPF.
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
    let run = ebpf_run(
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
    // Allowed at the eBPF layer — the connect then runs and is refused
    // by the (unlistening) stack: ECONNREFUSED proves it was not the
    // kernel's EPERM (errno=1).
    assert_ne!(
        fixture_errno(&run.stdout),
        Some(1),
        "granted connect must not hit the eBPF deny; stdout: {} stderr: {}",
        run.stdout,
        run.stderr
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().all(|l| !l.contains("dest=127.0.0.1")),
        "granted destination must not be denied; got {denied:?}"
    );
}

/// An expired grant entry never becomes effective — the kernel-side
/// expiry check skips it and the connect denies.
#[test]
fn expired_grant_denies() {
    if !supported() {
        return;
    }
    let dir = workdir("expired");
    let policy = write_policy(&dir);
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
    let _run = ebpf_run(
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
    let denied = denied_records(&audit);
    assert!(
        denied
            .iter()
            .any(|l| l.contains("decision=not-allowed") && l.contains("dest=127.0.0.1")),
        "expired grant must not allow; got {denied:?}"
    );
}

/// IPv6 deny is enforced by the INET6_CONNECT program — `::1` under
/// deny-all produces the deny event for family=AF_INET6.
#[test]
fn ipv6_connect_denied() {
    if !supported() {
        return;
    }
    let dir = workdir("v6");
    let policy = write_policy(&dir);
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let run = ebpf_run(
        &dir,
        &policy,
        &["--audit-log", audit_arg.as_str()],
        "[::1]:9",
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().any(|l| l.contains("dest=::1")),
        "expected an audited ::1 denial; got {denied:?} stdout:{}",
        run.stdout
    );
}

/// An IPv4-mapped IPv6 destination (`::ffff:a.b.c.d`) connects through
/// an AF_INET6 socket — the kernel fires `INET6_CONNECT`, not the v4
/// hook. The v4 deny must be projected into the v6 table or the mapped
/// spelling bypasses it. A default-allow policy with a single v4 deny
/// isolates exactly that path: `EPERM` + a `deny-cidr` record can only
/// come from the projected entry.
#[test]
fn v4_mapped_v6_connect_denied() {
    if !supported() {
        return;
    }
    let dir = workdir("v4mapped");
    let policy = write_policy_with(&dir, "deny cidr=\"127.0.0.0/8\"");
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let run = ebpf_run(
        &dir,
        &policy,
        &["--audit-log", audit_arg.as_str()],
        "[::ffff:127.0.0.1]:9",
    );
    // EPERM (errno 1) — the projected v6 entry denied it; without the
    // projection this connect would reach the stack as ECONNREFUSED.
    assert_eq!(
        fixture_errno(&run.stdout),
        Some(1),
        "expected EPERM for the v4-mapped destination, got: {} (stderr: {})",
        run.stdout,
        run.stderr
    );
    let denied = denied_records(&audit);
    assert!(
        denied.iter().any(|l| l.contains("decision=deny-cidr")),
        "expected a layer=ip deny-cidr record for the mapped deny; got {denied:?}"
    );
}

/// `--report` carries the capability block (mechanism + hooks), the
/// two-layer egress disposition, limitations naming the UDP/sendto
/// gap, and the drain counters.
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
    let _run = ebpf_run(
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
        "cgroup-ebpf"
    );
    assert!(
        cap.to_member("hooks")
            .unwrap()
            .required()
            .unwrap()
            .to_unquoted_string_str()
            .unwrap()
            .contains("INET4_CONNECT"),
    );
    let stats = parsed
        .value()
        .to_member("drain_stats")
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
    // The UDP sendto/sendmsg coverage gap is spelled out — the route
    // never claims complete UDP destination enforcement.
    let limitations = parsed
        .value()
        .to_member("limitations")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .map(|v| v.to_unquoted_string_str().unwrap())
        .collect::<Vec<_>>();
    assert!(
        limitations.iter().any(|l| l.contains("sendto")),
        "limitations must name the unconnected-UDP gap: {limitations:?}"
    );
}

/// The unprivileged refusal is a startup diagnostic, not a silent
/// degrade — asserted by `check_support` in `supported()`, and the
/// command's exit-2 refusal is the user-visible half. This test runs
/// only in an *unprivileged* environment (in a privileged one the
/// command legitimately proceeds).
#[test]
fn unprivileged_launch_refuses() {
    let eff = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|b| {
            b.lines()
                .find(|l| l.starts_with("CapEff:"))
                .and_then(|l| u64::from_str_radix(l[7..].trim(), 16).ok())
        })
        .unwrap_or(0);
    if eff & (1 << 21) != 0 || eff & (1 << 39) != 0 {
        // Privileged environment — the refusal path is not
        // exercisable, so assert the other half of the contract: the
        // launch does NOT hit the capability refusal (the probe passes
        // and setup proceeds — any later failure is a different path).
        let dir = workdir("refuse");
        let policy = write_policy(&dir);
        let run = ebpf_run(&dir, &policy, &[], "127.0.0.1:9");
        assert!(
            !run.stderr.contains("cgroup eBPF route unsupported"),
            "a privileged launch must not hit the capability refusal: {}",
            run.stderr
        );
        return;
    }
    let dir = workdir("refuse");
    let policy = write_policy(&dir);
    let report = dir.join("report.json");
    let report_arg = report.display().to_string();
    let audit = dir.join("audit.jsonl");
    let audit_arg = audit.display().to_string();
    let run = ebpf_run(
        &dir,
        &policy,
        &[
            "--report",
            report_arg.as_str(),
            "--audit-log",
            audit_arg.as_str(),
        ],
        "127.0.0.1:9",
    );
    assert_eq!(run.code, 2, "unprivileged run must refuse: {}", run.stderr);
    assert!(
        run.stderr.contains("cgroup eBPF route unsupported"),
        "refusal must name the route: {}",
        run.stderr
    );
    // The report records the refusal — 'unsupported', with a reason.
    let body = std::fs::read_to_string(&report).expect("report file");
    assert!(body.contains("\"state\":\"unsupported\""), "{body}");
}

/// The private cgroup is removed on a normal exit — no residue in the
/// shared hierarchy.
#[test]
fn private_cgroup_is_removed() {
    if !supported() {
        return;
    }
    let dir = workdir("cleanup");
    let policy = write_policy(&dir);
    let before: Vec<String> = std::fs::read_dir("/sys/fs/cgroup")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("mcp-writ-ebpf-"))
                .collect()
        })
        .unwrap_or_default();
    let _run = ebpf_run(&dir, &policy, &[], "127.0.0.1:9");
    let after: Vec<String> = std::fs::read_dir("/sys/fs/cgroup")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with("mcp-writ-ebpf-"))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(before, after, "private cgroup residue left behind");
}
