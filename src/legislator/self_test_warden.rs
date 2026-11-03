use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(target_os = "linux")]
use tokio::io::{AsyncWriteExt, BufReader};

#[cfg(any(target_os = "linux", test))]
use crate::auditor::checker;
#[cfg(target_os = "linux")]
use crate::framing::{self, DEFAULT_MAX_FRAME_BYTES};
use crate::legislator::self_test::{SpawnStatus, WARDEN_PROBE_PATH, WardenVerdict};
#[cfg(any(target_os = "linux", test))]
use crate::legislator::self_test_auditor::build_tools_call;
use crate::legislator::self_test_auditor::is_policy_jsonrpc_error;
use crate::policy::Policy;
#[cfg(any(target_os = "linux", test))]
use crate::policy::ToolPolicy;
#[cfg(target_os = "linux")]
use crate::protocol::{build_initialized_notification, build_mcp_2025_11_25_initialize};
use crate::warden::{SpawnOptions, Warden};

/// Bytes written to the control file; the reader result must echo this.
#[cfg(any(target_os = "linux", test))]
const CONTROL_FILE_CONTENTS: &str = "mcp-writ-self-test-control";

/// Classify a Warden observation.
///
/// `denied_observed` is the only `warden: pass` evidence: it reports
/// that the seccomp user-notification watcher answered a
/// kernel-reported open of the probe path with `EACCES`. The kernel —
/// not the child — produced that observation, so it outranks every
/// JSON-RPC self-report: a successful `result` *after* a supervised
/// denial is a fabricated claim, not proof the open was served.
/// Without the flag, a successful MCP `result` (not `isError`) is a
/// `fail`; policy JSON-RPC errors, tool `isError`, fabricated EACCES
/// text, and missing evidence are `inconclusive`.
pub fn classify_warden_observation(response: Option<&str>, denied_observed: bool) -> WardenVerdict {
    if denied_observed {
        return WardenVerdict::Pass;
    }
    if let Some(line) = response {
        if jsonrpc_has_success_result(line) {
            return WardenVerdict::Fail;
        }
        if is_policy_jsonrpc_error(line) {
            return WardenVerdict::Inconclusive;
        }
    }
    WardenVerdict::Inconclusive
}

fn jsonrpc_has_success_result(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line.trim()) else {
        return false;
    };
    let value = json.value();
    crate::protocol::value_is_response(value)
        && crate::protocol::value_has_member(value, "result")
        && crate::protocol::jsonrpc_error_from_value(value).is_none()
        && !crate::protocol::mcp_call_result_is_error(value)
}

#[cfg(any(target_os = "linux", test))]
fn control_result_has_known_content(line: &str) -> bool {
    jsonrpc_has_success_result(line) && line.contains(CONTROL_FILE_CONTENTS)
}

pub(crate) async fn collect_warden_evidence(
    draft: &Policy,
    command: &[String],
    tmpdir: &Path,
    timeout: Duration,
) -> (WardenVerdict, String, SpawnStatus, String, String) {
    let _ = timeout;
    #[cfg(not(target_os = "linux"))]
    return match spawn_short_lived(draft, command, tmpdir, Duration::from_millis(400)).await {
        Ok(spawn) => (
            WardenVerdict::Skipped,
            "OS-deny evidence is Linux-only (seccomp-notify supervised open)".to_string(),
            spawn,
            "child started".to_string(),
            String::new(),
        ),
        Err((spawn, e)) => (
            WardenVerdict::Inconclusive,
            format!("spawn failed before OS-deny probe: {e}"),
            spawn,
            e,
            String::new(),
        ),
    };

    #[cfg(target_os = "linux")]
    {
        let notes = warden_probe_policy_notes();
        // One deadline bounds the whole evidence operation — the
        // carve's filesystem walk is as much a hang surface as the
        // probe itself, and the walk checks that deadline internally:
        // timing out the await could never stop a blocking scan
        // already in flight.
        let deadline = tokio::time::Instant::now() + timeout;
        let carve_deadline = std::time::Instant::now() + timeout;
        // The probe's argument grants (`./**` for a bare argument,
        // `dir/**` otherwise) are spelled the same as discovery's and
        // leave reserved names just as reachable — carve them before
        // the supplied command runs. The walk blocks on real I/O, so
        // it runs off the async runtime; a failed or timed-out carve
        // refuses the spawn.
        let (draft_owned, command_owned, tmpdir_owned) =
            (draft.clone(), command.to_vec(), tmpdir.to_path_buf());
        let prepared = match tokio::time::timeout_at(
            deadline,
            tokio::task::spawn_blocking(move || {
                let mut p =
                    prepare_warden_probe_policy(&draft_owned, &tmpdir_owned, &command_owned);
                crate::legislator::tools_list::carve_arg_grants(
                    &mut p,
                    &command_owned,
                    Some(carve_deadline),
                )
                .map(|()| p)
            }),
        )
        .await
        {
            Ok(Ok(Ok(p))) => p,
            Ok(Ok(Err(e))) => {
                return (
                    WardenVerdict::Inconclusive,
                    format!("cannot carve a secret-free probe grant: {e}"),
                    SpawnStatus::NotAttempted,
                    e.to_string(),
                    notes,
                );
            }
            Ok(Err(e)) => {
                return (
                    WardenVerdict::Inconclusive,
                    format!("grant carving failed: {e}"),
                    SpawnStatus::NotAttempted,
                    e.to_string(),
                    notes,
                );
            }
            Err(_) => {
                return (
                    WardenVerdict::Inconclusive,
                    "timed out carving a secret-free probe grant".to_string(),
                    SpawnStatus::NotAttempted,
                    "timed out".to_string(),
                    notes,
                );
            }
        };
        match tokio::time::timeout_at(
            deadline,
            run_warden_os_deny_probe(&prepared, command, tmpdir),
        )
        .await
        {
            Ok(Ok((verdict, detail, spawn))) => (
                verdict,
                detail.clone(),
                spawn,
                match spawn {
                    SpawnStatus::Started => "child started".to_string(),
                    SpawnStatus::Failed | SpawnStatus::NotAttempted => detail,
                },
                notes.clone(),
            ),
            Ok(Err(e)) => (
                WardenVerdict::Inconclusive,
                e.clone(),
                SpawnStatus::Failed,
                e,
                notes.clone(),
            ),
            Err(_) => (
                WardenVerdict::Inconclusive,
                "timed out before OS-deny evidence".to_string(),
                SpawnStatus::Started,
                "timed out".to_string(),
                notes,
            ),
        }
    }
}

#[cfg(target_os = "linux")]
fn warden_probe_policy_notes() -> String {
    "diagnostic overlay (not the original draft): secret-overlay off, tool FS cleared, \
     runtime syscalls added (including execve), extra Landlock directories. \
     Probe success does not prove the original draft can launch the server."
        .to_string()
}

/// The system trees the probe policy grants read-only wherever they
/// exist — an interpreter install prefix beneath one of these needs
/// no new grant, so discovery must not spend its scan budget carving
/// it either. `/etc/ssl` carries the OpenSSL configuration: Node
/// reads `openssl.cnf` during early init and dies inside the sandbox
/// without it, and the dir cannot cover WARDEN_PROBE_PATH, so the
/// OS-deny evidence stands.
pub(crate) const PROBE_BASE_DIRS: &[&str] = &[
    "/usr", "/lib", "/lib64", "/bin", "/sbin", "/proc", "/dev", "/etc/ssl",
];

/// Build the diagnostic policy: tool FS empty, secret-overlay off, defaults Landlock only.
pub fn prepare_warden_probe_policy(draft: &Policy, tmpdir: &Path, command: &[String]) -> Policy {
    let mut policy = draft.clone();
    policy.fs.secret_overlay = false;
    policy.fs.allow_specified = true;

    // Landlock PathBeneath rejects file fds when the access mask includes
    // directory-only rights (EINVAL). Only grant directories. Do not add
    // `/etc` (that would allow `/etc/passwd` and erase the OS-deny probe),
    // and do not grant the caller's workspace either: the probe needs
    // only the control file under `tmpdir`, the command's own directory,
    // and the runtime libraries below — broad workspace authority would
    // grant the diagnostic child rights the draft never asked for.
    for dir in PROBE_BASE_DIRS {
        push_landlock_dir(&mut policy.fs.read_only, &format!("{dir}/**"));
    }
    // libuv and CPython open `/dev/null` read-write for stdio
    // redirection — a read-only `/dev/**` grant cannot satisfy the
    // write half. A literal file spelling: the backend hands it
    // file-scoped rights.
    push_unique(&mut policy.fs.read_write, "/dev/null");
    // The command's interpreter runtime: install prefixes above the
    // `bin`/`Scripts` dir (stdlib, site-packages, lib/node_modules)
    // and `node_modules` roots the entry point resolves dependencies
    // from — the runtime profiles document these as required grants.
    for dir in crate::legislator::tools_list::runtime_grant_dirs(command) {
        push_landlock_dir(&mut policy.fs.read_only, &format!("{}/**", dir.display()));
    }
    push_landlock_dir(
        &mut policy.fs.read_write,
        &format!("{}/**", tmpdir.display()),
    );

    if let Some(argv0) = command.first()
        && let Ok(resolved) = crate::workload::resolve_command_path(argv0)
        && let Some(parent) = resolved.parent()
    {
        push_landlock_dir(
            &mut policy.fs.read_only,
            &format!("{}/**", parent.display()),
        );
    }
    for arg in command.iter().skip(1) {
        // An option token is never a filesystem path — a file spelled
        // `-x` is reached as `./-x`, so even a coincidental `--mode`
        // file contributes no grant through the bare spelling.
        if arg.starts_with('-') {
            continue;
        }
        let path = Path::new(arg);
        let parent = if path.exists() {
            path.canonicalize()
                .ok()
                .and_then(|c| c.parent().map(Path::to_path_buf))
                .or_else(|| path.parent().map(Path::to_path_buf))
        } else if !crate::pathutil::selector_plausible(arg) {
            // A missing argument needs path-like punctuation to earn a
            // grant — `stdio` is a literal value, while `config.json`
            // and `sub/file` keep their parent.
            None
        } else {
            // A bare argument lives in the current directory — an
            // empty `parent()` normalizes to `.`, not to nothing.
            path.parent().map(|p| {
                if p.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    p.to_path_buf()
                }
            })
        };
        if let Some(parent) = parent {
            // A grant covering WARDEN_PROBE_PATH would let the child serve
            // the probe path and erase the OS-deny evidence.
            let canonical_parent = parent.canonicalize().unwrap_or_else(|_| parent.clone());
            if !Path::new(WARDEN_PROBE_PATH).starts_with(&canonical_parent) {
                push_landlock_dir(
                    &mut policy.fs.read_only,
                    &format!("{}/**", parent.display()),
                );
            }
        }
    }

    for tool in &mut policy.tools {
        tool.fs = None;
        tool.fs_explicit = true;
    }

    for name in runtime_syscalls() {
        push_unique(&mut policy.syscalls.allowed, name);
    }
    policy
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|e| e == value) {
        list.push(value.to_string());
    }
}

/// Grant a directory glob to Landlock. File paths are skipped (they EINVAL).
fn push_landlock_dir(list: &mut Vec<String>, spec: &str) {
    let mut base = spec.trim();
    while let Some(rest) = base.strip_suffix("/**") {
        base = rest;
    }
    while let Some(rest) = base.strip_suffix("/*") {
        base = rest;
    }
    // A partial-component star is a literal character under the
    // Auditor's wildcard grammar — do not reduce `/a/foo*` to `/a/foo`.
    if base.contains(['*', '?']) {
        return;
    }
    base = base.trim_end_matches('/');
    if base.is_empty() {
        return;
    }
    let path = Path::new(base);
    if !path.is_dir() {
        return;
    }
    let glob = if spec.contains('*') {
        spec.to_string()
    } else {
        format!("{base}/**")
    };
    push_unique(list, &glob);
}

/// The Linux seccomp allowlist the probe child gets: the union of the
/// documented runtime profiles (`examples/policies/runtime/python.kdl`
/// and `node.kdl`). Discovery must launch real interpreters — CPython
/// dies at `os.uname()`, libuv at `eventfd2`, asyncio at `socketpair`
/// — so the baseline is the observed set, not a minimal one. The
/// entries stay safe under the probe's other walls: write-path ops are
/// Landlock-confined to the private tmpdir, and the network pair only
/// opens channels that deny-all egress then refuses. io_uring is
/// deliberately absent — a ring submits work outside this filter.
fn runtime_syscalls() -> &'static [&'static str] {
    &[
        // Loader + basic I/O
        "read",
        "write",
        "openat",
        "openat2",
        "open",
        "close",
        "newfstatat",
        "stat",
        "fstat",
        "lstat",
        "statx",
        "lseek",
        "pread64",
        "pwrite64",
        "readv",
        "writev",
        "getcwd",
        "chdir",
        "fcntl",
        "flock",
        "fsync",
        "getdents64",
        "access",
        "readlink",
        "dup",
        "dup2",
        "dup3",
        // Write-path ops — usable only where a filesystem grant is
        // write; the probe grants just the tmpdir and /dev/null.
        "rename",
        "renameat",
        "renameat2",
        "mkdir",
        "mkdirat",
        "unlink",
        "unlinkat",
        "rmdir",
        "truncate",
        "ftruncate",
        "symlink",
        "symlinkat",
        "link",
        "linkat",
        "mknod",
        "mknodat",
        "utimensat",
        // Mode changes — Landlock cannot confine chmod targets; DAC
        // still requires euid == owner. Documented for Node servers
        // that chmod a temp file before rename.
        "chmod",
        "fchmod",
        "fchmodat",
        // Memory (mprotect is required by V8's JIT)
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "madvise",
        // Threads, signals, futex
        "clone",
        "clone3",
        "futex",
        "set_tid_address",
        "set_robust_list",
        "rseq",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "sigaltstack",
        // Event loop (libuv / asyncio): eventfd2, the timerfd family,
        // and socketpair are required — libuv's uv_loop_init asserts on
        // eventfd2, asyncio's self-pipe wakeup is a socketpair().
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "epoll_wait",
        "poll",
        "select",
        "pipe",
        "pipe2",
        "eventfd2",
        "timerfd_create",
        "timerfd_settime",
        "timerfd_gettime",
        "socketpair",
        "getsockname",
        "getpeername",
        "getsockopt",
        "setsockopt",
        // Socket wakeups + outbound channels — destinations stay
        // confined by the probe's deny-all egress.
        "sendto",
        "recvfrom",
        "sendmsg",
        "recvmsg",
        "shutdown",
        "socket",
        "connect",
        // Process identity + misc probes runtimes issue at startup
        // (`uname` — os.uname via platform/uuid; capget/sysinfo/ioctl
        // are libuv+V8 probes).
        "getpid",
        "getppid",
        "getuid",
        "getgid",
        "geteuid",
        "getegid",
        "gettid",
        "uname",
        "capget",
        "sysinfo",
        "ioctl",
        "sched_getparam",
        "sched_getscheduler",
        "setsid",
        "prctl",
        "arch_prctl",
        "sched_getaffinity",
        "sched_yield",
        "prlimit64",
        "getrandom",
        "nanosleep",
        "clock_gettime",
        "clock_nanosleep",
        "membarrier",
        // Startup + subprocesses — servers like mcp-server-git exec
        // helpers; the inherited filter keeps execve in the child.
        "execve",
        "execveat",
        "wait4",
        "kill",
        "exit",
        "exit_group",
    ]
}

#[cfg(not(target_os = "linux"))]
async fn spawn_short_lived(
    policy: &Policy,
    command: &[String],
    tmpdir: &Path,
    timeout: Duration,
) -> Result<SpawnStatus, (SpawnStatus, String)> {
    if command.is_empty() {
        return Err((SpawnStatus::NotAttempted, "empty command".to_string()));
    }
    let argv = resolve_argv(command).map_err(|e| (SpawnStatus::NotAttempted, e))?;
    let warden = Warden::new(policy.clone());
    let opts = SpawnOptions {
        restrict_environment: true,
        allowed_names: Vec::new(),
        tmpdir: Some(tmpdir.to_path_buf()),
        ..Default::default()
    };
    // A self-test workload is a real spawn: dyld needs the same derived
    // code-map grants a `run` launch computes (argv[0] is resolved).
    #[cfg(target_os = "macos")]
    let opts = {
        let mut o = opts;
        o.exec_map_dirs =
            crate::warden::macos_sandbox::code_map_dirs(std::path::Path::new(&argv[0]), &argv);
        o
    };
    let mut child = warden
        .spawn_child_async_with(&argv, &opts)
        .await
        .map_err(|e| (SpawnStatus::Failed, e.to_string()))?;
    let _ = tokio::time::timeout(timeout, child.wait_for_natural_exit()).await;
    let _ = child.kill().await;
    Ok(SpawnStatus::Started)
}

#[cfg(target_os = "linux")]
async fn run_warden_os_deny_probe(
    policy: &Policy,
    command: &[String],
    tmpdir: &Path,
) -> Result<(WardenVerdict, String, SpawnStatus), String> {
    let Some(tool) = file_reading_tool(policy) else {
        eprintln!("self-test: warden OS-deny probe skipped (no file-reading tool)");
        return Ok((
            WardenVerdict::Inconclusive,
            "no file-reading tool for control call".to_string(),
            SpawnStatus::NotAttempted,
        ));
    };

    let control_path = tmpdir.join("self-test-control.txt");
    let _ = std::fs::write(&control_path, CONTROL_FILE_CONTENTS.as_bytes());
    let control_line = build_tools_call(
        9,
        &tool.name,
        &format!(r#"{{"path":"{}"}}"#, control_path.display()),
    );
    let probe_line = build_tools_call(
        10,
        &tool.name,
        &format!(r#"{{"path":"{WARDEN_PROBE_PATH}"}}"#),
    );
    if let Err(v) = checker::check_request(&probe_line, policy) {
        return Ok((
            WardenVerdict::Inconclusive,
            format!("Auditor denied OS-deny probe first ({v}); not OS evidence"),
            SpawnStatus::NotAttempted,
        ));
    }

    if command.is_empty() {
        return Ok((
            WardenVerdict::Inconclusive,
            "empty command".to_string(),
            SpawnStatus::NotAttempted,
        ));
    }
    let argv = match resolve_argv(command) {
        Ok(argv) => argv,
        Err(e) => {
            return Ok((WardenVerdict::Inconclusive, e, SpawnStatus::NotAttempted));
        }
    };
    let warden = Warden::new(policy.clone());
    let opts = SpawnOptions {
        restrict_environment: true,
        allowed_names: Vec::new(),
        tmpdir: Some(tmpdir.to_path_buf()),
        ..Default::default()
    };
    // The pass evidence is the notification watcher, not anything the
    // child reports: the child's `pre_exec` installs a filter that
    // parks every `open*` on the listener, and `PathDenyWatcher`
    // answers `EACCES` to exactly the probe path. A child that never
    // triggers a real OS deny cannot produce the flag.
    let (mut child, listener) = match warden
        .spawn_child_async_unotify(&argv, &opts, crate::warden::unotify::OPEN_PATH_NRS)
        .await
    {
        Ok(pair) => pair,
        Err(e) => {
            return Ok((
                WardenVerdict::Inconclusive,
                format!("supervised Warden spawn failed: {e}"),
                SpawnStatus::Failed,
            ));
        }
    };
    let watcher = match crate::warden::unotify::PathDenyWatcher::start(
        listener,
        Path::new(WARDEN_PROBE_PATH),
    ) {
        Ok(watcher) => watcher,
        Err(e) => {
            let _ = child.kill().await;
            return Ok((
                WardenVerdict::Inconclusive,
                format!("path-deny watcher failed to start: {e}"),
                SpawnStatus::Started,
            ));
        }
    };
    let Some((mut stdin, stdout)) = child.take_io() else {
        let _ = child.kill().await;
        let _ = watcher.shutdown().await;
        return Ok((
            WardenVerdict::Inconclusive,
            "failed to capture child stdio".to_string(),
            SpawnStatus::Started,
        ));
    };
    let mut reader = BufReader::new(stdout);

    if let Err(e) = handshake(&mut stdin, &mut reader).await {
        let _ = child.kill().await;
        let _ = watcher.shutdown().await;
        return Ok((
            WardenVerdict::Inconclusive,
            format!("handshake failed ({e}); not treating later signals as path-deny evidence"),
            SpawnStatus::Started,
        ));
    }

    if let Err(e) = write_line(&mut stdin, &control_line).await {
        let _ = child.kill().await;
        let _ = watcher.shutdown().await;
        return Ok((
            WardenVerdict::Inconclusive,
            format!("control call write failed ({e})"),
            SpawnStatus::Started,
        ));
    }
    let control_resp =
        tokio::time::timeout(Duration::from_millis(800), read_jsonrpc_line(&mut reader)).await;
    match control_resp {
        Ok(Ok(line))
            if crate::protocol::jsonrpc_id_as_i64(&line) == Some(9)
                && control_result_has_known_content(&line) => {}
        other => {
            let _ = child.kill().await;
            let _ = watcher.shutdown().await;
            return Ok((
                WardenVerdict::Inconclusive,
                format!(
                    "control call did not return known file contents ({other:?}); not OS-deny evidence"
                ),
                SpawnStatus::Started,
            ));
        }
    }

    if let Err(e) = write_line(&mut stdin, &probe_line).await {
        let verdict = classify_warden_observation(None, watcher.denied_observed());
        let _ = child.kill().await;
        let _ = watcher.shutdown().await;
        return Ok((
            verdict,
            format!("write to child failed ({e}); classified from watcher evidence"),
            SpawnStatus::Started,
        ));
    }

    let response = tokio::select! {
        line = read_jsonrpc_line(&mut reader) => line.ok(),
        status = child.wait_for_natural_exit() => {
            let st = match status {
                crate::warden::NaturalExit::Exited(s) => s.ok(),
                crate::warden::NaturalExit::SupervisionLost(_) => None,
            };
            let verdict = classify_warden_observation(None, watcher.denied_observed());
            let _ = watcher.shutdown().await;
            return Ok((verdict, format!("child exited before JSON-RPC ({st:?})"), SpawnStatus::Started));
        }
    };

    if let Some(ref line) = response
        && crate::protocol::jsonrpc_id_as_i64(line) != Some(10)
    {
        let _ = child.kill().await;
        let _ = watcher.shutdown().await;
        return Ok((
            WardenVerdict::Inconclusive,
            format!("probe response id did not match id=10: {line}"),
            SpawnStatus::Started,
        ));
    }

    // The denial flag is set before the watcher answers EACCES, so by
    // the time the child's reaction is readable the evidence is already
    // recorded — no ordering race on our side.
    let denied = watcher.denied_observed();
    let verdict = classify_warden_observation(response.as_deref(), denied);
    let _ = child.kill().await;
    let _ = watcher.shutdown().await;
    let detail = match (&verdict, response.as_deref()) {
        (WardenVerdict::Pass, _) => {
            "OS deny observed (seccomp-notify EACCES on probe open)".to_string()
        }
        (WardenVerdict::Fail, Some(line)) => format!("child served the path: {line}"),
        (WardenVerdict::Inconclusive, Some(line)) => {
            format!("JSON-RPC self-report is not OS evidence: {line}")
        }
        (other, _) => format!("{} (no further detail)", other.as_str()),
    };
    Ok((verdict, detail, SpawnStatus::Started))
}

/// Known file-reading tool used by the Warden control call. No arbitrary fallback.
#[cfg(any(target_os = "linux", test))]
fn file_reading_tool(policy: &Policy) -> Option<&ToolPolicy> {
    policy
        .tools
        .iter()
        .find(|t| t.allowed && t.name == "read_file")
}

fn resolve_argv(command: &[String]) -> Result<Vec<String>, String> {
    let resolved = crate::workload::resolve_command_path(&command[0])
        .map_err(|e| format!("cannot resolve '{}': {e}", command[0]))?;
    let mut argv = command.to_vec();
    argv[0] = resolved.to_string_lossy().into_owned();
    Ok(argv)
}

#[cfg(target_os = "linux")]
async fn handshake<W, R>(stdin: &mut W, reader: &mut BufReader<R>) -> Result<(), String>
where
    W: tokio::io::AsyncWrite + Unpin,
    R: tokio::io::AsyncRead + Unpin,
{
    write_line(stdin, &build_mcp_2025_11_25_initialize(1)).await?;
    let line = tokio::time::timeout(Duration::from_millis(800), read_jsonrpc_line(reader))
        .await
        .map_err(|_| "initialize timed out".to_string())?
        .map_err(|e| format!("initialize read failed: {e}"))?;
    if crate::protocol::jsonrpc_id_as_i64(&line) != Some(1) || !jsonrpc_has_success_result(&line) {
        return Err(format!(
            "initialize did not return a success result: {line}"
        ));
    }
    write_line(stdin, &build_initialized_notification()).await?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn write_line<W: tokio::io::AsyncWrite + Unpin>(
    stdin: &mut W,
    line: &str,
) -> Result<(), String> {
    stdin
        .write_all(line.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    stdin.write_all(b"\n").await.map_err(|e| e.to_string())?;
    stdin.flush().await.map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(target_os = "linux")]
async fn read_jsonrpc_line<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut BufReader<R>,
) -> Result<String, String> {
    loop {
        let line = framing::read_line_bounded(reader, DEFAULT_MAX_FRAME_BYTES)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "child closed stdout".to_string())?;
        let trimmed = line.trim();
        if trimmed.is_empty() || !trimmed.starts_with('{') {
            continue;
        }
        if crate::protocol::is_jsonrpc_notification(trimmed) {
            continue;
        }
        return Ok(trimmed.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legislator::self_test_auditor::first_allowed_tool;
    use crate::policy::kdl_loader::parse_kdl_policy;

    #[test]
    fn jsonrpc_policy_error_is_not_warden_pass() {
        let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Policy violation: tool 'read_file' is not allowed (secret-path overlay)"}}"#;
        assert!(is_policy_jsonrpc_error(line));
        assert_eq!(
            classify_warden_observation(Some(line), false),
            WardenVerdict::Inconclusive
        );
    }

    #[test]
    fn eacces_jsonrpc_is_not_warden_pass() {
        let line = r#"{"jsonrpc":"2.0","id":10,"error":{"code":-32603,"message":"EACCES - fabricated, no open performed"}}"#;
        assert!(!is_policy_jsonrpc_error(line));
        assert_eq!(
            classify_warden_observation(Some(line), false),
            WardenVerdict::Inconclusive
        );
    }

    #[test]
    fn mcp_iserror_result_is_not_warden_fail_or_pass() {
        let line = r#"{"jsonrpc":"2.0","id":10,"result":{"isError":true,"content":[{"type":"text","text":"EACCES"}]}}"#;
        assert!(!jsonrpc_has_success_result(line));
        assert_eq!(
            classify_warden_observation(Some(line), false),
            WardenVerdict::Inconclusive
        );
    }

    #[test]
    fn successful_open_is_warden_fail() {
        let line =
            r#"{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"root:x"}]}}"#;
        assert_eq!(
            classify_warden_observation(Some(line), false),
            WardenVerdict::Fail
        );
    }

    #[test]
    fn success_result_mentioning_permission_denied_is_not_warden_pass() {
        let line = r#"{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"notes: EACCES / permission denied (os error 13)"}]}}"#;
        assert!(jsonrpc_has_success_result(line));
        assert_eq!(
            classify_warden_observation(Some(line), false),
            WardenVerdict::Fail
        );
    }

    #[test]
    fn supervised_deny_flag_is_the_only_pass_evidence() {
        // No response, flag set: pass — the flag is the kernel-mediated
        // observation itself.
        assert_eq!(classify_warden_observation(None, true), WardenVerdict::Pass);
        // Kernel evidence outranks a fabricated success claim: a child
        // that says "served" after the watcher denied the open is
        // lying about the result, not proof the open went through.
        let served =
            r#"{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"root:x"}]}}"#;
        assert_eq!(
            classify_warden_observation(Some(served), true),
            WardenVerdict::Pass
        );
        // A forged-deny self-report without the flag stays
        // inconclusive — the child cannot produce the evidence itself.
        let forged = r#"{"jsonrpc":"2.0","id":10,"result":{"isError":true,"content":[{"type":"text","text":"EACCES"}]}}"#;
        assert_eq!(
            classify_warden_observation(Some(forged), false),
            WardenVerdict::Inconclusive
        );
    }

    #[test]
    fn warden_probe_policy_leaves_auditor_tool_fs_empty() {
        let tmpdir = tempfile::tempdir().unwrap();
        let directory = tmpdir.path().to_string_lossy().replace('\\', "/");
        let kdl = r##"
            policy version=1
            defaults {
                filesystem {
                    secret-overlay #false
                    allow "/workspace/**" mode="read"
                }
                syscalls {
                    allow "read" "write" "openat" "execve" "exit_group"
                }
            }
            server "t" {
                tool "read_file" args_schema="{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}"
            }
        "##;
        let kdl = kdl.replace("/workspace", &directory);
        let loaded = parse_kdl_policy(&kdl).unwrap();
        assert!(
            loaded.tools[0].fs.is_some(),
            "defaults.filesystem is inherited on load"
        );
        let prepared = prepare_warden_probe_policy(&loaded, tmpdir.path(), &["echo".into()]);
        assert!(
            prepared.tools[0].fs.is_none(),
            "Auditor tool FS must be empty so global Landlock is the only OS grant"
        );
        assert!(!prepared.fs.secret_overlay);

        #[cfg(target_os = "linux")]
        {
            assert!(
                prepared
                    .fs
                    .read_write
                    .iter()
                    .any(|p| p == &format!("{directory}/**"))
            );
            // `/dev/null` is the intended *file* grant — libuv/CPython
            // open it read-write for stdio, so it stays a literal
            // spelling the backend hands file-scoped rights. Every
            // other grant must name a directory: Landlock PathBeneath
            // rejects file fds whose mask carries directory-only
            // rights (EINVAL).
            assert!(
                prepared.fs.read_write.iter().any(|p| p == "/dev/null"),
                "/dev/null must stay a literal read-write file grant: {:?}",
                prepared.fs.read_write
            );
            for path in prepared
                .fs
                .read_only
                .iter()
                .chain(prepared.fs.read_write.iter())
            {
                let base = path.trim_end_matches("/**").trim_end_matches("/*");
                if base == "/dev/null" {
                    continue;
                }
                assert!(
                    Path::new(base).is_dir(),
                    "Landlock grants must be directories (files EINVAL): {path}"
                );
            }
        }

        let line = build_tools_call(1, "read_file", r#"{"path":"/etc/passwd"}"#);
        assert!(
            checker::check_request(&line, &prepared).is_ok(),
            "Auditor must allow /etc/passwd so Warden can be the denier"
        );
        assert!(
            checker::check_request(&line, &loaded).is_err(),
            "inherited tool FS on the raw draft would cut the probe first"
        );
    }

    #[test]
    fn warden_probe_policy_grants_no_workspace_authority() {
        // The diagnostic overlay must stay least-privilege: the only
        // read-write grants are the control tmpdir and `/dev/null`
        // (libuv/CPython open it read-write for stdio) — never the
        // caller's workspace, which the draft policy did not ask for.
        let tmpdir = tempfile::tempdir().unwrap();
        let kdl = r##"
            policy version=1
            defaults { filesystem { secret-overlay #false } }
            server "t" {
                tool "read_file" args_schema="{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}"
            }
        "##;
        let loaded = parse_kdl_policy(kdl).unwrap();
        let prepared = prepare_warden_probe_policy(&loaded, tmpdir.path(), &["echo".into()]);
        let tmpdir_prefix = format!("{}", tmpdir.path().display());
        for spec in &prepared.fs.read_write {
            assert!(
                spec.starts_with(&tmpdir_prefix) || spec == "/dev/null",
                "read_write grant outside the control tmpdir: {spec}"
            );
        }
    }

    #[test]
    fn file_reading_tool_is_read_file_not_first_allowed() {
        let kdl = r##"
            policy version=1
            defaults { filesystem { secret-overlay #false } }
            server "t" {
                tool "fetch_url" side_effect="network"
                tool "read_file" side_effect="read_only"
            }
        "##;
        let policy = parse_kdl_policy(kdl).unwrap();
        assert_eq!(
            file_reading_tool(&policy).map(|t| t.name.as_str()),
            Some("read_file")
        );
        let only_fetch = r##"
            policy version=1
            defaults { filesystem { secret-overlay #false } }
            server "t" { tool "fetch_url" side_effect="network" }
        "##;
        let fetch_only = parse_kdl_policy(only_fetch).unwrap();
        assert!(file_reading_tool(&fetch_only).is_none());
        assert_eq!(
            first_allowed_tool(&fetch_only).map(|t| t.name.as_str()),
            Some("fetch_url")
        );
    }

    #[test]
    fn control_result_requires_known_file_contents() {
        let with_content = format!(
            r#"{{"jsonrpc":"2.0","id":9,"result":{{"ok":true,"head":"{CONTROL_FILE_CONTENTS}"}}}}"#
        );
        assert!(control_result_has_known_content(&with_content));
        let success_only = r#"{"jsonrpc":"2.0","id":9,"result":{"ok":true,"n":2}}"#;
        assert!(!control_result_has_known_content(success_only));
    }
}
