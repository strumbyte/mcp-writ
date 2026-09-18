use std::path::Path;
use std::process::ExitStatus;
use std::time::Duration;

use tokio::io::{AsyncWriteExt, BufReader};

use crate::auditor::checker;
use crate::framing::{self, DEFAULT_MAX_FRAME_BYTES};
use crate::legislator::protocol::{
    build_initialized_notification, build_mcp_2025_11_25_initialize,
};
use crate::legislator::self_test::{SpawnStatus, WARDEN_PROBE_PATH, WardenVerdict};
use crate::legislator::self_test_auditor::{build_tools_call, is_policy_jsonrpc_error};
use crate::policy::{Policy, ToolPolicy};
use crate::warden::{SpawnOptions, Warden};

/// Bytes written to the control file; the reader result must echo this.
const CONTROL_FILE_CONTENTS: &str = "mcp-writ-self-test-control";

/// Classify a Warden observation.
///
/// JSON-RPC messages from the child are self-reports and are never `warden: pass`.
/// A successful MCP `result` (not `isError`) means the path was served (`fail`).
/// Policy JSON-RPC errors, tool `isError`, fabricated EACCES text, and missing
/// exit status are `inconclusive`. Only SIGSYS after a healthy control call is `pass`.
pub fn classify_warden_observation(
    response: Option<&str>,
    status: Option<ExitStatus>,
) -> WardenVerdict {
    if let Some(line) = response {
        if jsonrpc_has_success_result(line) {
            return WardenVerdict::Fail;
        }
        if is_policy_jsonrpc_error(line) {
            return WardenVerdict::Inconclusive;
        }
    }
    if let Some(st) = status
        && is_sigsys(st)
    {
        return WardenVerdict::Pass;
    }
    WardenVerdict::Inconclusive
}

fn jsonrpc_has_success_result(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line.trim()) else {
        return false;
    };
    let value = json.value();
    crate::legislator::protocol::value_is_response(value)
        && crate::legislator::protocol::value_has_member(value, "result")
        && crate::legislator::protocol::jsonrpc_error_from_value(value).is_none()
        && !crate::legislator::protocol::mcp_call_result_is_error(value)
}

fn control_result_has_known_content(line: &str) -> bool {
    jsonrpc_has_success_result(line) && line.contains(CONTROL_FILE_CONTENTS)
}

fn is_sigsys(status: ExitStatus) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        status.signal() == Some(libc::SIGSYS)
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        false
    }
}

pub(crate) async fn collect_warden_evidence(
    draft: &Policy,
    command: &[String],
    tmpdir: &Path,
    timeout: Duration,
) -> (WardenVerdict, String, SpawnStatus, String, String) {
    if !cfg!(target_os = "linux") {
        return match spawn_short_lived(draft, command, tmpdir, Duration::from_millis(400)).await {
            Ok(spawn) => (
                WardenVerdict::Skipped,
                "OS-deny evidence is Linux-only (SIGSYS / Landlock EACCES)".to_string(),
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
    }

    let notes = warden_probe_policy_notes();
    let prepared = prepare_warden_probe_policy(draft, tmpdir, command);
    match tokio::time::timeout(
        timeout,
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

fn warden_probe_policy_notes() -> String {
    "diagnostic overlay (not the original draft): secret-overlay off, tool FS cleared, \
     runtime syscalls added (including execve), extra Landlock directories. \
     Probe success does not prove the original draft can launch the server."
        .to_string()
}

/// Build the diagnostic policy: tool FS empty, secret-overlay off, defaults Landlock only.
pub fn prepare_warden_probe_policy(draft: &Policy, tmpdir: &Path, command: &[String]) -> Policy {
    let mut policy = draft.clone();
    policy.fs.secret_overlay = false;
    policy.fs.allow_specified = true;

    // Landlock PathBeneath rejects file fds when the access mask includes
    // directory-only rights (EINVAL). Only grant directories. Do not add
    // `/etc` (that would allow `/etc/passwd` and erase the OS-deny probe).
    push_landlock_dir(&mut policy.fs.read_write, "/workspace/**");
    for path in [
        "/usr/**",
        "/lib/**",
        "/lib64/**",
        "/bin/**",
        "/sbin/**",
        "/proc/**",
        "/dev/**",
    ] {
        push_landlock_dir(&mut policy.fs.read_only, path);
    }
    push_landlock_dir(
        &mut policy.fs.read_write,
        &format!("{}/**", tmpdir.display()),
    );

    if let Some(argv0) = command.first()
        && let Ok(resolved) = crate::verifier::hash::resolve_command_path(argv0)
        && let Some(parent) = resolved.parent()
    {
        push_landlock_dir(
            &mut policy.fs.read_only,
            &format!("{}/**", parent.display()),
        );
    }
    for arg in command.iter().skip(1) {
        let path = Path::new(arg);
        let parent = if path.exists() {
            path.canonicalize()
                .ok()
                .and_then(|c| c.parent().map(Path::to_path_buf))
                .or_else(|| path.parent().map(Path::to_path_buf))
        } else {
            path.parent().map(Path::to_path_buf)
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
    while let Some(rest) = base.strip_suffix('*') {
        base = rest.trim_end_matches('/');
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

fn runtime_syscalls() -> &'static [&'static str] {
    &[
        "read",
        "write",
        "close",
        "openat",
        "open",
        "newfstatat",
        "stat",
        "fstat",
        "lstat",
        "lseek",
        "mmap",
        "mprotect",
        "munmap",
        "brk",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "ioctl",
        "pread64",
        "pwrite64",
        "readv",
        "writev",
        "getcwd",
        "chdir",
        "fcntl",
        "flock",
        "fsync",
        "dup",
        "dup2",
        "dup3",
        "pipe",
        "pipe2",
        "clone",
        "clone3",
        "execve",
        "exit",
        "exit_group",
        "wait4",
        "kill",
        "getpid",
        "getppid",
        "getuid",
        "getgid",
        "geteuid",
        "getegid",
        "setsid",
        "sigaltstack",
        "futex",
        "nanosleep",
        "clock_gettime",
        "clock_nanosleep",
        "getrandom",
        "prctl",
        "arch_prctl",
        "set_tid_address",
        "set_robust_list",
        "sched_getaffinity",
        "sched_yield",
        "madvise",
        "prlimit64",
        "rseq",
        "getdents64",
        "access",
        "readlink",
        "epoll_create1",
        "epoll_ctl",
        "epoll_pwait",
        "epoll_wait",
        "poll",
        "select",
    ]
}

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
        tmpdir: Some(tmpdir.to_path_buf()),
    };
    let mut child = warden
        .spawn_child_async_with(&argv, &opts)
        .map_err(|e| (SpawnStatus::Failed, e.to_string()))?;
    let _ = tokio::time::timeout(timeout, child.wait_for_natural_exit()).await;
    let _ = child.kill().await;
    Ok(SpawnStatus::Started)
}

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
        tmpdir: Some(tmpdir.to_path_buf()),
    };
    let mut child = match warden.spawn_child_async_with(&argv, &opts) {
        Ok(child) => child,
        Err(e) => {
            return Ok((
                WardenVerdict::Inconclusive,
                format!("Warden spawn failed: {e}"),
                SpawnStatus::Failed,
            ));
        }
    };
    let Some((mut stdin, stdout)) = child.take_io() else {
        let _ = child.kill().await;
        return Ok((
            WardenVerdict::Inconclusive,
            "failed to capture child stdio".to_string(),
            SpawnStatus::Started,
        ));
    };
    let mut reader = BufReader::new(stdout);

    if let Err(e) = handshake(&mut stdin, &mut reader).await {
        let _ = child.kill().await;
        return Ok((
            WardenVerdict::Inconclusive,
            format!("handshake failed ({e}); not treating later signals as path-deny evidence"),
            SpawnStatus::Started,
        ));
    }

    if let Err(e) = write_line(&mut stdin, &control_line).await {
        let _ = child.kill().await;
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
            if crate::legislator::protocol::jsonrpc_id_as_i64(&line) == Some(9)
                && control_result_has_known_content(&line) => {}
        other => {
            let _ = child.kill().await;
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
        let status = child.try_wait().ok().flatten();
        let verdict = classify_warden_observation(None, status);
        let _ = child.kill().await;
        return Ok((
            verdict,
            format!("write to child failed ({e}); classified from exit status"),
            SpawnStatus::Started,
        ));
    }

    let response = tokio::select! {
        line = read_jsonrpc_line(&mut reader) => line.ok(),
        status = child.wait_for_natural_exit() => {
            let st = status.ok();
            let verdict = classify_warden_observation(None, st);
            return Ok((verdict, format!("child exited before JSON-RPC ({st:?})"), SpawnStatus::Started));
        }
    };

    if let Some(ref line) = response
        && crate::legislator::protocol::jsonrpc_id_as_i64(line) != Some(10)
    {
        let _ = child.kill().await;
        return Ok((
            WardenVerdict::Inconclusive,
            format!("probe response id did not match id=10: {line}"),
            SpawnStatus::Started,
        ));
    }

    // A closed stdout (no JSON-RPC response) usually means the child was
    // killed (e.g. SIGSYS) — give the exit status a short, bounded window
    // to arrive instead of trusting a single non-reaped try_wait.
    let status = match response.as_deref() {
        Some(_) => child.try_wait().ok().flatten(),
        None => {
            match tokio::time::timeout(Duration::from_millis(800), child.wait_for_natural_exit())
                .await
            {
                Ok(st) => st.ok(),
                Err(_) => child.try_wait().ok().flatten(),
            }
        }
    };
    let verdict = classify_warden_observation(response.as_deref(), status);
    let _ = child.kill().await;
    let detail = match (&verdict, response.as_deref()) {
        (WardenVerdict::Pass, _) => "OS deny observed (SIGSYS)".to_string(),
        (WardenVerdict::Fail, Some(line)) => format!("child served the path: {line}"),
        (WardenVerdict::Inconclusive, Some(line)) => {
            format!("JSON-RPC self-report is not OS evidence: {line}")
        }
        (other, _) => format!("{} (no further detail)", other.as_str()),
    };
    Ok((verdict, detail, SpawnStatus::Started))
}

/// Known file-reading tool used by the Warden control call. No arbitrary fallback.
fn file_reading_tool(policy: &Policy) -> Option<&ToolPolicy> {
    policy
        .tools
        .iter()
        .find(|t| t.allowed && t.name == "read_file")
}

fn resolve_argv(command: &[String]) -> Result<Vec<String>, String> {
    let resolved = crate::verifier::hash::resolve_command_path(&command[0])
        .map_err(|e| format!("cannot resolve '{}': {e}", command[0]))?;
    let mut argv = command.to_vec();
    argv[0] = resolved.to_string_lossy().into_owned();
    Ok(argv)
}

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
    if crate::legislator::protocol::jsonrpc_id_as_i64(&line) != Some(1)
        || !jsonrpc_has_success_result(&line)
    {
        return Err(format!(
            "initialize did not return a success result: {line}"
        ));
    }
    write_line(stdin, &build_initialized_notification()).await?;
    Ok(())
}

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
        if crate::legislator::protocol::is_jsonrpc_notification(trimmed) {
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
            classify_warden_observation(Some(line), None),
            WardenVerdict::Inconclusive
        );
    }

    #[test]
    fn eacces_jsonrpc_is_not_warden_pass() {
        let line = r#"{"jsonrpc":"2.0","id":10,"error":{"code":-32603,"message":"EACCES - fabricated, no open performed"}}"#;
        assert!(!is_policy_jsonrpc_error(line));
        assert_eq!(
            classify_warden_observation(Some(line), None),
            WardenVerdict::Inconclusive
        );
    }

    #[test]
    fn mcp_iserror_result_is_not_warden_fail_or_pass() {
        let line = r#"{"jsonrpc":"2.0","id":10,"result":{"isError":true,"content":[{"type":"text","text":"EACCES"}]}}"#;
        assert!(!jsonrpc_has_success_result(line));
        assert_eq!(
            classify_warden_observation(Some(line), None),
            WardenVerdict::Inconclusive
        );
    }

    #[test]
    fn successful_open_is_warden_fail() {
        let line =
            r#"{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"root:x"}]}}"#;
        assert_eq!(
            classify_warden_observation(Some(line), None),
            WardenVerdict::Fail
        );
    }

    #[test]
    fn success_result_mentioning_permission_denied_is_not_warden_pass() {
        let line = r#"{"jsonrpc":"2.0","id":10,"result":{"content":[{"type":"text","text":"notes: EACCES / permission denied (os error 13)"}]}}"#;
        assert!(jsonrpc_has_success_result(line));
        assert_eq!(
            classify_warden_observation(Some(line), None),
            WardenVerdict::Fail
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
            for path in prepared
                .fs
                .read_only
                .iter()
                .chain(prepared.fs.read_write.iter())
            {
                let base = path.trim_end_matches("/**").trim_end_matches("/*");
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
