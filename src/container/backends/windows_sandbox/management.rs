//! ID-based Windows Sandbox management. Never infer ownership from PIDs.
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;

const CALL_TIMEOUT: Duration = Duration::from_secs(15);
const OUTPUT_CAP: u64 = 64 * 1024;

pub(super) fn cli() -> PathBuf {
    std::env::var_os("MCP_WRIT_WSB_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "wsb.exe".into())
}

pub(super) async fn output(command: &mut Command, timeout: Duration) -> Result<String, String> {
    String::from_utf8(bounded_output(command, timeout).await?).map_err(|e| e.to_string())
}

async fn bounded_output(command: &mut Command, timeout: Duration) -> Result<Vec<u8>, String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW (management console only)
    let mut child = command
        .spawn()
        .map_err(|e| format!("management command: {e}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or("missing management stdout")?
        .take(OUTPUT_CAP + 1);
    let mut stderr = child
        .stderr
        .take()
        .ok_or("missing management stderr")?
        .take(OUTPUT_CAP + 1);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = tokio::time::timeout(timeout, async {
        tokio::try_join!(
            child.wait(),
            stdout.read_to_end(&mut out),
            stderr.read_to_end(&mut err)
        )
    })
    .await
    .map_err(|_| "management command deadline exceeded".to_string())?
    .map_err(|e| e.to_string())?;
    if out.len() > OUTPUT_CAP as usize || err.len() > OUTPUT_CAP as usize {
        return Err("management output exceeds 64 KiB".into());
    }
    if !result.0.success() {
        return Err(format!(
            "management command {}: {} {}",
            result.0,
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err)
        ));
    }
    Ok(out)
}

pub(super) async fn call(cli: &Path, args: &[&str]) -> Result<String, String> {
    output(Command::new(cli).args(args), CALL_TIMEOUT).await
}

pub(super) fn listed_ids(text: &str) -> Result<Vec<uuid::Uuid>, String> {
    let json = nojson::RawJson::parse(text).map_err(|e| format!("wsb list JSON: {e}"))?;
    json.value()
        .to_member("WindowsSandboxEnvironments")
        .and_then(|v| v.required())
        .and_then(|v| v.to_array())
        .map_err(|e| format!("wsb list environments: {e}"))?
        .map(|entry| {
            let id = entry
                .to_member("Id")
                .and_then(|v| v.required())
                .and_then(|v| v.as_string_str())
                .map_err(|e| e.to_string())?;
            uuid::Uuid::parse_str(id).map_err(|e| e.to_string())
        })
        .collect()
}

async fn has_client() -> Result<bool, String> {
    let bytes = bounded_output(
        Command::new("tasklist.exe").args([
            "/FI",
            "IMAGENAME eq WindowsSandbox*",
            "/FO",
            "CSV",
            "/NH",
        ]),
        CALL_TIMEOUT,
    )
    .await?;
    // tasklist uses the console code page for the localized no-match message.
    // Match only the ASCII executable column; wsb JSON remains strict UTF-8.
    let text = String::from_utf8_lossy(&bytes);
    Ok(text.lines().any(|line| {
        matches!(
            line.split(',').next().unwrap_or("").trim_matches('"'),
            "WindowsSandbox.exe" | "WindowsSandboxClient.exe" | "WindowsSandboxRemoteSession.exe"
        )
    }))
}

/// Read-only prerequisite probe shared by plan and launch. Returns the
/// host's Default Switch IPv4 — callers carry it through `LaunchSpec` so
/// one launch performs the PowerShell/`wsb` probe once instead of once
/// per trait call.
pub async fn prerequisites() -> Result<String, String> {
    if !cfg!(all(windows, target_arch = "x86_64")) {
        return Err("windows-sandbox requires a Windows x86-64 host".into());
    }
    let system = PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot is missing")?);
    if !system.join("System32/WindowsSandbox.exe").is_file() {
        return Err("enable Containers-DisposableClientVM, reboot, and update Windows Sandbox from the Store".into());
    }
    // Session 0 (services) cannot provide the accepted interactive guest logon.
    let session = output(Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command",
        "if (-not [Environment]::UserInteractive -or [Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) { exit 1 }; (Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' -AddressFamily IPv4 -ErrorAction Stop | Select-Object -First 1).IPAddress"
    ]), CALL_TIMEOUT).await.map_err(|e| format!("interactive logon and Default Switch IPv4 required: {e}"))?;
    let ip = session
        .trim()
        .parse::<std::net::Ipv4Addr>()
        .map_err(|_| "Default Switch IPv4 was not returned".to_string())?;
    let version = call(&cli(), &["--version"]).await?;
    if !supported_version(&version) {
        return Err(format!(
            "unsupported wsb CLI version (validated family: 0.8.x): {}",
            version.trim()
        ));
    }
    vacancy().await?;
    Ok(ip.to_string())
}

/// The cheap half of the readiness check: no owned environment exists and
/// no interactive Sandbox client is running. `OwnedSandbox::start` calls
/// it standalone under the cross-process launch lock — the race window a
/// top-level probe cannot close.
pub(super) async fn vacancy() -> Result<(), String> {
    if !listed_ids(&call(&cli(), &["list", "--raw"]).await?)?.is_empty() || has_client().await? {
        return Err(
            "an existing Windows Sandbox is active; close it before launching another".into(),
        );
    }
    Ok(())
}

fn supported_version(text: &str) -> bool {
    let parts: Result<Vec<u32>, _> = text.trim().split('.').map(str::parse).collect();
    matches!(parts.as_deref(), Ok([0, 8, build, _]) if *build >= 107)
}

/// A guard is armed before start, so failed/partial starts stop the reserved ID.
pub(super) struct OwnedSandbox {
    cli: PathBuf,
    pub(super) id: String,
    active: bool,
    client: Option<tokio::process::Child>,
    _lock: std::fs::File,
}

impl OwnedSandbox {
    pub(super) async fn start(xml: &str, id: String) -> Result<Self, String> {
        let root =
            PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or("LOCALAPPDATA is missing")?)
                .join("mcp-writ");
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("windows-sandbox.lock"))
            .map_err(|e| e.to_string())?;
        lock.try_lock()
            .map_err(|_| "another mcp-writ Windows Sandbox session is active".to_string())?;
        // Check under the cross-process lock, including existing user-owned VMs.
        vacancy().await?;
        let mut owned = Self {
            cli: cli(),
            id,
            active: false,
            client: None,
            _lock: lock,
        };
        let result = owned.start_inner(xml).await;
        if let Err(error) = result {
            return match owned.stop().await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(format!("{error}; cleanup failed: {cleanup}")),
            };
        }
        Ok(owned)
    }

    async fn start_inner(&mut self, xml: &str) -> Result<(), String> {
        let before = listed_ids(&call(&self.cli, &["list", "--raw"]).await?)?;
        let requested = uuid::Uuid::parse_str(&self.id).map_err(|e| e.to_string())?;
        if before.contains(&requested) {
            return Err("requested Sandbox ID already exists".into());
        }
        if !before.is_empty() {
            return Err("an existing Windows Sandbox is active".into());
        }
        self.active = true;
        call(
            &self.cli,
            &["start", "--id", &self.id, "--config", xml, "--raw"],
        )
        .await?;
        let ids = listed_ids(&call(&self.cli, &["list", "--raw"]).await?)?;
        let id = uuid::Uuid::parse_str(&self.id).map_err(|e| e.to_string())?;
        if !ids.contains(&id) {
            return Err("wsb did not create the requested owned ID".into());
        }
        self.client = Some(
            Command::new(&self.cli)
                .args(["connect", "--id", &self.id])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| format!("wsb connect: {e}"))?,
        );
        Ok(())
    }

    pub(super) async fn stop(&mut self) -> Result<(), String> {
        if self.active {
            let id = uuid::Uuid::parse_str(&self.id).map_err(|e| e.to_string())?;
            if listed_ids(&call(&self.cli, &["list", "--raw"]).await?)?.contains(&id) {
                call(&self.cli, &["stop", "--id", &self.id, "--raw"]).await?;
            }
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if !listed_ids(&call(&self.cli, &["list", "--raw"]).await?)?.contains(&id)
                        && !has_client().await?
                    {
                        return Ok::<_, String>(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            })
            .await
            .map_err(|_| "owned Sandbox ID/client did not disappear within 10s".to_string())??;
            self.active = false;
        }
        if let Some(mut child) = self.client.take() {
            let _ = child.kill().await;
        }
        Ok(())
    }
}

impl Drop for OwnedSandbox {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        // Last-resort bounded stop for cancellation/panic. Explicit cleanup is
        // awaited and reported; this guard never kills a process by name.
        let mut command = std::process::Command::new(&self.cli);
        command
            .args(["stop", "--id", &self.id, "--raw"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        if let Ok(mut child) = command.spawn() {
            let deadline = std::time::Instant::now() + CALL_TIMEOUT;
            loop {
                match child.try_wait() {
                    Ok(Some(status)) if status.success() => return,
                    // Terminated without success — try_wait already
                    // reaped it, nothing left to wait for.
                    Ok(Some(_)) => break,
                    // Still running or the poll failed: keep retrying
                    // until the deadline, then kill and reap below.
                    Ok(None) | Err(_) => {}
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        eprintln!(
            "cleanup unconfirmed for owned Sandbox {}; run wsb stop --id {}",
            self.id, self.id
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_parser_uses_only_instance_ids_and_rejects_unknown_shapes() {
        let id = uuid::Uuid::now_v7();
        assert!(
            listed_ids(&format!(
                r#"{{"WindowsSandboxEnvironments":[],"trace_id":"{id}"}}"#
            ))
            .unwrap()
            .is_empty()
        );
        assert_eq!(
            listed_ids(&format!(
                r#"{{"WindowsSandboxEnvironments":[{{"Id":"{id}"}}]}}"#
            ))
            .unwrap(),
            vec![id]
        );
        for text in [
            "{}",
            "[]",
            r#"{"WindowsSandboxEnvironments":[{"Id":"wrong"}]}"#,
        ] {
            assert!(listed_ids(text).is_err());
        }
        assert!(supported_version("0.8.107.0\n"));
        for text in ["0.8.9.0", "1.0.0.0", "junk0.8.107.0", "0.8.a.0"] {
            assert!(!supported_version(text));
        }
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn owned_management_partial_start_collision_and_wrong_id() {
        let build = tempfile::tempdir().unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/windows_sandbox/wsb_cli_stub.rs");
        let binary = build.path().join("stub.exe");
        assert!(
            std::process::Command::new("rustc")
                .args(["--edition=2024", "-o"])
                .arg(&binary)
                .arg(source)
                .status()
                .unwrap()
                .success()
        );
        for mode in [
            "ok",
            "fail",
            "wrong-id",
            "collision",
            "existing",
            "invalid-list",
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cli = dir.path().join("wsb.exe");
            std::fs::copy(&binary, &cli).unwrap();
            let id = uuid::Uuid::now_v7().to_string();
            let other = uuid::Uuid::now_v7().to_string();
            let initial = match mode {
                "collision" => format!(r#"{{"WindowsSandboxEnvironments":[{{"Id":"{id}"}}]}}"#),
                "existing" => format!(r#"{{"WindowsSandboxEnvironments":[{{"Id":"{other}"}}]}}"#),
                "invalid-list" => "{}".into(),
                _ => r#"{"WindowsSandboxEnvironments":[]}"#.into(),
            };
            std::fs::write(dir.path().join("ids.txt"), initial).unwrap();
            let lock = std::fs::File::create(dir.path().join("lock")).unwrap();
            let mut owned = OwnedSandbox {
                cli,
                id: id.clone(),
                active: false,
                client: None,
                _lock: lock,
            };
            let result = owned.start_inner(mode).await;
            assert_eq!(result.is_ok(), mode == "ok", "{mode}: {result:?}");
            owned.stop().await.unwrap();
            let calls = std::fs::read_to_string(dir.path().join("calls.txt")).unwrap();
            assert!(
                !calls
                    .lines()
                    .any(|line| line.starts_with("stop\t") && line.contains(&other))
            );
            if matches!(mode, "collision" | "existing" | "invalid-list") {
                assert!(
                    !calls.contains("start") && !calls.contains("stop"),
                    "{calls}"
                );
            } else if mode != "wrong-id" {
                assert_eq!(
                    calls
                        .lines()
                        .filter(|line| line.starts_with("stop\t") && line.contains(&id))
                        .count(),
                    1,
                    "{calls}"
                );
            }
        }
    }
}
