//! Windows Sandbox command backend for an interactive, single-VM session.
//! The host and Default Switch are trusted; relay credentials travel over TCP.
use std::net::{Shutdown, TcpStream};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    BackendCapabilities, BackendError, IsolationBackend, IsolationCheck, IsolationHandle,
    LaunchSpec, SessionStdio,
};
use crate::container::engine::BoxFuture;
use crate::execution::{IsolationKind, IsolationUnit, TargetArch, TargetOs};

pub mod agent;
mod management;
mod owned_job;
pub mod relay_protocol;
pub use management::prerequisites;

/// Host-side channel key carrying the Default Switch IPv4 that
/// `prerequisites()` already probed. `sandbox::run_inner` seeds it into
/// `LaunchSpec.env` so one launch performs the expensive PowerShell/`wsb`
/// probe once instead of once per trait call; a spec without it — a
/// direct `check`/`launch` — probes on demand.
pub(crate) const HOST_IP_ENV: &str = "MCP_WRIT_WSB_HOST_IP";

/// The launch's `allowed_peers` host address: reuse the IPv4 the spec
/// carries from the run's single prerequisite probe, or probe now when
/// the caller never seeded it.
async fn probed_host_ip(spec: &LaunchSpec) -> Result<String, BackendError> {
    if let Some((_, ip)) = spec.env.iter().find(|(k, _)| k == HOST_IP_ENV)
        && ip.parse::<std::net::Ipv4Addr>().is_ok()
    {
        return Ok(ip.clone());
    }
    prerequisites().await.map_err(failed)
}

pub(crate) async fn confirm_stopped(id: &str) -> Result<(), String> {
    let id = uuid::Uuid::parse_str(id).map_err(|e| e.to_string())?;
    let text = management::call(&management::cli(), &["list", "--raw"]).await?;
    if management::listed_ids(&text)?.contains(&id) {
        Err(format!("owned Sandbox {id} remains after cleanup"))
    } else {
        Ok(())
    }
}
use relay_protocol::*;

pub const CAPABILITIES: BackendCapabilities = BackendCapabilities {
    host_os: &[TargetOs::Windows],
    guest_os: &[TargetOs::Windows],
    oci_image: false,
    argv_command: true,
    stdio_pipes: true,
    terminate: true,
    host_shares: true,
    resource_limits: false,
    observations: &[
        "owned-sandbox-id",
        "authenticated-relay",
        "guest-report-mount",
    ],
};

/// Command/payload backend. There is no container engine or OCI image.
pub struct WindowsSandboxBackend;

fn failed(e: impl ToString) -> BackendError {
    BackendError::LaunchFailed(e.to_string())
}

impl IsolationBackend for WindowsSandboxBackend {
    fn kind(&self) -> IsolationKind {
        IsolationKind::WindowsSandbox
    }
    fn capabilities(&self) -> BackendCapabilities {
        CAPABILITIES
    }
    fn check<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<IsolationCheck, BackendError>> {
        Box::pin(async move {
            if spec.isolation != self.kind()
                || spec.image.is_some()
                || spec.command.is_none()
                || spec.guest_os != TargetOs::Windows
                || spec.guest_arch != TargetArch::X86_64
                || spec.shares.len() != 2
                || spec.shares[0].guest != r"C:\relay-ro"
                || spec.shares[0].writable
                || spec.shares[1].guest != r"C:\relay-rw"
                || !spec.shares[1].writable
            {
                return Err(BackendError::Unsupported("windows-sandbox requires a Windows x86-64 command and dedicated RO/RW shares; use run --isolation windows-sandbox".into()));
            }
            probed_host_ip(spec).await?;
            Ok(IsolationCheck { verified: self.kind(), unit: IsolationUnit::Vm,
                detail: Some("interactive guest logon; one owned Sandbox; 4096 MiB; plaintext TCP on trusted Default Switch".into()) })
        })
    }
    fn launch<'a>(
        &'a self,
        spec: &'a LaunchSpec,
    ) -> BoxFuture<'a, Result<Box<dyn IsolationHandle>, BackendError>> {
        Box::pin(async move {
            self.check(spec).await?;
            let ro = &spec.shares[0].host;
            let rw = &spec.shares[1].host;
            let command = spec
                .command
                .as_ref()
                .ok_or_else(|| failed("missing guest command"))?;
            let encoded = nojson::array(|f| {
                for arg in command {
                    f.element(arg.as_str())?;
                }
                Ok(())
            })
            .to_string();
            if encoded.len() > 64 * 1024 {
                return Err(failed("guest command exceeds 64 KiB"));
            }
            std::fs::write(ro.join("command.json"), encoded)?;
            let launch_id = spec
                .env
                .iter()
                .find(|(k, _)| k == "MCP_WRIT_LAUNCH_ID")
                .map(|(_, v)| v.clone())
                .ok_or_else(|| failed("missing launch ID"))?;
            // UUID v4 uses the OS CSPRNG; keep two hyphenated UUIDs per credential.
            let token = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            let peer_token = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            let host_ip = probed_host_ip(spec).await?;
            let mut config = format!(
                "guest=true\nproduct=true\nlisten_port=49152\nlaunch_id={launch_id}\ntoken={token}\npeer_token={peer_token}\nallowed_peers={host_ip}\n"
            );
            for (env, key) in [
                ("MCP_WRIT_SERVER", "server_name"),
                ("MCP_WRIT_FAIL_ON", "fail_on"),
            ] {
                if let Some((_, value)) = spec.env.iter().find(|(name, _)| name == env) {
                    if value.contains(['\n', '\r']) {
                        return Err(failed("relay config value contains a newline"));
                    }
                    config.push_str(&format!("{key}={value}\n"));
                }
            }
            std::fs::write(ro.join("relay-config.txt"), config)?;
            let xml = configuration(ro, rw);
            let id = uuid::Uuid::now_v7().to_string();
            if let Some(path) = &spec.unit_id_file {
                std::fs::write(path, &id)?;
            }
            let mut owned = management::OwnedSandbox::start(&xml, id)
                .await
                .map_err(failed)?;
            let hello_path = rw.join("relay-hello.txt");
            let connect = async {
                let address = loop {
                    if let Ok(file) = std::fs::File::open(&hello_path) {
                        use std::io::Read;
                        let mut text = String::new();
                        file.take(1025).read_to_string(&mut text)?;
                        if text.len() > 1024 {
                            return Err(failed("relay address record too large"));
                        }
                        let ip = text
                            .lines()
                            .find_map(|s| s.strip_prefix("ip="))
                            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
                        if let Some(ip) = ip {
                            break std::net::SocketAddr::from((ip, 49152));
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                };
                tokio::task::spawn_blocking(move || {
                    let mut conn = TcpStream::connect_timeout(&address, IO_TIMEOUT)?;
                    conn.set_nodelay(true)?;
                    let deadline = Instant::now() + IO_TIMEOUT;
                    let (kind, proof) = read_frame_until(&mut conn, deadline)?;
                    if kind != F_PEER || proof != hello(&launch_id, &peer_token).as_bytes() {
                        return Err(invalid("guest relay authentication failed"));
                    }
                    write_frame_until(
                        &mut conn,
                        F_HELLO,
                        hello(&launch_id, &token).as_bytes(),
                        deadline,
                    )?;
                    let (kind, proof) = read_frame_until(&mut conn, deadline)?;
                    if kind != F_HELLO_ACK || proof != ack(&launch_id).as_bytes() {
                        return Err(invalid("guest relay acknowledgement failed"));
                    }
                    Ok(conn)
                })
                .await
                .map_err(failed)?
                .map_err(BackendError::Io)
            };
            let conn = match tokio::time::timeout(Duration::from_secs(30), connect).await {
                Ok(Ok(conn)) => conn,
                result => {
                    let error = match result {
                        Ok(Err(e)) => e.to_string(),
                        _ => "guest relay did not connect within 30s".into(),
                    };
                    let cleanup = owned.stop().await;
                    return Err(failed(format!("{error}; cleanup={cleanup:?}")));
                }
            };
            Ok(Box::new(RelayHandle::new(owned, conn)?) as Box<dyn IsolationHandle>)
        })
    }
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn configuration(ro: &std::path::Path, rw: &std::path::Path) -> String {
    format!(
        r#"<Configuration>
<Networking>Enable</Networking><vGPU>Disable</vGPU><AudioInput>Disable</AudioInput>
<VideoInput>Disable</VideoInput><PrinterRedirection>Disable</PrinterRedirection>
<ClipboardRedirection>Disable</ClipboardRedirection><MemoryInMB>4096</MemoryInMB>
<MappedFolders>
<MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\relay-ro</SandboxFolder><ReadOnly>true</ReadOnly></MappedFolder>
<MappedFolder><HostFolder>{}</HostFolder><SandboxFolder>C:\relay-rw</SandboxFolder><ReadOnly>false</ReadOnly></MappedFolder>
</MappedFolders><LogonCommand><Command>cmd.exe /c C:\relay-ro\mcp-writ-wsb-relay.exe 1&gt; C:\relay-rw\agent-stdout.log 2&gt; C:\relay-rw\agent-stderr.log</Command></LogonCommand>
</Configuration>"#,
        xml_escape(&ro.to_string_lossy()),
        xml_escape(&rw.to_string_lossy())
    )
}

struct RelayHandle {
    owned: management::OwnedSandbox,
    socket: TcpStream,
    stopped: Arc<AtomicBool>,
    stdio: Option<SessionStdio>,
    exit: tokio::sync::oneshot::Receiver<Result<i32, String>>,
}

impl RelayHandle {
    fn new(owned: management::OwnedSandbox, socket: TcpStream) -> Result<Self, BackendError> {
        let (input, mut input_pump) = tokio::io::duplex(64 * 1024);
        let (output, mut output_pump) = tokio::io::duplex(64 * 1024);
        let mut reader_socket = socket.try_clone()?;
        let mut writer_socket = socket.try_clone()?;
        let (send, exit) = tokio::sync::oneshot::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let mut buf = [0; 64 * 1024];
            while !stop.load(Ordering::Acquire) {
                let read = runtime.block_on(async {
                    tokio::time::timeout(POLL, input_pump.read(&mut buf)).await
                });
                let (kind, bytes) = match read {
                    Err(_) => continue,
                    Ok(Ok(0)) => (F_STDIN_EOF, &[][..]),
                    Ok(Ok(n)) => (F_STDIN, &buf[..n]),
                    Ok(Err(_)) => break,
                };
                if write_frame(&mut writer_socket, kind, bytes).is_err() {
                    let _ = writer_socket.shutdown(Shutdown::Both);
                    break;
                }
                if kind == F_STDIN_EOF {
                    break;
                }
            }
        });
        let stop = stopped.clone();
        let runtime = tokio::runtime::Handle::current();
        tokio::task::spawn_blocking(move || {
            let result = (|| -> Result<i32, String> {
                let mut reader = FrameReader::default();
                while !stop.load(Ordering::Acquire) {
                    match reader.poll(&mut reader_socket).map_err(|e| e.to_string())? {
                        None => continue,
                        Some((F_STDOUT, data)) => {
                            runtime
                                .block_on(async {
                                    tokio::time::timeout(IO_TIMEOUT, output_pump.write_all(&data))
                                        .await
                                })
                                .map_err(|_| "host stdout backpressure deadline".to_string())?
                                .map_err(|e| e.to_string())?;
                        }
                        Some((F_STDERR, _)) => {
                            // Already retained in the guest's bounded stderr.log.
                            // Drain these frames without letting a blocked host
                            // diagnostic pipe stall MCP or owned-VM cleanup.
                        }
                        Some((F_EXIT, data)) => {
                            if data.len() > 64 {
                                return Err("invalid exit frame".into());
                            }
                            let text = std::str::from_utf8(&data).map_err(|e| e.to_string())?;
                            let json = nojson::RawJson::parse(text).map_err(|e| e.to_string())?;
                            let code = json
                                .value()
                                .to_member("code")
                                .and_then(|v| v.required())
                                .map_err(|e| e.to_string())?;
                            return i32::try_from(code).map_err(|e| e.to_string());
                        }
                        Some((F_AGENT_ERROR, _)) => {
                            return Err("guest relay failed; see bounded agent diagnostics".into());
                        }
                        Some(_) => return Err("unexpected guest relay frame".into()),
                    }
                }
                Err("relay stopped".into())
            })();
            drop(output_pump); // preserve trailing stdout before publishing exit
            let _ = send.send(result);
        });
        Ok(Self {
            owned,
            socket,
            stopped,
            stdio: Some(SessionStdio {
                stdin: Box::new(input),
                stdout: Box::new(output),
            }),
            exit,
        })
    }
}

impl IsolationHandle for RelayHandle {
    fn unit_id(&self) -> Option<String> {
        Some(self.owned.id.clone())
    }
    fn take_stdio(&mut self) -> Result<SessionStdio, BackendError> {
        self.stdio
            .take()
            .ok_or_else(|| failed("relay stdio already taken"))
    }
    fn wait_exit(&mut self) -> BoxFuture<'_, Result<i32, BackendError>> {
        Box::pin(async {
            let id = uuid::Uuid::parse_str(&self.owned.id).map_err(failed)?;
            // A stopped VM's NAT endpoint can leave an idle TCP connection
            // open. Observe the owned instance independently of MCP traffic,
            // so external stop also terminates a host with stdin still open.
            let gone = async {
                let mut failures = 0;
                loop {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let listing = management::call(&management::cli(), &["list", "--raw"]).await;
                    check_owned_listing(&id, listing, &mut failures)?;
                }
            };
            tokio::select! {
                result = &mut self.exit => result.map_err(failed)?.map_err(failed),
                result = gone => result,
            }
        })
    }
    fn terminate(&mut self) -> BoxFuture<'_, Result<(), BackendError>> {
        self.cleanup()
    }
    fn cleanup(&mut self) -> BoxFuture<'_, Result<(), BackendError>> {
        Box::pin(async {
            self.stopped.store(true, Ordering::Release);
            let _ = self.socket.shutdown(Shutdown::Both);
            self.stdio.take();
            self.owned.stop().await.map_err(failed)
        })
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

const MAX_LIST_FAILURES: u8 = 3;

fn check_owned_listing(
    id: &uuid::Uuid,
    listing: Result<String, String>,
    failures: &mut u8,
) -> Result<(), BackendError> {
    match listing.and_then(|text| management::listed_ids(&text)) {
        Ok(ids) => {
            *failures = 0;
            if !ids.contains(id) {
                return Err(failed("owned Windows Sandbox stopped during the session"));
            }
        }
        Err(error) => {
            *failures += 1;
            if *failures >= MAX_LIST_FAILURES {
                return Err(failed(format!(
                    "Windows Sandbox monitoring failed after {failures} consecutive listing failures: {error}"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owned_monitor_retries_call_and_parse_errors_and_resets_after_success() {
        let id = uuid::Uuid::new_v4();
        let listing = format!(r#"{{"WindowsSandboxEnvironments":[{{"Id":"{id}"}}]}}"#);
        let mut failures = 0;
        for _ in 0..2 {
            check_owned_listing(&id, Err("transient CLI error".into()), &mut failures).unwrap();
            check_owned_listing(&id, Ok("invalid JSON".into()), &mut failures).unwrap();
            assert_eq!(failures, 2);
            check_owned_listing(&id, Ok(listing.clone()), &mut failures).unwrap();
            assert_eq!(failures, 0);
        }
    }

    #[test]
    fn owned_monitor_fails_after_three_consecutive_call_or_parse_errors() {
        let id = uuid::Uuid::new_v4();
        for listing in [Err("CLI unavailable".into()), Ok("invalid JSON".into())] {
            let mut failures = 0;
            for _ in 1..MAX_LIST_FAILURES {
                check_owned_listing(&id, listing.clone(), &mut failures).unwrap();
            }
            let error = check_owned_listing(&id, listing, &mut failures).unwrap_err();
            assert!(error.to_string().contains("3 consecutive listing failures"));
        }
    }

    #[test]
    fn owned_monitor_fails_immediately_when_owned_id_is_absent() {
        let id = uuid::Uuid::new_v4();
        let other = uuid::Uuid::new_v4();
        for listing in [
            r#"{"WindowsSandboxEnvironments":[]}"#.to_string(),
            format!(r#"{{"WindowsSandboxEnvironments":[{{"Id":"{other}"}}]}}"#),
        ] {
            for mut failures in [0, MAX_LIST_FAILURES - 1] {
                let error =
                    check_owned_listing(&id, Ok(listing.clone()), &mut failures).unwrap_err();
                assert!(error.to_string().contains("stopped during the session"));
                assert_eq!(failures, 0);
            }
        }
    }
}
