//! Real-machine validation of the Windows Sandbox stdio relay (PR-23).
//!
//! This prototype uses mapped folders (declared in the `.wsb`) and NAT
//! networking. The documented wsb exec command provides no process stdio;
//! lifecycle uses explicit instance IDs through wsb start/list/stop.
//! This test therefore drives the MCP contract through the PR-23 relay
//! pair (`tests/fixtures/windows_sandbox/wsb_relay_agent.rs` inside the
//! disposable VM, the in-test frame codec on the host):
//!
//!   host                                   guest (WDAGUtilityAccount)
//!   ────                                   ─────────────────────────
//!   MappedFolder RO → `C:\relay-ro`   ←──  agent reads config, stages
//!                                          runner/probe onto `C:\mcp-secure`
//!   MappedFolder RW → `C:\relay-rw`   ←──  agent writes relay-hello.txt,
//!                                          logs/, report/, stderr.log
//!   TCP (Default Switch)            ←──→   agent listens, host connects;
//!                                          length-prefixed frames carry
//!                                          the workload's stdio verbatim
//!
//! The guest is spawned as the `.wsb` `LogonCommand`; the host never
//! receives a command channel — the workload argv comes from the RO-share
//! config the host wrote before launch.
//!
//! Host protocol and real-VM test tiers, all gated on `MCP_WRIT_REQUIRE_WSB_TESTS=1` (see
//! `docs/validation/windows-sandbox.md`):
//!
//!   - `wsb_relay_loopback_protocol` runs the agent *on the host* against
//!     loopback — no Sandbox required. It proves the frame codec,
//!     handshake rejection (bad token / bad launch_id / non-hello first
//!     frame), bidirectional data, EOF, and that diagnostics never reach
//!     the stdout stream. A Windows runner + probe are still needed.
//!   - `wsb_relay_stdio_session` launches a real `.wsb` unit and drives
//!     the same MCP leg set as the Hyper-V validation — AppContainer
//!     token, DACL writes, capability denies, env hygiene — so the two
//!     substrates produce comparable evidence.
//!   - `wsb_relay_sandbox_kill_cleans_up` terminates the sandbox mid-
//!     session and verifies the relay socket dies, the child is torn
//!     down with the owned VM. Global vmwp counts are supplemental only.
//!
//! Prerequisites for the sandbox tier (any missing → skip, or fail with
//! `MCP_WRIT_REQUIRE_WSB_TESTS=1`):
//!   - Windows 11 with Sandbox support on x86_64 and the ID-based wsb CLI
//!     (see the validation document for this host's exact baseline)
//!   - `Containers-DisposableClientVM` enabled → `WindowsSandbox.exe`
//!     under `%SystemRoot%\System32`
//!   - an interactive logon session — `WindowsSandbox.exe` is the GUI
//!     client; this LogonCommand prototype requires guest logon
//!   - the Hyper-V Default Switch present (Networking=Enable needs it)
//!   - `rustc` for the two fixtures and a Windows PE `mcp-secure-runner`

mod common;
#[path = "fixtures/windows_sandbox/relay_protocol.rs"]
mod relay_protocol;
use relay_protocol::*;
#[path = "fixtures/windows_sandbox/relay_tests.rs"]
mod relay_tests;

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use mcp_writ::container::guest_report;

/// A first sandbox boot materializes the base image's runtime view and
/// the LogonCommand then has to stage files and bind; budgets cover the
/// slow path without turning a hang into a pass.
const SANDBOX_BOOT_SECS: u64 = 300;
const LEG_TIMEOUT_SECS: u64 = 60;
const TEARDOWN_SECS: u64 = 90;

/// Run at most one sandbox at a time — a boot is a VM with its own
/// memory footprint, and the mapped-share channels are per-launch.
static VM_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/windows_sandbox")
}

// ─── prerequisites ─────────────────────────────────────────────────────

fn check_host_prereqs() -> Option<String> {
    if !cfg!(windows) {
        return Some("host is not Windows — Windows Sandbox only exists there".into());
    }
    if !cfg!(target_arch = "x86_64") {
        return Some("host is not x86_64 — the host-built runner/probe must match".into());
    }
    None
}

/// `WindowsSandbox.exe` only exists when `Containers-DisposableClientVM`
/// is enabled; its absence is the precise "feature off" signal — staged
/// CBS payloads leave no executables behind.
fn windows_sandbox_exe() -> Option<PathBuf> {
    let p = PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join("System32")
        .join("WindowsSandbox.exe");
    p.is_file().then_some(p)
}

fn check_sandbox_prereqs() -> Option<String> {
    if let Some(reason) = check_host_prereqs() {
        return Some(reason);
    }
    if windows_sandbox_exe().is_none() {
        return Some(
            "WindowsSandbox.exe absent — enable the Windows feature \
             'Windows Sandbox' (Containers-DisposableClientVM) and reboot"
                .into(),
        );
    }
    if let Err(e) = cli_output(&wsb_cli(), &["list", "--raw"], Duration::from_secs(15)) {
        return Some(format!(
            "wsb CLI with instance IDs is required for owned teardown: {e}"
        ));
    }
    None
}

/// Compile a std-only fixture once per test binary with plain `rustc` —
/// same contract as `common::compiled_open_path_fixture` /
/// `hyperv_vm_e2e::compiled_hyperv_probe`.
fn compiled_fixture(src_name: &str, out_name: &str) -> Option<PathBuf> {
    let src = fixtures_dir().join(src_name);
    let dir = match tempfile::Builder::new()
        .prefix("mcp_writ_wsb_build_")
        .tempdir_in(test_root())
    {
        Ok(d) => d,
        Err(e) => {
            common::skip_wsb_test(&format!("fixture tempdir failed: {e}"));
            return None;
        }
    };
    let out = dir.path().join(out_name);
    let status = Command::new("rustc")
        .args(["--edition", "2024", "-D", "warnings", "-O", "-o"])
        .arg(&out)
        .arg(&src)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .status();
    match status {
        Ok(s) if s.success() && out.exists() => Some(dir.keep().join(out_name)),
        Ok(s) => {
            common::skip_wsb_test(&format!("rustc {src_name} failed: {s}"));
            None
        }
        Err(e) => {
            common::skip_wsb_test(&format!("rustc unavailable: {e}"));
            None
        }
    }
}

fn compiled_agent() -> Option<PathBuf> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| compiled_fixture("wsb_relay_agent.rs", "wsb-relay-agent.exe"))
        .clone()
}

fn compiled_probe() -> Option<PathBuf> {
    static FIXTURE: OnceLock<Option<PathBuf>> = OnceLock::new();
    FIXTURE
        .get_or_init(|| compiled_fixture("wsb_probe_server.rs", "wsb-probe.exe"))
        .clone()
}

/// Windows PE runner — same marker check as `hyperv_vm_e2e`: the report
/// channel only exists on runners that carry `MCP_WRIT_RUNNER_CAPS`.
fn windows_runner() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_BIN_EXE_mcp-secure-runner"));
    let bytes = std::fs::read(&path).ok()?;
    let is_pe = bytes.len() >= 2 && bytes[..2] == *b"MZ";
    if !is_pe {
        common::skip_wsb_test("mcp-secure-runner is not a Windows PE binary");
        return None;
    }
    if guest_report::scan_runner_caps(&bytes).is_none() {
        common::skip_wsb_test("runner has no MCP_WRIT_RUNNER_CAPS marker");
        return None;
    }
    Some(path)
}

// ─── session layout ────────────────────────────────────────────────────

struct WsbDirs {
    _root: tempfile::TempDir,
    /// Becomes the guest's read-only `C:\relay-ro` (or just a plain dir
    /// in the loopback tier).
    ro: PathBuf,
    /// Becomes the guest's writable `C:\relay-rw` — the only host-visible
    /// writable surface, carrying logs/report/status back.
    rw: PathBuf,
}

impl Drop for WsbDirs {
    fn drop(&mut self) {
        let Some(root) = std::env::var_os("MCP_WRIT_WSB_EVIDENCE_DIR") else {
            return;
        };
        let name = self._root.path().file_name().unwrap();
        let out = PathBuf::from(root).join(name);
        // Config credentials and staged executables are never evidence.
        for file in [
            "relay-status.txt",
            "agent.log",
            "stderr.log",
            "agent-stderr.log",
            "metrics.json",
            "guest-identity.json",
            "lifecycle.json",
            "host-memory-before.json",
            "host-memory-during.json",
            "host-memory-after.json",
            "report/report.json",
            "logs/audit.jsonl",
        ] {
            let src = self.rw.join(file);
            if src.is_file() {
                let dst = out.join(file);
                if let Err(e) = std::fs::create_dir_all(dst.parent().unwrap())
                    .and_then(|()| std::fs::copy(src, dst).map(|_| ()))
                {
                    eprintln!("evidence copy failed: {e}");
                }
            }
        }
    }
}

fn session_dirs() -> WsbDirs {
    let root = tempfile::Builder::new()
        .prefix("mcp_writ_wsb_run_")
        .tempdir_in(test_root())
        .expect("session tempdir");
    let ro = root.path().join("relay-ro");
    let rw = root.path().join("relay-rw");
    for d in [&ro, &rw] {
        std::fs::create_dir_all(d).expect("session dir");
    }
    WsbDirs {
        _root: root,
        ro,
        rw,
    }
}

/// Populate the read-only share: the three binaries plus the policy and
/// the relay config. Everything the guest needs arrives through this one
/// folder — the RW share stays empty until the agent itself writes.
fn stage_ro_dir(
    dirs: &WsbDirs,
    runner: &Path,
    agent: &Path,
    probe: &Path,
    policy_text: &str,
    config_text: &str,
) {
    for (src, name) in [
        (runner, "mcp-secure-runner.exe"),
        (agent, "wsb-relay-agent.exe"),
        (probe, "wsb-probe.exe"),
    ] {
        std::fs::copy(src, dirs.ro.join(name))
            .unwrap_or_else(|e| panic!("stage {}: {e}", src.display()));
        let bytes = std::fs::read(src).expect("read fixture PE");
        // Clean guests may lack the MSVC redistributable. Keep it app-local
        // beside both the RO-share agent and the staged runner/probe.
        for dll in
            mcp_writ::container::pe_magic::required_redist_dlls(&bytes).expect("fixture must be PE")
        {
            assert!(!dll.contains(['/', '\\']), "unexpected imported DLL path");
            let system =
                PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot")).join("System32");
            std::fs::copy(system.join(&dll), dirs.ro.join(&dll))
                .unwrap_or_else(|e| panic!("required app-local CRT {dll}: {e}"));
        }
    }
    std::fs::write(dirs.ro.join("policy.kdl"), policy_text).expect("stage policy");
    std::fs::write(dirs.ro.join("relay-config.txt"), config_text).expect("stage config");
}

/// Relay config the agent reads first. `paths` overrides the
/// `C:\…` defaults so the loopback tier can point the same binary at
/// host temp dirs.
fn relay_config(
    launch_id: &str,
    token: &str,
    listen_port: u16,
    allowed_peers: &[String],
    paths: &[(&str, &Path)],
) -> String {
    let (host_token, peer_token) = token.split_once(':').expect("two independent credentials");
    let mut s = format!(
        "peer_token={peer_token}\nlisten_port={listen_port}\nlaunch_id={launch_id}\ntoken={host_token}\n\
         allowed_peers={}\n",
        allowed_peers.join(",")
    );
    for (k, v) in paths {
        s.push_str(&format!("{k}={}\n", v.display()));
    }
    s
}

fn sandbox_config(launch_id: &str, token: &str, port: u16, host_ip: &str) -> String {
    relay_config(launch_id, token, port, &[host_ip.to_string()], &[]) + "guest=true\n"
}

/// The sandbox-tier policy is the checked-in fixture — its paths are the
/// fixed guest contract (`C:\relay-rw`, `C:\mcp-secure`, `C:\wsb-deny`).
fn sandbox_policy() -> String {
    std::fs::read_to_string(fixtures_dir().join("policy.kdl")).expect("read policy.kdl")
}

/// Loopback tier: same server/tool surface as `policy.kdl`, but every
/// path the legs touch is a host temp path — a loopback run must not
/// write to the host's real `C:\`.
fn loopback_policy(dirs: &WsbDirs, stage: &Path, deny: &Path) -> String {
    let f = |p: &Path| p.display().to_string().replace('\\', "/");
    let workspace = format!("{}/workspace", f(&dirs.rw));
    let tmp = format!("{}/tmp", f(&dirs.rw));
    let stage = f(stage);
    let drive = stage.split('/').next().unwrap();
    let read_paths = if drive.eq_ignore_ascii_case("C:") {
        "allow \"C:/**\"".to_string()
    } else {
        format!("allow \"C:/**\"; allow \"{drive}/**\"")
    };
    let write_paths = read_paths.replace("\";", "\" mode=\"write\";") + " mode=\"write\"";
    format!(
        r#"// Loopback-tier policy — same tool surface as policy.kdl, host
// temp paths substituted for the guest contract's C:\… paths.
policy version=1

defaults {{
    filesystem {{
        secret-overlay #true
        allow "{workspace}" mode="write"
        allow "{tmp}" mode="write"
        allow "{stage}" mode="read"
    }}
    network {{
        deny host="*"
    }}
    environment {{
    }}
}}

server "wsb-probe" {{
    tool "read_file" side_effect="read_only" {{
        filesystem {{ {read_paths} }}
    }}
    tool "vm_identity" side_effect="read_only" {{
        filesystem {{ {read_paths} }}
    }}
    tool "env_probe" side_effect="read_only" {{
        filesystem {{ {read_paths} }}
    }}
    tool "create_file" side_effect="write" {{
        filesystem {{ {write_paths} }}
    }}
    tool "net_probe" side_effect="read_only" {{
        filesystem {{ {read_paths} }}
    }}
    tool "spawn_child" side_effect="write" {{
        filesystem {{ {write_paths} }}
    }}
    tool "exit_child" side_effect="write" {{
        filesystem {{ {write_paths} }}
    }}
    tool "exec_shell" deny=#true
    tool "echo" side_effect="read_only" {{
        filesystem {{ {read_paths} }}
    }}
}}
// deny zone: {deny}
"#,
        deny = f(deny)
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The `.wsb` launch file. Networking stays enabled — the relay is the
/// one channel that needs it; mapped folders carry config in and
/// evidence out. `LogonCommand` starts the agent; its own console output
/// (launch failures before the share logging exists) is redirected onto
/// the RW share so the host can attribute a boot failure.
fn write_wsb_file(dirs: &WsbDirs) -> PathBuf {
    let wsb = format!(
        r#"<Configuration>
  <Networking>Enable</Networking>
  <vGPU>Disable</vGPU>
  <AudioInput>Disable</AudioInput>
  <VideoInput>Disable</VideoInput>
  <PrinterRedirection>Disable</PrinterRedirection>
  <ClipboardRedirection>Disable</ClipboardRedirection>
  <MemoryInMB>4096</MemoryInMB>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>C:\relay-ro</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>C:\relay-rw</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c C:\relay-ro\wsb-relay-agent.exe 1&gt; C:\relay-rw\agent-stdout.log 2&gt; C:\relay-rw\agent-stderr.log</Command>
  </LogonCommand>
</Configuration>
"#,
        xml_escape(&dirs.ro.display().to_string()),
        xml_escape(&dirs.rw.display().to_string()),
    );
    let path = dirs.ro.parent().unwrap().join("session.wsb");
    std::fs::write(&path, wsb).expect("write session.wsb");
    path
}

// ─── frame codec (host half) ───────────────────────────────────────────

/// The host-side end of the relay: stdout frames are accumulated into a
/// line buffer so JSON-RPC responses split across frames still resolve;
/// stderr frames are collected separately — the assertion surface for
/// "diagnostics never reach the stdout stream".
struct Relay {
    conn: TcpStream,
    reader: FrameReader,
    stdout_buf: Vec<u8>,
    lines: Vec<String>,
    stderr_bytes: Vec<u8>,
    exit_code: Option<Option<i32>>,
    agent_errors: Vec<String>,
}

impl Relay {
    /// Connect to a listening agent and complete the handshake. The
    /// `launch_id`/`token` pair binds this TCP connection to this
    /// launch — a guest-side caller with the port but not the token
    /// cannot attach to the workload.
    fn connect(
        addr: &str,
        launch_id: &str,
        token: &str,
        handshake_secs: u64,
    ) -> std::io::Result<Relay> {
        let sock: std::net::SocketAddr = addr
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        let mut conn = TcpStream::connect_timeout(&sock, Duration::from_secs(10))?;
        let deadline = Instant::now() + IO_TIMEOUT.min(Duration::from_secs(handshake_secs));
        conn.set_nodelay(true)?;
        let (host_token, peer_token) = token
            .split_once(':')
            .ok_or_else(|| invalid("missing peer credential"))?;
        let (kind, payload) = read_frame_until(&mut conn, deadline)?;
        if kind != F_PEER || payload != hello(launch_id, peer_token).as_bytes() {
            return Err(invalid("agent identity mismatch"));
        }
        write_frame_until(
            &mut conn,
            F_HELLO,
            hello(launch_id, host_token).as_bytes(),
            deadline,
        )?;
        let (kind, payload) = read_frame_until(&mut conn, deadline)?;
        if kind != F_HELLO_ACK || payload != ack(launch_id).as_bytes() {
            return Err(invalid("invalid hello acknowledgement"));
        }
        Ok(Relay {
            conn,
            reader: FrameReader::default(),
            stdout_buf: Vec::new(),
            lines: Vec::new(),
            stderr_bytes: Vec::new(),
            exit_code: None,
            agent_errors: Vec::new(),
        })
    }

    /// Fallible frame send — the kill leg provokes the dead socket
    /// rather than panic on it.
    fn try_send(&mut self, kind: u8, payload: &[u8]) -> std::io::Result<()> {
        write_frame(&mut self.conn, kind, payload)
    }

    fn send_line(&mut self, line: &str) {
        self.try_send(F_STDIN, format!("{line}\n").as_bytes())
            .expect("send stdin frame");
    }

    fn stdin_eof(&mut self) {
        self.try_send(F_STDIN_EOF, b"").expect("send stdin-eof");
    }

    /// One inbound frame: stdout feeds the line buffer, stderr and
    /// control frames update their own channels. Returns false on
    /// socket EOF/error — a bare read timeout returns true ("no data
    /// yet"), so callers poll it against their own deadline.
    fn pump_one(&mut self) -> bool {
        match self.reader.poll(&mut self.conn) {
            Ok(None) => true,
            Ok(Some((F_STDOUT, data))) => {
                if self.stdout_buf.len() + data.len() > MAX_FRAME + 64 * 1024
                    || self.lines.len() >= 64
                    || self.lines.iter().map(String::len).sum::<usize>()
                        + self.stdout_buf.len()
                        + data.len()
                        > 4 * MAX_FRAME
                {
                    self.agent_errors
                        .push("host stdout buffer cap exceeded".into());
                    return false;
                }
                self.stdout_buf.extend_from_slice(&data);
                while let Some(pos) = self.stdout_buf.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = self.stdout_buf.drain(..=pos).collect();
                    self.lines.push(String::from_utf8_lossy(&line).into_owned());
                }
                true
            }
            Ok(Some((F_STDERR, data))) => {
                if self.stderr_bytes.len() + data.len() > 64 * 1024 {
                    self.agent_errors.push("host stderr cap exceeded".into());
                    return false;
                }
                self.stderr_bytes.extend_from_slice(&data);
                true
            }
            Ok(Some((F_EXIT, payload))) => {
                let text = String::from_utf8_lossy(&payload).to_string();
                let code = text
                    .find("\"code\":")
                    .and_then(|p| text[p + 7..].trim_end_matches('}').parse::<i64>().ok())
                    .map(|c| c as i32);
                self.exit_code = Some(code);
                true
            }
            Ok(Some((F_AGENT_ERROR, payload))) => {
                self.agent_errors
                    .push(String::from_utf8_lossy(&payload).into_owned());
                false
            }
            Ok(Some((kind, _))) => {
                // Unknown frames are surfaced, not silently dropped —
                // a protocol peer that invents kinds is itself a finding.
                self.agent_errors
                    .push(format!("unexpected frame kind={kind:#04x}"));
                false
            }
            // A read timeout means "alive, no data" — any real socket
            // failure means the relay is gone.
            Err(e) => {
                if e.kind() != std::io::ErrorKind::UnexpectedEof {
                    self.agent_errors.push(format!("relay read: {e}"));
                }
                false
            }
        }
    }

    /// Read until a JSON-RPC response for `id` arrives in the stdout
    /// stream; earlier lines stay buffered for later lookups.
    fn wait_id(&mut self, id: i64, secs: u64) -> Option<String> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            if let Some(pos) = self
                .lines
                .iter()
                .position(|l| mcp_writ::protocol::jsonrpc_id_as_i64(l) == Some(id))
            {
                return Some(self.lines.remove(pos));
            }
            if Instant::now() > deadline || !self.pump_one() {
                return None;
            }
        }
    }

    /// Wait for the agent's `exit` frame after stdin EOF.
    fn wait_exit(&mut self, secs: u64) -> Option<Option<i32>> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while self.exit_code.is_none() {
            if Instant::now() > deadline || !self.pump_one() {
                return None;
            }
        }
        self.exit_code
    }
}

fn request(id: i64, method: &str, params: &str) -> String {
    format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"{method}\",\"params\":{params}}}")
}

fn tool_call(id: i64, name: &str, args: &str) -> String {
    request(
        id,
        "tools/call",
        &format!("{{\"name\":\"{name}\",\"arguments\":{args}}}"),
    )
}

// ─── host-side sandbox helpers ─────────────────────────────────────────

/// The host's address on the Hyper-V Default Switch — what the guest
/// sees as the peer when the host connects back. `allowed_peers` in the
/// relay config pins the handshake to exactly this address.
fn host_default_switch_ip() -> Option<String> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetIPAddress -InterfaceAlias 'vEthernet (Default Switch)' \
             -AddressFamily IPv4 -ErrorAction SilentlyContinue).IPAddress",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .find(|l| l.parse::<std::net::Ipv4Addr>().is_ok())
}

/// Global worker count for supplemental diagnostics. It cannot establish
/// ownership or attribute teardown to a particular VM.
fn vmwp_count() -> usize {
    Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq vmwp.exe", "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.contains("vmwp.exe"))
                .count()
        })
        .unwrap_or(0)
}

fn wait_file(path: &Path, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if path.is_file() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn wait_until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

/// Parse `relay-hello.txt` the agent published on the RW share —
/// `ip=`/`port=`/`pid=` lines — into a connectable `ip:port`.
fn read_relay_hello(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut ip = None;
    let mut port = None;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("ip=") {
            ip = Some(v.trim().to_string());
        }
        if let Some(v) = line.strip_prefix("port=") {
            port = Some(v.trim().to_string());
        }
    }
    Some(format!("{}:{}", ip?, port?))
}

/// Status lines the agent appends to `relay-status.txt` — the coarse
/// lifecycle channel the host reads when the socket is not up (or is
/// deliberately refused).
fn relay_status_lines(rw: &Path) -> Vec<String> {
    std::fs::read_to_string(rw.join("relay-status.txt"))
        .map(|t| t.lines().map(|l| l.to_string()).collect())
        .unwrap_or_default()
}

/// Pids of Windows Sandbox interactive clients on the machine.
/// Used only to refuse an existing interactive Sandbox before launch.
/// These PIDs are never used for teardown or ownership inference.
/// The Store version keeps WindowsSandboxServer alive while no VM exists.
fn sandbox_pids() -> std::io::Result<Vec<u32>> {
    let out = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq WindowsSandbox*", "/FO", "CSV", "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let out = out?;
    if !out.status.success() {
        return Err(std::io::Error::other("tasklist failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut cols = l.split(',');
            let name = cols.next()?.trim_matches('"');
            if !matches!(
                name,
                "WindowsSandbox.exe"
                    | "WindowsSandboxClient.exe"
                    | "WindowsSandboxRemoteSession.exe"
            ) {
                return None;
            }
            cols.next()?.trim_matches('"').parse::<u32>().ok()
        })
        .collect())
}

/// The documented wsb CLI accepts an explicit ID. This is the sole teardown
/// authority; an unrelated process appearing after launch is never owned.
struct SandboxGuard {
    cli: PathBuf,
    id: String,
    connect: Option<std::process::Child>,
    active: bool,
    _lock: Option<std::fs::File>,
}

fn wsb_cli() -> PathBuf {
    std::env::var_os("MCP_WRIT_WSB_EXE")
        .map(PathBuf::from)
        .unwrap_or_else(|| "wsb.exe".into())
}

/// Pipe output through temporary files so waiting cannot deadlock on a full
/// stdout pipe. Only 64 KiB is read back. Every management call has a deadline.
fn cli_output(cli: &Path, args: &[&str], timeout: Duration) -> Result<String, String> {
    let out = tempfile::tempfile_in(test_root()).map_err(|e| e.to_string())?;
    let err = tempfile::tempfile_in(test_root()).map_err(|e| e.to_string())?;
    let child = Command::new(cli)
        .args(args)
        .stdin(Stdio::null())
        .stdout(out.try_clone().map_err(|e| e.to_string())?)
        .stderr(err.try_clone().map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("{}: {e}", cli.display()))?;
    let mut child = ProcGuard(child);
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.0.try_wait().map_err(|e| e.to_string())? {
            use std::io::{Seek, SeekFrom};
            let read = |mut file: std::fs::File| -> std::io::Result<String> {
                file.seek(SeekFrom::Start(0))?;
                let mut text = String::new();
                file.take(64 * 1024).read_to_string(&mut text)?;
                Ok(text)
            };
            let stdout = read(out).map_err(|e| e.to_string())?;
            let stderr = read(err).map_err(|e| e.to_string())?;
            return if status.success() {
                Ok(stdout)
            } else {
                Err(format!("wsb {args:?}: {status}: {stdout} {stderr}"))
            };
        }
        if Instant::now() >= deadline {
            return Err(format!("wsb {} exceeded {}s", args[0], timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn listed_ids(text: &str) -> Result<Vec<uuid::Uuid>, String> {
    let json = nojson::RawJson::parse(text).map_err(|e| format!("wsb list JSON: {e}"))?;
    let environments = json
        .value()
        .to_member("WindowsSandboxEnvironments")
        .and_then(|v| v.required())
        .and_then(|v| v.to_array())
        .map_err(|e| format!("wsb list environments: {e}"))?;
    environments
        .map(|environment| {
            let id = environment
                .to_member("Id")
                .and_then(|v| v.required())
                .and_then(|v| v.as_string_str())
                .map_err(|e| format!("wsb list instance ID: {e}"))?;
            uuid::Uuid::parse_str(id).map_err(|e| format!("wsb list instance ID: {e}"))
        })
        .collect()
}

impl SandboxGuard {
    fn launch(wsb: &Path) -> SandboxGuard {
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(test_root().join("sandbox.lock"))
            .expect("open Sandbox validation lock");
        lock.try_lock()
            .expect("another Sandbox validation process is active");
        // The supported prototype uses a user session. Refuse an existing
        // client instead of depending on legacy singleton activation behavior.
        assert!(
            sandbox_pids()
                .expect("inspect existing Sandbox clients")
                .is_empty(),
            "an existing Windows Sandbox is active; close it before validation"
        );
        let xml = std::fs::read_to_string(wsb).expect("read sandbox configuration");
        let id = uuid::Uuid::now_v7().to_string();
        let mut owned =
            Self::launch_with(wsb_cli(), id, &xml, Duration::from_secs(SANDBOX_BOOT_SECS))
                .unwrap_or_else(|e| panic!("Sandbox launch failed: {e}"));
        owned._lock = Some(lock);
        owned
    }

    fn launch_with(cli: PathBuf, id: String, xml: &str, timeout: Duration) -> Result<Self, String> {
        let before = cli_output(&cli, &["list", "--raw"], Duration::from_secs(15))?;
        let parsed_id = uuid::Uuid::parse_str(&id).map_err(|e| e.to_string())?;
        let existing_ids = listed_ids(&before)?;
        if existing_ids.contains(&parsed_id) {
            return Err("requested Sandbox ID already exists".into());
        }
        if !existing_ids.is_empty() {
            return Err("an existing Windows Sandbox is active; close it before validation".into());
        }
        // Arm before start: failure/timeouts can happen after the VM was made.
        let mut owned = Self {
            cli,
            id,
            connect: None,
            active: true,
            _lock: None,
        };
        cli_output(
            &owned.cli,
            &["start", "--id", &owned.id, "--config", xml, "--raw"],
            timeout,
        )?;
        let after = cli_output(&owned.cli, &["list", "--raw"], Duration::from_secs(15))?;
        if !listed_ids(&after)?.contains(&parsed_id) {
            return Err("wsb did not return the requested owned ID".into());
        }
        // LogonCommand needs a guest logon. Keep the connection client handle;
        // stopping the VM itself always goes through the explicit ID.
        owned.connect = Some(
            Command::new(&owned.cli)
                .args(["connect", "--id", &owned.id])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("wsb connect: {e}"))?,
        );
        eprintln!("owned Sandbox id={}", owned.id);
        Ok(owned)
    }

    fn kill(&mut self) -> Result<(), String> {
        if self.active {
            let deadline = Instant::now() + Duration::from_secs(TEARDOWN_SECS);
            cli_output(
                &self.cli,
                &["stop", "--id", &self.id, "--raw"],
                Duration::from_secs(TEARDOWN_SECS),
            )?;
            self.active = false;
            // Store Sandbox returns from stop before its remote-session UI
            // always exits. Wait for shutdown before releasing the VM lock;
            // process enumeration is only a readiness check, never a kill list.
            let id = uuid::Uuid::parse_str(&self.id).map_err(|e| e.to_string())?;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err("Sandbox ID or interactive client remained after stop".into());
                }
                let list = cli_output(
                    &self.cli,
                    &["list", "--raw"],
                    remaining.min(Duration::from_secs(15)),
                )?;
                if !listed_ids(&list)?.contains(&id)
                    && sandbox_pids().map_err(|e| e.to_string())?.is_empty()
                {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        if let Some(mut client) = self.connect.take() {
            let _ = client.kill();
            let _ = client.wait();
        }
        Ok(())
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        if let Err(e) = self.kill() {
            eprintln!(
                "CLEANUP FAILED for owned Sandbox {}: {e}; run wsb stop --id {}",
                self.id, self.id
            );
        }
    }
}

/// Pick an unused TCP port — bind :0, release, reuse the number. The
/// loopback tier needs one for the host-side agent; for the sandbox the
/// port is allocated inside the guest where nothing else is listening,
/// so a fixed-looking port is fine — but a collision would read as a
/// guest bind failure either way, so use the same picker.
fn pick_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind :0")
        .local_addr()
        .expect("local_addr")
        .port()
}

// ─── shared MCP session ────────────────────────────────────────────────

/// Drive the probe's full leg set over an established relay connection.
/// `workspace` is the guest-visible writable path the `create_file`
/// legs use; `deny_dir` is a guest-NTFS path with no policy grant.
/// `ro_deny` names a write target that must be denied by the substrate's
/// *read-only* surface — `C:\relay-ro` in the sandbox tier; the loopback
/// tier passes `None` because a host dir has no RO mapping to invoke.
/// Returns every response line keyed by id.
fn run_probe_legs(
    relay: &mut Relay,
    launch_client: &str,
    workspace: &str,
    deny_dir: &str,
    ro_deny: Option<&str>,
) -> std::collections::HashMap<i64, String> {
    relay.send_line(&request(
        0,
        "initialize",
        &format!(
            "{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\
             \"clientInfo\":{{\"name\":\"{launch_client}\",\"version\":\"0\"}}}}"
        ),
    ));
    let init = relay
        .wait_id(0, LEG_TIMEOUT_SECS)
        .expect("initialize response never arrived — runner/agent boot failed");
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    relay.send_line("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");
    relay.send_line(&request(1, "tools/list", "{}"));
    let list = relay
        .wait_id(1, LEG_TIMEOUT_SECS)
        .expect("tools/list response never arrived");
    assert!(
        list.contains("\"result\"") && list.contains("net_probe"),
        "tools/list must return the probe's tool inventory, got: {list}"
    );

    let legs: &[(i64, &str, String)] = &[
        (2, "vm_identity", format!("{{\"path\":\"{workspace}\"}}")),
        (
            3,
            "create_file",
            format!("{{\"path\":\"{workspace}/wsb-ok.txt\",\"content\":\"wsb\"}}"),
        ),
        (
            4,
            "read_file",
            format!("{{\"path\":\"{workspace}/wsb-ok.txt\"}}"),
        ),
        // Secret-overlay deny at the RPC layer — `.ssh` is a reserved
        // directory name on every platform; never reaches the tool.
        (
            5,
            "read_file",
            format!("{{\"path\":\"{workspace}/.ssh/id_rsa\"}}"),
        ),
        // AppContainer DACL: `C:\Windows` is writable by Administrators
        // but the confined child has no ACE there.
        (
            6,
            "create_file",
            "{\"path\":\"C:/Windows/wsb-evil.txt\",\"content\":\"x\"}".into(),
        ),
        // Guest-NTFS deny zone — created by the agent, granted nowhere.
        (
            7,
            "create_file",
            format!("{{\"path\":\"{deny_dir}/evil.txt\",\"content\":\"x\"}}"),
        ),
        // AppContainer capability: the policy grants no network caps.
        (
            8,
            "net_probe",
            format!("{{\"addr\":\"192.0.2.1:80\",\"path\":\"{workspace}\"}}"),
        ),
        // Descendant creation under the warden's launch conditions.
        (9, "spawn_child", format!("{{\"path\":\"{workspace}\"}}")),
        (10, "env_probe", format!("{{\"path\":\"{workspace}\"}}")),
        // Auditor tool gate.
        (11, "exec_shell", "{\"cmd\":\"id\"}".into()),
    ];
    let mut leg_ids: Vec<i64> = legs.iter().map(|(id, ..)| *id).collect();
    for (id, name_, args) in legs {
        relay.send_line(&tool_call(*id, name_, args));
    }
    // The confined write must fail. The unconfined agent separately probes
    // RO mapping enforcement before it publishes its listening endpoint.
    if let Some(path) = ro_deny {
        relay.send_line(&tool_call(
            12,
            "create_file",
            &format!("{{\"path\":\"{path}\",\"content\":\"x\"}}"),
        ));
        leg_ids.push(12);
    }
    relay.send_line(&request(13, "evil/method", "{}"));
    leg_ids.push(13);

    let mut got = std::collections::HashMap::new();
    for id in leg_ids {
        let line = relay
            .wait_id(id, LEG_TIMEOUT_SECS)
            .unwrap_or_else(|| panic!("no response for id={id}"));
        got.insert(id, line);
    }
    got
}

/// Assert the stdout stream carried nothing but JSON-RPC — the
/// "diagnostics must not contaminate MCP stdout" leg. `lines` are the
/// already-consumed responses; `lines`/`stdout_buf` still pending are
/// checked too.
fn assert_stdout_is_pure_jsonrpc(
    relay: &Relay,
    responses: &std::collections::HashMap<i64, String>,
) {
    for line in responses.values().chain(relay.lines.iter()) {
        let json = nojson::RawJson::parse(line.trim()).expect("stdout must be complete JSON");
        assert_eq!(
            json.value()
                .to_member("jsonrpc")
                .unwrap()
                .required()
                .unwrap()
                .as_string_str()
                .unwrap(),
            "2.0"
        );
    }
    assert!(
        relay.stdout_buf.is_empty(),
        "incomplete trailing stdout frame"
    );
}

/// The stderr channel is where the runner's tracing must land — assert
/// it saw traffic (the runner always emits its launch logs at info
/// level) and that none of it leaked into a response.
fn assert_diagnostics_on_stderr_only(relay: &Relay) {
    let stderr = String::from_utf8_lossy(&relay.stderr_bytes);
    assert!(
        !stderr.is_empty(),
        "runner tracing expected on the stderr frame channel"
    );
    assert!(
        stderr.contains("Policy loaded"),
        "stderr channel must carry runner diagnostics (\"Policy loaded\"): {stderr}"
    );
}

fn assert_report(dirs: &WsbDirs, launch_id: &str) {
    let report_path = dirs.rw.join("report").join("report.json");
    let report = std::fs::read_to_string(&report_path).unwrap_or_else(|e| {
        panic!(
            "guest report missing at {}: {e} (status: {:?})",
            report_path.display(),
            relay_status_lines(&dirs.rw)
        )
    });
    guest_report::validate_guest_report_text(
        &report,
        uuid::Uuid::parse_str(launch_id).unwrap(),
        Some(env!("CARGO_PKG_VERSION")),
    )
    .expect("guest report must carry this launch's id and runner identity");
    let json = nojson::RawJson::parse(&report).unwrap();
    let observations = json
        .value()
        .to_member("observations")
        .unwrap()
        .required()
        .unwrap();
    for required in ["os.process", "os.fs", "os.net.outbound"] {
        let observed = observations
            .to_array()
            .unwrap()
            .find(|o| {
                o.to_member("control")
                    .unwrap()
                    .required()
                    .unwrap()
                    .as_string_str()
                    .unwrap()
                    == required
            })
            .unwrap_or_else(|| panic!("missing {required} observation"));
        assert_eq!(
            observed
                .to_member("state")
                .unwrap()
                .required()
                .unwrap()
                .as_string_str()
                .unwrap(),
            "verified",
            "required guest control {required} was not verified"
        );
    }
    for needle in [
        "\"os.process\",\"layer\":\"os\",\"mechanism\":\"appcontainer + job\"",
        "\"os.fs\",\"layer\":\"os\",\"mechanism\":\"appcontainer + dacl\"",
        "\"os.net.outbound\",\"layer\":\"os\",\"mechanism\":\"appcontainer capabilities\"",
    ] {
        assert!(
            report.contains(needle),
            "guest report must contain {needle:?}"
        );
    }
}

fn assert_audit(dirs: &WsbDirs) {
    let audit = std::fs::read_to_string(dirs.rw.join("logs").join("audit.jsonl"))
        .expect("audit log missing on the RW share");
    assert!(
        audit.contains("tool_call.denied") && audit.contains("mcp_message.allowed"),
        "audit log must record allows and denies"
    );
}

/// Measure the same small and large RPC through the real runner in both tiers.
/// Measurements are observations; PR-24 budgets are set after the VM baseline.
fn measure_rpc(relay: &mut Relay, workspace: &str, rw: &Path, contact_s: f64, tier: &str) {
    let large = "x".repeat(900 * 1024);
    relay.send_line(&tool_call(
        100,
        "echo",
        &format!("{{\"path\":\"{workspace}\",\"text\":\"{large}\"}}"),
    ));
    // Deliberately pause the receiver before draining a response split into
    // many relay frames. The payload must remain byte-for-byte intact.
    std::thread::sleep(Duration::from_millis(300));
    let reply = relay.wait_id(100, 30).expect("large echo response");
    let expected = format!("\"text\":\"{large}\"");
    assert!(
        reply.contains(&expected),
        "large echo was truncated or corrupted"
    );
    let mut samples = Vec::new();
    for id in 101..131 {
        let start = Instant::now();
        relay.send_line(&tool_call(
            id,
            "echo",
            &format!("{{\"path\":\"{workspace}\",\"text\":\"ping\"}}"),
        ));
        let reply = relay.wait_id(id, 30).expect("latency echo response");
        assert!(reply.contains("\"text\":\"ping\""));
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    let median = (samples[14] + samples[15]) / 2.0;
    let p95 = samples[28];
    let metrics = format!(
        "{{\"tier\":\"{tier}\",\"first_contact_s\":{contact_s},\"rpc_samples\":30,\"rpc_median_ms\":{median},\"rpc_p95_ms\":{p95},\"large_echo_bytes\":921600}}\n"
    );
    std::fs::write(rw.join("metrics.json"), &metrics).unwrap();
    eprintln!("relay measurements: {}", metrics.trim());
}

/// These are host-wide observations, not per-ID VM accounting. Retain the
/// raw counter names/values so background VM activity stays visible.
fn host_memory_snapshot(rw: &Path, phase: &str) {
    let script = r#"$ErrorActionPreference='Stop';
$os=Get-CimInstance Win32_OperatingSystem;
$counters=@(Get-CimInstance Win32_PerfFormattedData_BalancerStats_HyperVDynamicMemoryVM |
    Select-Object Name,PhysicalMemory,GuestVisiblePhysicalMemory);
[pscustomobject]@{utc=[DateTime]::UtcNow.ToString('o');
    host_available_bytes=[uint64]$os.FreePhysicalMemory*1024;
    hyperv_counters=$counters} | ConvertTo-Json -Depth 4 -Compress"#;
    let snapshot = cli_output(
        Path::new("powershell.exe"),
        &["-NoProfile", "-NonInteractive", "-Command", script],
        Duration::from_secs(15),
    )
    .expect("host memory counters");
    nojson::RawJson::parse(&snapshot).expect("host memory JSON");
    std::fs::write(rw.join(format!("host-memory-{phase}.json")), snapshot).unwrap();
}

fn stop_sandbox(sandbox: &mut SandboxGuard, dirs: &WsbDirs) -> f64 {
    let start = Instant::now();
    sandbox.kill().expect("stop only the owned Sandbox ID");
    let stop_s = start.elapsed().as_secs_f64();
    std::fs::write(
        dirs.rw.join("lifecycle.json"),
        format!(
            "{{\"sandbox_id\":\"{}\",\"owned_id_absent_after_stop\":true,\"interactive_clients_closed\":true,\"stop_s\":{stop_s}}}\n",
            sandbox.id
        ),
    )
    .unwrap();
    stop_s
}

fn finish_vm_metrics(dirs: &WsbDirs, ident: &str, stop_s: f64) {
    let json = nojson::RawJson::parse(ident).unwrap();
    let text = json
        .value()
        .to_member("result")
        .unwrap()
        .required()
        .unwrap()
        .to_member("content")
        .unwrap()
        .required()
        .unwrap()
        .to_array()
        .unwrap()
        .next()
        .unwrap()
        .to_member("text")
        .unwrap()
        .required()
        .unwrap()
        .as_string_str()
        .unwrap();
    let value = |key: &str| -> u64 {
        text.split_ascii_whitespace()
            .find_map(|field| field.strip_prefix(key))
            .expect("guest memory field")
            .parse()
            .expect("guest memory bytes")
    };
    let total = value("guest_total_physical_bytes=");
    let available = value("guest_available_physical_bytes=");
    assert!(
        total > 0 && available <= total,
        "invalid guest memory sample"
    );
    std::fs::write(dirs.rw.join("guest-identity.json"), ident).unwrap();
    let metrics = std::fs::read_to_string(dirs.rw.join("metrics.json")).unwrap();
    let prefix = metrics.trim().strip_suffix('}').unwrap();
    let metrics = format!(
        "{prefix},\"stop_s\":{stop_s},\"configured_memory_mib\":4096,\"guest_total_physical_bytes\":{total},\"guest_available_physical_bytes\":{available}}}\n"
    );
    std::fs::write(dirs.rw.join("metrics.json"), &metrics).unwrap();
    eprintln!("VM measurements: {}", metrics.trim());
}

/// Shared leg assertions for both tiers — the response expectations are
/// identical; only the paths differ. `expect_ro_deny` mirrors
/// `run_probe_legs`' `ro_deny`: leg 12 only ran (and is only asserted)
/// where a read-only mapping exists.
fn assert_common_legs(
    got: &std::collections::HashMap<i64, String>,
    workspace: &str,
    expect_ro_deny: bool,
) {
    let text_of = |id: i64| got.get(&id).cloned().unwrap_or_default();
    let ident = text_of(2);
    assert!(
        ident.contains("appcontainer=true"),
        "the spawned child must carry an AppContainer token: {ident}"
    );
    assert!(
        ident.contains("in_job=true"),
        "the spawned child must be inside the warden's Job object: {ident}"
    );
    assert!(
        text_of(3).contains(&format!("created {workspace}/wsb-ok.txt")),
        "write inside the workspace grant must succeed: {}",
        text_of(3)
    );
    assert!(
        text_of(4).contains(&format!("opened {workspace}/wsb-ok.txt")),
        "read inside the workspace grant must succeed: {}",
        text_of(4)
    );
    assert!(
        text_of(5).contains("secret-path overlay"),
        "secret paths must deny at the RPC layer: {}",
        text_of(5)
    );
    // `os error 5` (ERROR_ACCESS_DENIED), not the localized message.
    assert!(
        text_of(6).contains("os error 5"),
        "write to C:\\Windows must hit the AppContainer DACL deny: {}",
        text_of(6)
    );
    assert!(
        text_of(7).contains("os error 5"),
        "write to the ungranted deny zone must hit the DACL deny: {}",
        text_of(7)
    );
    // `os error 10013` pins WSAEACCES — a timeout would mean the
    // capability deny never engaged.
    assert!(
        text_of(8).contains("os error 10013"),
        "TCP connect must hit the AppContainer capability deny (WSAEACCES): {}",
        text_of(8)
    );
    // Descendant creation is substrate-dependent: the Hyper-V container's
    // process-limit Job denies it (`!CHILD_OK` there), while the plain
    // Windows warden — which is what runs on both this host loopback and
    // inside the sandbox VM — allows descendants that remain inside the
    // same AppContainer/Job confinement. Here the honest assertion is
    // the observed allow; a denial under WSB would itself be a recorded
    // substrate difference, not a relay defect.
    assert!(
        text_of(9).contains("spawn ok"),
        "descendant creation under the native warden must produce a spawn verdict: {}",
        text_of(9)
    );
    assert!(
        text_of(10).contains("mcp_vars_present=[]"),
        "MCP_* control variables must not reach the workload env: {}",
        text_of(10)
    );
    assert!(
        text_of(11).contains("tool is not allowed"),
        "deny=#true tool must be refused by the auditor: {}",
        text_of(11)
    );
    if expect_ro_deny {
        // Any read-only-surface denial counts — the RO mapping's own
        // rejection and the DACL layer's are both attributable; what
        // must never appear is `created`.
        assert!(
            text_of(12).contains("os error"),
            "write to the read-only mapped share must be denied: {}",
            text_of(12)
        );
        assert!(
            !text_of(12).contains("\"created"),
            "the RO-share write must not succeed: {}",
            text_of(12)
        );
    }
    assert!(
        text_of(13).contains("unknown-method"),
        "unknown method must be refused: {}",
        text_of(13)
    );
}

// ─── tier 1: loopback protocol validation ──────────────────────────────

/// The relay protocol proven end-to-end without the sandbox: the agent
/// runs on the host against loopback with temp-dir paths. This tier
/// owns the handshake/codec/EOF/diagnostics-separation evidence — the
/// parts that do not depend on the VM substrate at all.
#[test]
fn wsb_relay_loopback_protocol() {
    if let Some(reason) = check_host_prereqs() {
        common::skip_wsb_test(&reason);
        return;
    }
    let Some(agent) = compiled_agent() else {
        return;
    };
    let Some(probe) = compiled_probe() else {
        return;
    };
    let Some(runner) = windows_runner() else {
        return;
    };

    let dirs = session_dirs();
    let stage = dirs.ro.parent().unwrap().join("stage");
    let deny = dirs.ro.parent().unwrap().join("wsb-deny");
    // The workload tmpdir must be a *sibling* of the deny zone, never an
    // ancestor: the warden's DACL grant on it inherits down the tree, so
    // a deny dir inside %TEMP% would be writable — silently voiding the
    // deny leg.
    let child_tmp = dirs.ro.parent().unwrap().join("child-tmp");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::create_dir_all(&child_tmp).unwrap();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let token = new_token();
    let port = pick_port();
    let workspace = dirs.rw.display().to_string().replace('\\', "/") + "/workspace";

    let policy = loopback_policy(&dirs, &stage, &deny);
    let config = relay_config(
        &launch_id,
        &token,
        port,
        &["127.0.0.1".to_string()],
        &[
            ("ro_dir", dirs.ro.as_path()),
            ("rw_dir", dirs.rw.as_path()),
            ("stage_dir", stage.as_path()),
            ("deny_dir", deny.as_path()),
            ("temp_dir", child_tmp.as_path()),
        ],
    );
    stage_ro_dir(&dirs, &runner, &agent, &probe, &policy, &config);

    let config_path = dirs.ro.join("relay-config.txt");
    let t0 = Instant::now();
    let agent_proc = Command::new(&agent)
        .args(["--config", config_path.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn loopback relay agent");
    let _agent_guard = ProcGuard(agent_proc);

    // The agent publishes relay-hello.txt once it is listening.
    let hello_path = dirs.rw.join("relay-hello.txt");
    assert!(
        wait_file(&hello_path, 30),
        "agent never published relay-hello.txt; status: {:?}",
        relay_status_lines(&dirs.rw)
    );
    let addr = format!("127.0.0.1:{port}");

    // ── handshake rejections: wrong token, wrong launch id, non-hello
    // first frame — each must close without an ack, and the status log
    // must name the refusal (a silent drop is indistinguishable from a
    // dead listener).
    let host_token = token.split_once(':').unwrap().0;
    for (label, hello_payload) in [
        (
            "bad token",
            format!("{{\"v\":1,\"launch_id\":\"{launch_id}\",\"token\":\"WRONG\"}}"),
        ),
        (
            "bad launch_id",
            format!(
                "{{\"v\":1,\"launch_id\":\"{}\",\"token\":\"{host_token}\"}}",
                uuid::Uuid::now_v7()
            ),
        ),
        (
            "wrong version",
            hello(&launch_id, host_token).replacen("\"v\":1", "\"v\":2", 1),
        ),
        ("trailing input", hello(&launch_id, host_token) + " garbage"),
        (
            "duplicate token",
            hello(&launch_id, host_token).replace("{", "{\"token\":\"WRONG\","),
        ),
    ] {
        let mut c = TcpStream::connect(&addr).expect("connect for rejection leg");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        read_frame(&mut c).expect("agent proof");
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_frame(&mut c, F_HELLO, hello_payload.as_bytes()).expect("send bad hello");
        let mut one = [0u8; 1];
        let closed = match c.read(&mut one) {
            Ok(n) => n == 0,
            Err(e) => matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ),
        };
        assert!(closed, "{label}: connection must be closed without an ack");
    }
    // A first frame that is not a hello must be rejected the same way.
    {
        let mut c = TcpStream::connect(&addr).expect("connect for non-hello leg");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        read_frame(&mut c).expect("agent proof");
        c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        write_frame(&mut c, F_STDIN, b"garbage").expect("send non-hello frame");
        let mut one = [0u8; 1];
        let closed = match c.read(&mut one) {
            Ok(n) => n == 0,
            Err(e) => matches!(
                e.kind(),
                std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
            ),
        };
        assert!(closed, "non-hello first frame: connection must be closed");
    }
    assert!(wait_until(5, || relay_status_lines(&dirs.rw)
        .iter()
        .filter(|l| l.contains("rejected"))
        .count()
        == 6));
    let status = relay_status_lines(&dirs.rw).join("\n");
    assert!(
        status.contains("rejected"),
        "agent must log each handshake refusal: {status}"
    );

    // ── the real session ────────────────────────────────────────────
    let mut relay = Relay::connect(&addr, &launch_id, &token, 30).unwrap_or_else(|e| {
        panic!(
            "handshake failed: {e}; status: {:?}",
            relay_status_lines(&dirs.rw)
        )
    });
    let first_contact_s = t0.elapsed().as_secs_f64();
    let deny_guest = deny.display().to_string().replace('\\', "/");
    let got = run_probe_legs(
        &mut relay,
        "wsb-loopback-e2e",
        &workspace,
        &deny_guest,
        None,
    );
    assert!(
        relay.agent_errors.is_empty(),
        "agent must not report errors during a healthy session: {:?}",
        relay.agent_errors
    );
    assert_common_legs(&got, &workspace, false);
    assert_stdout_is_pure_jsonrpc(&relay, &got);
    assert_diagnostics_on_stderr_only(&relay);
    measure_rpc(
        &mut relay,
        &workspace,
        &dirs.rw,
        first_contact_s,
        "loopback",
    );

    // The workspace write must be visible on the host side of what the
    // sandbox tier would call the RW share — same semantics, plain dir.
    assert!(
        dirs.rw.join("workspace").join("wsb-ok.txt").is_file(),
        "workspace write must be visible to the host side"
    );

    // stdin EOF must wind the runner down and produce the exit frame.
    relay.stdin_eof();
    let code = relay
        .wait_exit(60)
        .expect("no exit frame after stdin EOF — child/agent wedged")
        .expect("exit frame carried a null code");
    assert_eq!(code, 0, "runner must exit 0 on stdin EOF");

    assert_report(&dirs, &launch_id);
    assert_audit(&dirs);
    assert!(
        dirs.rw.join("stderr.log").is_file(),
        "bounded stderr.log must exist on the rw dir"
    );
    eprintln!("loopback relay evidence: handshake rejects logged, exit code {code}");
}

/// Guest abnormal-exit propagation on loopback: the probe's `exit_child`
/// tool dies mid-session — the runner's wait layer must turn that into
/// a clean exit frame, and the relay must close rather than hang. This
/// is the loopback stand-in for the sandbox kill test's teardown leg:
/// the VM-side equivalent is the whole sandbox disappearing under the
/// socket, which only the real tier can show.
#[test]
fn wsb_relay_loopback_child_exit() {
    if let Some(reason) = check_host_prereqs() {
        common::skip_wsb_test(&reason);
        return;
    }
    let Some(agent) = compiled_agent() else {
        return;
    };
    let Some(probe) = compiled_probe() else {
        return;
    };
    let Some(runner) = windows_runner() else {
        return;
    };

    let dirs = session_dirs();
    let stage = dirs.ro.parent().unwrap().join("stage");
    let deny = dirs.ro.parent().unwrap().join("wsb-deny");
    let child_tmp = dirs.ro.parent().unwrap().join("child-tmp");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::create_dir_all(&child_tmp).unwrap();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let token = new_token();
    let port = pick_port();
    let workspace = dirs.rw.display().to_string().replace('\\', "/") + "/workspace";

    let policy = loopback_policy(&dirs, &stage, &deny);
    let config = relay_config(
        &launch_id,
        &token,
        port,
        &["127.0.0.1".to_string()],
        &[
            ("ro_dir", dirs.ro.as_path()),
            ("rw_dir", dirs.rw.as_path()),
            ("stage_dir", stage.as_path()),
            ("deny_dir", deny.as_path()),
            ("temp_dir", child_tmp.as_path()),
        ],
    );
    stage_ro_dir(&dirs, &runner, &agent, &probe, &policy, &config);

    let agent_proc = Command::new(&agent)
        .args([
            "--config",
            dirs.ro.join("relay-config.txt").to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn loopback relay agent");
    let _agent_guard = ProcGuard(agent_proc);

    let hello_path = dirs.rw.join("relay-hello.txt");
    assert!(
        wait_file(&hello_path, 30),
        "agent never published relay-hello.txt; status: {:?}",
        relay_status_lines(&dirs.rw)
    );
    let mut relay =
        Relay::connect(&format!("127.0.0.1:{port}"), &launch_id, &token, 30).expect("handshake");
    relay.send_line(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\
         \"clientInfo\":{\"name\":\"wsb-crash-e2e\",\"version\":\"0\"}}",
    ));
    relay
        .wait_id(0, LEG_TIMEOUT_SECS)
        .expect("initialize response never arrived");
    relay.send_line("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}");

    // The probe exits code 3 inside the tool call — no response can
    // arrive for id=1, so what must arrive is the exit frame.
    relay.send_line(&tool_call(
        1,
        "exit_child",
        &format!("{{\"code\":3,\"path\":\"{workspace}\"}}"),
    ));
    let exit = relay
        .wait_exit(60)
        .expect("no exit frame after guest abnormal exit — relay wedged");
    // The runner's wait layer exits with the child's observed code
    // (natural exit path → `std::process::exit(code)`), so the relay's
    // exit frame must carry the probe's code 3 — not merely *a* code.
    assert_eq!(
        exit,
        Some(3),
        "exit frame must propagate the child's exit code 3, got {exit:?}"
    );

    // The session is over — further reads must observe the relay
    // closing, not a live socket pretending the guest is still there.
    let closed = wait_until(30, || !relay.pump_one());
    assert!(closed, "relay must close after the child exit frame");
}

// ─── tier 2: real Windows Sandbox session ──────────────────────────────

/// The full PR-23 acceptance session inside a real disposable VM:
/// `.wsb` launch → agent hello on the mapped share → TCP handshake →
/// the Hyper-V-tier leg set → EOF teardown → report/audit on the share.
/// Evidence combines the management ID, authenticated relay, guest identity,
/// and observed Warden controls; vmwp counts alone are insufficient.
#[test]
fn wsb_relay_stdio_session() {
    if let Some(reason) = check_sandbox_prereqs() {
        common::skip_wsb_test(&reason);
        return;
    }
    let Some(host_ip) = host_default_switch_ip() else {
        common::skip_wsb_test(
            "no IPv4 address on 'vEthernet (Default Switch)' — the relay's \
             connect-back channel needs it (Hyper-V default switch missing?)",
        );
        return;
    };
    let _vm_guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(agent) = compiled_agent() else {
        return;
    };
    let Some(probe) = compiled_probe() else {
        return;
    };
    let Some(runner) = windows_runner() else {
        return;
    };

    let baseline_vmwp = vmwp_count();
    let dirs = session_dirs();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let token = new_token();
    let port = pick_port();
    stage_ro_dir(
        &dirs,
        &runner,
        &agent,
        &probe,
        &sandbox_policy(),
        &sandbox_config(&launch_id, &token, port, &host_ip),
    );
    let wsb = write_wsb_file(&dirs);

    host_memory_snapshot(&dirs.rw, "before");
    let t0 = Instant::now();
    let mut sandbox = SandboxGuard::launch(&wsb);

    // Boot → LogonCommand → agent listen → relay-hello.txt on the share.
    let hello_path = dirs.rw.join("relay-hello.txt");
    assert!(
        wait_file(&hello_path, SANDBOX_BOOT_SECS),
        "sandbox booted but the agent never published relay-hello.txt in \
         {}s — see {} / agent-*.log on the RW share",
        SANDBOX_BOOT_SECS,
        dirs.rw.display()
    );
    let addr = read_relay_hello(&hello_path).expect("relay-hello.txt has no ip/port");
    eprintln!("sandbox agent listening at {addr} (host default-switch ip {host_ip})");

    eprintln!(
        "host vmwp count: before={baseline_vmwp}, during={} (supplemental, not instance identity)",
        vmwp_count()
    );

    let mut relay = Relay::connect(&addr, &launch_id, &token, 30).unwrap_or_else(|e| {
        panic!(
            "relay handshake failed: {e}; status: {:?}",
            relay_status_lines(&dirs.rw)
        )
    });
    let first_contact_s = t0.elapsed().as_secs_f64();

    let got = run_probe_legs(
        &mut relay,
        "wsb-sandbox-e2e",
        "C:/relay-rw/workspace",
        "C:/wsb-deny",
        Some("C:/relay-ro/probe.txt"),
    );
    assert!(
        relay.agent_errors.is_empty(),
        "agent must not report errors during a healthy session: {:?}",
        relay.agent_errors
    );
    assert_common_legs(&got, "C:/relay-rw/workspace", true);
    assert_stdout_is_pure_jsonrpc(&relay, &got);
    assert_diagnostics_on_stderr_only(&relay);
    measure_rpc(
        &mut relay,
        "C:/relay-rw/workspace",
        &dirs.rw,
        first_contact_s,
        "vm",
    );

    // Sandbox-specific identity: the disposable VM's well-known account.
    let ident = got.get(&2).cloned().unwrap_or_default();
    assert!(
        ident.to_lowercase().contains("wdagutilityaccount"),
        "guest identity must be the sandbox's WDAGUtilityAccount: {ident}"
    );
    host_memory_snapshot(&dirs.rw, "during");
    // The RO-share write denial must be attributable to the sandbox's
    // own mapping — the file must NOT appear on the host's ro dir even
    // if a guest write had somehow slipped past the RO flag.
    assert!(
        !dirs.ro.join("probe.txt").is_file(),
        "a write the guest believes denied must not exist on the host ro share"
    );

    // The workspace write reaches the host through the RW mapping.
    assert!(
        dirs.rw.join("workspace").join("wsb-ok.txt").is_file(),
        "workspace write must be visible on the host through the RW mapped folder"
    );

    // stdin EOF → runner exits → agent emits the exit frame; the sandbox
    // itself keeps running until the host closes it (LogonCommand's
    // lifetime is the agent's, not the VM's).
    relay.stdin_eof();
    let code = relay
        .wait_exit(60)
        .expect("no exit frame after stdin EOF — relay/child wedged")
        .expect("exit frame carried a null code");
    assert_eq!(code, 0, "runner must exit 0 on stdin EOF");
    let session_s = t0.elapsed().as_secs_f64();

    assert_report(&dirs, &launch_id);
    assert_audit(&dirs);

    // Stop the exact owned ID; no process enumeration is used to stop VMs.
    let stop_s = stop_sandbox(&mut sandbox, &dirs);
    finish_vm_metrics(&dirs, &ident, stop_s);
    host_memory_snapshot(&dirs.rw, "after");
    assert!(
        wait_until(TEARDOWN_SECS, || !relay.pump_one()),
        "owned Sandbox socket did not close"
    );
    eprintln!("host vmwp count after owned stop: {}", vmwp_count());
    eprintln!(
        "wsb session evidence: first_contact={first_contact_s:.2}s \
         session={session_s:.2}s exit_code={code}"
    );
}

/// Mid-session host-side kill: the relay socket must die with the VM,
/// the guest-side child must be torn down *by the VM teardown* (the
/// host cannot reach in to reap it). The management command owns teardown.
#[test]
fn wsb_relay_sandbox_kill_cleans_up() {
    if let Some(reason) = check_sandbox_prereqs() {
        common::skip_wsb_test(&reason);
        return;
    }
    let Some(host_ip) = host_default_switch_ip() else {
        common::skip_wsb_test("no IPv4 address on 'vEthernet (Default Switch)'");
        return;
    };
    let _vm_guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(agent) = compiled_agent() else {
        return;
    };
    let Some(probe) = compiled_probe() else {
        return;
    };
    let Some(runner) = windows_runner() else {
        return;
    };

    let baseline_vmwp = vmwp_count();
    let dirs = session_dirs();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let token = new_token();
    let port = pick_port();
    stage_ro_dir(
        &dirs,
        &runner,
        &agent,
        &probe,
        &sandbox_policy(),
        &sandbox_config(&launch_id, &token, port, &host_ip),
    );
    let wsb = write_wsb_file(&dirs);

    let mut sandbox = SandboxGuard::launch(&wsb);
    let hello_path = dirs.rw.join("relay-hello.txt");
    assert!(
        wait_file(&hello_path, SANDBOX_BOOT_SECS),
        "agent never published relay-hello.txt"
    );
    let addr = read_relay_hello(&hello_path).expect("relay-hello.txt has no ip/port");
    eprintln!(
        "host vmwp count: before={baseline_vmwp}, during={} (supplemental)",
        vmwp_count()
    );
    let mut relay = Relay::connect(&addr, &launch_id, &token, 30).expect("relay handshake failed");

    // Prove the session is alive with a real round-trip, then kill the
    // sandbox while it is mid-flight.
    relay.send_line(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\
         \"clientInfo\":{\"name\":\"wsb-kill-e2e\",\"version\":\"0\"}}",
    ));
    relay
        .wait_id(0, LEG_TIMEOUT_SECS)
        .expect("initialize response never arrived");

    stop_sandbox(&mut sandbox, &dirs);

    // The relay must observe the VM's death — a socket that keeps
    // "working" against a dead guest would be a hanging relay. Each poll
    // sends a frame first: a dead NAT endpoint ACKs nothing, so the
    // write side provokes the reset the read side then sees.
    let socket_died = wait_until(TEARDOWN_SECS, || {
        relay.try_send(F_STDIN, b"").is_err() || !relay.pump_one()
    });
    assert!(
        socket_died,
        "relay socket must fail once the sandbox VM is killed"
    );
    eprintln!("host vmwp count after owned stop: {}", vmwp_count());
    eprintln!("wsb kill evidence: relay socket died after owned-ID stop");
}

/// Owns a spawned process until the test ends — kills it on drop so a
/// failed assertion cannot leak a listener or a child.
struct ProcGuard(std::process::Child);

impl Drop for ProcGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn new_token() -> String {
    format!(
        "{}{}:{}{}",
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7(),
        uuid::Uuid::now_v7()
    )
}

fn test_root() -> PathBuf {
    let root = std::env::var_os("MCP_WRIT_WSB_TEST_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/wsb-tests"));
    assert!(root.is_absolute(), "WSB test root must be absolute");
    std::fs::create_dir_all(&root).expect("create D-drive test root");
    root
}
