//! Real-machine validation of the Windows Sandbox stdio relay (PR-23).
//!
//! Windows Sandbox is not a container engine: it gives the host exactly
//! two channels — mapped folders (file visibility declared in the `.wsb`)
//! and NAT networking — and its stock tooling provides no process stdio.
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
//! Three test tiers, all gated on `MCP_WRIT_REQUIRE_WSB_TESTS=1` (see
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
//!     down with the VM, and no `vmwp.exe` leaks.
//!
//! Prerequisites for the sandbox tier (any missing → skip, or fail with
//! `MCP_WRIT_REQUIRE_WSB_TESTS=1`):
//!   - Windows 11 (Pro/Enterprise/Education — Home lacks the feature)
//!     on x86_64, build 19041+ (this host's baseline is higher)
//!   - `Containers-DisposableClientVM` enabled → `WindowsSandbox.exe`
//!     under `%SystemRoot%\System32`
//!   - an interactive logon session — `WindowsSandbox.exe` is the GUI
//!     client; there is no headless launch API
//!   - the Hyper-V Default Switch present (Networking=Enable needs it)
//!   - `rustc` for the two fixtures and a Windows PE `mcp-secure-runner`

mod common;

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

// Frame kinds — the agent's wire contract (see wsb_relay_agent.rs).
const F_HELLO: u8 = 0x01;
const F_HELLO_ACK: u8 = 0x02;
const F_STDIN: u8 = 0x03;
const F_STDIN_EOF: u8 = 0x04;
const F_STDOUT: u8 = 0x05;
const F_STDERR: u8 = 0x06;
const F_EXIT: u8 = 0x07;
const F_AGENT_ERROR: u8 = 0x08;
const MAX_FRAME: usize = 1024 * 1024;

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
    None
}

/// Compile a std-only fixture once per test binary with plain `rustc` —
/// same contract as `common::compiled_open_path_fixture` /
/// `hyperv_vm_e2e::compiled_hyperv_probe`.
fn compiled_fixture(src_name: &str, out_name: &str) -> Option<PathBuf> {
    let src = fixtures_dir().join(src_name);
    let dir = match tempfile::Builder::new()
        .prefix("mcp_writ_wsb_build_")
        .tempdir()
    {
        Ok(d) => d,
        Err(e) => {
            common::skip_wsb_test(&format!("fixture tempdir failed: {e}"));
            return None;
        }
    };
    let out = dir.path().join(out_name);
    let status = Command::new("rustc")
        .args(["--edition", "2024", "-O", "-o"])
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

fn session_dirs() -> WsbDirs {
    let root = tempfile::Builder::new()
        .prefix("mcp_writ_wsb_run_")
        .tempdir()
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
    let mut s = format!(
        "listen_port={listen_port}\nlaunch_id={launch_id}\ntoken={token}\n\
         allowed_peers={}\n",
        allowed_peers.join(",")
    );
    for (k, v) in paths {
        s.push_str(&format!("{k}={}\n", v.display()));
    }
    s
}

fn sandbox_config(launch_id: &str, token: &str, port: u16, host_ip: &str) -> String {
    relay_config(launch_id, token, port, &[host_ip.to_string()], &[])
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
        filesystem {{ allow "C:/**" }}
    }}
    tool "vm_identity" side_effect="read_only" {{
        filesystem {{ allow "C:/**" }}
    }}
    tool "env_probe" side_effect="read_only" {{
        filesystem {{ allow "C:/**" }}
    }}
    tool "create_file" side_effect="write" {{
        filesystem {{ allow "C:/**" mode="write" }}
    }}
    tool "net_probe" side_effect="read_only" {{
        filesystem {{ allow "C:/**" }}
    }}
    tool "spawn_child" side_effect="write" {{
        filesystem {{ allow "C:/**" mode="write" }}
    }}
    tool "exit_child" side_effect="write" {{
        filesystem {{ allow "C:/**" mode="write" }}
    }}
    tool "exec_shell" deny=#true
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

fn write_frame(w: &mut impl Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    assert!(payload.len() <= MAX_FRAME);
    w.write_all(&[kind])?;
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

fn read_frame(r: &mut impl Read) -> std::io::Result<(u8, Vec<u8>)> {
    let mut kind = [0u8; 1];
    r.read_exact(&mut kind)?;
    let mut lenb = [0u8; 4];
    r.read_exact(&mut lenb)?;
    let len = u32::from_be_bytes(lenb) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame payload {len} exceeds 1 MiB cap"),
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok((kind[0], buf))
}

/// The host-side end of the relay: stdout frames are accumulated into a
/// line buffer so JSON-RPC responses split across frames still resolve;
/// stderr frames are collected separately — the assertion surface for
/// "diagnostics never reach the stdout stream".
struct Relay {
    conn: TcpStream,
    stdout_buf: Vec<u8>,
    lines: Vec<String>,
    stderr_bytes: Vec<u8>,
    exit_code: Option<Option<i32>>,
    agent_errors: Vec<String>,
}

/// A read that timed out is "no data yet", not a dead socket — the
/// distinction drives every wait loop below.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
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
        conn.set_read_timeout(Some(Duration::from_secs(handshake_secs)))?;
        conn.set_nodelay(true).ok();
        let hello = format!(
            "{{\"v\":1,\"launch_id\":\"{launch_id}\",\"token\":\"{token}\"}}"
        );
        write_frame(&mut conn, F_HELLO, hello.as_bytes())?;
        let (kind, payload) = read_frame(&mut conn)?;
        if kind != F_HELLO_ACK {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("expected hello-ack, got kind={kind:#04x}"),
            ));
        }
        let text = String::from_utf8_lossy(&payload);
        assert!(
            text.contains(launch_id),
            "hello-ack must echo this launch's id: {text}"
        );
        // Session reads use a short timeout so the wait loops' own
        // deadlines govern; a long read timeout would smear them.
        conn.set_read_timeout(Some(Duration::from_secs(5)))?;
        Ok(Relay {
            conn,
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
        match read_frame(&mut self.conn) {
            Ok((F_STDOUT, data)) => {
                self.stdout_buf.extend_from_slice(&data);
                while let Some(pos) = self.stdout_buf.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = self.stdout_buf.drain(..=pos).collect();
                    self.lines.push(String::from_utf8_lossy(&line).into_owned());
                }
                true
            }
            Ok((F_STDERR, data)) => {
                self.stderr_bytes.extend_from_slice(&data);
                true
            }
            Ok((F_EXIT, payload)) => {
                let text = String::from_utf8_lossy(&payload).to_string();
                let code = text
                    .find("\"code\":")
                    .and_then(|p| text[p + 7..].trim_end_matches('}').parse::<i64>().ok())
                    .map(|c| c as i32);
                self.exit_code = Some(code);
                true
            }
            Ok((F_AGENT_ERROR, payload)) => {
                self.agent_errors
                    .push(String::from_utf8_lossy(&payload).into_owned());
                true
            }
            Ok((kind, _)) => {
                // Unknown frames are surfaced, not silently dropped —
                // a protocol peer that invents kinds is itself a finding.
                self.agent_errors
                    .push(format!("unexpected frame kind={kind:#04x}"));
                true
            }
            // A read timeout means "alive, no data" — any real socket
            // failure means the relay is gone.
            Err(e) => is_timeout(&e),
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

/// `vmwp.exe` count — the utility-VM worker. Windows Sandbox runs its VM
/// under the same worker shape as a Hyper-V unit; counting lets the test
/// prove a sandbox booted and later prove it is gone, without trusting
/// the GUI client's process state.
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

/// Pids of every Windows Sandbox client/server process on the machine.
/// Teardown must only ever touch the pids OUR launch added — a blanket
/// `taskkill /IM WindowsSandbox*.exe` would also destroy a sandbox the
/// user opened themselves, which the PR-23 contract explicitly forbids.
fn sandbox_pids() -> Vec<u32> {
    let out = Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq WindowsSandbox*", "/FO", "CSV", "/NH"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    let Ok(out) = out else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let mut cols = l.split(',');
            let name = cols.next()?.trim_matches('"');
            if !name.starts_with("WindowsSandbox") {
                return None;
            }
            cols.next()?.trim_matches('"').parse::<u32>().ok()
        })
        .collect()
}

/// Owns the sandbox our launch created. Kills exactly the processes the
/// launch added — the spawned `WindowsSandbox.exe` plus any
/// Client/Server pids that appeared after it — never a sandbox that was
/// already running.
struct SandboxGuard {
    child: Option<std::process::Child>,
    pre_pids: Vec<u32>,
}

impl SandboxGuard {
    fn launch(wsb: &Path) -> SandboxGuard {
        let exe = windows_sandbox_exe().expect("WindowsSandbox.exe");
        let pre_pids = sandbox_pids();
        let child = Command::new(exe)
            .arg(wsb)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to launch WindowsSandbox.exe");
        SandboxGuard {
            child: Some(child),
            pre_pids,
        }
    }

    /// Kill the sandbox this guard owns. The spawned client may have
    /// already exited after handing off to a paired Server process, so
    /// teardown targets the pid set difference — ours, and only ours.
    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        for pid in sandbox_pids() {
            if !self.pre_pids.contains(&pid) {
                let _ = Command::new("taskkill")
                    .args(["/F", "/PID", &pid.to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
}

impl Drop for SandboxGuard {
    fn drop(&mut self) {
        self.kill();
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
    // The read-only surface leg: the substrate's RO mapping must deny
    // the write even where the warden's DACL would allow it — separate
    // evidence from the DACL legs, so it only runs where an RO mapping
    // actually exists.
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
fn assert_stdout_is_pure_jsonrpc(relay: &Relay, responses: &std::collections::HashMap<i64, String>) {
    for (id, line) in responses {
        assert!(
            line.contains("\"jsonrpc\""),
            "response id={id} is not a JSON-RPC frame: {line}"
        );
    }
    for line in &relay.lines {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        assert!(
            t.contains("\"jsonrpc\""),
            "unclaimed stdout line is not JSON-RPC: {t}"
        );
    }
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
    for needle in [
        "\"os.process\",\"layer\":\"os\",\"mechanism\":\"appcontainer + job\"",
        "\"os.fs\",\"layer\":\"os\",\"mechanism\":\"appcontainer + dacl\"",
        "\"os.net.outbound\",\"layer\":\"os\",\"mechanism\":\"appcontainer capabilities\"",
    ] {
        assert!(report.contains(needle), "guest report must contain {needle:?}");
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
    let Some(agent) = compiled_agent() else { return };
    let Some(probe) = compiled_probe() else { return };
    let Some(runner) = windows_runner() else { return };

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
    let token = uuid::Uuid::now_v7().to_string();
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
    for (label, hello_payload) in [
        (
            "bad token",
            format!("{{\"v\":1,\"launch_id\":\"{launch_id}\",\"token\":\"WRONG\"}}"),
        ),
        (
            "bad launch_id",
            format!(
                "{{\"v\":1,\"launch_id\":\"{}\",\"token\":\"{token}\"}}",
                uuid::Uuid::now_v7()
            ),
        ),
    ] {
        let mut c = TcpStream::connect(&addr).expect("connect for rejection leg");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        write_frame(&mut c, F_HELLO, hello_payload.as_bytes()).expect("send bad hello");
        let mut one = [0u8; 1];
        let closed = c.read(&mut one).map(|n| n == 0).unwrap_or(true);
        assert!(closed, "{label}: connection must be closed without an ack");
    }
    // A first frame that is not a hello must be rejected the same way.
    {
        let mut c = TcpStream::connect(&addr).expect("connect for non-hello leg");
        c.set_read_timeout(Some(Duration::from_secs(10))).ok();
        write_frame(&mut c, F_STDIN, b"garbage").expect("send non-hello frame");
        let mut one = [0u8; 1];
        let closed = c.read(&mut one).map(|n| n == 0).unwrap_or(true);
        assert!(closed, "non-hello first frame: connection must be closed");
    }
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
    let deny_guest = deny.display().to_string().replace('\\', "/");
    let got = run_probe_legs(&mut relay, "wsb-loopback-e2e", &workspace, &deny_guest, None);
    assert!(
        relay.agent_errors.is_empty(),
        "agent must not report errors during a healthy session: {:?}",
        relay.agent_errors
    );
    assert_common_legs(&got, &workspace, false);
    assert_stdout_is_pure_jsonrpc(&relay, &got);
    assert_diagnostics_on_stderr_only(&relay);

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
    let Some(agent) = compiled_agent() else { return };
    let Some(probe) = compiled_probe() else { return };
    let Some(runner) = windows_runner() else { return };

    let dirs = session_dirs();
    let stage = dirs.ro.parent().unwrap().join("stage");
    let deny = dirs.ro.parent().unwrap().join("wsb-deny");
    let child_tmp = dirs.ro.parent().unwrap().join("child-tmp");
    std::fs::create_dir_all(&stage).unwrap();
    std::fs::create_dir_all(&child_tmp).unwrap();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let token = uuid::Uuid::now_v7().to_string();
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
        .args(["--config", dirs.ro.join("relay-config.txt").to_str().unwrap()])
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
/// Engine evidence is `vmwp.exe` presence during the session and the
/// sandbox's generated identity inside `vm_identity`.
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
    let Some(agent) = compiled_agent() else { return };
    let Some(probe) = compiled_probe() else { return };
    let Some(runner) = windows_runner() else { return };

    let baseline_vmwp = vmwp_count();
    let dirs = session_dirs();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let token = uuid::Uuid::now_v7().to_string();
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

    let _sandbox = SandboxGuard::launch(&wsb);
    let t0 = Instant::now();

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

    assert!(
        wait_until(60, || vmwp_count() > baseline_vmwp),
        "a vmwp.exe worker must exist while the sandbox runs — engine-level \
         evidence that the guest is a VM, not host processes"
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

    // Sandbox-specific identity: the disposable VM's well-known account.
    let ident = got.get(&2).cloned().unwrap_or_default();
    assert!(
        ident.to_lowercase().contains("wdagutilityaccount"),
        "guest identity must be the sandbox's WDAGUtilityAccount: {ident}"
    );
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

    // Teardown: killing the sandbox must remove the vmwp it added.
    drop(_sandbox);
    assert!(
        wait_until(TEARDOWN_SECS, || vmwp_count() <= baseline_vmwp),
        "the sandbox's vmwp.exe must be gone after the client is killed"
    );
    eprintln!(
        "wsb session evidence: first_contact={first_contact_s:.2}s \
         session={session_s:.2}s exit_code={code}"
    );
}

/// Mid-session host-side kill: the relay socket must die with the VM,
/// the guest-side child must be torn down *by the VM teardown* (the
/// host cannot reach in to reap it), and no `vmwp.exe` may leak.
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
    let Some(agent) = compiled_agent() else { return };
    let Some(probe) = compiled_probe() else { return };
    let Some(runner) = windows_runner() else { return };

    let baseline_vmwp = vmwp_count();
    let dirs = session_dirs();
    let launch_id = uuid::Uuid::now_v7().to_string();
    let token = uuid::Uuid::now_v7().to_string();
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
    assert!(
        wait_until(60, || vmwp_count() > baseline_vmwp),
        "a vmwp.exe worker must exist while the sandbox runs"
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

    sandbox.kill();

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
    assert!(
        wait_until(TEARDOWN_SECS, || vmwp_count() <= baseline_vmwp),
        "the sandbox's vmwp.exe must be gone after the kill"
    );
    eprintln!("wsb kill evidence: relay socket died with the VM, vmwp back to baseline");
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
