//! Guest-side Windows Sandbox relay, promoted from the PR-23 validation.
//! Shipped as `mcp-writ-wsb-relay`; fixture wrappers compile the same source.
//!
//! This agent uses mapped folders (configured in the `.wsb`) and NAT
//! networking. The wsb exec API provides no process stdio, so this agent
//! — launched inside the
//! disposable VM as the `.wsb` `LogonCommand` — is the guest half of a
//! dedicated stdio relay:
//!
//!   1. read `relay-config.txt` on the read-only share (`C:\relay-ro`)
//!   2. stage the runner/probe/policy onto the guest's own NTFS
//!      (`C:\mcp-secure` — mirroring the product `GuestLayout`), create
//!      the RW-share channel dirs, and create `C:\wsb-deny` as a
//!      real-NTFS deny zone
//!   3. listen on `0.0.0.0:<listen_port>` (plus a best-effort guest-side
//!      firewall rule — the agent is admin inside the disposable VM)
//!   4. publish `relay-hello.txt` on the RW share (`C:\relay-rw`) carrying
//!      its egress IP + port so the host can connect back
//!   5. accept connections until one completes the handshake: peer IP in
//!      `allowed_peers` (the host's Default Switch addresses), then a
//!      `hello` frame carrying this launch's `launch_id` + `token`
//!   6. spawn `mcp-secure-runner.exe` with the product channel env
//!      (`MCP_ORIG_ENTRYPOINT`, `MCP_WRIT_*`) and pump stdio over frames
//!
//! Frame layout (v1): `u8 kind | u32 BE len | payload[len]`, `len <= 1 MiB`
//! (the auditor's DEFAULT_MAX_FRAME_BYTES — the relay must not become the
//! unbounded buffer the wire cap forbids).
//!
//!   host -> agent : 0x01 hello {v,launch_id,token} · 0x03 stdin-data
//!                   0x04 stdin-eof · 0x0a cancel
//!   agent -> host : 0x02 hello-ack {v,launch_id,agent} · 0x05 stdout-data
//!                   0x06 stderr-data (first 64 KiB only, rest -> stderr.log)
//!                   0x07 exit {code} · 0x08 agent-error {error}
//!                   0x09 initial peer proof {v,launch_id,token}
//!
//! Backpressure is bounded: stdout/stderr pumps block on each frame write;
//! stdin has two queued frames and a 15 s full-queue deadline. No unbounded
//! queue exists in the relay. The host never receives a command channel:
//! the spawned argv comes from the RO-share config the host itself wrote,
//! so a guest-side caller cannot ask the host to execute anything.
//!
//! Compiled by the test with plain `rustc` (std-only, same contract as
//! `hyperv_probe_server.rs`). For protocol-level host testing the same
//! binary runs outside the sandbox via `--config` pointing at a host
//! directory (`wsb_relay_loopback_protocol` in the e2e).

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::owned_job;
use super::relay_protocol;
use relay_protocol::*;

// ─── protocol constants ──────────────────────────────────────────────────

/// Output pump chunk; stdin uses at most four 1 MiB buffers including queue,
/// pending reader frame and the active pipe write.
const CHUNK: usize = 64 * 1024;
/// stderr bytes forwarded to the host; the remainder lands in
/// `stderr.log` on the RW share (bounded there too).
const STDERR_FORWARD_CAP: u64 = 64 * 1024;
const STDERR_LOG_CAP: u64 = 256 * 1024;
/// Total window the agent waits for the host to connect after publishing
/// `relay-hello.txt` — a missing host must not pin the VM forever.
const ACCEPT_DEADLINE: Duration = Duration::from_secs(180);
/// How long `wait_child` polls before declaring the child wedged after a
/// socket failure (the kill path's own bound).
const POST_KILL_WAIT: Duration = Duration::from_secs(20);

// ─── config ─────────────────────────────────────────────────────────────

struct Cfg {
    ro_dir: PathBuf,
    rw_dir: PathBuf,
    stage_dir: PathBuf,
    deny_dir: PathBuf,
    temp_dir: PathBuf,
    listen_port: u16,
    launch_id: String,
    token: String,
    peer_token: String,
    allowed_peers: Vec<String>,
    server_name: String,
    guest: bool,
    product: bool,
    fail_on: String,
}

fn read_config(path: &Path) -> Result<Cfg, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut kv = std::collections::HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!("config line without '=': {line}"));
        };
        if kv
            .insert(k.trim().to_string(), v.trim().to_string())
            .is_some()
        {
            return Err(format!("duplicate config key {}", k.trim()));
        }
    }
    let get = |k: &str| kv.get(k).cloned();
    let req = |k: &str| -> Result<String, String> {
        get(k)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("missing config key {k}"))
    };
    let ro_dir = PathBuf::from(get("ro_dir").unwrap_or_else(|| r"C:\relay-ro".into()));
    let rw_dir = PathBuf::from(get("rw_dir").unwrap_or_else(|| r"C:\relay-rw".into()));
    for key in ["launch_id", "token", "peer_token"] {
        let value = req(key)?;
        if value.len() < 32
            || value.len() > 128
            || !value.bytes().all(|c| c.is_ascii_hexdigit() || c == b'-')
        {
            return Err(format!("invalid {key}"));
        }
    }
    let allowed_peers: Vec<String> = req("allowed_peers")?
        .split(',')
        .map(|s| {
            s.trim()
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.to_string())
        })
        .collect::<Result<_, _>>()
        .map_err(|e| format!("allowed_peers: {e}"))?;
    Ok(Cfg {
        stage_dir: PathBuf::from(get("stage_dir").unwrap_or_else(|| r"C:\mcp-secure".into())),
        deny_dir: PathBuf::from(get("deny_dir").unwrap_or_else(|| r"C:\wsb-deny".into())),
        temp_dir: PathBuf::from(get("temp_dir").unwrap_or_else(|| r"C:\Windows\Temp".into())),
        listen_port: req("listen_port")?
            .parse::<u16>()
            .map_err(|e| format!("listen_port: {e}"))?,
        launch_id: req("launch_id")?,
        token: req("token")?,
        peer_token: req("peer_token")?,
        allowed_peers,
        server_name: get("server_name").unwrap_or_else(|| {
            if get("product").as_deref() == Some("true") {
                String::new()
            } else {
                "wsb-probe".into()
            }
        }),
        guest: get("guest").as_deref() == Some("true"),
        product: get("product").as_deref() == Some("true"),
        fail_on: get("fail_on").unwrap_or_else(|| "high".into()),
        ro_dir,
        rw_dir,
    })
}

// ─── share-side logging ─────────────────────────────────────────────────

struct Log {
    agent: fs::File,
    status: fs::File,
    budget: Arc<std::sync::atomic::AtomicUsize>,
}

impl Log {
    fn open(rw: &Path) -> std::io::Result<Log> {
        Ok(Log {
            agent: fs::File::create(rw.join("agent.log"))?,
            status: fs::File::create(rw.join("relay-status.txt"))?,
            budget: Arc::new(std::sync::atomic::AtomicUsize::new(1024 * 1024)),
        })
    }
    fn stamp() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    }
    /// `relay-status.txt` — the host's coarse lifecycle view.
    fn status(&mut self, msg: &str) {
        if !self.reserve(msg.len() * 2 + 64) {
            return;
        }
        let _ = writeln!(self.status, "{} {msg}", Self::stamp());
        let _ = self.status.flush();
        let _ = writeln!(self.agent, "{} {msg}", Self::stamp());
        let _ = self.agent.flush();
    }
    /// `agent.log` — detail channel (firewall result, copy list, errors).
    fn detail(&mut self, msg: &str) {
        if !self.reserve(msg.len() + 32) {
            return;
        }
        let _ = writeln!(self.agent, "{} {msg}", Self::stamp());
        let _ = self.agent.flush();
    }
    /// Second handle set on the same files for pump threads — writes
    /// interleave at line granularity, which the timestamped format
    /// tolerates.
    fn reserve(&self, bytes: usize) -> bool {
        self.budget
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                n.checked_sub(bytes)
            })
            .is_ok()
    }
    fn clone_empty(&self) -> Log {
        Log {
            agent: self.agent.try_clone().expect("clone agent.log"),
            status: self.status.try_clone().expect("clone status log"),
            budget: Arc::clone(&self.budget),
        }
    }
}

// ─── guest-side setup ────────────────────────────────────────────────────

/// Stage the guest payload onto real NTFS so the warden's DACL grants
/// behave like the product contract (mapped folders may not honor NTFS
/// ACLs — the same shape as the bind-mount finding in the Hyper-V run).
fn stage_files(cfg: &Cfg, log: &mut Log) -> Result<(), String> {
    let stage = &cfg.stage_dir;
    fs::create_dir_all(stage.join("etc"))
        .map_err(|e| format!("mkdir {}/etc: {e}", stage.display()))?;
    let copies = [
        (
            cfg.ro_dir.join("mcp-secure-runner.exe"),
            stage.join("mcp-secure-runner.exe"),
        ),
        (
            cfg.ro_dir.join("policy.kdl"),
            stage.join("etc").join("policy.kdl"),
        ),
    ];
    for (src, dst) in &copies {
        fs::copy(src, dst)
            .map_err(|e| format!("copy {} -> {}: {e}", src.display(), dst.display()))?;
        log.detail(&format!("staged {} -> {}", src.display(), dst.display()));
    }
    if cfg.product {
        copy_payload(&cfg.ro_dir.join("workload"), &stage.join("workload"), 0)?;
    } else {
        fs::copy(
            cfg.ro_dir.join("wsb-probe.exe"),
            stage.join("wsb-probe.exe"),
        )
        .map_err(|e| e.to_string())?;
    }
    for file in fs::read_dir(&cfg.ro_dir).map_err(|e| e.to_string())? {
        let file = file.map_err(|e| e.to_string())?;
        if file
            .path()
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"))
        {
            fs::copy(file.path(), stage.join(file.file_name())).map_err(|e| e.to_string())?;
        }
    }
    for sub in ["logs", "report", "workspace", "tmp"] {
        fs::create_dir_all(cfg.rw_dir.join(sub))
            .map_err(|e| format!("mkdir {}/{sub}: {e}", cfg.rw_dir.display()))?;
    }
    fs::create_dir_all(&cfg.deny_dir)
        .map_err(|e| format!("mkdir {}: {e}", cfg.deny_dir.display()))?;
    Ok(())
}

fn copy_payload(source: &Path, dest: &Path, depth: usize) -> Result<(), String> {
    if depth > 32 {
        return Err("payload directory nesting exceeds 32".into());
    }
    fs::create_dir_all(dest).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            copy_payload(&entry.path(), &dest.join(entry.file_name()), depth + 1)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), dest.join(entry.file_name())).map_err(|e| e.to_string())?;
        } else {
            return Err("payload contains a link or special file".into());
        }
    }
    Ok(())
}

/// Best-effort inbound allow for the listen port inside the disposable
/// guest — never on the host. The result lands in `agent.log` either way.
fn open_guest_firewall(port: u16, log: &mut Log) {
    let out = Command::new("netsh")
        .args([
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=mcp-writ wsb relay",
            "dir=in",
            "action=allow",
            "protocol=TCP",
            &format!("localport={port}"),
        ])
        .output();
    match out {
        Ok(o) => log.detail(&format!(
            "netsh firewall rule: status={} out={} err={}",
            o.status,
            String::from_utf8_lossy(&o.stdout).trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => log.detail(&format!("netsh firewall rule failed to run: {e}")),
    }
}

/// The guest's egress IPv4 on the sandbox NAT — a UDP "connect" chooses
/// the source address without sending a packet.
fn egress_ip() -> Option<String> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    // TEST-NET-1 destination: routing lookup only, nothing is emitted.
    sock.connect("192.0.2.1:53").ok()?;
    Some(sock.local_addr().ok()?.ip().to_string())
}

// ─── handshake ───────────────────────────────────────────────────────────

/// Accept connections until one proves it is the host: peer IP inside
/// `allowed_peers`, then peer proof and a `hello` frame with this launch's
/// `launch_id` and `token`. Wrong handshakes are closed and logged — the
/// listener stays up until `ACCEPT_DEADLINE`.
fn wait_for_host(listener: &TcpListener, cfg: &Cfg, log: &mut Log) -> Result<TcpStream, String> {
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("nonblocking listener: {e}"))?;
    let deadline = Instant::now() + ACCEPT_DEADLINE;
    loop {
        if Instant::now() > deadline {
            return Err(format!(
                "no host connected within {}s",
                ACCEPT_DEADLINE.as_secs()
            ));
        }
        match listener.accept() {
            Ok((mut conn, peer)) => {
                // A Windows accept()ed socket inherits the listener's
                // nonblocking flag — unlike POSIX accept(2). Restore
                // blocking mode first or every session read fails with
                // WSAEWOULDBLOCK (10035) and the relay dies instantly.
                conn.set_nonblocking(false).map_err(|e| e.to_string())?;
                let peer_ip = peer.ip().to_string();
                if !cfg.allowed_peers.contains(&peer_ip) {
                    log.status(&format!(
                        "rejected connection from {peer} (not in allowed_peers)"
                    ));
                    drop(conn);
                    continue;
                }
                conn.set_nodelay(true).map_err(|e| e.to_string())?;
                // Authenticate the agent before the host releases its distinct
                // credential. A forged hello file must not steal that credential.
                let hello_deadline = deadline.min(Instant::now() + IO_TIMEOUT);
                if write_frame_until(
                    &mut conn,
                    F_PEER,
                    hello(&cfg.launch_id, &cfg.peer_token).as_bytes(),
                    hello_deadline,
                )
                .is_err()
                {
                    continue;
                }
                match read_frame_until(&mut conn, hello_deadline) {
                    Ok((F_HELLO, payload))
                        if payload == hello(&cfg.launch_id, &cfg.token).as_bytes() =>
                    {
                        write_frame_until(
                            &mut conn,
                            F_HELLO_ACK,
                            ack(&cfg.launch_id).as_bytes(),
                            hello_deadline,
                        )
                        .map_err(|e| format!("ack write: {e}"))?;
                        log.status(&format!("host connected from {peer_ip}"));
                        return Ok(conn);
                    }
                    _ => log.status("rejected handshake (version, credentials, frame or deadline)"),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(format!("accept failed: {e}")),
        }
    }
}

// ─── child spawn + pumps ────────────────────────────────────────────────

fn spawn_runner(cfg: &Cfg) -> Result<Child, String> {
    let stage = &cfg.stage_dir;
    let probe = stage.join("wsb-probe.exe");
    let argv_json = if cfg.product {
        let path = cfg.ro_dir.join("command.json");
        if fs::metadata(&path).map_err(|e| e.to_string())?.len() > 64 * 1024 {
            return Err("command exceeds 64 KiB".into());
        }
        fs::read_to_string(path).map_err(|e| e.to_string())?
    } else {
        format!(
            "[\"{}\"]",
            probe.display().to_string().replace('\\', "\\\\")
        )
    };
    let mut cmd = Command::new(stage.join("mcp-secure-runner.exe"));
    if cfg.product {
        cmd.current_dir(stage.join("workload"));
    }
    cmd.env("MCP_ORIG_ENTRYPOINT", &argv_json)
        .env("MCP_ORIG_CMD", "[]")
        .env("MCP_WRIT_POLICY_PATH", stage.join("etc").join("policy.kdl"))
        .env("MCP_WRIT_AUDIT_DIR", cfg.rw_dir.join("logs"))
        .env("MCP_WRIT_REPORT_OUT", cfg.rw_dir.join("report"))
        .env("MCP_WRIT_TEMP_DIR", &cfg.temp_dir)
        .env("MCP_WRIT_LAUNCH_ID", &cfg.launch_id)
        .env("MCP_WRIT_SERVER", &cfg.server_name)
        // Channel variables the product clears before launch — an
        // inherited value must not redirect the guest's own contract.
        .env("MCP_WRIT_ENV", "")
        .env("MCP_WRIT_SKIP_SANDBOX", "")
        .env("MCP_WRIT_FAIL_ON", &cfg.fail_on)
        .env("MCP_WRIT_PROBE_LANDLOCK_ABI", "")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.spawn().map_err(|e| {
        format!(
            "spawn {}: {e}",
            stage.join("mcp-secure-runner.exe").display()
        )
    })
}

/// The single write side of the relay socket, shared by the stdout pump,
/// the stderr pump, and the final `exit`/`error` writes. A frame is
/// three `write_all` calls; the mutex keeps whole frames atomic so a
/// stderr chunk can never interleave inside a stdout frame.
#[derive(Clone)]
struct FrameWriter(Arc<std::sync::Mutex<TcpStream>>);

impl FrameWriter {
    fn send(&self, kind: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut conn = self.0.lock().unwrap_or_else(|e| e.into_inner());
        write_frame(&mut conn, kind, payload)
    }
}

/// socket -> child stdin; `stdin-eof` half-closes; a socket failure flips
/// `socket_dead` so the main loop can kill the child. A child-side stdin
/// close is not a socket failure — it flips `stdin_closed` instead: the
/// pump keeps monitoring the socket (discarding further stdin frames) so
/// `run()` can still deliver the exit frame to a live host. Errors go to
/// the status log — "socket died" and "child closed stdin" are different
/// findings and must not collapse into one flag.
fn pump_stdin(
    mut conn: TcpStream,
    child_in: std::process::ChildStdin,
    socket_dead: Arc<AtomicBool>,
    eof_seen: Arc<AtomicBool>,
    log: Arc<std::sync::Mutex<Log>>,
) {
    let mut reader = FrameReader::default();
    let (send, receive) = std::sync::mpsc::sync_channel::<Option<Vec<u8>>>(2);
    // Child-side stdin closure is not a socket failure — it gets its own
    // flag so `run()` does not take the socket-dead shutdown path.
    let stdin_closed = Arc::new(AtomicBool::new(false));
    {
        let stdin_closed = Arc::clone(&stdin_closed);
        let log_pipe = Arc::clone(&log);
        thread::spawn(move || {
            let mut child_in = child_in;
            while let Ok(Some(bytes)) = receive.recv() {
                if child_in.write_all(&bytes).is_err() {
                    stdin_closed.store(true, Ordering::Release);
                    if let Ok(mut l) = log_pipe.lock() {
                        l.status("child stdin closed (pipe write failed)");
                    }
                    return;
                }
            }
        });
    }
    let mut closed = false;
    loop {
        let item = match reader.poll(&mut conn) {
            Ok(None) => continue,
            Ok(Some((F_STDIN, payload))) if !closed => {
                if stdin_closed.load(Ordering::Acquire) {
                    // Child closed stdin — the socket may still be alive;
                    // drop the payload and keep monitoring for EOF/cancel.
                    continue;
                }
                Ok(Some(payload))
            }
            Ok(Some((F_STDIN_EOF, payload))) if payload.is_empty() && !closed => {
                closed = true;
                eof_seen.store(true, Ordering::Release);
                // Keep watching the socket after EOF so disconnect/cancel can
                // still stop a child that ignores its closed input. When the
                // pipe already died the close sentinel is moot — the dead
                // writer already dropped child_in.
                if stdin_closed.load(Ordering::Acquire) {
                    continue;
                }
                Ok(None)
            }
            Ok(Some((F_CANCEL, payload))) if payload.is_empty() => Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionAborted,
                "host cancelled",
            )),
            Ok(Some(_)) => Err(invalid("unexpected frame or data after stdin EOF")),
            Err(e) => Err(e),
        };
        let result = item.and_then(|mut item| {
            let deadline = Instant::now() + IO_TIMEOUT;
            loop {
                match send.try_send(item) {
                    Ok(()) => return Ok(()),
                    Err(std::sync::mpsc::TrySendError::Full(back)) => item = back,
                    Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                        // Pipe writer exited — child closed stdin. Same
                        // dedicated flag; keep watching the socket.
                        stdin_closed.store(true, Ordering::Release);
                        return Ok(());
                    }
                }
                // A dead socket flagged by another pump is not local
                // backpressure — keep the two findings distinct.
                if socket_dead.load(Ordering::Acquire) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "socket died",
                    ));
                }
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "child stdin backpressure deadline",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
        if let Err(e) = result {
            if let Ok(mut l) = log.lock() {
                l.status(&format!("stdin pump ended: {e}"));
            }
            socket_dead.store(true, Ordering::Release);
            return;
        }
    }
}

/// child stdout -> socket frames; a socket failure flips `socket_dead`
/// so the main loop can kill the child.
fn pump_stdout(
    mut child_out: std::process::ChildStdout,
    writer: FrameWriter,
    socket_dead: Arc<AtomicBool>,
    log: Arc<std::sync::Mutex<Log>>,
) {
    let mut buf = [0u8; CHUNK];
    loop {
        match child_out.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if let Err(e) = writer.send(F_STDOUT, &buf[..n]) {
                    if let Ok(mut l) = log.lock() {
                        l.status(&format!("stdout pump socket error: {e}"));
                    }
                    socket_dead.store(true, Ordering::Release);
                    return;
                }
            }
        }
    }
}

/// child stderr -> frames (first `STDERR_FORWARD_CAP` bytes) + `stderr.log`
/// on the RW share (first `STDERR_LOG_CAP` bytes); the pipe is drained to
/// the end regardless so the child never wedges on a full stderr buffer.
/// A dead socket stops the forwarding half — and flips `socket_dead` like
/// the other pumps — but the drain and the stderr.log keep running.
fn pump_stderr(
    mut child_err: std::process::ChildStderr,
    writer: FrameWriter,
    rw_dir: PathBuf,
    socket_dead: Arc<AtomicBool>,
) {
    let mut forwarded = 0u64;
    let mut logged = 0u64;
    let mut forward = true;
    let mut log_file = fs::File::create(rw_dir.join("stderr.log")).ok();
    let mut buf = [0u8; CHUNK];
    loop {
        match child_err.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                if forward {
                    let fwd_room = STDERR_FORWARD_CAP.saturating_sub(forwarded) as usize;
                    if fwd_room > 0 {
                        let take = n.min(fwd_room);
                        if writer.send(F_STDERR, &buf[..take]).is_err() {
                            forward = false;
                            socket_dead.store(true, Ordering::Release);
                        } else {
                            forwarded += take as u64;
                        }
                    }
                }
                if let Some(f) = log_file.as_mut() {
                    let log_room = STDERR_LOG_CAP.saturating_sub(logged) as usize;
                    if log_room > 0 {
                        let take = n.min(log_room);
                        let _ = f.write_all(&buf[..take]);
                        logged += take as u64;
                    }
                }
            }
        }
    }
}

/// Wait for the child normally, or kill it once the relay socket died
/// (the host went away mid-session). Returns the exit code when the
/// child produced one, `None` after a socket death or a wedged kill.
fn wait_child(
    child: &mut Child,
    socket_dead: &Arc<AtomicBool>,
    eof_seen: &AtomicBool,
    log: &mut Log,
) -> Option<i32> {
    let mut kill_at: Option<Instant> = None;
    let mut eof_at: Option<Instant> = None;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return st.code(),
            Ok(None) => {}
            Err(_) => return None,
        }
        if eof_seen.load(Ordering::Acquire) {
            eof_at.get_or_insert_with(Instant::now);
        }
        if eof_at.is_some_and(|t| t.elapsed() > POST_KILL_WAIT) {
            log.status("child ignored stdin EOF deadline");
            socket_dead.store(true, Ordering::Release);
        }
        if socket_dead.load(Ordering::Acquire) {
            if kill_at.is_none() {
                log.status("relay socket lost — killing child");
                let _ = child.kill();
                kill_at = Some(Instant::now());
            }
            if kill_at.is_some_and(|t| t.elapsed() > POST_KILL_WAIT) {
                log.status("child did not exit after kill within 20s");
                return None;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

// ─── main ────────────────────────────────────────────────────────────────

pub fn main() {
    if let Err(e) = owned_job::contain_current_process() {
        eprintln!("wsb-relay-agent: cannot own process tree: {e}");
        std::process::exit(1);
    }
    let mut config_path = PathBuf::from(r"C:\relay-ro\relay-config.txt");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--config"
            && let Some(p) = args.next()
        {
            config_path = PathBuf::from(p);
        }
    }
    let cfg = match read_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "wsb-relay-agent: fatal: config {}: {e}",
                config_path.display()
            );
            std::process::exit(1);
        }
    };
    let mut log = match fs::create_dir_all(&cfg.rw_dir).and_then(|()| Log::open(&cfg.rw_dir)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "wsb-relay-agent: fatal: rw dir {}: {e}",
                cfg.rw_dir.display()
            );
            std::process::exit(1);
        }
    };
    log.status(&format!(
        "boot: pid={} config={}",
        std::process::id(),
        config_path.display()
    ));
    match run(&cfg, &mut log) {
        Ok(code) => {
            log.status(&format!("done: child exit code {code:?}"));
        }
        Err(e) => {
            log.status(&format!("fatal: {e}"));
            std::process::exit(1);
        }
    }
}

fn run(cfg: &Cfg, log: &mut Log) -> Result<Option<i32>, String> {
    stage_files(cfg, log)?;
    if cfg.guest {
        if std::env::var("USERNAME").unwrap_or_default().to_lowercase() != "wdagutilityaccount" {
            return Err("guest firewall setup requires WDAGUtilityAccount".into());
        }
        open_guest_firewall(cfg.listen_port, log);
        // Probe mapping enforcement as the unconfined agent as well: a Warden
        // denial alone cannot establish that the RO mapping itself works.
        let ro_write = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(cfg.ro_dir.join("agent-ro-probe.txt"));
        if !matches!(ro_write, Err(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied) {
            return Err("read-only mapped-folder probe did not deny access".into());
        }
        log.status("RO mapping: unconfined write denied (access denied)");
    }

    let listen_ip = if cfg.guest { "0.0.0.0" } else { "127.0.0.1" };
    let listener = TcpListener::bind((listen_ip, cfg.listen_port))
        .map_err(|e| format!("bind 0.0.0.0:{}: {e}", cfg.listen_port))?;
    let egress = if cfg.guest {
        egress_ip().ok_or("guest IPv4 missing")?
    } else {
        "127.0.0.1".into()
    };
    // The host polls this file on the RW share, then connects back to
    // the published address — inbound to the host is never required.
    let hello_path = cfg.rw_dir.join("relay-hello.txt");
    let hello_tmp = cfg.rw_dir.join("relay-hello.tmp");
    fs::write(
        &hello_tmp,
        format!(
            "ip={egress}\nport={}\npid={}\n",
            cfg.listen_port,
            std::process::id()
        ),
    )
    .map_err(|e| format!("write {}: {e}", hello_path.display()))?;
    fs::rename(hello_tmp, &hello_path).map_err(|e| format!("publish hello: {e}"))?;
    log.status(&format!("listening: {egress}:{}", cfg.listen_port));

    let conn = wait_for_host(&listener, cfg, log)?;
    // The writer side is shared mutex-guarded across pumps; the reader
    // side is a second handle to the same socket used only by the stdin
    // pump — reads and writes never contend on one handle.
    // A shutdown handle independent of the writer mutex must remain usable
    // while a slow peer blocks a frame write.
    let shutdown = conn.try_clone().map_err(|e| e.to_string())?;
    let reader = conn.try_clone().map_err(|e| format!("clone socket: {e}"))?;
    let writer = FrameWriter(Arc::new(std::sync::Mutex::new(conn)));

    let mut child = match spawn_runner(cfg) {
        Ok(c) => c,
        Err(e) => {
            let _ = writer.send(
                F_AGENT_ERROR,
                format!("{{\"error\":\"{}\"}}", e.replace('"', "'")).as_bytes(),
            );
            return Err(e);
        }
    };
    log.status(&format!("runner spawned: pid={}", child.id()));

    let socket_dead = Arc::new(AtomicBool::new(false));
    let eof_seen = Arc::new(AtomicBool::new(false));
    let shared_log = Arc::new(std::sync::Mutex::new(log.clone_empty()));
    let child_in = child.stdin.take().ok_or("child stdin missing")?;
    let child_out = child.stdout.take().ok_or("child stdout missing")?;
    let child_err = child.stderr.take().ok_or("child stderr missing")?;

    let dead_in = Arc::clone(&socket_dead);
    let log_in = Arc::clone(&shared_log);
    let eof_in = Arc::clone(&eof_seen);
    let t_in = thread::spawn(move || pump_stdin(reader, child_in, dead_in, eof_in, log_in));
    let dead_out = Arc::clone(&socket_dead);
    let w_out = writer.clone();
    let log_out = Arc::clone(&shared_log);
    let t_out = thread::spawn(move || pump_stdout(child_out, w_out, dead_out, log_out));
    let w_err = writer.clone();
    let dead_err = Arc::clone(&socket_dead);
    let rw_dir = cfg.rw_dir.clone();
    let t_err = thread::spawn(move || pump_stderr(child_err, w_err, rw_dir, dead_err));

    let code = wait_child(&mut child, &socket_dead, &eof_seen, log);
    let drain_deadline = Instant::now() + IO_TIMEOUT;
    while !t_out.is_finished() || !t_err.is_finished() {
        if socket_dead.load(Ordering::Acquire) || Instant::now() >= drain_deadline {
            let _ = shutdown.shutdown(std::net::Shutdown::Both);
            log.status("output drain interrupted or exceeded deadline");
            // Dropping JoinHandle detaches; exiting this process closes the
            // unnamed Job, reaping descendants that hold pipes open.
            return Err("output drain did not complete".into());
        }
        thread::sleep(Duration::from_millis(20));
    }
    // Tell the host, then close; pumps unwind on their own once the
    // socket is gone (or already returned on child EOF).
    let exit = format!(
        "{{\"code\":{}}}",
        code.map_or("null".into(), |c| c.to_string())
    );
    if socket_dead.load(Ordering::Acquire) {
        // The host is gone — F_EXIT has nowhere to go. Shut the socket
        // down so a pump wedged in a send unwinds, then join.
        let _ = shutdown.shutdown(std::net::Shutdown::Both);
        let _ = t_out.join();
        let _ = t_err.join();
    } else {
        // Drain the pumps first so the exit frame can never overtake
        // the child's trailing stdout/stderr frames on the socket.
        let _ = t_out.join();
        let _ = t_err.join();
        if let Err(e) = writer.send(F_EXIT, exit.as_bytes()) {
            log.status(&format!("exit frame send failed: {e}"));
        }
        let _ = shutdown.shutdown(std::net::Shutdown::Both);
    }
    // A runner can stop reading stdin before it exits. A pump blocked in that
    // pipe must not hold the agent alive. Process exit plus the owned Job is
    // the final bound for pipe threads and all remaining descendants.
    drop(t_in);
    log.status(&format!("session end: child exit {code:?}"));
    Ok(code)
}
