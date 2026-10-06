//! Std-only probe for the WSL Containers (`wslc`) validation
//! (`tests/wslc_container_e2e/`, `docs/validation/wslc.md`).
//!
//! Compiled by the test via plain `rustc --target x86_64-unknown-linux-musl`
//! (no cargo, no crates) and baked into the probe image. It has two modes:
//!
//!   `wslc-probe`               MCP mode — the same JSON-RPC tool loop the
//!                              shared Kata fixture speaks, so the
//!                              runner-wrapped session exercises identical
//!                              guest-control legs. serverInfo is
//!                              `wslc-probe` to match fixtures/wslc/policy.kdl.
//!   `wslc-probe <cmd> [args]`  substrate mode — plain key=value facts the
//!                              test drives directly via `wslc run <img>
//!                              <cmd>` without the runner/policy layer, to
//!                              measure the wslc substrate contract itself
//!                              (stdio, virtiofs, Consommé networking,
//!                              signals, exit codes, TTY presence):
//!
//!     stdio-echo          read one stdin line → `ECHO:<line>` on stdout,
//!                         `STDERR-MARK` on stderr; drain stdin to EOF;
//!                         exit 0 (bidirectional stdio + stream separation
//!                         + EOF propagation)
//!     exit-code <n>       exit(n) — exit-code fidelity
//!     print-env <name>    `ENV:<name>=<value|ABSENT>` — `-e` delivery
//!     tty-check           /dev/tty openability + /proc/self/fd/{0,1,2}
//!                         targets — non-TTY launch evidence
//!     identity            osrelease/hostname/NoNewPrivs/Seccomp/lsm/
//!                         virtiofs+9p mounts/cgroup/pid1 — session-VM and
//!                         container identity facts
//!     share-probe <path>  mount entry (fstype+opts) covering <path>,
//!                         dir listing, file read, create test — virtiofs
//!                         RO/RW/visibility facts
//!     case-probe <dir>    create `CaseProbe<PID>.TXT`, stat lowercase —
//!                         case-sensitivity evidence
//!     reparse-probe <p>   open+read <p> — whether a host reparse point
//!                         (junction/symlink) is visible through the share
//!     net-dns <name>      resolve <name>:80 — Consommé DNS
//!     net-tcp <addr>      connect_timeout(<addr>, 5s) — Consommé reach
//!     net-tcp-gw <port>   discover the default gateway in
//!                         /proc/net/route, connect <gw>:<port> —
//!                         host-loopback reachability evidence
//!     net-routes          /proc/net/route + /proc/net/if_inet6 +
//!                         /etc/resolv.conf dump — gateway/IPv6
//!                         discovery evidence
//!     net-listen <port>   bind 0.0.0.0:<port>, write `PROBE-LISTEN-OK`
//!                         to each accepted conn, loop until killed —
//!                         `-p` publish evidence
//!     sleep <secs>        install SIGINT/SIGTERM handlers, sleep, print
//!                         `SIGNAL=<n>` when signalled — stop/kill delivery
//!
//! MCP tools (runner-wrapped mode — same names/semantics as the shared
//! kata probe so deny legs attribute identically):
//!
//!   read_file {path}          open read; content head + dev/ino identity
//!   create_file {path,content?} create_new write (fs write grant evidence)
//!   chmod_666 {path}          chmod — outside the policy syscall allowlist
//!   vm_identity {}            kernel release, NoNewPrivs/Seccomp fields,
//!                             virtiofs+9p state, lsm list, kata marker
//!   net_probe {addr?}         outbound TCP connect — socket/connect sit
//!                             outside the fixture policy's allowlist
//!   mrtr_probe {}             MRTR leg: without params.requestState the
//!                             result is an `input_required` interim
//!                             (elicitation/create inputRequest); a retry
//!                             carrying requestState gets the final result
//!   slow_echo {ms}            sleep <ms> then answer — slow-peer tolerance
//!   big_text {bytes}          answer with a <bytes>-sized text payload —
//!                             excessive-output transport leg
//!
//! argv mode additionally exposes:
//!     mem-probe           /proc/self/status VmPeak/VmRSS + the unit's
//!                         cgroup v2 memory.current/peak — RSS evidence
//!
//! A known tool returns `isError=false` even when the operation fails —
//! failure details ride in the result text. Unknown tools get
//! `isError=true`; unknown methods get -32601.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};

// ─── minimal JSON parser (same contract as open_path_server.rs) ────────

#[derive(Clone)]
enum J {
    Null,
    Bool(bool),
    Num(String),
    // Parsed for completeness; request fields used here are never arrays.
    #[allow(dead_code)]
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
    Str(String),
}

impl J {
    fn get(&self, key: &str) -> Option<&J> {
        if let J::Obj(m) = self {
            m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
        } else {
            None
        }
    }

    fn as_str(&self) -> Option<&str> {
        if let J::Str(s) = self { Some(s) } else { None }
    }

    fn raw(&self) -> String {
        match self {
            J::Num(n) => n.clone(),
            J::Str(s) => format!("\"{}\"", json_escape(s)),
            J::Bool(b) => b.to_string(),
            _ => "null".to_string(),
        }
    }
}

struct Jp<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Jp<'a> {
    fn new(text: &'a str) -> Self {
        Jp {
            s: text.as_bytes(),
            i: 0,
        }
    }
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }
    fn value(&mut self) -> Option<J> {
        self.ws();
        match *self.s.get(self.i)? {
            b'{' => self.obj(),
            b'[' => self.arr(),
            b'"' => self.string().map(J::Str),
            b't' => self.lit("true").map(|_| J::Bool(true)),
            b'f' => self.lit("false").map(|_| J::Bool(false)),
            b'n' => self.lit("null").map(|_| J::Null),
            _ => self.num(),
        }
    }
    fn lit(&mut self, w: &str) -> Option<()> {
        if self.s[self.i..].starts_with(w.as_bytes()) {
            self.i += w.len();
            Some(())
        } else {
            None
        }
    }
    fn num(&mut self) -> Option<J> {
        self.ws();
        let start = self.i;
        while matches!(
            self.s.get(self.i),
            Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
        ) {
            self.i += 1;
        }
        (self.i > start).then(|| J::Num(self.s[start..self.i].iter().map(|b| *b as char).collect()))
    }
    fn hex4(&mut self) -> Option<u32> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            let d = match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => return None,
            };
            v = v * 16 + d as u32;
        }
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        (*self.s.get(self.i)? == b'"').then(|| self.i += 1);
        let mut out = String::new();
        loop {
            let c = *self.s.get(self.i)?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = *self.s.get(self.i)?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{0008}'),
                        b'f' => out.push('\u{000C}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            if (0xD800..0xDC00).contains(&hi) {
                                if self.s.get(self.i) == Some(&b'\\')
                                    && self.s.get(self.i + 1) == Some(&b'u')
                                {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if !(0xDC00..0xE000).contains(&lo) {
                                        return None;
                                    }
                                    let cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                                    out.push(char::from_u32(cp)?);
                                } else {
                                    return None;
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return None;
                            } else {
                                out.push(char::from_u32(hi)?);
                            }
                        }
                        _ => return None,
                    }
                }
                _ => {
                    // Multi-byte UTF-8 passthrough (same contract as
                    // open_path_server.rs): `c` is the first byte of a
                    // sequence already consumed; re-emit the full sequence.
                    let len = if c < 0x80 {
                        1
                    } else if c < 0xE0 {
                        2
                    } else if c < 0xF0 {
                        3
                    } else {
                        4
                    };
                    let start = self.i - 1;
                    let end = start + len;
                    let chunk = std::str::from_utf8(self.s.get(start..end)?).ok()?;
                    out.push_str(chunk);
                    self.i = end;
                }
            }
        }
    }
    fn obj(&mut self) -> Option<J> {
        (*self.s.get(self.i)? == b'{').then(|| self.i += 1);
        let mut m = Vec::new();
        loop {
            self.ws();
            match self.s.get(self.i)? {
                b'}' => {
                    self.i += 1;
                    return Some(J::Obj(m));
                }
                b',' => self.i += 1,
                _ => {
                    let k = self.string()?;
                    self.ws();
                    (*self.s.get(self.i)? == b':').then(|| self.i += 1);
                    let v = self.value()?;
                    m.push((k, v));
                }
            }
        }
    }
    fn arr(&mut self) -> Option<J> {
        (*self.s.get(self.i)? == b'[').then(|| self.i += 1);
        let mut a = Vec::new();
        loop {
            self.ws();
            match self.s.get(self.i)? {
                b']' => {
                    self.i += 1;
                    return Some(J::Arr(a));
                }
                b',' => self.i += 1,
                _ => a.push(self.value()?),
            }
        }
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

// ─── tools ───────────────────────────────────────────────────────────

fn text_result(id_raw: String, text: String, is_error: bool, rt: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{{rt}\"content\":[{{\"type\":\"text\",\"text\":\"{t}\"}}],\"isError\":{e}}}}}",
        id = id_raw,
        rt = rt,
        t = json_escape(&text),
        e = is_error
    )
}

fn rpc_error(id_raw: String, code: i64, message: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"error\":{{\"code\":{code},\"message\":\"{m}\"}}}}",
        id = id_raw,
        code = code,
        m = json_escape(message)
    )
}

fn tool_read_file(args: &J) -> String {
    let Some(path) = args.get("path").and_then(J::as_str) else {
        return "missing arguments.path".to_string();
    };
    match File::open(path) {
        Ok(mut f) => {
            let mut buf = vec![0u8; 256];
            let n = io::Read::read(&mut f, &mut buf).unwrap_or(0);
            let meta = f.metadata().ok();
            let (dev, ino) = meta
                .map(|m| {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        (m.dev(), m.ino())
                    }
                    #[cfg(not(unix))]
                    {
                        (0, 0)
                    }
                })
                .unwrap_or((0, 0));
            format!(
                "opened {path}: dev={dev} ino={ino} head=\"{}\"",
                json_escape(&String::from_utf8_lossy(&buf[..n]))
            )
        }
        Err(e) => format!("open {path} failed: {e}"),
    }
}

fn tool_create_file(args: &J) -> String {
    let Some(path) = args.get("path").and_then(J::as_str) else {
        return "missing arguments.path".to_string();
    };
    let content = args.get("content").and_then(J::as_str).unwrap_or("");
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut f) => match f.write_all(content.as_bytes()) {
            Ok(()) => format!("created {path} ({} bytes)", content.len()),
            Err(e) => format!("write {path} failed: {e}"),
        },
        Err(e) => format!("create {path} failed: {e}"),
    }
}

/// chmod is deliberately outside the fixture policy's syscall allowlist —
/// a guest kernel that applied the seccomp program answers this with
/// EPERM, one that did not performs the chmod.
fn tool_chmod_666(args: &J) -> String {
    let Some(path) = args.get("path").and_then(J::as_str) else {
        return "missing arguments.path".to_string();
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)) {
            Ok(()) => format!("chmod {path} succeeded"),
            Err(e) => format!("chmod {path} failed: {e}"),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        "chmod unsupported on this platform".to_string()
    }
}

/// Guest-side identity the host cannot fake: kernel release, cgroup/fs
/// view, and this process's own sandbox state. The probe runs under the
/// runner's Landlock+seccomp, so `Seccomp: 2` and `NoNewPrivs: 1` are the
/// in-guest mechanism state — for a `wslc` unit this is the session VM's
/// kernel, not the Windows host or a `wsl.exe` distro's.
fn tool_vm_identity() -> String {
    let read = |p: &str| {
        std::fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_string())
    };
    let field = |text: &str, name: &str| -> String {
        text.lines()
            .find(|l| l.starts_with(name))
            .map(|l| {
                l.split_once(':')
                    .map(|x| x.1.trim().to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_else(|| "absent".to_string())
    };
    let status = read("/proc/self/status").unwrap_or_default();
    let fstab = read("/proc/filesystems").unwrap_or_default();
    let mounts = read("/proc/mounts").unwrap_or_default();
    format!(
        "uname.osrelease={} nodename={} | NoNewPrivs={} Seccomp={} Seccomp_filters={} | virtiofs_in_filesystems={} securityfs_mounted={} lsm_list={} | cmdline_has_kata={}",
        read("/proc/sys/kernel/osrelease").unwrap_or_else(|| "?".into()),
        read("/proc/sys/kernel/hostname").unwrap_or_else(|| "?".into()),
        field(&status, "NoNewPrivs"),
        field(&status, "Seccomp"),
        field(&status, "Seccomp_filters"),
        fstab.contains("virtiofs") || fstab.contains("9p"),
        mounts.contains("securityfs"),
        read("/sys/kernel/security/lsm").unwrap_or_else(|| "unreadable".into()),
        read("/proc/cmdline")
            .map(|c| c.contains("kata"))
            .unwrap_or(false)
    )
}

/// `socket`/`connect` are outside the fixture policy's syscall allowlist
/// (and `network { deny host="*" }` drops `socket` from it even if listed),
/// so an outbound TCP connect must surface EPERM/EACCES inside the guest —
/// the kernel-level network-deny proof.
fn tool_net_probe(args: &J) -> String {
    let addr = args
        .get("addr")
        .and_then(J::as_str)
        .unwrap_or("192.0.2.1:80");
    // `connect` on a reachable-looking but dead target would park this
    // single-threaded probe loop for the OS default timeout; bound it so
    // a slow path still surfaces as a connection failure.
    match addr.parse::<std::net::SocketAddr>() {
        Ok(sa) => {
            match std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(2)) {
                Ok(_) => format!("connect {addr} succeeded (unexpected)"),
                Err(e) => format!("connect {addr} failed: {e}"),
            }
        }
        Err(e) => format!("connect {addr} failed: invalid address: {e}"),
    }
}

/// MRTR (2026-07-28 input_required) leg: a call without
/// `params.requestState` gets an interim `resultType=input_required`
/// bearing one `elicitation/create` inputRequest — the proxy's MRTR gate
/// decides whether it reaches the client. A retry carrying
/// `requestState` (plus the policy-gated `inputResponses`) is the
/// continuation and gets the final result as ordinary text.
const MRTR_INTERIM: &str = "{\"resultType\":\"input_required\",\"requestState\":\"wslc-seed\",\"inputRequests\":{\"github_login\":{\"method\":\"elicitation/create\",\"params\":{\"mode\":\"form\",\"message\":\"Provide a login\",\"requestedSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}}}}}";

fn tool_mrtr_probe_final(params: Option<&J>) -> String {
    let answered: Vec<String> = params
        .and_then(|p| p.get("inputResponses"))
        .map(|r| match r {
            J::Obj(m) => m.iter().map(|(k, _)| k.clone()).collect(),
            _ => vec![],
        })
        .unwrap_or_default();
    format!("mrtr-ok answered=[{}]", answered.join(","))
}

/// Slow-peer leg: hold the tool response for `ms` milliseconds — the
/// transport must still deliver it intact.
fn tool_slow_echo(args: &J) -> String {
    let ms = args
        .get("ms")
        .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        .or_else(|| {
            args.get("ms").and_then(|v| match v {
                J::Num(n) => n.parse::<u64>().ok(),
                _ => None,
            })
        })
        .unwrap_or(0)
        .min(30_000);
    std::thread::sleep(std::time::Duration::from_millis(ms));
    format!("slept={ms}")
}

/// Excessive-output leg: a text payload of `bytes` bytes — the transport
/// must deliver the whole frame, not truncate or wedge on it.
fn tool_big_text(args: &J) -> String {
    let n = args
        .get("bytes")
        .and_then(|v| match v {
            J::Num(s) => s.parse::<usize>().ok(),
            J::Str(s) => s.parse::<usize>().ok(),
            _ => None,
        })
        .unwrap_or(1024)
        .min(8 * 1024 * 1024);
    let body = "x".repeat(n.saturating_sub(6));
    format!("{body}BIGEND")
}

fn tools_list() -> &'static str {
    "{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"create_file\"},{\"name\":\"chmod_666\"},{\"name\":\"vm_identity\"},{\"name\":\"net_probe\"},{\"name\":\"mrtr_probe\"},{\"name\":\"slow_echo\"},{\"name\":\"big_text\"}]}"
}

// ─── MCP main loop ───────────────────────────────────────────────────

fn mcp_loop() {
    let stdin = io::stdin();
    let stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let mut p = Jp::new(&line);
        let Some(req) = p.value() else {
            continue;
        };
        let method = req
            .get("method")
            .and_then(J::as_str)
            .unwrap_or("")
            .to_string();
        let id_raw = req
            .get("id")
            .map(|j| j.raw())
            .unwrap_or_else(|| "null".into());
        let is_request = req.get("id").is_some();
        match method.as_str() {
            "initialize" => {
                writeln!(
                    stdout.lock(),
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"wslc-probe\",\"version\":\"0\"}}}}}}",
                    id = id_raw
                )
                .ok();
            }
            "tools/list" => {
                writeln!(
                    stdout.lock(),
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{list}}}",
                    id = id_raw,
                    list = tools_list()
                )
                .ok();
            }
            "tools/call" => {
                let params = req.get("params");
                let name = params
                    .and_then(|p| p.get("name"))
                    .and_then(J::as_str)
                    .unwrap_or("")
                    .to_string();
                let args = params
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or(J::Obj(vec![]));
                // MRTR: a stateless call on `mrtr_probe` answers with the
                // interim `input_required` *result object* (not the text
                // envelope) — a retry carrying requestState completes.
                if name == "mrtr_probe" && params.and_then(|p| p.get("requestState")).is_none() {
                    writeln!(
                        stdout.lock(),
                        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{MRTR_INTERIM}}}",
                        id = id_raw
                    )
                    .ok();
                    stdout.lock().flush().ok();
                    continue;
                }
                let out = match name.as_str() {
                    "read_file" => (tool_read_file(&args), false),
                    "create_file" => (tool_create_file(&args), false),
                    "chmod_666" => (tool_chmod_666(&args), false),
                    "vm_identity" => (tool_vm_identity(), false),
                    "net_probe" => (tool_net_probe(&args), false),
                    "mrtr_probe" => (tool_mrtr_probe_final(params), false),
                    "slow_echo" => (tool_slow_echo(&args), false),
                    "big_text" => (tool_big_text(&args), false),
                    _ => (format!("unknown tool '{name}'"), true),
                };
                // A 2026-07-28 result MUST declare `resultType` — the
                // proxy denies an absent member on that wire. The
                // request's params._meta pins the wire version.
                let rt = if params
                    .and_then(|p| p.get("_meta"))
                    .and_then(|m| m.get("io.modelcontextprotocol/protocolVersion"))
                    .and_then(J::as_str)
                    == Some("2026-07-28")
                {
                    "\"resultType\":\"complete\","
                } else {
                    ""
                };
                writeln!(stdout.lock(), "{}", text_result(id_raw, out.0, out.1, rt)).ok();
            }
            m if m.starts_with("notifications/") => {}
            _ if is_request => {
                writeln!(
                    stdout.lock(),
                    "{}",
                    rpc_error(id_raw, -32601, &format!("method not found: {method}"))
                )
                .ok();
            }
            _ => {}
        }
        stdout.lock().flush().ok();
    }
}

// ─── substrate (argv) mode ───────────────────────────────────────────
//
// Plain key=value facts driven directly by `wslc run <img> <cmd>` — no
// MCP, no runner, no policy. Every command prints machine-readable
// `key=value` or `KEY=free text` lines so the harness can diff the
// substrate contract against the documented CLI surface.

fn read_to_string_or(p: &str, absent: &str) -> String {
    std::fs::read_to_string(p)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| absent.to_string())
}

fn status_field(name: &str) -> String {
    let status = read_to_string_or("/proc/self/status", "");
    status
        .lines()
        .find(|l| l.starts_with(name))
        .map(|l| {
            l.split_once(':')
                .map(|x| x.1.trim().to_string())
                .unwrap_or_default()
        })
        .unwrap_or_else(|| "absent".to_string())
}

/// Read one stdin line and echo it back; a marker goes to stderr so the
/// harness can prove the streams stay separate. Then drain stdin to EOF
/// and exit 0 — EOF propagation is part of the contract under test.
fn cmd_stdio_echo() -> i32 {
    let stdin = io::stdin();
    let mut lock = stdin.lock();
    let mut line = String::new();
    match lock.read_line(&mut line) {
        Ok(0) => println!("ECHO-EOF"),
        Ok(_) => println!("ECHO:{}", line.trim_end()),
        Err(e) => println!("ECHO-ERR:{e}"),
    }
    eprintln!("STDERR-MARK");
    // Drain to EOF so a host that holds stdin open keeps us alive; a
    // host that closes it gets a clean 0 exit.
    let mut sink = String::new();
    while lock.read_line(&mut sink).unwrap_or(0) > 0 {
        sink.clear();
    }
    0
}

/// /dev/tty openability is the controlling-terminal proof; the fd link
/// targets show what the CLI actually attached (pipes vs a pts).
fn cmd_tty_check() -> i32 {
    match File::open("/dev/tty") {
        Ok(_) => println!("dev_tty=opened"),
        Err(e) => println!("dev_tty=failed:{e}"),
    }
    for fd in [0, 1, 2] {
        let target = std::fs::read_link(format!("/proc/self/fd/{fd}"))
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| format!("unreadable:{e}"));
        println!("fd{fd}={target}");
    }
    0
}

/// Session-VM and container identity: kernel release, hostname, LSM
/// list, own sandbox state, mounts that carry host shares, the cgroup
/// membership, and PID 1's name (the unit's init — distinct from the
/// session VM's init).
fn cmd_identity() -> i32 {
    let mounts = read_to_string_or("/proc/mounts", "");
    let share_mounts: Vec<&str> = mounts
        .lines()
        .filter(|l| l.contains("virtiofs") || l.contains("9p"))
        .collect();
    println!(
        "osrelease={}",
        read_to_string_or("/proc/sys/kernel/osrelease", "?")
    );
    println!(
        "hostname={}",
        read_to_string_or("/proc/sys/kernel/hostname", "?")
    );
    println!("NoNewPrivs={}", status_field("NoNewPrivs"));
    println!("Seccomp={}", status_field("Seccomp"));
    println!("Seccomp_filters={}", status_field("Seccomp_filters"));
    println!(
        "lsm_list={}",
        read_to_string_or("/sys/kernel/security/lsm", "unreadable")
    );
    println!("share_mounts={}", share_mounts.len());
    for m in share_mounts {
        println!("mount={m}");
    }
    println!("cgroup={}", read_to_string_or("/proc/self/cgroup", "?"));
    println!("pid1_comm={}", read_to_string_or("/proc/1/comm", "?"));
    0
}

/// The /proc/mounts entry covering `path` (longest mount-point match) —
/// fstype + options tell the harness whether a virtiofs share arrived
/// read-only, plus dev/ino identity and create/list/read results.
fn cmd_share_probe(path: &str) -> i32 {
    let mounts = read_to_string_or("/proc/mounts", "");
    let norm = path.trim_end_matches('/');
    let best = mounts
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let src = f.next()?;
            let mp = f.next()?;
            let fs = f.next()?;
            let opts = f.next()?;
            let mp_norm = mp.trim_end_matches('/');
            if norm == mp_norm
                || norm.starts_with(&format!("{mp_norm}/"))
                || mp_norm.is_empty() && norm.starts_with('/')
            {
                Some((mp.len(), src, mp, fs, opts))
            } else {
                None
            }
        })
        .max_by_key(|(len, ..)| *len);
    match best {
        Some((_, src, mp, fs, opts)) => println!("mount=src:{src} mp:{mp} fs:{fs} opts:{opts}"),
        None => println!("mount=none"),
    }
    let dir = if std::path::Path::new(path).is_dir() {
        path.to_string()
    } else {
        std::path::Path::new(path)
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "/".into())
    };
    match std::fs::read_dir(&dir) {
        Ok(rd) => {
            let mut names: Vec<String> = rd
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect();
            names.sort();
            println!("list={}", names.join(","));
        }
        Err(e) => println!("list=failed:{e}"),
    }
    if std::path::Path::new(path).is_file() {
        match File::open(path) {
            Ok(mut f) => {
                let mut buf = vec![0u8; 256];
                let n = io::Read::read(&mut f, &mut buf).unwrap_or(0);
                #[cfg(unix)]
                let ids = {
                    use std::os::unix::fs::MetadataExt;
                    let m = f.metadata().unwrap();
                    format!(" dev={} ino={}", m.dev(), m.ino())
                };
                #[cfg(not(unix))]
                let ids = String::new();
                println!("read=ok:{} bytes{}", n, ids);
                println!("head={}", json_escape(&String::from_utf8_lossy(&buf[..n])));
            }
            Err(e) => println!("read=failed:{e}"),
        }
    }
    // Write test: creating a file inside the probed path's directory is
    // the RW proof — an RO share must refuse it.
    let probe_file = format!("{dir}/.wslc-probe-write-{}", std::process::id());
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_file)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe_file);
            println!("write=ok");
        }
        Err(e) => println!("write=failed:{e}"),
    }
    0
}

/// Create an upper-case name, then stat its lowercase spelling — on a
/// case-insensitive view (NTFS through virtiofs) the stat succeeds.
fn cmd_case_probe(dir: &str) -> i32 {
    let upper = format!("{dir}/CaseProbe{}.TXT", std::process::id());
    match OpenOptions::new().write(true).create_new(true).open(&upper) {
        Ok(mut f) => {
            let _ = f.write_all(b"case");
        }
        Err(e) => {
            println!("create=failed:{e}");
            return 1;
        }
    }
    let lower = format!("{dir}/caseprobe{}.txt", std::process::id());
    let found = std::path::Path::new(&lower).exists();
    println!("lowercase_stat={found}");
    let _ = std::fs::remove_file(&upper);
    // A created-lowercase → read-uppercase check too, in case only one
    // direction is folded.
    let lower2 = format!("{dir}/caseprobe2{}.txt", std::process::id());
    let _ = std::fs::write(&lower2, b"case2");
    let upper2 = format!("{dir}/CASEPROBE2{}.TXT", std::process::id());
    println!("uppercase_stat={}", std::path::Path::new(&upper2).exists());
    let _ = std::fs::remove_file(&lower2);
    0
}

/// Whether a host reparse point (junction/symlink) is visible and
/// readable through the share — record, never assume.
fn cmd_reparse_probe(path: &str) -> i32 {
    match std::fs::symlink_metadata(path) {
        Ok(m) => {
            println!("metadata=ok is_symlink={}", m.file_type().is_symlink());
        }
        Err(e) => {
            println!("metadata=failed:{e}");
            return 0;
        }
    }
    match File::open(path) {
        Ok(mut f) => {
            let mut buf = vec![0u8; 128];
            let n = io::Read::read(&mut f, &mut buf).unwrap_or(0);
            println!(
                "read=ok:{n} head={}",
                json_escape(&String::from_utf8_lossy(&buf[..n]))
            );
        }
        Err(e) => println!("read=failed:{e}"),
    }
    match std::fs::read_link(path) {
        Ok(t) => println!("readlink={}", t.display()),
        Err(e) => println!("readlink=failed:{e}"),
    }
    0
}

fn cmd_net_dns(name: &str) -> i32 {
    use std::net::ToSocketAddrs;
    match (name, 80u16).to_socket_addrs() {
        Ok(addrs) => {
            let list: Vec<String> = addrs.map(|a| a.to_string()).collect();
            println!("resolved={} [{}]", list.len(), list.join(","));
            0
        }
        Err(e) => {
            println!("resolved=failed:{e}");
            1
        }
    }
}

fn cmd_net_tcp(addr: &str) -> i32 {
    match addr.parse::<std::net::SocketAddr>() {
        Ok(sa) => {
            let t = std::time::Instant::now();
            match std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(5)) {
                Ok(_) => {
                    println!("connected={}ms", t.elapsed().as_millis());
                    0
                }
                Err(e) => {
                    println!("connected=failed:{e}");
                    1
                }
            }
        }
        Err(e) => {
            println!("connected=invalid:{e}");
            2
        }
    }
}

fn cmd_net_routes() -> i32 {
    for line in read_to_string_or("/proc/net/route", "?").lines() {
        println!("route={line}");
    }
    for line in read_to_string_or("/proc/net/ipv6_route", "?").lines() {
        println!("route6={line}");
    }
    for line in read_to_string_or("/proc/net/if_inet6", "?").lines() {
        println!("if_inet6={line}");
    }
    for line in read_to_string_or("/etc/resolv.conf", "?").lines() {
        println!("resolv={line}");
    }
    0
}

/// Parse the default gateway out of /proc/net/route (Destination ==
/// 00000000; the gateway field is a little-endian hex dword) and TCP
/// connect to it on `port` — the Consommé host-loopback reach leg.
fn cmd_net_tcp_gw(port: &str) -> i32 {
    let port: u16 = match port.parse() {
        Ok(p) => p,
        Err(e) => {
            println!("connected=invalid-port:{e}");
            return 2;
        }
    };
    let routes = read_to_string_or("/proc/net/route", "");
    let gw = routes.lines().find_map(|line| {
        let mut f = line.split_whitespace();
        let _iface = f.next()?;
        if f.next()? != "00000000" {
            return None;
        }
        let v = u32::from_str_radix(f.next()?, 16).ok()?;
        Some(std::net::Ipv4Addr::from(v.to_le_bytes()))
    });
    let Some(gw) = gw else {
        println!("gateway=none-found");
        return 1;
    };
    println!("gateway={gw}");
    let sa = std::net::SocketAddr::new(std::net::IpAddr::V4(gw), port);
    match std::net::TcpStream::connect_timeout(&sa, std::time::Duration::from_secs(5)) {
        Ok(_) => {
            println!("connected=gw:{gw}:{port}");
            0
        }
        Err(e) => {
            println!("connected=failed:{e}");
            1
        }
    }
}

fn cmd_net_listen(port: &str) -> i32 {
    let port: u16 = port.parse().unwrap_or(0);
    let listener = match std::net::TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => {
            println!("listen=failed:{e}");
            return 1;
        }
    };
    println!("listen=bound:{port}");
    io::stdout().flush().ok();
    // Serve every connect — the harness polls reachability before it
    // reads the payload, so one-shot accept would race it.
    loop {
        match listener.accept() {
            Ok((mut s, peer)) => {
                let _ = s.write_all(b"PROBE-LISTEN-OK\n");
                eprintln!("accepted={peer}");
            }
            Err(e) => {
                eprintln!("accept=failed:{e}");
            }
        }
    }
}

static GOT_SIGNAL: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

extern "C" fn on_signal(sig: i32) {
    GOT_SIGNAL.store(sig as u32, std::sync::atomic::Ordering::SeqCst);
}

// musl exposes signal(2); SIGINT=2 / SIGTERM=15 on Linux. The handler
// only records — the loop below reports, keeping the handler async-safe.
extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

fn cmd_sleep(secs: &str) -> i32 {
    let secs: u64 = secs.parse().unwrap_or(300);
    unsafe {
        signal(2, on_signal);
        signal(15, on_signal);
    }
    println!("sleep=armed");
    io::stdout().flush().ok();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while std::time::Instant::now() < deadline {
        let sig = GOT_SIGNAL.load(std::sync::atomic::Ordering::SeqCst);
        if sig != 0 {
            println!("SIGNAL={sig}");
            io::stdout().flush().ok();
            return 0;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    println!("sleep=elapsed");
    0
}

/// RSS evidence: this process's VmPeak/VmRSS plus the unit cgroup's
/// memory.current/peak/max — what the unit actually costs the session
/// VM. `wslc exec <unit> wslc-probe mem-probe` against a live unit.
fn cmd_mem_probe() -> i32 {
    println!("VmPeak={}", status_field("VmPeak"));
    println!("VmRSS={}", status_field("VmRSS"));
    println!("VmSize={}", status_field("VmSize"));
    for f in ["memory.current", "memory.peak", "memory.max"] {
        println!(
            "cgroup.{}={}",
            f,
            read_to_string_or(&format!("/sys/fs/cgroup/{f}"), "absent")
        );
    }
    0
}

fn run_argv(cmd: &str, args: &[String]) -> i32 {
    match cmd {
        "stdio-echo" => cmd_stdio_echo(),
        "exit-code" => args
            .first()
            .and_then(|s| s.parse::<i32>().ok())
            .unwrap_or(0),
        "print-env" => {
            let name = args.first().map(|s| s.as_str()).unwrap_or("");
            match std::env::var(name) {
                Ok(v) => println!("ENV:{name}={v}"),
                Err(_) => println!("ENV:{name}=ABSENT"),
            }
            0
        }
        "tty-check" => cmd_tty_check(),
        "identity" => cmd_identity(),
        "share-probe" => cmd_share_probe(args.first().map(|s| s.as_str()).unwrap_or("/")),
        "case-probe" => cmd_case_probe(args.first().map(|s| s.as_str()).unwrap_or("/tmp")),
        "reparse-probe" => cmd_reparse_probe(args.first().map(|s| s.as_str()).unwrap_or("/")),
        "net-dns" => cmd_net_dns(args.first().map(|s| s.as_str()).unwrap_or("localhost")),
        "net-tcp" => cmd_net_tcp(args.first().map(|s| s.as_str()).unwrap_or("127.0.0.1:1")),
        "net-tcp-gw" => cmd_net_tcp_gw(args.first().map(|s| s.as_str()).unwrap_or("0")),
        "net-routes" => cmd_net_routes(),
        "net-listen" => cmd_net_listen(args.first().map(|s| s.as_str()).unwrap_or("8080")),
        "sleep" => cmd_sleep(args.first().map(|s| s.as_str()).unwrap_or("300")),
        "mem-probe" => cmd_mem_probe(),
        other => {
            eprintln!("unknown probe command: {other}");
            2
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(cmd) = args.first() {
        std::process::exit(run_argv(cmd, &args[1..]));
    }
    mcp_loop();
}
