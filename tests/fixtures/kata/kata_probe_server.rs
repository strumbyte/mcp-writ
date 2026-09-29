//! Std-only MCP probe server for the Kata VM validation legs
//! (`tests/kata_vm_e2e.rs`, `docs/validation/kata.md`).
//!
//! Compiled by the test via plain `rustc` (no cargo, no crates) and baked
//! into the probe image as the workload `mcp-secure-runner` wraps. Every
//! tool performs a real guest-side operation so the run produces evidence
//! about the guest's control state, not just relayed strings:
//!
//!   read_file    {path}          open read; content head + dev/ino identity
//!   create_file  {path,content?} create_new write (fs write grant evidence)
//!   chmod_666    {path}          chmod — a syscall outside the policy
//!                                allowlist, so success/errno shows whether
//!                                the guest kernel applied seccomp
//!   vm_identity  {}              guest kernel release, /proc/self/status
//!                                NoNewPrivs/Seccomp fields, virtio-fs and
//!                                securityfs state — the VM-side identity
//!                                proof (never trusted without host-side
//!                                engine/runtime evidence)
//!
//! Tool failures are MCP `result.isError=true`, not JSON-RPC errors.
//! Unknown tools get `isError=true`; unknown methods get -32601.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};

// ─── minimal JSON parser (same contract as open_path_server.rs) ────────

#[derive(Clone)]
enum J {
    Null,
    Bool(bool),
    Num(String),
    Str(String),
    // Parsed for completeness; request fields used here are never arrays.
    #[allow(dead_code)]
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
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
        Jp { s: text.as_bytes(), i: 0 }
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

fn text_result(id_raw: String, text: String, is_error: bool) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"{t}\"}}],\"isError\":{e}}}}}",
        id = id_raw,
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
/// view, and this process's own sandbox state. Read /proc/self/status —
/// the probe itself runs under Landlock+seccomp, so `Seccomp: 2` and
/// `NoNewPrivs: 1` are the in-guest mechanism state.
fn tool_vm_identity() -> String {
    let read = |p: &str| std::fs::read_to_string(p).ok().map(|s| s.trim().to_string());
    let field = |text: &str, name: &str| -> String {
        text.lines()
            .find(|l| l.starts_with(name))
            .map(|l| l.split_once(':').map(|x| x.1.trim().to_string()).unwrap_or_default())
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
    match std::net::TcpStream::connect(addr) {
        Ok(_) => format!("connect {addr} succeeded (unexpected)"),
        Err(e) => format!("connect {addr} failed: {e}"),
    }
}

fn tools_list() -> &'static str {
    "{\"tools\":[{\"name\":\"read_file\"},{\"name\":\"create_file\"},{\"name\":\"chmod_666\"},{\"name\":\"vm_identity\"},{\"name\":\"net_probe\"}]}"
}

// ─── main loop ───────────────────────────────────────────────────────

fn main() {
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
        let method = req.get("method").and_then(J::as_str).unwrap_or("").to_string();
        let id_raw = req.get("id").map(|j| j.raw()).unwrap_or_else(|| "null".into());
        let is_request = req.get("id").is_some();
        match method.as_str() {
            "initialize" => {
                writeln!(
                    stdout.lock(),
                    "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"result\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"kata-probe\",\"version\":\"0\"}}}}}}",
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
                let out = match name.as_str() {
                    "read_file" => (tool_read_file(&args), false),
                    "create_file" => (tool_create_file(&args), false),
                    "chmod_666" => (tool_chmod_666(&args), false),
                    "vm_identity" => (tool_vm_identity(), false),
                    "net_probe" => (tool_net_probe(&args), false),
                    _ => (format!("unknown tool '{name}'"), true),
                };
                writeln!(stdout.lock(), "{}", text_result(id_raw, out.0, out.1)).ok();
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
