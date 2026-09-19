//! Std-only synthetic MCP server for path-resolution evidence.
//!
//! Compiled by integration tests via plain `rustc` (no cargo, no crates).
//! Every tool performs a real filesystem operation and reports the identity
//! of the object it actually reached — never just a re-normalized copy of
//! the input string.
//!
//! Tools:
//!   read_file   {path}           open read; head + handle identity
//!   create_file {path, content?} create_new write; created + parent identity
//!   ident       {path}           stat + lstat identity without open()
//!   kind        {path}           lstat file type only
//!   wait_file   {path, barrier}  wait for `barrier` to exist, then like read_file
//!   open_env    {env?}           open $env (default MCP_WRIT_FIXTURE_INTERNAL_PATH);
//!                                exercises an access the Auditor cannot see in args
//!
//! Identity fields: dev/ino (unix), volume/file_index (windows), canonical
//! (std::fs::canonicalize), kind. Tool failures are MCP result.isError=true,
//! not JSON-RPC protocol errors.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

const DEFAULT_ENV_VAR: &str = "MCP_WRIT_FIXTURE_INTERNAL_PATH";
const WAIT_BARRIER_MAX_MS: u64 = 15_000;

// ─── minimal JSON parser ─────────────────────────────────────────────────────

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

    /// Re-serialize for echoing a JSON-RPC `id` token unchanged in type.
    fn raw(&self) -> String {
        match self {
            J::Num(n) => n.clone(),
            J::Str(s) => format!("\"{}\"", json_escape(s)),
            J::Bool(b) => b.to_string(),
            J::Null => "null".to_string(),
            J::Arr(_) | J::Obj(_) => "null".to_string(),
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
            b't' => self.lit(b"true").map(|_| J::Bool(true)),
            b'f' => self.lit(b"false").map(|_| J::Bool(false)),
            b'n' => self.lit(b"null").map(|_| J::Null),
            _ => self.num(),
        }
    }

    fn lit(&mut self, w: &[u8]) -> Option<()> {
        if self.s[self.i..].starts_with(w) {
            self.i += w.len();
            Some(())
        } else {
            None
        }
    }

    fn num(&mut self) -> Option<J> {
        let start = self.i;
        while matches!(
            self.s.get(self.i),
            Some(b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E')
        ) {
            self.i += 1;
        }
        if self.i > start {
            Some(J::Num(
                String::from_utf8_lossy(&self.s[start..self.i]).into_owned(),
            ))
        } else {
            None
        }
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
        if *self.s.get(self.i)? != b'"' {
            return None;
        }
        self.i += 1;
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
                    // Multi-byte UTF-8 passthrough: `c` is the first byte of
                    // a sequence already consumed; re-emit the full sequence.
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
        self.i += 1; // consume '{'
        let mut members = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Some(J::Obj(members));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.s.get(self.i) != Some(&b':') {
                return None;
            }
            self.i += 1;
            let v = self.value()?;
            members.push((k, v));
            self.ws();
            match self.s.get(self.i)? {
                b',' => self.i += 1,
                b'}' => {
                    self.i += 1;
                    return Some(J::Obj(members));
                }
                _ => return None,
            }
        }
    }

    fn arr(&mut self) -> Option<J> {
        self.i += 1; // consume '['
        let mut elems = Vec::new();
        self.ws();
        if self.s.get(self.i) == Some(&b']') {
            self.i += 1;
            return Some(J::Arr(elems));
        }
        loop {
            let v = self.value()?;
            elems.push(v);
            self.ws();
            match self.s.get(self.i)? {
                b',' => self.i += 1,
                b']' => {
                    self.i += 1;
                    return Some(J::Arr(elems));
                }
                _ => return None,
            }
        }
    }
}

// ─── JSON output helpers ─────────────────────────────────────────────────────

fn json_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) <= 0x1F => out.push_str(&format!("\\u{:04x}", c as u32)),
            _ => out.push(c),
        }
    }
    out
}

fn json_str(s: &str) -> String {
    format!("\"{}\"", json_escape(s))
}

// ─── filesystem identity ─────────────────────────────────────────────────────

#[cfg(windows)]
mod win_ident {
    //! `GetFileInformationByHandle` — the stable std `MetadataExt` on Windows
    //! does not expose volume/file-index (unstable `windows_by_handle`), so
    //! handle-based identity uses this direct FFI call instead.
    use std::os::windows::io::RawHandle;

    /// BY_HANDLE_FILE_INFORMATION. FILETIME members are modeled as two u32
    /// fields because FILETIME is 4-byte-aligned in the Win32 layout — a
    /// Rust `u64` would force 8-byte alignment and shift every later field.
    #[repr(C)]
    pub struct ByHandleInfo {
        pub attributes: u32,
        pub creation_lo: u32,
        pub creation_hi: u32,
        pub access_lo: u32,
        pub access_hi: u32,
        pub write_lo: u32,
        pub write_hi: u32,
        pub volume_serial: u32,
        pub size_high: u32,
        pub size_low: u32,
        pub num_links: u32,
        pub index_high: u32,
        pub index_low: u32,
    }

    unsafe extern "system" {
        pub fn GetFileInformationByHandle(h: RawHandle, info: *mut ByHandleInfo) -> i32;
    }
}

#[cfg(windows)]
fn handle_identity_fields(f: &File) -> String {
    use std::os::windows::io::AsRawHandle;
    let mut info = win_ident::ByHandleInfo {
        attributes: 0,
        creation_lo: 0,
        creation_hi: 0,
        access_lo: 0,
        access_hi: 0,
        write_lo: 0,
        write_hi: 0,
        volume_serial: 0,
        size_high: 0,
        size_low: 0,
        num_links: 0,
        index_high: 0,
        index_low: 0,
    };
    // Safety: `info` is a valid BY_HANDLE_FILE_INFORMATION out-buffer and the
    // file handle is open for the duration of the call.
    let ok = unsafe {
        win_ident::GetFileInformationByHandle(f.as_raw_handle(), &mut info)
    };
    if ok == 0 {
        return "\"volume\":null,\"file_index\":null".to_string();
    }
    let index = ((info.index_high as u64) << 32) | info.index_low as u64;
    format!(
        "\"volume\":{},\"file_index\":{}",
        info.volume_serial, index
    )
}

#[cfg(unix)]
fn handle_identity_fields(f: &File) -> String {
    use std::os::unix::fs::MetadataExt;
    match f.metadata() {
        Ok(m) => format!("\"dev\":{},\"ino\":{}", m.dev(), m.ino()),
        Err(_) => "\"dev\":null,\"ino\":null".to_string(),
    }
}

#[cfg(not(any(unix, windows)))]
fn handle_identity_fields(_f: &File) -> String {
    String::new()
}

#[cfg(unix)]
fn stat_identity_fields(m: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("\"dev\":{},\"ino\":{}", m.dev(), m.ino())
}

#[cfg(windows)]
fn stat_identity_fields(m: &std::fs::Metadata) -> String {
    // `Metadata` cannot expose a handle-derived identity on stable std, so
    // stat-only objects carry their attribute mask (includes
    // FILE_ATTRIBUTE_REPARSE_POINT) plus the canonical path.
    use std::os::windows::fs::MetadataExt;
    format!("\"attrs\":{}", m.file_attributes())
}

#[cfg(not(any(unix, windows)))]
fn stat_identity_fields(_m: &std::fs::Metadata) -> String {
    String::new()
}

fn kind_str(ft: &std::fs::FileType) -> &'static str {
    if ft.is_symlink() {
        "symlink"
    } else if ft.is_dir() {
        "dir"
    } else if ft.is_file() {
        "file"
    } else {
        "other"
    }
}

fn canonical_str(path: &str) -> Option<String> {
    std::fs::canonicalize(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn canonical_field(path: &str) -> String {
    canonical_str(path)
        .map(|c| format!("\"canonical\":{}", json_str(&c)))
        .unwrap_or_else(|| "\"canonical\":null".to_string())
}

/// Fields for an open handle: canonical, kind (from `meta`), OS identity.
fn handle_fields(path: &str, f: &File, meta: &std::fs::Metadata) -> String {
    let id = handle_identity_fields(f);
    let base = format!(
        "{},\"kind\":\"{}\"",
        canonical_field(path),
        kind_str(&meta.file_type())
    );
    if id.is_empty() {
        base
    } else {
        format!("{base},{id}")
    }
}

/// Fields for stat/lstat results where no open handle exists.
fn stat_fields(path: &str, meta: &std::fs::Metadata) -> String {
    let id = stat_identity_fields(meta);
    let base = format!(
        "{},\"kind\":\"{}\"",
        canonical_field(path),
        kind_str(&meta.file_type())
    );
    if id.is_empty() {
        base
    } else {
        format!("{base},{id}")
    }
}

/// Cross-platform error label: ErrorKind covers Windows ERROR_ACCESS_DENIED
/// (5) and Unix EACCES/EPERM with one name so tests compare like-for-like.
fn errno_name(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::PermissionDenied => "EACCES".to_string(),
        io::ErrorKind::NotFound => "ENOENT".to_string(),
        io::ErrorKind::AlreadyExists => "EEXIST".to_string(),
        io::ErrorKind::TimedOut => "ETIMEDOUT".to_string(),
        _ => match e.raw_os_error() {
            Some(n) => format!("errno_{n}"),
            None => "io_error".to_string(),
        },
    }
}

fn error_result(id: &str, e: &io::Error) -> String {
    let errno = e.raw_os_error().unwrap_or(0);
    let name = errno_name(e);
    let msg = format!("open failed: {name} (os error {errno})");
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"isError":true,"content":[{{"type":"text","text":{msg}}}],"structuredContent":{{"ok":false,"errno":{errno},"error":{name_j}}}}}}}"#,
        msg = json_str(&msg),
        name_j = json_str(&name),
    )
}

fn ok_result(id: &str, head: &str, structured: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":{head}}}],"structuredContent":{{"ok":true,{structured}}}}}}}"#,
        head = json_str(head),
    )
}

// ─── tools ───────────────────────────────────────────────────────────────────

fn open_and_report(id: &str, path: &str) -> String {
    match File::open(path) {
        Ok(mut f) => {
            let mut buf = [0u8; 64];
            let n = std::io::Read::read(&mut f, &mut buf).unwrap_or(0);
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            match f.metadata() {
                Ok(meta) => {
                    let fields = handle_fields(path, &f, &meta);
                    ok_result(id, &head, &format!("{fields},\"n\":{n}"))
                }
                Err(e) => error_result(id, &e),
            }
        }
        Err(e) => error_result(id, &e),
    }
}

fn tool_create_file(id: &str, path: &str, content: Option<&str>) -> String {
    let result = OpenOptions::new().write(true).create_new(true).open(path);
    match result {
        Ok(mut f) => {
            let body = content.unwrap_or("created\n");
            if let Err(e) = f.write_all(body.as_bytes()) {
                return error_result(id, &e);
            }
            let created = match f.metadata() {
                Ok(meta) => handle_fields(path, &f, &meta),
                Err(e) => return error_result(id, &e),
            };
            // Parent directory identity: proves where the object was created,
            // not where a normalized string claims it went. A relative path
            // like `file.txt` has parent `""` — the real parent is the cwd.
            let parent_path = Path::new(path)
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            let parent_fields = parent_path
                .metadata()
                .ok()
                .map(|m| stat_fields(&parent_path.to_string_lossy(), &m))
                .unwrap_or_else(|| "\"canonical\":null".to_string());
            ok_result(
                id,
                "created",
                &format!("{created},\"parent\":{{{parent_fields}}}"),
            )
        }
        Err(e) => error_result(id, &e),
    }
}

fn tool_ident(id: &str, path: &str) -> String {
    let lstat = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) => return error_result(id, &e),
    };
    let lstat_fields = stat_fields(path, &lstat);
    let stat_out = match std::fs::metadata(path) {
        Ok(m) => stat_fields(path, &m),
        Err(e) if e.kind() == io::ErrorKind::NotFound => "null".to_string(),
        Err(e) => return error_result(id, &e),
    };
    let structured = if stat_out == "null" {
        format!("\"lstat\":{{{lstat_fields}}},\"stat\":null")
    } else {
        format!("\"lstat\":{{{lstat_fields}}},\"stat\":{{{stat_out}}}")
    };
    ok_result(id, "ident", &structured)
}

fn tool_kind(id: &str, path: &str) -> String {
    match std::fs::symlink_metadata(path) {
        Ok(m) => ok_result(
            id,
            kind_str(&m.file_type()),
            &format!("\"kind\":\"{}\"", kind_str(&m.file_type())),
        ),
        Err(e) => error_result(id, &e),
    }
}

fn tool_wait_file(id: &str, path: &str, barrier: &str) -> String {
    let start = std::time::Instant::now();
    while !Path::new(barrier).exists() {
        if start.elapsed().as_millis() as u64 > WAIT_BARRIER_MAX_MS {
            let e = io::Error::new(io::ErrorKind::TimedOut, "barrier wait timed out");
            return error_result(id, &e);
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    open_and_report(id, path)
}

fn tool_open_env(id: &str, env_name: &str) -> String {
    match std::env::var(env_name) {
        Ok(path) => {
            let inner = open_and_report(id, &path);
            // Attach which env var was used so the evidence is complete.
            inner.replacen(
                "\"ok\":true,",
                &format!("\"ok\":true,\"env_path\":{},", json_str(&path)),
                1,
            )
        }
        Err(_) => {
            let e = io::Error::new(
                io::ErrorKind::NotFound,
                format!("env var {env_name} not set"),
            );
            error_result(id, &e)
        }
    }
}

// ─── dispatch ────────────────────────────────────────────────────────────────

const TOOLS_JSON: &str = concat!(
    r#"{"name":"read_file","description":"Open a path and report handle identity","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},"#,
    r#"{"name":"create_file","description":"Create a file and report created+parent identity","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path"]}},"#,
    r#"{"name":"ident","description":"Report stat/lstat identity without open","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},"#,
    r#"{"name":"kind","description":"Report lstat file type","inputSchema":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"]}},"#,
    r#"{"name":"wait_file","description":"Wait for barrier file then open path","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"barrier":{"type":"string"}},"required":["path","barrier"]}},"#,
    r#"{"name":"open_env","description":"Open path from an env var (server-internal access)","inputSchema":{"type":"object","properties":{"env":{"type":"string"}}}}"#,
);

fn handle_line(line: &str) -> Option<String> {
    let mut p = Jp::new(line);
    let v = p.value()?;
    let method = v.get("method")?.as_str()?;
    match method {
        "initialize" => {
            let id = v.get("id")?.raw();
            Some(format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"protocolVersion":"2025-11-25","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"open-path","version":"1.0.0"}}}}}}"#
            ))
        }
        "notifications/initialized" => None,
        "tools/list" => {
            let id = v.get("id")?.raw();
            Some(format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"tools":[{TOOLS_JSON}]}}}}"#
            ))
        }
        "tools/call" => {
            let id = v.get("id")?.raw();
            let params = v.get("params");
            let name = params.and_then(|p| p.get("name")).and_then(J::as_str);
            let args = params.and_then(|p| p.get("arguments"));
            let arg_str = |key: &str| args.and_then(|a| a.get(key)).and_then(J::as_str);
            match name {
                Some("read_file") => Some(open_and_report(&id, arg_str("path").unwrap_or(""))),
                Some("create_file") => Some(tool_create_file(
                    &id,
                    arg_str("path").unwrap_or(""),
                    arg_str("content"),
                )),
                Some("ident") => Some(tool_ident(&id, arg_str("path").unwrap_or(""))),
                Some("kind") => Some(tool_kind(&id, arg_str("path").unwrap_or(""))),
                Some("wait_file") => Some(tool_wait_file(
                    &id,
                    arg_str("path").unwrap_or(""),
                    arg_str("barrier").unwrap_or(""),
                )),
                Some("open_env") => Some(tool_open_env(
                    &id,
                    arg_str("env").unwrap_or(DEFAULT_ENV_VAR),
                )),
                _ => Some(format!(
                    r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32602,"message":"unknown or malformed tool call"}}}}"#
                )),
            }
        }
        _ => v.get("id").map(|id| {
            format!(
                r#"{{"jsonrpc":"2.0","id":{},"error":{{"code":-32601,"message":"Method not found"}}}}"#,
                id.raw()
            )
        }),
    }
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    for line in stdin.lock().lines() {
        let Ok(line) = line else {
            continue;
        };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(response) = handle_line(line) {
            let _ = writeln!(stdout, "{response}");
            let _ = stdout.flush();
        }
    }
}
