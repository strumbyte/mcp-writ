//! Std-only synthetic MCP server: `read_file` opens `arguments.path`.
//! Compiled by the Linux self-test integration test via `rustc`.

use std::fs::File;
use std::io::{self, BufRead, Write};

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

fn handle_line(line: &str) -> Option<String> {
    if !line.contains("\"method\"") {
        return None;
    }
    let id = extract_id_json(line)?;
    if line.contains("\"initialize\"") {
        return Some(format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"protocolVersion":"2025-11-25","capabilities":{{"tools":{{}}}},"serverInfo":{{"name":"open-path","version":"1.0.0"}}}}}}"#
        ));
    }
    if line.contains("notifications/initialized") {
        return None;
    }
    if line.contains("tools/list") {
        return Some(format!(
            r#"{{"jsonrpc":"2.0","id":{id},"result":{{"tools":[{{"name":"read_file","description":"Open a path","inputSchema":{{"type":"object","properties":{{"path":{{"type":"string"}}}},"required":["path"]}}}}]}}}}"#
        ));
    }
    if line.contains("tools/call") {
        let path = extract_path(line).unwrap_or_default();
        return Some(open_path_response(&id, &path));
    }
    Some(format!(
        r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":-32601,"message":"Method not found"}}}}"#
    ))
}

/// Raw JSON token for `id` (number or quoted string), unchanged from the request.
fn extract_id_json(line: &str) -> Option<String> {
    let key = "\"id\":";
    let start = line.find(key)? + key.len();
    let rest = line[start..].trim_start();
    if rest.starts_with('"') {
        return take_json_string_literal(rest);
    }
    let bytes = rest.as_bytes();
    let mut i = 0;
    if bytes.first() == Some(&b'-') {
        i = 1;
    }
    let digits_start = i;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == digits_start {
        return None;
    }
    Some(rest[..i].to_string())
}

fn take_json_string_literal(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.first() != Some(&b'"') {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                i += 1;
                if i >= bytes.len() {
                    return None;
                }
                if bytes[i] == b'u' {
                    i += 1;
                    for _ in 0..4 {
                        if i >= bytes.len() || !bytes[i].is_ascii_hexdigit() {
                            return None;
                        }
                        i += 1;
                    }
                } else {
                    i += 1;
                }
            }
            b'"' => return Some(s[..=i].to_string()),
            _ => i += 1,
        }
    }
    None
}

fn extract_path(line: &str) -> Option<String> {
    let key = "\"path\":\"";
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

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

fn open_path_response(id: &str, path: &str) -> String {
    match File::open(path) {
        Ok(mut f) => {
            let mut buf = [0u8; 64];
            let n = std::io::Read::read(&mut f, &mut buf).unwrap_or(0);
            let head = json_escape(&String::from_utf8_lossy(&buf[..n]));
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"{head}"}}],"structuredContent":{{"ok":true,"n":{n},"head":"{head}"}}}}}}"#
            )
        }
        Err(e) => {
            let errno = e.raw_os_error().unwrap_or(0);
            let name = if errno == 13 {
                "EACCES"
            } else if errno == 1 {
                "EPERM"
            } else {
                "OS_ERROR"
            };
            format!(
                r#"{{"jsonrpc":"2.0","id":{id},"result":{{"content":[{{"type":"text","text":"open failed: {name} (os error {errno})"}}],"isError":true}}}}"#
            )
        }
    }
}
