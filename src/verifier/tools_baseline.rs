use std::io;
use std::path::{Path, PathBuf};

use crate::protocol::tools_list::{parse_tools_list_response, verified_tool_json};
use crate::tool_def::ToolDefinition;

/// Default baselines directory: `~/.config/mcp-writ/baselines/`
fn baselines_dir() -> Option<PathBuf> {
    dirs_path().map(|p| p.join("baselines"))
}

fn dirs_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("mcp-writ"))
    }
    #[cfg(windows)]
    {
        std::env::var_os("APPDATA").map(|h| PathBuf::from(h).join("mcp-writ"))
    }
}

/// Serialize tool definitions to a compact JSON string (no serde).
fn tools_to_json(tools: &[ToolDefinition]) -> String {
    let mut out = String::with_capacity(1024);
    out.push('[');
    for (idx, tool) in tools.iter().enumerate() {
        if idx > 0 {
            out.push(',');
        }
        out.push_str(&verified_tool_json(tool));
    }
    out.push(']');
    out
}

/// Save a tools/list baseline to `~/.config/mcp-writ/baselines/<server_name>.json`.
pub fn save_baseline(server_name: &str, tools: &[ToolDefinition]) -> io::Result<PathBuf> {
    let dir =
        baselines_dir().ok_or_else(|| io::Error::other("cannot determine baselines directory"))?;
    std::fs::create_dir_all(&dir)?;

    let filename = sanitize_filename(server_name);
    let path = dir.join(format!("{filename}.json"));
    let json = tools_to_json(tools);
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Save a tools/list baseline to a specific directory (for testing).
pub fn save_baseline_to(
    dir: &Path,
    server_name: &str,
    tools: &[ToolDefinition],
) -> io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let filename = sanitize_filename(server_name);
    let path = dir.join(format!("{filename}.json"));
    let json = tools_to_json(tools);
    std::fs::write(&path, json)?;
    Ok(path)
}

/// Load a tools/list baseline from `~/.config/mcp-writ/baselines/<server_name>.json`.
pub fn load_baseline(server_name: &str) -> io::Result<Option<Vec<ToolDefinition>>> {
    let dir = match baselines_dir() {
        Some(d) => d,
        None => return Ok(None),
    };
    load_baseline_from(&dir, server_name)
}

/// Load a tools/list baseline from a specific directory.
pub fn load_baseline_from(
    dir: &Path,
    server_name: &str,
) -> io::Result<Option<Vec<ToolDefinition>>> {
    let filename = sanitize_filename(server_name);
    let path = dir.join(format!("{filename}.json"));
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };

    // Wrap in a JSON-RPC-like envelope so we can reuse parse_tools_list_response
    let envelope = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":{content}}}}}"#);
    match parse_tools_list_response(&envelope) {
        Ok(tools) => Ok(Some(tools)),
        Err(e) => Err(io::Error::other(format!("failed to parse baseline: {e}"))),
    }
}

/// Sanitize server name for use as a filename. Lowercase ASCII letters,
/// digits, and `-` pass through, `_` escapes to `__`, and every other
/// character encodes as `_<codepoint hex>_`. Uppercase and non-ASCII
/// letters are encoded too, so `Prod` (`_50_rod`) and `prod` stay
/// distinct even on case-insensitive filesystems, and `a.b` (`a_2e_b`)
/// and `a_b` (`a__b`) cannot collide on one baseline.
fn sanitize_filename(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' {
            sanitized.push(c);
        } else if c == '_' {
            sanitized.push_str("__");
        } else {
            sanitized.push_str(&format!("_{:x}_", c as u32));
        }
    }
    if sanitized.is_empty() {
        "unnamed".to_string()
    } else {
        sanitized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_dir(label: &str) -> std::path::PathBuf {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mcp_writ_baseline_{label}_{id}_{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_save_and_load_baseline() {
        let dir = make_test_dir("save_load");
        let tools = vec![
            ToolDefinition::new("read_file", "Read a file from disk")
                .with_input_schema(r#"{"type":"object","properties":{"path":{"type":"string"}}}"#),
            ToolDefinition::new("write_file", "Write content"),
        ];

        let path = save_baseline_to(&dir, "my-server", &tools).unwrap();
        assert!(path.exists());

        let loaded = load_baseline_from(&dir, "my-server").unwrap().unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].name, "read_file");
        assert_eq!(loaded[0].description, "Read a file from disk");
        assert!(loaded[0].input_schema.is_some());
        assert_eq!(loaded[1].name, "write_file");
        assert_eq!(loaded[1].description, "Write content");
        assert!(loaded[1].input_schema.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_baseline_not_found() {
        let dir = make_test_dir("not_found");
        let result = load_baseline_from(&dir, "nonexistent").unwrap();
        assert!(result.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("my-server"), "my-server");
        assert_eq!(sanitize_filename("my server/v2"), "my_20_server_2f_v2");
        assert_eq!(sanitize_filename("a.b.c"), "a_2e_b_2e_c");
        assert_eq!(sanitize_filename("a_b"), "a__b");
        assert_eq!(sanitize_filename(""), "unnamed");
        // Spellings that differ only in sanitized characters must not map
        // to the same baseline file.
        assert_ne!(sanitize_filename("a.b"), sanitize_filename("a_b"));
        // Case-only differences must survive on case-insensitive
        // filesystems: uppercase encodes as `_<hex>_`.
        assert_eq!(sanitize_filename("Prod"), "_50_rod");
        assert_ne!(sanitize_filename("Prod"), sanitize_filename("prod"));
        assert_ne!(
            sanitize_filename("my server"),
            sanitize_filename("my_server")
        );
    }

    #[test]
    fn test_tools_to_json_escape() {
        let tools = vec![ToolDefinition::new("tool", "desc with \"quotes\"")];
        let json = tools_to_json(&tools);
        assert!(json.contains(r#"\"quotes\""#));
    }

    #[test]
    fn test_tools_to_json_roundtrip() {
        let tools = vec![
            ToolDefinition::new("tool", "A simple tool").with_input_schema(r#"{"type":"object"}"#),
        ];
        let json = tools_to_json(&tools);

        // Verify it's valid by parsing back
        let envelope = format!(r#"{{"jsonrpc":"2.0","id":1,"result":{{"tools":{json}}}}}"#);
        let parsed = parse_tools_list_response(&envelope).unwrap();
        assert_eq!(parsed[0].name, "tool");
        assert_eq!(parsed[0].description, "A simple tool");
        assert!(parsed[0].input_schema.is_some());
    }
}
