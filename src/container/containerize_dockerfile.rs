use crate::container::dockerfile::escape_dockerfile_env;
use crate::container::runtime_detect::RuntimeType;
use crate::error::ContainerError;

/// Template for generating a Dockerfile that containerizes a non-container MCP server.
///
/// Unlike [`DockerfileTemplate`](super::dockerfile::DockerfileTemplate) (which wraps an
/// *existing* container image), this template creates a fresh image from a base OS/runtime
/// image and copies the user's MCP server files into it.
#[derive(Debug, Clone)]
pub struct ContainerizeDockerfileTemplate {
    /// Detected (or overridden) runtime type.
    pub runtime_type: RuntimeType,
    /// Base image to use (e.g. `node:20-slim`, `python:3.12-slim`).
    pub base_image: String,
    /// Path to the mcp-secure-runner binary in the build context.
    pub runner_path: String,
    /// Path to the KDL policy file in the build context.
    pub policy_path: String,
    /// The MCP server command and its arguments (e.g. `["npx", "@mcp/server"]`).
    pub command: Vec<String>,
    /// Optional extra files/dirs to COPY into the image (relative to build context).
    pub extra_copies: Vec<CopyEntry>,
}

/// A single COPY instruction entry.
#[derive(Debug, Clone)]
pub struct CopyEntry {
    /// Source path (relative to the build context).
    pub src: String,
    /// Destination path inside the container.
    pub dst: String,
}

/// Working directory inside the container for user app files.
const WORKDIR: &str = "/app";
/// Destination for the runner binary inside the container.
const RUNNER_DST: &str = "/usr/local/bin/mcp-secure-runner";
/// Destination for the policy file inside the container.
const POLICY_DST: &str = "/etc/mcp-secure/policy.kdl";

impl ContainerizeDockerfileTemplate {
    /// Generate a Dockerfile string for containerizing the MCP server.
    pub fn generate(&self) -> Result<String, ContainerError> {
        if self.base_image.is_empty() {
            return Err(ContainerError::DockerfileGeneration(
                "base_image must not be empty".to_string(),
            ));
        }
        if self.command.is_empty() {
            return Err(ContainerError::DockerfileGeneration(
                "command must not be empty".to_string(),
            ));
        }

        let mut out = String::with_capacity(512);

        // FROM
        out.push_str("FROM ");
        out.push_str(&self.base_image);
        out.push('\n');

        // WORKDIR
        out.push_str("WORKDIR ");
        out.push_str(WORKDIR);
        out.push('\n');

        // COPY runner binary + chmod (JSON array form for safe paths)
        out.push_str("COPY [\"");
        out.push_str(&escape_json_string(&self.runner_path));
        out.push_str("\", \"");
        out.push_str(&escape_json_string(RUNNER_DST));
        out.push_str("\"]\n");
        out.push_str("RUN chmod +x ");
        out.push_str(RUNNER_DST);
        out.push('\n');

        // COPY policy (JSON array form)
        out.push_str("COPY [\"");
        out.push_str(&escape_json_string(&self.policy_path));
        out.push_str("\", \"");
        out.push_str(&escape_json_string(POLICY_DST));
        out.push_str("\"]\n");

        // Extra COPY entries (JSON array form)
        for entry in &self.extra_copies {
            out.push_str("COPY [\"");
            out.push_str(&escape_json_string(&entry.src));
            out.push_str("\", \"");
            out.push_str(&escape_json_string(&entry.dst));
            out.push_str("\"]\n");
        }

        // ENV: store original command for mcp-secure-runner
        let cmd_json = command_to_json_array(&self.command);
        out.push_str("ENV MCP_ORIG_CMD=\"");
        out.push_str(&escape_dockerfile_env(&cmd_json));
        out.push_str("\" MCP_WRIT_ENV=\"\" MCP_WRIT_SERVER=\"\" MCP_WRIT_SKIP_SANDBOX=\"\" MCP_WRIT_FAIL_ON=\"\"\n");
        out.push_str("HEALTHCHECK NONE\n");

        // ENTRYPOINT: mcp-secure-runner
        out.push_str("ENTRYPOINT [\"");
        out.push_str(RUNNER_DST);
        out.push_str("\"]\n");

        Ok(out)
    }
}

/// Escape a string for use inside a JSON double-quoted string.
///
/// Handles: backslash, double quote, and all control characters (U+0000–U+001F).
fn escape_json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                // \u00XX for other control characters
                let code = c as u32;
                out.push_str(&format!("\\u{code:04x}"));
            }
            _ => out.push(c),
        }
    }
    out
}

/// Serialize a command slice to a JSON array string without serde.
fn command_to_json_array(cmd: &[String]) -> String {
    let mut out = String::from("[");
    for (i, s) in cmd.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&escape_json_string(s));
        out.push('"');
    }
    out.push(']');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpl(rt: RuntimeType, base: &str, cmd: &[&str]) -> ContainerizeDockerfileTemplate {
        ContainerizeDockerfileTemplate {
            runtime_type: rt,
            base_image: base.to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            command: cmd.iter().map(|s| s.to_string()).collect(),
            extra_copies: vec![],
        }
    }

    // ── Node.js ────────────────────────────────────────────────────────

    #[test]
    fn test_nodejs_dockerfile() {
        let t = tmpl(
            RuntimeType::NodeJs,
            "node:20-slim",
            &["npx", "@modelcontextprotocol/server-filesystem"],
        );
        let df = t.generate().unwrap();

        assert!(df.starts_with("FROM node:20-slim\n"));
        assert!(df.contains("WORKDIR /app\n"));
        assert!(df.contains(r#"COPY ["mcp-secure-runner", "/usr/local/bin/mcp-secure-runner"]"#));
        assert!(df.contains("RUN chmod +x /usr/local/bin/mcp-secure-runner\n"));
        assert!(df.contains(r#"COPY ["policy.kdl", "/etc/mcp-secure/policy.kdl"]"#));
        assert!(df.contains("MCP_ORIG_CMD="));
        assert!(df.contains("MCP_WRIT_FAIL_ON=\"\""));
        assert!(df.contains("npx"));
        assert!(df.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"));
    }

    // ── Python ─────────────────────────────────────────────────────────

    #[test]
    fn test_python_dockerfile() {
        let t = tmpl(
            RuntimeType::Python,
            "python:3.12-slim",
            &["python", "-m", "my_mcp_server"],
        );
        let df = t.generate().unwrap();

        assert!(df.starts_with("FROM python:3.12-slim\n"));
        assert!(df.contains("WORKDIR /app\n"));
        assert!(df.contains(r#"COPY ["mcp-secure-runner", "/usr/local/bin/mcp-secure-runner"]"#));
        assert!(df.contains(r#"COPY ["policy.kdl", "/etc/mcp-secure/policy.kdl"]"#));
        assert!(df.contains("python"));
        assert!(df.contains("my_mcp_server"));
        assert!(df.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"));
    }

    // ── Native ─────────────────────────────────────────────────────────

    #[test]
    fn test_native_dockerfile() {
        let t = tmpl(
            RuntimeType::Native,
            "debian:bookworm-slim",
            &["./my-server", "--port", "8080"],
        );
        let df = t.generate().unwrap();

        assert!(df.starts_with("FROM debian:bookworm-slim\n"));
        assert!(df.contains("WORKDIR /app\n"));
        assert!(df.contains(r#"COPY ["mcp-secure-runner", "/usr/local/bin/mcp-secure-runner"]"#));
        assert!(df.contains(r#"COPY ["policy.kdl", "/etc/mcp-secure/policy.kdl"]"#));
        assert!(df.contains("my-server"));
        assert!(df.contains("8080"));
    }

    // ── Unknown (--base-image override) ────────────────────────────────

    #[test]
    fn test_unknown_runtime_with_custom_base() {
        let t = tmpl(
            RuntimeType::Unknown,
            "custom-runtime:latest",
            &["my-binary"],
        );
        let df = t.generate().unwrap();

        assert!(df.starts_with("FROM custom-runtime:latest\n"));
        assert!(df.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"));
    }

    // ── Extra COPY entries ─────────────────────────────────────────────

    #[test]
    fn test_extra_copies() {
        let mut t = tmpl(RuntimeType::NodeJs, "node:20-slim", &["node", "server.js"]);
        t.extra_copies = vec![
            CopyEntry {
                src: "package.json".to_string(),
                dst: "/app/package.json".to_string(),
            },
            CopyEntry {
                src: "server.js".to_string(),
                dst: "/app/server.js".to_string(),
            },
        ];
        let df = t.generate().unwrap();

        assert!(df.contains(r#"COPY ["package.json", "/app/package.json"]"#));
        assert!(df.contains(r#"COPY ["server.js", "/app/server.js"]"#));
    }

    // ── Error cases ────────────────────────────────────────────────────

    #[test]
    fn test_empty_base_image_fails() {
        let t = tmpl(RuntimeType::NodeJs, "", &["node", "server.js"]);
        let err = t.generate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("base_image"));
    }

    #[test]
    fn test_empty_command_fails() {
        let t = tmpl(RuntimeType::NodeJs, "node:20-slim", &[]);
        let err = t.generate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("command"));
    }

    // ── Dockerfile structure ───────────────────────────────────────────

    #[test]
    fn test_line_structure_no_extras() {
        let t = tmpl(
            RuntimeType::Python,
            "python:3.12-slim",
            &["python", "app.py"],
        );
        let df = t.generate().unwrap();
        let lines: Vec<&str> = df.lines().collect();

        // FROM, WORKDIR, COPY runner, RUN chmod, COPY policy, ENV, HEALTHCHECK, ENTRYPOINT = 8 lines
        assert_eq!(lines.len(), 8, "unexpected line count: {df}");
        assert!(lines[0].starts_with("FROM "));
        assert!(lines[1].starts_with("WORKDIR "));
        assert!(lines[2].starts_with("COPY ")); // runner
        assert!(lines[3].starts_with("RUN chmod"));
        assert!(lines[4].starts_with("COPY ")); // policy
        assert!(lines[5].starts_with("ENV "));
        assert_eq!(lines[6], "HEALTHCHECK NONE");
        assert!(lines[7].starts_with("ENTRYPOINT "));
    }

    #[test]
    fn test_line_structure_with_extras() {
        let mut t = tmpl(RuntimeType::Native, "debian:bookworm-slim", &["./server"]);
        t.extra_copies = vec![CopyEntry {
            src: "server".to_string(),
            dst: "/app/server".to_string(),
        }];
        let df = t.generate().unwrap();
        let lines: Vec<&str> = df.lines().collect();

        // FROM, WORKDIR, COPY runner, RUN chmod, COPY policy, COPY extra, ENV, HEALTHCHECK, ENTRYPOINT = 9
        assert_eq!(lines.len(), 9, "unexpected line count: {df}");
    }

    // ── Command serialization ──────────────────────────────────────────

    #[test]
    fn test_command_to_json_single() {
        let cmd = vec!["node".to_string()];
        assert_eq!(command_to_json_array(&cmd), r#"["node"]"#);
    }

    #[test]
    fn test_command_to_json_multiple() {
        let cmd = vec!["python".to_string(), "-m".to_string(), "server".to_string()];
        assert_eq!(command_to_json_array(&cmd), r#"["python","-m","server"]"#);
    }

    #[test]
    fn test_command_to_json_with_special_chars() {
        let cmd = vec![r#"echo "hello""#.to_string()];
        assert_eq!(command_to_json_array(&cmd), r#"["echo \"hello\""]"#);
    }

    #[test]
    fn test_command_to_json_with_backslash() {
        let cmd = vec![r"path\to\file".to_string()];
        assert_eq!(command_to_json_array(&cmd), r#"["path\\to\\file"]"#);
    }

    // ── ENV escaping in output ─────────────────────────────────────────

    #[test]
    fn test_env_cmd_is_escaped() {
        let t = tmpl(RuntimeType::NodeJs, "node:20-slim", &["node", "server.js"]);
        let df = t.generate().unwrap();

        // The JSON array gets escaped for Dockerfile ENV double-quote context
        // ["node","server.js"] → [\"node\",\"server.js\"]
        assert!(df.contains(r#"MCP_ORIG_CMD="[\"node\",\"server.js\"]""#));
    }

    #[test]
    fn test_dollar_sign_in_command_escaped() {
        let t = tmpl(
            RuntimeType::Python,
            "python:3.12-slim",
            &["python", "$HOME/server.py"],
        );
        let df = t.generate().unwrap();

        // $ should be escaped as \$ inside Dockerfile ENV
        assert!(df.contains(r"\$HOME"));
    }

    // ── COPY path injection prevention ───────────────────────────────

    #[test]
    fn test_copy_json_array_form_with_spaces() {
        let mut t = tmpl(RuntimeType::NodeJs, "node:20-slim", &["node", "server.js"]);
        t.extra_copies = vec![CopyEntry {
            src: "my file.js".to_string(),
            dst: "/app/my file.js".to_string(),
        }];
        let df = t.generate().unwrap();

        // JSON array form correctly handles spaces
        assert!(df.contains(r#"COPY ["my file.js", "/app/my file.js"]"#));
    }

    #[test]
    fn test_copy_json_array_form_with_quotes() {
        let mut t = tmpl(RuntimeType::NodeJs, "node:20-slim", &["node", "server.js"]);
        t.extra_copies = vec![CopyEntry {
            src: r#"file"name.js"#.to_string(),
            dst: r#"/app/file"name.js"#.to_string(),
        }];
        let df = t.generate().unwrap();

        // Quotes in paths must be escaped in JSON form
        assert!(df.contains(r#"COPY ["file\"name.js", "/app/file\"name.js"]"#));
    }

    // ── JSON control character escaping ──────────────────────────────

    #[test]
    fn test_escape_json_string_control_chars() {
        assert_eq!(escape_json_string("hello\nworld"), r"hello\nworld");
        assert_eq!(escape_json_string("tab\there"), r"tab\there");
        assert_eq!(escape_json_string("cr\rhere"), r"cr\rhere");
    }

    #[test]
    fn test_escape_json_string_null_byte() {
        assert_eq!(escape_json_string("a\0b"), r"a\u0000b");
    }

    #[test]
    fn test_command_to_json_with_control_chars() {
        let cmd = vec!["line1\nline2".to_string()];
        assert_eq!(command_to_json_array(&cmd), r#"["line1\nline2"]"#);
    }
}
