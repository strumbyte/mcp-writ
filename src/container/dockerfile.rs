use std::fmt;

use crate::error::ContainerError;

/// Represents the original ENTRYPOINT or CMD value from a Docker image.
///
/// Docker supports both exec form (JSON array) and shell form (string).
#[derive(Clone)]
pub enum EntrypointValue {
    /// Shell form: `ENTRYPOINT command param1 param2`
    Shell(String),
    /// Exec form: `ENTRYPOINT ["executable", "param1", "param2"]`
    Exec(Vec<String>),
    /// Not set in the original image.
    None,
}

impl fmt::Debug for EntrypointValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shell(s) => write!(f, "Shell({s:?})"),
            Self::Exec(v) => write!(f, "Exec({v:?})"),
            Self::None => write!(f, "None"),
        }
    }
}

impl EntrypointValue {
    /// Serialize to a string suitable for an ENV value in a Dockerfile.
    ///
    /// - `Shell("foo bar")` → `foo bar`
    /// - `Exec(["foo", "bar"])` → `["foo","bar"]` (JSON array)
    /// - `None` → empty string
    fn to_env_value(&self) -> String {
        match self {
            Self::Shell(s) => s.clone(),
            Self::Exec(parts) => {
                let json = nojson::array(|a| {
                    for p in parts {
                        a.element(p.as_str())?;
                    }
                    Ok(())
                });
                json.to_string()
            }
            Self::None => String::new(),
        }
    }
}

/// Template for generating a secure-runner–wrapped Dockerfile.
pub struct DockerfileTemplate {
    /// Base image to wrap (e.g. `node:20-slim`).
    pub base_image: String,
    /// Path to the mcp-secure-runner binary to COPY into the image.
    pub runner_path: String,
    /// Path to the policy file to COPY into the image.
    pub policy_path: String,
    /// Original ENTRYPOINT from the base image.
    pub orig_entrypoint: EntrypointValue,
    /// Original CMD from the base image.
    pub orig_cmd: EntrypointValue,
}

impl fmt::Debug for DockerfileTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockerfileTemplate")
            .field("base_image", &self.base_image)
            .field("runner_path", &self.runner_path)
            .field("policy_path", &self.policy_path)
            .field("orig_entrypoint", &self.orig_entrypoint)
            .field("orig_cmd", &self.orig_cmd)
            .finish()
    }
}

impl DockerfileTemplate {
    /// Generate a Dockerfile that wraps the original image with mcp-secure-runner.
    pub fn generate(&self) -> Result<String, ContainerError> {
        if self.base_image.is_empty() {
            return Err(ContainerError::DockerfileGeneration(
                "base_image must not be empty".to_string(),
            ));
        }

        let entrypoint_env = self.orig_entrypoint.to_env_value();
        let cmd_env = self.orig_cmd.to_env_value();

        let mut out = String::with_capacity(512);

        // FROM
        out.push_str("FROM ");
        out.push_str(&self.base_image);
        out.push('\n');

        // COPY runner binary
        out.push_str("COPY ");
        out.push_str(&self.runner_path);
        out.push_str(" /usr/local/bin/mcp-secure-runner\n");

        // COPY policy
        out.push_str("COPY ");
        out.push_str(&self.policy_path);
        out.push_str(" /etc/mcp-secure/policy.kdl\n");

        // ENV with original entrypoint/cmd, and clear MCP_WRIT_SKIP_SANDBOX from base image
        out.push_str("ENV MCP_ORIG_ENTRYPOINT=\"");
        out.push_str(&escape_dockerfile_env(&entrypoint_env));
        out.push_str("\" MCP_ORIG_CMD=\"");
        out.push_str(&escape_dockerfile_env(&cmd_env));
        out.push_str("\" MCP_WRIT_ENV=\"\" MCP_WRIT_SERVER=\"\" MCP_WRIT_SKIP_SANDBOX=\"\" MCP_WRIT_FAIL_ON=\"\"\n");

        out.push_str("HEALTHCHECK NONE\n");

        // New ENTRYPOINT
        out.push_str("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n");

        Ok(out)
    }
}

/// Escape a value for use inside double quotes in a Dockerfile ENV instruction.
///
/// Escapes backslashes, double quotes, and dollar signs.
pub fn escape_dockerfile_env(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '$' => escaped.push_str("\\$"),
            _ => escaped.push(c),
        }
    }
    escaped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_basic_dockerfile() {
        let tmpl = DockerfileTemplate {
            base_image: "node:20-slim".to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Exec(vec!["node".to_string()]),
            orig_cmd: EntrypointValue::Exec(vec!["server.js".to_string()]),
        };
        let dockerfile = tmpl.generate().unwrap();

        assert!(dockerfile.starts_with("FROM node:20-slim\n"));
        assert!(dockerfile.contains("COPY mcp-secure-runner /usr/local/bin/mcp-secure-runner\n"));
        assert!(dockerfile.contains("COPY policy.kdl /etc/mcp-secure/policy.kdl\n"));
        assert!(dockerfile.contains("MCP_ORIG_ENTRYPOINT="));
        assert!(dockerfile.contains("MCP_ORIG_CMD="));
        assert!(dockerfile.contains("MCP_WRIT_FAIL_ON=\"\""));
        assert!(dockerfile.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"));
    }

    #[test]
    fn test_generate_with_shell_form() {
        let tmpl = DockerfileTemplate {
            base_image: "python:3.12".to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Shell("python app.py".to_string()),
            orig_cmd: EntrypointValue::None,
        };
        let dockerfile = tmpl.generate().unwrap();

        assert!(dockerfile.starts_with("FROM python:3.12\n"));
        assert!(dockerfile.contains("MCP_ORIG_ENTRYPOINT=\"python app.py\""));
        assert!(dockerfile.contains("MCP_ORIG_CMD=\"\""));
    }

    #[test]
    fn test_generate_with_exec_array_serialization() {
        let tmpl = DockerfileTemplate {
            base_image: "alpine:3.19".to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Exec(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "echo hello".to_string(),
            ]),
            orig_cmd: EntrypointValue::Exec(vec!["--verbose".to_string()]),
        };
        let dockerfile = tmpl.generate().unwrap();

        // Exec form should be JSON-serialized in ENV
        assert!(
            dockerfile.contains(r#"MCP_ORIG_ENTRYPOINT="[\"/bin/sh\",\"-c\",\"echo hello\"]""#)
        );
        assert!(dockerfile.contains(r#"MCP_ORIG_CMD="[\"--verbose\"]""#));
    }

    #[test]
    fn test_generate_with_no_entrypoint_or_cmd() {
        let tmpl = DockerfileTemplate {
            base_image: "ubuntu:24.04".to_string(),
            runner_path: "target/release/mcp-secure-runner".to_string(),
            policy_path: "config/policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::None,
            orig_cmd: EntrypointValue::None,
        };
        let dockerfile = tmpl.generate().unwrap();

        assert!(dockerfile.starts_with("FROM ubuntu:24.04\n"));
        assert!(
            dockerfile.contains(
                "COPY target/release/mcp-secure-runner /usr/local/bin/mcp-secure-runner\n"
            )
        );
        assert!(dockerfile.contains("COPY config/policy.kdl /etc/mcp-secure/policy.kdl\n"));
        assert!(dockerfile.contains("MCP_ORIG_ENTRYPOINT=\"\""));
        assert!(dockerfile.contains("MCP_ORIG_CMD=\"\""));
    }

    #[test]
    fn test_generate_empty_base_image_fails() {
        let tmpl = DockerfileTemplate {
            base_image: String::new(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::None,
            orig_cmd: EntrypointValue::None,
        };
        let result = tmpl.generate();
        assert!(result.is_err());
    }

    #[test]
    fn test_entrypoint_value_to_env_shell() {
        let val = EntrypointValue::Shell("python -m flask run".to_string());
        assert_eq!(val.to_env_value(), "python -m flask run");
    }

    #[test]
    fn test_entrypoint_value_to_env_exec() {
        let val = EntrypointValue::Exec(vec!["node".to_string(), "index.js".to_string()]);
        let env = val.to_env_value();
        // Should be a JSON array
        assert_eq!(env, r#"["node","index.js"]"#);
    }

    #[test]
    fn test_entrypoint_value_to_env_none() {
        let val = EntrypointValue::None;
        assert_eq!(val.to_env_value(), "");
    }

    #[test]
    fn test_escape_dockerfile_env_quotes() {
        let escaped = escape_dockerfile_env(r#"["hello","world"]"#);
        assert_eq!(escaped, r#"[\"hello\",\"world\"]"#);
    }

    #[test]
    fn test_escape_dockerfile_env_dollar_sign() {
        let escaped = escape_dockerfile_env("$HOME/bin:$PATH");
        assert_eq!(escaped, "\\$HOME/bin:\\$PATH");
    }

    #[test]
    fn test_dockerfile_line_count_and_structure() {
        let tmpl = DockerfileTemplate {
            base_image: "rust:1.77".to_string(),
            runner_path: "runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Shell("/start.sh".to_string()),
            orig_cmd: EntrypointValue::Exec(vec!["--port".to_string(), "8080".to_string()]),
        };
        let dockerfile = tmpl.generate().unwrap();
        let lines: Vec<&str> = dockerfile.lines().collect();

        // Exactly 6 lines: FROM, COPY runner, COPY policy, ENV, HEALTHCHECK, ENTRYPOINT
        assert_eq!(lines.len(), 6);
        assert!(lines[0].starts_with("FROM "));
        assert!(lines[1].starts_with("COPY "));
        assert!(lines[2].starts_with("COPY "));
        assert!(lines[3].starts_with("ENV "));
        assert_eq!(lines[4], "HEALTHCHECK NONE");
        assert!(lines[5].starts_with("ENTRYPOINT "));
    }
}
