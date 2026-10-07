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

/// The `NAME=""` clears baked into every generated image's ENV line —
/// every `MCP_WRIT_*` channel/control var so a value inherited from the
/// base image cannot redirect the runner's policy, audit, temp, or
/// report paths, rebind its launch id, flip its failure policy, or
/// divert it into probe mode. The launch re-sets the real values with
/// `-e` (`engine::container_run_args` clears this same set before
/// re-introducing the launch's own).
pub(crate) const CHANNEL_CLEAR_ENVS: &str = "MCP_WRIT_ENV=\"\" MCP_WRIT_SERVER=\"\" MCP_WRIT_SKIP_SANDBOX=\"\" MCP_WRIT_FAIL_ON=\"\" MCP_WRIT_POLICY_PATH=\"\" MCP_WRIT_AUDIT_DIR=\"\" MCP_WRIT_TEMP_DIR=\"\" MCP_WRIT_LAUNCH_ID=\"\" MCP_WRIT_REPORT_OUT=\"\" MCP_WRIT_PROBE_LANDLOCK_ABI=\"\"";

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
    /// Runner capability JSON recorded on the image
    /// (`MCP_WRIT_RUNNER_CAPS`) so `run-image` can tell report-capable
    /// builds from legacy ones. Empty records `""` — the legacy state.
    pub runner_caps: String,
    /// The guest contract the generated image serves — path spellings,
    /// the runner's destination, and the COPY-only emission rules a
    /// Windows image needs all come from it.
    pub guest: &'static crate::container::guest_layout::GuestLayout,
    /// Context-relative names of MSVC-redistributable DLLs to ship
    /// app-local next to the runner (Windows guest only — a PE that
    /// imports `vcruntime140.dll` fails loader lock on Server Core
    /// without it). Ignored for Linux guests.
    pub crt_dlls: Vec<String>,
}

impl fmt::Debug for DockerfileTemplate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DockerfileTemplate")
            .field("base_image", &self.base_image)
            .field("runner_path", &self.runner_path)
            .field("policy_path", &self.policy_path)
            .field("orig_entrypoint", &self.orig_entrypoint)
            .field("orig_cmd", &self.orig_cmd)
            .field("guest_os", &self.guest.guest_os.name())
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
        // `base_image` is rendered verbatim into `FROM <image>` — prove
        // it is a single Dockerfile-safe token before emission.
        crate::container::image_ref::validate_image_reference(&self.base_image)
            .map_err(ContainerError::DockerfileGeneration)?;
        match self.guest.guest_os {
            crate::execution::TargetOs::Linux => self.generate_linux(),
            crate::execution::TargetOs::Windows => self.generate_windows(),
            other => Err(ContainerError::DockerfileGeneration(format!(
                "no Dockerfile contract for guest OS '{}'",
                other.name()
            ))),
        }
    }

    /// The Linux guest variant — the existing emission shape.
    fn generate_linux(&self) -> Result<String, ContainerError> {
        let entrypoint_env = self.orig_entrypoint.to_env_value();
        let cmd_env = self.orig_cmd.to_env_value();
        let policy_dst = crate::container::guest_layout::policy_file(self.guest);

        let mut out = String::with_capacity(512);

        // FROM
        out.push_str("FROM ");
        out.push_str(&self.base_image);
        out.push('\n');

        // COPY runner binary
        out.push_str("COPY ");
        out.push_str(&self.runner_path);
        out.push(' ');
        out.push_str(self.guest.runner_path);
        out.push('\n');

        // COPY policy
        out.push_str("COPY ");
        out.push_str(&self.policy_path);
        out.push(' ');
        out.push_str(&policy_dst);
        out.push('\n');

        // ENV with original entrypoint/cmd, clear every MCP_WRIT_*
        // channel var a base image could bake in (the launch re-sets
        // the real values with -e), and record the runner's capability
        // marker.
        out.push_str("ENV MCP_ORIG_ENTRYPOINT=\"");
        out.push_str(&escape_dockerfile_env(&entrypoint_env));
        out.push_str("\" MCP_ORIG_CMD=\"");
        out.push_str(&escape_dockerfile_env(&cmd_env));
        out.push_str("\" ");
        out.push_str(CHANNEL_CLEAR_ENVS);
        out.push_str(" MCP_WRIT_RUNNER_CAPS=\"");
        out.push_str(&escape_dockerfile_env(&self.runner_caps));
        out.push_str("\"\n");

        out.push_str("HEALTHCHECK NONE\n");

        // New ENTRYPOINT
        out.push_str("ENTRYPOINT [\"");
        out.push_str(self.guest.runner_path);
        out.push_str("\"]\n");

        Ok(out)
    }

    /// The Windows guest variant. Deliberately COPY-only: a `RUN`
    /// instruction would launch a build container that must match the
    /// host's kernel build (process isolation on a newer host refuses
    /// the older image), so everything the image needs is placed by
    /// COPY/ENV/ENTRYPOINT — matching the PR-20-validated fixture
    /// Dockerfile. The `# escape=\` parser directive pins the default
    /// escape so `\\` inside an ENV value still decodes to a literal
    /// backslash; all generated paths use forward slashes so the escape
    /// character never appears in one.
    fn generate_windows(&self) -> Result<String, ContainerError> {
        let entrypoint_env = self.orig_entrypoint.to_env_value();
        let cmd_env = self.orig_cmd.to_env_value();
        let policy_dst = crate::container::guest_layout::policy_file(self.guest);

        let mut out = String::with_capacity(640);

        out.push_str("# escape=\\\n");

        // FROM
        out.push_str("FROM ");
        out.push_str(&self.base_image);
        out.push('\n');

        // COPY runner binary (JSON array form keeps the path immune to
        // whitespace rules).
        out.push_str("COPY [\"");
        out.push_str(&escape_json_string(&self.runner_path));
        out.push_str("\", \"");
        out.push_str(&escape_json_string(self.guest.runner_path));
        out.push_str("\"]\n");

        // App-local CRT — each DLL lands next to the exe.
        let runner_dir = self
            .guest
            .runner_path
            .rsplit_once('/')
            .map(|(d, _)| d)
            .unwrap_or("C:/mcp-secure");
        for dll in &self.crt_dlls {
            out.push_str("COPY [\"");
            out.push_str(&escape_json_string(dll));
            out.push_str("\", \"");
            out.push_str(&escape_json_string(runner_dir));
            out.push('/');
            out.push_str(&escape_json_string(dll));
            out.push_str("\"]\n");
        }

        // COPY policy
        out.push_str("COPY [\"");
        out.push_str(&escape_json_string(&self.policy_path));
        out.push_str("\", \"");
        out.push_str(&escape_json_string(&policy_dst));
        out.push_str("\"]\n");

        // ENV with original entrypoint/cmd, clear the channel vars the
        // launch is responsible for, and record the runner's capability
        // marker.
        out.push_str("ENV MCP_ORIG_ENTRYPOINT=\"");
        out.push_str(&escape_dockerfile_env(&entrypoint_env));
        out.push_str("\" MCP_ORIG_CMD=\"");
        out.push_str(&escape_dockerfile_env(&cmd_env));
        out.push_str("\" ");
        out.push_str(CHANNEL_CLEAR_ENVS);
        out.push_str(" MCP_WRIT_RUNNER_CAPS=\"");
        out.push_str(&escape_dockerfile_env(&self.runner_caps));
        out.push_str("\"\n");

        out.push_str("HEALTHCHECK NONE\n");

        // New ENTRYPOINT
        out.push_str("ENTRYPOINT [\"");
        out.push_str(self.guest.runner_path);
        out.push_str("\"]\n");

        Ok(out)
    }
}

/// Escape a string for use inside a JSON double-quoted string (Dockerfile
/// `COPY ["src","dst"]` array elements, `ENTRYPOINT` arrays, …).
///
/// Handles: backslash, double quote, and all control characters
/// (U+0000–U+001F).
pub fn escape_json_string(s: &str) -> String {
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
            runner_caps: "{\"v\":\"0.5.0\",\"caps\":[\"guest-report-1\"]}".to_string(),
            guest: &crate::container::guest_layout::LINUX,
            crt_dlls: vec![],
        };
        let dockerfile = tmpl.generate().unwrap();

        assert!(dockerfile.starts_with("FROM node:20-slim\n"));
        assert!(dockerfile.contains("COPY mcp-secure-runner /usr/local/bin/mcp-secure-runner\n"));
        assert!(dockerfile.contains("COPY policy.kdl /etc/mcp-secure/policy.kdl\n"));
        assert!(dockerfile.contains("MCP_ORIG_ENTRYPOINT="));
        assert!(dockerfile.contains("MCP_ORIG_CMD="));
        assert!(dockerfile.contains("MCP_WRIT_FAIL_ON=\"\""));
        assert!(dockerfile.contains(
            "MCP_WRIT_RUNNER_CAPS=\"{\\\"v\\\":\\\"0.5.0\\\",\\\"caps\\\":[\\\"guest-report-1\\\"]}\""
        ));
        assert!(dockerfile.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]\n"));
    }

    /// Every `MCP_WRIT_*` channel/control var is baked empty — a base
    /// image must not be able to inherit a value that redirects the
    /// runner's policy/audit/temp/report paths, launch id, failure
    /// policy, or probe mode.
    #[test]
    fn test_generate_clears_all_channel_envs() {
        for guest in [
            &crate::container::guest_layout::LINUX,
            &crate::container::guest_layout::WINDOWS,
        ] {
            let tmpl = DockerfileTemplate {
                base_image: "base:latest".to_string(),
                runner_path: "runner".to_string(),
                policy_path: "policy.kdl".to_string(),
                orig_entrypoint: EntrypointValue::None,
                orig_cmd: EntrypointValue::None,
                runner_caps: String::new(),
                guest,
                crt_dlls: vec![],
            };
            let df = tmpl.generate().unwrap();
            for var in [
                "MCP_WRIT_ENV",
                "MCP_WRIT_SERVER",
                "MCP_WRIT_SKIP_SANDBOX",
                "MCP_WRIT_FAIL_ON",
                "MCP_WRIT_POLICY_PATH",
                "MCP_WRIT_AUDIT_DIR",
                "MCP_WRIT_TEMP_DIR",
                "MCP_WRIT_LAUNCH_ID",
                "MCP_WRIT_REPORT_OUT",
                "MCP_WRIT_PROBE_LANDLOCK_ABI",
            ] {
                assert!(
                    df.contains(&format!("{var}=\"\"")),
                    "{} image ENV must clear {var}: {df}",
                    guest.guest_os.name()
                );
            }
        }
    }

    #[test]
    fn test_generate_with_shell_form() {
        let tmpl = DockerfileTemplate {
            base_image: "python:3.12".to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Shell("python app.py".to_string()),
            orig_cmd: EntrypointValue::None,
            runner_caps: String::new(),
            guest: &crate::container::guest_layout::LINUX,
            crt_dlls: vec![],
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
            runner_caps: String::new(),
            guest: &crate::container::guest_layout::LINUX,
            crt_dlls: vec![],
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
            runner_caps: String::new(),
            guest: &crate::container::guest_layout::LINUX,
            crt_dlls: vec![],
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
            runner_caps: String::new(),
            guest: &crate::container::guest_layout::LINUX,
            crt_dlls: vec![],
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
            runner_caps: String::new(),
            guest: &crate::container::guest_layout::LINUX,
            crt_dlls: vec![],
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

    // ── Windows guest variant ──────────────────────────────────────

    #[test]
    fn test_generate_windows_dockerfile() {
        let tmpl = DockerfileTemplate {
            base_image: "mcr.microsoft.com/windows/servercore@sha256:abc".to_string(),
            runner_path: "mcp-secure-runner.exe".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Exec(vec![
                "C:/mcp-secure/hyperv-probe.exe".to_string(),
            ]),
            orig_cmd: EntrypointValue::None,
            runner_caps: "{\"v\":\"0.1.0\",\"caps\":[\"guest-report-1\"]}".to_string(),
            guest: &crate::container::guest_layout::WINDOWS,
            crt_dlls: vec!["vcruntime140.dll".to_string()],
        };
        let df = tmpl.generate().unwrap();

        // Parser directive pinned first; the build is COPY-only — no
        // RUN so no build-time process isolation is required.
        assert!(df.starts_with("# escape=\\\n"));
        assert!(df.contains("FROM mcr.microsoft.com/windows/servercore@sha256:abc\n"));
        assert!(
            df.contains(
                "COPY [\"mcp-secure-runner.exe\", \"C:/mcp-secure/mcp-secure-runner.exe\"]"
            )
        );
        assert!(df.contains("COPY [\"vcruntime140.dll\", \"C:/mcp-secure/vcruntime140.dll\"]"));
        assert!(df.contains("COPY [\"policy.kdl\", \"C:/etc/mcp-secure/policy.kdl\"]"));
        assert!(df.contains("MCP_ORIG_ENTRYPOINT="));
        assert!(df.contains("MCP_WRIT_RUNNER_CAPS="));
        assert!(df.contains("HEALTHCHECK NONE"));
        assert!(df.contains("ENTRYPOINT [\"C:/mcp-secure/mcp-secure-runner.exe\"]\n"));
        // A Windows image must not emit a RUN or chmod — neither is
        // buildable under the kernel-mismatch rule, and the exe needs
        // no mode bits.
        assert!(!df.contains("\nRUN"), "no RUN in a windows image: {df}");
        assert!(!df.contains("chmod"), "no chmod in a windows image: {df}");
        assert!(!df.contains("/usr/local/bin"), "no linux paths: {df}");
    }

    #[test]
    fn test_generate_windows_no_crt_means_no_crt_copy() {
        let tmpl = DockerfileTemplate {
            base_image: "mcr.microsoft.com/windows/servercore:ltsc2025".to_string(),
            runner_path: "mcp-secure-runner.exe".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::None,
            orig_cmd: EntrypointValue::None,
            runner_caps: String::new(),
            guest: &crate::container::guest_layout::WINDOWS,
            crt_dlls: vec![],
        };
        let df = tmpl.generate().unwrap();
        assert!(!df.contains(".dll"), "no crt COPY lines: {df}");
    }

    #[test]
    fn test_generate_windows_env_escapes_backslash() {
        let tmpl = DockerfileTemplate {
            base_image: "base".to_string(),
            runner_path: "mcp-secure-runner.exe".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Exec(vec!["C:\\servers\\my mcp.exe".to_string()]),
            orig_cmd: EntrypointValue::None,
            runner_caps: String::new(),
            guest: &crate::container::guest_layout::WINDOWS,
            crt_dlls: vec![],
        };
        let df = tmpl.generate().unwrap();
        // A literal backslash is `\\` in the JSON payload and each of
        // those is doubled again under the pinned `\` escape, so the
        // Dockerfile text carries `\\\\`; the build-time ENV value
        // decodes back to `["C:\\servers\\my mcp.exe"]`.
        assert!(
            df.contains(r#"MCP_ORIG_ENTRYPOINT="[\"C:\\\\servers\\\\my mcp.exe\"]""#),
            "got: {df}"
        );
    }

    #[test]
    fn test_generate_unknown_guest_refused() {
        static OTHER: crate::container::guest_layout::GuestLayout =
            crate::container::guest_layout::GuestLayout {
                guest_os: crate::execution::TargetOs::Other("plan9"),
                ..crate::container::guest_layout::LINUX
            };
        let tmpl = DockerfileTemplate {
            base_image: "base".to_string(),
            runner_path: "runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::None,
            orig_cmd: EntrypointValue::None,
            runner_caps: String::new(),
            guest: &OTHER,
            crt_dlls: vec![],
        };
        let err = tmpl.generate().unwrap_err();
        assert!(err.to_string().contains("plan9"), "got: {err}");
    }
}
