use std::path::Path;

use crate::container::elf_magic::looks_like_elf;
use crate::error::ContainerError;

/// Detected runtime type for a command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeType {
    NodeJs,
    Python,
    Native,
    Unknown,
}

impl RuntimeType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::NodeJs => "nodejs",
            Self::Python => "python",
            Self::Native => "native",
            Self::Unknown => "unknown",
        }
    }
}

/// Result of runtime detection: the runtime type, recommended base image,
/// and the original command.
#[derive(Debug, Clone)]
pub struct RuntimeInfo {
    pub runtime_type: RuntimeType,
    pub base_image: String,
    pub command: Vec<String>,
}

/// Detect the runtime type from a command and select an appropriate base image.
///
/// When `base_image_override` is `Some`, the provided image is used directly
/// and runtime detection is skipped (the type is set to `Unknown`).
///
/// When `None`, the first element of `command` is analyzed:
/// - `npx` / `node` → `NodeJs` with `node:22-slim`
/// - `python` / `python3` → `Python` with `python:3.13-slim`
/// - An existing file with ELF magic bytes → `Native` with `debian:bookworm-slim`
/// - Otherwise → error requesting `--base-image`
pub fn detect_runtime(
    command: &[String],
    base_image_override: Option<&str>,
) -> Result<RuntimeInfo, ContainerError> {
    let cmd_vec = command.to_vec();

    // If an explicit base image is provided, skip detection entirely.
    if let Some(image) = base_image_override {
        return Ok(RuntimeInfo {
            runtime_type: RuntimeType::Unknown,
            base_image: image.to_string(),
            command: cmd_vec,
        });
    }

    let first = command
        .first()
        .ok_or_else(|| ContainerError::RuntimeDetect("empty command; nothing to detect".into()))?;

    // Extract the basename to handle full paths like /usr/bin/node
    let basename = Path::new(first.as_str())
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(first.as_str());

    match basename {
        "npx" | "node" => Ok(RuntimeInfo {
            runtime_type: RuntimeType::NodeJs,
            base_image: "node:22-slim".to_string(),
            command: cmd_vec,
        }),
        "python" | "python3" => Ok(RuntimeInfo {
            runtime_type: RuntimeType::Python,
            base_image: "python:3.13-slim".to_string(),
            command: cmd_vec,
        }),
        _ => {
            // Check whether the command points to an ELF binary on disk.
            if looks_like_elf(Path::new(first)) {
                Ok(RuntimeInfo {
                    runtime_type: RuntimeType::Native,
                    base_image: "debian:bookworm-slim".to_string(),
                    command: cmd_vec,
                })
            } else {
                Err(ContainerError::RuntimeDetect(format!(
                    "cannot detect runtime for command '{}'; use --base-image to specify explicitly",
                    first,
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(val: &str) -> String {
        val.to_string()
    }

    // ── Node.js detection ───────────────────────────────────────

    #[test]
    fn test_detect_node_npx() {
        let cmd = vec![s("npx"), s("@modelcontextprotocol/server-filesystem")];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::NodeJs);
        assert_eq!(info.base_image, "node:22-slim");
        assert_eq!(info.command, cmd);
    }

    #[test]
    fn test_detect_node_bare() {
        let cmd = vec![s("node"), s("server.js")];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::NodeJs);
        assert_eq!(info.base_image, "node:22-slim");
    }

    #[test]
    fn test_detect_node_full_path() {
        let cmd = vec![s("/usr/local/bin/node"), s("app.js")];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::NodeJs);
        assert_eq!(info.base_image, "node:22-slim");
    }

    #[test]
    fn test_detect_npx_full_path() {
        let cmd = vec![s("/usr/bin/npx"), s("some-package")];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::NodeJs);
    }

    // ── Python detection ────────────────────────────────────────

    #[test]
    fn test_detect_python() {
        let cmd = vec![s("python"), s("-m"), s("my_server")];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::Python);
        assert_eq!(info.base_image, "python:3.13-slim");
    }

    #[test]
    fn test_detect_python3() {
        let cmd = vec![s("python3"), s("server.py")];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::Python);
        assert_eq!(info.base_image, "python:3.13-slim");
    }

    #[test]
    fn test_detect_python_full_path() {
        let cmd = vec![s("/usr/bin/python3"), s("app.py")];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::Python);
    }

    // ── Native (ELF) detection ──────────────────────────────────

    #[test]
    fn test_detect_native_elf() {
        let dir = std::env::temp_dir()
            .join("mcp_writ_rt_test")
            .join(format!("elf_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin_path = dir.join("fake_elf");
        // Write a minimal ELF-like file (just the magic + padding)
        let mut data = vec![0x7f, b'E', b'L', b'F'];
        data.extend_from_slice(&[0u8; 60]); // padding
        std::fs::write(&bin_path, &data).unwrap();

        let cmd = vec![bin_path.to_string_lossy().to_string()];
        let info = detect_runtime(&cmd, None).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::Native);
        assert_eq!(info.base_image, "debian:bookworm-slim");
    }

    // ── Unknown / error cases ───────────────────────────────────

    #[test]
    fn test_detect_unknown_errors() {
        let cmd = vec![s("some-random-binary")];
        let err = detect_runtime(&cmd, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("cannot detect runtime"));
        assert!(msg.contains("--base-image"));
    }

    #[test]
    fn test_detect_empty_command_errors() {
        let cmd: Vec<String> = vec![];
        let err = detect_runtime(&cmd, None).unwrap_err();
        assert!(err.to_string().contains("empty command"));
    }

    // ── --base-image override ───────────────────────────────────

    #[test]
    fn test_base_image_override_skips_detection() {
        let cmd = vec![s("some-random-binary")];
        let info = detect_runtime(&cmd, Some("custom:latest")).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::Unknown);
        assert_eq!(info.base_image, "custom:latest");
        assert_eq!(info.command, cmd);
    }

    #[test]
    fn test_base_image_override_with_known_command() {
        // Even for known commands, explicit override takes precedence
        let cmd = vec![s("node"), s("app.js")];
        let info = detect_runtime(&cmd, Some("mynode:18")).unwrap();
        assert_eq!(info.runtime_type, RuntimeType::Unknown);
        assert_eq!(info.base_image, "mynode:18");
    }

    // ── looks_like_elf helper ───────────────────────────────────

    #[test]
    fn test_looks_like_elf_nonexistent_file() {
        assert!(!looks_like_elf(Path::new("/nonexistent/path/to/binary")));
    }

    #[test]
    fn test_looks_like_elf_text_file() {
        let dir = std::env::temp_dir()
            .join("mcp_writ_rt_test")
            .join(format!("text_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("script.sh");
        std::fs::write(&path, "#!/bin/bash\necho hello").unwrap();
        assert!(!looks_like_elf(&path));
    }

    #[test]
    fn test_looks_like_elf_too_short() {
        let dir = std::env::temp_dir()
            .join("mcp_writ_rt_test")
            .join(format!("short_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("tiny");
        std::fs::write(&path, [0x7f, b'E']).unwrap(); // only 2 bytes
        assert!(!looks_like_elf(&path));
    }

    // ── RuntimeType::as_str ─────────────────────────────────────

    #[test]
    fn test_runtime_type_as_str() {
        assert_eq!(RuntimeType::NodeJs.as_str(), "nodejs");
        assert_eq!(RuntimeType::Python.as_str(), "python");
        assert_eq!(RuntimeType::Native.as_str(), "native");
        assert_eq!(RuntimeType::Unknown.as_str(), "unknown");
    }
}
