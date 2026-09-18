use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::legislator::heuristics::Permission;
use crate::legislator::js_bind;
use crate::legislator::py_bind;
use crate::legislator::sinks::{self, ToolCapability};
use crate::verifier::hash::{
    argv_contains_inline_eval, first_payload_arg, first_payload_arg_index,
};

/// Interpreter family whose ELF must not be treated as MCP Capability evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpreterKind {
    Python,
    Node,
    Npx,
}

impl InterpreterKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Node => "node",
            Self::Npx => "npx",
        }
    }
}

impl std::fmt::Display for InterpreterKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How argv / an inspect path maps onto a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PayloadKind {
    /// Native binary — Inspector ELF analysis is the Capability source.
    Native,
    /// Interpreter plus a source file that Legislator should parse.
    Source {
        interpreter: InterpreterKind,
        path: PathBuf,
    },
    /// `-c` / `--eval` / `-e` / `--command`: warn, do not parse, skip ELF.
    InlineEval {
        interpreter: InterpreterKind,
        flag: String,
    },
    /// Interpreter (or inspect of an interpreter binary) without a source file.
    Unresolved { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadDiscovery {
    pub kind: PayloadKind,
}

impl PayloadDiscovery {
    pub fn skips_native_elf(&self) -> bool {
        !matches!(self.kind, PayloadKind::Native)
    }
}

/// A literal (or explicitly unbound) tool ↔ handler pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolBinding {
    pub tool_name: String,
    pub function_name: Option<String>,
    pub body: String,
    pub bound: bool,
    pub warning: Option<String>,
}

/// A same-file function used for 1-hop sink inlining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFunction {
    pub name: String,
    pub body: String,
}

/// Result of parsing a source payload (no ELF).
#[derive(Debug, Clone)]
pub struct SourceAnalysis {
    pub path: PathBuf,
    pub interpreter: InterpreterKind,
    pub tools: Vec<ToolCapability>,
    pub warnings: Vec<String>,
    pub skip_note: String,
}

/// Human-readable summary of the resolved source payload.
pub fn elf_skip_note(path: &Path) -> String {
    format!("native ELF skipped; source payload = {}", path.display())
}

/// Resolve the same payload object Verifier hashes (`first_payload_arg`).
pub fn discover_from_argv(argv: &[String]) -> PayloadDiscovery {
    if argv.is_empty() {
        return PayloadDiscovery {
            kind: PayloadKind::Unresolved {
                reason: "empty argv".into(),
            },
        };
    }

    if let Some(interpreter) = interpreter_from_command(&argv[0]) {
        if argv_contains_inline_eval(argv) {
            let flag = first_inline_eval_flag(argv).unwrap_or("-c").to_string();
            return PayloadDiscovery {
                kind: PayloadKind::InlineEval { interpreter, flag },
            };
        }
        return match first_payload_arg(argv) {
            Some(payload) => source_or_unresolved(interpreter, PathBuf::from(payload)),
            None => PayloadDiscovery {
                kind: PayloadKind::Unresolved {
                    reason: format!("{interpreter} invocation has no source payload argument"),
                },
            },
        };
    }

    let argv0 = PathBuf::from(&argv[0]);
    if let Some(interpreter) = source_kind_from_path(&argv0) {
        return PayloadDiscovery {
            kind: PayloadKind::Source {
                interpreter,
                path: argv0,
            },
        };
    }

    PayloadDiscovery {
        kind: PayloadKind::Native,
    }
}

/// Inspect takes a single path; classify script vs interpreter vs native ELF.
pub fn discover_from_path(path: &Path) -> PayloadDiscovery {
    if let Some(interpreter) = source_kind_from_path(path) {
        return PayloadDiscovery {
            kind: PayloadKind::Source {
                interpreter,
                path: path.to_path_buf(),
            },
        };
    }
    if let Some(interpreter) = interpreter_from_command(&path.to_string_lossy()) {
        return PayloadDiscovery {
            kind: PayloadKind::Unresolved {
                reason: format!(
                    "inspect target is an interpreter ({interpreter}) without a source payload"
                ),
            },
        };
    }
    if let Some(interpreter) = shebang_interpreter(path) {
        return PayloadDiscovery {
            kind: PayloadKind::Source {
                interpreter,
                path: path.to_path_buf(),
            },
        };
    }
    PayloadDiscovery {
        kind: PayloadKind::Native,
    }
}

fn source_or_unresolved(interpreter: InterpreterKind, path: PathBuf) -> PayloadDiscovery {
    if source_kind_from_path(&path).is_some() || path.is_file() {
        return PayloadDiscovery {
            kind: PayloadKind::Source { interpreter, path },
        };
    }
    PayloadDiscovery {
        kind: PayloadKind::Unresolved {
            reason: format!("no source file payload (got '{}')", path.display()),
        },
    }
}

pub fn interpreter_from_command(argv0: &str) -> Option<InterpreterKind> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let name = name
        .strip_suffix(".exe")
        .or_else(|| name.strip_suffix(".EXE"))
        .unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    if lower == "python" || lower == "python3" || lower.starts_with("python3.") {
        return Some(InterpreterKind::Python);
    }
    if lower == "pythonw" || lower == "py" || lower == "pyw" {
        return Some(InterpreterKind::Python);
    }
    if lower == "node" || lower == "nodejs" {
        return Some(InterpreterKind::Node);
    }
    if lower == "npx" {
        return Some(InterpreterKind::Npx);
    }
    None
}

pub fn source_kind_from_path(path: &Path) -> Option<InterpreterKind> {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())?;
    match ext.as_str() {
        "py" | "pyw" => Some(InterpreterKind::Python),
        "js" | "mjs" | "cjs" | "ts" | "mts" | "cts" | "jsx" | "tsx" => Some(InterpreterKind::Node),
        _ => None,
    }
}

fn shebang_interpreter(path: &Path) -> Option<InterpreterKind> {
    let mut buf = [0u8; 256];
    let n = fs::File::open(path)
        .and_then(|mut f| {
            use std::io::Read;
            f.read(&mut buf)
        })
        .ok()?;
    let head = std::str::from_utf8(&buf[..n]).ok()?;
    let first = head.lines().next()?;
    if !first.starts_with("#!") {
        return None;
    }
    let lower = first.to_ascii_lowercase();
    if lower.contains("python") {
        return Some(InterpreterKind::Python);
    }
    if lower.contains("nodejs") || lower.contains("node") {
        return Some(InterpreterKind::Node);
    }
    None
}

fn first_inline_eval_flag(argv: &[String]) -> Option<&str> {
    let end = first_payload_arg_index(argv).unwrap_or(argv.len());
    argv[..end]
        .iter()
        .map(String::as_str)
        .find(|a| matches!(*a, "-c" | "-e" | "--eval" | "--command"))
}

/// Parse a source file into per-tool Capability (fail-secure: I/O errors propagate).
pub fn analyze_source_path(path: &Path) -> io::Result<SourceAnalysis> {
    let source = fs::read_to_string(path)?;
    let interpreter = source_kind_from_path(path)
        .or_else(|| shebang_interpreter(path))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("cannot determine source language for {}", path.display()),
            )
        })?;
    Ok(analyze_source(path, interpreter, &source))
}

pub fn analyze_source(path: &Path, interpreter: InterpreterKind, source: &str) -> SourceAnalysis {
    let (bindings, functions) = match interpreter {
        InterpreterKind::Python => (
            py_bind::bind_python(source),
            py_bind::extract_functions(source),
        ),
        InterpreterKind::Node | InterpreterKind::Npx => {
            (js_bind::bind_js(source), js_bind::extract_functions(source))
        }
    };
    let mut warnings = Vec::new();
    for b in &bindings {
        if let Some(w) = &b.warning {
            warnings.push(w.clone());
        }
    }
    let tools = sinks::capabilities_from_bindings(&bindings, &functions, interpreter, source);
    SourceAnalysis {
        path: path.to_path_buf(),
        interpreter,
        tools,
        warnings,
        skip_note: elf_skip_note(path),
    }
}

pub fn format_source_human(analysis: &SourceAnalysis) -> String {
    let mut out = String::new();
    out.push_str(&analysis.skip_note);
    out.push('\n');
    if !analysis.warnings.is_empty() {
        out.push_str("\nWarnings:\n");
        for w in &analysis.warnings {
            out.push_str(&format!(
                "  - {}\n",
                crate::termutil::sanitize_for_terminal(w)
            ));
        }
    }
    out.push_str("\n=== Source Tools ===\n");
    if analysis.tools.is_empty() {
        out.push_str("  (none bound)\n");
        return out;
    }
    for tool in &analysis.tools {
        let perms = if tool.permissions.is_empty() {
            "(no proven capability)".to_string()
        } else {
            tool.permissions
                .iter()
                .map(Permission::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        };
        let bind = if tool.bound { "bound" } else { "unbound" };
        out.push_str(&format!(
            "  - {} [{bind}]: {}\n",
            crate::termutil::sanitize_for_terminal(&tool.tool_name),
            crate::termutil::sanitize_for_terminal(&perms)
        ));
        if !tool.audit_risks.is_empty() {
            out.push_str(&format!(
                "      audit_risks: {}\n",
                crate::termutil::sanitize_for_terminal(&tool.audit_risks.join(", "))
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_script_payload_matches_hash_helper() {
        let argv = vec!["python".into(), "server.py".into()];
        assert_eq!(first_payload_arg(&argv), Some("server.py"));
        let d = discover_from_argv(&argv);
        assert!(d.skips_native_elf());
        match d.kind {
            PayloadKind::Source { interpreter, path } => {
                assert_eq!(interpreter, InterpreterKind::Python);
                assert_eq!(path, PathBuf::from("server.py"));
            }
            other => panic!("expected Source, got {other:?}"),
        }
    }

    #[test]
    fn python3_and_versioned_interpreters() {
        for cmd in [
            "python3",
            "python3.12",
            "/usr/bin/python3",
            "C:\\Python\\python.exe",
            "py",
            "py.exe",
            "C:\\Windows\\py.exe",
            "pythonw",
            "pyw",
        ] {
            let argv = vec![cmd.into(), "app.py".into()];
            assert!(
                matches!(
                    discover_from_argv(&argv).kind,
                    PayloadKind::Source {
                        interpreter: InterpreterKind::Python,
                        ..
                    }
                ),
                "{cmd}"
            );
        }
        let launcher = discover_from_argv(&["py".into(), "-3".into(), "server.py".into()]);
        match launcher.kind {
            PayloadKind::Source {
                interpreter: InterpreterKind::Python,
                path,
            } => {
                assert_eq!(path, PathBuf::from("server.py"));
            }
            other => panic!("expected Source for py -3 server.py, got {other:?}"),
        }
        assert_eq!(
            first_payload_arg(&["py".into(), "-3".into(), "server.py".into()]),
            Some("server.py")
        );
    }

    #[test]
    fn node_and_npx_skip_elf() {
        let node = discover_from_argv(&["node".into(), "index.js".into()]);
        assert!(matches!(
            node.kind,
            PayloadKind::Source {
                interpreter: InterpreterKind::Node,
                ..
            }
        ));
        let npx = discover_from_argv(&["npx".into(), "@scope/pkg".into()]);
        assert!(npx.skips_native_elf());
        assert!(matches!(npx.kind, PayloadKind::Unresolved { .. }));
    }

    #[test]
    fn inline_eval_is_not_parsed() {
        for argv in [
            vec!["python".into(), "-c".into(), "print(1)".into()],
            vec!["python3".into(), "--command".into(), "print(1)".into()],
            vec!["node".into(), "--eval".into(), "1".into()],
            vec!["node".into(), "-e".into(), "1".into()],
        ] {
            let d = discover_from_argv(&argv);
            assert!(
                matches!(d.kind, PayloadKind::InlineEval { .. }),
                "{argv:?} -> {:?}",
                d.kind
            );
            assert!(d.skips_native_elf());
        }
    }

    #[test]
    fn payload_flag_after_script_is_not_inline_eval() {
        let argv = vec![
            "python".into(),
            "server.py".into(),
            "--command".into(),
            "payload".into(),
        ];
        assert!(!argv_contains_inline_eval(&argv));
        assert!(matches!(
            discover_from_argv(&argv).kind,
            PayloadKind::Source { .. }
        ));
    }

    #[test]
    fn native_binary_stays_native() {
        let d = discover_from_argv(&["/usr/local/bin/mcp-native".into()]);
        assert_eq!(d.kind, PayloadKind::Native);
        assert!(!d.skips_native_elf());
    }

    #[test]
    fn shebang_script_inspect() {
        let dir = std::env::temp_dir().join(format!(
            "mcp_writ_shebang_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("mcp-server");
        std::fs::write(&path, "#!/usr/bin/env python3\nprint(1)\n").unwrap();
        let d = discover_from_path(&path);
        assert!(matches!(
            d.kind,
            PayloadKind::Source {
                interpreter: InterpreterKind::Python,
                ..
            }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inspect_interpreter_binary_is_unresolved() {
        let d = discover_from_path(Path::new("/usr/bin/python3"));
        assert!(matches!(d.kind, PayloadKind::Unresolved { .. }));
        assert!(d.skips_native_elf());
    }

    #[test]
    fn inspect_py_extension() {
        let d = discover_from_path(Path::new("tests/fixtures/py_mcp/fastmcp_literal.py"));
        assert!(matches!(
            d.kind,
            PayloadKind::Source {
                interpreter: InterpreterKind::Python,
                ..
            }
        ));
        assert_eq!(
            elf_skip_note(Path::new("server.py")),
            "native ELF skipped; source payload = server.py"
        );
    }

    #[test]
    fn direct_script_argv0() {
        let d = discover_from_argv(&["./server.py".into()]);
        assert!(matches!(
            d.kind,
            PayloadKind::Source {
                interpreter: InterpreterKind::Python,
                ..
            }
        ));
    }
}
