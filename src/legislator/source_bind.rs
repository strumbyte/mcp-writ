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
pub fn native_skip_note(path: &Path) -> String {
    format!(
        "native analysis skipped; source payload = {}",
        path.display()
    )
}

/// One `<type> "<sha256>" target="<path>"` line's data for the draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashLine {
    /// Absolute path the Verifier hashes (`sha256:<hex>` covers the file at
    /// this path on the generating host).
    pub target: String,
    /// `sha256:<hex>` digest of the target file.
    pub hash_value: String,
}

/// Launch-target hashes a generated draft can pin.
///
/// Mirrors the runtime binding contract in
/// `crate::verifier::hash::bind_launched_workload`: `binary-hash` pins the
/// resolved `argv[0]` image, `entrypoint-hash` pins a source-file payload.
/// Fields are `None` when the corresponding target cannot be hashed on this
/// host; `unbound_reasons` then carries the human-readable causes the draft
/// emits as one `// REVIEW:` comment each.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadHashes {
    /// `binary-hash` line data: the resolved `argv[0]` image.
    pub binary: Option<HashLine>,
    /// `entrypoint-hash` line data: the source payload file.
    pub entrypoint: Option<HashLine>,
    /// Why launch targets could not be pinned (empty when fully bound).
    pub unbound_reasons: Vec<String>,
}

impl WorkloadHashes {
    /// True when the draft should emit a `server` block for this workload —
    /// at least one hash line or an unbound reason to record.
    pub fn has_content(&self) -> bool {
        self.binary.is_some() || self.entrypoint.is_some() || !self.unbound_reasons.is_empty()
    }
}

/// Compute the draft's launch-target hashes from argv and its payload
/// discovery. Hash values are this host's digests; the REVIEW comments the
/// generator emits with them tell the operator to recompute on the
/// deployment host.
pub fn workload_hashes(argv: &[String], discovery: &PayloadDiscovery) -> WorkloadHashes {
    let mut out = WorkloadHashes::default();
    let mut reasons: Vec<String> = Vec::new();

    match argv.first() {
        Some(argv0) => match crate::verifier::hash::resolve_command_path(argv0) {
            Ok(resolved) => match crate::verifier::hash::hash_file(&resolved) {
                Ok(hash_value) => {
                    out.binary = Some(HashLine {
                        target: draft_target(&resolved),
                        hash_value,
                    });
                }
                Err(e) => reasons.push(format!(
                    "binary-hash not emitted: cannot hash '{}': {e}",
                    resolved.display()
                )),
            },
            Err(e) => reasons.push(format!(
                "binary-hash not emitted: cannot resolve '{argv0}': {e}"
            )),
        },
        None => reasons.push("binary-hash not emitted: empty argv".to_string()),
    }

    if let Some(reason) = argv.first().and_then(|a| delegating_launcher_reason(a)) {
        reasons.push(reason);
    }

    // The runtime refuses inline eval no matter which argv[0] carries the
    // flag; discovery only classifies known interpreters as InlineEval, so a
    // `sh -c ...` / `perl -e ...` launch still needs the reason recorded or
    // the draft would look fully bound yet always fail at `run`.
    if !matches!(discovery.kind, PayloadKind::InlineEval { .. }) && argv_contains_inline_eval(argv)
    {
        reasons.push(
            "entrypoint-hash not emitted: inline evaluation flags \
             (-c/-e/--eval/--command) are not a hash-bindable workload — \
             'run' refuses this launch"
                .to_string(),
        );
    }

    // Direct execution (`./server.py`, or a PATH-installed entry script)
    // honors the payload's shebang: the kernel picks the interpreter, which
    // no hash entry pins. Indirect forms (`python3 server.py`) pin the
    // interpreter already, so the shebang is inert there and must not draw
    // a caveat.
    if let PayloadKind::Source { path, .. } = &discovery.kind
        && argv.first().is_some_and(|a| direct_script_exec(a, path))
        && let Some(shebang) = shebang_line(path)
        && let Some(cmd) = shebang.split_whitespace().next()
    {
        if Path::new(cmd).file_name().and_then(|s| s.to_str()) == Some("env") {
            reasons.push(
                "entrypoint-hash pins the script, but its env shebang selects the \
                 interpreter via PATH at run time — that interpreter is not pinned; \
                 invoke the interpreter on the script directly to bind it"
                    .to_string(),
            );
        } else {
            reasons.push(format!(
                "entrypoint-hash pins the script, but its shebang interpreter \
                 '{cmd}' is selected by the kernel at run time — that interpreter \
                 is not pinned; invoke the interpreter on the script directly \
                 to bind it"
            ));
        }
    }

    match &discovery.kind {
        PayloadKind::Native => {}
        PayloadKind::Source { path, .. } => {
            let resolved = resolve_payload_path(path);
            match resolved.and_then(|p| {
                crate::verifier::hash::hash_file(&p)
                    .ok()
                    .map(|hash_value| (p, hash_value))
            }) {
                Some((p, hash_value)) => {
                    out.entrypoint = Some(HashLine {
                        target: draft_target(&p),
                        hash_value,
                    });
                }
                None => reasons.push(format!(
                    "entrypoint-hash not emitted: cannot hash payload '{}'",
                    path.display()
                )),
            }
        }
        PayloadKind::InlineEval { interpreter, flag } => reasons.push(format!(
            "entrypoint-hash not emitted: {interpreter} {flag} is inline evaluation, \
             which is not a hash-bindable workload"
        )),
        PayloadKind::Unresolved { reason } => {
            reasons.push(format!("entrypoint-hash not emitted: {reason}"))
        }
    }

    out.unbound_reasons = reasons;
    out
}

/// Absolute spelling for a source payload path: canonicalized when the file
/// exists, else the cwd-joined spelling (the Verifier's `same_file`
/// canonicalizes both sides at launch).
fn resolve_payload_path(path: &Path) -> Option<PathBuf> {
    if let Ok(p) = std::fs::canonicalize(path) {
        return Some(p);
    }
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    std::env::current_dir().ok().map(|cwd| cwd.join(path))
}

/// Path spelling written into the draft's `target=`. `std::fs::canonicalize`
/// returns `\\?\` verbatim paths on Windows; the plain spelling names the
/// same object and keeps the draft readable.
fn draft_target(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        s.strip_prefix(r"\\?\").unwrap_or(&s).to_string()
    }
}

/// `argv[0]`s that exec another command selected at run time. A hash pin on
/// the launcher alone does not bind the workload it ends up running: `env`
/// execs whatever its arguments name, `py` picks a Python interpreter via its
/// own resolution, `npx` resolves a package and a node binary. The runtime
/// contract pins `binary-hash` to the spawned `argv[0]` image, so the inner
/// executable cannot be expressed as a hash entry — the draft records the
/// caveat instead of presenting the policy as fully bound.
fn delegating_launcher_reason(argv0: &str) -> Option<String> {
    let name = Path::new(argv0)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
    match stem {
        "env" | "nice" | "nohup" | "timeout" | "gtimeout" | "setsid" | "stdbuf" | "chrt"
        | "taskset" | "ionice" | "sudo" | "doas" => Some(format!(
            "binary-hash pins the delegating launcher '{stem}' only — the \
             command it selects from its arguments is not bound; rerun \
             generate-policy on the inner command directly to bind the workload"
        )),
        "py" | "pyw" => Some(format!(
            "'{stem}' selects the Python interpreter at run time — the selected \
             interpreter executable is not pinned; invoke the interpreter \
             directly to bind it"
        )),
        "npx" | "bunx" | "uvx" | "pipx" | "pnpx" => Some(format!(
            "'{stem}' resolves the package and runtime executable at run time — \
             those are not pinned; invoke the runtime on the entrypoint \
             directly to bind them"
        )),
        "uv" | "poetry" | "pipenv" | "pdm" | "hatch" | "conda" | "npm" | "pnpm" | "yarn"
        | "deno" | "bun" | "docker" | "podman" => Some(format!(
            "'{stem}' resolves the workload (subcommand, package, image, or \
             script) at run time — the resolved target is not pinned; rerun \
             generate-policy on the resolved command directly to bind it"
        )),
        _ => None,
    }
}

/// The content of `path`'s shebang line without the `#!` prefix
/// (`#!/usr/bin/env python3` → `/usr/bin/env python3`), when present.
fn shebang_line(path: &Path) -> Option<String> {
    let mut buf = [0u8; 256];
    let n = fs::File::open(path)
        .and_then(|mut f| {
            use std::io::Read;
            f.read(&mut buf)
        })
        .ok()?;
    let head = std::str::from_utf8(&buf[..n]).ok()?;
    let first = head.lines().next()?;
    first.strip_prefix("#!").map(|s| s.trim().to_string())
}

/// True when `argv[0]` names the payload file itself — direct script
/// execution (`./server.py`, or a PATH-installed entry script), where the
/// kernel honors the shebang. `python3 server.py` is indirect: the pinned
/// interpreter runs and the shebang is inert.
fn direct_script_exec(argv0: &str, path: &Path) -> bool {
    match (
        crate::verifier::hash::resolve_command_path(argv0).ok(),
        resolve_payload_path(path),
    ) {
        (Some(a), Some(b)) => crate::verifier::hash::same_file(&a, &b),
        _ => Path::new(argv0) == path,
    }
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
        let end = first_payload_arg_index(argv).unwrap_or(argv.len());
        if argv[..end].iter().any(|a| a == "-m") {
            return PayloadDiscovery {
                kind: PayloadKind::Unresolved {
                    reason: format!(
                        "{interpreter} -m executes a module by name, which is not a \
                         hash-bindable workload"
                    ),
                },
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

    // An extensionless script still names its interpreter in the shebang;
    // PATH-installed entry points (`mcp-server-git`, …) are the common case.
    if let Ok(resolved) = crate::verifier::hash::resolve_command_path(&argv[0])
        && let Some(interpreter) = shebang_interpreter(&resolved)
    {
        return PayloadDiscovery {
            kind: PayloadKind::Source {
                interpreter,
                path: resolved,
            },
        };
    }

    PayloadDiscovery {
        kind: PayloadKind::Native,
    }
}

/// Inspect takes a single path; classify script vs interpreter vs native binary.
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
    let lower = name.to_ascii_lowercase();
    let lower = lower.strip_suffix(".exe").unwrap_or(lower.as_str());
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

/// Interpreter named by a shebang line's *command token* — not substrings.
/// `#!/usr/bin/python3` is the fixed form; `#!/usr/bin/env python3` delegates
/// through env, whose own options (`-S`, `-i`, `-u NAME`, `-C DIR`, …) and
/// `VAR=val` assignments must be skipped before the command is read. A hook
/// path or option string that merely contains "python"/"node" (`run.sh` in a
/// python-named directory, `env -S bash -c '…python…'`) must not classify.
fn shebang_interpreter(path: &Path) -> Option<InterpreterKind> {
    let line = shebang_line(path)?;
    let mut tokens = line.split_whitespace();
    let first = tokens.next()?;
    let cmd = if Path::new(first).file_name().and_then(|s| s.to_str()) == Some("env") {
        let mut iter = tokens.peekable();
        let mut found = None;
        while let Some(tok) = iter.next() {
            if tok == "-S" || tok == "--split-string" {
                continue;
            }
            if matches!(tok, "-u" | "--unset" | "-C" | "--chdir") {
                iter.next();
                continue;
            }
            if tok.starts_with('-') || tok.contains('=') {
                continue;
            }
            found = Some(tok);
            break;
        }
        found?
    } else {
        first
    };
    interpreter_from_command(cmd)
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
        skip_note: native_skip_note(path),
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
            "PYTHON.EXE",
            "py.eXe",
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
        let mixed_case = discover_from_argv(&["Node.ExE".into(), "index.js".into()]);
        assert!(matches!(
            mixed_case.kind,
            PayloadKind::Source {
                interpreter: InterpreterKind::Node,
                ..
            }
        ));
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
    fn delegating_launchers_are_flagged() {
        for argv0 in [
            "env",
            "/usr/bin/env",
            "env.exe",
            "py",
            "C:\\Windows\\py.exe",
            "pyw",
            "npx",
            "npx.EXE",
            "PY.eXe",
            "Env.ExE",
            // Exec wrappers
            "nice",
            "nohup",
            "timeout",
            "gtimeout",
            "setsid",
            "stdbuf",
            "chrt",
            "taskset",
            "ionice",
            "sudo",
            "doas",
            // Package runners
            "bunx",
            "uvx",
            "pipx",
            "pnpx",
            // Subcommand-based selection
            "uv",
            "poetry",
            "pipenv",
            "pdm",
            "hatch",
            "conda",
            "npm",
            "pnpm",
            "yarn",
            "deno",
            "bun",
            "docker",
            "podman",
        ] {
            assert!(
                delegating_launcher_reason(argv0).is_some(),
                "{argv0} must be flagged as a delegating launcher"
            );
        }
        for argv0 in ["python", "python3", "node", "server.py", "/bin/sh"] {
            assert!(
                delegating_launcher_reason(argv0).is_none(),
                "{argv0} is a direct interpreter or file, not a delegating launcher"
            );
        }
    }

    #[test]
    fn env_launcher_marks_workload_not_fully_bound() {
        let argv = vec![
            "env".into(),
            "FOO=1".into(),
            "python3".into(),
            "server.py".into(),
        ];
        let discovery = discover_from_argv(&argv);
        let w = workload_hashes(&argv, &discovery);
        assert!(
            w.unbound_reasons.iter().any(|r| r.contains("env")),
            "env launch must carry a reason: {:?}",
            w.unbound_reasons
        );
        // The hash model cannot express a pin on the command env selects:
        // binary-hash targets the spawned argv[0] and entrypoint-hash must
        // match the executable or first payload argument.
        assert!(w.entrypoint.is_none());
    }

    #[test]
    fn env_shebang_marks_direct_exec_unbound() {
        let dir = std::env::temp_dir().join(format!(
            "mcp_writ_envshebang_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let script = dir.join("server.py");
        std::fs::write(&script, "#!/usr/bin/env python3\nprint(1)\n").unwrap();

        // Direct exec: argv[0] is the script — the kernel honors the shebang.
        let argv = vec![script.to_string_lossy().into_owned()];
        let w = workload_hashes(&argv, &discover_from_argv(&argv));
        assert!(
            w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
            "{:?}",
            w.unbound_reasons
        );

        // Indirect exec (`python3 server.py`): the interpreter is pinned and
        // the shebang is inert — no caveat.
        let argv = vec!["python3".into(), script.to_string_lossy().into_owned()];
        let w = workload_hashes(&argv, &discover_from_argv(&argv));
        assert!(
            !w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
            "{:?}",
            w.unbound_reasons
        );

        // Fixed shebang (no env): no PATH delegation, but the kernel-selected
        // interpreter image is still not pinned — the draft flags it.
        std::fs::write(&script, "#!/usr/bin/python3\nprint(1)\n").unwrap();
        let argv = vec![script.to_string_lossy().into_owned()];
        let w = workload_hashes(&argv, &discover_from_argv(&argv));
        assert!(
            !w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
            "{:?}",
            w.unbound_reasons
        );
        assert!(
            w.unbound_reasons
                .iter()
                .any(|r| r.contains("shebang interpreter '/usr/bin/python3'")),
            "fixed shebang must flag the unpinned interpreter: {:?}",
            w.unbound_reasons
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shebang_interpreter_parses_command_token() {
        let dir = std::env::temp_dir().join(format!(
            "mcp_writ_shebang_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Extensionless so only the shebang can identify the language.
        let script = dir.join("entrypoint");
        let kind_of = |body: &str| {
            std::fs::write(&script, body).unwrap();
            discover_from_path(&script).kind
        };

        // Fixed interpreter shebangs.
        assert_eq!(
            kind_of("#!/usr/bin/python3 -u\nprint(1)\n"),
            PayloadKind::Source {
                interpreter: InterpreterKind::Python,
                path: script.clone(),
            }
        );
        assert_eq!(
            kind_of("#!/usr/bin/node\nconsole.log(1)\n"),
            PayloadKind::Source {
                interpreter: InterpreterKind::Node,
                path: script.clone(),
            }
        );

        // env delegation: plain, -S with options, and VAR=val assignments.
        assert!(matches!(
            kind_of("#!/usr/bin/env python3\n"),
            PayloadKind::Source {
                interpreter: InterpreterKind::Python,
                ..
            }
        ));
        assert!(matches!(
            kind_of("#!/usr/bin/env -S python3 -u\n"),
            PayloadKind::Source {
                interpreter: InterpreterKind::Python,
                ..
            }
        ));
        assert!(matches!(
            kind_of("#!/usr/bin/env -S FOO=1 node --harmony\n"),
            PayloadKind::Source {
                interpreter: InterpreterKind::Node,
                ..
            }
        ));
        assert!(matches!(
            kind_of("#!/usr/bin/env -i -u PATH node\n"),
            PayloadKind::Source {
                interpreter: InterpreterKind::Node,
                ..
            }
        ));

        // Substrings in hook paths, options, or eval text must not classify.
        let hook = dir.join("python-hooks").join("run");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(&hook, "#!/bin/sh\nexit 0\n").unwrap();
        assert_eq!(discover_from_path(&hook).kind, PayloadKind::Native);
        assert_eq!(
            kind_of("#!/usr/bin/env -S bash -c 'echo python'\n"),
            PayloadKind::Native
        );
        assert_eq!(kind_of("#!/opt/python-tools/run.sh\n"), PayloadKind::Native);
        assert_eq!(kind_of("#!/usr/bin/env -S deno run\n"), PayloadKind::Native);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn extensionless_shebang_script_is_a_source_payload() {
        let dir = std::env::temp_dir().join(format!(
            "mcp_writ_extless_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // PATH-installed entry scripts (`mcp-server-git`, …) are commonly
        // extensionless with an env shebang.
        let script = dir.join("mcp-server");
        std::fs::write(&script, "#!/usr/bin/env python3\nprint(1)\n").unwrap();

        let argv = vec![script.to_string_lossy().into_owned()];
        let d = discover_from_argv(&argv);
        match &d.kind {
            PayloadKind::Source { interpreter, path } => {
                assert_eq!(*interpreter, InterpreterKind::Python);
                assert_eq!(
                    path,
                    &crate::verifier::hash::resolve_command_path(&argv[0]).unwrap()
                );
            }
            other => panic!("expected Source for shebang script, got {other:?}"),
        }

        // Direct exec: the env shebang's PATH-selected interpreter is unpinned.
        let w = workload_hashes(&argv, &d);
        assert!(
            w.unbound_reasons.iter().any(|r| r.contains("env shebang")),
            "{:?}",
            w.unbound_reasons
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn option_operands_are_not_the_payload() {
        // Value-taking options consume the next token; pinning it would bind
        // a preload module or flag value while the real script stays unpinned.
        for (argv, expected) in [
            (
                vec![
                    "node".into(),
                    "--require".into(),
                    "stub.cjs".into(),
                    "index.js".into(),
                ],
                "index.js",
            ),
            (
                vec![
                    "node".into(),
                    "--preserve-symlinks".into(),
                    "--loader".into(),
                    "ts-loader.mjs".into(),
                    "server.js".into(),
                ],
                "server.js",
            ),
            (
                vec![
                    "python".into(),
                    "-W".into(),
                    "ignore".into(),
                    "-X".into(),
                    "utf8".into(),
                    "server.py".into(),
                ],
                "server.py",
            ),
        ] {
            let d = discover_from_argv(&argv);
            match d.kind {
                PayloadKind::Source { path, .. } => {
                    assert_eq!(path, PathBuf::from(expected), "{argv:?}")
                }
                other => panic!("expected Source for {argv:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn inline_eval_reason_without_known_interpreter() {
        // `sh -c` / `perl -e` are Native for discovery, but the runtime
        // refuses the launch — the draft must carry the reason instead of
        // looking fully bound.
        for argv in [
            vec!["sh".into(), "-c".into(), "exec node server.js".into()],
            vec!["perl".into(), "-e".into(), "1".into()],
            vec!["ruby".into(), "-e".into(), "puts 1".into()],
        ] {
            let w = workload_hashes(&argv, &discover_from_argv(&argv));
            assert!(
                w.unbound_reasons
                    .iter()
                    .any(|r| r.contains("inline evaluation")),
                "{argv:?} -> {:?}",
                w.unbound_reasons
            );
            assert!(w.entrypoint.is_none());
        }
    }

    #[test]
    fn module_flag_is_unresolved() {
        for argv in [
            vec!["python".into(), "-m".into(), "http.server".into()],
            vec!["python".into(), "-m".into()],
            vec!["node".into(), "-m".into(), "mod".into()],
        ] {
            let d = discover_from_argv(&argv);
            assert!(
                matches!(d.kind, PayloadKind::Unresolved { .. }),
                "{argv:?} -> {:?}",
                d.kind
            );
        }
        let d = discover_from_argv(&["python".into(), "-m".into(), "http.server".into()]);
        match d.kind {
            PayloadKind::Unresolved { reason } => {
                assert!(reason.contains("-m"), "{reason}")
            }
            other => panic!("expected Unresolved, got {other:?}"),
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
            native_skip_note(Path::new("server.py")),
            "native analysis skipped; source payload = server.py"
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
