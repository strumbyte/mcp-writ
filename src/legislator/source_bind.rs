use std::io;
use std::path::{Path, PathBuf};

use crate::legislator::heuristics::Permission;
use crate::legislator::js_bind;
use crate::legislator::py_bind;
use crate::legislator::sinks::{self, ToolCapability};
use crate::workload::{
    CommandNames, argv_contains_inline_eval_with_exe, first_payload_arg_index_with_exe,
    first_payload_arg_with_exe, payload_boundary_blocker_with_exe, payload_is_module_with_exe,
    shebang_line,
};

// Re-exported so `PayloadKind`/`SourceAnalysis` keep their documented paths.
pub use crate::workload::{InterpreterKind, interpreter_from_command};

mod workload;

pub use workload::{HashLine, WorkloadHashes, workload_hashes};

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
    /// `-c` / `--eval` / `-e` / `--command`, or Node's `-p` / `--print`:
    /// warn, do not parse, skip ELF.
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

/// `argv[0]`s that exec another command selected at run time. A hash pin on
/// the launcher alone does not bind the workload it ends up running: `env`
/// execs whatever its arguments name, `py` picks a Python interpreter via its
/// own resolution, `npx` resolves a package and a node binary. The runtime
/// contract pins `binary-hash` to the spawned `argv[0]` image, so the inner
/// executable cannot be expressed as a hash entry — the draft records the
/// caveat instead of presenting the policy as fully bound.
fn delegating_launcher_reason(names: &CommandNames) -> Option<String> {
    use crate::workload::DelegatingLauncher;
    let (kind, stem) = names.delegating_launcher()?;
    Some(match kind {
        DelegatingLauncher::ExecsArgv => format!(
            "binary-hash pins the delegating launcher '{stem}' only — the \
             command it selects from its arguments is not bound; rerun \
             generate-policy on the inner command directly to bind the workload"
        ),
        DelegatingLauncher::PythonSelector => format!(
            "'{stem}' selects the Python interpreter at run time — the selected \
             interpreter executable is not pinned; invoke the interpreter \
             directly to bind it"
        ),
        DelegatingLauncher::CommandShell => format!(
            "'{stem}' delegates to a command string (`/c`, `-Command`) — the \
             command it runs is not pinned; invoke the workload command \
             directly to bind it"
        ),
        DelegatingLauncher::PackageExecutor => format!(
            "'{stem}' resolves the package and runtime executable at run time — \
             those are not pinned; invoke the runtime on the entrypoint \
             directly to bind them"
        ),
        DelegatingLauncher::WorkloadResolver => format!(
            "'{stem}' resolves the workload (subcommand, package, image, or \
             script) at run time — the resolved target is not pinned; rerun \
             generate-policy on the resolved command directly to bind it"
        ),
    })
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

    // The resolved image's file name classifies alongside `argv[0]` — a
    // renamed alias (`worker` → `python3.12`) still runs the
    // interpreter's grammar, so the launch classifies under it.
    let resolved_exe = crate::workload::resolve_command_path(&argv[0]).ok();
    let names = CommandNames::new(&argv[0], resolved_exe.as_deref());
    if let Some(interpreter) = names.interpreter() {
        if argv_contains_inline_eval_with_exe(argv, resolved_exe.as_deref()) {
            let flag = first_inline_eval_flag(argv, resolved_exe.as_deref())
                .unwrap_or("-c")
                .to_string();
            return PayloadDiscovery {
                kind: PayloadKind::InlineEval { interpreter, flag },
            };
        }
        // `-m <name>`, the attached `-m<name>` spelling (which
        // `first_payload_arg_index` surfaces as the payload token itself),
        // and clusters carrying a live `-m` (`-Bm <name>`) all name a
        // module, not a hash-bindable file.
        let module_named = payload_is_module_with_exe(argv, resolved_exe.as_deref());
        if module_named {
            return PayloadDiscovery {
                kind: PayloadKind::Unresolved {
                    reason: format!(
                        "{interpreter} -m executes a module by name, which is not a \
                         hash-bindable workload"
                    ),
                },
            };
        }
        return match first_payload_arg_with_exe(argv, resolved_exe.as_deref()) {
            Some(payload) => source_or_unresolved(interpreter, PathBuf::from(payload)),
            None => {
                let reason = match payload_boundary_blocker_with_exe(argv, resolved_exe.as_deref())
                {
                    Some(flag) => format!(
                        "{interpreter} option '{flag}' may consume an operand, \
                         leaving the payload boundary ambiguous"
                    ),
                    None => format!("{interpreter} invocation has no source payload argument"),
                };
                PayloadDiscovery {
                    kind: PayloadKind::Unresolved { reason },
                }
            }
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

    // A delegating launcher resolves the workload at run time — even when
    // the launcher itself is a shebang-carrying script, analyzing or
    // hashing it as the workload's source would pin the launcher, not
    // what it resolves to.
    if let Some(reason) = delegating_launcher_reason(&names) {
        return PayloadDiscovery {
            kind: PayloadKind::Unresolved { reason },
        };
    }

    // An extensionless script still names its interpreter in the shebang;
    // PATH-installed entry points (`mcp-server-git`, …) are the common case.
    if let Some(resolved) = resolved_exe
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

fn first_inline_eval_flag<'a>(argv: &'a [String], resolved_exe: Option<&Path>) -> Option<&'a str> {
    let names = CommandNames::new(argv.first().map(String::as_str).unwrap_or(""), resolved_exe);
    let end = first_payload_arg_index_with_exe(argv, resolved_exe).unwrap_or(argv.len());
    argv[..end]
        .iter()
        .map(String::as_str)
        .find(|a| names.is_inline_eval(a))
}

/// Bound on a submitted source file — the whole file is materialized
/// and the parse builds per-tool capability collections sized by the
/// input, so an attacker-sized artifact is refused at the door rather
/// than exhausting analyzer memory mid-parse.
const MAX_SOURCE_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// Parse a source file into per-tool Capability (fail-secure: I/O errors propagate).
pub fn analyze_source_path(path: &Path) -> io::Result<SourceAnalysis> {
    let source = crate::fspriv::read_text_bounded(path, MAX_SOURCE_FILE_BYTES)?;
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
mod tests;
