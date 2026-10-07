//! Launch-target hashing for generated drafts: pin `binary-hash` /
//! `entrypoint-hash` entries against the resolved argv payload, mirroring
//! the runtime binding contract in
//! `crate::verifier::hash::bind_launched_workload`.

use std::path::{Path, PathBuf};

use super::{PayloadDiscovery, PayloadKind, delegating_launcher_reason};
use crate::workload::{
    CommandNames, argv_contains_inline_eval_with_exe, first_payload_arg_with_exe, is_perl_command,
    is_powershell_command, is_ruby_command, is_shell_command, node_preload_flags_present_with_exe,
    payload_boundary_blocker_with_exe, shebang_line,
};

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

    // Resolve `argv[0]` once — the binary-hash target and the
    // interpreter-grammar spelling share the resolved image's file
    // name, so a renamed alias (`worker` → `python3.12`) still classifies
    // under the family the kernel would exec.
    let resolved_exe = match argv.first() {
        Some(argv0) => match crate::workload::resolve_command_path(argv0) {
            Ok(resolved) => {
                match crate::verifier::hash::hash_file(&resolved) {
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
                }
                Some(resolved)
            }
            Err(e) => {
                reasons.push(format!(
                    "binary-hash not emitted: cannot resolve '{argv0}': {e}"
                ));
                None
            }
        },
        None => {
            reasons.push("binary-hash not emitted: empty argv".to_string());
            None
        }
    };
    let names = CommandNames::new(
        argv.first().map(String::as_str).unwrap_or(""),
        resolved_exe.as_deref(),
    );

    if let Some(reason) = delegating_launcher_reason(&names) {
        reasons.push(reason);
    }

    // The runtime refuses inline eval no matter which argv[0] carries the
    // flag; discovery only classifies known interpreters as InlineEval, so a
    // `sh -c ...` / `perl -e ...` launch still needs the reason recorded or
    // the draft would look fully bound yet always fail at `run`.
    if !matches!(discovery.kind, PayloadKind::InlineEval { .. })
        && argv_contains_inline_eval_with_exe(argv, resolved_exe.as_deref())
    {
        reasons.push(
            "entrypoint-hash not emitted: inline evaluation flags \
             (-c/-e/--eval/--command, -p/--print on node, -E on perl) are \
             not a hash-bindable workload — 'run' refuses this launch"
                .to_string(),
        );
    }

    // `-r`/`--require`/`--import`/`--loader` load modules before the
    // payload; the pinned entrypoint covers none of them.
    if node_preload_flags_present_with_exe(argv, resolved_exe.as_deref()) {
        reasons.push(
            "entrypoint-hash does not cover Node preload modules loaded via \
             -r/--require/--import/--loader — those modules are not hash-bound"
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
        PayloadKind::Native => {
            // `interpreter_from_command` does not model shells, Perl,
            // Ruby, or PowerShell, so `sh server.sh` / `perl server.pl`
            // / `pwsh -File server.ps1` classify as Native: binary-hash
            // pins the interpreter image while the source file it
            // launches stays unpinned — record the reason instead of
            // presenting the draft as fully bound. Eval spellings are
            // already covered by the inline-eval reason above.
            let argv0 = argv.first().map(String::as_str).unwrap_or("");
            if !argv_contains_inline_eval_with_exe(argv, resolved_exe.as_deref())
                && names.any_is(|s| {
                    is_shell_command(s)
                        || is_perl_command(s)
                        || is_ruby_command(s)
                        || is_powershell_command(s)
                })
            {
                match first_payload_arg_with_exe(argv, resolved_exe.as_deref()) {
                    Some(payload) => reasons.push(format!(
                        "entrypoint-hash not emitted: '{argv0}' launches the source \
                         payload '{payload}' — the script is not hash-bound; rerun \
                         generate-policy on the interpreter invocation to bind it"
                    )),
                    // Arguments are present but the payload boundary is
                    // unresolved (an unrecognized option may consume the
                    // script token) — still an unbound interpreter launch.
                    None if argv.len() > 1 => {
                        let reason = match payload_boundary_blocker_with_exe(
                            argv,
                            resolved_exe.as_deref(),
                        ) {
                            Some(flag) => format!(
                                "entrypoint-hash not emitted: '{argv0}' option \
                                 '{flag}' may consume an operand, leaving the \
                                 payload boundary ambiguous — the launched \
                                 script is not hash-bound; rerun \
                                 generate-policy on the interpreter invocation \
                                 to bind it"
                            ),
                            None => format!(
                                "entrypoint-hash not emitted: '{argv0}' is invoked with \
                                 arguments whose source payload cannot be identified — \
                                 the launched script is not hash-bound; rerun \
                                 generate-policy on the interpreter invocation to bind it"
                            ),
                        };
                        reasons.push(reason);
                    }
                    None => {}
                }
            }
            // A directly executed script whose shebang names an interpreter
            // this crate does not model (`#!/bin/sh`, `#!/usr/bin/env bash`,
            // `#!/usr/bin/env perl`, …) classifies as Native: binary-hash
            // pins the script file while the kernel selects the shebang
            // interpreter — record the same caveat the Source arm reports.
            // A real native binary never carries a shebang line, so it is
            // unaffected.
            if let Some(resolved) = &resolved_exe
                && let Some(shebang) = shebang_line(resolved)
                && let Some(cmd) = shebang.split_whitespace().next()
            {
                if Path::new(cmd).file_name().and_then(|s| s.to_str()) == Some("env") {
                    reasons.push(
                        "binary-hash pins the entry script, but its env shebang selects the \
                         interpreter via PATH at run time — that interpreter is not pinned; \
                         invoke the interpreter on the script directly to bind it"
                            .to_string(),
                    );
                } else {
                    reasons.push(format!(
                        "binary-hash pins the entry script, but its shebang interpreter \
                         '{cmd}' is selected by the kernel at run time — that interpreter \
                         is not pinned; invoke the interpreter on the script directly \
                         to bind it"
                    ));
                }
            }
        }
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

/// True when `argv[0]` names the payload file itself — direct script
/// execution (`./server.py`, or a PATH-installed entry script), where the
/// kernel honors the shebang. `python3 server.py` is indirect: the pinned
/// interpreter runs and the shebang is inert.
fn direct_script_exec(argv0: &str, path: &Path) -> bool {
    match (
        crate::workload::resolve_command_path(argv0).ok(),
        resolve_payload_path(path),
    ) {
        (Some(a), Some(b)) => crate::workload::same_file(&a, &b),
        _ => Path::new(argv0) == path,
    }
}
