//! Launch-target hashing for generated drafts: pin `binary-hash` /
//! `entrypoint-hash` entries against the resolved argv payload, mirroring
//! the runtime binding contract in
//! `crate::verifier::hash::bind_launched_workload`.

use std::path::{Path, PathBuf};

use super::{PayloadDiscovery, PayloadKind, delegating_launcher_reason};
use crate::workload::{
    CommandNames, InterpreterKind, LaunchResolution, argv_contains_inline_eval_with_exe,
    first_payload_arg_with_exe, is_perl_command, is_powershell_command, is_ruby_command,
    is_shell_command, node_preload_flags_present_with_exe, payload_boundary_blocker_with_exe,
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
    /// The modeled interpreter family this workload launches under —
    /// the payload's family for `Source` / `InlineEval` kinds, else the
    /// family the launch argv itself names (`python -m` runs CPython
    /// whether or not the module token is hash-bindable). `None` for
    /// native launches and launches whose argv names no modeled family.
    /// The draft generator seeds the matching
    /// `examples/policies/runtime/*.kdl` seccomp baseline from it — an
    /// interpreted payload has no ELF syscall table to analyze, and without
    /// the baseline the emitted `syscalls` block is an allow-nothing list
    /// that refuses the enforced launch outright.
    pub interpreter: Option<InterpreterKind>,
    /// The resolved interpreter/launch executable — the same path the
    /// `binary-hash` line spells as `target=` when the pin was emitted.
    /// Set whenever `argv[0]` resolves (even when hashing failed): the
    /// draft's interpreter-derived read grants are grounded in the
    /// resolution, not the pin.
    pub interpreter_path: Option<PathBuf>,
    /// The resolved payload file — the same path `entrypoint-hash`
    /// spells as `target=` when the pin was emitted. `None` for `-m`,
    /// inline-eval, and otherwise unbound payloads.
    pub payload_path: Option<PathBuf>,
    /// `argv[0]` — or the interpreter a `#!` line selects — resolved to
    /// an absolute path *without* symlink canonicalization: a venv's
    /// `bin/python` is a symlink whose spelled location is where the
    /// interpreter's own prefix discovery (`pyvenv.cfg`, the
    /// `site-packages` layout) starts from.
    pub spelled_path: Option<PathBuf>,
}

impl WorkloadHashes {
    /// True when the draft should emit a `server` block for this workload —
    /// at least one hash line or an unbound reason to record.
    pub fn has_content(&self) -> bool {
        self.binary.is_some() || self.entrypoint.is_some() || !self.unbound_reasons.is_empty()
    }
}

/// Bytes the capability analysis already materialized, with the digest
/// computed over exactly them. A generated draft's hash pin must certify
/// *these* bytes: re-reading the pathname after live discovery ran the
/// workload would let a self-rewriting server pin content the analysis
/// never saw (the TOCTOU this type exists to close).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedDigest {
    /// Path the analyzed bytes came from.
    pub path: PathBuf,
    /// `sha256:` digest over the analyzed buffer.
    pub digest: String,
    /// True when `path` was derived by resolving `argv[0]` — i.e. it IS
    /// the launch image the `binary-hash` line pins. False for an
    /// explicit `--binary-path` or a source payload: those never stand in
    /// for the spawned `argv[0]` object.
    pub binds_launch_image: bool,
}

/// Compute the draft's launch-target hashes from argv and its payload
/// discovery. Hash values are this host's digests; the REVIEW comments the
/// generator emits with them tell the operator to recompute on the
/// deployment host.
///
/// `analyzed` carries the digest of the bytes capability analysis already
/// consumed. When it names the same object the launch binds (the resolved
/// `argv[0]` image, or the source payload), the pin is taken from it
/// verbatim — no second read. If the object resolves differently between
/// analysis and hashing the pin is refused with an unbound reason rather
/// than certifying unanalyzed bytes.
pub fn workload_hashes(
    argv: &[String],
    discovery: &PayloadDiscovery,
    analyzed: Option<&AnalyzedDigest>,
) -> WorkloadHashes {
    let mut out = WorkloadHashes {
        interpreter: match &discovery.kind {
            PayloadKind::Source { interpreter, .. }
            | PayloadKind::InlineEval { interpreter, .. } => Some(*interpreter),
            PayloadKind::Native | PayloadKind::Unresolved { .. } => None,
        },
        ..Default::default()
    };
    let mut reasons: Vec<String> = Vec::new();

    // Resolve `argv[0]` the way `run` does under a hash policy: a `#!`
    // script expands to the interpreter-plus-script launch the kernel
    // performs, so `binary` pins the interpreter the kernel selects —
    // never the script the kernel would hand it. Grammar and payload
    // analysis below run on the resolved argv, the same shape
    // `bind_launched_workload` sees.
    let (resolved_exe, launch_argv) = match argv.first() {
        Some(argv0) => match crate::workload::resolve_launch(argv0, true) {
            Ok(resolution) => {
                let launch_argv = resolution.into_argv(argv);
                out.spelled_path = spelled_launch_path(argv0, &resolution).map(plain_path);
                let exe = resolution.exe;
                out.interpreter_path = Some(plain_path(exe.clone()));
                match analyzed.filter(|a| a.binds_launch_image) {
                    Some(a) if crate::workload::same_file(&a.path, &exe) => {
                        // The analysis read IS this launch image — pin
                        // its digest without a second pathname read.
                        out.binary = Some(HashLine {
                            target: draft_target(&exe),
                            hash_value: a.digest.clone(),
                        });
                    }
                    Some(a) => reasons.push(format!(
                        "binary-hash not emitted: '{argv0}' resolved to '{}' during \
                         analysis but '{}' at hash time — the analyzed bytes cannot \
                         be bound to this launch",
                        a.path.display(),
                        exe.display()
                    )),
                    None => match crate::verifier::hash::hash_file(&exe) {
                        Ok(hash_value) => {
                            out.binary = Some(HashLine {
                                target: draft_target(&exe),
                                hash_value,
                            });
                        }
                        Err(e) => reasons.push(format!(
                            "binary-hash not emitted: cannot hash '{}': {e}",
                            exe.display()
                        )),
                    },
                }
                (Some(exe), launch_argv)
            }
            Err(e) => {
                reasons.push(format!(
                    "binary-hash not emitted: cannot resolve '{argv0}': {e}"
                ));
                (None, argv.to_vec())
            }
        },
        None => {
            reasons.push("binary-hash not emitted: empty argv".to_string());
            (None, argv.to_vec())
        }
    };
    let argv: &[String] = &launch_argv;
    let names = CommandNames::new(
        argv.first().map(String::as_str).unwrap_or(""),
        resolved_exe.as_deref(),
    );

    // The payload may stay unbound (`-m`, an unrecognized spelling, a
    // delegating launcher) while the launch's interpreter family is
    // still readable from argv — `-m` is how the real Python servers
    // run, and the interpreter-derived runtime defaults (read grants,
    // syscall baseline, environment candidates) key on the launch,
    // not the payload. Truly unclassifiable launches (`env` wrappers,
    // renamed binaries) name no family and stay `None`.
    if out.interpreter.is_none() {
        out.interpreter = names.interpreter();
    }

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

    match &discovery.kind {
        PayloadKind::Native => {
            // A modeled interpreter family launching a source file the
            // discovery did not classify as Source (`sh server.sh`,
            // `perl server.pl`, `pwsh -File server.ps1`, or a
            // Native-forced `python3 server.py`): binary-hash pins the
            // interpreter image while the payload stays unpinned —
            // record the reason instead of presenting the draft as
            // fully bound. Eval spellings are already covered by the
            // inline-eval reason above.
            let argv0 = argv.first().map(String::as_str).unwrap_or("");
            if !argv_contains_inline_eval_with_exe(argv, resolved_exe.as_deref())
                && names.any_is(|s| {
                    crate::workload::interpreter_from_command(s).is_some()
                        || is_shell_command(s)
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
            // An interpreter outside the modeled option grammars (a
            // `#!/usr/bin/awk` script's kernel-selected interpreter,
            // a renamed binary, …) cannot prove a payload boundary —
            // the launch is binary-pinned only and the script it reads
            // stays unpinned; record it rather than letting the draft
            // look fully bound.
            if let Some(resolved) = &resolved_exe
                && !crate::workload::exe_grammar_modeled(argv, Some(resolved))
                && first_payload_arg_with_exe(argv, Some(resolved)).is_some()
            {
                reasons.push(format!(
                    "entrypoint-hash not emitted: the resolved executable '{}' \
                     has no modeled option grammar — the payload script it reads \
                     cannot be hash-bound; a policy pinning it would fail closed \
                     at 'run'",
                    resolved.display()
                ));
            }
        }
        PayloadKind::Source { path, .. } => {
            let resolved = resolve_payload_path(path);
            out.payload_path = resolved.clone().map(plain_path);
            match analyzed.filter(|a| !a.binds_launch_image) {
                // The analysis already materialized the payload — pin the
                // digest of exactly those bytes when the resolved object
                // still matches; a swapped payload must not smuggle bytes
                // the analysis never saw into the pin.
                Some(a)
                    if resolved
                        .as_ref()
                        .is_some_and(|p| crate::workload::same_file(&a.path, p)) =>
                {
                    let p = resolved.expect("guarded by is_some_and");
                    out.entrypoint = Some(HashLine {
                        target: draft_target(&p),
                        hash_value: a.digest.clone(),
                    });
                }
                Some(a) => reasons.push(format!(
                    "entrypoint-hash not emitted: payload '{}' resolved to '{}' during \
                     analysis but '{}' at hash time — the analyzed bytes cannot be \
                     bound to this launch",
                    path.display(),
                    a.path.display(),
                    resolved
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<unresolvable>".to_string())
                )),
                None => match resolved.and_then(|p| {
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
                },
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

/// `argv[0]` — or, under a `#!` launch, the interpreter the shebang
/// selects — as an absolute path *without* symlink canonicalization:
/// a venv `bin/python` is a symlink whose spelled location is what the
/// interpreter's own prefix discovery (`pyvenv.cfg`, the `site-packages`
/// layout) keys on. `interpreter_path` keeps the canonical image the
/// pin binds; this keeps the spelled one the runtime reads its layout
/// from.
fn spelled_launch_path(argv0: &str, resolution: &LaunchResolution) -> Option<PathBuf> {
    // `#!` expansion: `argv_head` spells the interpreter the kernel
    // hands the script to — an env-selected name stays a bare PATH
    // lookup, a direct shebang interpreter stays the absolute path the
    // line named.
    let token = if resolution.argv_head.len() > 1 {
        resolution.argv_head.first().map(String::as_str)?
    } else {
        argv0
    };
    let p = Path::new(token);
    if p.is_absolute() {
        return Some(p.to_path_buf());
    }
    if token.contains('/') || token.contains('\\') {
        return std::env::current_dir().ok().map(|cwd| cwd.join(p));
    }
    crate::workload::search_path(token)
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

/// `std::fs::canonicalize` returns `\\?\` verbatim paths on Windows; the
/// plain spelling names the same object. Stored launch paths keep the
/// plain spelling so they read like the `draft_target` pins and the
/// grants `build_runtime_seed_grants` emits from them.
fn plain_path(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    let stripped = if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        Some(format!(r"\\{rest}"))
    } else {
        s.strip_prefix(r"\\?\").map(str::to_string)
    };
    match stripped {
        Some(p) => PathBuf::from(p),
        None => path,
    }
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
