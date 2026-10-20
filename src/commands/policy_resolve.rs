//! `mcp-writ policy resolve` — the composed-policy inspector (PR-24).
//!
//! Loads a KDL policy exactly the way a launch does — `extends`,
//! `include`, and matching `when` blocks resolved — then prints the
//! effective document via [`Policy::to_kdl`](crate::policy::Policy::to_kdl) together with the
//! provenance the load recorded: for every field the composition
//! wrote, which file wrote it and what the write did
//! (`set`/`union`/`replace`/`prune`). The load's warnings (schema
//! laxity, replacements that dropped inherited entries, weakened
//! postures, inbound notes) ride along — on stderr in `kdl` mode,
//! in-band in `json` mode.
//!
//! Output contract: `--format kdl` (default) writes only the composed
//! KDL to stdout so it can be piped to a file or re-loaded;
//! `--format json` writes one object `{schema_version, policy, kdl,
//! provenance, review_markers, warnings}` — `policy.hash` is `null`
//! when the canonical hash could not be computed. Exit codes match
//! `plan`'s convention — `0` resolved, `1` load/bind failure,
//! `2` invalid input.

use std::path::Path;

use crate::cli::{PolicyResolveArgs, ResolveFormat};
use crate::error::PolicyError;
use crate::execution::ExecutionTarget;
use crate::policy::kdl_loader::load_kdl_policy_for_target_scanned;
use crate::policy::provenance::{LoadDiagnostics, ProvRecord};

/// Schema version of the JSON `--format json` produces.
const RESOLVE_REPORT_SCHEMA_VERSION: &str = "1";

/// Outputs the JSON literal `null` — the local counterpart of the
/// `enforcement` module's private `JsonNull`.
struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

/// Run `policy resolve` and exit the process with the result's code.
pub fn run_policy_resolve(args: PolicyResolveArgs) -> ! {
    crate::commands::tracing_init::init_tracing(args.verbose);
    // Parse/semantic errors are already a result: status invalid.
    if let Some(ref msg) = args.invalid_input {
        let msg = msg.clone();
        emit_invalid(&args, &msg);
    }
    let policy_path = args
        .policy
        .as_deref()
        .expect("invalid_input covers a missing --policy");

    // The scanned load returns the warnings an enforcing loader would
    // print — `resolve` surfaces them but never enforces
    // `MCP_WRIT_REPLACE_MODE`/`MCP_WRIT_REVIEW_MODE`: an inspector that
    // died at load would hide the findings it exists to show.
    let env = args
        .env
        .clone()
        .unwrap_or_else(|| std::env::var("MCP_WRIT_ENV").unwrap_or_default());
    let (policy, diagnostics) =
        match load_kdl_policy_for_target_scanned(policy_path, &env, &ExecutionTarget::native()) {
            Ok(loaded) => loaded,
            Err(e) => emit_failure(&args, policy_path, &e),
        };

    // Bind exactly like `run`/`plan`/`check` do — `--server` selects
    // the identity a multi-server policy resolves for.
    let bound = match policy.bind_to_server(args.server.as_deref()) {
        Ok(b) => b,
        Err(e) => emit_failure(&args, policy_path, &e),
    };

    emit_resolved(&args, &bound, &diagnostics);
}

/// Exit with the machine-readable (or human) `invalid` result — the
/// `plan`/`check` convention, exit 2.
fn emit_invalid(args: &PolicyResolveArgs, msg: &str) -> ! {
    match args.format {
        ResolveFormat::Json => {
            println!(
                "{}",
                nojson::object(|f| {
                    f.member("schema_version", RESOLVE_REPORT_SCHEMA_VERSION)?;
                    f.member("status", "invalid")?;
                    f.member("reason", msg)
                })
            );
        }
        ResolveFormat::Kdl => eprintln!("Error: {msg}"),
    }
    std::process::exit(2);
}

/// Exit with a load/bind failure — exit 1, JSON when requested so the
/// machine channel stays machine-readable.
fn emit_failure(args: &PolicyResolveArgs, path: &Path, e: &PolicyError) -> ! {
    let detail = format!("{}: {e}", path.display());
    match args.format {
        ResolveFormat::Json => {
            println!(
                "{}",
                nojson::object(|f| {
                    f.member("schema_version", RESOLVE_REPORT_SCHEMA_VERSION)?;
                    f.member("status", "error")?;
                    f.member("reason", detail.as_str())
                })
            );
        }
        ResolveFormat::Kdl => eprintln!("Error: {detail}"),
    }
    std::process::exit(1);
}

/// Emit the resolved policy and exit 0.
fn emit_resolved(
    args: &PolicyResolveArgs,
    policy: &crate::policy::Policy,
    diagnostics: &LoadDiagnostics,
) -> ! {
    match args.format {
        ResolveFormat::Kdl => {
            // stdout is the document; warnings, review markers, and the
            // provenance log go to stderr so `--format kdl` stays
            // re-loadable. `resolve` reports the markers without
            // enforcing them — the same listing
            // `MCP_WRIT_REVIEW_MODE=warn` would print, minus the gate.
            print!("{}", policy.to_kdl());
            diagnostics.emit_warnings();
            let _ = crate::policy::review::ReviewMode::Warn.enforce(&diagnostics.review_markers);
            if let Some(prov) = policy.provenance.as_deref() {
                for rec in &prov.records {
                    // Record fields carry policy-derived text (file
                    // paths, declared names) — sanitize before stderr.
                    eprintln!(
                        "  # {}",
                        crate::termutil::sanitize_for_terminal(&describe_record(rec))
                    );
                }
            }
        }
        ResolveFormat::Json => {
            println!("{}", resolved_json(policy, diagnostics));
        }
    }
    std::process::exit(0);
}

/// The human provenance line for `kdl` mode — `field <- op by
/// file:line (dropped N from other.kdl)`.
fn describe_record(rec: &ProvRecord) -> String {
    let mut line = format!(
        "{} {} by {}",
        rec.field,
        rec.op.as_str(),
        rec.file.display()
    );
    if let Some(l) = rec.line {
        line.push_str(&format!(":{l}"));
    }
    if !rec.replaced.is_empty() {
        let parts: Vec<String> = rec
            .replaced
            .iter()
            .map(|(f, n)| format!("{n} from {}", f.display()))
            .collect();
        line.push_str(&format!(" (dropped {})", parts.join(", ")));
    }
    line
}

/// Serialize the resolved result as one JSON object.
fn resolved_json(policy: &crate::policy::Policy, diagnostics: &LoadDiagnostics) -> String {
    let kdl = policy.to_kdl();
    // A hash failure must not masquerade as an empty-string digest —
    // `null` keeps the field truthful about what the emitter produced.
    let hash = policy.effective_hash().ok();
    let records: &[ProvRecord] = policy
        .provenance
        .as_deref()
        .map(|p| p.records.as_slice())
        .unwrap_or(&[]);
    nojson::object(|f| {
        f.member("schema_version", RESOLVE_REPORT_SCHEMA_VERSION)?;
        f.member("status", "resolved")?;
        f.member(
            "policy",
            nojson::object(|f| {
                f.member("version", policy.version)?;
                match &hash {
                    Some(h) => f.member("hash", h.as_str()),
                    None => f.member("hash", JsonNull),
                }
            }),
        )?;
        f.member("kdl", kdl.as_str())?;
        f.member(
            "provenance",
            nojson::array(|f| {
                for rec in records {
                    f.element(nojson::object(|o| write_record(o, rec)))?;
                }
                Ok(())
            }),
        )?;
        // The `// REVIEW` markers the load collected — invisible in
        // `kdl` mode's stdout, so they carry the same `{file, line,
        // text}` shape `check` reports.
        f.member(
            "review_markers",
            nojson::array(|f| {
                for m in &diagnostics.review_markers {
                    f.element(nojson::object(|o| {
                        o.member("file", m.path.display().to_string().as_str())?;
                        o.member("line", m.line)?;
                        o.member(
                            "text",
                            crate::termutil::sanitize_for_terminal(&m.text).as_str(),
                        )
                    }))?;
                }
                Ok(())
            }),
        )?;
        f.member(
            "warnings",
            nojson::array(|f| {
                for w in &diagnostics.warnings {
                    f.element(nojson::object(|o| {
                        o.member("kind", w.kind.as_str())?;
                        o.member("file", w.file.display().to_string().as_str())?;
                        match w.line {
                            Some(l) => o.member("line", l)?,
                            None => o.member("line", JsonNull)?,
                        }
                        o.member(
                            "message",
                            crate::termutil::sanitize_for_terminal(&w.message).as_str(),
                        )
                    }))?;
                }
                Ok(())
            }),
        )
    })
    .to_string()
}

/// Serialize one provenance record — `{field, file, line, op, items,
/// replaced}`. `items` carries what the write added (`set`/`union`) or
/// dropped (`replace`/`prune`); `replaced` names, per contributing
/// file, how many entries the write removed.
fn write_record(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    r: &ProvRecord,
) -> std::fmt::Result {
    f.member("field", r.field.as_str())?;
    f.member("op", r.op.as_str())?;
    f.member("file", r.file.display().to_string().as_str())?;
    match r.line {
        Some(l) => f.member("line", l)?,
        None => f.member("line", JsonNull)?,
    }
    f.member(
        "items",
        nojson::array(|f| {
            for i in &r.items {
                f.element(i.as_str())?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "replaced",
        nojson::array(|f| {
            for (file, n) in &r.replaced {
                f.element(nojson::object(|o| {
                    o.member("file", file.display().to_string().as_str())?;
                    o.member("count", *n)
                }))?;
            }
            Ok(())
        }),
    )
}
