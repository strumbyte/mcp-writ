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

use std::collections::BTreeMap;
use std::path::Path;

use crate::cli::{PolicyResolveArgs, ResolveFormat};
use crate::error::PolicyError;
use crate::execution::ExecutionTarget;
use crate::policy::kdl_loader::{
    load_kdl_policy_for_target_scanned, load_kdl_policy_for_target_scanned_rules,
};
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

    // `--version-diff` (PR-28): replay the same documents under the
    // other composition-rules version and report which effective fields
    // the rule change moves — union-vs-replace defaults, deny pruning,
    // profile composition. The simulated load only changes merge
    // semantics; declaration grammar stays at each file's declared
    // version, so a v3 document never gets rejected for carrying v3
    // syntax while the diff counts what v2 rules would have granted.
    let version_diff = if args.version_diff {
        Some(compute_version_diff(&args, policy_path, &env, &bound))
    } else {
        None
    };

    emit_resolved(&args, &bound, &diagnostics, version_diff.as_ref());
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
    version_diff: Option<&VersionDiff>,
) -> ! {
    match args.format {
        ResolveFormat::Kdl => {
            // stdout is the document; warnings, review markers, and the
            // provenance log go to stderr so `--format kdl` stays
            // re-loadable. `resolve` reports the markers without
            // enforcing them — the same listing
            // `MCP_WRIT_REVIEW_MODE=warn` would print, minus the gate.
            // The version-diff rides in `//` comments — KDL-tolerable,
            // still re-loadable.
            if let Some(d) = version_diff {
                for line in d.comment_lines() {
                    println!("// {line}");
                }
            }
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
            println!("{}", resolved_json(policy, diagnostics, version_diff));
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

/// One effective-field difference between the declared-rules load and
/// the simulated other-rules load.
struct VersionFieldDiff {
    field: String,
    /// Sorted effective value under the document's declared rules.
    declared: Vec<String>,
    /// Sorted effective value under the simulated other rules version.
    simulated: Vec<String>,
}

/// The `--version-diff` result: either the field list, or the simulated
/// load's failure (a document that the other rules version cannot
/// compose — e.g. strict-shape validation — is itself the finding).
enum VersionDiff {
    Diff {
        declared: u32,
        simulated: u32,
        fields: Vec<VersionFieldDiff>,
    },
    SimFailed {
        declared: u32,
        simulated: u32,
        reason: String,
    },
}

impl VersionDiff {
    /// `kdl`-mode rendering — one `//` comment header plus one line per
    /// moved field, safe to keep inline ahead of the document.
    fn comment_lines(&self) -> Vec<String> {
        let (declared, simulated) = match self {
            Self::Diff {
                declared,
                simulated,
                ..
            }
            | Self::SimFailed {
                declared,
                simulated,
                ..
            } => (*declared, *simulated),
        };
        let mut lines = Vec::new();
        match self {
            Self::Diff { fields, .. } => {
                lines.push(format!(
                    "version-diff: declared v{declared} vs simulated v{simulated} — \
                     {} field(s) differ",
                    fields.len()
                ));
                for d in fields {
                    lines.push(format!(
                        "version-diff: {}: v{declared}={:?} v{simulated}={:?}",
                        d.field, d.declared, d.simulated
                    ));
                }
            }
            Self::SimFailed { reason, .. } => {
                lines.push(format!(
                    "version-diff: simulated v{simulated} load failed: {reason}"
                ));
            }
        }
        lines
            .into_iter()
            .map(|l| {
                // Field values carry declared spellings — every code
                // point KDL counts as a newline (including U+2028/29,
                // which `sanitize_for_terminal` misses) must not end
                // the `//` comment and reparse as policy nodes.
                crate::termutil::escape_kdl_comment(&l)
            })
            .collect()
    }
}

/// Replay the load under the other composition-rules version and diff
/// the two effective policies field-by-field. Declared v3 simulates v2
/// (and vice versa); the diff says nothing when no effective field
/// moves — composition without overlaps looks identical either way.
fn compute_version_diff(
    args: &PolicyResolveArgs,
    policy_path: &Path,
    env: &str,
    declared: &crate::policy::Policy,
) -> VersionDiff {
    let declared_version = declared.version;
    let sim_version = if declared_version >= 3 { 2 } else { 3 };
    match load_kdl_policy_for_target_scanned_rules(
        policy_path,
        env,
        &ExecutionTarget::native(),
        Some(sim_version),
    )
    .and_then(|(p, _)| p.bind_to_server(args.server.as_deref()))
    {
        Ok(simulated) => {
            let a = effective_field_map(declared);
            let b = effective_field_map(&simulated);
            let mut fields = Vec::new();
            for (k, dv) in &a {
                let sv = b.get(k).cloned().unwrap_or_default();
                if *dv != sv {
                    fields.push(VersionFieldDiff {
                        field: k.clone(),
                        declared: dv.clone(),
                        simulated: sv,
                    });
                }
            }
            for (k, sv) in &b {
                if !a.contains_key(k) {
                    fields.push(VersionFieldDiff {
                        field: k.clone(),
                        declared: Vec::new(),
                        simulated: sv.clone(),
                    });
                }
            }
            VersionDiff::Diff {
                declared: declared_version,
                simulated: sim_version,
                fields,
            }
        }
        Err(e) => VersionDiff::SimFailed {
            declared: declared_version,
            simulated: sim_version,
            reason: crate::termutil::sanitize_for_terminal(&format!("{e}")),
        },
    }
}

/// Flatten a composed policy to `{field -> sorted values}` so the two
/// rules versions can be compared entry-for-entry. Only effective
/// grants and postures appear — declaration bookkeeping (`*_explicit`,
/// `replace` flags) is exactly what `--version-diff` abstracts away.
fn effective_field_map(policy: &crate::policy::Policy) -> BTreeMap<String, Vec<String>> {
    use crate::policy::EgressRule;
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut put = |k: &str, mut v: Vec<String>| {
        v.sort();
        v.dedup();
        m.insert(k.to_string(), v);
    };
    let scalar = |v: bool| vec![v.to_string()];

    put("defaults.filesystem.read-only", policy.fs.read_only.clone());
    put(
        "defaults.filesystem.read-write",
        policy.fs.read_write.clone(),
    );
    put(
        "defaults.filesystem.executable",
        policy.fs.executable.clone(),
    );
    put("defaults.filesystem.denied", policy.fs.denied_paths.clone());
    put(
        "defaults.filesystem.secret-overlay",
        scalar(policy.fs.secret_overlay),
    );
    put("defaults.syscalls.allowed", policy.syscalls.allowed.clone());
    put("defaults.syscalls.denied", policy.syscalls.denied.clone());
    put(
        "defaults.network.allow",
        policy
            .network
            .outbound
            .allowed
            .iter()
            .cloned()
            .chain(
                policy
                    .network
                    .outbound
                    .allowed_cidrs
                    .iter()
                    .map(|c| format!("cidr:{c}")),
            )
            .collect(),
    );
    put(
        "defaults.network.deny",
        policy
            .network
            .outbound
            .denied_hosts
            .iter()
            .cloned()
            .chain(
                policy
                    .network
                    .outbound
                    .denied_cidrs
                    .iter()
                    .map(|c| format!("cidr:{c}")),
            )
            .collect(),
    );
    put(
        "defaults.network.deny-all-others",
        scalar(policy.network.outbound.deny_all_others),
    );
    put(
        "defaults.network.inbound",
        scalar(policy.network.inbound.allow_listen),
    );
    put(
        "defaults.network.egress",
        policy
            .network
            .outbound
            .egress_rules
            .iter()
            .map(EgressRule::describe)
            .collect(),
    );
    put(
        "defaults.environment.allowed",
        policy.environment.allowed.clone(),
    );
    put(
        "defaults.environment.restrict",
        scalar(policy.environment.restrict && !policy.environment.inherit_parent),
    );

    for tool in &policy.tools {
        let key = match &tool.server {
            Some(s) => format!("server \"{s}\" tool \"{}\"", tool.name),
            None => format!("tool \"{}\"", tool.name),
        };
        put(&format!("{key}.allowed"), scalar(tool.allowed));
        if let Some(ref side) = tool.side_effect {
            put(&format!("{key}.side-effect"), vec![side.clone()]);
        }
        if let Some(ref fs) = tool.fs {
            put(
                &format!("{key}.filesystem.allowed"),
                fs.allowed_paths.clone(),
            );
            put(
                &format!("{key}.filesystem.read-only"),
                fs.read_only_paths.clone(),
            );
            put(
                &format!("{key}.filesystem.read-write"),
                fs.read_write_paths.clone(),
            );
            put(&format!("{key}.filesystem.denied"), fs.denied_paths.clone());
            if let Some(rp) = fs.require_path {
                put(&format!("{key}.filesystem.require-path"), scalar(rp));
            }
        }
        if let Some(ref sc) = tool.syscalls {
            put(&format!("{key}.syscalls.allowed"), sc.allowed.clone());
            put(&format!("{key}.syscalls.denied"), sc.denied.clone());
        }
        if let Some(ref net) = tool.network {
            put(
                &format!("{key}.network.allow"),
                net.allowed_hosts
                    .iter()
                    .cloned()
                    .chain(net.allowed_cidrs.iter().map(|c| format!("cidr:{c}")))
                    .collect(),
            );
            put(
                &format!("{key}.network.deny"),
                net.denied_hosts
                    .iter()
                    .cloned()
                    .chain(net.denied_cidrs.iter().map(|c| format!("cidr:{c}")))
                    .collect(),
            );
            put(
                &format!("{key}.network.egress"),
                net.egress_rules.iter().map(EgressRule::describe).collect(),
            );
        }
    }
    m
}

/// Serialize the resolved result as one JSON object.
fn resolved_json(
    policy: &crate::policy::Policy,
    diagnostics: &LoadDiagnostics,
    version_diff: Option<&VersionDiff>,
) -> String {
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
        )?;
        // `--version-diff` — present only when requested. `fields`
        // lists each effective field the other rules version moves
        // with both values; `simulated_error` stands in for the list
        // when the simulated load cannot complete.
        match version_diff {
            Some(VersionDiff::Diff {
                declared,
                simulated,
                fields,
            }) => f.member(
                "version_diff",
                nojson::object(|o| {
                    o.member("declared_version", *declared)?;
                    o.member("simulated_version", *simulated)?;
                    o.member(
                        "fields",
                        nojson::array(|a| {
                            for d in fields {
                                a.element(nojson::object(|e| {
                                    e.member(
                                        "field",
                                        crate::termutil::sanitize_for_terminal(&d.field).as_str(),
                                    )?;
                                    e.member(
                                        "declared",
                                        nojson::array(|v| {
                                            for i in &d.declared {
                                                v.element(
                                                    crate::termutil::sanitize_for_terminal(i)
                                                        .as_str(),
                                                )?;
                                            }
                                            Ok(())
                                        }),
                                    )?;
                                    e.member(
                                        "simulated",
                                        nojson::array(|v| {
                                            for i in &d.simulated {
                                                v.element(
                                                    crate::termutil::sanitize_for_terminal(i)
                                                        .as_str(),
                                                )?;
                                            }
                                            Ok(())
                                        }),
                                    )
                                }))?;
                            }
                            Ok(())
                        }),
                    )
                }),
            )?,
            Some(VersionDiff::SimFailed {
                declared,
                simulated,
                reason,
            }) => f.member(
                "version_diff",
                nojson::object(|o| {
                    o.member("declared_version", *declared)?;
                    o.member("simulated_version", *simulated)?;
                    o.member("simulated_error", reason.as_str())
                }),
            )?,
            None => {}
        }
        Ok(())
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
