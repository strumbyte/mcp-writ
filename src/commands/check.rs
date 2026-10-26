//! `mcp-writ check` — policy drift re-verification.
//!
//! Re-reads a policy's declared integrity pins and re-verifies them
//! against the current artifacts — the `generate-policy` digests are
//! computed on one host and drift when the workload, interpreter,
//! lockfile, image, or tools/list changes under it:
//!
//! - `binary-hash` / `entrypoint-hash` / `lockfile-hash` — the pin's
//!   `target=` file is re-hashed with the same streaming SHA-256 the
//!   launch verifier uses ([`crate::verifier::hash::hash_file`]);
//! - `docker-manifest-hash` — the pin's `target=` is an image
//!   reference: inspected through the container engine and the
//!   manifest digest compared, the same comparison `run-image`
//!   performs, and bounded like `plan`'s `image.inspect` — a wedged
//!   daemon reports `unreadable`, it does not hang the check. A
//!   `target=` naming a file is hashed as a file instead — the same
//!   entry under a native `run` is file-hashed like any other pin
//!   (a `target=` whose file was deleted since the pin was written is
//!   an image reference by this rule);
//! - `tools-list-hash` — only when `-- <command>` names the server's
//!   launch argv: the server is spawned exactly like
//!   `generate-policy` live discovery (restricted environment, no OS
//!   sandbox) and the fresh `tools/list` is canonicalized through
//!   [`crate::verifier::tools_diff::hash_tools_list`]. Without a
//!   command the pin is `unverified`, never skipped.
//! - launch binding — `-- <command>` also re-runs the path
//!   correspondence `bind_launched_workload` enforces before a native
//!   `run` spawn: a `binary-hash`/`entrypoint-hash` target must
//!   canonicalize to the resolved executable (an entrypoint may
//!   instead name its first payload argument). A content-verified pin
//!   whose target does not correspond is `mismatch` — the verdict
//!   `run` refuses the launch with.
//! - `// REVIEW` markers left by `generate-policy` are reported in-band
//!   (`review_markers`) — `check` never reads `MCP_WRIT_REVIEW_MODE`;
//!   a marked policy is `drifted` here regardless.
//!
//! The machine-readable [`CheckReport`] goes to stdout, the human
//! summary and remediation to stderr, and the process exits with the
//! fixed status code (`clean` 0 / `drifted` 1 / `invalid` 2 /
//! `error` 1) — the `plan` convention, so a CI gate treats a drifted
//! policy like a blocked launch.

use std::path::Path;

use crate::audit_log::now_iso8601_millis;
use crate::cli::CheckArgs;
use crate::enforcement::{
    CHECK_REPORT_SCHEMA_VERSION, CheckReport, CheckStatus, PinResult, PinStatus,
    PolicyWarningRecord, ReviewMarkerRecord,
};
use crate::error::PolicyError;
use crate::execution::ExecutionTarget;
use crate::legislator::tools_list::{DiscoveryOptions, fetch_tools_list_detailed_with};
use crate::policy::kdl_loader::load_kdl_policy_for_target_scanned;
use crate::policy::{HashType, Policy};
use crate::termutil::sanitize_for_terminal;

/// Run `check` and exit the process with the status-mapped code.
pub async fn run_check(args: CheckArgs) -> ! {
    crate::commands::tracing_init::init_tracing(args.verbose);
    let report_path = args.report.clone();
    let report = evaluate(args).await;
    emit_and_exit(&report, report_path.as_deref());
}

fn base_report() -> CheckReport {
    CheckReport {
        schema_version: CHECK_REPORT_SCHEMA_VERSION,
        created_at: now_iso8601_millis(),
        status: CheckStatus::Clean,
        reason_code: None,
        reason: None,
        target: ExecutionTarget::native(),
        policy: None,
        pins: Vec::new(),
        review_markers: Vec::new(),
        warnings: Vec::new(),
        remediation: Vec::new(),
    }
}

fn invalid_report(reason: String) -> CheckReport {
    let mut report = base_report();
    report.status = CheckStatus::Invalid;
    report.reason_code = Some("invalid_input");
    report.reason = Some(reason.clone());
    report.remediation = vec![format!("fix the invocation: {reason}")];
    report
}

/// Evaluate the parsed `check` arguments into a [`CheckReport`].
async fn evaluate(args: CheckArgs) -> CheckReport {
    if let Some(msg) = args.invalid_input {
        return invalid_report(msg);
    }
    let Some(policy_path) = args.policy.as_deref() else {
        // parse_check_args already records a missing --policy as
        // invalid_input; this arm is only a defensive default.
        return invalid_report("check requires --policy <path>".to_string());
    };

    // Load the same way a launch does (extends/include/when resolved,
    // target-validated) — but keep the REVIEW markers and load warnings
    // in-band instead of enforcing MCP_WRIT_REVIEW_MODE /
    // MCP_WRIT_REPLACE_MODE: a drift report that dies at load would
    // hide the findings it exists to surface.
    let env = std::env::var("MCP_WRIT_ENV").unwrap_or_default();
    let (policy, diagnostics) =
        match load_kdl_policy_for_target_scanned(policy_path, &env, &ExecutionTarget::native()) {
            Ok(loaded) => loaded,
            Err(e) => {
                let mut report = base_report();
                report.status = CheckStatus::Invalid;
                match &e {
                    PolicyError::FileRead(_) => {
                        report.reason_code = Some("policy_not_found");
                    }
                    _ => {
                        report.reason_code = Some("policy_invalid");
                    }
                }
                let detail = format!("{}: {e}", policy_path.display());
                report.reason = Some(detail.clone());
                report.remediation = vec![match report.reason_code {
                    Some("policy_not_found") => {
                        format!("restore the policy file or fix --policy: {detail}")
                    }
                    _ => format!("fix the policy so it loads: {detail}"),
                }];
                return report;
            }
        };

    // Bind exactly like `run`/`plan` do — a multi-server policy needs
    // `--server`, and the bound view is the honest scope of the check.
    let bound = match policy.bind_to_server(args.server.as_deref()) {
        Ok(b) => b,
        Err(e) => {
            let mut report = base_report();
            report.status = CheckStatus::Invalid;
            report.reason_code = Some("policy_bind_failed");
            report.reason = Some(e.to_string());
            report.remediation = vec![format!(
                "pass --server <name> naming one of: {}",
                policy.declared_servers().join(", ")
            )];
            return report;
        }
    };

    let mut report = base_report();
    report.policy = bound.audit_context().ok();
    report.review_markers = diagnostics
        .review_markers
        .iter()
        .map(|m| {
            // Classify the raw marker text — sanitizing first could
            // rewrite bytes the head-match rules key on.
            let kind = crate::policy::review::MarkerKind::classify(&m.text);
            ReviewMarkerRecord {
                file: m.path.display().to_string(),
                line: m.line,
                text: sanitize_for_terminal(&m.text),
                kind: kind.as_str(),
                why: kind.why(),
                how: kind.how(),
            }
        })
        .collect();
    report.warnings = diagnostics
        .warnings
        .iter()
        .map(|w| PolicyWarningRecord {
            kind: w.kind.as_str().to_string(),
            file: w.file.display().to_string(),
            line: w.line,
            message: sanitize_for_terminal(&w.message),
        })
        .collect();

    check_hash_pins(&bound, args.engine, &mut report.pins).await;
    check_launch_binding(&bound, &args.command, &mut report.pins);
    check_tools_list_pins(&bound, &args.command, &mut report.pins).await;

    finalize(report)
}

/// Every `hash_entries` pin, in policy order. `binary-hash` /
/// `entrypoint-hash` / `lockfile-hash` — and a `docker-manifest-hash`
/// whose `target=` names a file — are re-hashed with the launch
/// verifier's hash function: the check a native `run` performs on every
/// entry (`verify_server_hashes` treats every `target=` as a file). A
/// `docker-manifest-hash` `target=` that is not a file is an image
/// reference: inspected through the engine and the repo digest
/// compared, the same check `run-image` performs before launch — and
/// bounded like `plan`'s `image.inspect`, so a wedged daemon is a
/// failed pin rather than a hung check. `is_file` is evaluated now, at
/// check time: a `target=` whose file was deleted since the pin was
/// written lands on the inspect side. No pull: a missing image or
/// engine is reported, never worked around.
async fn check_hash_pins(
    policy: &Policy,
    engine_kind: Option<crate::container::engine::EngineKind>,
    pins: &mut Vec<PinResult>,
) {
    // The engine resolves lazily on the first image-reference pin and
    // its result is reused — a policy whose docker pins all name files
    // (or carries none) never touches it, and a resolution failure is
    // reported on every image pin alike.
    let mut engine = None;
    for entry in &policy.hash_entries {
        if entry.hash_type != HashType::DockerManifest || Path::new(&entry.target).is_file() {
            pins.push(file_pin_result(entry));
            continue;
        }
        let pin = match engine
            .get_or_insert_with(|| crate::container::engine::resolve_engine(engine_kind))
        {
            Ok(engine) => image_pin_result(engine.as_ref(), entry).await,
            Err(e) => PinResult {
                server: entry.server_name.clone(),
                pin_type: entry.hash_type.as_str(),
                target: entry.target.clone(),
                status: PinStatus::Unverified,
                expected: entry.hash_value.clone(),
                actual: None,
                detail: Some(format!("container engine unavailable: {e}")),
            },
        };
        pins.push(pin);
    }
}

/// Re-hash one pin's `target=` as a file — the verification a native
/// `run` performs on every entry, `docker-manifest-hash` included.
fn file_pin_result(entry: &crate::policy::HashEntry) -> PinResult {
    match crate::verifier::hash::hash_file(Path::new(&entry.target)) {
        Ok(actual) if actual == entry.hash_value => PinResult {
            server: entry.server_name.clone(),
            pin_type: entry.hash_type.as_str(),
            target: entry.target.clone(),
            status: PinStatus::Verified,
            expected: entry.hash_value.clone(),
            actual: Some(actual),
            detail: None,
        },
        Ok(actual) => PinResult {
            server: entry.server_name.clone(),
            pin_type: entry.hash_type.as_str(),
            target: entry.target.clone(),
            status: PinStatus::Mismatch,
            expected: entry.hash_value.clone(),
            actual: Some(actual),
            detail: None,
        },
        Err(e) => PinResult {
            server: entry.server_name.clone(),
            pin_type: entry.hash_type.as_str(),
            target: entry.target.clone(),
            status: PinStatus::Unreadable,
            expected: entry.hash_value.clone(),
            actual: None,
            detail: Some(e.to_string()),
        },
    }
}

/// Whether `pin` is `entry`'s report row — the server, kind, and
/// target all name the same pin, and the row is still `verified` (a
/// content-failure verdict is kept). The bound policy is single-server,
/// but the server match keeps the row lookup honest if this check is
/// ever run against an unbound view.
fn verified_row_for(pin: &PinResult, entry: &crate::policy::HashEntry) -> bool {
    pin.server == entry.server_name
        && pin.pin_type == entry.hash_type.as_str()
        && pin.target == entry.target
        && pin.status == PinStatus::Verified
}

/// Downgrade `entry`'s verified pin row(s) to `mismatch` carrying the
/// binding failure — the verdict `run` would hand the launch. A pin
/// already reporting content drift keeps its verdict.
fn mark_binding_failure(pins: &mut [PinResult], entry: &crate::policy::HashEntry, detail: &str) {
    for pin in pins.iter_mut() {
        if verified_row_for(pin, entry) {
            pin.status = PinStatus::Mismatch;
            pin.detail = Some(detail.to_string());
        }
    }
}

/// `-- <command>` doubles as the launch argv for identity binding —
/// the same path correspondence `bind_launched_workload` enforces
/// before a native `run` spawn: a `binary-hash`/`entrypoint-hash`
/// `target=` must canonicalize to the resolved executable (an
/// entrypoint may instead name its first payload argument), an
/// interpreted launch needs a binary pin on the interpreter, and the
/// interpreter's option grammar must be modeled. A content-verified
/// pin that fails a binding rule is `mismatch` — the launch would be
/// refused. Without a command the launch argv is unknown, so only pin
/// contents are re-verified; a policy with hash entries but no
/// identity pin cannot bind any launch — that completeness refusal is
/// `plan`'s `hash.identity` check, not drift.
fn check_launch_binding(policy: &Policy, command: &[String], pins: &mut [PinResult]) {
    use crate::workload::{
        argv_contains_inline_eval_with_exe, exe_grammar_modeled, first_payload_arg_with_exe,
        payload_boundary_blocker_with_exe, same_file,
    };

    let identity: Vec<_> = policy
        .hash_entries
        .iter()
        .filter(|e| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint))
        .collect();
    if command.is_empty() || identity.is_empty() {
        return;
    }

    // Resolve `argv[0]` the way `plan`/`run` do for a hashed policy:
    // `#!` expands to the interpreter launch the kernel would perform,
    // so `exe` is the image `binary-hash` must pin.
    let argv0 = command[0].as_str();
    let (argv, exe) = match crate::workload::resolve_launch(argv0, true) {
        Ok(resolution) => (resolution.into_argv(command), resolution.exe),
        Err(e) => {
            for entry in &identity {
                for pin in pins.iter_mut() {
                    if verified_row_for(pin, entry) {
                        pin.status = PinStatus::Unverified;
                        pin.detail = Some(format!(
                            "launch argv[0] '{argv0}' cannot be resolved: {e} — \
                             identity binding was not checked"
                        ));
                    }
                }
            }
            return;
        }
    };

    if argv_contains_inline_eval_with_exe(&argv, Some(&exe)) {
        for entry in &identity {
            mark_binding_failure(
                pins,
                entry,
                "the launch argv uses inline evaluation — evaluated argv text is \
                 not a hash-bindable workload; `run` refuses at binding",
            );
        }
        return;
    }

    let payload_arg = first_payload_arg_with_exe(&argv, Some(&exe));
    let at_exe =
        |entry: &crate::policy::HashEntry| same_file(Path::new(&entry.target), exe.as_path());
    let at_payload = |entry: &crate::policy::HashEntry| {
        entry.hash_type == HashType::Entrypoint
            && payload_arg.is_some_and(|arg| same_file(Path::new(arg), Path::new(&entry.target)))
    };

    let has_binary = identity.iter().any(|e| e.hash_type == HashType::Binary);
    let matched_exe = identity.iter().any(|e| at_exe(e));
    let matched_binary = identity
        .iter()
        .any(|e| e.hash_type == HashType::Binary && at_exe(e));
    let payload_bound: Vec<_> = identity
        .iter()
        .filter(|e| !at_exe(e) && at_payload(e))
        .copied()
        .collect();

    // The same refusal order `bind_launched_workload` applies — each
    // refusal marks the pins it implicates.
    if has_binary && !matched_exe {
        for entry in &identity {
            mark_binding_failure(
                pins,
                entry,
                &format!(
                    "no binary-hash/entrypoint-hash target canonicalizes to the \
                     resolved executable '{}' — `run` refuses at binding",
                    exe.display()
                ),
            );
        }
        return;
    }

    let mut entrypoint_failed = false;
    for entry in identity
        .iter()
        .filter(|e| e.hash_type == HashType::Entrypoint && !at_exe(e) && !at_payload(e))
    {
        let reason = match payload_boundary_blocker_with_exe(&argv, Some(&exe)) {
            Some(flag) => format!(
                "entrypoint-hash target '{}' cannot bind — option '{flag}' leaves \
                 the payload boundary ambiguous",
                entry.target
            ),
            None => format!(
                "entrypoint-hash target '{}' is not the launched executable or its \
                 first payload argument",
                entry.target
            ),
        };
        mark_binding_failure(pins, entry, &format!("{reason} — `run` refuses at binding"));
        entrypoint_failed = true;
    }
    if entrypoint_failed {
        return;
    }

    if !payload_bound.is_empty() && !matched_binary {
        for entry in &payload_bound {
            mark_binding_failure(
                pins,
                entry,
                &format!(
                    "an entrypoint-hash pins the payload script, but no binary-hash \
                     binds the resolved interpreter '{}' — `run` refuses at binding",
                    exe.display()
                ),
            );
        }
        return;
    }
    if !payload_bound.is_empty() && !exe_grammar_modeled(&argv, Some(&exe)) {
        for entry in &payload_bound {
            mark_binding_failure(
                pins,
                entry,
                &format!(
                    "an entrypoint-hash pins the payload script, but the resolved \
                     executable '{}' has no modeled option grammar — the payload \
                     boundary cannot be proven for a renamed or unmodeled \
                     interpreter; `run` refuses at binding",
                    exe.display()
                ),
            );
        }
    }
}

/// One image-reference `docker-manifest-hash`: the local inspect and
/// repo-digest comparison `run-image` performs before launch, bounded
/// like `plan`'s `image.inspect` (`engine.rs` bounds only the post-exit
/// drain, never `wait`) — a wedged daemon makes the pin `unreadable`,
/// it does not hang the check.
async fn image_pin_result(
    engine: &dyn crate::container::engine::ContainerEngine,
    entry: &crate::policy::HashEntry,
) -> PinResult {
    let inspected = match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::container::inspect::inspect_image(engine, &entry.target),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => Err(crate::error::ContainerError::InspectExec(format!(
            "{} image inspect timed out after 5s",
            engine.name()
        ))),
    };
    match inspected {
        Ok(meta) => match meta.digest {
            Some(actual) if actual == entry.hash_value => PinResult {
                server: entry.server_name.clone(),
                pin_type: entry.hash_type.as_str(),
                target: entry.target.clone(),
                status: PinStatus::Verified,
                expected: entry.hash_value.clone(),
                actual: Some(actual),
                detail: None,
            },
            // No repo digest: a locally built or imported image carries
            // no manifest digest to compare — the pin could not be
            // evaluated, it did not mismatch.
            None => PinResult {
                server: entry.server_name.clone(),
                pin_type: entry.hash_type.as_str(),
                target: entry.target.clone(),
                status: PinStatus::Unverified,
                expected: entry.hash_value.clone(),
                actual: None,
                detail: Some(
                    "engine inspect returned no repository digest — a \
                     locally built or imported image has no manifest \
                     digest to compare against the pin"
                        .to_string(),
                ),
            },
            Some(actual) => PinResult {
                server: entry.server_name.clone(),
                pin_type: entry.hash_type.as_str(),
                target: entry.target.clone(),
                status: PinStatus::Mismatch,
                expected: entry.hash_value.clone(),
                actual: Some(actual),
                detail: None,
            },
        },
        Err(e) => PinResult {
            server: entry.server_name.clone(),
            pin_type: entry.hash_type.as_str(),
            target: entry.target.clone(),
            status: PinStatus::Unreadable,
            expected: entry.hash_value.clone(),
            actual: None,
            detail: Some(e.to_string()),
        },
    }
}

/// `tools-list-hash` — only exercised when `-- <command>` fetches a
/// fresh `tools/list` (the same restricted-environment spawn
/// `generate-policy` live discovery uses). No command ⇒ `unverified`:
/// a pin the check could not run is drift, not a pass.
async fn check_tools_list_pins(policy: &Policy, command: &[String], pins: &mut Vec<PinResult>) {
    if policy.tools_list_hashes.is_empty() {
        return;
    }
    if command.is_empty() {
        for entry in &policy.tools_list_hashes {
            pins.push(PinResult {
                server: entry.server_name.clone(),
                pin_type: "tools-list-hash",
                target: "tools/list".to_string(),
                status: PinStatus::Unverified,
                expected: entry.hash_value.clone(),
                actual: None,
                detail: Some(
                    "no tools/list source — pass `-- <command>` with the server's \
                     launch argv to fetch it"
                        .to_string(),
                ),
            });
        }
        return;
    }

    let fetched = fetch_tools_list_detailed_with(
        command,
        None,
        &DiscoveryOptions {
            restrict_environment: true,
        },
    )
    .await;
    let tools = match fetched {
        Ok(fetch) => fetch.tools,
        Err(e) => {
            for entry in &policy.tools_list_hashes {
                pins.push(PinResult {
                    server: entry.server_name.clone(),
                    pin_type: "tools-list-hash",
                    target: "tools/list".to_string(),
                    status: PinStatus::Unverified,
                    expected: entry.hash_value.clone(),
                    actual: None,
                    detail: Some(format!("tools/list fetch failed: {e}")),
                });
            }
            return;
        }
    };

    // The verifier's own canonical hash — `verify_tools_list` compares
    // the same digest; canonicalization failure is fail-closed there,
    // so it reads as `mismatch`, the verdict `run` would hand the
    // session.
    let actual = crate::verifier::tools_diff::hash_tools_list(&tools);
    for entry in &policy.tools_list_hashes {
        let pin = match &actual {
            Ok(actual) if *actual == entry.hash_value => PinResult {
                server: entry.server_name.clone(),
                pin_type: "tools-list-hash",
                target: "tools/list".to_string(),
                status: PinStatus::Verified,
                expected: entry.hash_value.clone(),
                actual: Some(actual.clone()),
                detail: None,
            },
            Ok(actual) => PinResult {
                server: entry.server_name.clone(),
                pin_type: "tools-list-hash",
                target: "tools/list".to_string(),
                status: PinStatus::Mismatch,
                expected: entry.hash_value.clone(),
                actual: Some(actual.clone()),
                detail: None,
            },
            Err(e) => PinResult {
                server: entry.server_name.clone(),
                pin_type: "tools-list-hash",
                target: "tools/list".to_string(),
                status: PinStatus::Mismatch,
                expected: entry.hash_value.clone(),
                actual: None,
                detail: Some(format!(
                    "tools/list could not be canonicalized for hashing (fail-closed): {e}"
                )),
            },
        };
        pins.push(pin);
    }
}

/// Fold the per-pin outcomes and REVIEW markers into the report's
/// status, reason, and remediation. Order of precedence: an actual
/// mismatch outranks a missing artifact, which outranks a pin the check
/// could not run, which outranks unresolved markers.
fn finalize(mut report: CheckReport) -> CheckReport {
    let count = |s: PinStatus| report.pins.iter().filter(|p| p.status == s).count();
    let mismatched = count(PinStatus::Mismatch);
    let unreadable = count(PinStatus::Unreadable);
    let unverified = count(PinStatus::Unverified);
    let markers = report.review_markers.len();

    let mut remediation = Vec::new();
    let mut parts = Vec::new();
    let reason_code = if mismatched > 0 {
        parts.push(format!("{mismatched} pin(s) mismatched"));
        remediation.push(
            "re-pin from a reviewed diff: regenerate into a separate file on the \
             deployment host, review the change, and update the pin — never \
             resolve a mismatch by just deleting it"
                .to_string(),
        );
        Some("hash_mismatch")
    } else if unreadable > 0 {
        parts.push(format!("{unreadable} pin target(s) unreadable"));
        remediation.push(
            "restore the pinned files/images or fix their `target=` paths, then \
             re-run check"
                .to_string(),
        );
        Some("target_unreadable")
    } else if unverified > 0 {
        parts.push(format!("{unverified} pin(s) could not be verified"));
        remediation.push(
            "tools-list-hash pins need `-- <command>` to re-fetch tools/list; \
             docker-manifest-hash pins need a resolvable container engine \
             (--engine) and an image carrying a repo digest — a locally built \
             image has none"
                .to_string(),
        );
        Some("pin_unverified")
    } else {
        None
    };
    if markers > 0 {
        parts.push(format!("{markers} unresolved REVIEW marker(s)"));
        // One next-action per marker kind present, in first-seen order —
        // the kind's `how` is the representative resolution.
        for kind in marker_kinds_in_order(&report.review_markers) {
            remediation.push(format!(
                "{kind}: {}",
                first_how(&report.review_markers, kind)
            ));
        }
        remediation.push(
            "delete each resolved `// REVIEW` comment — \
             `MCP_WRIT_REVIEW_MODE=refuse` makes a marked policy fail to load"
                .to_string(),
        );
    }

    if let (None, 0) = (reason_code, markers) {
        report.status = CheckStatus::Clean;
    } else {
        report.status = CheckStatus::Drifted;
        report.reason_code = reason_code.or(Some("unresolved_review"));
        report.reason = Some(parts.join("; "));
        report.remediation = remediation;
    }
    report
}

/// The marker kinds present, in first-seen order — one entry per kind
/// so the summary can group and the remediation can list one action
/// each.
fn marker_kinds_in_order(markers: &[ReviewMarkerRecord]) -> Vec<&'static str> {
    let mut kinds: Vec<&'static str> = Vec::new();
    for m in markers {
        if !kinds.contains(&m.kind) {
            kinds.push(m.kind);
        }
    }
    kinds
}

/// The `how` text of the first marker of `kind` — identical across the
/// group since `how` is fixed per kind.
fn first_how(markers: &[ReviewMarkerRecord], kind: &'static str) -> &'static str {
    markers
        .iter()
        .find(|m| m.kind == kind)
        .map(|m| m.how)
        .unwrap_or("")
}

/// Human summary + remediation on stderr.
fn print_summary(report: &CheckReport) {
    match report.status {
        CheckStatus::Clean => {
            let verified = report
                .pins
                .iter()
                .filter(|p| p.status == PinStatus::Verified)
                .count();
            if report.pins.is_empty() {
                eprintln!("check: clean — policy carries no integrity pins or REVIEW markers");
            } else {
                eprintln!("check: clean — {verified} pin(s) verified, no REVIEW markers");
            }
        }
        status => {
            // Policy- and error-derived strings (pin targets, server
            // names, load-error details, marker file paths) are
            // sanitized like the marker text and every other terminal
            // surface — a policy file controls their bytes.
            let reason = report.reason.as_deref().unwrap_or("(no detail)");
            eprintln!(
                "check: {status} — {}",
                sanitize_for_terminal(reason),
                status = status.as_str()
            );
            for pin in &report.pins {
                if pin.status == PinStatus::Verified {
                    continue;
                }
                let detail = pin
                    .detail
                    .as_deref()
                    .map(|d| format!(" ({})", sanitize_for_terminal(d)))
                    .unwrap_or_default();
                let actual = pin
                    .actual
                    .as_deref()
                    .map(|a| format!(" actual={}", sanitize_for_terminal(a)))
                    .unwrap_or_default();
                eprintln!(
                    "  {} {} '{}' → {}{}{}",
                    sanitize_for_terminal(&pin.server),
                    pin.pin_type,
                    sanitize_for_terminal(&pin.target),
                    pin.status.as_str(),
                    actual,
                    detail
                );
            }
            // Each marker shows its location and kind, then the kind's
            // why and how on the next lines. A kind with several markers
            // collapses to a count, a capped location list, and the
            // guidance once — a 12-tool dispatcher draft should not
            // repeat the same advice a dozen times.
            const PER_KIND_SHOWN: usize = 8;
            for kind in marker_kinds_in_order(&report.review_markers) {
                let group: Vec<&ReviewMarkerRecord> = report
                    .review_markers
                    .iter()
                    .filter(|m| m.kind == kind)
                    .collect();
                if group.len() == 1 {
                    let marker = group[0];
                    eprintln!(
                        "  {}:{}: {}",
                        sanitize_for_terminal(&marker.file),
                        marker.line,
                        marker.text
                    );
                    eprintln!("    kind: {kind}");
                } else {
                    eprintln!("  {kind} ({} marker(s)):", group.len());
                    for marker in group.iter().take(PER_KIND_SHOWN) {
                        eprintln!(
                            "    {}:{}: {}",
                            sanitize_for_terminal(&marker.file),
                            marker.line,
                            marker.text
                        );
                    }
                    if group.len() > PER_KIND_SHOWN {
                        eprintln!("    … {} more marker(s)", group.len() - PER_KIND_SHOWN);
                    }
                }
                if let Some(first) = group.first() {
                    eprintln!("    why: {}", first.why);
                    eprintln!("    how: {}", first.how);
                }
            }
        }
    }
    for (i, step) in report.remediation.iter().enumerate() {
        eprintln!("  {}. {}", i + 1, sanitize_for_terminal(step));
    }
}

/// Emit `report` and exit with [`CheckStatus::exit_code`].
///
/// Without `--report` the JSON result goes to stdout — `check` owns
/// stdout outright. With `--report` the JSON goes to the file; a write
/// failure is itself a result: status `error` (exit 1),
/// machine-readable on stdout.
fn emit_and_exit(report: &CheckReport, report_path: Option<&Path>) -> ! {
    let Some(path) = report_path else {
        println!("{}", report.to_json());
        print_summary(report);
        std::process::exit(report.status.exit_code());
    };

    match crate::fspriv::write_file_atomic(path, report.to_json().as_bytes()) {
        Ok(()) => {
            eprintln!("check report written to {}", path.display());
            print_summary(report);
            std::process::exit(report.status.exit_code());
        }
        Err(e) => {
            let err = CheckReport {
                schema_version: CHECK_REPORT_SCHEMA_VERSION,
                created_at: now_iso8601_millis(),
                status: CheckStatus::Error,
                reason_code: Some("report_write_failed"),
                reason: Some(format!(
                    "failed to write check report to '{}': {e}",
                    path.display()
                )),
                target: report.target.clone(),
                policy: report.policy.clone(),
                pins: report.pins.clone(),
                review_markers: report.review_markers.clone(),
                warnings: report.warnings.clone(),
                remediation: vec![format!(
                    "fix the --report destination '{}': {e}",
                    path.display()
                )],
            };
            // The requested destination failed; stdout remains as the
            // fallback machine channel.
            println!("{}", err.to_json());
            eprintln!(
                "Error: failed to write check report to '{}': {e}",
                path.display()
            );
            std::process::exit(CheckStatus::Error.exit_code());
        }
    }
}
