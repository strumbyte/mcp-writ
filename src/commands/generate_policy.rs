use std::path::PathBuf;

use crate::cli::GenPolicyArgs;

use super::tracing_init::init_tracing;

pub async fn run_generate_policy(args: GenPolicyArgs) {
    init_tracing(args.verbose);

    let discovery = crate::legislator::source_bind::discover_from_argv(&args.command);
    let (capability, tool_caps, analyzed) = resolve_generate_capability(&args, &discovery);

    // Launch-target hashes are computed BEFORE live discovery executes the
    // workload: the analyzed bytes' digest is what gets pinned, and any
    // residual pathname hash here still sees pre-execution content. A server
    // that rewrites itself during tools/list can never make the draft
    // certify bytes the analysis skipped — at `run` the pin either matches
    // the current bytes or the launch is refused.
    let workload = crate::legislator::source_bind::workload_hashes(
        &args.command,
        &discovery,
        analyzed.as_ref(),
    );

    let fetched = if args.static_only {
        eprintln!(
            "INFO: generate-policy uses static inspection only (no server execution). \
             Pass --live-discovery to run tools/list, or --unsafe-unsandboxed-discovery \
             to also inherit the ambient environment."
        );
        None
    } else {
        eprintln!(
            "WARNING: generate-policy executes the MCP server to discover tools. \
             Discovery inherits a restricted environment (PATH + private TMPDIR). \
             Use --static-only to skip execution, or --unsafe-unsandboxed-discovery \
             to inherit the ambient environment."
        );
        let opts = crate::legislator::tools_list::DiscoveryOptions {
            restrict_environment: !args.unsafe_unsandboxed_discovery,
        };
        Some(
            crate::legislator::tools_list::fetch_tools_list_detailed_with(
                &args.command,
                None,
                &opts,
            )
            .await
            .unwrap_or_else(|e| {
                eprintln!(
                    "Error fetching tools list: {}",
                    crate::termutil::sanitize_for_terminal(&e.to_string())
                );
                std::process::exit(1);
            }),
        )
    };

    let tools = fetched.as_ref().map(|f| f.tools.as_slice()).unwrap_or(&[]);
    if let Some(ref fetched) = fetched {
        tracing::info!(
            protocol_version = %fetched.protocol_version,
            tool_count = fetched.tools.len(),
            "Legislator fetched tools/list"
        );
    }

    let intents = crate::legislator::heuristics::analyze_tools(tools);

    let validation = if discovery.skips_native_elf() {
        crate::legislator::cross_validator::cross_validate_source(&tool_caps, &intents)
    } else {
        crate::legislator::cross_validator::cross_validate(&capability, &intents)
    };

    let project_hint = crate::legislator::project_hints::resolve_project_dir_for_policy(
        args.project_dir.as_deref(),
        &args.command,
    )
    .and_then(|dir| {
        if !dir.exists() {
            if args.project_dir.is_some() {
                eprintln!(
                    "Error: Project directory does not exist: {}",
                    crate::termutil::sanitize_for_terminal(&dir.display().to_string())
                );
                std::process::exit(1);
            }
            return None;
        }
        Some(crate::legislator::project_hints::analyze_project(&dir))
    });

    let policy_kdl = crate::legislator::policy_generator::generate_policy(
        &validation,
        &capability,
        project_hint.as_ref(),
        tools,
        &workload,
    );

    match args.output {
        Some(path) => {
            crate::fspriv::write_file_atomic(&path, policy_kdl.as_bytes()).unwrap_or_else(|e| {
                eprintln!(
                    "Error writing policy: {}",
                    crate::termutil::sanitize_for_terminal(&e.to_string())
                );
                std::process::exit(1);
            });
            eprintln!("Policy draft written to {}", path.display());
        }
        None => print!("{policy_kdl}"),
    }

    if !args.self_test {
        return;
    }

    // Self-test is opt-in. Spawn is always Warden-backed with a restricted
    // environment. Discovery's --unsafe-unsandboxed-discovery is never reused.
    let _ = args.unsafe_unsandboxed_discovery;
    match crate::legislator::self_test::run_self_test(
        &policy_kdl,
        &args.command,
        crate::legislator::self_test::DEFAULT_TIMEOUT,
    )
    .await
    {
        Ok(report) => {
            crate::legislator::self_test::eprint_report(&report);
            std::process::exit(report.exit_code());
        }
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    }
}

/// The third tuple element binds the analysis to the bytes it actually
/// consumed: `Some` when a workload file was read (the native launch image
/// or the source payload), carrying its digest so `workload_hashes` pins
/// exactly those bytes instead of re-reading a path the executed payload
/// could have swapped.
fn resolve_generate_capability(
    args: &GenPolicyArgs,
    discovery: &crate::legislator::source_bind::PayloadDiscovery,
) -> (
    crate::inspector::profile::CapabilityProfile,
    Vec<crate::legislator::sinks::ToolCapability>,
    Option<crate::legislator::source_bind::AnalyzedDigest>,
) {
    use crate::inspector::profile::CapabilityProfile;
    use crate::legislator::source_bind::{AnalyzedDigest, PayloadKind};

    match &discovery.kind {
        PayloadKind::Native => {
            let binary_path = match args.binary_path.clone() {
                Some(p) => p,
                None => {
                    let argv0 = args.command.first().unwrap_or_else(|| {
                        eprintln!("Error: no command to run");
                        std::process::exit(1);
                    });
                    // Bare command names (env, cat, …) resolve through PATH —
                    // the analyzer and the draft must read the same file the
                    // runtime would spawn.
                    crate::workload::resolve_command_path(argv0)
                        .unwrap_or_else(|_| PathBuf::from(argv0))
                }
            };
            // The analysis read goes through the canonical spelling: a
            // symlinked binary still analyzes (the real object is read),
            // and `analyzed.path` names the same object `resolve_launch`
            // will bind at hash time.
            let binary_path = std::fs::canonicalize(&binary_path).unwrap_or(binary_path);
            let data = crate::fspriv::read_file_bounded(
                &binary_path,
                crate::inspector::MAX_ANALYZED_FILE_BYTES,
            )
            .unwrap_or_else(|e| {
                eprintln!(
                    "Error reading binary '{}': {}",
                    crate::termutil::sanitize_for_terminal(&binary_path.display().to_string()),
                    crate::termutil::sanitize_for_terminal(&e.to_string())
                );
                std::process::exit(1);
            });
            let capability = crate::inspector::profile::analyze(&data).unwrap_or_else(|e| {
                eprintln!(
                    "Error analyzing binary: {}",
                    crate::termutil::sanitize_for_terminal(&e.to_string())
                );
                std::process::exit(1);
            });
            // An explicit --binary-path is analyzed for capability only —
            // it does not stand in for the argv[0] launch image.
            let analyzed = AnalyzedDigest {
                path: binary_path,
                digest: crate::verifier::hash::hash_bytes(&data),
                binds_launch_image: args.binary_path.is_none(),
            };
            (capability, Vec::new(), Some(analyzed))
        }
        PayloadKind::Source { path, .. } => {
            eprintln!(
                "{}",
                crate::termutil::sanitize_for_terminal(
                    &crate::legislator::source_bind::native_skip_note(path)
                )
            );
            match crate::legislator::source_bind::analyze_source_path(path) {
                Ok(analysis) => {
                    for w in &analysis.warnings {
                        eprintln!("WARNING: {}", crate::termutil::sanitize_for_terminal(w));
                    }
                    let analyzed = AnalyzedDigest {
                        path: analysis.path.clone(),
                        digest: analysis.payload_digest.clone(),
                        binds_launch_image: false,
                    };
                    (CapabilityProfile::empty(), analysis.tools, Some(analyzed))
                }
                Err(e) => {
                    eprintln!(
                        "WARNING: failed to parse source '{}': {} (fail-secure: no native fallback)",
                        crate::termutil::sanitize_for_terminal(&path.display().to_string()),
                        crate::termutil::sanitize_for_terminal(&e.to_string())
                    );
                    (CapabilityProfile::empty(), Vec::new(), None)
                }
            }
        }
        PayloadKind::InlineEval { flag, interpreter } => {
            eprintln!(
                "WARNING: {} {} is not statically parseable; skipping source AST and native binary capability",
                crate::termutil::sanitize_for_terminal(&interpreter.to_string()),
                crate::termutil::sanitize_for_terminal(flag)
            );
            (CapabilityProfile::empty(), Vec::new(), None)
        }
        PayloadKind::Unresolved { reason } => {
            eprintln!(
                "WARNING: {}; skipping native binary capability",
                crate::termutil::sanitize_for_terminal(reason)
            );
            (CapabilityProfile::empty(), Vec::new(), None)
        }
    }
}
