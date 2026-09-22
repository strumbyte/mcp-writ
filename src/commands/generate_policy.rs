use std::path::PathBuf;

use crate::cli::GenPolicyArgs;

use super::tracing_init::init_tracing;

pub async fn run_generate_policy(args: GenPolicyArgs) {
    init_tracing(args.verbose);

    let discovery = crate::legislator::source_bind::discover_from_argv(&args.command);
    let (capability, tool_caps) = resolve_generate_capability(&args, &discovery);

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
                eprintln!("Error fetching tools list: {e}");
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
                eprintln!("Error: Project directory does not exist: {}", dir.display());
                std::process::exit(1);
            }
            return None;
        }
        Some(crate::legislator::project_hints::analyze_project(&dir))
    });

    let workload = crate::legislator::source_bind::workload_hashes(&args.command, &discovery);

    let policy_kdl = crate::legislator::policy_generator::generate_policy(
        &validation,
        &capability,
        project_hint.as_ref(),
        tools,
        &workload,
    );

    match args.output {
        Some(path) => {
            std::fs::write(&path, &policy_kdl).unwrap_or_else(|e| {
                eprintln!("Error writing policy: {e}");
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

fn resolve_generate_capability(
    args: &GenPolicyArgs,
    discovery: &crate::legislator::source_bind::PayloadDiscovery,
) -> (
    crate::inspector::profile::CapabilityProfile,
    Vec<crate::legislator::sinks::ToolCapability>,
) {
    use crate::inspector::profile::CapabilityProfile;
    use crate::legislator::source_bind::PayloadKind;

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
            let data = std::fs::read(&binary_path).unwrap_or_else(|e| {
                eprintln!("Error reading binary '{}': {e}", binary_path.display());
                std::process::exit(1);
            });
            let capability = crate::inspector::profile::analyze(&data).unwrap_or_else(|e| {
                eprintln!("Error analyzing binary: {e}");
                std::process::exit(1);
            });
            (capability, Vec::new())
        }
        PayloadKind::Source { path, .. } => {
            eprintln!("{}", crate::legislator::source_bind::native_skip_note(path));
            match crate::legislator::source_bind::analyze_source_path(path) {
                Ok(analysis) => {
                    for w in &analysis.warnings {
                        eprintln!("WARNING: {w}");
                    }
                    (CapabilityProfile::empty(), analysis.tools)
                }
                Err(e) => {
                    eprintln!(
                        "WARNING: failed to parse source '{}': {e} (fail-secure: no native fallback)",
                        path.display()
                    );
                    (CapabilityProfile::empty(), Vec::new())
                }
            }
        }
        PayloadKind::InlineEval { flag, interpreter } => {
            eprintln!(
                "WARNING: {interpreter} {flag} is not statically parseable; skipping source AST and native binary capability"
            );
            (CapabilityProfile::empty(), Vec::new())
        }
        PayloadKind::Unresolved { reason } => {
            eprintln!("WARNING: {reason}; skipping native binary capability");
            (CapabilityProfile::empty(), Vec::new())
        }
    }
}
