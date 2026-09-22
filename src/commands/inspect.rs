use crate::cli::{InspectArgs, OutputFormat};

use super::tracing_init::init_tracing;

pub fn run_inspect(args: InspectArgs) {
    init_tracing(args.verbose);

    let discovery = if args.command.is_empty() {
        crate::legislator::source_bind::discover_from_path(&args.binary_path)
    } else {
        crate::legislator::source_bind::discover_from_argv(&args.command)
    };
    if discovery.skips_native_elf() {
        run_inspect_source(&args, discovery);
        return;
    }

    let data = std::fs::read(&args.binary_path).unwrap_or_else(|e| {
        eprintln!("Error reading binary '{}': {e}", args.binary_path.display());
        std::process::exit(1);
    });

    let profile = crate::inspector::profile::analyze(&data).unwrap_or_else(|e| {
        eprintln!("Error analyzing binary: {e}");
        std::process::exit(1);
    });

    let output = if let Some(ref dir) = args.project_dir {
        // Verify the project directory exists before analyzing
        if !std::path::Path::exists(dir) {
            eprintln!("Error: Project directory does not exist: {}", dir.display());
            std::process::exit(1);
        }
        let hint = crate::legislator::project_hints::analyze_project(dir);
        match args.format {
            OutputFormat::Human => {
                let mut out = crate::inspector::profile::format_human(&profile);
                out.push('\n');
                out.push_str(&crate::legislator::project_hints::format_project_hints(
                    &hint,
                ));
                out
            }
            OutputFormat::Json => super::inspect_format::format_json_with_project(&profile, &hint),
            OutputFormat::Kdl => super::inspect_format::format_kdl_with_project(&profile, &hint),
        }
    } else {
        match args.format {
            OutputFormat::Human => crate::inspector::profile::format_human(&profile),
            OutputFormat::Json => crate::inspector::profile::format_json(&profile),
            OutputFormat::Kdl => crate::inspector::profile::format_kdl(&profile),
        }
    };

    match args.output {
        Some(path) => std::fs::write(&path, &output).unwrap_or_else(|e| {
            eprintln!("Error writing output: {e}");
            std::process::exit(1);
        }),
        None => print!("{output}"),
    }
}

fn run_inspect_source(
    args: &InspectArgs,
    discovery: crate::legislator::source_bind::PayloadDiscovery,
) {
    use crate::legislator::source_bind::PayloadKind;

    let analysis = match &discovery.kind {
        PayloadKind::Source { path, .. } => {
            match crate::legislator::source_bind::analyze_source_path(path) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("WARNING: failed to parse source '{}': {e}", path.display());
                    eprintln!("{}", crate::legislator::source_bind::native_skip_note(path));
                    std::process::exit(1);
                }
            }
        }
        PayloadKind::InlineEval { flag, interpreter } => {
            eprintln!(
                "WARNING: {interpreter} {flag} is not statically parseable; skipping source AST and native binary capability"
            );
            std::process::exit(0);
        }
        PayloadKind::Unresolved { reason } => {
            eprintln!("WARNING: {reason}; skipping native binary capability");
            std::process::exit(0);
        }
        PayloadKind::Native => unreachable!("run_inspect_source is only for interpreters"),
    };

    if !matches!(args.format, OutputFormat::Human) {
        eprintln!("{}", analysis.skip_note);
    }

    let profile = crate::inspector::profile::CapabilityProfile::empty();
    let hint = args.project_dir.as_ref().map(|dir| {
        if !std::path::Path::exists(dir) {
            eprintln!("Error: Project directory does not exist: {}", dir.display());
            std::process::exit(1);
        }
        crate::legislator::project_hints::analyze_project(dir)
    });

    let output = match args.format {
        OutputFormat::Human => {
            let mut out = crate::legislator::source_bind::format_source_human(&analysis);
            if let Some(ref h) = hint {
                out.push('\n');
                out.push_str(&crate::legislator::project_hints::format_project_hints(h));
            }
            out
        }
        OutputFormat::Json => super::inspect_format::format_json_with_extras(
            &profile,
            hint.as_ref(),
            Some(analysis.tools.as_slice()),
        ),
        OutputFormat::Kdl => {
            let mut out = crate::inspector::profile::format_kdl(&profile);
            out.push_str("\nsource_tools {\n");
            for t in &analysis.tools {
                let perms: Vec<String> = t
                    .permissions
                    .iter()
                    .map(|p| format!("\"{}\"", crate::termutil::escape_kdl_string(p.as_str())))
                    .collect();
                out.push_str(&format!(
                    "    tool \"{}\" bound={}",
                    crate::termutil::escape_kdl_string(&t.tool_name),
                    if t.bound { "#true" } else { "#false" },
                ));
                if perms.is_empty() {
                    out.push('\n');
                } else {
                    out.push_str(" {\n");
                    out.push_str(&format!("        permissions {}\n", perms.join(" ")));
                    out.push_str("    }\n");
                }
            }
            out.push_str("}\n");
            out
        }
    };

    match args.output {
        Some(ref path) => std::fs::write(path, &output).unwrap_or_else(|e| {
            eprintln!("Error writing output: {e}");
            std::process::exit(1);
        }),
        None => print!("{output}"),
    }
}
