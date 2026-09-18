use std::path::PathBuf;

use crate::error::CliError;

use super::{CliOutput, GenPolicyArgs};

pub(super) fn parse_gen_policy_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, CliError> {
    // --binary <path> (optional; defaults to command[0])
    let binary_taken = noargs::opt("binary")
        .short('b')
        .doc("Path to binary to inspect (default: first element of command)")
        .take(&mut raw);
    let binary_path = if binary_taken.is_value_present() {
        Some(PathBuf::from(binary_taken.value()))
    } else {
        None
    };

    // --output <path> (optional)
    let output_taken = noargs::opt("output")
        .short('o')
        .doc("Write generated policy to file instead of stdout")
        .take(&mut raw);
    let output = if output_taken.is_value_present() {
        Some(PathBuf::from(output_taken.value()))
    } else {
        None
    };

    // --project <dir> (optional; same knob as inspect)
    let project_taken = noargs::opt("project")
        .doc("Analyze project directory for permission hints (no CWD fallback)")
        .take(&mut raw);
    let project_dir = if project_taken.is_value_present() {
        Some(PathBuf::from(project_taken.value()))
    } else {
        None
    };

    // -v / --verbose
    let verbose = if noargs::flag("verbose")
        .short('v')
        .doc("Increase log verbosity")
        .take(&mut raw)
        .is_present()
    {
        1u8
    } else {
        0u8
    };

    let live_discovery = noargs::flag("live-discovery")
        .doc("Execute the MCP server to discover tools (default: static inspection only)")
        .take(&mut raw)
        .is_present();

    let static_only_flag = noargs::flag("static-only")
        .doc(
            "Do not execute the MCP server; generate a draft from static inspection only (default)",
        )
        .take(&mut raw)
        .is_present();

    let unsafe_unsandboxed_discovery = noargs::flag("unsafe-unsandboxed-discovery")
        .doc("Run tools/list discovery with the ambient environment (implies --live-discovery)")
        .take(&mut raw)
        .is_present();

    let self_test = noargs::flag("self-test")
        .doc(
            "After drafting, spawn the server via Warden (restricted TMPDIR, 8s) and collect \
             Auditor/Warden evidence. Never uses --unsafe-unsandboxed-discovery",
        )
        .take(&mut raw)
        .is_present();

    if static_only_flag && (live_discovery || unsafe_unsandboxed_discovery) {
        return Err(CliError::Parse(
            "--static-only cannot be combined with --live-discovery or --unsafe-unsandboxed-discovery"
                .to_string(),
        ));
    }

    let static_only = !live_discovery && !unsafe_unsandboxed_discovery;

    if let Some(help) = raw
        .finish()
        .map_err(|e| CliError::Parse(format!("{e:?}")))?
    {
        return Ok(CliOutput::Info(help.to_string()));
    }

    if command.is_empty() {
        return Err(CliError::MissingCommand);
    }

    Ok(CliOutput::GeneratePolicy(GenPolicyArgs {
        binary_path,
        output,
        verbose,
        static_only,
        unsafe_unsandboxed_discovery,
        self_test,
        project_dir,
        command,
    }))
}
