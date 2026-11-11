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

    // --policy-version <2|3> (optional; default 2 — 3 declares
    // `policy version=3`. The generated template carries no
    // version-sensitive spellings — no `require-path`, no bare
    // `allow none=#true`, no `replace` — so the declaration alone
    // makes the draft valid under either grammar)
    let policy_version_taken = noargs::opt("policy-version")
        .doc("Policy schema version to declare in the draft: 2 (default) or 3")
        .take(&mut raw);
    let policy_version = if policy_version_taken.is_value_present() {
        match policy_version_taken.value().parse::<u32>() {
            Ok(v @ (2 | 3)) => v,
            _ => {
                return Err(CliError::Parse(
                    "--policy-version must be 2 or 3".to_string(),
                ));
            }
        }
    } else if policy_version_taken.is_present() {
        return Err(CliError::Parse(
            "--policy-version requires a value: 2 or 3".to_string(),
        ));
    } else {
        2
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
        .doc("Run tools/list discovery without the OS sandbox, inheriting the ambient environment (implies --live-discovery)")
        .take(&mut raw)
        .is_present();

    let unsafe_discovery_best_effort_lifetime =
        noargs::flag("unsafe-discovery-best-effort-lifetime")
            .doc(
                "Run tools/list discovery inside the sandbox but without requiring a \
                 kernel descendant-lifetime boundary — for hosts (macOS, cgroup-less \
                 Linux) that cannot provide one; child cleanup falls back to \
                 best-effort (implies --live-discovery)",
            )
            .take(&mut raw)
            .is_present();

    let self_test = noargs::flag("self-test")
        .doc(
            "After drafting, spawn the server via Warden (restricted TMPDIR, 8s) and collect \
             Auditor/Warden evidence. Never uses --unsafe-unsandboxed-discovery",
        )
        .take(&mut raw)
        .is_present();

    if static_only_flag
        && (live_discovery || unsafe_unsandboxed_discovery || unsafe_discovery_best_effort_lifetime)
    {
        return Err(CliError::Parse(
            "--static-only cannot be combined with --live-discovery, \
             --unsafe-unsandboxed-discovery, or --unsafe-discovery-best-effort-lifetime"
                .to_string(),
        ));
    }
    if unsafe_unsandboxed_discovery && unsafe_discovery_best_effort_lifetime {
        return Err(CliError::Parse(
            "--unsafe-unsandboxed-discovery cannot be combined with \
             --unsafe-discovery-best-effort-lifetime"
                .to_string(),
        ));
    }

    let static_only =
        !live_discovery && !unsafe_unsandboxed_discovery && !unsafe_discovery_best_effort_lifetime;

    // Help-only positional for `-- <command> [args...]`: `parse_from`
    // splits the trailing argv off before noargs sees it, so this entry
    // exists purely to document it — in help mode `Arg::take` consumes
    // nothing and real parsing still reads the pre-split `command`.
    if raw.metadata().help_mode {
        noargs::arg("-- <command> [args...]")
            .doc("The MCP server command to analyze (its argv[0] is the default --binary)")
            .take(&mut raw);
    }

    if let Some(help) = raw
        .finish()
        .map_err(|e| CliError::Parse(format!("{e:?}")))?
    {
        let mut help = help;
        help.push_str(super::QUICKSTART_FLOW);
        return Ok(CliOutput::Info(help));
    }

    if command.is_empty() {
        return Err(CliError::MissingCommand);
    }

    Ok(CliOutput::GeneratePolicy(GenPolicyArgs {
        binary_path,
        output,
        verbose,
        policy_version,
        static_only,
        unsafe_unsandboxed_discovery,
        unsafe_discovery_best_effort_lifetime,
        self_test,
        project_dir,
        command,
    }))
}
