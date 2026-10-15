use std::path::PathBuf;

use crate::container::engine::EngineKind;

use super::{CheckArgs, CliOutput};

/// Record `msg` as the parse/semantic failure the `check` command
/// reports as status `invalid` (exit 2).
fn invalid_args(mut args: CheckArgs, msg: String) -> CliOutput {
    args.invalid_input = Some(msg);
    CliOutput::Check(args)
}

/// Parse `check` arguments.
///
/// ```text
///   mcp-writ check --policy <path> [--server <name>] [--engine <e>]
///                [--report <path>] [-v] [-- <mcp-server-command>]
/// ```
///
/// Like `plan`, this parser never returns `Err`: a malformed invocation
/// is a *result*, recorded in `CheckArgs::invalid_input` so the command
/// can emit the machine-readable `invalid` status with exit code 2.
/// `--help` output is still honored via [`CliOutput::Info`].
///
/// The trailing `-- <command>` is the tools-list source: when the policy
/// carries `tools-list-hash` pins, `check` spawns the server exactly
/// like `generate-policy` live discovery (restricted environment) and
/// re-verifies the pin against the fresh `tools/list`. Without a
/// command the pins are reported `unverified` — never skipped.
pub(super) fn parse_check_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, crate::error::CliError> {
    let mut args = CheckArgs::default();
    let mut missing_value = None;

    // --policy <path> (required by the command semantics; absence is a
    // machine-readable `invalid` result, not a usage error)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file (required)")
        .take(&mut raw);
    if policy_taken.is_value_present() && !policy_taken.value().is_empty() {
        args.policy = Some(PathBuf::from(policy_taken.value()));
    } else if policy_taken.is_present() {
        missing_value.get_or_insert_with(|| "--policy requires a file path".to_string());
    }

    // --server <name> (optional)
    let server_taken = noargs::opt("server")
        .doc("Server identity to bind from a multi-server policy")
        .take(&mut raw);
    if server_taken.is_value_present() && !server_taken.value().is_empty() {
        args.server = Some(server_taken.value().to_string());
    } else if server_taken.is_present() {
        missing_value.get_or_insert_with(|| "--server requires a server name".to_string());
    }

    // --engine docker|podman|buildah|wslc (docker-manifest-hash pins only)
    let engine_taken = noargs::opt("engine")
        .short('e')
        .doc(
            "Container engine used to inspect docker-manifest-hash image \
             references: docker, podman, buildah, or wslc (auto-detect if \
             omitted; wslc is a Windows-host explicit choice)",
        )
        .take(&mut raw);
    let mut engine_error = None;
    if engine_taken.is_value_present() {
        match engine_taken.value().parse::<EngineKind>() {
            Ok(e) => args.engine = Some(e),
            Err(e) => engine_error = Some(e.to_string()),
        }
    } else if engine_taken.is_present() {
        missing_value.get_or_insert_with(|| {
            "--engine requires a value: docker, podman, buildah, or wslc".to_string()
        });
    }

    // --report <path> (optional; default: the JSON result goes to stdout)
    let report_taken = noargs::opt("report")
        .doc("Write the check result JSON to this path instead of stdout")
        .take(&mut raw);
    if report_taken.is_value_present() && !report_taken.value().is_empty() {
        args.report = Some(PathBuf::from(report_taken.value()));
    } else if report_taken.is_present() {
        missing_value.get_or_insert_with(|| "--report requires a file path".to_string());
    }

    // -v / --verbose
    args.verbose = if noargs::flag("verbose")
        .short('v')
        .doc("Increase log verbosity")
        .take(&mut raw)
        .is_present()
    {
        1u8
    } else {
        0u8
    };

    args.command = command;

    // A missing option value is reported before leftover-argument and
    // bad-value errors — the same precedence `plan` uses.
    if let Some(msg) = missing_value {
        return Ok(invalid_args(args, msg));
    }

    match raw.finish() {
        Ok(Some(help)) => return Ok(CliOutput::Info(help.to_string())),
        Ok(None) => {}
        Err(e) => {
            return Ok(invalid_args(args, format!("unrecognized arguments: {e:?}")));
        }
    }

    if let Some(e) = engine_error {
        return Ok(invalid_args(args, format!("invalid --engine value: {e}")));
    }

    if args.policy.is_none() {
        return Ok(invalid_args(
            args,
            "check requires --policy <path>: the drift check re-verifies a \
             policy's integrity pins against the current files, image \
             metadata, and tools/list"
                .to_string(),
        ));
    }

    Ok(CliOutput::Check(args))
}
