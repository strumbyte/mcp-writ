use std::path::PathBuf;

use crate::error::CliError;
use crate::verifier::fail_on::FailOn;

use super::{CliOutput, RunArgs};

pub(super) fn parse_run_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, CliError> {
    // --transport <type> (default: "stdio")
    let transport_taken = noargs::opt("transport")
        .short('t')
        .default("stdio")
        .doc("Transport type (default: stdio)")
        .take(&mut raw);
    let transport = transport_taken.value().to_string();

    // --policy <path> (optional)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file")
        .take(&mut raw);
    let policy = if policy_taken.is_value_present() && !policy_taken.value().is_empty() {
        Some(PathBuf::from(policy_taken.value()))
    } else if policy_taken.is_present() {
        return Err(CliError::Parse("--policy requires a file path".to_string()));
    } else {
        None
    };

    // --server <name> (optional; required for multi-server policies)
    let server_taken = noargs::opt("server")
        .doc("Server identity to bind from a multi-server policy")
        .take(&mut raw);
    let server = if server_taken.is_value_present() && !server_taken.value().is_empty() {
        Some(server_taken.value().to_string())
    } else if server_taken.is_present() {
        return Err(CliError::Parse(
            "--server requires a server name".to_string(),
        ));
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

    // --dry-run
    let dry_run = noargs::flag("dry-run")
        .doc(
            "Run the server without OS sandboxing; log and forward tool-call \
             policy violations. Blocking tool-definition checks still apply. \
             Server execution may have side effects.",
        )
        .take(&mut raw)
        .is_present();

    // --fail-on <high|critical|none> (optional; env/default resolved later)
    let fail_on_taken = noargs::opt("fail-on")
        .doc(
            "Minimum CC severity that aborts run (default: high). \
             critical: all High findings become warn/audit (not only CC-005). \
             none: never abort on CC (dangerous). Warns on stderr at startup.",
        )
        .take(&mut raw);
    let fail_on_cli = if fail_on_taken.is_value_present() {
        Some(FailOn::parse(fail_on_taken.value()).map_err(|e| CliError::Parse(e.to_string()))?)
    } else if fail_on_taken.is_present() {
        return Err(CliError::Parse(
            "--fail-on requires a value: high, critical, or none".to_string(),
        ));
    } else {
        None
    };

    // --audit-log <path> (optional)
    let audit_log_taken = noargs::opt("audit-log")
        .doc("Path to audit log file (JSONL format); defaults to stderr via tracing")
        .take(&mut raw);
    let audit_log = if audit_log_taken.is_value_present() {
        Some(PathBuf::from(audit_log_taken.value()))
    } else if audit_log_taken.is_present() {
        return Err(CliError::Parse(
            "--audit-log requires a file path".to_string(),
        ));
    } else {
        None
    };

    // --report <path> (optional)
    let report_taken = noargs::opt("report")
        .doc(
            "Write the launch report (plan, observations, final result) as \
             JSON to this path; a human summary goes to stderr",
        )
        .take(&mut raw);
    let report = if report_taken.is_value_present() && !report_taken.value().is_empty() {
        Some(PathBuf::from(report_taken.value()))
    } else if report_taken.is_present() {
        return Err(CliError::Parse("--report requires a file path".to_string()));
    } else {
        None
    };

    if let Some(help) = raw
        .finish()
        .map_err(|e| CliError::Parse(format!("{e:?}")))?
    {
        return Ok(CliOutput::Info(help.to_string()));
    }

    if command.is_empty() {
        return Err(CliError::MissingCommand);
    }

    Ok(CliOutput::Run(RunArgs {
        transport,
        policy,
        server,
        verbose,
        dry_run,
        fail_on_cli,
        audit_log,
        report,
        command,
    }))
}
