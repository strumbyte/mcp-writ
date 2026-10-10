use std::path::PathBuf;

use super::{CliOutput, EbpfArgs};

/// Parse `ebpf-run` arguments.
///
/// `mcp-writ ebpf-run [--policy <path>] [--server <name>]
///   [--allowlist <path>] [--audit-log <path>] [--audit-sync]
///   [--report <path>] [-v] -- <command> [args...]`
///
/// The opt-in cgroup-eBPF launch: the workload joins a private cgroup
/// in `pre_exec` and `BPF_CGROUP_INET4/6_CONNECT` programs enforce
/// connect destinations in-kernel. `--policy` is optional — the same
/// `load_policy_or_default` default as `unotify-run` applies.
pub(super) fn parse_ebpf_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, crate::error::CliError> {
    let mut args = EbpfArgs::default();
    let mut missing_value: Option<String> = None;

    // --policy <path>
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file")
        .take(&mut raw);
    if policy_taken.is_value_present() && !policy_taken.value().is_empty() {
        args.policy = Some(PathBuf::from(policy_taken.value()));
    } else if policy_taken.is_present() {
        missing_value.get_or_insert_with(|| "--policy requires a file path".to_string());
    }

    // --server <name>
    let server_taken = noargs::opt("server")
        .doc("Server identity to bind from a multi-server policy")
        .take(&mut raw);
    if server_taken.is_value_present() && !server_taken.value().is_empty() {
        args.server = Some(server_taken.value().to_string());
    } else if server_taken.is_present() {
        missing_value.get_or_insert_with(|| "--server requires a server name".to_string());
    }

    // --allowlist <path> — a dns-gate `--allowlist-export` snapshot the
    // drain loop resyncs into the grant maps.
    let allowlist_taken = noargs::opt("allowlist")
        .doc("Dynamic IP allow list snapshot exported by dns-gate (--allowlist-export)")
        .take(&mut raw);
    if allowlist_taken.is_value_present() && !allowlist_taken.value().is_empty() {
        args.allowlist = Some(PathBuf::from(allowlist_taken.value()));
    } else if allowlist_taken.is_present() {
        missing_value.get_or_insert_with(|| "--allowlist requires a file path".to_string());
    }

    // --audit-log <path>
    let audit_taken = noargs::opt("audit-log")
        .doc("Write audit JSONL to this file")
        .take(&mut raw);
    if audit_taken.is_value_present() && !audit_taken.value().is_empty() {
        args.audit_log = Some(PathBuf::from(audit_taken.value()));
    } else if audit_taken.is_present() {
        missing_value.get_or_insert_with(|| "--audit-log requires a file path".to_string());
    }

    // --audit-sync
    args.audit_sync = noargs::flag("audit-sync")
        .doc("Flush + fsync every audit record (requires --audit-log)")
        .take(&mut raw)
        .is_present();

    // --report <path> — the capability/status report JSON.
    let report_taken = noargs::opt("report")
        .doc("Write the capability + egress-layer report JSON to this path")
        .take(&mut raw);
    if report_taken.is_value_present() && !report_taken.value().is_empty() {
        args.report = Some(PathBuf::from(report_taken.value()));
    } else if report_taken.is_present() {
        missing_value.get_or_insert_with(|| "--report requires a file path".to_string());
    }

    // -v / --verbose — `take` consumes one occurrence per call.
    let mut verbose = 0u8;
    while noargs::flag("verbose")
        .short('v')
        .doc("Increase log verbosity")
        .take(&mut raw)
        .is_present()
    {
        verbose = verbose.saturating_add(1);
    }
    args.verbose = verbose;

    if let Some(msg) = missing_value {
        return Err(crate::error::CliError::Parse(msg));
    }

    if let Some(help) = raw
        .finish()
        .map_err(|e| crate::error::CliError::Parse(format!("{e:?}")))?
    {
        return Ok(CliOutput::Info(help.to_string()));
    }

    if command.is_empty() {
        return Err(crate::error::CliError::Parse(
            "ebpf-run requires a command after `--` — the workload whose connects are enforced"
                .to_string(),
        ));
    }
    if args.audit_sync && args.audit_log.is_none() {
        return Err(crate::error::CliError::Parse(
            "--audit-sync requires --audit-log (the tracing sink cannot fsync)".to_string(),
        ));
    }
    args.command = command;

    Ok(CliOutput::EbpfRun(args))
}
