use std::path::PathBuf;

use super::{CliOutput, NamespacedArgs};

/// Parse `namespaced-run` arguments.
///
/// `mcp-writ namespaced-run [--policy <path>] [--server <name>]
///   --upstream <ip>[:port] [--audit-log <path>] [--audit-sync]
///   [--report <path>] [-v] -- <command> [args...]`
///
/// The PoC launches a workload inside `userns+netns+mountns` whose only
/// egress device is a TUN feeding the in-process proxy. `--upstream` is
/// the resolver the embedded DNS gate forwards to — required whenever
/// the policy's name rules must resolve (the gate never recurses
/// through itself).
pub(super) fn parse_namespaced_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, crate::error::CliError> {
    let mut args = NamespacedArgs::default();
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

    // --upstream <ip>[:port] — the DNS gate's resolver (required:
    // without it name rules can never mint grants, and making it
    // optional would let a forgotten flag silently break policy).
    let upstream_taken = noargs::opt("upstream")
        .doc("Upstream DNS resolver as an IP literal, e.g. 1.1.1.1 or 1.1.1.1:53")
        .take(&mut raw);
    if upstream_taken.is_value_present() && !upstream_taken.value().is_empty() {
        match super::parse_dns_gate::parse_ip_endpoint(upstream_taken.value(), 53) {
            Ok(addr) => args.upstream = Some(addr),
            Err(e) => {
                missing_value.get_or_insert_with(|| format!("invalid --upstream: {e}"));
            }
        }
    } else if upstream_taken.is_present() {
        missing_value.get_or_insert_with(|| "--upstream requires an IP endpoint".to_string());
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

    // --report <path> — the PoC capability/status report JSON.
    let report_taken = noargs::opt("report")
        .doc("Write the capability + egress-layer report JSON to this path")
        .take(&mut raw);
    if report_taken.is_value_present() && !report_taken.value().is_empty() {
        args.report = Some(PathBuf::from(report_taken.value()));
    } else if report_taken.is_present() {
        missing_value.get_or_insert_with(|| "--report requires a file path".to_string());
    }

    // -v / --verbose
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
            "namespaced-run requires a command after `--` — the workload to run inside the namespace"
                .to_string(),
        ));
    }
    if args.upstream.is_none() {
        return Err(crate::error::CliError::Parse(
            "namespaced-run requires --upstream <ip>[:port] — the embedded DNS gate \
             forwards only to an explicit IP-literal resolver"
                .to_string(),
        ));
    }
    if args.audit_sync && args.audit_log.is_none() {
        return Err(crate::error::CliError::Parse(
            "--audit-sync requires --audit-log (the tracing sink cannot fsync)".to_string(),
        ));
    }
    args.command = command;

    Ok(CliOutput::NamespacedRun(args))
}
