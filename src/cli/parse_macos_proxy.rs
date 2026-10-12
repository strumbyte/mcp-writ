use std::path::PathBuf;

use super::{CliOutput, MacosProxyArgs};

/// Parse `macos-proxy-run` arguments.
///
/// `mcp-writ macos-proxy-run [--policy <path>] [--server <name>]
///   [--listen <port>] [--audit-log <path>] [--audit-sync]
///   [--report <path>] [-v] -- <command> [args...]`
///
/// The PR-11 opt-in: `sandbox-exec` pins the workload's outbound TCP
/// to a loopback CONNECT proxy (the injected `*_proxy` env vars carry
/// a per-launch credential); the proxy evaluates the policy's name/IP
/// destination rules and dials outward — the payload is never
/// inspected. The plain `run` path is unchanged; this command is how
/// the route is selected.
pub(super) fn parse_macos_proxy_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, crate::error::CliError> {
    let mut args = MacosProxyArgs::default();
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

    // --listen <port> — loopback CONNECT proxy port. `0` (default) lets
    // the kernel assign one; an explicit port is for reproducible
    // diagnostics, never for exposing the listener beyond loopback.
    let listen_taken = noargs::opt("listen")
        .doc("Loopback port for the CONNECT proxy (default: kernel-assigned)")
        .take(&mut raw);
    if listen_taken.is_value_present() && !listen_taken.value().is_empty() {
        match listen_taken.value().parse::<u16>() {
            Ok(0) => args.listen_port = 0,
            Ok(p) => args.listen_port = p,
            Err(_) => {
                missing_value.get_or_insert_with(|| "--listen requires a port number".to_string());
            }
        }
    } else if listen_taken.is_present() {
        missing_value.get_or_insert_with(|| "--listen requires a port number".to_string());
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
            "macos-proxy-run requires a command after `--` — the workload to run \
             under the proxy-pinned sandbox profile"
                .to_string(),
        ));
    }
    if args.audit_sync && args.audit_log.is_none() {
        return Err(crate::error::CliError::Parse(
            "--audit-sync requires --audit-log (the tracing sink cannot fsync)".to_string(),
        ));
    }
    args.command = command;

    Ok(CliOutput::MacosProxyRun(args))
}
