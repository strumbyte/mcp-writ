use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use super::{CliOutput, DnsGateArgs};

/// `ADDR` / `ADDR:PORT` / `[v6]` / `[v6]:port` — an IP literal with an
/// optional port. Hostnames are refused: a resolver endpoint that
/// itself needed resolution would recurse through the policy it is
/// meant to enforce. `pub(crate)`: `namespaced-run`'s `--upstream`
/// shares the same contract.
pub(crate) fn parse_ip_endpoint(value: &str, default_port: u16) -> Result<SocketAddr, String> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    // `[v6]` without a port — SocketAddr needs the bracketed form only
    // when a port follows, so strip the brackets for the bare literal.
    if let Some(inner) = value.strip_prefix('[').and_then(|v| v.strip_suffix(']'))
        && let Ok(ip) = inner.parse::<IpAddr>()
    {
        return Ok(SocketAddr::new(ip, default_port));
    }
    Err(format!(
        "'{value}' is not an IP literal endpoint — use ADDR, ADDR:PORT, [v6], or [v6]:PORT (hostnames are not resolvable here)"
    ))
}

/// Parse `dns-gate` arguments.
///
/// `mcp-writ dns-gate --policy <path> --upstream <ip>[:port]
///   [--listen <ip>[:port]] [--refuse-rcode nxdomain|refused]
///   [--allowlist-export <path>] [--audit-log <path>] [--audit-sync] [-v]`
///
/// `--policy` and `--upstream` are required: the gate's only job is
/// enforcing the policy's name layer, so running one with no policy
/// (or the default open posture) would be a silently-unrestricted
/// resolver.
pub(super) fn parse_dns_gate_args(
    mut raw: noargs::RawArgs,
    _command: Vec<String>,
) -> Result<CliOutput, crate::error::CliError> {
    let mut args = DnsGateArgs::default();
    let mut missing_value: Option<String> = None;

    // --policy <path> (required)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file (required)")
        .take(&mut raw);
    if policy_taken.is_value_present() && !policy_taken.value().is_empty() {
        args.policy = Some(PathBuf::from(policy_taken.value()));
    } else if policy_taken.is_present() {
        missing_value.get_or_insert_with(|| "--policy requires a file path".to_string());
    }

    // --upstream <ip>[:port] (required)
    let upstream_taken = noargs::opt("upstream")
        .doc("Upstream resolver, an IP literal with optional port (default 53)")
        .take(&mut raw);
    if upstream_taken.is_value_present() && !upstream_taken.value().is_empty() {
        match parse_ip_endpoint(upstream_taken.value(), 53) {
            Ok(addr) => args.upstream = Some(addr),
            Err(e) => {
                missing_value.get_or_insert_with(|| format!("invalid --upstream: {e}"));
            }
        }
    } else if upstream_taken.is_present() {
        missing_value.get_or_insert_with(|| "--upstream requires an IP endpoint".to_string());
    }

    // --listen <ip>[:port] (default 127.0.0.1:1053)
    let listen_taken = noargs::opt("listen")
        .doc("Listen address for UDP and TCP, IP literal with optional port (default 127.0.0.1:1053)")
        .take(&mut raw);
    if listen_taken.is_value_present() && !listen_taken.value().is_empty() {
        match parse_ip_endpoint(listen_taken.value(), 1053) {
            Ok(addr) => args.listen = addr,
            Err(e) => {
                missing_value.get_or_insert_with(|| format!("invalid --listen: {e}"));
            }
        }
    } else if listen_taken.is_present() {
        missing_value.get_or_insert_with(|| "--listen requires an IP endpoint".to_string());
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

    // --refuse-rcode nxdomain|refused (default refused)
    let rcode_taken = noargs::opt("refuse-rcode")
        .doc("RCODE answered for policy-refused names: nxdomain or refused (default refused)")
        .take(&mut raw);
    if rcode_taken.is_value_present() && !rcode_taken.value().is_empty() {
        match crate::dnsgate::Refusal::parse(rcode_taken.value()) {
            Ok(r) => args.refusal = r,
            Err(e) => {
                missing_value.get_or_insert(e);
            }
        }
    } else if rcode_taken.is_present() {
        missing_value.get_or_insert_with(|| {
            "--refuse-rcode requires a value: nxdomain or refused".to_string()
        });
    }

    // --allowlist-export <path> — write the dynamic IP allow list
    // snapshot after every registration batch.
    let export_taken = noargs::opt("allowlist-export")
        .doc("Export the TTL-scoped dynamic IP allow list snapshot to this path")
        .take(&mut raw);
    if export_taken.is_value_present() && !export_taken.value().is_empty() {
        args.allowlist_export = Some(PathBuf::from(export_taken.value()));
    } else if export_taken.is_present() {
        missing_value.get_or_insert_with(|| "--allowlist-export requires a file path".to_string());
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

    // -v / --verbose — `take` consumes one occurrence per call (one
    // `v` out of a `-vv` cluster, one `--verbose`), so repeat until
    // nothing is left and count: 0 = policy level, 1 = DEBUG,
    // 2+ = TRACE. Help output dedupes the repeated spec by name.
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

    // Required arguments are checked after `finish` so `--help` works
    // without them.
    if args.policy.is_none() {
        return Err(crate::error::CliError::Parse(
            "dns-gate requires --policy <path> — the gate enforces a policy's name layer; without one it would be an unrestricted resolver".to_string(),
        ));
    }
    if args.upstream.is_none() {
        return Err(crate::error::CliError::Parse(
            "dns-gate requires --upstream <ip>[:port] — the resolver allowed names are forwarded to (IP literal; a hostname would recurse through the gate itself)".to_string(),
        ));
    }
    if args.audit_sync && args.audit_log.is_none() {
        return Err(crate::error::CliError::Parse(
            "--audit-sync requires --audit-log (the tracing sink cannot fsync)".to_string(),
        ));
    }

    Ok(CliOutput::DnsGate(args))
}
