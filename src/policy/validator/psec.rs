//! PSEC (Windows Process Security) expressibility: the measured v1.0
//! contract limits on egress, environment, transport, and fs spellings.
//! Shared with the launch-time warden policy-check so a policy that can
//! never be enforced fails at load, not at spawn.

use crate::error::PolicyError;
use crate::execution::{ExecutionTarget, TargetOs};
use crate::policy::{Policy, TransportType};

/// Target-OS representability: constraints the workload OS cannot express.
/// Decided by `os` — the *workload's* OS — so a Windows host can still
/// accept a policy for a Linux container guest.
/// Whether a policy `allowed`/`denied` host entry can be encoded as a
/// PSEC egress destination: only literal IPv4 addresses produce a
/// subnet rule (`IpSubnet{address, prefix_length:32}`) — the measured
/// v1.0 contract. Hostnames, wildcards and IPv6 spellings have no
/// verified representation. Shared by the validator (load-time refusal
/// for a `--windows-mechanism psec` target) and the warden's
/// policy-check stage (the same refusal for a programmatically built
/// policy that never passed through validation).
pub(crate) fn psec_ipv4_expressible(entry: &str) -> bool {
    entry.parse::<std::net::Ipv4Addr>().is_ok()
}

/// Whether a policy fs path can appear in a PSEC fs list: a literal,
/// absolute Windows path — drive-letter (`X:\…`, `X:/…`), UNC
/// (`\\server\share\…`), or the `\\?\…`/`//?/…` verbatim spellings of
/// either (the form the runtime itself emits for resolved image paths,
/// so a policy may spell a path the way a report displays it). Globs
/// are not expanded by the mechanism; a relative or drive-relative
/// spelling would resolve against an undefined base inside the
/// server-side check. Shared by this validator (load-time refusal)
/// and the warden's policy-check stage.
pub(crate) fn psec_fs_path_expressible(path: &str) -> Result<(), String> {
    // A verbatim prefix is part of the spelling, not a glob character —
    // strip it for the checks; '*'/'?' anywhere else still refuses.
    let verbatim = path
        .strip_prefix("\\\\?\\")
        .or_else(|| path.strip_prefix("//?/"));
    let stripped = verbatim.unwrap_or(path);
    if stripped.contains(['*', '?']) {
        return Err("PSEC filesystem rules are literal paths — glob \
                    characters are never expanded"
            .to_string());
    }
    // Checked by explicit Windows syntax, not `Path::is_absolute` —
    // this validation runs on every platform and the host's path rules
    // must never decide what the Windows-side server would resolve.
    let bytes = stripped.as_bytes();
    let drive_abs = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    // UNC bodies must name a server and a share (`server\share[\…]`).
    // The `UNC\…` spelling is recognized only as the body of a `\\?\`
    // verbatim path — a bare `UNC\…` is a relative path whose first
    // component happens to be named "UNC".
    let unc_body = stripped
        .strip_prefix("\\\\")
        .or_else(|| stripped.strip_prefix("//"))
        .or_else(|| {
            if verbatim.is_some() {
                stripped
                    .strip_prefix("UNC\\")
                    .or_else(|| stripped.strip_prefix("UNC/"))
            } else {
                None
            }
        });
    let unc_abs = unc_body.is_some_and(unc_body_names_server_and_share);
    if !drive_abs && !unc_abs {
        return Err("PSEC filesystem rules need an absolute Windows path \
                    (drive-letter or UNC) — a relative spelling would \
                    resolve against an undefined base"
            .to_string());
    }
    Ok(())
}

/// The text after a UNC marker (`\\`, `//`, or the verbatim `UNC\` /
/// `UNC/` form) names a usable UNC target only when a server and a
/// share are both present and nonempty: `server\share[\…]`.
fn unc_body_names_server_and_share(body: &str) -> bool {
    let mut parts = body.split(['\\', '/']);
    matches!(parts.next(), Some(server) if !server.is_empty())
        && matches!(parts.next(), Some(share) if !share.is_empty())
}

pub(super) fn validate_target_network_enforcement(
    policy: &Policy,
    target: &ExecutionTarget,
) -> Result<(), PolicyError> {
    if target.workload_os != TargetOs::Windows {
        return Ok(());
    }
    if !(policy.network.outbound.deny_all_others && !policy.network.outbound.allowed.is_empty()) {
        return Ok(());
    }
    // A PSEC security environment *can* pin egress destinations — the
    // measured v1.0 contract accepts IPv4 subnet rules under a deny-all
    // default. Only literal IPv4 entries are expressible; every other
    // spelling refuses, naming the entries.
    if matches!(
        target.effective_windows_mechanism(),
        Some(crate::execution::WindowsNativeMechanism::Psec)
    ) {
        // A `host:port` allow entry cannot be expressed: parse-time
        // normalization folds the port into `allowed`, so without this
        // check the entry would silently widen into an every-port rule.
        // `allowed_port_qualified` holds the source spellings; only
        // entries still present (folded) in `allowed` count.
        let ported: Vec<String> = policy
            .network
            .outbound
            .allowed_port_qualified
            .iter()
            .filter(|raw| {
                policy
                    .network
                    .outbound
                    .allowed
                    .contains(&crate::policy::host::normalize_policy_host(raw))
            })
            .map(|e| format!("'{e}'"))
            .collect();
        if !ported.is_empty() {
            return Err(PolicyError::Validation(format!(
                "PSEC egress rules pin whole IPv4 destinations — outbound \
                 allow entries {} carried an explicit port the spec cannot \
                 express; drop the port (every port to the destination is \
                 allowed) or select a different --windows-mechanism",
                ported.join(", ")
            )));
        }
        let bad: Vec<String> = policy
            .network
            .outbound
            .allowed
            .iter()
            .filter(|e| !psec_ipv4_expressible(e))
            .map(|e| format!("'{e}'"))
            .collect();
        if bad.is_empty() {
            return Ok(());
        }
        return Err(PolicyError::Validation(format!(
            "PSEC egress rules pin IPv4 destinations only — outbound allow \
             entries {} are not IPv4 literals; drop them or select a \
             different --windows-mechanism",
            bad.join(", ")
        )));
    }
    Err(PolicyError::Validation(
        "Windows AppContainer cannot enforce per-destination outbound allowlists; \
         use an empty allow list (deny all) or deny_all_others=false (unrestricted), \
         or place a network broker in front of the sandbox"
            .to_string(),
    ))
}

/// Load-time refusal for requirements a PSEC launch can never satisfy —
/// the same contract `warden::psec_spec::build_launch_spec` enforces at
/// launch (`policy-check`), checked here so a `--windows-mechanism psec`
/// run fails while the policy loads, not while the process spawns.
/// `tmpdir` is deliberately absent: it is a `SpawnOptions`/CLI value,
/// not a policy field, so the launch-time check owns it.
pub(super) fn validate_psec_expressibility(
    policy: &Policy,
    target: &ExecutionTarget,
) -> Result<(), PolicyError> {
    let psec = matches!(
        target.effective_windows_mechanism(),
        Some(crate::execution::WindowsNativeMechanism::Psec)
    );
    if !psec {
        return Ok(());
    }
    if !policy.environment.allowed.is_empty() {
        return Err(PolicyError::Validation(format!(
            "PSEC children receive a mechanism-managed environment — \
             environment.allowed entries {} cannot be delivered; drop \
             them (a bare environment.restrict holds by construction) \
             or select a different --windows-mechanism",
            policy
                .environment
                .allowed
                .iter()
                .map(|n| format!("'{n}'"))
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    if !policy.network.outbound.deny_all_others {
        return Err(PolicyError::Validation(
            "PSEC cannot express unrestricted outbound egress — the measured \
             host applies deny-all to security-environment children and \
             `default_action: allow` did not restore connectivity; set \
             deny_all_others (with optional IPv4 allow entries) or select a \
             different --windows-mechanism"
                .to_string(),
        ));
    }
    if policy.network.inbound.allow_listen {
        return Err(PolicyError::Validation(
            "PSEC v1.0 has no ingress rules — inbound.allow_listen cannot be \
             enforced; drop it or select a different --windows-mechanism"
                .to_string(),
        ));
    }
    if matches!(policy.transport.type_, TransportType::Http) {
        return Err(PolicyError::Validation(
            "PSEC has no loopback exemption and egress rules do not exempt \
             loopback (measured) — an HTTP transport workload cannot reach \
             its listener; use stdio or select a different \
             --windows-mechanism"
                .to_string(),
        ));
    }
    // Filesystem spellings — the same per-entry contract
    // `build_launch_spec` enforces at `policy-check` (literal absolute
    // Windows paths; no globs), refused here so `run` fails at load.
    let mut bad_fs: Vec<String> = Vec::new();
    for (list, field) in [
        (&policy.fs.read_only, "fs.read_only"),
        (&policy.fs.read_write, "fs.read_write"),
        (&policy.fs.denied_paths, "fs.denied_paths"),
    ] {
        for path in list {
            if let Err(reason) = psec_fs_path_expressible(path) {
                bad_fs.push(format!("{field} entry '{path}': {reason}"));
            }
        }
    }
    if !bad_fs.is_empty() {
        return Err(PolicyError::Validation(format!(
            "PSEC filesystem rules are literal absolute Windows paths — {}; \
             fix the entries or select a different --windows-mechanism",
            bad_fs.join("; ")
        )));
    }
    Ok(())
}
