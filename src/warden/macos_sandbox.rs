//! macOS sandbox implementation using `sandbox-exec` and SBPL.
//!
//! Generates deny-default SBPL profiles from the existing [`Policy`] struct
//! and spawns child processes via `sandbox-exec -p <profile> -- <command>`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[cfg(unix)]
use libc::{SIGKILL, kill as libc_kill};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::enforcement::{ControlState, FsAccess, GrantOrigin, GrantSubject, ProcessGrant};
use crate::error::{SandboxStage, WardenError};
use crate::execution::TargetOs;
use crate::policy::Policy;
use crate::policy::validator::is_strict_subpath_or_descendant_for;

fn is_local_hostname(name: &str) -> bool {
    name == "localhost" || name == "*" || name == "127.0.0.1" || name == "[::1]" || name == "::1"
}

/// Whether `host` names an explicit loopback endpoint —
/// `localhost`, `127.0.0.1`, `::1`, or `[::1]` — with an optional
/// `:port`. Bare-port (`"443"`), wildcard (`"*:443"`, `":443"`), and
/// every other host form are NOT explicit: their destination set is
/// wider than loopback, so proxy mode routes them to the CONNECT
/// proxy rather than granting a direct `localhost:port` rule.
///
/// The `:port` split only applies where `:` can be a port separator:
/// `[v6]:port`, `name:port`, `v4:port`. A bare string with more than
/// one colon is an IPv6 literal — its colons are hex-field
/// separators, never a port split. The parser stores
/// `host="::1:8080"` as the v6 address `::1:8080` (not `::1` port
/// 8080), and stores `[::1]:8080` / `host="::1" port=8080` as the
/// bare literal `::1` plus a port qualifier — so the whole literal
/// is the host identity here.
fn is_explicit_loopback_host(host: &str) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    if let Some((v6, _)) = lower
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
    {
        return v6 == "::1";
    }
    if lower.matches(':').count() > 1 {
        return lower == "::1";
    }
    // At most one ':' remains — it can only be a port separator.
    let name = lower.split(':').next().unwrap_or(lower.as_str());
    matches!(name, "localhost" | "127.0.0.1")
}

/// Extract a port number from a host string.
///
/// Supports formats: `"localhost:8080"`, `"*:443"`, `":80"`, `"127.0.0.1:80"`,
/// or plain `"8080"`. Remote hostnames are not converted to localhost.
fn extract_local_port(host: &str) -> Result<Option<u16>, WardenError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok(if port == 0 { None } else { Some(port) });
    }
    let lower = trimmed.to_ascii_lowercase();
    // Check the whole string before splitting on ':'. Bare IPv6 loopback
    // "::1" would otherwise become (":", "1") via rsplit_once.
    if is_local_hostname(&lower) {
        return Ok(None);
    }
    // A bare multi-colon string is an IPv6 literal, not host:port —
    // `::1:8080` is the v6 address `::1:8080`, never `::1` port 8080
    // (the policy grammar stores it exactly that way and rejects
    // unbracketed `v6:port` spellings for the same reason; the port
    // form is `[v6]:port`). Any non-loopback v6 literal is a remote
    // host for the localhost-only mechanism.
    if !lower.starts_with('[') && lower.matches(':').count() > 1 {
        return Err(WardenError::sandbox_setup(
            crate::error::SandboxStage::Policy,
            format!(
                "macOS SBPL cannot pin remote host '{trimmed}'; refuse rather than mapping to localhost"
            ),
        ));
    }
    let (name, port_part) = if let Some((h, p)) = lower.rsplit_once(':') {
        (h, Some(p))
    } else {
        (lower.as_str(), None)
    };
    let local = is_local_hostname(name) || name.is_empty();
    if !local {
        return Err(WardenError::sandbox_setup(
            crate::error::SandboxStage::Policy,
            format!(
                "macOS SBPL cannot pin remote host '{trimmed}'; refuse rather than mapping to localhost"
            ),
        ));
    }
    match port_part {
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .map(Some)
            .ok_or_else(|| {
                WardenError::sandbox_setup(
                    crate::error::SandboxStage::Policy,
                    format!("invalid local port in '{trimmed}'"),
                )
            }),
        None => Ok(None),
    }
}

/// Escape a path for embedding in an SBPL string literal.
///
/// Only produces escapes that SBPL (TinyScheme) actually supports:
/// `\\`, `\"`, `\n`, `\r`, `\t`. Returns an error if the path contains
/// control characters that SBPL cannot represent (NUL or 0x01–0x1F
/// other than `\n`, `\r`, `\t`), since emitting unsupported escapes
/// would cause the sandbox rule to match a different path than intended.
fn escape_sbpl_path(path: &str) -> Result<String, WardenError> {
    let mut result = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if (c as u32) <= 0x1F || (c as u32) == 0x7F => {
                return Err(WardenError::sandbox_setup(
                    crate::error::SandboxStage::Policy,
                    format!(
                        "escape_sbpl_path: path contains control character U+{:04X} \
                         which SBPL cannot represent",
                        c as u32
                    ),
                ));
            }
            c => result.push(c),
        }
    }
    Ok(result)
}

/// Generate a deny-default SBPL profile from the given policy.
#[cfg(test)]
pub fn generate_sbpl(policy: &Policy) -> Result<String, WardenError> {
    generate_sbpl_with_tmpdir(policy, "/private/tmp/mcp-writ-unused")
}

/// Generate SBPL that permits writes only under `tmpdir` (a private directory).
pub fn generate_sbpl_with_tmpdir(policy: &Policy, tmpdir: &str) -> Result<String, WardenError> {
    Ok(sbpl_profile(policy, tmpdir)?.0)
}

/// How the profile's network section is built.
///
/// `Native` is the historical behavior: under `deny_all_others` only
/// `localhost:port` entries extracted from `allow host=` rules emit
/// remote-TCP allows, everything else is kernel-denied; without it the
/// profile grants unrestricted `network-outbound` (+ `network-bind`
/// when `allow_listen` is set). `ConnectProxy` is the PR-11 opt-in:
/// the only remote-TCP endpoint the kernel lets the workload reach is
/// the loopback CONNECT proxy (plus any `localhost:port` rules the
/// policy declares) — the policy's real destination rules are enforced
/// by the proxy, not by SBPL, so `deny_all_others` never widens to
/// unrestricted outbound and the OS resolver (mDNSResponder) is not
/// granted at all (an OS-resolved name could reach an external DNS
/// server the policy never judged — resolution is the proxy's job).
pub(super) enum EgressProfile {
    Native,
    ConnectProxy { proxy_port: u16 },
}

/// Generate the SBPL profile together with the grant entries the same
/// emission produced — the launch report lists exactly these entries, so
/// the permission table can never diverge from the generated profile.
///
/// `grants` describes the *profile contents* (what the profile would
/// permit). Whether the kernel accepted the profile is a separate,
/// control-level observation — `sandbox-exec` does not expose it.
pub(super) fn sbpl_profile(
    policy: &Policy,
    tmpdir: &str,
) -> Result<(String, Vec<ProcessGrant>), WardenError> {
    sbpl_profile_with_egress(policy, tmpdir, EgressProfile::Native)
}

/// [`sbpl_profile`] with an explicit egress mode — see
/// [`EgressProfile`] for what the two modes emit.
pub(super) fn sbpl_profile_with_egress(
    policy: &Policy,
    tmpdir: &str,
    egress: EgressProfile,
) -> Result<(String, Vec<ProcessGrant>), WardenError> {
    let mut p = String::with_capacity(2048);
    let mut grants: Vec<ProcessGrant> = Vec::new();

    fn fs_grant(
        grants: &mut Vec<ProcessGrant>,
        path: &str,
        access: FsAccess,
        origin: GrantOrigin,
        reason: Option<&str>,
    ) {
        grants.push(ProcessGrant {
            subject: GrantSubject::FsPath {
                path: path.to_string(),
                access,
            },
            origin,
            state: ControlState::Planned,
            reason: reason.map(str::to_string),
        });
    }
    fn rule_grant(
        grants: &mut Vec<ProcessGrant>,
        kind: &'static str,
        name: &str,
        origin: GrantOrigin,
    ) {
        grants.push(ProcessGrant {
            subject: GrantSubject::Rule {
                kind,
                name: name.to_string(),
            },
            origin,
            state: ControlState::Planned,
            reason: None,
        });
    }
    /// Emit `(allow <rule_body>)` and record the matching grant — one
    /// call keeps the profile line and the grant entry on the same
    /// inputs, so the launch report cannot diverge from the profile.
    fn emit_rule(
        p: &mut String,
        grants: &mut Vec<ProcessGrant>,
        rule_body: &str,
        kind: &'static str,
        name: &str,
        origin: GrantOrigin,
    ) {
        p.push_str(&format!("(allow {rule_body})\n"));
        rule_grant(grants, kind, name, origin);
    }
    /// Emit `(allow <op> (<selector> "<path>"))`, record the matching fs
    /// grant, and queue `path` as an ancestor/symlink walk input — the
    /// SBPL line, the grant entry, and the walk input share one source.
    #[expect(clippy::too_many_arguments)]
    fn emit_fs(
        p: &mut String,
        grants: &mut Vec<ProcessGrant>,
        walk_inputs: &mut Vec<String>,
        op: &str,
        selector: &str,
        path: &str,
        access: FsAccess,
        origin: GrantOrigin,
    ) {
        p.push_str(&format!("(allow {op} ({selector} \"{path}\"))\n"));
        fs_grant(grants, path, access, origin, None);
        walk_inputs.push(path.to_string());
    }
    // Paths the ancestor/symlink walk must cover — every path the
    // profile grants, collected as each rule emits. The launch report
    // and this walk can never diverge from the generated profile.
    let mut walk_inputs: Vec<String> = Vec::new();

    // --- Base: deny-default ---
    p.push_str("(version 1)\n(deny default)\n");

    // --- Essential process operations ---
    for op in [
        "process-fork",
        "process-exec",
        "signal (target self)",
        "process-info* (target same-sandbox)",
        "sysctl-read",
    ] {
        emit_rule(
            &mut p,
            &mut grants,
            op,
            "operation",
            op,
            GrantOrigin::OsImplementation,
        );
    }

    // --- System library reads (required by most processes) ---
    for path in ["/usr/lib", "/System/Library", "/usr/share"] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read*",
            "subpath",
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Dynamic library/framework mapping (required by dyld) ---
    for path in ["/usr/lib", "/System/Library"] {
        emit_rule(
            &mut p,
            &mut grants,
            &format!("file-map-executable (subpath \"{path}\")"),
            "file_map_executable",
            path,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Executable binary paths (required for exec to load binaries) ---
    for path in ["/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec"] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read-data file-read-metadata",
            "subpath",
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Standard config and metadata paths ---
    for path in [
        "/etc/hosts",
        "/etc/resolv.conf",
        "/private/etc/hosts",
        "/private/etc/resolv.conf",
        "/",
    ] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read*",
            "literal",
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // Local timezone data: tz detection (tzlocal, ICU) reads
    // /etc/localtime -> /var/db/timezone/zoneinfo/…; without it a
    // sandboxed server silently computes a different local zone than the
    // unsandboxed host.
    for (selector, path) in [
        ("literal", "/etc/localtime"),
        ("literal", "/private/etc/localtime"),
        ("subpath", "/private/var/db/timezone"),
    ] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            "file-read*",
            selector,
            path,
            FsAccess::Read,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Symlink resolution metadata ---
    p.push_str("(allow file-read-metadata (literal \"/var\"))\n");
    fs_grant(
        &mut grants,
        "/var",
        FsAccess::Traverse,
        GrantOrigin::OsImplementation,
        None,
    );

    // --- Device nodes ---
    for (op, selector, path, access) in [
        ("file-read*", "literal", "/dev/null", FsAccess::Read),
        ("file-read*", "literal", "/dev/urandom", FsAccess::Read),
        ("file-read*", "literal", "/dev/random", FsAccess::Read),
        (
            "file-write-data",
            "literal",
            "/dev/null",
            FsAccess::ReadWrite,
        ),
        (
            "file-read-data file-write-data",
            "subpath",
            "/dev/fd",
            FsAccess::ReadWrite,
        ),
    ] {
        emit_fs(
            &mut p,
            &mut grants,
            &mut walk_inputs,
            op,
            selector,
            path,
            access,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Private TMPDIR only (no shared /tmp or /private/tmp) ---
    let escaped_tmp = escape_sbpl_path(tmpdir)?;
    p.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{escaped_tmp}\"))\n"
    ));
    grants.push(ProcessGrant {
        subject: GrantSubject::PrivateTmpdir,
        origin: GrantOrigin::Runtime,
        state: ControlState::Planned,
        reason: None,
    });
    walk_inputs.push(tmpdir.to_string());

    // --- IOKit (required for basic system queries) ---
    emit_rule(
        &mut p,
        &mut grants,
        "iokit-open (iokit-registry-entry-class \"RootDomainUserClient\")",
        "iokit_open",
        "RootDomainUserClient",
        GrantOrigin::OsImplementation,
    );

    // --- Mach services (required for basic operation) ---
    let mach_services = [
        "com.apple.system.logger",
        "com.apple.system.opendirectoryd.libinfo",
        "com.apple.system.DirectoryService.libinfo_v1",
        "com.apple.trustd",
        "com.apple.trustd.agent",
        "com.apple.cfprefsd.daemon",
        "com.apple.cfprefsd.agent",
        "com.apple.logd",
        "com.apple.secinitd",
        "com.apple.bsd.dirhelper",
    ];
    p.push_str("(allow mach-lookup\n");
    for (i, service) in mach_services.iter().enumerate() {
        let closing = if i + 1 == mach_services.len() {
            ")"
        } else {
            ""
        };
        p.push_str(&format!("  (global-name \"{service}\"){closing}\n"));
        rule_grant(
            &mut grants,
            "mach_lookup",
            service,
            GrantOrigin::OsImplementation,
        );
    }

    // --- Syslog socket (required for logging) ---
    emit_rule(
        &mut p,
        &mut grants,
        "network-outbound (literal \"/private/var/run/syslog\")",
        "unix_socket_outbound",
        "/private/var/run/syslog",
        GrantOrigin::OsImplementation,
    );

    // Spelled-path conflict checks ran at load time, but a grant like
    // `/etc` canonicalizes to `/private/etc` and could still reach a
    // denied subtree the spelled comparison never saw — under
    // deny-default SBPL an `(allow …)` line is the only thing that would
    // reopen it, so re-check the canonical forms.
    let denied_canon: Vec<String> = policy
        .fs
        .denied_paths
        .iter()
        .map(|d| canonical_grant_path(d))
        .collect();

    // --- Policy: read-only paths ---
    for path in &policy.fs.read_only {
        let canon = canonical_grant_path(path);
        reject_denied_grant(path, &canon, &denied_canon)?;
        let escaped = escape_sbpl_path(&canon)?;
        p.push_str(&format!("(allow file-read* (subpath \"{escaped}\"))\n"));
        // Record the canonical path the SBPL line actually grants; keep the
        // spelled form in the reason when canonicalization rewrote it, and
        // feed the spelled form to the ancestor/symlink walk — the spelled
        // chain is where its symlink hops live.
        let reason = (canon != *path).then(|| format!("canonicalized from {path}"));
        fs_grant(
            &mut grants,
            &canon,
            FsAccess::Read,
            GrantOrigin::Policy,
            reason.as_deref(),
        );
        walk_inputs.push(path.clone());
    }

    // --- Policy: read-write paths ---
    for path in &policy.fs.read_write {
        let canon = canonical_grant_path(path);
        reject_denied_grant(path, &canon, &denied_canon)?;
        let escaped = escape_sbpl_path(&canon)?;
        p.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{escaped}\"))\n"
        ));
        let reason = (canon != *path).then(|| format!("canonicalized from {path}"));
        fs_grant(
            &mut grants,
            &canon,
            FsAccess::ReadWrite,
            GrantOrigin::Policy,
            reason.as_deref(),
        );
        walk_inputs.push(path.clone());
    }

    // --- Traversal: a granted path is unreachable when its ancestors
    // cannot even be stat'd — runtimes walk components explicitly
    // (Node's realpathSync module loader, CPython's getpath realpath).
    // Grant metadata on every ancestor of every granted path; "/" is
    // already covered by the literal above. Symlink hops in the spelled
    // form additionally need file-read-data — following the link is a
    // read of the link vnode (e.g. /tmp -> private/tmp).
    // BTreeSet: SBPL lines and grant entries are emitted in sorted order
    // so the same policy always produces the same profile text.
    //
    // /bin/sh is a shim that opens this symlink at startup to pick the
    // real shell; it is a walk input only — the leaf-symlink check below
    // grants file-read* on it.
    walk_inputs.push("/private/var/select/sh".to_string());
    let mut ancestors = std::collections::BTreeSet::new();
    let mut links = std::collections::BTreeSet::new();
    for spelled in &walk_inputs {
        for anc in Path::new(&canonical_grant_path(spelled))
            .ancestors()
            .skip(1)
        {
            let s = anc.to_string_lossy().into_owned();
            if s != "/" {
                ancestors.insert(s);
            }
        }
        let spelled_path = Path::new(spelled.as_str());
        for anc in spelled_path.ancestors() {
            if anc.parent().is_none() {
                continue;
            }
            let s = anc.to_string_lossy().into_owned();
            let is_link = std::fs::symlink_metadata(anc)
                .map(|m| m.file_type().is_symlink())
                .unwrap_or(false);
            if is_link {
                links.insert(s);
            } else if anc != spelled_path {
                ancestors.insert(s);
            }
        }
    }
    for s in links {
        let escaped = escape_sbpl_path(&s)?;
        p.push_str(&format!("(allow file-read* (literal \"{escaped}\"))\n"));
        fs_grant(
            &mut grants,
            &s,
            FsAccess::Read,
            GrantOrigin::Runtime,
            Some("symlink hop on a granted path"),
        );
    }
    for s in ancestors {
        let escaped = escape_sbpl_path(&s)?;
        p.push_str(&format!(
            "(allow file-read-metadata (literal \"{escaped}\"))\n"
        ));
        fs_grant(
            &mut grants,
            &s,
            FsAccess::Traverse,
            GrantOrigin::Runtime,
            Some("ancestor of a granted path"),
        );
    }

    // --- Network rules ---
    let proxied = matches!(egress, EgressProfile::ConnectProxy { .. });
    if let EgressProfile::ConnectProxy { proxy_port } = egress {
        // The single endpoint every outbound TCP connect is pinned to —
        // the loopback CONNECT proxy, which evaluates the policy's real
        // destination rules. Emitted unconditionally so the kernel
        // never sees an unrestricted `network-outbound`, whatever the
        // policy's default posture says.
        emit_rule(
            &mut p,
            &mut grants,
            &format!("network-outbound (remote tcp \"localhost:{proxy_port}\")"),
            "connect_proxy",
            &format!("localhost:{proxy_port}"),
            GrantOrigin::Runtime,
        );
    }
    if proxied || policy.network.outbound.deny_all_others {
        // Consume the allow rules *with* their qualifiers, not the
        // flat `allowed`/`allowed_cidrs` lists: a parsed
        // `allow host="localhost:8080"` folds its port out of
        // `allowed` (`allowed_port_qualified` keeps the spelling), and
        // bare-port / scoped-wildcard entries (`443`, `* port=443`)
        // exist only in `egress_rules` — iterating the flat lists
        // would emit no rule for any of them. The qualifiers also
        // gate the emit itself: SBPL `remote tcp` rules carry no
        // proto, so a `proto=udp`-only rule must be skipped rather
        // than silently widened to a TCP grant it never declared.
        for rule in policy
            .network
            .outbound
            .egress_rules()
            .iter()
            .filter(|r| r.allow)
        {
            let host = match &rule.dest {
                crate::policy::EgressDest::Host(h) => h.as_str(),
                // `cidr` entries are IP-layer rules — the SBPL profile
                // can only express `localhost:port` remote endpoints,
                // so none of them emit a rule.
                crate::policy::EgressDest::Cidr(cidr) => {
                    grants.push(ProcessGrant {
                        subject: GrantSubject::Rule {
                            kind: "net_destination_cidr",
                            name: cidr.clone(),
                        },
                        origin: GrantOrigin::Policy,
                        state: ControlState::Skipped,
                        reason: Some(if proxied {
                            "SBPL remote rules express localhost ports only — this \
                             IP-layer entry is enforced by the CONNECT proxy"
                                .to_string()
                        } else {
                            "SBPL remote rules express localhost ports only — this \
                             IP-layer entry is enforced at the RPC layer only"
                                .to_string()
                        }),
                    });
                    continue;
                }
            };
            // The grant row names the effective destination spelling
            // (`host` plus a declared `:port` the flat list folded).
            let rule_name = match rule.port {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            let skip = |grants: &mut Vec<ProcessGrant>, reason: String| {
                grants.push(ProcessGrant {
                    subject: GrantSubject::Rule {
                        kind: "tcp_host",
                        name: rule_name.clone(),
                    },
                    origin: GrantOrigin::Policy,
                    state: ControlState::Skipped,
                    reason: Some(reason),
                });
            };
            // A rule whose qualifiers cover no TCP gets no rule —
            // emitting `remote tcp` would grant a TCP reach the
            // policy never allowed (the SBPL form cannot express
            // proto).
            let tcp_blocked = !rule.proto.covers(crate::policy::EgressProto::Tcp);
            let extracted = match extract_local_port(host) {
                Ok(spelled_port) => {
                    // `Ok` = a local shape (loopback name, wildcard,
                    // or bare port); the effective port is the
                    // spelling's own port else the rule qualifier's.
                    spelled_port.or(rule.port)
                }
                Err(e) => {
                    // In proxy mode a remote host/name is not a build
                    // failure (the proxy enforces it); under the native
                    // path the refusal contract of `extract_local_port`
                    // still applies — propagate it there.
                    if !proxied {
                        return Err(e);
                    }
                    let reason = if tcp_blocked {
                        "no local port extracted and no TCP coverage — no SBPL rule \
                         is emitted; UDP has no CONNECT-proxy path and is denied \
                         outright, so the rule authorizes nothing on this path"
                            .to_string()
                    } else {
                        "no local port extracted; no SBPL rule is emitted — \
                         this destination is enforced by the CONNECT proxy"
                            .to_string()
                    };
                    skip(&mut grants, reason);
                    continue;
                }
            };
            match extracted {
                Some(port) => {
                    if proxied && !is_explicit_loopback_host(host) {
                        // Proxy mode: only an entry that names an
                        // explicit loopback endpoint gets a direct
                        // `localhost:port` rule — bare-port and
                        // `*`-wildcard spellings name a wider
                        // destination set than loopback, so they route
                        // to the CONNECT proxy (which judges each
                        // CONNECT authority) instead of a direct SBPL
                        // grant the policy did not declare.
                        skip(
                            &mut grants,
                            "not an explicit loopback endpoint; no SBPL rule is \
                             emitted — this destination is enforced by the CONNECT \
                             proxy"
                                .to_string(),
                        );
                    } else if tcp_blocked {
                        skip(
                            &mut grants,
                            if proxied {
                                "rule covers no TCP and UDP egress is denied outright \
                                 on this path — no SBPL rule is emitted"
                                    .to_string()
                            } else {
                                "rule covers no TCP — SBPL remote rules are tcp-only, \
                                 so emitting one would widen it; enforced at the RPC \
                                 layer only"
                                    .to_string()
                            },
                        );
                    } else {
                        emit_rule(
                            &mut p,
                            &mut grants,
                            &format!("network-outbound (remote tcp \"localhost:{port}\")"),
                            "tcp_loopback",
                            &format!("localhost:{port}"),
                            GrantOrigin::Policy,
                        );
                    }
                }
                None => {
                    if tcp_blocked {
                        skip(
                            &mut grants,
                            if proxied {
                                "rule covers no TCP and UDP egress is denied outright \
                                 on this path — no SBPL rule is emitted"
                                    .to_string()
                            } else {
                                "rule covers no TCP — SBPL remote rules are tcp-only, \
                                 so emitting one would widen it; enforced at the RPC \
                                 layer only"
                                    .to_string()
                            },
                        );
                    } else {
                        skip(
                            &mut grants,
                            if proxied {
                                "no local port extracted; no SBPL rule is emitted — \
                                 this destination is enforced by the CONNECT proxy"
                                    .to_string()
                            } else {
                                "no local port extracted; no SBPL rule is emitted — \
                                 this entry is enforced at the RPC layer only"
                                    .to_string()
                            },
                        );
                    }
                }
            }
        }
        // In proxy mode `allow_listen` is honored as loopback-only: the
        // workload may bind/accept TCP on loopback, never an external
        // interface. UDP has no proxy path and stays fully denied.
        if proxied && policy.network.inbound.allow_listen {
            emit_rule(
                &mut p,
                &mut grants,
                "network-bind (local tcp \"localhost:*\")",
                "network_bind",
                "loopback-only (proxy mode)",
                GrantOrigin::Policy,
            );
            emit_rule(
                &mut p,
                &mut grants,
                "network-inbound (local tcp \"localhost:*\")",
                "network_inbound",
                "loopback-only (proxy mode)",
                GrantOrigin::Policy,
            );
        }
    } else {
        emit_rule(
            &mut p,
            &mut grants,
            "network-outbound",
            "network_outbound",
            "unrestricted",
            GrantOrigin::Policy,
        );
        if policy.network.inbound.allow_listen {
            emit_rule(
                &mut p,
                &mut grants,
                "network-bind",
                "network_bind",
                "unrestricted",
                GrantOrigin::Policy,
            );
        }
    }

    // --- DNS resolution (allow mDNSResponder for name resolution) ---
    // In CONNECT-proxy mode the OS resolver stays denied: an
    // OS-resolved name could reach an upstream DNS server the policy
    // never judged (a covert egress channel), and proxied clients do
    // not need it — they hand the hostname to the proxy, which resolves
    // outside the sandbox. `getaddrinfo` inside the workload simply
    // fails — the fail-closed posture the improvement plan prescribes.
    if !proxied {
        emit_rule(
            &mut p,
            &mut grants,
            "mach-lookup (global-name \"com.apple.mDNSResponder\")",
            "mach_lookup",
            "com.apple.mDNSResponder",
            GrantOrigin::OsImplementation,
        );
    }

    Ok((p, grants))
}

/// Resolve a policy path to the form the kernel matches. Sandbox filters
/// compare the fully-resolved vnode path, so a grant written as `/tmp/x`
/// would never match `/private/tmp/x`. Canonicalize the deepest existing
/// ancestor and reattach the remainder so write targets that do not
/// exist yet still resolve; fall back to the literal when nothing does.
fn canonical_grant_path(path: &str) -> String {
    let mut cursor = Path::new(path).to_path_buf();
    let mut tail = Vec::new();
    loop {
        match cursor.canonicalize() {
            Ok(mut canon) => {
                for seg in tail.iter().rev() {
                    canon.push(seg);
                }
                return canon.to_string_lossy().into_owned();
            }
            Err(_) => match cursor.file_name() {
                Some(name) => {
                    tail.push(name.to_os_string());
                    cursor.pop();
                }
                None => return path.to_string(),
            },
        }
    }
}

/// A canonicalized grant must not equal, contain, or sit inside a
/// canonicalized denied path — any overlap means the `(allow …)` line
/// would silently re-allow what the policy denied.
fn reject_denied_grant(
    spelled: &str,
    canon: &str,
    denied_canon: &[String],
) -> Result<(), WardenError> {
    for denied in denied_canon {
        if is_strict_subpath_or_descendant_for(canon, denied, TargetOs::MacOs)
            || is_strict_subpath_or_descendant_for(denied, canon, TargetOs::MacOs)
        {
            return Err(WardenError::sandbox_setup(
                SandboxStage::Policy,
                format!(
                    "filesystem grant '{spelled}' resolves to '{canon}', which overlaps denied path '{denied}'"
                ),
            ));
        }
    }
    Ok(())
}

/// Per-launch private directory used as TMPDIR inside the sandbox.
/// Removed when dropped (kept alive by the child wrapper).
pub struct PrivateTmpDir {
    path: PathBuf,
}

impl PrivateTmpDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Create a per-launch private directory used as TMPDIR inside the sandbox.
pub fn create_private_tmpdir() -> Result<PrivateTmpDir, WardenError> {
    let dir = std::env::temp_dir().join(format!(
        "mcp-writ-sbx-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("failed to create private TMPDIR: {e}"),
        )
    })?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            WardenError::sandbox_setup(
                crate::error::SandboxStage::Prepare,
                format!("failed to restrict private TMPDIR permissions: {e}"),
            )
        })?;
    }
    // SBPL matches the real path. On macOS, /var/folders is reached
    // through /private/var/folders, so retain the canonical private path.
    let canonical = dir.canonicalize().map_err(|e| {
        let _ = std::fs::remove_dir(&dir);
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("failed to resolve private TMPDIR: {e}"),
        )
    })?;
    Ok(PrivateTmpDir { path: canonical })
}

/// Child process plus the private TMPDIR that must outlive it.
pub struct MacosChild {
    child: Child,
    /// Process group id captured at spawn (`process_group(0)` ⇒ pgid ==
    /// child pid). The group outlives its leader while any descendant
    /// still belongs to it, so the retained id stays a valid kill target
    /// after the leader has exited — unlike a `child.id()` read.
    pgid: u32,
    /// Whether the leader has been reaped by `wait`/`try_wait`. Once
    /// reaped, the freed pid/pgid may name a recycled, unrelated
    /// process group — group signaling must stop.
    reaped: bool,
    _tmpdir: PrivateTmpDir,
}

impl MacosChild {
    /// Observe the leader's exit before reaping it. A blocking `WNOWAIT`
    /// waitid keeps the zombie — and therefore the pgid the sweep names —
    /// allocated; sweeping after `wait` has already reaped could signal a
    /// recycled, unrelated process group.
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if !self.reaped && self.leader_exited_unreaped(true) {
            // Leader is a zombie still pinning the group — sweep the
            // surviving descendants, then the real wait reaps it below.
            self.kill_group();
        }
        let status = self.child.wait();
        if status.is_ok() {
            self.reaped = true;
        }
        status
    }

    /// True when the leader has exited but not yet been reaped — see
    /// [`exited_unreaped`] for the probe semantics.
    #[cfg(unix)]
    fn leader_exited_unreaped(&self, blocking: bool) -> bool {
        exited_unreaped(self.child.id(), blocking)
    }

    /// SIGKILL the process group by the pgid captured at spawn —
    /// descendants of an exited leader still hold the group and are
    /// reachable through it. Skipped once the leader has been reaped:
    /// the freed pgid could then name a recycled, unrelated group.
    fn kill_group(&self) {
        if self.reaped {
            return;
        }
        #[cfg(unix)]
        unsafe {
            let _ = libc_kill(-(self.pgid as i32), SIGKILL);
        }
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        self.kill_group();
        self.child.kill()
    }

    /// Non-blocking poll that reaps on `Some`. Probes the exit without
    /// reaping first: a leader the inner `try_wait` already reaped frees
    /// its pid, and the recorded pgid may by then name a recycled group
    /// that must not be signaled — so the sweep runs only while the
    /// zombie still pins it. Narrow gap a caller must accept: if the
    /// leader exits between the probe and the inner call — the probe saw
    /// it alive — the sweep never ran and detached descendants can
    /// outlive the session (the freed pgid must still never be signaled,
    /// so skipping is the safe direction; `wait` closes the gap with a
    /// blocking probe).
    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if !self.reaped && self.leader_exited_unreaped(false) {
            self.kill_group();
        }
        let status = self.child.try_wait();
        if matches!(status, Ok(Some(_))) {
            self.reaped = true;
        }
        status
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }
}

impl std::ops::Deref for MacosChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for MacosChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for MacosChild {
    fn drop(&mut self) {
        // The group is killed whether or not the leader already exited:
        // descendants it spawned still hold the pgid and must not
        // outlive the session. `kill_group` skips a reaped leader —
        // the freed pgid may have been recycled into another group.
        self.kill_group();
        match self.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.child.kill();
                let _ = self.wait();
            }
        }
    }
}

/// Spawn a child process sandboxed via `sandbox-exec`.
///
/// The helper is invoked by its validated absolute path only — `PATH`
/// order can never substitute a fake helper that skips the profile.
pub fn spawn_sandboxed(
    policy: &Policy,
    command: &str,
    args: &[String],
) -> Result<MacosChild, WardenError> {
    let helper = super::sandbox_exec::sandbox_exec_path()?;
    let tmpdir = create_private_tmpdir()?;
    let sbpl = generate_sbpl_with_tmpdir(policy, tmpdir.path().to_string_lossy().as_ref())?;

    let mut cmd = Command::new(&helper);
    cmd.arg("-p")
        .arg(&sbpl)
        .arg("--")
        .arg(command)
        .args(args)
        .env("TMPDIR", tmpdir.path())
        .env("TMP", tmpdir.path())
        .env("TEMP", tmpdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        cmd.process_group(0);
        // fd hygiene: the child seals every ambient descriptor above
        // stdio — sandboxed or not, inherited fds are capabilities the
        // SBPL path rules never mediated.
        super::attach_fd_hygiene(&mut cmd, &[])
            .map_err(|e| WardenError::sandbox_setup(SandboxStage::Prepare, e.to_string()))?;
    }
    let child = cmd.spawn().map_err(WardenError::ProcessSpawn)?;
    let pgid = child.id();
    Ok(MacosChild {
        child,
        pgid,
        reaped: false,
        _tmpdir: tmpdir,
    })
}

/// True when `pid` exited but has not yet been reaped. The `WNOWAIT`
/// waitid reports the exit while keeping the zombie, so the pid — and
/// the process-group id a sweep names — stays reserved until a real
/// wait consumes it. `blocking` omits `WNOHANG` so the probe itself
/// waits for the exit (used by `MacosChild::wait`); callers polling
/// pass `WNOHANG`. `waitid` is the call where `WNOWAIT` is specified;
/// under `WNOHANG` it returns 0 for both a report and "nothing to
/// report", so `si_pid` distinguishes the two. EINTR is retried — a
/// caught signal landing mid-probe is not evidence of state.
#[cfg(unix)]
fn exited_unreaped(pid: u32, blocking: bool) -> bool {
    let flags = libc::WEXITED | libc::WNOWAIT | if blocking { 0 } else { libc::WNOHANG };
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let ret = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, flags) };
        if ret == 0 {
            return unsafe { info.si_pid() } == pid as libc::pid_t;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            return false;
        }
    }
}

/// Result of the post-spawn liveness probe ([`initial_exit_check`]).
///
/// `sandbox-exec` applies the profile to itself and then execs the
/// workload, so a rejected profile or an un-exec'able command exits the
/// process within milliseconds — though a workload that simply finishes
/// quickly exits the same way, so an early exit alone does not prove
/// rejection. Surviving the window is the only post-spawn fact the
/// mechanism exposes — it never proves the kernel accepted individual
/// rules.
pub(crate) enum SpawnLiveness {
    /// The process was still running when the probe window ended.
    Running,
    /// The process exited inside the probe window (status recorded).
    Exited(std::process::ExitStatus),
    /// The probe itself failed (`try_wait` error); state is unknown.
    PollFailed,
}

/// Total window [`initial_exit_check`] observes. A `sandbox-exec`
/// startup failure exits in single-digit milliseconds; the window
/// bounds the check without adding noticeable latency to a healthy
/// launch.
const INITIAL_EXIT_WINDOW: Duration = Duration::from_millis(150);
/// Poll granularity inside the window.
const INITIAL_EXIT_POLL: Duration = Duration::from_millis(10);

/// Bounded post-spawn liveness probe: polls until the child exits or
/// [`INITIAL_EXIT_WINDOW`] elapses. This is the only way to catch a
/// `sandbox-exec` startup rejection — `spawn()` succeeding only proves
/// the binary ran, and the child's stderr is the workload's own
/// channel, never parsed as evidence. Awaits between polls so the
/// spawn path never holds a runtime worker thread for the window.
///
/// The exit is observed through a non-reaping `WNOWAIT` probe first:
/// while the zombie still pins its pid/pgid the process group is
/// swept (`process_group(0)` ⇒ pgid == pid), and only then does
/// `try_wait` reap the leader. Sweeping after the reap could signal a
/// recycled, unrelated group. An exit landing between the probe and
/// the inner `try_wait` reaps without a sweep — the freed pgid must
/// still never be signaled, so skipping is the safe direction.
pub(super) async fn initial_exit_check(child: &mut tokio::process::Child) -> SpawnLiveness {
    let deadline = Instant::now() + INITIAL_EXIT_WINDOW;
    loop {
        #[cfg(unix)]
        if let Some(pid) = child.id()
            && exited_unreaped(pid, false)
        {
            // Leader is a zombie pinning the group — descendants it
            // spawned still hold the pgid and must not outlive the
            // session. The `try_wait` below then reaps the leader.
            let _ = unsafe { libc_kill(-(pid as i32), SIGKILL) };
        }
        match child.try_wait() {
            Ok(Some(status)) => return SpawnLiveness::Exited(status),
            Ok(None) if Instant::now() >= deadline => return SpawnLiveness::Running,
            Ok(None) => tokio::time::sleep(INITIAL_EXIT_POLL).await,
            Err(_) => return SpawnLiveness::PollFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default_policy;

    // ---------------------------------------------------------------
    // extract_port
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_port_host_colon_port() {
        assert_eq!(extract_local_port("localhost:8080").unwrap(), Some(8080));
        assert_eq!(extract_local_port("*:443").unwrap(), Some(443));
    }

    #[test]
    fn test_extract_port_colon_port() {
        assert_eq!(extract_local_port(":80").unwrap(), Some(80));
    }

    #[test]
    fn test_extract_port_plain_number() {
        assert_eq!(extract_local_port("80").unwrap(), Some(80));
    }

    #[test]
    fn test_extract_port_invalid() {
        assert!(extract_local_port("not-a-port").is_err());
        assert_eq!(extract_local_port("").unwrap(), None);
    }

    #[test]
    fn test_extract_port_rejects_remote_host() {
        assert!(extract_local_port("api.example.com:443").is_err());
        assert!(extract_local_port("https://evil.example").is_err());
    }

    #[test]
    fn test_extract_port_bare_ipv6_loopback() {
        assert_eq!(extract_local_port("::1").unwrap(), None);
        assert_eq!(extract_local_port("[::1]").unwrap(), None);
        assert_eq!(extract_local_port("[::1]:8080").unwrap(), Some(8080));
    }

    #[test]
    fn test_extract_port_bare_ipv6_is_never_host_port() {
        // A bare multi-colon string is a v6 literal, not host:port —
        // `::1:8080` is the v6 address `::1:8080`, not `::1` port
        // 8080. Any non-loopback literal is a remote host and must
        // refuse, exactly like a remote name.
        assert!(extract_local_port("::1:8080").is_err());
        assert!(extract_local_port("::1:443").is_err());
        assert!(extract_local_port("2001:db8::1").is_err());
        // The loopback literal itself stays port-less.
        assert_eq!(extract_local_port("::1").unwrap(), None);
    }

    #[test]
    fn test_is_explicit_loopback_host_classifies_stored_forms() {
        // The host identity the parser stores: `host="::1"` is the
        // loopback literal; `host="::1:8080"` is the *non-loopback*
        // v6 address `::1:8080` — never `::1` with a port.
        assert!(is_explicit_loopback_host("::1"));
        assert!(is_explicit_loopback_host("[::1]"));
        assert!(is_explicit_loopback_host("[::1]:8080"));
        assert!(is_explicit_loopback_host("localhost"));
        assert!(is_explicit_loopback_host("localhost:8080"));
        assert!(is_explicit_loopback_host("127.0.0.1"));
        assert!(is_explicit_loopback_host("127.0.0.1:80"));
        assert!(!is_explicit_loopback_host("::1:8080"));
        assert!(!is_explicit_loopback_host("::1:443"));
        assert!(!is_explicit_loopback_host("2001:db8::1"));
        assert!(!is_explicit_loopback_host("*:443"));
        assert!(!is_explicit_loopback_host("443"));
        assert!(!is_explicit_loopback_host("api.example.com:443"));
    }

    // ---------------------------------------------------------------
    // escape_sbpl_path
    // ---------------------------------------------------------------

    #[test]
    fn test_escape_no_special_chars() {
        assert_eq!(
            escape_sbpl_path("/usr/local/bin")
                .expect("failed to escape sbpl path for no special chars"),
            "/usr/local/bin"
        );
    }

    #[test]
    fn test_escape_quotes() {
        assert_eq!(
            escape_sbpl_path("/path/with\"quotes\"")
                .expect("failed to escape sbpl path for quotes"),
            "/path/with\\\"quotes\\\""
        );
    }

    #[test]
    fn test_escape_backslash() {
        assert_eq!(
            escape_sbpl_path("/path\\back").expect("failed to escape sbpl path for backslash"),
            "/path\\\\back"
        );
    }

    #[test]
    fn test_escape_supported_control_chars() {
        assert_eq!(
            escape_sbpl_path("/path\nwith\nnewlines").unwrap(),
            "/path\\nwith\\nnewlines"
        );
        assert_eq!(
            escape_sbpl_path("/path\twith\ttabs").unwrap(),
            "/path\\twith\\ttabs"
        );
        assert_eq!(
            escape_sbpl_path("/path\rwith\rreturns").unwrap(),
            "/path\\rwith\\rreturns"
        );
    }

    #[test]
    fn test_escape_rejects_nul() {
        let result = escape_sbpl_path("/path\0with_nul");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+0000"),
            "error should mention the codepoint: {msg}"
        );
    }

    #[test]
    fn test_escape_rejects_other_control_chars() {
        // BEL (U+0007)
        let result = escape_sbpl_path("/path\x07bel");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+0007"),
            "error should mention the codepoint: {msg}"
        );

        // ESC (U+001B)
        let result = escape_sbpl_path("/path\x1besc");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+001B"),
            "error should mention the codepoint: {msg}"
        );

        // DEL (U+007F)
        let result = escape_sbpl_path("/path\x7Fdel");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+007F"),
            "error should mention the codepoint: {msg}"
        );
    }

    // ---------------------------------------------------------------
    // generate_sbpl — structure
    // ---------------------------------------------------------------

    #[test]
    fn test_sbpl_starts_with_version_and_deny_default() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.starts_with("(version 1)\n(deny default)\n"));
    }

    #[test]
    fn test_sbpl_contains_essential_operations() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow process-fork)"));
        assert!(sbpl.contains("(allow process-exec)"));
        assert!(sbpl.contains("(allow signal (target self))"));
        assert!(sbpl.contains("(allow sysctl-read)"));
        assert!(sbpl.contains("(allow process-info* (target same-sandbox))"));
    }

    #[test]
    fn test_sbpl_contains_system_library_reads() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (subpath \"/usr/lib\"))"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/System/Library\"))"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/usr/share\"))"));
        // Dynamic library mapping
        assert!(sbpl.contains("(allow file-map-executable (subpath \"/usr/lib\"))"));
        assert!(sbpl.contains("(allow file-map-executable (subpath \"/System/Library\"))"));
        // Executable binary paths
        assert!(sbpl.contains("(subpath \"/bin\")"));
        assert!(sbpl.contains("(subpath \"/usr/bin\")"));
    }

    #[test]
    fn test_sbpl_contains_dev_nodes() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (literal \"/dev/null\"))"));
        assert!(sbpl.contains("(allow file-read* (literal \"/dev/urandom\"))"));
    }

    #[test]
    fn test_sbpl_contains_tmp_paths() {
        let policy = default_policy();
        let sbpl = generate_sbpl_with_tmpdir(&policy, "/private/tmp/mcp-writ-test-tmp").unwrap();
        assert!(sbpl.contains(
            "(allow file-read* file-write* (subpath \"/private/tmp/mcp-writ-test-tmp\"))"
        ));
        assert!(!sbpl.contains("(allow file-read* file-write* (subpath \"/private/tmp\"))"));
        assert!(!sbpl.contains("(allow file-read* file-write* (subpath \"/tmp\"))"));
        assert!(!sbpl.contains("(subpath \"/etc\")"));
        assert!(sbpl.contains("(literal \"/etc/hosts\")"));
    }

    #[test]
    fn test_sbpl_contains_mach_services() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("com.apple.system.logger"));
        assert!(sbpl.contains("com.apple.mDNSResponder"));
        assert!(sbpl.contains("com.apple.trustd"));
        assert!(sbpl.contains("com.apple.secinitd"));
        assert!(sbpl.contains("com.apple.system.opendirectoryd.libinfo"));
    }

    // ---------------------------------------------------------------
    // generate_sbpl — filesystem policy
    // ---------------------------------------------------------------

    #[test]
    fn test_sbpl_read_only_paths() {
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/opt/data".to_string(), "/usr/local/share".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (subpath \"/opt/data\"))"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/usr/local/share\"))"));
    }

    #[test]
    fn test_sbpl_read_write_paths() {
        let mut policy = default_policy();
        // "/var/data" canonicalizes to "/private/var/data" on macOS —
        // the kernel matches resolved vnode paths, so the profile must
        // carry the resolved form.
        policy.fs.read_write = vec!["/var/data".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/private/var/data\"))"));
    }

    #[test]
    fn test_grant_overlapping_denied_path_rejected() {
        // `/etc` canonicalizes to `/private/etc` on macOS, so a spelled
        // grant that cleared the load-time conflict check can still reach
        // a denied subtree — the emitted `(allow …)` line would reopen it.
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/etc".to_string()];
        policy.fs.denied_paths = vec!["/private/etc/mcp-writ-denied".to_string()];
        let err = generate_sbpl(&policy).expect_err("grant covering a denied path must fail");
        assert!(
            err.to_string().contains("overlaps denied path"),
            "got: {err}"
        );

        let mut policy = default_policy();
        policy.fs.read_write = vec!["/private/etc/mcp-writ-denied/sub".to_string()];
        policy.fs.denied_paths = vec!["/etc/mcp-writ-denied".to_string()];
        let err = generate_sbpl(&policy).expect_err("grant inside a denied path must fail");
        assert!(
            err.to_string().contains("overlaps denied path"),
            "got: {err}"
        );

        // Distinct spellings that canonicalize to the same path — the
        // grant re-allows the denial verbatim. `is_strict_subpath_or_
        // descendant_for` already catches equality (case-insensitively
        // under the macOS component rules), and a case-only difference
        // between canonicalized spellings must reject identically.
        assert!(
            reject_denied_grant(
                "/private/etc/mcp-writ-denied",
                "/private/etc/mcp-writ-denied",
                &["/private/etc/mcp-writ-denied".to_string()],
            )
            .is_err(),
            "canonical-equal grant must be rejected"
        );
        assert!(
            reject_denied_grant(
                "/private/etc/MCP-WRIT-DENIED",
                "/private/etc/MCP-WRIT-DENIED",
                &["/private/etc/mcp-writ-denied".to_string()],
            )
            .is_err(),
            "case-variant canonical-equal grant must be rejected"
        );
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/etc/mcp-writ-denied".to_string()];
        policy.fs.denied_paths = vec!["/private/etc/mcp-writ-denied".to_string()];
        let err = generate_sbpl(&policy)
            .expect_err("grant canonicalizing to the denied path itself must fail");
        assert!(
            err.to_string().contains("overlaps denied path"),
            "got: {err}"
        );
    }

    #[test]
    fn test_sbpl_canonicalizes_symlinked_grant_prefix() {
        // A policy path under /tmp (a symlink to /private/tmp) must emit
        // the resolved subpath, including ancestors for traversal —
        // otherwise the grant silently matches nothing.
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/tmp/mcp-writ-nonexistent-dir".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(
            sbpl.contains("(allow file-read* (subpath \"/private/tmp/mcp-writ-nonexistent-dir\"))")
        );
        assert!(sbpl.contains("(allow file-read-metadata (literal \"/private/tmp\"))"));
        // /tmp is a symlink to private/tmp — following it requires
        // file-read-data on the link vnode itself, not just metadata.
        assert!(sbpl.contains("(allow file-read* (literal \"/tmp\"))"));
    }

    #[test]
    fn test_grant_records_canonical_path_with_spelled_reason() {
        // The recorded grant must name the path the SBPL line actually
        // grants (the canonical form); when canonicalization rewrote it,
        // the spelled policy path stays in the reason.
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/tmp/mcp-writ-nonexistent-dir".to_string()];
        let (sbpl, grants) = sbpl_profile(&policy, "/private/tmp/mcp-writ-unused").unwrap();
        assert!(
            sbpl.contains("(allow file-read* (subpath \"/private/tmp/mcp-writ-nonexistent-dir\"))")
        );
        let grant = grants
            .iter()
            .find(|g| {
                matches!(
                    &g.subject,
                    GrantSubject::FsPath { path, .. }
                        if path == "/private/tmp/mcp-writ-nonexistent-dir"
                )
            })
            .expect("grant must carry the canonical path");
        assert_eq!(grant.origin, GrantOrigin::Policy);
        assert_eq!(
            grant.reason.as_deref(),
            Some("canonicalized from /tmp/mcp-writ-nonexistent-dir")
        );
    }

    #[test]
    fn test_sbpl_path_escaping_in_policy() {
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/path/with\"quotes".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (subpath \"/path/with\\\"quotes\"))"));
    }

    #[test]
    fn test_sbpl_rejects_control_char_in_policy_path() {
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/path/\x07evil".to_string()];
        assert!(generate_sbpl(&policy).is_err());

        let mut policy = default_policy();
        policy.fs.read_write = vec!["/path/\0nul".to_string()];
        assert!(generate_sbpl(&policy).is_err());
    }

    // ---------------------------------------------------------------
    // generate_sbpl — network policy
    // ---------------------------------------------------------------

    #[test]
    fn test_sbpl_network_deny_all_no_allowed() {
        let policy = default_policy();
        // deny_all_others = true, allowed = []
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(!sbpl.contains("(allow network-outbound)"));
        assert!(!sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_deny_all_with_specific_ports() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = true;
        policy.network.outbound.allowed = vec!["localhost:443".to_string(), "*:80".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:443\"))"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:80\"))"));
        // Must NOT have blanket allow
        assert!(!sbpl.contains("(allow network-outbound)\n"));
        assert!(!sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_allow_all() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = false;
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow network-outbound)\n"));
        assert!(!sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_allow_all_with_inbound() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = false;
        policy.network.inbound.allow_listen = true;
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow network-outbound)\n"));
        assert!(sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_rejects_remote_hostname() {
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec!["api.example.com:443".to_string()];
        assert!(generate_sbpl(&policy).is_err());
    }

    // ---------------------------------------------------------------
    // Integration tests (macOS only)
    // ---------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_blocks_write_outside_allowed() {
        let policy = default_policy();
        let test_file = std::env::current_dir()
            .unwrap()
            .join("_sandbox_write_deny_test");

        // Clean up from any previous failed run
        let _ = std::fs::remove_file(&test_file);

        let mut child = spawn_sandboxed(
            &policy,
            "/bin/sh",
            &[
                "-c".to_string(),
                format!("echo denied > '{}' 2>/dev/null", test_file.display()),
            ],
        )
        .expect("sandbox-exec should spawn");

        let _ = child.wait();

        let blocked = !test_file.exists();
        let _ = std::fs::remove_file(&test_file);
        assert!(blocked, "sandbox should block writes outside allowed paths");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_allows_tmp_write() {
        use std::io::Read;

        let policy = default_policy();

        let mut child = spawn_sandboxed(
            &policy,
            "/bin/sh",
            &[
                "-c".to_string(),
                "echo allowed > \"$TMPDIR/mcp_writ_sandbox_allow_test\" && cat \"$TMPDIR/mcp_writ_sandbox_allow_test\"".to_string(),
            ],
        )
        .expect("sandbox-exec should spawn");

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut output)
            .ok();
        let status = child.wait().expect("sandboxed shell should exit");
        assert!(status.success(), "sandboxed shell failed: {status}");

        assert!(
            output.trim().contains("allowed"),
            "sandbox should allow writes to private TMPDIR, got: {output}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_blocks_network_when_denied() {
        use std::net::TcpListener;

        // Bind a local TCP listener so we know the port is reachable
        // outside the sandbox — this proves the sandbox is what blocks
        // the connection, not a missing listener.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
        let port = listener.local_addr().unwrap().port();

        // Default policy: deny_all_others=true, allowed=[]
        // → SBPL will NOT contain (allow network-outbound) for any TCP port
        let policy = default_policy();

        let mut child = spawn_sandboxed(
            &policy,
            "/bin/sh",
            &[
                "-c".to_string(),
                format!("nc -z -w 2 127.0.0.1 {} 2>/dev/null", port),
            ],
        )
        .expect("sandbox-exec should spawn");

        let status = child.wait().expect("should be able to wait");
        drop(listener);

        assert!(
            !status.success(),
            "sandbox should block TCP connection to 127.0.0.1:{port} when deny_all_others=true"
        );
    }

    // ---------------------------------------------------------------
    // sbpl_profile_with_egress — CONNECT-proxy mode (PR-11)
    // ---------------------------------------------------------------

    fn proxy_sbpl(policy: &Policy) -> (String, Vec<ProcessGrant>) {
        sbpl_profile_with_egress(
            policy,
            "/private/tmp/mcp-writ-proxy-test",
            EgressProfile::ConnectProxy { proxy_port: 18099 },
        )
        .expect("proxy-mode profile should build")
    }

    #[test]
    fn test_proxy_mode_pins_outbound_to_proxy_port() {
        let policy = default_policy();
        let (sbpl, grants) = proxy_sbpl(&policy);
        // The only remote endpoint is the loopback CONNECT proxy.
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:18099\"))"));
        // No unrestricted outbound, no bind, no inbound, no resolver.
        assert!(!sbpl.contains("(allow network-outbound)\n"));
        assert!(!sbpl.contains("network-bind"));
        assert!(!sbpl.contains("network-inbound"));
        assert!(!sbpl.contains("mDNSResponder"));
        let proxy_grant = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "connect_proxy"))
            .expect("proxy pin must be recorded as a grant");
        assert_eq!(proxy_grant.origin, GrantOrigin::Runtime);
    }

    #[test]
    fn test_proxy_mode_never_widens_on_open_posture() {
        // deny_all_others=false must NOT relax the pin — the whole
        // point of the route is that the proxy decides egress.
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = false;
        let (sbpl, _) = proxy_sbpl(&policy);
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:18099\"))"));
        assert!(!sbpl.contains("(allow network-outbound)\n"));
    }

    #[test]
    fn test_proxy_mode_remote_host_becomes_skipped_not_error() {
        // A remote hostname that the native path refuses to map is
        // not a build failure in proxy mode — the proxy enforces it.
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec!["api.example.com:443".to_string()];
        let (sbpl, grants) = proxy_sbpl(&policy);
        assert!(sbpl.contains("localhost:18099"));
        assert!(!sbpl.contains("api.example.com"));
        let entry = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { name, .. } if name.as_str() == "api.example.com:443"))
            .expect("remote host rule must be recorded");
        assert_eq!(entry.state, ControlState::Skipped);
        assert!(
            entry
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("CONNECT proxy")),
            "skip reason must name the enforcing mechanism: {entry:?}"
        );
        // The same policy still errors on the native path.
        assert!(sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test").is_err());
    }

    #[test]
    fn test_proxy_mode_keeps_localhost_rules_and_marks_cidrs() {
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec!["localhost:8080".to_string()];
        policy.network.outbound.allowed_cidrs = vec!["203.0.113.0/24".to_string()];
        let (sbpl, grants) = proxy_sbpl(&policy);
        // Both loopback endpoints allowed: the proxy + the declared rule.
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:18099\"))"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"));
        let cidr_grant = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "net_destination_cidr"))
            .expect("cidr rule must be recorded");
        assert_eq!(cidr_grant.state, ControlState::Skipped);
        assert!(
            cidr_grant
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("CONNECT proxy"))
        );
    }

    #[test]
    fn test_proxy_mode_only_explicit_loopback_gets_a_direct_rule() {
        // Bare-port and `*`-wildcard entries name a wider destination
        // set than loopback — proxy mode routes them to the CONNECT
        // proxy (Skipped), never to a direct `localhost:port` grant.
        // Grant names are the effective spelling — a bare `"443"` is
        // the wildcard-destination rule `*:443`.
        for (entry, grant_name) in [
            ("443", "*:443"),
            ("*:443", "*:443"),
            (":443", ":443"),
            ("example.com:443", "example.com:443"),
        ] {
            let mut policy = default_policy();
            policy.network.outbound.allowed = vec![entry.to_string()];
            let (sbpl, grants) = proxy_sbpl(&policy);
            assert!(
                !sbpl.contains("localhost:443"),
                "'{entry}' must not emit a direct loopback rule in proxy mode"
            );
            let skipped = grants
                .iter()
                .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == grant_name))
                .unwrap_or_else(|| panic!("'{entry}' must be recorded as skipped"));
            assert_eq!(skipped.state, ControlState::Skipped);
            assert!(
                skipped
                    .reason
                    .as_deref()
                    .is_some_and(|r| r.contains("CONNECT proxy"))
            );
        }
        // Explicit loopback endpoints still map to direct rules.
        for (entry, port) in [
            ("localhost:8080", 8080),
            ("127.0.0.1:80", 80),
            ("[::1]:8080", 8080),
        ] {
            let mut policy = default_policy();
            policy.network.outbound.allowed = vec![entry.to_string()];
            let (sbpl, _) = proxy_sbpl(&policy);
            assert!(
                sbpl.contains(&format!(
                    "(allow network-outbound (remote tcp \"localhost:{port}\"))"
                )),
                "'{entry}' must emit a direct loopback rule in proxy mode"
            );
        }
        // A bare `::1:8080` is the v6 literal `::1:8080`, never
        // `::1` port 8080 — proxy mode routes it to the CONNECT
        // proxy (which judges it as the v6 it is), not to a direct
        // loopback grant on the host's port 8080.
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec!["::1:8080".to_string()];
        let (sbpl, grants) = proxy_sbpl(&policy);
        assert!(
            !sbpl.contains("localhost:8080"),
            "'::1:8080' must not emit a direct loopback rule in proxy mode: {sbpl}"
        );
        let skipped = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "::1:8080"))
            .expect("'::1:8080' must be recorded as skipped");
        assert_eq!(skipped.state, ControlState::Skipped);
    }

    #[test]
    fn test_proxy_mode_allow_listen_is_loopback_only() {
        let mut policy = default_policy();
        policy.network.inbound.allow_listen = true;
        let (sbpl, grants) = proxy_sbpl(&policy);
        assert!(sbpl.contains("(allow network-bind (local tcp \"localhost:*\"))"));
        assert!(sbpl.contains("(allow network-inbound (local tcp \"localhost:*\"))"));
        assert!(!sbpl.contains("(allow network-bind)\n"));
        let bind = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "network_bind" && name.contains("loopback-only")))
            .expect("loopback-only bind grant must be recorded");
        assert_eq!(bind.state, ControlState::Planned);
    }

    #[test]
    fn test_native_mode_unchanged_under_egress_split() {
        // The native path must behave exactly as before the
        // EgressProfile split — same rules, same mDNS grant, same
        // remote-host refusal.
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec!["localhost:443".to_string()];
        let (sbpl, grants) = sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test").unwrap();
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:443\"))"));
        assert!(!sbpl.contains("localhost:18099"));
        assert!(sbpl.contains("mDNSResponder"));
        assert!(grants.iter().all(
            |g| !matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "connect_proxy")
        ));
    }

    // ---------------------------------------------------------------
    // Parsed-policy emit — `egress_rules` carries the qualifiers the
    // folded `allowed` list cannot (a parsed `localhost:8080` loses
    // its port in `allowed`; bare-port/scoped-wildcard rules exist
    // only in `egress_rules`).
    // ---------------------------------------------------------------

    fn parsed_policy(net_rules: &str) -> Policy {
        crate::policy::kdl_loader::parse_kdl_policy(&format!(
            "policy version=1\ndefaults {{\n    network {{\n{net_rules}    }}\n}}\n"
        ))
        .expect("fixture policy parses")
    }

    #[test]
    fn test_parsed_localhost_port_rule_emits_in_both_modes() {
        // A *parsed* `allow host="localhost:8080"` folds its port out
        // of `allowed` — the emit must still produce the documented
        // `(remote tcp "localhost:8080")` rule in both modes.
        let policy =
            parsed_policy("        allow host=\"localhost:8080\"\n        deny host=\"*\"\n");
        let (sbpl, _) = sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test").unwrap();
        assert!(
            sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"),
            "native mode must emit the parsed localhost:port rule: {sbpl}"
        );
        let (sbpl, _) = proxy_sbpl(&policy);
        assert!(
            sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"),
            "proxy mode must emit the parsed localhost:port rule: {sbpl}"
        );
    }

    #[test]
    fn test_parsed_bare_port_rule_emits_native_and_routes_in_proxy() {
        // `allow host="443"` exists only in `egress_rules` — the
        // native emit must produce `localhost:443`; proxy mode routes
        // it to the CONNECT proxy (not an explicit loopback endpoint).
        let policy = parsed_policy("        allow host=\"443\"\n        deny host=\"*\"\n");
        let (sbpl, _) = sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test").unwrap();
        assert!(
            sbpl.contains("(allow network-outbound (remote tcp \"localhost:443\"))"),
            "native mode must emit the bare-port rule: {sbpl}"
        );
        let (sbpl, grants) = proxy_sbpl(&policy);
        assert!(
            !sbpl.contains("(remote tcp \"localhost:443\")"),
            "proxy mode must not emit a direct :443 rule: {sbpl}"
        );
        let skipped = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "*:443"))
            .expect("the bare-port rule must be recorded as skipped");
        assert_eq!(skipped.state, ControlState::Skipped);
    }

    #[test]
    fn test_parsed_ipv6_loopback_rules_emit_and_nonloopback_v6_does_not() {
        // The parser stores `[::1]:8080` and `host="::1" port=8080`
        // as the bare literal `::1` plus a port qualifier — both must
        // emit the declared `localhost:8080` rule in both modes.
        for rule in ["allow host=\"[::1]:8080\"", "allow host=\"::1\" port=8080"] {
            let policy = parsed_policy(&format!("        {rule}\n        deny host=\"*\"\n"));
            for (label, (sbpl, _)) in [
                (
                    "native",
                    sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test").unwrap(),
                ),
                ("proxy", proxy_sbpl(&policy)),
            ] {
                assert!(
                    sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"),
                    "{label} mode must emit '{rule}' as localhost:8080: {sbpl}"
                );
            }
        }
        // `host="::1:8080"` is the non-loopback v6 literal
        // `::1:8080`, not `::1` port 8080 — proxy mode routes it to
        // the CONNECT proxy (which judges the v6 as written), and the
        // native path refuses it like any remote host.
        let policy = parsed_policy("        allow host=\"::1:8080\"\n        deny host=\"*\"\n");
        assert!(
            sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test").is_err(),
            "native mode must refuse a remote v6 literal, not map it to localhost"
        );
        let (sbpl, grants) = proxy_sbpl(&policy);
        assert!(
            !sbpl.contains("localhost:8080"),
            "proxy mode must not grant host loopback for the v6 literal: {sbpl}"
        );
        let skipped = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "::1:8080"))
            .expect("the v6 rule must be recorded as skipped");
        assert_eq!(skipped.state, ControlState::Skipped);
    }

    #[test]
    fn test_udp_only_localhost_rule_never_widens_to_tcp() {
        // `proto=udp` on a loopback endpoint must not emit `remote
        // tcp` — SBPL cannot carry the qualifier, so the rule stays
        // unemitted rather than granting a TCP reach it never
        // declared. Both modes.
        let policy = parsed_policy(
            "        allow host=\"localhost:5353\" proto=\"udp\"\n        deny host=\"*\"\n",
        );
        for (label, (sbpl, grants)) in [
            (
                "native",
                sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test").unwrap(),
            ),
            ("proxy", proxy_sbpl(&policy)),
        ] {
            assert!(
                !sbpl.contains("localhost:5353"),
                "{label} mode must not widen proto=udp to remote tcp: {sbpl}"
            );
            let skipped = grants
                .iter()
                .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "localhost:5353"))
                .unwrap_or_else(|| panic!("{label} mode must record the udp rule"));
            assert_eq!(skipped.state, ControlState::Skipped);
        }
    }
}
