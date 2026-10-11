use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, Errno, NetPort,
    PathBeneath, PathFd, RestrictionStatus, Ruleset, RulesetAttr, RulesetCreated,
    RulesetCreatedAttr, RulesetStatus,
};

use crate::enforcement::{ControlState, FsAccess, GrantOrigin, GrantSubject, ProcessGrant};
use crate::error::{SandboxStage, WardenError};
use crate::policy::Policy;

/// The ruleset built for a policy together with the process-wide grant
/// entries it produced — the launch report describes exactly this data.
pub struct LandlockBuild {
    pub ruleset: RulesetCreated,
    /// Per-entry outcomes of the same decisions that added (or skipped)
    /// rules: `Planned` entries became ruleset rules, `Skipped` entries
    /// name the policy element and the reason no rule exists for it.
    pub grants: Vec<ProcessGrant>,
}

fn fs_grant(
    path: &str,
    access: FsAccess,
    origin: GrantOrigin,
    state: ControlState,
    reason: Option<String>,
) -> ProcessGrant {
    ProcessGrant {
        subject: GrantSubject::FsPath {
            path: path.to_string(),
            access,
        },
        origin,
        state,
        reason,
    }
}

/// Reason attached to a grant whose glob spelling was resolved to a base
/// directory (`/**` → its root, ...). `None` for plain paths.
fn glob_base_reason(path: &str) -> Option<String> {
    landlock_base_path(path)
        .filter(|base| *base != path.trim())
        .map(|base| format!("glob resolved to base '{base}'"))
}

/// Apply Landlock filesystem restrictions based on the given policy.
///
/// Creates a default-deny ruleset and selectively opens access to paths
/// listed in the policy's `fs.read_only` and `fs.read_write` sections,
/// plus any per-tool `fs.allowed_paths`.
///
/// After `restrict_self()`, the calling process (and all future children)
/// are permanently constrained. The restrictions cannot be removed, only
/// tightened further.
pub fn create_landlock_ruleset(policy: &Policy) -> Result<LandlockBuild, WardenError> {
    create_landlock_ruleset_inner(policy, NetMode::Default)
}

/// PR-10 variant for `ebpf-run`: only the `ConnectTcp` handling is
/// dropped — on this route the cgroup `INET4/6_CONNECT` programs are
/// the connect authority (kernel-enforced verdict + ring-buffer deny
/// event). Keeping Landlock's `socket_connect` hook would deny matched
/// egress at the LSM layer *before* the cgroup hook runs, so the deny
/// would never be observed — the wrong layer would own the verdict.
/// `BindTcp` stays handled with zero rules added, preserving the
/// deny-all-bind posture the other routes enforce. Filesystem handling
/// is unchanged.
pub fn create_landlock_ruleset_ebpf(policy: &Policy) -> Result<LandlockBuild, WardenError> {
    create_landlock_ruleset_inner(policy, NetMode::Ebpf)
}

/// Which route the ruleset is being built for — controls which
/// `AccessNet` rights Landlock claims authority over.
#[derive(Clone, Copy, PartialEq, Eq)]
enum NetMode {
    /// Ordinary route: Landlock narrows TCP connect by port where
    /// expressible.
    Default,
    /// `namespaced-init` (PR-09): port narrowing only when exactly
    /// expressible, else the TUN proxy owns connect decisions.
    Namespaced,
    /// `ebpf-run` (PR-10): `ConnectTcp` stays *unhandled* — the cgroup
    /// connect hooks are the enforcement layer and must see denied
    /// connects to emit their audit events. `BindTcp` alone stays
    /// handled (no netport rules are added for it): inbound listen is
    /// denied by default exactly as on the other routes.
    Ebpf,
}

/// PR-09 variant for `namespaced-init`: the netport section keeps the
/// `ConnectTcp` narrowing *when it is exactly expressible* — every
/// TCP-covering allow must carry a port qualifier, so the collected
/// port set cannot accidentally deny an allowed destination. With any
/// unqualified TCP allow the `ConnectTcp` handling is dropped instead
/// of widened: inside the dedicated netns every connect dead-ends at
/// the TUN, and the userspace proxy is the destination-aware layer
/// Landlock cannot be. An open posture (`deny_all_others=false`) is
/// such an unqualified allow: it is not an `egress_rules` entry, so
/// it is seeded into the check rather than collected from rules.
pub fn create_landlock_ruleset_namespaced(policy: &Policy) -> Result<LandlockBuild, WardenError> {
    create_landlock_ruleset_inner(policy, NetMode::Namespaced)
}

/// The namespaced `ConnectTcp` plan: `Some(ports)` only when the port
/// set is *exactly* the policy's TCP allow surface — i.e. the posture
/// denies unmatched egress and every TCP-covering allow carries a
/// port. `None` means the handling cannot be expressed in port terms
/// and must be delegated to the proxy: an unqualified TCP allow
/// (e.g. `allow host="1.1.1.1"`), or an open posture
/// (`deny_all_others=false`, spelled by a bare `allow host="*"`) —
/// the posture is not an `egress_rules` entry, so it is seeded into
/// the check rather than collected from rules, since an empty port
/// set would install a deny-all.
fn namespaced_netport_plan(outbound: &crate::policy::OutboundPolicy) -> Option<Vec<u16>> {
    let mut unbound = !outbound.deny_all_others;
    let mut ports = Vec::new();
    for rule in outbound.egress_rules() {
        if !rule.allow || !rule.proto.covers(crate::policy::EgressProto::Tcp) {
            continue;
        }
        match rule.port {
            Some(p) if !ports.contains(&p) => ports.push(p),
            Some(_) => {}
            None => unbound = true,
        }
    }
    if unbound {
        None
    } else {
        ports.sort_unstable();
        Some(ports)
    }
}

/// The net-access set Landlock claims, per route. Default and the
/// exactly-expressible namespaced case handle all of V4
/// (`ConnectTcp` + `BindTcp`); since only `ConnectTcp` rules are ever
/// added, TCP bind stays default-denied. The ebpf route claims
/// `BindTcp` alone — `ConnectTcp` must remain *unhandled* so denied
/// connects reach the cgroup hook instead of dying at the LSM — while
/// still refusing every TCP bind. The inexact namespaced case handles
/// nothing: the TUN proxy is the connect authority.
fn net_handle_set(
    net_mode: NetMode,
    namespaced_netports: Option<&Vec<u16>>,
) -> BitFlags<AccessNet> {
    match net_mode {
        NetMode::Default => AccessNet::from_all(ABI::V4),
        NetMode::Namespaced if namespaced_netports.is_some() => AccessNet::from_all(ABI::V4),
        NetMode::Ebpf => AccessNet::BindTcp.into(),
        NetMode::Namespaced => BitFlags::EMPTY,
    }
}

fn create_landlock_ruleset_inner(
    policy: &Policy,
    net_mode: NetMode,
) -> Result<LandlockBuild, WardenError> {
    let mut grants = Vec::new();
    let read_access = AccessFs::from_read(ABI::V3);
    // Narrower access mask for read-write paths: read + write + truncate (V3)
    let read_write_access = AccessFs::from_read(ABI::V3) | AccessFs::from_write(ABI::V3);

    // Namespaced netport plan: add `ConnectTcp` handling only when the
    // collected ports are exactly the policy's TCP allow surface —
    // i.e. every TCP-covering allow carries a port. An unqualified TCP
    // allow (e.g. `allow host="1.1.1.1"`) cannot be expressed without
    // wrongly denying its other ports, so the handling is dropped and
    // the proxy is the TCP layer.
    let namespaced_netports: Option<Vec<u16>> = if net_mode == NetMode::Namespaced {
        namespaced_netport_plan(&policy.network.outbound)
    } else {
        None
    };
    let handle_net = net_handle_set(net_mode, namespaced_netports.as_ref());

    // Create a default-deny ruleset: V1/V2/V3 filesystem (including Truncate) + V4 network.
    // BestEffort ensures graceful degradation on older kernels:
    // - Kernel < 5.13: no Landlock at all
    // - Kernel 5.13–6.1: V1/V2 filesystem, truncate silently degraded
    // - Kernel 6.2–6.6: V3 filesystem with truncate enforcement
    // - Kernel >= 6.7: full filesystem (with truncate) + TCP network enforcement
    let ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V1))
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle access rights V1: {e}"),
            )
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V2))
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle access rights V2: {e}"),
            )
        })?
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(AccessFs::from_all(ABI::V3))
        .map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle access rights V3 (truncate): {e}"),
            )
        })?
        .set_compatibility(CompatLevel::BestEffort);
    let ruleset = if !handle_net.is_empty() {
        ruleset.handle_access(handle_net).map_err(|e| {
            WardenError::sandbox_setup(
                SandboxStage::Prepare,
                format!("Landlock: failed to handle net access rights: {e}"),
            )
        })?
    } else {
        ruleset
    };
    let mut ruleset = ruleset.create().map_err(|e| {
        WardenError::sandbox_setup(
            SandboxStage::Prepare,
            format!("Landlock: failed to create ruleset: {e}"),
        )
    })?;

    // Check for parent allow + child deny in global fs rules
    for denied in &policy.fs.denied_paths {
        for allowed in policy
            .fs
            .read_only
            .iter()
            .chain(policy.fs.read_write.iter())
        {
            if crate::policy::validator::is_strict_subpath_or_descendant(allowed, denied) {
                return Err(WardenError::sandbox_setup(
                    SandboxStage::Policy,
                    format!(
                        "Landlock policy error: denied path '{denied}' is a subpath of allowed path '{allowed}'. Landlock cannot carve out sub-paths from parent directory grants"
                    ),
                ));
            }
        }
    }

    // Allow read-only access to specified paths (denied paths excluded).
    for path in &policy.fs.read_only {
        if policy.fs.denied_paths.contains(path) {
            grants.push(fs_grant(
                path,
                FsAccess::Read,
                GrantOrigin::Policy,
                ControlState::Skipped,
                Some("denied by a policy deny rule".to_string()),
            ));
            continue;
        }
        match open_landlock_path(path) {
            Ok(fd) => {
                ruleset = ruleset
                    .add_rule(path_beneath(fd, read_access))
                    .map_err(|e| {
                        WardenError::sandbox_setup(
                            SandboxStage::Prepare,
                            format!("Landlock: failed to add read rule for '{path}': {e}"),
                        )
                    })?;
                grants.push(fs_grant(
                    path,
                    FsAccess::Read,
                    GrantOrigin::Policy,
                    ControlState::Planned,
                    glob_base_reason(path),
                ));
            }
            Err(e) => {
                tracing::warn!("Landlock: skipping read_only path '{path}': {e}");
                grants.push(fs_grant(
                    path,
                    FsAccess::Read,
                    GrantOrigin::Policy,
                    ControlState::Skipped,
                    Some(format!("cannot open for a Landlock rule: {e}")),
                ));
            }
        }
    }

    // Allow read-write access to specified paths (denied paths excluded).
    for path in &policy.fs.read_write {
        if policy.fs.denied_paths.contains(path) {
            grants.push(fs_grant(
                path,
                FsAccess::ReadWrite,
                GrantOrigin::Policy,
                ControlState::Skipped,
                Some("denied by a policy deny rule".to_string()),
            ));
            continue;
        }
        match open_landlock_path(path) {
            Ok(fd) => {
                ruleset = ruleset
                    .add_rule(path_beneath(fd, read_write_access))
                    .map_err(|e| {
                        WardenError::sandbox_setup(
                            SandboxStage::Prepare,
                            format!("Landlock: failed to add read-write rule for '{path}': {e}"),
                        )
                    })?;
                grants.push(fs_grant(
                    path,
                    FsAccess::ReadWrite,
                    GrantOrigin::Policy,
                    ControlState::Planned,
                    glob_base_reason(path),
                ));
            }
            Err(e) => {
                tracing::warn!("Landlock: skipping read_write path '{path}': {e}");
                grants.push(fs_grant(
                    path,
                    FsAccess::ReadWrite,
                    GrantOrigin::Policy,
                    ControlState::Skipped,
                    Some(format!("cannot open for a Landlock rule: {e}")),
                ));
            }
        }
    }

    // Apply per-tool filesystem rules.
    // Only allowed tools contribute paths. Paths are given read or read-write access based on mode.
    for tool in &policy.tools {
        if !tool.allowed {
            tracing::debug!("Landlock: skipping paths for denied tool '{}'", tool.name);
            continue;
        }

        if let Some(ref fs) = tool.fs {
            // Reject if Landlock additive model cannot carve out a sub-path denial
            for denied in fs.denied_paths.iter().chain(policy.fs.denied_paths.iter()) {
                for allowed in &fs.allowed_paths {
                    if crate::policy::validator::is_strict_subpath_or_descendant(allowed, denied) {
                        return Err(WardenError::sandbox_setup(
                            SandboxStage::Policy,
                            format!(
                                "Landlock policy error: tool '{}' path '{denied}' is denied but parent '{allowed}' is allowed. Landlock cannot carve out sub-paths from parent grants",
                                tool.name
                            ),
                        ));
                    }
                }
            }

            let tool_origin = || GrantOrigin::Tool(tool.name.clone());

            // Read-only paths from tool
            for path in &fs.read_only_paths {
                if fs.denied_paths.contains(path) || policy.fs.denied_paths.contains(path) {
                    grants.push(fs_grant(
                        path,
                        FsAccess::Read,
                        tool_origin(),
                        ControlState::Skipped,
                        Some("denied by a deny rule".to_string()),
                    ));
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(path_beneath(fd, read_access))
                            .map_err(|e| {
                                WardenError::sandbox_setup(
                                    SandboxStage::Prepare,
                                    format!(
                                        "Landlock: failed to add read tool rule for '{}' path '{path}': {e}",
                                        tool.name
                                    ),
                                )
                            })?;
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Planned,
                            glob_base_reason(path),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' read_only path '{path}': {e}",
                            tool.name
                        );
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Skipped,
                            Some(format!("cannot open for a Landlock rule: {e}")),
                        ));
                    }
                }
            }

            // Read-write paths from tool
            for path in &fs.read_write_paths {
                if fs.denied_paths.contains(path) || policy.fs.denied_paths.contains(path) {
                    grants.push(fs_grant(
                        path,
                        FsAccess::ReadWrite,
                        tool_origin(),
                        ControlState::Skipped,
                        Some("denied by a deny rule".to_string()),
                    ));
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(path_beneath(fd, read_write_access))
                            .map_err(|e| {
                                WardenError::sandbox_setup(
                                    SandboxStage::Prepare,
                                    format!(
                                        "Landlock: failed to add read-write tool rule for '{}' path '{path}': {e}",
                                        tool.name
                                    ),
                                )
                            })?;
                        grants.push(fs_grant(
                            path,
                            FsAccess::ReadWrite,
                            tool_origin(),
                            ControlState::Planned,
                            glob_base_reason(path),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' read_write path '{path}': {e}",
                            tool.name
                        );
                        grants.push(fs_grant(
                            path,
                            FsAccess::ReadWrite,
                            tool_origin(),
                            ControlState::Skipped,
                            Some(format!("cannot open for a Landlock rule: {e}")),
                        ));
                    }
                }
            }

            // Backward compatibility: allowed_paths without explicit mode defaults to read-only
            for path in &fs.allowed_paths {
                if fs.read_only_paths.contains(path)
                    || fs.read_write_paths.contains(path)
                    || fs.denied_paths.contains(path)
                    || policy.fs.denied_paths.contains(path)
                {
                    if !fs.read_only_paths.contains(path) && !fs.read_write_paths.contains(path) {
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Skipped,
                            Some("denied by a deny rule".to_string()),
                        ));
                    }
                    continue;
                }
                match open_landlock_path(path) {
                    Ok(fd) => {
                        ruleset = ruleset
                            .add_rule(path_beneath(fd, read_access))
                            .map_err(|e| {
                                WardenError::sandbox_setup(
                                    SandboxStage::Prepare,
                                    format!(
                                        "Landlock: failed to add fallback tool rule for '{}' path '{path}': {e}",
                                        tool.name
                                    ),
                                )
                            })?;
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Planned,
                            glob_base_reason(path),
                        ));
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Landlock: skipping tool '{}' fallback path '{path}': {e}",
                            tool.name
                        );
                        grants.push(fs_grant(
                            path,
                            FsAccess::Read,
                            tool_origin(),
                            ControlState::Skipped,
                            Some(format!("cannot open for a Landlock rule: {e}")),
                        ));
                    }
                }
            }
        }
    }

    // Add TCP connect rules for the port-only allow rules —
    // `allow host="443"` / `allow host="*" port=443` spellings are the
    // only egress shape a `ConnectTcp` netport rule can express (a port
    // with no destination bound). BindTcp is NOT whitelisted: all TCP
    // bind is denied by default. Every other allow rule is reported as
    // skipped rather than silently widened.
    //
    // In namespaced mode the kernel port narrowing is only a
    // defense-in-depth layer — the TUN proxy is the destination-aware
    // enforcement point — so the collected port set is the union of
    // *every* TCP-covering allow's port qualifier. When it is not
    // exactly expressible (an unqualified TCP allow exists, including
    // an open posture) the `ConnectTcp` handling was dropped above and
    // every TCP rule is recorded as delegated instead.
    // PR-10: on the cgroup-eBPF route `ConnectTcp` is delegated to the
    // kernel-side connect programs — every egress allow is recorded as
    // delegated rather than silently dropped. `BindTcp` remains
    // handled-with-no-rules above, so `bind(2)`/`listen(2)` stay
    // denied exactly as on the default route.
    if net_mode == NetMode::Ebpf {
        for rule in policy.network.outbound.egress_rules() {
            if !rule.allow {
                continue;
            }
            grants.push(ProcessGrant {
                subject: GrantSubject::Rule {
                    kind: match rule.dest {
                        crate::policy::EgressDest::Host(_) => "tcp_host",
                        crate::policy::EgressDest::Cidr(_) => "net_destination_cidr",
                    },
                    name: rule.describe(),
                },
                origin: GrantOrigin::Policy,
                state: ControlState::Skipped,
                reason: Some(
                    "destination/protocol narrowing delegated to the cgroup-eBPF \
                     connect hooks; TCP bind stays denied by the ruleset default"
                        .to_string(),
                ),
            });
        }
        return Ok(LandlockBuild { ruleset, grants });
    }

    if net_mode == NetMode::Namespaced {
        for rule in policy.network.outbound.egress_rules() {
            if !rule.allow || !rule.proto.covers(crate::policy::EgressProto::Tcp) {
                continue;
            }
            if namespaced_netports.is_some() && rule.port.is_some() {
                // Port is covered by the netport set below; the
                // destination narrowing still happens in the proxy.
                continue;
            }
            grants.push(ProcessGrant {
                subject: GrantSubject::Rule {
                    kind: match rule.dest {
                        crate::policy::EgressDest::Host(_) => "tcp_host",
                        crate::policy::EgressDest::Cidr(_) => "net_destination_cidr",
                    },
                    name: rule.describe(),
                },
                origin: GrantOrigin::Policy,
                state: ControlState::Skipped,
                reason: Some(
                    "destination/protocol narrowing delegated to the namespace \
                     egress proxy; Landlock netport rules bind a port only"
                        .to_string(),
                ),
            });
        }
        if let Some(ports) = &namespaced_netports {
            for &port in ports {
                ruleset = ruleset
                    .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
                    .map_err(|e| {
                        WardenError::sandbox_setup(
                            SandboxStage::Prepare,
                            format!("Landlock: failed to add connect rule for port {port}: {e}"),
                        )
                    })?;
                grants.push(ProcessGrant {
                    subject: GrantSubject::TcpConnect { port },
                    origin: GrantOrigin::Policy,
                    state: ControlState::Planned,
                    reason: Some(
                        "namespaced: grants connect to any destination on this port; \
                         per-destination rules are enforced at the TUN proxy"
                            .to_string(),
                    ),
                });
            }
        }
        return Ok(LandlockBuild { ruleset, grants });
    }

    let mut seen_ports: Vec<u16> = Vec::new();
    for rule in policy.network.outbound.egress_rules() {
        if !rule.allow {
            continue;
        }
        let bare_port = rule.port.filter(|_| {
            matches!(rule.dest, crate::policy::EgressDest::Host(ref h) if h == "*")
                && rule.proto.covers(crate::policy::EgressProto::Tcp)
        });
        let Some(port) = bare_port else {
            tracing::warn!(
                "Landlock: skipping egress rule '{}' (netport rules bind a port only)",
                rule.describe()
            );
            grants.push(ProcessGrant {
                subject: GrantSubject::Rule {
                    kind: match rule.dest {
                        crate::policy::EgressDest::Host(_) => "tcp_host",
                        crate::policy::EgressDest::Cidr(_) => "net_destination_cidr",
                    },
                    name: rule.describe(),
                },
                origin: GrantOrigin::Policy,
                state: ControlState::Skipped,
                reason: Some(
                    "Landlock netport rules cannot bind a destination or protocol — \
                     this rule is enforced at the RPC layer and by any launch \
                     mechanism that expresses it"
                        .to_string(),
                ),
            });
            continue;
        };
        if seen_ports.contains(&port) {
            continue;
        }
        seen_ports.push(port);
        ruleset = ruleset
            .add_rule(NetPort::new(port, AccessNet::ConnectTcp))
            .map_err(|e| {
                WardenError::sandbox_setup(
                    SandboxStage::Prepare,
                    format!("Landlock: failed to add connect rule for port {port}: {e}"),
                )
            })?;
        grants.push(ProcessGrant {
            subject: GrantSubject::TcpConnect { port },
            origin: GrantOrigin::Policy,
            state: ControlState::Planned,
            reason: Some(
                "grants connect to any destination on this port; per-destination \
                 rules are enforced at the RPC layer"
                    .to_string(),
            ),
        });
    }

    Ok(LandlockBuild { ruleset, grants })
}

/// Apply a created ruleset in a `pre_exec` hook, returning the raw
/// `RestrictionStatus` so the caller can record the kernel-reported
/// enforcement level *before* deciding whether it is acceptable.
///
/// Errors are `io::Error` built from raw errnos (extracted via
/// [`landlock::Errno`]) so no heap allocation happens on the post-fork
/// error path.
pub fn restrict_self_observed(
    ruleset: landlock::RulesetCreated,
) -> Result<RestrictionStatus, std::io::Error> {
    ruleset
        .restrict_self()
        .map_err(|e| std::io::Error::from_raw_os_error(*Errno::from(e)))
}

/// The `allow_degraded` decision, kept separate from the recorded level:
/// anything short of `FullyEnforced` aborts the spawn (EACCES) unless the
/// policy opted in. Runs after the status has been written to the shared
/// apply record, so a refused spawn still reports the real level.
pub fn enforcement_gate(
    status: &RestrictionStatus,
    allow_degraded: bool,
) -> Result<(), std::io::Error> {
    match status.ruleset {
        RulesetStatus::FullyEnforced => Ok(()),
        RulesetStatus::NotEnforced | RulesetStatus::PartiallyEnforced => {
            if allow_degraded {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            }
        }
    }
}

/// Apply the Landlock ruleset to the calling process.
#[allow(dead_code)]
pub fn apply_landlock(policy: &Policy) -> Result<(), WardenError> {
    let ruleset = create_landlock_ruleset(policy)?.ruleset;

    // Lock down the process.  After this call, the constraints are permanent.
    let status = ruleset.restrict_self().map_err(|e| {
        WardenError::sandbox_setup(
            SandboxStage::Apply,
            format!("Landlock: restrict_self failed: {e}"),
        )
    })?;

    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock: filesystem and network sandbox applied successfully");
            Ok(())
        }
        RulesetStatus::NotEnforced | RulesetStatus::PartiallyEnforced => {
            if policy.sandbox.allow_degraded {
                tracing::warn!(
                    status = ?status.ruleset,
                    "Landlock not fully enforced; continuing because sandbox.allow_degraded=true"
                );
                Ok(())
            } else {
                Err(WardenError::sandbox_setup(
                    SandboxStage::Apply,
                    format!(
                        "Landlock not fully enforced ({:?}); refuse to launch. \
                         Set sandbox.allow_degraded=true only when a weaker kernel is an accepted risk",
                        status.ruleset
                    ),
                ))
            }
        }
    }
}

/// Strip glob suffixes (`/**`, `/*`, trailing `*`) so Landlock can open a real
/// directory. Policy paths are globs for the Auditor; Landlock needs an fd.
///
/// Returns `None` when the path is empty or still contains wildcards
/// (e.g. `/home/*/.ssh`).
fn landlock_base_path(path: &str) -> Option<&str> {
    let mut p = path.trim();
    if p.is_empty() {
        return None;
    }
    loop {
        if let Some(rest) = p.strip_suffix("/**") {
            p = rest;
            continue;
        }
        if let Some(rest) = p.strip_suffix("/*") {
            p = rest;
            continue;
        }
        if let Some(rest) = p.strip_suffix('*') {
            p = rest.trim_end_matches('/');
            continue;
        }
        break;
    }
    if p.is_empty() || p.contains(['*', '?']) {
        None
    } else {
        Some(p)
    }
}

fn open_landlock_path(path: &str) -> Result<PathFd, String> {
    let Some(base) = landlock_base_path(path) else {
        return Err(format!("cannot map glob path to a directory: {path}"));
    };
    PathFd::new(base).map_err(|e| format!("{e}"))
}

/// Build a `PathBeneath` rule, first dropping rights that are meaningless on
/// non-directory targets (`ReadDir`, `Make*`, `Remove*`, `Refer`).
///
/// The landlock crate masks those off itself before issuing the rule (the
/// kernel would reject them with EINVAL), but records the rule as only
/// partially applied, which marks the whole ruleset `PartiallyEnforced` —
/// refused by the `enforcement_gate` unless `allow_degraded` is set.
/// Masking up front keeps the ruleset `FullyEnforced`; the effective
/// kernel rights are identical either way. On stat failure the full set
/// is kept — matching the crate's own `path_beneath_rules` behaviour.
fn path_beneath(fd: PathFd, access: BitFlags<AccessFs>) -> PathBeneath<PathFd> {
    let access = if fd_is_non_dir(&fd) {
        access & AccessFs::from_file(ABI::V3)
    } else {
        access
    };
    PathBeneath::new(fd, access)
}

/// `fstat` check matching the landlock crate's `is_file`: every
/// non-directory inode (regular file, device node, socket, fifo) may carry
/// only the `ACCESS_FILE` subset of rights.
fn fd_is_non_dir(fd: &PathFd) -> bool {
    use std::os::fd::{AsFd, AsRawFd};
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    let stat_ok = unsafe { libc::fstat(fd.as_fd().as_raw_fd(), &mut stat) } == 0;
    stat_ok && (stat.st_mode & libc::S_IFMT) != libc::S_IFDIR
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- landlock_base_path ---------------------------------------------------

    #[test]
    fn test_landlock_base_path_strips_recursive_glob() {
        assert_eq!(landlock_base_path("/usr/lib/**"), Some("/usr/lib"));
        assert_eq!(landlock_base_path("/workspace/**"), Some("/workspace"));
    }

    #[test]
    fn test_landlock_base_path_strips_single_star() {
        assert_eq!(landlock_base_path("/tmp/*"), Some("/tmp"));
    }

    #[test]
    fn test_landlock_base_path_plain_directory() {
        assert_eq!(landlock_base_path("/usr/bin"), Some("/usr/bin"));
    }

    #[test]
    fn test_landlock_base_path_rejects_mid_glob() {
        assert_eq!(landlock_base_path("/home/*/.ssh/**"), None);
        assert_eq!(landlock_base_path(""), None);
    }

    // -- collect_allowed_ports -------------------------------------------------

    /// Shim for the pre-schema port-collection tests: the policy a set
    /// of `host=` spellings produces (trimmed, unnormalized — only the
    /// bare-port form is read back as a port rule) then the netport
    /// rule set derived from it. [`OutboundPolicy::tcp_port_rules`]
    /// sorts and deduplicates, so assertions below expect canonical
    /// order.
    fn collect_allowed_ports(allowed: &[String]) -> Vec<u16> {
        let policy = crate::policy::OutboundPolicy {
            allowed: allowed.iter().map(|s| s.trim().to_string()).collect(),
            ..Default::default()
        };
        policy.tcp_port_rules()
    }

    #[test]
    fn test_collect_bare_ports() {
        let allowed = vec!["80".to_string(), "443".to_string(), "8080".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_collect_https_url() {
        let allowed = vec!["https://api.example.com".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_http_url() {
        let allowed = vec!["http://example.com".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_url_with_explicit_port() {
        let allowed = vec!["https://api.example.com:8443".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_http_url_with_explicit_port() {
        let allowed = vec!["http://example.com:3000".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_bare_hostname() {
        let allowed = vec!["api.openai.com".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_bare_hostname_with_port() {
        let allowed = vec!["api.example.com:9090".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_localhost() {
        let allowed = vec!["localhost".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_mixed_inputs() {
        let allowed = vec![
            "443".to_string(),
            "https://api.openai.com".to_string(),
            "http://example.com".to_string(),
            "https://api.anthropic.com:8443".to_string(),
            "cdn.example.com".to_string(),
        ];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn test_collect_ports_skips_invalid() {
        let allowed = vec![
            "443".to_string(),
            "not_a_port".to_string(), // no dots, not a number → skipped
            "99999".to_string(),      // > u16::MAX, no dots → skipped
            "80".to_string(),
        ];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![80, 443]);
    }

    #[test]
    fn test_collect_ports_empty() {
        let allowed: Vec<String> = vec![];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_ports_boundary_values() {
        let allowed = vec!["0".to_string(), "65535".to_string(), "65536".to_string()];
        let ports = collect_allowed_ports(&allowed);
        // Port 0 is not a valid connect target (skipped), 65536 exceeds u16::MAX (skipped)
        assert_eq!(ports, vec![65535]);
    }

    #[test]
    fn test_collect_ports_negative() {
        let allowed = vec!["-1".to_string(), "443".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]); // negative is invalid for u16
    }

    #[test]
    fn test_collect_url_with_path() {
        let allowed = vec!["https://api.example.com/v1/chat".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_deduplicates() {
        let allowed = vec![
            "443".to_string(),
            "https://api.example.com".to_string(),
            "443".to_string(),
        ];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn test_collect_localhost_with_port() {
        let allowed = vec!["localhost:8080".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert!(ports.is_empty());
    }

    #[test]
    fn test_collect_empty_string_entry() {
        let allowed = vec!["".to_string(), "443".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    #[test]
    fn test_collect_whitespace_port() {
        let allowed = vec![" 443 ".to_string()];
        let ports = collect_allowed_ports(&allowed);
        assert_eq!(ports, vec![443]);
    }

    // -- namespaced_netport_plan -------------------------------------------------

    use crate::policy::{EgressDest, EgressProto, EgressRule};

    fn allow_rule(dest: &str, proto: EgressProto, port: Option<u16>) -> EgressRule {
        EgressRule {
            allow: true,
            dest: EgressDest::Host(dest.to_string()),
            proto,
            port,
        }
    }

    /// Regression: a bare `allow host="*"` flips the posture open but
    /// is NOT an `egress_rules` entry — the port collection sees an
    /// empty set, which must not become a handled deny-all.
    #[test]
    fn test_namespaced_netport_plan_open_posture_delegates() {
        let out = crate::policy::OutboundPolicy {
            deny_all_others: false,
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&out), None);
    }

    /// Open posture stays delegated even beside port-qualified
    /// (non-TCP) rules — the TCP surface is still "any port".
    #[test]
    fn test_namespaced_netport_plan_open_posture_with_udp_rules() {
        let out = crate::policy::OutboundPolicy {
            deny_all_others: false,
            egress_rules: vec![allow_rule("*", EgressProto::Udp, Some(53))],
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&out), None);
    }

    /// Deny-all posture with every TCP allow port-qualified → the
    /// union of their ports is the netport set.
    #[test]
    fn test_namespaced_netport_plan_collects_qualified_ports() {
        let out = crate::policy::OutboundPolicy {
            deny_all_others: true,
            egress_rules: vec![
                allow_rule("1.1.1.1", EgressProto::Tcp, Some(443)),
                allow_rule("example.com", EgressProto::Tcp, Some(8443)),
                allow_rule("9.9.9.9", EgressProto::Udp, Some(53)),
                allow_rule("*", EgressProto::Tcp, Some(80)),
            ],
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&out), Some(vec![80, 443, 8443]));
    }

    /// Any TCP-covering allow without a port cannot be expressed —
    /// the whole handling delegates to the proxy.
    #[test]
    fn test_namespaced_netport_plan_unqualified_tcp_allow_delegates() {
        let out = crate::policy::OutboundPolicy {
            deny_all_others: true,
            egress_rules: vec![
                allow_rule("1.1.1.1", EgressProto::Tcp, Some(443)),
                allow_rule("example.com", EgressProto::Tcp, None),
            ],
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&out), None);
    }

    /// `proto="any"` covers TCP — an unport'd any-rule is unqualified
    /// for this purpose too.
    #[test]
    fn test_namespaced_netport_plan_any_proto_without_port_delegates() {
        let out = crate::policy::OutboundPolicy {
            deny_all_others: true,
            egress_rules: vec![allow_rule("1.1.1.1", EgressProto::Any, None)],
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&out), None);
    }

    /// Deny-all posture with no TCP-covering allows at all → `Some([])`
    /// keeps `ConnectTcp` handled so every connect is refused — the
    /// kernel mirrors the posture as defense-in-depth.
    #[test]
    fn test_namespaced_netport_plan_deny_all_no_tcp_is_empty_some() {
        let out = crate::policy::OutboundPolicy {
            deny_all_others: true,
            egress_rules: vec![allow_rule("9.9.9.9", EgressProto::Udp, Some(53))],
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&out), Some(vec![]));
    }

    /// A programmatically built policy (`egress_rules` field empty)
    /// derives the same plan through the flat lists: a bare-port
    /// `allowed` entry is the pre-schema spelling of the port-only
    /// rule; a bare hostname is an unqualified TCP allow → delegate.
    #[test]
    fn test_namespaced_netport_plan_derived_flat_rules() {
        let qualified = crate::policy::OutboundPolicy {
            deny_all_others: true,
            allowed: vec!["443".to_string(), "80".to_string()],
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&qualified), Some(vec![80, 443]));
        let unqualified = crate::policy::OutboundPolicy {
            deny_all_others: true,
            allowed: vec!["443".to_string(), "api.example.com".to_string()],
            ..Default::default()
        };
        assert_eq!(namespaced_netport_plan(&unqualified), None);
    }

    // -- path_beneath file/dir access masking ----------------------------------
    // A file rule carrying directory-only rights (e.g. ReadDir on /dev/null)
    // makes the crate downgrade the ruleset to PartiallyEnforced, which the
    // enforcement gate rejects with EACCES unless allow_degraded is set.
    // These tests pin the predicate and the masked right set.

    #[test]
    fn test_fd_is_non_dir_detects_files_and_dirs() {
        assert!(fd_is_non_dir(&PathFd::new("/dev/null").unwrap()));
        assert!(!fd_is_non_dir(&PathFd::new("/").unwrap()));
    }

    #[test]
    fn test_file_access_mask_drops_directory_only_rights() {
        let file_ok = AccessFs::from_file(ABI::V3);
        let read = AccessFs::from_read(ABI::V3);
        let rw = read | AccessFs::from_write(ABI::V3);
        assert!(file_ok.contains(AccessFs::ReadFile));
        assert!(file_ok.contains(AccessFs::WriteFile));
        assert!(file_ok.contains(AccessFs::Execute));
        assert!(file_ok.contains(AccessFs::Truncate));
        assert!(!file_ok.contains(AccessFs::ReadDir));
        assert!(!file_ok.contains(AccessFs::MakeReg));
        // A masked file rule still keeps the rights that matter for files.
        assert_eq!(read & file_ok, AccessFs::Execute | AccessFs::ReadFile);
        assert_eq!(
            rw & file_ok,
            AccessFs::Execute | AccessFs::ReadFile | AccessFs::WriteFile | AccessFs::Truncate
        );
    }

    // -- apply_landlock is not called in-process ------------------------------
    // restrict_self() would lock down the cargo test binary (and parallel tests).
    // These tests only verify that the policy used by apply_landlock is well-formed.

    #[test]
    fn test_network_policy_ports_are_collectable() {
        use crate::policy::{NetworkPolicy, OutboundPolicy, default_policy};

        let mut policy = default_policy();
        policy.network = NetworkPolicy {
            outbound: OutboundPolicy {
                // Pre-schema programmatic spelling of the port-only
                // rules — the derived `egress_rules` maps them to the
                // same `ConnectTcp` netport grants a parsed
                // `allow host="443"` produces.
                allowed: vec!["443".to_string(), "80".to_string()],
                allowed_port_qualified: vec![],
                allowed_cidrs: vec![],
                allowed_cidrs_port_qualified: vec![],
                denied_hosts: vec![],
                denied_cidrs: vec![],
                deny_all_others: true,
                egress_rules: vec![],
            },
            inbound: Default::default(),
        };

        assert_eq!(policy.network.outbound.tcp_port_rules(), vec![80, 443]);
    }

    #[test]
    fn test_empty_network_policy_collects_no_ports() {
        use crate::policy::default_policy;

        let policy = default_policy();
        assert!(policy.network.outbound.tcp_port_rules().is_empty());
    }

    // -- per-route net handle set ----------------------------------------

    /// PR-10: the ebpf route claims `BindTcp` alone — `ConnectTcp`
    /// must stay *unhandled* so a denied connect reaches the cgroup
    /// hook (the deny event would never be emitted if Landlock
    /// short-circuited it first); `BindTcp` handled-with-no-rules
    /// keeps the all-bind-denied contract the other routes enforce.
    #[test]
    fn test_ebpf_net_handle_set_is_bind_only() {
        let set = net_handle_set(NetMode::Ebpf, None);
        assert!(set.contains(AccessNet::BindTcp));
        assert!(!set.contains(AccessNet::ConnectTcp));
        assert_eq!(set, BitFlags::from(AccessNet::BindTcp));
    }

    /// The default and exactly-expressible namespaced routes claim
    /// the full V4 net set; an inexpressible namespaced plan claims
    /// nothing (the TUN proxy owns connect decisions).
    #[test]
    fn test_net_handle_set_default_and_namespaced() {
        assert_eq!(
            net_handle_set(NetMode::Default, None),
            AccessNet::from_all(ABI::V4)
        );
        let ports = vec![443u16];
        assert_eq!(
            net_handle_set(NetMode::Namespaced, Some(&ports)),
            AccessNet::from_all(ABI::V4)
        );
        assert_eq!(net_handle_set(NetMode::Namespaced, None), BitFlags::EMPTY);
    }
}
