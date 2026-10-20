use std::collections::BTreeMap;

use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch, apply_filter,
};

use crate::enforcement::{ControlState, GrantOrigin, GrantSubject, ProcessGrant};
use crate::error::WardenError;
use crate::policy::Policy;

/// Syscall names that are blocked by default even if the policy lists them,
/// unless the policy *explicitly* includes them in `syscalls.allowed`.
///
/// These are high-privilege operations that an MCP server should almost
/// never need.  If the policy does allow them, a warning is logged.
/// `io_uring_*` is listed because work submitted to a ring executes without
/// re-entering this filter — a policy that allows it takes that bypass
/// tradeoff explicitly (runtime/node.kdl deliberately omits it, so the
/// warning does not fire for the shared Node baseline).
const DANGEROUS_SYSCALLS: &[&str] = &[
    "ptrace",
    "keyctl",
    "unshare",
    "mount",
    "umount2",
    "io_uring_setup",
    "io_uring_enter",
    "io_uring_register",
];

/// Compile a seccomp-BPF program based on the given policy.
///
/// This compiles the BPF filter in the parent process (before fork),
/// avoiding memory allocations and lock acquisitions in `pre_exec`.
///
/// `execve`/`execveat` are not injected here — the filter contains them
/// only when the policy itself lists them. Used when the policy already
/// allows exec (`compile_seccomp_for_spawn` is the sibling for the
/// spawn-exec injection case).
pub fn compile_seccomp(policy: &Policy) -> Result<BpfProgram, WardenError> {
    compile_seccomp_inner(policy, false, false)
}

/// PR-09 namespaced variant — identical rules except the `socket()`
/// family pin, which is unconditional there rather than tied to the
/// egress posture (see `collect_syscall_rules`). Not part of the native
/// pipeline's public surface.
pub(super) fn compile_seccomp_inner_namespaced(
    policy: &Policy,
    allow_startup_exec: bool,
) -> Result<BpfProgram, WardenError> {
    compile_seccomp_inner(policy, allow_startup_exec, true)
}

/// Seccomp filter used for the initial spawn exec.
///
/// Injects `execve`/`execveat` so the child image can be started. The
/// allowance then remains for the process lifetime — a single filter
/// cannot be swapped after exec, so the exec'd image keeps the ability
/// to exec again. The launch report's `os.syscalls` control and the
/// grant reason spell this out; the earlier "post-exec filter" idea was
/// never wired into the apply pipeline and its helper was removed.
pub fn compile_seccomp_for_spawn(policy: &Policy) -> Result<BpfProgram, WardenError> {
    compile_seccomp_inner(policy, true, false)
}

/// The normalized syscall name list for one filter: the policy's
/// `syscalls.allowed` plus the startup `execve`/`execveat` the spawn
/// filter needs when `allow_startup_exec` is set. Both the BPF rule
/// build and the report's syscall grant entries derive from this list,
/// so the two cannot diverge.
fn allowed_syscall_names(policy: &Policy, allow_startup_exec: bool) -> Vec<String> {
    let mut allowed_syscalls: Vec<String> = policy.syscalls.allowed.clone();
    if allow_startup_exec {
        for required in ["execve", "execveat"] {
            if !allowed_syscalls.iter().any(|s| s == required) {
                allowed_syscalls.push(required.to_string());
            }
        }
    }
    allowed_syscalls
}

/// Process-grant entries for the same normalized names the compiled
/// filter is built from. `Planned` entries resolved to a syscall number
/// on this architecture and became filter rules; `Skipped` entries did
/// not (`reason` says why).
pub fn syscall_grant_intents(
    policy: &Policy,
    allow_startup_exec: bool,
    namespaced: bool,
) -> Vec<ProcessGrant> {
    let mut grants = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let allowed = allowed_syscall_names(policy, allow_startup_exec);
    // An explicit "clone" entry makes the SYS_clone rule unconditional
    // (see collect_syscall_rules), so a fork/vfork grant does not pin
    // its flag word in that case.
    let clone_allowed = allowed.iter().any(|s| s == "clone");
    for name in allowed {
        if !seen.insert(name.clone()) {
            continue;
        }
        let injected = !policy.syscalls.allowed.iter().any(|s| s == &name);
        let origin = if injected {
            GrantOrigin::Runtime
        } else {
            GrantOrigin::Policy
        };
        if syscall_numbers(&name).is_empty() {
            grants.push(ProcessGrant {
                subject: GrantSubject::Syscall { name },
                origin,
                state: ControlState::Skipped,
                reason: Some("no syscall mapping on this architecture".to_string()),
            });
            continue;
        }
        let mut reason: Vec<String> = Vec::new();
        if injected {
            reason.push(
                "execve/execveat injected for startup; remains allowed for the \
                 process lifetime"
                    .to_string(),
            );
        }
        if DANGEROUS_SYSCALLS.contains(&name.as_str()) {
            reason.push("dangerous syscall explicitly allowed by policy".to_string());
        }
        if name == "socket" {
            if namespaced {
                reason.push(
                    "socket() narrowed to AF_INET/AF_INET6 only — AF_UNIX, \
                     AF_VSOCK, AF_PACKET and AF_NETLINK stay denied: unix \
                     pathnames resolve on the shared host filesystem \
                     (Landlock does not mediate AF_UNIX connect below ABI v9) \
                     and the other families are not namespaced by netns, so \
                     any of them would bypass the TUN boundary"
                        .to_string(),
                );
            } else if policy.network.outbound.deny_all_others {
                let mut unix = false;
                let mut unix_star = false;
                for u in policy.network.outbound.unix_allows() {
                    unix = true;
                    unix_star |= u == "*";
                }
                reason.push(
                    if unix_star {
                        "restricted to AF_INET/AF_INET6 SOCK_STREAM plus the whole \
                     AF_UNIX family by 'allow unix=\"*\"'; other families stay \
                     denied"
                    } else if unix {
                        "restricted to AF_INET/AF_INET6 SOCK_STREAM plus AF_UNIX \
                     SOCK_STREAM by 'allow unix=' path opt-ins (Landlock \
                     ResolveUnix scopes the path on ABI v9); other families \
                     and datagram types stay denied"
                    } else {
                        "restricted to AF_INET/AF_INET6 SOCK_STREAM — AF_UNIX, \
                     AF_VSOCK, AF_PACKET and AF_NETLINK close the IPC escape \
                     route; datagram types stay denied"
                    }
                    .to_string(),
                );
            }
        }
        if matches!(name.as_str(), "sendto" | "sendmsg" | "sendmmsg")
            && !namespaced
            && policy.network.outbound.deny_all_others
        {
            reason.push(
                "MSG_FASTOPEN pinned clear — unotify sees connect(2) only, so \
                 the flag's connect-less send would carry an unsupervised \
                 destination; unconnected datagram sockets already cannot \
                 exist under the socket() type pin"
                    .to_string(),
            );
        }
        if name == "socketpair" {
            let unix_star = !namespaced
                && policy
                    .network
                    .outbound
                    .unix_allows()
                    .iter()
                    .any(|u| u == "*");
            if unix_star {
                reason.push(
                    "unrestricted — 'allow unix=\"*\"' opted the whole AF_UNIX \
                     family in"
                        .to_string(),
                );
            } else if namespaced || policy.network.outbound.deny_all_others {
                reason.push(
                    "AF_UNIX SOCK_DGRAM denied — a datagram pair can sendto(2) any \
                     unix pathname the socket() pin cannot reach; stream/seqpacket \
                     pairs stay"
                        .to_string(),
                );
            }
        }
        if matches!(
            name.as_str(),
            "kill" | "tkill" | "tgkill" | "pidfd_send_signal"
        ) {
            if namespaced {
                reason.push(
                    "cross-domain signals confined to in-namespace pids by \
                     CLONE_NEWPID"
                        .to_string(),
                );
            } else {
                let abi = super::landlock_impl::kernel_abi();
                reason.push(if abi >= 6 {
                    "cross-domain signals denied by Landlock Scope::Signal \
                     (ABI v6)"
                        .to_string()
                } else {
                    format!(
                        "kernel Landlock ABI v{abi} predates Scope::Signal (v6) \
                         — signals to outside processes are unmediated"
                    )
                });
            }
        }
        if (name == "fork" || name == "vfork") && !clone_allowed {
            reason.push("clone(2) flag word pinned to the fork form".to_string());
        }
        grants.push(ProcessGrant {
            subject: GrantSubject::Syscall { name },
            origin,
            state: ControlState::Planned,
            reason: if reason.is_empty() {
                None
            } else {
                Some(reason.join("; "))
            },
        });
    }
    grants
}

fn compile_seccomp_inner(
    policy: &Policy,
    allow_startup_exec: bool,
    namespaced: bool,
) -> Result<BpfProgram, WardenError> {
    let allowed_syscalls = allowed_syscall_names(policy, allow_startup_exec);

    // Translate policy syscall names to numeric rules.
    let rules = collect_syscall_rules(policy, &allowed_syscalls, namespaced)?;

    // Step 3: Determine target architecture.
    let arch = target_arch()?;

    // Step 4: Build filter.
    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(1), // EPERM
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("seccomp: failed to build filter: {e}"),
        )
    })?;

    // Step 5: Compile to BPF.
    let program: BpfProgram = filter.try_into().map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("seccomp: failed to compile BPF: {e}"),
        )
    })?;

    Ok(program)
}

/// Build the syscall-nr → rules map for a set of allowed policy names.
///
/// Each nr maps to a vector of or-bound rules; an empty vector means the
/// syscall matches unconditionally.
fn collect_syscall_rules(
    policy: &Policy,
    allowed_syscalls: &[String],
    namespaced: bool,
) -> Result<BTreeMap<i64, Vec<SeccompRule>>, WardenError> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    for name in allowed_syscalls {
        if DANGEROUS_SYSCALLS.contains(&name.as_str()) {
            tracing::warn!("seccomp: dangerous syscall '{name}' is explicitly allowed by policy");
        }

        let nrs = syscall_numbers(name);
        if nrs.is_empty() {
            tracing::warn!(
                "seccomp: syscall name '{name}' has no mapping on this architecture, skipping"
            );
            continue;
        }
        for nr in nrs {
            // socket() carries the AF_UNIX/deny-all boundary on the
            // native route *and* the TUN boundary on the namespaced
            // route:
            // - namespaced: the workload's sockets must dead-end inside
            //   its netns — only IP families cross the TUN boundary, so
            //   socket() is pinned to an explicit AF_INET/AF_INET6
            //   allowlist: AF_UNIX reaches host daemons through the
            //   shared mountns (Landlock does not mediate AF_UNIX
            //   connect(2) below ABI v9), and AF_VSOCK/AF_PACKET/
            //   AF_NETLINK/etc. are not namespaced by netns at all —
            //   they would bypass the TUN entirely.
            // - native under deny-all: the family pin is the same
            //   escape closure — AF_UNIX pathnames resolve on the
            //   shared host filesystem, abstract sockets ignore paths,
            //   and Landlock mediates neither below ABI v6/v9 — so the
            //   family closes at creation and the policy's `allow
            //   unix=` opt-ins reopen it: `"*"` admits the whole
            //   family, a path opt-in admits connection-oriented types
            //   (pathname sends stay Landlock-scoped where the kernel
            //   can express it).
            // Under an open posture the native route pins nothing —
            // matching the unrestricted TCP the posture promises.
            let pin_socket = namespaced || policy.network.outbound.deny_all_others;
            if name == "socket" && pin_socket {
                const SOCK_TYPE_MASK: u64 = 0xf;
                let cond = |arg: u8, op: SeccompCmpOp, value: u64| {
                    SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value).map_err(|e| {
                        WardenError::sandbox_setup(
                            crate::error::SandboxStage::Prepare,
                            format!("seccomp socket condition: {e}"),
                        )
                    })
                };
                let rule = |conds: Vec<SeccompCondition>| {
                    SeccompRule::new(conds).map_err(|e| {
                        WardenError::sandbox_setup(
                            crate::error::SandboxStage::Prepare,
                            format!("seccomp socket rule: {e}"),
                        )
                    })
                };
                let stream = |family: u64| {
                    rule(vec![
                        cond(0, SeccompCmpOp::Eq, family)?,
                        cond(
                            1,
                            SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                            libc::SOCK_STREAM as u64,
                        )?,
                    ])
                };
                let mut fam_rules = if namespaced {
                    // Namespaced: family pin only — the in-netns
                    // workload needs SOCK_DGRAM for DNS/UDP (the proxy
                    // relays datagrams), and every type inside the IP
                    // families still dead-ends at the TUN boundary.
                    vec![
                        rule(vec![cond(0, SeccompCmpOp::Eq, libc::AF_INET as u64)?])?,
                        rule(vec![cond(0, SeccompCmpOp::Eq, libc::AF_INET6 as u64)?])?,
                    ]
                } else {
                    vec![
                        stream(libc::AF_INET as u64)?,
                        stream(libc::AF_INET6 as u64)?,
                    ]
                };
                if !namespaced {
                    // D-2: `allow unix=` opens the family under the
                    // restricted posture. `"*"` is the whole family —
                    // every socket type, matching the unscoped opt-in
                    // spelling. A path opt-in only needs
                    // connection-oriented sockets — unix datagram
                    // sockets stay denied so a `sendto` cannot reach a
                    // pathname outside the grant.
                    let mut unix_star = false;
                    let mut unix_path = false;
                    for u in policy.network.outbound.unix_allows() {
                        if u == "*" {
                            unix_star = true;
                        } else {
                            unix_path = true;
                        }
                    }
                    if unix_star {
                        fam_rules.push(rule(vec![cond(
                            0,
                            SeccompCmpOp::Eq,
                            libc::AF_UNIX as u64,
                        )?])?);
                    }
                    if unix_path {
                        fam_rules.push(stream(libc::AF_UNIX as u64)?);
                    }
                }
                rules.insert(nr, fam_rules);
            } else if name == "socketpair" && pin_socket {
                // Shared across both routes: socketpair(2) needs no
                // pathname at creation — but a SOCK_DGRAM pair can
                // sendto(2) any host unix pathname, the same escape the
                // socket() family pin closes (and on the native route
                // the family pin does not cover socketpair's domain
                // word at all). Refuse only that combination: a
                // non-Unix domain has no unix pathname to reach, and
                // connection-bound types (stream/seqpacket) have no
                // sendto target, so local IPC pairs stay. `allow
                // unix="*"` opted the whole family in — datagram
                // sockets are already creatable there, so keeping the
                // pair denied would contradict the opt-in. An open
                // native posture pins nothing here either — the pair
                // buys no mediation the unrestricted socket() does not
                // already waive.
                let unix_star = !namespaced
                    && policy
                        .network
                        .outbound
                        .unix_allows()
                        .iter()
                        .any(|u| u == "*");
                if unix_star {
                    // An empty rule vector is the unconditional allow —
                    // the whole family opted in, so socketpair needs no
                    // domain/type conditions.
                    rules.insert(nr, vec![]);
                } else {
                    const SOCK_TYPE_MASK: u64 = 0xf;
                    let cond = |arg: u8, op: SeccompCmpOp, value: u64| {
                        SeccompCondition::new(arg, SeccompCmpArgLen::Dword, op, value).map_err(
                            |e| {
                                WardenError::sandbox_setup(
                                    crate::error::SandboxStage::Prepare,
                                    format!("seccomp socketpair condition: {e}"),
                                )
                            },
                        )
                    };
                    let rule = |conds: Vec<SeccompCondition>| {
                        SeccompRule::new(conds).map_err(|e| {
                            WardenError::sandbox_setup(
                                crate::error::SandboxStage::Prepare,
                                format!("seccomp socketpair rule: {e}"),
                            )
                        })
                    };
                    rules.insert(
                        nr,
                        vec![
                            rule(vec![cond(0, SeccompCmpOp::Ne, libc::AF_UNIX as u64)?])?,
                            rule(vec![cond(
                                1,
                                SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                                libc::SOCK_STREAM as u64,
                            )?])?,
                            rule(vec![cond(
                                1,
                                SeccompCmpOp::MaskedEq(SOCK_TYPE_MASK),
                                libc::SOCK_SEQPACKET as u64,
                            )?])?,
                        ],
                    );
                }
            } else if matches!(name.as_str(), "sendto" | "sendmsg" | "sendmmsg")
                && !namespaced
                && policy.network.outbound.deny_all_others
            {
                // Destination-bearing sends on the restricted native
                // route: the socket() pin already denies unconnected
                // INET datagram sockets and unotify supervises every
                // connect(2) — but sendto(2) on a SOCK_STREAM socket
                // with MSG_FASTOPEN connects from the send's own
                // sockaddr without any connect(2) call (sendmsg/sendmmsg
                // take the same flag in their trailing scalar word).
                // Pin the flags word so the fast-open bit must be
                // clear; AF_UNIX self-pipe sends and connected sends
                // pass unchanged. The namespaced route needs no pin —
                // its TUN boundary evaluates the SYN itself — and an
                // open posture promises unrestricted TCP already.
                let flags_arg: u8 = if name == "sendmsg" { 2 } else { 3 };
                let cond = SeccompCondition::new(
                    flags_arg,
                    SeccompCmpArgLen::Dword,
                    SeccompCmpOp::MaskedEq(libc::MSG_FASTOPEN as u64),
                    0,
                )
                .map_err(|e| {
                    WardenError::sandbox_setup(
                        crate::error::SandboxStage::Prepare,
                        format!("seccomp {name} flags condition: {e}"),
                    )
                })?;
                let rule = SeccompRule::new(vec![cond]).map_err(|e| {
                    WardenError::sandbox_setup(
                        crate::error::SandboxStage::Prepare,
                        format!("seccomp {name} flags rule: {e}"),
                    )
                })?;
                rules.insert(nr, vec![rule]);
            } else if (name == "fork" || name == "vfork") && nr == libc::SYS_clone {
                // fork/vfork expand to clone(2): pin clone's flag word to
                // exactly the bits those operations need so the grant
                // cannot mint namespaces or share memory/threads. The
                // exit signal is fixed at SIGCHLD; only the benign
                // CHILD_*TID bookkeeping flags stay optional.
                let required: u64 = libc::SIGCHLD as u64
                    | if name == "vfork" {
                        libc::CLONE_VM as u64 | libc::CLONE_VFORK as u64
                    } else {
                        0
                    };
                let optional: u64 =
                    libc::CLONE_CHILD_SETTID as u64 | libc::CLONE_CHILD_CLEARTID as u64;
                let cond = SeccompCondition::new(
                    0,
                    SeccompCmpArgLen::Qword,
                    SeccompCmpOp::MaskedEq(!optional),
                    required,
                )
                .map_err(|e| {
                    WardenError::sandbox_setup(
                        crate::error::SandboxStage::Prepare,
                        format!("seccomp {name} clone condition: {e}"),
                    )
                })?;
                let rule = SeccompRule::new(vec![cond]).map_err(|e| {
                    WardenError::sandbox_setup(
                        crate::error::SandboxStage::Prepare,
                        format!("seccomp {name} clone rule: {e}"),
                    )
                })?;
                match rules.get_mut(&nr) {
                    // An empty rule vector is an unconditional allow: an
                    // explicit "clone" entry must not be narrowed by a
                    // fork/vfork expansion.
                    Some(existing) if existing.is_empty() => {}
                    Some(existing) => existing.push(rule),
                    None => {
                        rules.insert(nr, vec![rule]);
                    }
                }
            } else {
                rules.insert(nr, vec![]);
            }
        }
    }

    Ok(rules)
}

pub fn policy_allows_execve(policy: &Policy) -> bool {
    policy
        .syscalls
        .allowed
        .iter()
        .any(|s| s == "execve" || s == "execveat")
}

/// Spawning a child requires either an explicit execve allowance or
/// `sandbox.allow_degraded` (which leaves leftover execve in the
/// inherited filter).
///
/// When the effective list lacks `execve` the refusal names the file
/// that wrote it — the load's provenance log says which declaration
/// (an `extends`/include/when replacement) last owned
/// `defaults.syscalls`, so an operator editing the entry file's
/// list is not sent to the wrong file.
pub fn require_execve_allowance(policy: &Policy) -> Result<(), WardenError> {
    if policy_allows_execve(policy) {
        return Ok(());
    }
    if policy.sandbox.allow_degraded {
        tracing::warn!(
            "syscalls.allowed does not include execve; spawn filter will leave execve \
             available because sandbox.allow_degraded=true"
        );
        return Ok(());
    }
    let mut msg = String::from(
        "syscalls.allowed must include execve (or execveat) to spawn a child process, \
         or set sandbox.allow_degraded=#true to accept leftover execve in the inherited filter",
    );
    if let Some(detail) = execve_provenance_detail(policy) {
        msg.push_str(&detail);
    }
    Err(WardenError::sandbox_setup(
        crate::error::SandboxStage::Policy,
        msg,
    ))
}

/// The provenance clause for the execve refusal — who wrote the
/// effective `defaults.syscalls`, and who lost `execve`/`execveat`
/// along the way. `None` for a policy without load provenance
/// (directly built or JSON-loaded) or when the records say nothing.
pub(crate) fn execve_provenance_detail(policy: &Policy) -> Option<String> {
    let prov = policy.provenance.as_deref()?;
    let mut out = String::new();
    if let Some((file, line)) = prov.field_writer("defaults.syscalls") {
        out.push_str(" — the effective allowlist was written by '");
        out.push_str(&file.display().to_string());
        if let Some(line) = line {
            out.push_str(&format!(":{line}"));
        }
        out.push('\'');
    }
    for item in ["execve", "execveat"] {
        for (contributor, replacer) in prov.dropped_from("defaults.syscalls", item) {
            out.push_str(&format!(
                "; '{}' replaced '{item}' declared by '{}'",
                replacer.display(),
                contributor.display()
            ));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Apply a pre-compiled seccomp-BPF program.
///
/// Safe to call within `pre_exec` after fork: `apply_filter` performs only a
/// direct syscall, and the error path unwraps the inner `io::Error` (an Os
/// repr that never heap-allocates) instead of formatting a message.
pub fn apply_seccomp_program(program: &BpfProgram) -> std::io::Result<()> {
    apply_filter(program).map_err(|e| match e {
        seccompiler::Error::Prctl(e) | seccompiler::Error::Seccomp(e) => e,
        _ => std::io::Error::from_raw_os_error(libc::EACCES),
    })
}

/// Apply a seccomp-BPF filter based on the given policy.
#[allow(dead_code)]
pub fn apply_seccomp(policy: &Policy) -> Result<(), WardenError> {
    let program = compile_seccomp(policy)?;
    apply_seccomp_program(&program).map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Apply,
            format!("seccomp: failed to apply filter: {e}"),
        )
    })?;
    tracing::info!("seccomp: syscall filter applied successfully");
    Ok(())
}

/// Set the `PR_SET_NO_NEW_PRIVS` bit via `prctl(2)`.
///
/// This is a prerequisite for unprivileged seccomp filter installation.
/// Once set, the bit is inherited across `fork`/`clone`/`execve` and
/// cannot be unset.
///
/// Returns the raw prctl errno as an `io::Error` so callers in `pre_exec`
/// context get a meaningful failure without any heap allocation.
pub(crate) fn set_no_new_privs() -> std::io::Result<()> {
    // SAFETY: prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) is a well-defined
    // Linux syscall with no pointer arguments.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Map the runtime architecture to seccompiler's `TargetArch`.
fn target_arch() -> Result<TargetArch, WardenError> {
    #[cfg(target_arch = "x86_64")]
    {
        return Ok(TargetArch::x86_64);
    }

    #[cfg(target_arch = "aarch64")]
    {
        return Ok(TargetArch::aarch64);
    }

    #[allow(unreachable_code)]
    Err(WardenError::sandbox_setup(
        crate::error::SandboxStage::Prepare,
        "seccomp: unsupported architecture (only x86_64 and aarch64 supported)",
    ))
}

/// Translate a syscall name (as written in the policy file) to every
/// Linux syscall number that can carry it on this architecture.
///
/// Policy names denote *operations* (`open`), but libcs implement them
/// through canonical syscalls (`openat`), and on aarch64 the legacy forms
/// do not exist at all — a policy written for x86_64 would silently lose
/// its coverage there. Each name therefore expands to the canonical
/// nr(s) libc can emit on this target, plus the native nr where the
/// architecture still provides the legacy form.
///
/// Returns an empty vec for unrecognised names so the caller can log a
/// warning without aborting the whole filter setup.
fn syscall_numbers(name: &str) -> Vec<i64> {
    if let Some(nr) = direct_number(name) {
        return vec![nr];
    }

    // Operation aliases: the canonical nr(s) carrying the operation on
    // every supported arch. Where a name has no direct mapping at all it
    // only lives here — e.g. aarch64 has no `open`, libc emits `openat`.
    let mut nrs: Vec<i64> = match name {
        "open" | "creat" => vec![libc::SYS_openat],
        // Path-based stat only: `fstat` is a real fd-based syscall on
        // both arches (aarch64 nr 80) and lives in `direct_number`.
        "stat" | "lstat" => vec![libc::SYS_newfstatat],
        "access" => vec![libc::SYS_faccessat, libc::SYS_faccessat2],
        "readlink" => vec![libc::SYS_readlinkat],
        "pipe" => vec![libc::SYS_pipe2],
        "dup2" => vec![libc::SYS_dup3],
        "poll" => vec![libc::SYS_ppoll],
        "select" => vec![libc::SYS_pselect6],
        "epoll_wait" => vec![libc::SYS_epoll_pwait],
        "mkdir" => vec![libc::SYS_mkdirat],
        "mknod" => vec![libc::SYS_mknodat],
        // unlinkat is the single primitive for both operations.
        "unlink" | "rmdir" => vec![libc::SYS_unlinkat],
        "chmod" => vec![libc::SYS_fchmodat],
        "chown" | "lchown" => vec![libc::SYS_fchownat],
        "link" => vec![libc::SYS_linkat],
        "symlink" => vec![libc::SYS_symlinkat],
        // aarch64 wires renameat at asm-generic nr 38; libc emits
        // renameat for rename()/renameat() there. renameat2's flag
        // operations (RENAME_NOREPLACE/EXCHANGE/WHITEOUT) are a separate
        // operation, granted only by an explicit "renameat2" entry.
        "rename" | "renameat" => vec![libc::SYS_renameat],
        // clone is the only fork primitive on aarch64; the allowlist has
        // no flag granularity for it on either arch.
        "fork" | "vfork" => vec![libc::SYS_clone],
        "accept" => vec![libc::SYS_accept, libc::SYS_accept4],
        // aarch64 dropped get/setrlimit; prlimit64 carries both (its pid
        // argument can target other processes — the widening is inherent
        // to the generic ABI, not this mapping).
        "getrlimit" | "setrlimit" => vec![libc::SYS_prlimit64],
        "futimesat" => vec![libc::SYS_utimensat],
        _ => Vec::new(),
    };
    nrs.extend(native_number(name));
    nrs
}

/// The native legacy nr for an aliased name, where the architecture
/// still provides it. aarch64 provides none of them.
#[cfg(target_arch = "x86_64")]
fn native_number(name: &str) -> Option<i64> {
    match name {
        "open" => Some(libc::SYS_open),
        "creat" => Some(libc::SYS_creat),
        "stat" => Some(libc::SYS_stat),
        "lstat" => Some(libc::SYS_lstat),
        "access" => Some(libc::SYS_access),
        "readlink" => Some(libc::SYS_readlink),
        "pipe" => Some(libc::SYS_pipe),
        "dup2" => Some(libc::SYS_dup2),
        "poll" => Some(libc::SYS_poll),
        "select" => Some(libc::SYS_select),
        "epoll_wait" => Some(libc::SYS_epoll_wait),
        "mkdir" => Some(libc::SYS_mkdir),
        "mknod" => Some(libc::SYS_mknod),
        "unlink" => Some(libc::SYS_unlink),
        "rmdir" => Some(libc::SYS_rmdir),
        "chmod" => Some(libc::SYS_chmod),
        "chown" => Some(libc::SYS_chown),
        "lchown" => Some(libc::SYS_lchown),
        "link" => Some(libc::SYS_link),
        "symlink" => Some(libc::SYS_symlink),
        "rename" => Some(libc::SYS_rename),
        "fork" => Some(libc::SYS_fork),
        "vfork" => Some(libc::SYS_vfork),
        "getrlimit" => Some(libc::SYS_getrlimit),
        "setrlimit" => Some(libc::SYS_setrlimit),
        "futimesat" => Some(libc::SYS_futimesat),
        "arch_prctl" => Some(libc::SYS_arch_prctl),
        _ => None,
    }
}

/// aarch64 has no legacy syscall nrs; every aliased name resolves to its
/// canonical nr only.
#[cfg(not(target_arch = "x86_64"))]
fn native_number(_name: &str) -> Option<i64> {
    None
}

/// Syscall names that map to exactly one nr on every supported arch.
fn direct_number(name: &str) -> Option<i64> {
    // Common syscalls present on both x86_64 and aarch64.
    let nr: Option<i64> = match name {
        "read" => Some(libc::SYS_read),
        "write" => Some(libc::SYS_write),
        "close" => Some(libc::SYS_close),
        "openat" => Some(libc::SYS_openat),
        "newfstatat" => Some(libc::SYS_newfstatat),
        "fstat" => Some(libc::SYS_fstat),
        "lseek" => Some(libc::SYS_lseek),
        "mmap" => Some(libc::SYS_mmap),
        "mprotect" => Some(libc::SYS_mprotect),
        "munmap" => Some(libc::SYS_munmap),
        "brk" => Some(libc::SYS_brk),
        "rt_sigaction" => Some(libc::SYS_rt_sigaction),
        "rt_sigprocmask" => Some(libc::SYS_rt_sigprocmask),
        "ioctl" => Some(libc::SYS_ioctl),
        "pread64" => Some(libc::SYS_pread64),
        "pwrite64" => Some(libc::SYS_pwrite64),
        "readv" => Some(libc::SYS_readv),
        "writev" => Some(libc::SYS_writev),
        "getcwd" => Some(libc::SYS_getcwd),
        "chdir" => Some(libc::SYS_chdir),
        "fcntl" => Some(libc::SYS_fcntl),
        "flock" => Some(libc::SYS_flock),
        "fsync" => Some(libc::SYS_fsync),
        "dup" => Some(libc::SYS_dup),
        "dup3" => Some(libc::SYS_dup3),
        "pipe2" => Some(libc::SYS_pipe2),
        "clone" => Some(libc::SYS_clone),
        "execve" => Some(libc::SYS_execve),
        "exit" => Some(libc::SYS_exit),
        "exit_group" => Some(libc::SYS_exit_group),
        "wait4" => Some(libc::SYS_wait4),
        "kill" => Some(libc::SYS_kill),
        "getpid" => Some(libc::SYS_getpid),
        // Go runtime thread identity and asynchronous preemption.
        "gettid" => Some(libc::SYS_gettid),
        "tgkill" => Some(libc::SYS_tgkill),
        "getppid" => Some(libc::SYS_getppid),
        "getuid" => Some(libc::SYS_getuid),
        "getgid" => Some(libc::SYS_getgid),
        "geteuid" => Some(libc::SYS_geteuid),
        "getegid" => Some(libc::SYS_getegid),
        "setsid" => Some(libc::SYS_setsid),
        "sigaltstack" => Some(libc::SYS_sigaltstack),
        "socket" => Some(libc::SYS_socket),
        "connect" => Some(libc::SYS_connect),
        "bind" => Some(libc::SYS_bind),
        "listen" => Some(libc::SYS_listen),
        "accept4" => Some(libc::SYS_accept4),
        "sendto" => Some(libc::SYS_sendto),
        "recvfrom" => Some(libc::SYS_recvfrom),
        "shutdown" => Some(libc::SYS_shutdown),
        "setsockopt" => Some(libc::SYS_setsockopt),
        "getsockopt" => Some(libc::SYS_getsockopt),
        "epoll_create1" => Some(libc::SYS_epoll_create1),
        "epoll_ctl" => Some(libc::SYS_epoll_ctl),
        "eventfd2" => Some(libc::SYS_eventfd2),
        "futex" => Some(libc::SYS_futex),
        "nanosleep" => Some(libc::SYS_nanosleep),
        "clock_gettime" => Some(libc::SYS_clock_gettime),
        "clock_nanosleep" => Some(libc::SYS_clock_nanosleep),
        "getrandom" => Some(libc::SYS_getrandom),
        "prctl" => Some(libc::SYS_prctl),
        // Thread/process lifecycle (needed by glibc and tokio runtime).
        "set_tid_address" => Some(libc::SYS_set_tid_address),
        "set_robust_list" => Some(libc::SYS_set_robust_list),
        "sched_getaffinity" => Some(libc::SYS_sched_getaffinity),
        "sched_yield" => Some(libc::SYS_sched_yield),
        "rt_sigreturn" => Some(libc::SYS_rt_sigreturn),
        "madvise" => Some(libc::SYS_madvise),
        "epoll_pwait" => Some(libc::SYS_epoll_pwait),
        "prlimit64" => Some(libc::SYS_prlimit64),
        "rseq" => Some(libc::SYS_rseq),
        "clone3" => Some(libc::SYS_clone3),
        "getdents64" => Some(libc::SYS_getdents64),
        // Modern names present on both arches; libc emits these directly.
        "faccessat" => Some(libc::SYS_faccessat),
        "faccessat2" => Some(libc::SYS_faccessat2),
        "readlinkat" => Some(libc::SYS_readlinkat),
        "statx" => Some(libc::SYS_statx),
        "mkdirat" => Some(libc::SYS_mkdirat),
        "unlinkat" => Some(libc::SYS_unlinkat),
        "fchmodat" => Some(libc::SYS_fchmodat),
        "fchownat" => Some(libc::SYS_fchownat),
        "linkat" => Some(libc::SYS_linkat),
        "symlinkat" => Some(libc::SYS_symlinkat),
        "renameat2" => Some(libc::SYS_renameat2),
        "openat2" => Some(libc::SYS_openat2),
        "execveat" => Some(libc::SYS_execveat),
        "ppoll" => Some(libc::SYS_ppoll),
        "pselect6" => Some(libc::SYS_pselect6),
        "memfd_create" => Some(libc::SYS_memfd_create),
        "close_range" => Some(libc::SYS_close_range),
        "sendmsg" => Some(libc::SYS_sendmsg),
        "recvmsg" => Some(libc::SYS_recvmsg),
        "sendmmsg" => Some(libc::SYS_sendmmsg),
        "recvmmsg" => Some(libc::SYS_recvmmsg),
        "getsockname" => Some(libc::SYS_getsockname),
        "getpeername" => Some(libc::SYS_getpeername),
        "socketpair" => Some(libc::SYS_socketpair),
        "sendfile" => Some(libc::SYS_sendfile),
        "ftruncate" => Some(libc::SYS_ftruncate),
        "truncate" => Some(libc::SYS_truncate),
        "fchmod" => Some(libc::SYS_fchmod),
        "fchown" => Some(libc::SYS_fchown),
        "statfs" => Some(libc::SYS_statfs),
        "fstatfs" => Some(libc::SYS_fstatfs),
        "utimensat" => Some(libc::SYS_utimensat),
        "mknodat" => Some(libc::SYS_mknodat),
        "inotify_init1" => Some(libc::SYS_inotify_init1),
        "inotify_add_watch" => Some(libc::SYS_inotify_add_watch),
        "inotify_rm_watch" => Some(libc::SYS_inotify_rm_watch),
        "copy_file_range" => Some(libc::SYS_copy_file_range),
        "splice" => Some(libc::SYS_splice),
        "readahead" => Some(libc::SYS_readahead),
        "fadvise64" => Some(libc::SYS_fadvise64),
        "pidfd_open" => Some(libc::SYS_pidfd_open),
        "pidfd_send_signal" => Some(libc::SYS_pidfd_send_signal),
        "uname" => Some(libc::SYS_uname),
        "sysinfo" => Some(libc::SYS_sysinfo),
        "waitid" => Some(libc::SYS_waitid),
        "getxattr" => Some(libc::SYS_getxattr),
        "setxattr" => Some(libc::SYS_setxattr),
        "listxattr" => Some(libc::SYS_listxattr),
        "removexattr" => Some(libc::SYS_removexattr),
        "fgetxattr" => Some(libc::SYS_fgetxattr),
        "fsetxattr" => Some(libc::SYS_fsetxattr),
        "flistxattr" => Some(libc::SYS_flistxattr),
        "fremovexattr" => Some(libc::SYS_fremovexattr),
        "lgetxattr" => Some(libc::SYS_lgetxattr),
        "lsetxattr" => Some(libc::SYS_lsetxattr),
        "llistxattr" => Some(libc::SYS_llistxattr),
        "lremovexattr" => Some(libc::SYS_lremovexattr),
        "timer_create" => Some(libc::SYS_timer_create),
        "timer_settime" => Some(libc::SYS_timer_settime),
        "timer_gettime" => Some(libc::SYS_timer_gettime),
        "timer_delete" => Some(libc::SYS_timer_delete),
        "timerfd_create" => Some(libc::SYS_timerfd_create),
        "timerfd_gettime" => Some(libc::SYS_timerfd_gettime),
        "timerfd_settime" => Some(libc::SYS_timerfd_settime),
        "signalfd4" => Some(libc::SYS_signalfd4),
        "getcpu" => Some(libc::SYS_getcpu),
        "sched_getattr" => Some(libc::SYS_sched_getattr),
        "sched_setattr" => Some(libc::SYS_sched_setattr),
        "sched_getparam" => Some(libc::SYS_sched_getparam),
        "sched_setparam" => Some(libc::SYS_sched_setparam),
        "sched_getscheduler" => Some(libc::SYS_sched_getscheduler),
        "sched_setscheduler" => Some(libc::SYS_sched_setscheduler),
        "getpriority" => Some(libc::SYS_getpriority),
        "setpriority" => Some(libc::SYS_setpriority),
        "ioprio_get" => Some(libc::SYS_ioprio_get),
        "ioprio_set" => Some(libc::SYS_ioprio_set),
        "get_mempolicy" => Some(libc::SYS_get_mempolicy),
        "set_mempolicy" => Some(libc::SYS_set_mempolicy),
        "msync" => Some(libc::SYS_msync),
        "mincore" => Some(libc::SYS_mincore),
        "mlock" => Some(libc::SYS_mlock),
        "mlock2" => Some(libc::SYS_mlock2),
        "mlockall" => Some(libc::SYS_mlockall),
        "munlock" => Some(libc::SYS_munlock),
        "munlockall" => Some(libc::SYS_munlockall),
        "personality" => Some(libc::SYS_personality),
        "capget" => Some(libc::SYS_capget),
        // io_uring operations submitted to a ring execute without
        // re-entering this filter; mapping the names only lets a policy
        // take that tradeoff explicitly (see runtime/node.kdl).
        "io_uring_setup" => Some(libc::SYS_io_uring_setup),
        "io_uring_enter" => Some(libc::SYS_io_uring_enter),
        "io_uring_register" => Some(libc::SYS_io_uring_register),
        "membarrier" => Some(libc::SYS_membarrier),
        // Dangerous syscalls — mapped so that explicit policy entries work.
        "ptrace" => Some(libc::SYS_ptrace),
        "keyctl" => Some(libc::SYS_keyctl),
        "unshare" => Some(libc::SYS_unshare),
        "mount" => Some(libc::SYS_mount),
        "umount2" => Some(libc::SYS_umount2),
        _ => None,
    };
    nr
}

#[cfg(test)]
mod tests;
