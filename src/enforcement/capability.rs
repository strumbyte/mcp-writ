//! The machine-readable capability catalog — one row per sandbox
//! mechanism and per isolation boundary, plus the shared requirement
//! vocabulary the capability probes, `--report` outputs, and (PR-16)
//! mechanism selection all read from.
//!
//! This module is the single source for data that must not diverge:
//!
//! - the per-layer egress disposition `plan` and the PoC `--report`
//!   outputs emit IS the catalog row's [`LayerCapability`] — the
//!   `os`/`note` strings are copied into [`EgressLayerStatus`] here,
//!   not re-typed at each call site;
//! - a mechanism's `requires` ids are the same tokens a probe names in
//!   [`UnmetRequirement::requirements`] and a `--report` `missing`
//!   member lists — a report can never claim requirements the catalog
//!   does not name;
//! - `status`/`deficiencies` bound the claim honestly — a verified
//!   environment is evidence scope, never a general-support statement,
//!   and an unsupported combination refuses or reports `null` instead
//!   of inferring a different path.
//!
//! The committed `docs/capability-matrix.json` is
//! [`capability_matrix_json`] output; `tests/capability_matrix.rs`
//! diffs the two so the document can never drift from the
//! implementation. This is leaf data (layer 0) — mechanism facts are
//! static strings, target facts come from [`crate::execution`].

use crate::enforcement::EgressLayerStatus;
use crate::execution::{
    ExecutionSubstrate, ExecutionTarget, IsolationKind, TargetOs, WindowsNativeMechanism,
};

/// Schema version of the [`capability_matrix_json`] document.
pub const CAPABILITY_MATRIX_SCHEMA_VERSION: &str = "1";

/// A host/kernel capability a mechanism requires — or uses when
/// present. `id` is the stable token a probe names when the
/// requirement is unmet (`UnmetRequirement`, a `--report` `missing`
/// member); `detail` is what the launch needs it for.
#[derive(Debug)]
pub struct Requirement {
    pub id: &'static str,
    pub detail: &'static str,
}

/// The OS-level disposition of one egress layer under a mechanism.
///
/// `os` is `None` when no mechanism on the path can reach the layer —
/// the layer then stays at the RPC/Auditor surface and `note` says why
/// honestly. `granularity` names the destination forms the OS
/// mechanism evaluates (`"fqdn"`, `"cidr"`, `"literal-ip"`, `"port"`,
/// `"proto"`); `transports` the traffic it covers (`"tcp"`, `"udp"`,
/// `"dns"`, `"any"` for a transport-independent destination rule).
#[derive(Debug)]
pub struct LayerCapability {
    /// `name` (FQDN rules) or `ip` (CIDR / literal-IP rules).
    pub layer: &'static str,
    /// The OS mechanism evaluating this layer; `None` = RPC-only.
    pub os: Option<&'static str>,
    /// Destination forms the OS mechanism enforces at this layer.
    pub granularity: &'static [&'static str],
    /// Transports the OS mechanism covers at this layer.
    pub transports: &'static [&'static str],
    /// Why the layer is — or is not — covered. The same text
    /// [`EgressLayerStatus::note`] carries in `plan`/`--report` output.
    pub note: &'static str,
}

impl LayerCapability {
    /// The [`EgressLayerStatus`] this capability projects — the RPC
    /// surface is the Auditor's argument checks on every path.
    pub fn status(&self) -> EgressLayerStatus {
        EgressLayerStatus {
            layer: self.layer,
            rpc: "auditor",
            os: self.os.map(|s| s.to_string()),
            note: Some(self.note.to_string()),
        }
    }
}

/// One sandbox mechanism's capability row.
///
/// `status` vocabulary: `adopted` (product path), `adopted-conditional`
/// (adopted behind a per-launch capability probe — failure refuses),
/// `opt-in` (implemented alternative path, explicit selection only),
/// `poc` (proof-of-concept, not a product route), `none` (no
/// mechanism). `auto_candidate` marks the rows the PR-16 `auto` Linux
/// egress-selection may pick; every mechanism today still requires its
/// explicit selection surface (`selected_by`).
#[derive(Debug)]
pub struct MechanismCapability {
    /// Stable row id — the value `target.sandbox_mechanism` reports.
    pub id: &'static str,
    /// The workload OS the mechanism applies to.
    pub os: &'static str,
    /// The CLI surface that selects it (`run`, `unotify-run`,
    /// `--windows-mechanism psec`, ...).
    pub selected_by: &'static str,
    /// Adoption status — see the type-level vocabulary.
    pub status: &'static str,
    /// Whether the design's `auto` Linux egress-selection may pick it.
    pub auto_candidate: bool,
    /// `os.*` control ids this mechanism's `plan` emits.
    pub controls: &'static [&'static str],
    /// The `name` + `ip` egress-layer dispositions (index 0 = name).
    pub layers: [LayerCapability; 2],
    /// Egress transports OS enforcement reaches at all on this path.
    pub transports: &'static [&'static str],
    /// Required host capabilities — a missing one refuses the launch.
    pub requires: &'static [Requirement],
    /// Used when present; absence degrades honestly and is recorded.
    pub optional: &'static [Requirement],
    /// Named gaps the mechanism cannot enforce.
    pub deficiencies: &'static [&'static str],
    /// When a launch selects this mechanism.
    pub select: &'static str,
    /// Conditions that refuse the launch — never a silent fallback.
    pub refuse: &'static [&'static str],
}

impl MechanismCapability {
    /// The `(name, ip)` layer statuses — what the mechanism's
    /// `os_egress_layer_status` and `--report` emit.
    pub fn egress_status(&self) -> (EgressLayerStatus, EgressLayerStatus) {
        (self.layers[0].status(), self.layers[1].status())
    }

    /// The single-layer status (`"name"` or `"ip"`).
    pub fn layer_status(&self, layer: &str) -> EgressLayerStatus {
        self.layers
            .iter()
            .find(|l| l.layer == layer)
            .expect("egress layer is 'name' or 'ip'")
            .status()
    }
}

/// An `--isolation` boundary — the coarser execution substrate the
/// mechanism rows do not cover. `kind` is the typed
/// [`IsolationKind`]; `unit`/`guest_os`/`substrate` serialize from its
/// methods so the matrix reports exactly what the launch would record.
#[derive(Debug)]
pub struct BoundaryCapability {
    pub kind: IsolationKind,
    /// The host environments the boundary exists on — a launch off
    /// them refuses at selection/`plan` time.
    pub host: &'static str,
    /// The engines (`--engine`) that can drive it.
    pub engines: &'static [&'static str],
    /// Same status vocabulary as [`MechanismCapability::status`].
    pub status: &'static str,
    /// Prerequisites and honest scope.
    pub note: &'static str,
}

/// An OS-independent control — the launch + RPC surface every
/// mechanism row shares.
#[derive(Debug)]
pub struct CommonControl {
    pub id: &'static str,
    /// `launch` or `rpc`.
    pub layer: &'static str,
    pub mechanism: &'static str,
    pub note: &'static str,
}

/// One probe-verified set of unmet requirements — the shared currency
/// between a `check_support` probe, a `--report` `missing` member, and
/// a mechanism selector that refuses rather than falls back.
/// `requirements` holds [`Requirement::id`] tokens from the
/// mechanism's catalog `requires`; `detail` is the human-readable
/// diagnostic.
#[derive(Debug)]
pub struct UnmetRequirement {
    pub requirements: Vec<&'static str>,
    pub detail: String,
}

impl UnmetRequirement {
    /// A single unmet requirement.
    pub fn one(id: &'static str, detail: impl Into<String>) -> Self {
        Self {
            requirements: vec![id],
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for UnmetRequirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for UnmetRequirement {}

// ---------------------------------------------------------------------------
// The mechanism catalog
// ---------------------------------------------------------------------------

/// Linux: Landlock + seccomp + `no_new_privs` — the `run` default.
pub const LINUX_NATIVE: MechanismCapability = MechanismCapability {
    id: "linux-native",
    os: "linux",
    selected_by: "run (default native Warden)",
    status: "adopted",
    auto_candidate: true,
    controls: &[
        "os.privileges",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: None,
            granularity: &[],
            transports: &[],
            note: "Landlock network rules bind a TCP port, not a destination — host \
                   rules are enforced by the Auditor's argument checks only; the \
                   `dns-gate` component can apply the same name rules to a \
                   workload that resolves through it, but it is not wired into \
                   this path",
        },
        LayerCapability {
            layer: "ip",
            os: None,
            granularity: &["port"],
            transports: &["tcp"],
            note: "Landlock cannot express a destination CIDR — cidr rules and \
                   literal-IP host rules are enforced by the Auditor's argument \
                   checks only on this path; the opt-in `unotify-run` PoC \
                   supervises connect(2) destinations through seccomp user \
                   notification, and the opt-in `ebpf-run` route enforces them \
                   in-kernel through cgroup eBPF (needs privileges)",
        },
    ],
    transports: &["tcp"],
    requires: &[
        Requirement {
            id: "no-new-privs",
            detail: "PR_SET_NO_NEW_PRIVS is set unconditionally before the seccomp \
                     filter installs",
        },
        Requirement {
            id: "seccomp-bpf",
            detail: "the syscall allowlist filter must build and install — an \
                     install failure refuses the spawn",
        },
        Requirement {
            id: "landlock",
            detail: "kernel >= 5.13 for filesystem rules — a NotEnforced ruleset \
                     refuses the launch unless `sandbox allow_degraded`",
        },
    ],
    optional: &[Requirement {
        id: "landlock-abi-v4",
        detail: "kernel >= 6.7: ConnectTcp/BindTcp port rules — older kernels \
                 report PartiallyEnforced, tolerated only under `sandbox \
                 allow_degraded`",
    }],
    deficiencies: &[
        "no destination-IP egress narrowing — cidr rules and literal-IP host \
         rules stay Auditor-checked (`namespaced-run`/`unotify-run`/`ebpf-run` \
         close the IP layer on their opt-in paths)",
        "no destination-name egress narrowing — host rules stay Auditor-checked \
         (`dns-gate` can cover a workload pointed at it)",
        "no per-destination UDP control — deny-all removes UDP socket creation \
         outright",
        "inbound listen is never granted — Landlock BindTcp is not used",
        "kernel-level denies have no launch-time observation channel beyond the \
         child's errno — only the seccomp-audited denies emit an audit record",
    ],
    select: "the default native Linux Warden — fs/syscall/landing enforcement \
             whenever a policy needs them, with destination egress rules left \
             Auditor-checked",
    refuse: &[
        "a `deny` beneath an allowed fs parent — rejected at policy load",
        "the syscall allowlist omits execve/execveat — the spawn refuses unless \
         `sandbox allow_degraded`",
        "the Landlock ruleset reports NotEnforced/PartiallyEnforced — refused \
         unless `sandbox allow_degraded`",
        "the command does not resolve or the sandbox apply fails — the spawn \
         aborts, never running unsandboxed",
    ],
};

/// Linux PoC: seccomp user-notification supervision of `connect(2)`.
pub const LINUX_UNOTIFY: MechanismCapability = MechanismCapability {
    id: "linux-unotify",
    os: "linux",
    selected_by: "unotify-run (opt-in PoC)",
    status: "poc",
    auto_candidate: false,
    controls: &[
        "os.privileges",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: Some("dns-gate (optional, external)"),
            granularity: &["fqdn"],
            transports: &["dns"],
            note: "host rules are name-layer; the dns-gate resolver enforces them \
                   for workloads pointed at it, and its allowlist export feeds \
                   this supervisor's grant source",
        },
        LayerCapability {
            layer: "ip",
            os: Some("seccomp-user-notif (PoC)"),
            granularity: &["cidr", "literal-ip"],
            transports: &["tcp"],
            note: "connect(2) destinations evaluated against cidr rules, IP-literal \
                   host rules, and live DNS-grant entries, then emulated on a \
                   dup'd socket fd; connect-only scope + supervisor-lifetime \
                   limits apply (see report limitations)",
        },
    ],
    transports: &["tcp"],
    requires: &[
        Requirement {
            id: "native-arch",
            detail: "x86_64 or aarch64 — the filter's audit arch is per-arch and \
                     compat tasks are killed rather than supervised",
        },
        Requirement {
            id: "seccomp-user-notif",
            detail: "seccomp(SECCOMP_GET_NOTIF_SIZES) answers with the expected \
                     ABI struct sizes (kernel >= 5.0)",
        },
        Requirement {
            id: "notif-continue",
            detail: "a live SECCOMP_USER_NOTIF_FLAG_CONTINUE round trip succeeds \
                     (kernel >= 5.5)",
        },
    ],
    optional: &[Requirement {
        id: "dns-gate",
        detail: "an external `dns-gate` with `--allowlist` export feeds \
                 TTL-scoped IP grants for allowed names",
    }],
    deficiencies: &[
        "connect(2) only — sendto/sendmsg, MSG_FASTOPEN, io_uring connect, fd \
         passing, and non-socket channels are outside this layer",
        "no UDP coverage at all",
        "no name-layer enforcement without the optional dns-gate pairing",
        "PoC scope — supervisor-lifetime enforcement, not the product route",
    ],
    select: "explicit opt-in PoC — per-destination IP enforcement on TCP \
             connect(2) without privileges, for evaluating the IP layer where \
             the namespaced route's requirements are unmet",
    refuse: &[
        "the capability probe reports an unmet requirement — refused, never \
         silently substituting the native path",
        "an allow rule carries a `port=` qualifier — unexpressible at this \
         layer, refused at the IP-layer projection",
        "`logging fail_closed` without a writable `--audit-log`",
    ],
};

/// Linux PoC: private userns+netns whose only egress is a TUN-fed
/// userspace proxy + embedded DNS gate.
pub const LINUX_NAMESPACED: MechanismCapability = MechanismCapability {
    id: "linux-namespaced",
    os: "linux",
    selected_by: "namespaced-run (opt-in PoC; the PR-16 `auto` candidate)",
    status: "poc",
    auto_candidate: true,
    controls: &[
        "os.privileges",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: Some("embedded-dns-gate"),
            granularity: &["fqdn"],
            transports: &["dns"],
            note: "DNS (UDP+TCP port 53) is intercepted and answered by the \
                   embedded policy gate; allowed names mint TTL-scoped grants \
                   into the ip layer — DoT/DoH bypasses name evaluation \
                   (documented gap)",
        },
        LayerCapability {
            layer: "ip",
            os: Some("tun-userspace-proxy"),
            granularity: &["cidr", "literal-ip", "proto", "port"],
            transports: &["tcp", "udp"],
            note: "every flow traverses the TUN-fed userspace proxy: TCP is \
                   policy-checked at connect, UDP per datagram, with proto/port \
                   qualifiers; IPv4 only — v6, fragments, and non-TCP/UDP \
                   protocols are dropped",
        },
    ],
    transports: &["tcp", "udp", "dns"],
    requires: &[
        Requirement {
            id: "userns",
            detail: "CLONE_NEWUSER unshares from a single-threaded process",
        },
        Requirement {
            id: "netns",
            detail: "CLONE_NEWNET creates the private network namespace",
        },
        Requirement {
            id: "mountns",
            detail: "CLONE_NEWNS creates the private mount namespace",
        },
        Requirement {
            id: "pidns",
            detail: "CLONE_NEWPID is created unconditionally at launch — a \
                     failed unshare refuses",
        },
        Requirement {
            id: "uid_gid_map",
            detail: "setgroups=deny + uid_map/gid_map writes map the launcher's \
                     euid to namespace-root",
        },
        Requirement {
            id: "tun",
            detail: "/dev/net/tun opens inside the fresh netns (IFF_TUN|IFF_NO_PI)",
        },
        Requirement {
            id: "loopback_up",
            detail: "rtnetlink brings the namespace's loopback up",
        },
        Requirement {
            id: "default_route_via_tun",
            detail: "rtnetlink adds the workload v4 address and default route \
                     via the TUN device",
        },
    ],
    optional: &[],
    deficiencies: &[
        "IPv4 only — IPv6 is disabled inside the netns and v6 packets are \
         dropped (fail-closed)",
        "no IP-fragment reassembly; non-TCP/UDP protocols (ICMP, GRE, raw) are \
         dropped",
        "DoT/DoH bypasses name-layer enforcement — IP rules still apply",
        "PoC — the product auto-selection integration is PR-16's scope",
    ],
    select: "explicit opt-in PoC, and the mechanism the design's `auto` Linux \
             egress-selection prefers — full TCP/UDP destination name+IP \
             enforcement inside a private netns without privileges",
    refuse: &[
        "any probe stage unmet — userns/netns/mountns/uid_gid_map/tun/\
         loopback_up/default_route_via_tun — refused, never falls back",
        "`--upstream` missing or not an IP literal — the embedded gate refuses \
         to start",
        "a runtime proxy/DNS/audit failure — the launch stops rather than \
         weakening enforcement",
    ],
};

/// Linux opt-in: cgroup-eBPF socket-addr hooks (privileged).
pub const LINUX_EBPF: MechanismCapability = MechanismCapability {
    id: "linux-ebpf",
    os: "linux",
    selected_by: "ebpf-run (opt-in, privileged)",
    status: "opt-in",
    auto_candidate: false,
    controls: &[
        "os.privileges",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: Some("dns-gate (optional, external)"),
            granularity: &["fqdn"],
            transports: &["dns"],
            note: "host rules are name-layer; the dns-gate resolver enforces them \
                   for workloads pointed at it, and its allowlist export feeds \
                   this route's grant maps",
        },
        LayerCapability {
            layer: "ip",
            os: Some("cgroup-ebpf INET4/6_CONNECT + UDP4/6_SENDMSG"),
            granularity: &["cidr", "literal-ip", "proto", "port"],
            transports: &["tcp", "udp"],
            note: "connect(2) and UDP sendto/sendmsg destinations enforced \
                   in-kernel against cidr rules, IP-literal host rules, and \
                   dynamic grants with proto/port scope; cgroup-scoped \
                   coverage applies (see report limitations)",
        },
    ],
    transports: &["tcp", "udp"],
    requires: &[
        Requirement {
            id: "cgroup-v2",
            detail: "a unified cgroup2 hierarchy mounted at /sys/fs/cgroup",
        },
        Requirement {
            id: "cap-bpf-or-sys-admin",
            detail: "CAP_BPF or CAP_SYS_ADMIN for bpf() program/map ops",
        },
        Requirement {
            id: "cap-net-admin",
            detail: "CAP_NET_ADMIN for cgroup program attach",
        },
        Requirement {
            id: "cgroup-writable",
            detail: "write access on the cgroup v2 hierarchy to create the \
                     private cgroup",
        },
        Requirement {
            id: "bpf-syscall",
            detail: "bpf(BPF_MAP_CREATE) succeeds — not blocked by \
                     unprivileged_bpf_disabled or LSM policy",
        },
        Requirement {
            id: "cgroup-bpf-connect",
            detail: "a CGROUP_SOCK_ADDR/INET4_CONNECT program loads — \
                     CONFIG_CGROUP_BPF and the socket-addr attach type exist",
        },
    ],
    optional: &[Requirement {
        id: "dns-gate",
        detail: "an external `dns-gate` with `--allowlist` export feeds \
                 TTL-scoped IP grants for allowed names",
    }],
    deficiencies: &[
        "connect(2)/UDP sendmsg destinations only — MSG_FASTOPEN, io_uring, fd \
         passing, and non-socket channels are outside",
        "IPv4/IPv6 only — other families do not reach the socket-addr hooks",
        "cgroup-scoped — a workload moved out of the private cgroup escapes the \
         hooks",
        "privileged route — needs CAP_BPF/CAP_SYS_ADMIN + CAP_NET_ADMIN + a \
         writable cgroup v2 hierarchy",
    ],
    select: "explicit opt-in — in-kernel per-destination IP enforcement where \
             privileges allow and the namespaced route's isolation is not \
             needed",
    refuse: &[
        "the capability probe reports an unmet requirement — refused, never \
         silently substituting the native path",
        "the policy's rule set exceeds the generated-program bound — refused \
         rather than silently dropping rules",
        "a filesystem write grant overlapping /sys/fs/cgroup — the workload \
         could migrate out of the enforced cgroup",
    ],
};

/// macOS: `sandbox-exec` + generated SBPL profile — the `run` default.
pub const MACOS_SBPL: MechanismCapability = MechanismCapability {
    id: "macos-sbpl",
    os: "macos",
    selected_by: "run (default native Warden)",
    status: "adopted",
    auto_candidate: false,
    controls: &[
        "os.sandbox",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.process",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: None,
            granularity: &[],
            transports: &[],
            note: "the SBPL profile can only express localhost TCP destinations — \
                   host rules are enforced by the Auditor's argument checks only; \
                   the `dns-gate` component can apply the same name rules to a \
                   workload that resolves through it, but it is not wired into \
                   this path",
        },
        LayerCapability {
            layer: "ip",
            os: None,
            granularity: &["port"],
            transports: &["tcp"],
            note: "the SBPL profile cannot express a destination CIDR — cidr rules \
                   and literal-IP host rules are enforced by the Auditor's \
                   argument checks only",
        },
    ],
    transports: &["tcp"],
    requires: &[Requirement {
        id: "sandbox-exec",
        detail: "the sandbox-exec binary must exist and launch — a missing or \
                 rejected launch fails the spawn",
    }],
    optional: &[],
    deficiencies: &[
        "no destination egress expressible — only loopback TCP ports (the opt-in \
         `macos-proxy-run` route adds name+IP destination enforcement)",
        "no syscall allowlist mechanism on macOS",
        "deprecated mechanism — sandbox-exec exposes no kernel-acceptance query, \
         so the per-domain controls stay unobserved",
        "per-tool filesystem is Auditor-only — OS rules cover the global lists \
         only",
    ],
    select: "the only native macOS mechanism — legacy sandbox-exec + generated \
             SBPL profile",
    refuse: &[
        "a remote hostname under deny-all — the spawn fails rather than mapping \
         it to localhost",
        "sandbox-exec missing, or the generated profile rejected — the spawn \
         fails",
    ],
};

/// macOS opt-in: SBPL loopback pin + CONNECT proxy destination control.
pub const MACOS_CONNECT_PROXY: MechanismCapability = MechanismCapability {
    id: "macos-connect-proxy",
    os: "macos",
    selected_by: "macos-proxy-run (opt-in)",
    status: "opt-in",
    auto_candidate: false,
    controls: &[
        "os.sandbox",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.process",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: Some("connect-proxy"),
            granularity: &["fqdn"],
            transports: &["tcp"],
            note: "CONNECT authority names evaluated by the proxy against \
                   allow/deny host rules (deny wins, deny_all_others applies); \
                   allowed names are resolved outside the sandbox and mint \
                   fixed-cap grants into the IP layer under the covering rules' \
                   proto/port qualifiers",
        },
        LayerCapability {
            layer: "ip",
            os: Some("connect-proxy + sbpl loopback pin"),
            granularity: &["cidr", "literal-ip", "port"],
            transports: &["tcp"],
            note: "SBPL pins every outbound TCP connect to the loopback proxy; \
                   the proxy enforces cidr/IP-literal rules, deny rules, and \
                   minted grants per flow before dialing outward",
        },
    ],
    transports: &["tcp"],
    requires: &[
        Requirement {
            id: "sandbox-exec",
            detail: "the sandbox-exec binary must exist and launch — the loopback \
                     pin depends on it",
        },
        Requirement {
            id: "loopback-bind",
            detail: "a loopback TCP listener binds for the proxy — its address \
                     is injected into the profile",
        },
    ],
    optional: &[],
    deficiencies: &[
        "TCP only — the profile denies all UDP egress outright",
        "the workload must use the injected proxy env — a client ignoring it has \
         no egress (fail-closed, but proxy-unaware apps cannot egress)",
        "the proxy is trusted code in the launcher process — a launcher \
         compromise voids the mechanism",
        "minted name->IP grants use a fixed 5-minute cap — getaddrinfo exposes \
         no TTL",
        "the pin relies on deprecated sandbox-exec — same kernel-observability \
         gap as the native path",
    ],
    select: "explicit opt-in — adds name+IP destination enforcement on macOS, \
             where the native path has none",
    refuse: &[
        "the proxy cannot bind/listen or the SBPL build fails — refused; never \
         silently substitutes the native-only path",
    ],
};

/// Windows: AppContainer + Job Object + DACL grants — the `run` default.
pub const WINDOWS_APPCONTAINER: MechanismCapability = MechanismCapability {
    id: "windows-appcontainer",
    os: "windows",
    selected_by: "run (default), or --windows-mechanism appcontainer",
    status: "adopted",
    auto_candidate: false,
    controls: &[
        "os.process",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.net.loopback",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: None,
            granularity: &[],
            transports: &[],
            note: "AppContainer capabilities are all-or-none — host rules are \
                   enforced by the Auditor's argument checks only; no \
                   native-Windows name-layer enforcement exists, so name-based \
                   egress needs a network broker in front of the sandbox or a \
                   guest network (--isolation windows-sandbox, --engine wslc)",
        },
        LayerCapability {
            layer: "ip",
            os: None,
            granularity: &[],
            transports: &[],
            note: "AppContainer capabilities cannot bind a destination address — \
                   cidr rules and literal-IP host rules are enforced by the \
                   Auditor's argument checks only",
        },
    ],
    transports: &[],
    requires: &[
        Requirement {
            id: "appcontainer-api",
            detail: "CreateAppContainerProfile + capability SIDs — in-box \
                     Windows APIs",
        },
        Requirement {
            id: "job-object",
            detail: "a kill-on-close Job Object the child is assigned to",
        },
    ],
    optional: &[],
    deficiencies: &[
        "no per-destination egress — network capabilities are all-or-none (the \
         opt-in `--windows-mechanism psec` path expresses IPv4 destination rules)",
        "no name-layer enforcement — a loopback broker cannot be reached under \
         the capability model; use a guest network",
        "no syscall allowlist mechanism on Windows",
        "ambient read access via ALL_APPLICATION_PACKAGES stays ambient — only \
         explicit ACL grants are enumerated",
    ],
    select: "the default native Windows mechanism — AppContainer profile + \
             capability SIDs + DACL grants + Job Object",
    refuse: &[
        "deny-all plus a nonempty `allow` list — unexpressible as capabilities, \
         rejected at load",
        "profile or capability setup failure — the spawn fails",
    ],
};

/// Windows conditional: PSEC v1.0 security environment — opt-in.
pub const WINDOWS_PSEC: MechanismCapability = MechanismCapability {
    id: "windows-psec",
    os: "windows",
    selected_by: "--windows-mechanism psec (opt-in, conditional)",
    status: "adopted-conditional",
    auto_candidate: false,
    controls: &[
        "os.process",
        "os.fs",
        "os.net.outbound",
        "os.net.inbound",
        "os.net.loopback",
        "os.syscalls",
    ],
    layers: [
        LayerCapability {
            layer: "name",
            os: None,
            granularity: &[],
            transports: &[],
            note: "PSEC cannot express a destination name — host rules are \
                   enforced by the Auditor's argument checks only, and no \
                   native-Windows name layer exists to wire them to: PSEC \
                   v1.0 has no loopback exemption, so a loopback DNS gate \
                   or CONNECT proxy cannot be reached by the workload; \
                   name-based egress needs a network broker in front of the \
                   sandbox or a guest network (--isolation windows-sandbox, \
                   --engine wslc)",
        },
        LayerCapability {
            layer: "ip",
            os: Some("psec"),
            granularity: &["literal-ip"],
            transports: &["any"],
            note: "PSEC v1.0 encodes literal IPv4 destination /32 egress rules \
                   — IPv6, non-/32 prefixes, and port-qualified destinations \
                   are refused at policy load",
        },
    ],
    transports: &["any"],
    requires: &[
        Requirement {
            id: "x86-64",
            detail: "the capability probe refuses ARM64 and other architectures \
                     — the verified surface is x86-64 only",
        },
        Requirement {
            id: "processmodel-psec-1.x",
            detail: "processmodel.dll exports resolve and \
                     IsProcessSecurityEnvironmentVersionSupported accepts the \
                     1.x schema — probed per launch",
        },
    ],
    optional: &[],
    deficiencies: &[
        "IPv4 /32 literal destinations only — no IPv6, no prefixes, no port \
         qualifiers, no names",
        "no ingress section and no loopback exemption — inbound listen and HTTP \
         transports refuse",
        "the child environment is mechanism-managed — allow lists and TMPDIR \
         overrides refuse",
        "preview contract — conditional status, x86-64 verified surface only",
    ],
    select: "explicit opt-in — real per-destination IPv4 egress on native \
             Windows where AppContainer has none",
    refuse: &[
        "the capability probe fails — refused, never falls back to AppContainer",
        "a policy the spec cannot express — non-IPv4 destinations, hostnames, \
         env allow lists, unrestricted egress, inbound listen, HTTP transport \
         — refused at the policy-check stage",
    ],
};

/// Any other OS: no OS sandbox mechanism — the honest `none` row.
pub const GENERIC_NONE: MechanismCapability = MechanismCapability {
    id: "generic-none",
    os: "other",
    selected_by: "run (fallback — no OS sandbox exists)",
    status: "none",
    auto_candidate: false,
    controls: &["os.sandbox"],
    layers: [
        LayerCapability {
            layer: "name",
            os: None,
            granularity: &[],
            transports: &[],
            note: "no OS sandbox mechanism exists on this platform — host rules \
                   are enforced by the Auditor's argument checks only",
        },
        LayerCapability {
            layer: "ip",
            os: None,
            granularity: &[],
            transports: &[],
            note: "no OS sandbox mechanism exists on this platform — cidr rules \
                   are enforced by the Auditor's argument checks only",
        },
    ],
    transports: &[],
    requires: &[],
    optional: &[],
    deficiencies: &[
        "no OS sandbox mechanism — every OS-layer control is NotApplied and \
         the Auditor surface alone applies",
    ],
    select: "unrecognized host OS — the launch continues unsandboxed with a \
             warning rather than refusing",
    refuse: &[],
};

/// Every mechanism row, in catalog order.
pub const MECHANISMS: &[MechanismCapability] = &[
    LINUX_NATIVE,
    LINUX_UNOTIFY,
    LINUX_NAMESPACED,
    LINUX_EBPF,
    MACOS_SBPL,
    MACOS_CONNECT_PROXY,
    WINDOWS_APPCONTAINER,
    WINDOWS_PSEC,
    GENERIC_NONE,
];

/// The launch + RPC controls every mechanism shares — the
/// OS-independent enforcement surface.
pub const COMMON_CONTROLS: &[CommonControl] = &[
    CommonControl {
        id: "launch.identity",
        layer: "launch",
        mechanism: "verifier allowlist",
        note: "hash-pinned payload identity verified before spawn on every OS",
    },
    CommonControl {
        id: "launch.env",
        layer: "launch",
        mechanism: "spawn env",
        note: "the restricted child environment is applied at launch on every \
               OS, including --dry-run and skip-sandbox runs",
    },
    CommonControl {
        id: "rpc.tools",
        layer: "rpc",
        mechanism: "auditor",
        note: "per-tool allowlist on tools/call",
    },
    CommonControl {
        id: "rpc.tools_list",
        layer: "rpc",
        mechanism: "auditor",
        note: "tools/list shape enforcement",
    },
    CommonControl {
        id: "rpc.secret_overlay",
        layer: "rpc",
        mechanism: "auditor",
        note: "secret values overlaid on RPC arguments",
    },
    CommonControl {
        id: "rpc.trajectory",
        layer: "rpc",
        mechanism: "auditor",
        note: "opt-in trajectory rules",
    },
    CommonControl {
        id: "rpc.confused_deputy",
        layer: "rpc",
        mechanism: "auditor",
        note: "opt-in confused-deputy protection",
    },
];

/// The `--isolation` boundaries — coarser substrates the mechanism rows
/// do not cover.
pub const BOUNDARIES: &[BoundaryCapability] = &[
    BoundaryCapability {
        kind: IsolationKind::Container,
        host: "any host with a resolvable engine",
        engines: &["docker", "podman", "wslc"],
        status: "adopted",
        note: "the default run-image isolation — a normal OCI container; `--engine \
               wslc` is a Windows-only explicit engine whose session VM is \
               substrate plumbing, not the boundary",
    },
    BoundaryCapability {
        kind: IsolationKind::Kata,
        host: "linux",
        engines: &["docker"],
        status: "adopted-conditional",
        note: "needs a kata runtime registered with dockerd plus /dev/kvm and \
               /dev/vhost-vsock — a dedicated QEMU VM per launch",
    },
    BoundaryCapability {
        kind: IsolationKind::AppleContainer,
        host: "macos arm64",
        engines: &["container"],
        status: "adopted-conditional",
        note: "Apple's `container` tool — one Virtualization.framework Linux VM \
               per container; needs `container system` running",
    },
    BoundaryCapability {
        kind: IsolationKind::HyperV,
        host: "windows x86-64",
        engines: &["docker"],
        status: "adopted-conditional",
        note: "a Hyper-V isolated Windows container — needs OSType=windows plus \
               vmcompute/hns; the image's OS build must not exceed the host's",
    },
    BoundaryCapability {
        kind: IsolationKind::WindowsSandbox,
        host: "windows x86-64",
        engines: &["wsb"],
        status: "adopted-conditional",
        note: "the Store `wsb` CLI behind the relay — one disposable VM per `run` \
               launch (never `run-image`)",
    },
];

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

/// The catalog row with `id`, when one exists.
pub fn mechanism(id: &str) -> Option<&'static MechanismCapability> {
    MECHANISMS.iter().find(|m| m.id == id)
}

/// The mechanism a recorded [`ExecutionTarget`] implies.
///
/// Only a *native* substrate has a mechanism on this host — for
/// container/VM targets the enforcement lives inside the guest and the
/// guest's own report names it (`None` here, never an inference). On a
/// native Windows target the effective `--windows-mechanism` picks the
/// row.
pub fn mechanism_for(target: &ExecutionTarget) -> Option<&'static MechanismCapability> {
    if target.substrate != ExecutionSubstrate::Native {
        return None;
    }
    Some(match target.workload_os {
        TargetOs::Linux => &LINUX_NATIVE,
        TargetOs::MacOs => &MACOS_SBPL,
        TargetOs::Windows => match target.effective_windows_mechanism() {
            Some(WindowsNativeMechanism::Psec) => &WINDOWS_PSEC,
            _ => &WINDOWS_APPCONTAINER,
        },
        TargetOs::Other(_) => &GENERIC_NONE,
    })
}

// ---------------------------------------------------------------------------
// Matrix serialization
// ---------------------------------------------------------------------------

struct JsonNull;

impl nojson::DisplayJson for JsonNull {
    fn fmt(&self, f: &mut nojson::JsonFormatter<'_, '_>) -> std::fmt::Result {
        write!(f.inner_mut(), "null")
    }
}

fn write_requirement(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    r: &Requirement,
) -> std::fmt::Result {
    f.member("id", r.id)?;
    f.member("detail", r.detail)
}

fn write_layer(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    l: &LayerCapability,
) -> std::fmt::Result {
    f.member("layer", l.layer)?;
    match l.os {
        Some(os) => f.member("os", os)?,
        None => f.member("os", JsonNull)?,
    }
    f.member(
        "granularity",
        nojson::array(|a| {
            for g in l.granularity {
                a.element(*g)?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "transports",
        nojson::array(|a| {
            for t in l.transports {
                a.element(*t)?;
            }
            Ok(())
        }),
    )?;
    f.member("note", l.note)
}

fn write_mechanism(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    m: &MechanismCapability,
) -> std::fmt::Result {
    f.member("id", m.id)?;
    f.member("os", m.os)?;
    f.member("selected_by", m.selected_by)?;
    f.member("status", m.status)?;
    f.member("auto_candidate", m.auto_candidate)?;
    f.member(
        "controls",
        nojson::array(|a| {
            for c in m.controls {
                a.element(*c)?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "layers",
        nojson::array(|a| {
            for l in &m.layers {
                a.element(nojson::object(|lo| write_layer(lo, l)))?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "transports",
        nojson::array(|a| {
            for t in m.transports {
                a.element(*t)?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "requires",
        nojson::array(|a| {
            for r in m.requires {
                a.element(nojson::object(|ro| write_requirement(ro, r)))?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "optional",
        nojson::array(|a| {
            for r in m.optional {
                a.element(nojson::object(|ro| write_requirement(ro, r)))?;
            }
            Ok(())
        }),
    )?;
    f.member(
        "deficiencies",
        nojson::array(|a| {
            for d in m.deficiencies {
                a.element(*d)?;
            }
            Ok(())
        }),
    )?;
    f.member("select", m.select)?;
    f.member(
        "refuse",
        nojson::array(|a| {
            for r in m.refuse {
                a.element(*r)?;
            }
            Ok(())
        }),
    )
}

fn write_boundary(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    b: &BoundaryCapability,
) -> std::fmt::Result {
    f.member("id", b.kind.name())?;
    f.member("substrate", b.kind.substrate().name())?;
    f.member("unit", b.kind.unit().name())?;
    f.member("guest_os", b.kind.guest_os().name())?;
    f.member("host", b.host)?;
    f.member(
        "engines",
        nojson::array(|a| {
            for e in b.engines {
                a.element(*e)?;
            }
            Ok(())
        }),
    )?;
    f.member("status", b.status)?;
    f.member("note", b.note)
}

fn write_common_control(
    f: &mut nojson::JsonObjectFormatter<'_, '_, '_>,
    c: &CommonControl,
) -> std::fmt::Result {
    f.member("id", c.id)?;
    f.member("layer", c.layer)?;
    f.member("mechanism", c.mechanism)?;
    f.member("note", c.note)
}

/// Serialize the catalog as the versioned matrix document — the output
/// `mcp-writ capability-matrix` prints and `docs/capability-matrix.json`
/// commits. Pure function of the catalog: no host probing, so the
/// document describes the product, never this machine.
pub fn capability_matrix_json() -> String {
    nojson::object(|o| -> std::fmt::Result {
        o.member("schema_version", CAPABILITY_MATRIX_SCHEMA_VERSION)?;
        o.member("component", "mcp-writ")?;
        o.member("generated_from", "enforcement-model")?;
        o.member(
            "positioning",
            nojson::object(|p| -> std::fmt::Result {
                p.member(
                    "native_warden",
                    "linux-first — Landlock+seccomp+no_new_privs on Linux; \
                     sandbox-exec (a deprecated, legacy mechanism) on macOS; \
                     AppContainer or the conditional PSEC on Windows",
                )?;
                p.member(
                    "stronger_boundaries",
                    "for workloads that need a container or VM boundary rather \
                     than a native-process sandbox, use --isolation (kata, \
                     apple-container, hyperv, windows-sandbox) or an OCI \
                     container (--engine docker|podman|wslc)",
                )?;
                p.member(
                    "honesty",
                    "an unsupported combination refuses or reports null — the \
                     matrix never infers enforcement from a different path, \
                     and `verified environment` bounds evidence scope, not \
                     general support",
                )
            }),
        )?;
        o.member(
            "common_controls",
            nojson::array(|a| {
                for c in COMMON_CONTROLS {
                    a.element(nojson::object(|co| write_common_control(co, c)))?;
                }
                Ok(())
            }),
        )?;
        o.member(
            "mechanisms",
            nojson::array(|a| {
                for m in MECHANISMS {
                    a.element(nojson::object(|mo| write_mechanism(mo, m)))?;
                }
                Ok(())
            }),
        )?;
        o.member(
            "boundaries",
            nojson::array(|a| {
                for b in BOUNDARIES {
                    a.element(nojson::object(|bo| write_boundary(bo, b)))?;
                }
                Ok(())
            }),
        )
    })
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_ids_are_unique_and_layers_named() {
        let mut ids = std::collections::HashSet::new();
        for m in MECHANISMS {
            assert!(ids.insert(m.id), "duplicate mechanism id {}", m.id);
            assert_eq!(m.layers[0].layer, "name");
            assert_eq!(m.layers[1].layer, "ip");
            for c in m.controls {
                assert!(c.starts_with("os."), "{} not an os.* id", c);
            }
            for r in m.requires.iter().chain(m.optional.iter()) {
                assert!(!r.id.is_empty());
                assert!(!r.detail.is_empty());
            }
        }
    }

    #[test]
    fn every_isolation_kind_has_a_boundary_row() {
        for kind in [
            IsolationKind::Container,
            IsolationKind::Kata,
            IsolationKind::AppleContainer,
            IsolationKind::HyperV,
            IsolationKind::WindowsSandbox,
        ] {
            assert!(
                BOUNDARIES.iter().any(|b| b.kind == kind),
                "no boundary row for {}",
                kind.name()
            );
        }
    }

    #[test]
    fn matrix_json_parses() {
        let body = capability_matrix_json();
        let leaked: &'static str = Box::leak(body.clone().into_boxed_str());
        nojson::RawJson::parse(leaked).expect("matrix must be valid JSON");
    }
}
