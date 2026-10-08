pub mod deputy;
pub(crate) mod host;
pub mod kdl_canon;
mod kdl_emit;
mod kdl_inherit;
pub mod kdl_loader;
mod kdl_parse;
pub mod loader;
pub mod mcp;
pub mod merge;
pub mod validator;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub version: u32,
    pub transport: TransportConfig,
    pub tools: Vec<ToolPolicy>,
    pub fs: FsPolicy,
    pub syscalls: SyscallPolicy,
    pub network: NetworkPolicy,
    /// Environment the spawned server child receives (`defaults.environment`).
    /// `restrict == false` keeps the default full parent-env inheritance.
    pub environment: EnvironmentPolicy,
    pub logging: LoggingPolicy,
    pub sandbox: SandboxPolicy,
    pub confused_deputy_protection: bool,
    /// Opt-in process-local trajectory rules. Default off (omitted = current behavior).
    pub trajectory: bool,
    /// Ordered `after` children of `trajectory`. Property order is not significant.
    pub trajectory_rules: Vec<TrajectoryRule>,
    pub hash_entries: Vec<HashEntry>,
    pub tools_list_hashes: Vec<ToolsListHashEntry>,
    /// `mcp` passage rules per server (KDL schema v2 only). Independent
    /// of tool allow/deny: these rules govern MCP method passage, not
    /// tool execution.
    pub mcp_rules: Vec<mcp::ServerMcpRules>,
}

/// One deterministic cross-tool trajectory rule (`after` child of `trajectory`).
///
/// Properties are name-keyed (`side_effect`, `deny-next`). Child node order is
/// significant; property appearance order is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrajectoryRule {
    pub after_side_effect: SideEffect,
    pub deny_next: SideEffect,
}

/// OS-sandbox degradation policy. Default is fail-closed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxPolicy {
    /// When true, Landlock NotEnforced/Partial states are allowed. Default false.
    pub allow_degraded: bool,
}

/// Child-process environment policy (`defaults { environment { ... } }`).
///
/// Default (`restrict: false`, empty `allowed`) inherits the parent
/// environment unchanged at spawn. When `restrict` is true — i.e. the
/// `environment` node was declared — the child receives only the launch
/// contract's base set (`PATH`, the Windows system roots plus
/// `LOCALAPPDATA` — required for AppContainer spawns — and the
/// `TMPDIR`/`TMP`/`TEMP` override when one is configured) plus each
/// `allowed` name that exists in the parent environment; a listed name
/// missing from the parent stays unset.
///
/// This is a launch contract, not OS sandboxing: it applies in dry-run and
/// `MCP_WRIT_SKIP_SANDBOX` modes as well.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvironmentPolicy {
    /// `defaults { environment { ... } }` was declared: restrict the child's
    /// environment to the base set plus `allowed` names.
    pub restrict: bool,
    /// Parent-environment variable names copied to the child when present.
    pub allowed: Vec<String>,
    /// An `environment` node was declared — under `defaults` or inside a
    /// matching `when` block — making `allowed` authoritative even when
    /// empty. Without this marker an include/extends merge cannot tell
    /// "declared empty" apart from "never declared" and would inherit the
    /// other side's allow list instead of replacing it.
    pub declared: bool,
}

/// Type of hash entry in the KDL policy for supply chain verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    /// Native binary hash (ELF/Mach-O)
    Binary,
    /// Lock file hash (package-lock.json, requirements.txt, etc.)
    Lockfile,
    /// Entry point hash (index.js, main.py, etc.)
    Entrypoint,
    /// Docker image manifest digest
    DockerManifest,
}

impl HashType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binary => "binary-hash",
            Self::Lockfile => "lockfile-hash",
            Self::Entrypoint => "entrypoint-hash",
            Self::DockerManifest => "docker-manifest-hash",
        }
    }
}

/// A hash entry parsed from a KDL policy `server` block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashEntry {
    pub server_name: String,
    pub hash_type: HashType,
    pub hash_value: String,
    pub target: String,
    pub approved: Option<String>,
}

/// A tools-list-hash entry parsed from a KDL policy `server` block.
/// Used for supply chain verification of MCP server tool definitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolsListHashEntry {
    pub server_name: String,
    pub hash_value: String,
    pub approved: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportConfig {
    pub type_: TransportType,
    pub listen_addr: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportType {
    Stdio,
    Http,
}

/// Error type for parsing [`TransportType`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportParseError {
    pub input: String,
}

impl std::fmt::Display for TransportParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unknown transport type '{}', expected 'stdio' or 'http'",
            self.input
        )
    }
}

impl std::error::Error for TransportParseError {}

impl std::str::FromStr for TransportType {
    type Err = TransportParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "stdio" => Ok(Self::Stdio),
            "http" => Ok(Self::Http),
            _ => Err(TransportParseError {
                input: s.to_string(),
            }),
        }
    }
}

impl TransportType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Stdio => "stdio",
            Self::Http => "http",
        }
    }
}

/// How the Auditor treats MCP MRTR `params.inputResponses` on `tools/call`.
///
/// `inputResponses` is a sibling of `params.arguments` and is therefore **not**
/// covered by `args_schema`. Elicitation content (secrets, “user confirmed
/// delete”, extra paths) would otherwise bypass the same security intent.
///
/// Secure default (`Auto`):
/// - `args_schema` is set → treat as [`InputResponsesMode::Deny`]
/// - no schema → treat as [`InputResponsesMode::Allow`] (nothing to bypass)
///
/// Spec: <https://modelcontextprotocol.io/specification/2026-07-28/basic/patterns/mrtr>
/// and <https://modelcontextprotocol.io/specification/2026-07-28/server/tools>
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InputResponsesMode {
    /// Implicit secure default (see type docs).
    #[default]
    Auto,
    /// Reject the `tools/call` if `inputResponses` is present.
    Deny,
    /// Pass `inputResponses` through without schema inspection.
    Allow,
    /// Pass through, but record presence in the audit log.
    Inspect,
}

impl InputResponsesMode {
    /// Parse a KDL `input_responses` property value.
    pub fn parse_kdl(value: &str) -> Result<Self, String> {
        match value {
            "auto" => Ok(Self::Auto),
            "deny" => Ok(Self::Deny),
            "allow" => Ok(Self::Allow),
            "inspect" => Ok(Self::Inspect),
            other => Err(format!(
                "invalid input_responses '{other}', expected auto|deny|allow|inspect"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Deny => "deny",
            Self::Allow => "allow",
            Self::Inspect => "inspect",
        }
    }

    /// Resolve `Auto` using whether any security-sensitive tool contract exists.
    ///
    /// `args_schema`, filesystem, network, syscall, or side-effect contracts all
    /// mean `inputResponses` could bypass the same intent.
    pub fn resolve(self, has_security_contract: bool) -> ResolvedInputResponses {
        match self {
            Self::Auto => {
                if has_security_contract {
                    ResolvedInputResponses::Deny
                } else {
                    ResolvedInputResponses::Allow
                }
            }
            Self::Deny => ResolvedInputResponses::Deny,
            Self::Allow => ResolvedInputResponses::Allow,
            Self::Inspect => ResolvedInputResponses::Inspect,
        }
    }
}

/// Effective `inputResponses` decision after resolving [`InputResponsesMode::Auto`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedInputResponses {
    Deny,
    Allow,
    Inspect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolPolicy {
    pub name: String,
    pub allowed: bool,
    pub args_schema: Option<String>,
    pub side_effect: Option<String>,
    pub server: Option<String>,
    pub fs: Option<FsToolPolicy>,
    pub syscalls: Option<ToolSyscallPolicy>,
    pub network: Option<ToolNetworkPolicy>,
    pub input_responses: InputResponsesMode,
    /// True when `input_responses` was written in source (including explicit `auto`).
    pub input_responses_specified: bool,
    /// True when this tool declared its own `filesystem` block.
    pub fs_explicit: bool,
    /// True when this tool declared its own `network` block.
    pub network_explicit: bool,
    /// True when this tool declared its own `syscalls` block.
    pub syscalls_explicit: bool,
    /// True when an `environment` block appeared under this tool, its
    /// profile, or its server-defaults. Per-tool environment is not
    /// enforced; the validator rejects it at load time.
    pub environment_explicit: bool,
    /// True when a `process` block grants exec (`deny-all #false` or an allow).
    pub process_exec_allowed: bool,
    /// True when this tool declared its own `process` block (including deny-all).
    pub process_explicit: bool,
    /// `deputy` block: explicit Confused Deputy role + extraction rules
    /// (KDL schema v2). `None` leaves the fixed-name compatibility
    /// mapping in effect — see `deputy::deputy_binding`.
    pub deputy: Option<deputy::DeputyPolicy>,
}

impl ToolPolicy {
    /// Construct a tool policy with optional fields unset and `input_responses = Auto`.
    pub fn named(name: impl Into<String>, allowed: bool) -> Self {
        Self {
            name: name.into(),
            allowed,
            args_schema: None,
            side_effect: None,
            server: None,
            fs: None,
            syscalls: None,
            network: None,
            input_responses: InputResponsesMode::Auto,
            input_responses_specified: false,
            fs_explicit: false,
            network_explicit: false,
            syscalls_explicit: false,
            environment_explicit: false,
            process_exec_allowed: false,
            process_explicit: false,
            deputy: None,
        }
    }

    /// True when this tool has a contract that `inputResponses` could bypass.
    pub fn has_security_contract(&self) -> bool {
        self.args_schema.is_some()
            || self.side_effect.is_some()
            || self.fs.as_ref().is_some_and(|fs| {
                fs.allow_specified
                    || fs.require_path.is_some()
                    || !fs.allowed_paths.is_empty()
                    || !fs.denied_paths.is_empty()
            })
            || self.network.as_ref().is_some_and(|net| {
                net.allow_specified || !net.allowed_hosts.is_empty() || !net.denied_hosts.is_empty()
            })
            || self
                .syscalls
                .as_ref()
                .is_some_and(|sc| !sc.allowed.is_empty() || !sc.denied.is_empty())
            // A `use`-role deputy contract vets the paths it extracts —
            // unchecked `inputResponses` would bypass exactly that.
            || self
                .deputy
                .as_ref()
                .is_some_and(|d| d.role == deputy::DeputyRole::Use)
    }

    /// Effective `input_responses` mode after treating unspecified as Auto.
    pub fn input_responses_mode(&self) -> InputResponsesMode {
        self.input_responses
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolSyscallPolicy {
    pub allowed: Vec<String>,
    pub denied: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolNetworkPolicy {
    /// Name-layer allow rules (`allow host=`).
    pub allowed_hosts: Vec<String>,
    /// IP-layer allow rules (`allow cidr=`) — canonical `addr/prefix`.
    pub allowed_cidrs: Vec<String>,
    /// Deny rules evaluated at both layers — an IP literal here is an
    /// IP-layer deny as well as a name-layer deny.
    pub denied_hosts: Vec<String>,
    /// IP-layer deny rules (`deny cidr=`) — canonical `addr/prefix`.
    pub denied_cidrs: Vec<String>,
    pub allow_specified: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FsToolPolicy {
    pub allowed_paths: Vec<String>,
    pub read_only_paths: Vec<String>,
    pub read_write_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub allow_specified: bool,
    /// Tool/profile-only opt-in. None preserves the mandatory-path default.
    /// False is valid only with an explicitly empty filesystem allow-list.
    pub require_path: Option<bool>,
}

impl FsToolPolicy {
    pub fn new(allowed_paths: Vec<String>, denied_paths: Vec<String>) -> Self {
        let allow_specified = !allowed_paths.is_empty();
        Self {
            allowed_paths: allowed_paths.clone(),
            read_only_paths: allowed_paths,
            read_write_paths: Vec::new(),
            denied_paths,
            allow_specified,
            require_path: None,
        }
    }

    /// No target is needed only when the policy explicitly forbids every path.
    /// Keep this guard in the checker as well as load-time validation.
    pub fn allows_pathless_call(&self) -> bool {
        self.require_path == Some(false)
            && self.allow_specified
            && self.allowed_paths.is_empty()
            && self.read_only_paths.is_empty()
            && self.read_write_paths.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsPolicy {
    pub read_only: Vec<String>,
    pub read_write: Vec<String>,
    pub denied_paths: Vec<String>,
    /// True when a layer specified at least one global allow rule.
    pub allow_specified: bool,
    /// Default-on overlay: well-known secret paths are denied even when an
    /// explicit allow glob would match. KDL `secret-overlay #false` disables.
    pub secret_overlay: bool,
}

impl Default for FsPolicy {
    fn default() -> Self {
        Self {
            read_only: Vec::new(),
            read_write: Vec::new(),
            denied_paths: Vec::new(),
            allow_specified: false,
            secret_overlay: true,
        }
    }
}

/// Documented `side_effect` values. Unknown strings are a load error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SideEffect {
    ReadOnly,
    Write,
    Network,
    Execute,
}

impl SideEffect {
    /// Parse a KDL `side_effect` property. Unknown values fail closed.
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "read_only" => Ok(Self::ReadOnly),
            "write" => Ok(Self::Write),
            "network" => Ok(Self::Network),
            "execute" => Ok(Self::Execute),
            other => Err(format!(
                "unknown side_effect '{other}', expected read_only|write|network|execute"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Write => "write",
            Self::Network => "network",
            Self::Execute => "execute",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyscallPolicy {
    pub allowed: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPolicy {
    pub outbound: OutboundPolicy,
    pub inbound: InboundPolicy,
}

/// Separate listen/bind authorization from outbound client access.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundPolicy {
    /// When true, the OS sandbox may grant listener/server capabilities.
    pub allow_listen: bool,
}

/// Outbound rules are evaluated at two layers:
///
/// - **Name layer** — `host=` entries (FQDNs, wildcards, URL spellings).
///   Evaluated by the Auditor's argument checks and, on paths that
///   provide one, a DNS-gateway name policy.
/// - **IP layer** — `cidr=` entries (static `addr/prefix` rules), plus
///   every `host=` entry that is an IP literal: a literal needs no
///   resolution, so `allow host="192.0.2.1"` is a static IP-layer rule
///   (`/32` or `/128`) too. The same holds on the deny side — an IP
///   literal in `denied_hosts` is an IP-layer deny.
///
/// [`Self::ip_layer_allows`] / [`Self::ip_layer_denies`] project the
/// effective rule set for the IP layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundPolicy {
    /// Name-layer allow rules (`allow host=`), normalized.
    pub allowed: Vec<String>,
    /// Source spellings of `allowed` entries that carried an explicit
    /// port qualifier (`host:port`, `[v6]:port`, or a URL authority
    /// port). Normalization folds the port away — the auditor's
    /// identity is the host — but the spelling is retained so a
    /// mechanism emitting real destination rules (PSEC) refuses the
    /// qualifier it cannot express instead of silently widening the
    /// entry to every port. Empty for programmatically built policies.
    pub allowed_port_qualified: Vec<String>,
    /// IP-layer allow rules (`allow cidr=`) — canonical `addr/prefix`
    /// with host bits masked.
    pub allowed_cidrs: Vec<String>,
    /// Source spellings of `allowed_cidrs` entries that carried a port
    /// qualifier — same refusal contract as `allowed_port_qualified`.
    pub allowed_cidrs_port_qualified: Vec<String>,
    /// Deny rules evaluated at both layers (`deny host=`); IP literals
    /// here are IP-layer denies.
    pub denied_hosts: Vec<String>,
    /// IP-layer deny rules (`deny cidr=`) — canonical `addr/prefix`.
    pub denied_cidrs: Vec<String>,
    pub deny_all_others: bool,
}

impl Default for OutboundPolicy {
    fn default() -> Self {
        Self {
            allowed: Vec::new(),
            allowed_port_qualified: Vec::new(),
            allowed_cidrs: Vec::new(),
            allowed_cidrs_port_qualified: Vec::new(),
            denied_hosts: Vec::new(),
            denied_cidrs: Vec::new(),
            deny_all_others: true,
        }
    }
}

impl OutboundPolicy {
    /// The effective IP-layer allow set in canonical `addr/prefix`
    /// form: declared `allowed_cidrs` plus a host route (`/32` or
    /// `/128`) for every `allowed` entry that is an IP literal —
    /// `allow host=` on a literal needs no resolution, so it is a
    /// static IP-layer rule as well.
    ///
    /// Entries covered by an IP-layer deny rule
    /// ([`Self::ip_layer_denies`]) are not returned: deny wins over
    /// allow at every evaluation point.
    pub fn ip_layer_allows(&self) -> Vec<String> {
        let denies = self.ip_layer_denies();
        let mut out: Vec<String> = Vec::new();
        for cidr in self
            .allowed_cidrs
            .iter()
            .cloned()
            .chain(self.allowed.iter().filter_map(|h| {
                h.parse::<std::net::IpAddr>()
                    .ok()
                    .map(host::ip_literal_cidr)
            }))
        {
            if !out.contains(&cidr) && !denies.iter().any(|d| host::cidr_covers(d, &cidr)) {
                out.push(cidr);
            }
        }
        out
    }

    /// The effective IP-layer deny set in canonical `addr/prefix` form:
    /// declared `denied_cidrs` plus a host route for every IP literal
    /// in `denied_hosts` — `denied_hosts` evaluates at both layers.
    /// A `*` in `denied_hosts` is the deny-all posture and is not an
    /// IP-layer entry.
    pub fn ip_layer_denies(&self) -> Vec<String> {
        let mut out: Vec<String> = self.denied_cidrs.clone();
        for h in &self.denied_hosts {
            if let Ok(addr) = h.parse::<std::net::IpAddr>() {
                let cidr = host::ip_literal_cidr(addr);
                if !out.contains(&cidr) {
                    out.push(cidr);
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggingPolicy {
    pub level: String,
    /// When true (default), audit channel/write failures fail closed.
    pub fail_closed: bool,
}

impl Default for LoggingPolicy {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            fail_closed: true,
        }
    }
}

/// Remove allowed destinations that are covered by a deny rule.
///
/// `denied_hosts` prunes `allowed` (name layer); the IP-layer deny set
/// — `denied_cidrs` plus IP literals in `denied_hosts` — prunes
/// `allowed_cidrs` entries the deny range covers entirely. A denied
/// rule that only *partially* overlaps an allowed range does not
/// prune: deny-vs-allow is evaluated per destination at check time,
/// and the overlap stays visible to mechanisms that must refuse
/// carve-outs they cannot express (PSEC).
pub fn apply_outbound_deny_precedence(outbound: &mut OutboundPolicy) {
    outbound.allowed.retain(|allowed| {
        !outbound
            .denied_hosts
            .iter()
            .any(|denied| host_covered_by_deny(allowed, denied))
    });
    // Port-qualifier provenance tracks `allowed` membership — a
    // spelling whose folded host a deny rule covered must not still
    // refuse as port-qualified.
    outbound.allowed_port_qualified.retain(|raw| {
        outbound
            .allowed
            .contains(&crate::policy::host::normalize_policy_host(raw))
    });
    // IP layer: an `allow cidr` inside a denied range can never pass.
    // A programmatic `denied_hosts` `*` is the deny-all posture and
    // clears the IP layer the same way it clears `allowed`.
    let deny_all_ip = outbound.denied_hosts.iter().any(|d| d == "*");
    let denied_ip = outbound.ip_layer_denies();
    outbound
        .allowed_cidrs
        .retain(|cidr| !deny_all_ip && !denied_ip.iter().any(|d| host::cidr_covers(d, cidr)));
    outbound.allowed_cidrs_port_qualified.retain(|raw| {
        host::analyze_policy_cidr(raw)
            .map(|(cidr, _)| outbound.allowed_cidrs.contains(&cidr))
            .unwrap_or(false)
    });
}

/// Apply the same wildcard-aware deny reducer to a per-tool network policy.
pub fn apply_tool_network_deny_precedence(network: &mut ToolNetworkPolicy) {
    let denied_hosts = network.denied_hosts.clone();
    network.allowed_hosts.retain(|allowed| {
        !denied_hosts
            .iter()
            .any(|denied| host_covered_by_deny(allowed, denied))
    });
    // One layer down: a denied CIDR (or an IP literal in
    // `denied_hosts`, which is a `/32`/`/128` IP-layer deny) covers an
    // allowed CIDR the allow sits entirely inside.
    let denied_ip: Vec<String> = network
        .denied_cidrs
        .iter()
        .cloned()
        .chain(network.denied_hosts.iter().filter_map(|h| {
            h.parse::<std::net::IpAddr>()
                .ok()
                .map(host::ip_literal_cidr)
        }))
        .collect();
    let deny_all_ip = network.denied_hosts.iter().any(|d| d == "*");
    network
        .allowed_cidrs
        .retain(|cidr| !deny_all_ip && !denied_ip.iter().any(|d| host::cidr_covers(d, cidr)));
}

pub fn host_covered_by_deny(allowed: &str, denied: &str) -> bool {
    let a = canonicalize_policy_host(allowed);
    let d = canonicalize_policy_host(denied);
    if d == "*" || a == d {
        return true;
    }
    if let Some(suffix) = d.strip_prefix("*.") {
        let with_dot = format!(".{suffix}");
        return a == suffix || a.ends_with(&with_dot);
    }
    false
}

/// Lowercase, strip a trailing DNS root dot, and fold every equivalent
/// spelling of the same network address into one canonical form —
/// WHATWG IPv4 numbers (`127.1`, `0x7f.1`, `2130706433`), IPv6 literals
/// (expanded, uppercase, `::ffff:`-mapped), IDN domain names (Unicode
/// and `xn--` spellings of the same name), and ASCII DNS names — so a
/// denylist entry cannot be evaded by a non-canonical spelling.
///
/// Hosts the URL grammar cannot represent keep their trimmed lowercase
/// form: they can never equal a parsed host and so stay unmatchable
/// rather than accidentally permissive. The same holds for an invalid
/// IDN — UTS-46 rejects it and the unmatchable fallback stands.
pub fn canonicalize_policy_host(host: &str) -> String {
    let trimmed = host.trim().trim_end_matches('.');
    // A wildcard covers the canonical form of its suffix, so normalize
    // the suffix the same way and re-pin the marker.
    if let Some(suffix) = trimmed.strip_prefix("*.") {
        return format!("*.{}", canonicalize_policy_host(suffix));
    }
    if !trimmed.is_ascii() {
        // Unicode domain names canonicalize to their IDNA (Punycode)
        // spelling — the form a parsed URL host already carries — so a
        // denylist entry in either spelling matches the same wire host.
        // UTS-46 also maps full-width spellings to ASCII (`１２７.１` →
        // `127.1`), so the result re-enters the URL host grammar to fold
        // WHATWG IPv4/IPv6 forms rather than surviving as an unmatched
        // ASCII string. An invalid IDN keeps the lowercase fallback —
        // never equal to a parsed host.
        return match idna::domain_to_ascii(trimmed) {
            Ok(ascii) => host::canonicalize_url_host(ascii.trim_end_matches('.'))
                .unwrap_or_else(|| ascii.to_ascii_lowercase()),
            Err(_) => trimmed.to_ascii_lowercase(),
        };
    }
    host::canonicalize_url_host(trimmed).unwrap_or_else(|| trimmed.to_ascii_lowercase())
}

/// Map a policy `logging.level` value to a tracing level.
///
/// Unknown values fall back to `info`. `warning` is accepted as an alias of `warn`.
pub fn tracing_level_from_policy(level: &str) -> tracing::Level {
    match level.to_ascii_lowercase().as_str() {
        "error" => tracing::Level::ERROR,
        "warn" | "warning" => tracing::Level::WARN,
        "debug" => tracing::Level::DEBUG,
        "trace" => tracing::Level::TRACE,
        _ => tracing::Level::INFO,
    }
}

/// Supported `policy version=` range. v1 keeps the legacy open `tool`
/// shape and the default passage profile; v2 adds the closed `tool`
/// shape and `server` `mcp` passage rules (MRTR additional requests are
/// denied without an explicit rule either way).
const MIN_SUPPORTED_VERSION: u32 = 1;
const MAX_SUPPORTED_VERSION: u32 = 2;

impl Default for Policy {
    fn default() -> Self {
        default_policy()
    }
}

impl Policy {
    /// Validate for the OS this process runs on (native compatibility).
    /// Use [`Policy::validate_for_target`] when the workload runs under a
    /// different OS (e.g. a container guest).
    pub fn validate(&self) -> Result<(), crate::error::PolicyError> {
        validator::validate_policy(self)
    }

    /// Validate against an explicit execution target — the workload's OS
    /// decides representability, not the build host.
    pub fn validate_for_target(
        &self,
        target: &crate::execution::ExecutionTarget,
    ) -> Result<(), crate::error::PolicyError> {
        validator::validate_policy_for_target(self, target)
    }

    /// Return a copy of the policy with all `@path` args_schema references loaded
    /// and replaced with inline JSON string contents, relative to `base_dir`.
    pub fn inlined_schemas(&self, base_dir: &std::path::Path) -> Result<Policy, String> {
        let mut policy = self.clone();
        for tool in &mut policy.tools {
            if let Some(ref schema_ref) = tool.args_schema
                && let Some(file_path) = schema_ref.strip_prefix('@')
            {
                let file_path = file_path.trim();
                let resolved = if std::path::Path::new(file_path).is_absolute() {
                    std::path::PathBuf::from(file_path)
                } else {
                    base_dir.join(file_path)
                };
                let content = std::fs::read_to_string(&resolved).map_err(|e| {
                    format!("failed to read schema file '{}': {e}", resolved.display())
                })?;
                tool.args_schema = Some(content);
            }
        }
        Ok(policy)
    }

    /// Unique server identities declared on tools and integrity entries.
    pub fn declared_servers(&self) -> Vec<String> {
        let mut names = std::collections::BTreeSet::new();
        for tool in &self.tools {
            if let Some(ref server) = tool.server {
                names.insert(server.clone());
            }
        }
        for entry in &self.hash_entries {
            names.insert(entry.server_name.clone());
        }
        for entry in &self.tools_list_hashes {
            names.insert(entry.server_name.clone());
        }
        for rules in &self.mcp_rules {
            if let Some(ref name) = rules.server_name {
                names.insert(name.clone());
            }
        }
        names.into_iter().collect()
    }

    /// Bind this policy to exactly one server identity.
    ///
    /// Multi-server policies require `selector`. The returned policy retains
    /// only that server's tools and integrity records so Warden/Auditor cannot
    /// borrow another server's grants.
    pub fn bind_to_server(
        &self,
        selector: Option<&str>,
    ) -> Result<Policy, crate::error::PolicyError> {
        let servers = self.declared_servers();
        let selected = match (servers.as_slice(), selector) {
            ([], None) => return Ok(self.clone()),
            ([], Some(name)) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "unknown server '{name}'; policy declares no server identities"
                )));
            }
            ([only], None) => only.clone(),
            ([only], Some(name)) if name == only => only.clone(),
            ([only], Some(name)) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "unknown server '{name}'; policy declares '{only}'"
                )));
            }
            (_, None) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "policy declares multiple servers ({}); pass --server <name>",
                    servers.join(", ")
                )));
            }
            (_, Some(name)) if servers.iter().any(|s| s == name) => name.to_string(),
            (_, Some(name)) => {
                return Err(crate::error::PolicyError::Validation(format!(
                    "unknown server '{name}'; declared servers: {}",
                    servers.join(", ")
                )));
            }
        };

        let mut bound = self.clone();
        let unnamed_tools = self.tools.iter().any(|t| t.server.is_none());
        let unnamed_mcp = self.mcp_rules.iter().any(|r| r.server_name.is_none());
        if (unnamed_tools || unnamed_mcp) && !servers.is_empty() {
            return Err(crate::error::PolicyError::Validation(
                "policy mixes named server blocks with a nameless server block that declares rules"
                    .to_string(),
            ));
        }
        bound
            .tools
            .retain(|t| t.server.as_deref() == Some(selected.as_str()));
        bound.hash_entries.retain(|e| e.server_name == selected);
        bound
            .tools_list_hashes
            .retain(|e| e.server_name == selected);
        bound
            .mcp_rules
            .retain(|r| r.server_name.as_deref() == Some(selected.as_str()));
        Ok(bound)
    }

    /// Serialize the effective policy into a self-contained KDL string.
    ///
    /// The resulting KDL has all inheritance (extends), includes, profiles,
    /// and server-defaults already merged into concrete rules, suitable for
    /// embedding into container images or environments without external files.
    pub fn to_kdl(&self) -> String {
        kdl_emit::to_kdl(self)
    }

    /// `sha256:<hex>` of this policy's canonical effective KDL — the value
    /// that ties an audit event or launch report to the exact ruleset that
    /// was enforced.
    pub fn effective_hash(&self) -> Result<String, crate::error::PolicyError> {
        kdl_canon::hash_canonical_kdl(&self.to_kdl())
    }

    /// Identity stamped on audit events and the launch report: the bound
    /// server name (or `default` for a server-less policy), the declared
    /// `policy version`, and [`Policy::effective_hash`].
    pub fn audit_context(
        &self,
    ) -> Result<crate::audit_log::PolicyAuditContext, crate::error::PolicyError> {
        Ok(crate::audit_log::PolicyAuditContext {
            id: self
                .declared_servers()
                .first()
                .cloned()
                .unwrap_or_else(|| "default".to_string()),
            version: self.version.to_string(),
            hash: self.effective_hash()?,
        })
    }

    /// Serialize like [`Policy::to_kdl`] and prove the result round-trips:
    /// the emitted KDL is re-parsed, re-validated for `target`'s workload
    /// OS, and compared semantically against `self` so no control node is
    /// dropped silently on export.
    ///
    /// Fails closed: a policy whose effective state cannot be represented in
    /// the self-contained format is an error, not a lossy export.
    pub(crate) fn to_kdl_verified(
        &self,
        target: &crate::execution::ExecutionTarget,
    ) -> Result<String, crate::error::PolicyError> {
        let kdl = self.to_kdl();
        let reparsed = kdl_loader::parse_kdl_policy(&kdl).map_err(|e| {
            crate::error::PolicyError::Validation(format!(
                "self-contained KDL export does not re-parse: {e}"
            ))
        })?;
        validator::validate_policy_for_target(&reparsed, target).map_err(|e| {
            crate::error::PolicyError::Validation(format!(
                "self-contained KDL export fails validation for target '{}': {e}",
                target.workload_os.name()
            ))
        })?;
        if !kdl_emit::policies_equivalent_for_export(self, &reparsed) {
            return Err(crate::error::PolicyError::Validation(
                "self-contained KDL export does not reproduce the effective policy".to_string(),
            ));
        }
        Ok(kdl)
    }
}

pub fn default_policy() -> Policy {
    Policy {
        version: 1,
        transport: TransportConfig {
            type_: TransportType::Stdio,
            listen_addr: None,
        },
        tools: Vec::new(),
        fs: FsPolicy {
            read_only: Vec::new(),
            read_write: Vec::new(),
            denied_paths: Vec::new(),
            allow_specified: false,
            secret_overlay: true,
        },
        syscalls: SyscallPolicy {
            allowed: Vec::new(),
        },
        network: NetworkPolicy {
            outbound: OutboundPolicy::default(),
            inbound: InboundPolicy::default(),
        },
        environment: EnvironmentPolicy::default(),
        logging: LoggingPolicy::default(),
        sandbox: SandboxPolicy::default(),
        confused_deputy_protection: false,
        trajectory: false,
        trajectory_rules: Vec::new(),
        hash_entries: Vec::new(),
        tools_list_hashes: Vec::new(),
        mcp_rules: Vec::new(),
    }
}

#[cfg(test)]
mod tests;
