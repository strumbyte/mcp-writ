use std::path::PathBuf;

use crate::container::engine::EngineKind;
use crate::container::options::{ContainerizeOptions, RunImageOptions, WrapOptions};
use crate::error::CliError;
use crate::execution::IsolationKind;
use crate::verifier::fail_on::FailOn;

mod parse_check;
mod parse_containerize;
mod parse_dns_gate;
mod parse_ebpf;
mod parse_gen_policy;
mod parse_inspect;
mod parse_macos_proxy;
mod parse_namespaced;
mod parse_plan;
mod parse_policy;
mod parse_run;
mod parse_run_image;
mod parse_unotify;
mod parse_wrap_image;

#[cfg(test)]
mod tests_parse;

/// Result of parsing CLI arguments.
#[derive(Debug)]
pub enum CliOutput {
    /// The `run` subcommand with its parsed arguments.
    Run(RunArgs),
    /// The `inspect` subcommand with its parsed arguments.
    Inspect(InspectArgs),
    /// The `generate-policy` subcommand with its parsed arguments.
    GeneratePolicy(GenPolicyArgs),
    /// The `plan` subcommand with its parsed arguments.
    Plan(PlanArgs),
    /// The `run-image` subcommand with its parsed arguments.
    RunImage(RunImageArgs),
    /// The `wrap-image` subcommand with its parsed arguments.
    WrapImage(WrapImageArgs),
    /// The `containerize` subcommand with its parsed arguments.
    Containerize(ContainerizeArgs),
    /// The `dns-gate` subcommand with its parsed arguments.
    DnsGate(DnsGateArgs),
    /// The `unotify-run` subcommand with its parsed arguments.
    UnotifyRun(UnotifyArgs),
    /// The `namespaced-run` subcommand with its parsed arguments.
    NamespacedRun(NamespacedArgs),
    /// The `ebpf-run` subcommand with its parsed arguments.
    EbpfRun(EbpfArgs),
    /// The `macos-proxy-run` subcommand with its parsed arguments.
    MacosProxyRun(MacosProxyArgs),
    /// The `capability-matrix` subcommand — no arguments; prints the
    /// machine-readable per-OS capability catalog as JSON.
    CapabilityMatrix,
    /// The `check` subcommand with its parsed arguments.
    Check(CheckArgs),
    /// The `policy` subcommand (`resolve` — the composed-policy
    /// inspector, PR-24) with its parsed arguments.
    PolicyResolve(PolicyResolveArgs),
    /// Informational output (--version or --help) to be printed and exited.
    Info(String),
}

/// Parsed arguments for the `run` subcommand.
#[derive(Debug)]
pub struct RunArgs {
    pub isolation: Option<IsolationKind>,
    pub sandbox: crate::container::sandbox::SandboxOptions,
    pub transport: String,
    pub policy: Option<PathBuf>,
    pub server: Option<String>,
    pub verbose: u8,
    pub dry_run: bool,
    /// CLI `--fail-on` when present. Env is resolved later (`CLI > env > high`).
    pub fail_on_cli: Option<FailOn>,
    pub audit_log: Option<PathBuf>,
    /// `--audit-sync` — flush + fsync every audit record as it is
    /// written (a storage round-trip per record, the smallest possible
    /// force-kill loss window). Requires `--audit-log`; meaningless on
    /// the tracing sink and rejected with `--isolation windows-sandbox`
    /// (audit lives inside the sandbox state area there).
    pub audit_sync: bool,
    /// `--report <path>` — write the launch plan + observations + final
    /// result as one JSON object (never on MCP stdout).
    pub report: Option<PathBuf>,
    /// `--windows-mechanism <name>` — explicit native Windows sandbox
    /// mechanism (`appcontainer` default, `psec` conditional). `None`
    /// keeps the platform default; incompatible with `--isolation`.
    pub windows_mechanism: Option<crate::execution::WindowsNativeMechanism>,
    /// `--linux-mechanism <auto|namespaced|native>` — the Linux egress
    /// mechanism request (`None` = flag absent; the native `run` launch
    /// maps that to `auto`). Consulted only on native Linux launches;
    /// incompatible with `--isolation`.
    pub linux_mechanism: Option<crate::execution::LinuxMechanismRequest>,
    /// `--dns-upstream <ip>[:port]` — the resolver the namespaced
    /// route's embedded DNS gate forwards to. `None` falls back to the
    /// first dialable nameserver in `/etc/resolv.conf`.
    pub dns_upstream: Option<std::net::SocketAddr>,
    /// `--max-frame-bytes <n>` — JSON-RPC frame cap for the Auditor's
    /// relay. `None` resolves to [`crate::framing::DEFAULT_MAX_FRAME_BYTES`]
    /// at launch.
    pub max_frame_bytes: Option<usize>,
    pub command: Vec<String>,
}

/// Parsed arguments for the `plan` subcommand.
///
/// `plan` computes the enforcement plan and inspects launch prerequisites
/// without starting the workload, pulling an image, or mutating any
/// configuration. `invalid_input` records a parse/semantic error the
/// command reports as status `invalid` (exit 2) instead of a usage error.
#[derive(Debug, Default)]
pub struct PlanArgs {
    pub sandbox: crate::container::sandbox::SandboxOptions,
    pub policy: Option<PathBuf>,
    pub server: Option<String>,
    pub verbose: u8,
    /// Image mode: engine override (auto-detect when `None`). Only
    /// meaningful with `image`.
    pub engine: Option<EngineKind>,
    /// Image mode: the isolation method to plan for (`--isolation`,
    /// default `container`). Only meaningful with `image`.
    pub isolation: Option<IsolationKind>,
    /// Image mode: the image reference to plan a `run-image` for. Mutually
    /// exclusive with `command`.
    pub image: Option<String>,
    /// Image mode: permit a tag-only (non-digest-pinned) image reference.
    pub allow_mutable_tag: bool,
    /// Native mode: trailing `-- <command>` argv.
    pub command: Vec<String>,
    /// `--report <path>` — write the plan result JSON here instead of
    /// stdout. A write failure is the `error` status (exit 1).
    pub report: Option<PathBuf>,
    /// `--windows-mechanism <name>` — explicit native Windows sandbox
    /// mechanism (`appcontainer` default, `psec` conditional). Native
    /// mode only; a value with `--image` is recorded as `invalid_input`.
    pub windows_mechanism: Option<crate::execution::WindowsNativeMechanism>,
    /// `--linux-mechanism <auto|namespaced|native>` — the Linux egress
    /// mechanism request for a native-mode plan (`None` = `auto`). A
    /// value with `--image` is recorded as `invalid_input`.
    pub linux_mechanism: Option<crate::execution::LinuxMechanismRequest>,
    /// `--dns-upstream <ip>[:port]` — the resolver the namespaced
    /// route's embedded DNS gate would forward to; `plan` reports the
    /// resolved value the launch would use.
    pub dns_upstream: Option<std::net::SocketAddr>,
    /// A parse/semantic error captured for the machine-readable `invalid`
    /// result (e.g. `--image` combined with `-- <command>`).
    pub invalid_input: Option<String>,
}

/// Parsed arguments for the `check` subcommand.
///
/// `check` re-reads a policy's integrity pins (`binary-hash`,
/// `entrypoint-hash`, `lockfile-hash`, `docker-manifest-hash`,
/// `tools-list-hash`) and compares them against the current files,
/// image metadata, and — when `-- <command>` is given — a freshly
/// fetched `tools/list`, plus the unresolved `// REVIEW` markers left
/// by `generate-policy`. `invalid_input` records a parse/semantic
/// error the command reports as status `invalid` (exit 2) instead of a
/// usage error.
#[derive(Debug, Default)]
pub struct CheckArgs {
    /// `--policy <path>` (required by the command).
    pub policy: Option<PathBuf>,
    /// `--server <name>` — bind a multi-server policy to one identity;
    /// also selects which server's `tools-list-hash` pins a fetched
    /// tools/list verifies.
    pub server: Option<String>,
    /// `--engine <docker|podman|buildah|wslc>` — engine used to inspect
    /// `docker-manifest-hash` image references (auto-detect when `None`).
    pub engine: Option<EngineKind>,
    /// `--report <path>` — write the check result JSON here instead of
    /// stdout. A write failure is the `error` status (exit 1).
    pub report: Option<PathBuf>,
    pub verbose: u8,
    /// Trailing `-- <command>` — the server's launch argv. The server
    /// is spawned (restricted environment, no OS sandbox) to fetch its
    /// `tools/list` for `tools-list-hash` re-verification, and the argv
    /// re-checks that `binary-hash`/`entrypoint-hash` `target=`s bind
    /// the resolved executable or its payload the way
    /// `bind_launched_workload` would require at `run`. Without it,
    /// tools-list pins are reported `unverified` and binding is not
    /// re-evaluated.
    pub command: Vec<String>,
    /// A parse/semantic error captured for the machine-readable
    /// `invalid` result.
    pub invalid_input: Option<String>,
}

/// Output format for `policy resolve` — `kdl` prints the composed
/// policy document on stdout (warnings and provenance on stderr);
/// `json` emits one object carrying the KDL text, the per-field
/// provenance log, and the load's warnings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveFormat {
    Kdl,
    Json,
}

/// Parsed arguments for `policy resolve` — the PR-24 composed-policy
/// inspector: `extends`/`include`/`when` resolved to the effective
/// document (serialized with [`Policy::to_kdl`](crate::policy::Policy::to_kdl)) plus the provenance
/// log that names the file each field's write came from.
/// `invalid_input` records a parse/semantic error the command reports
/// as status `invalid` (exit 2) instead of a usage error.
#[derive(Debug)]
pub struct PolicyResolveArgs {
    /// The action taken on `policy` — `resolve`. Stored so the parse
    /// records a missing/unknown action as `invalid_input` rather than
    /// rejecting it at the CLI layer.
    pub action: Option<String>,
    /// `--policy <path>` (required by the command).
    pub policy: Option<PathBuf>,
    /// `--server <name>` — bind a multi-server policy to one identity
    /// before resolving.
    pub server: Option<String>,
    /// `--env <value>` — the environment `when` blocks resolve
    /// against. `None` means the ambient `MCP_WRIT_ENV`, exactly as a
    /// launch load sees it.
    pub env: Option<String>,
    /// `--format <kdl|json>` (default `kdl`).
    pub format: ResolveFormat,
    pub verbose: u8,
    /// A parse/semantic error captured for the machine-readable
    /// `invalid` result.
    pub invalid_input: Option<String>,
}

impl Default for PolicyResolveArgs {
    fn default() -> Self {
        Self {
            action: None,
            policy: None,
            server: None,
            env: None,
            format: ResolveFormat::Kdl,
            verbose: 0,
            invalid_input: None,
        }
    }
}

/// Parsed arguments for the `inspect` subcommand.
#[derive(Debug)]
pub struct InspectArgs {
    pub binary_path: PathBuf,
    pub project_dir: Option<PathBuf>,
    pub format: OutputFormat,
    pub output: Option<PathBuf>,
    pub verbose: u8,
    /// Trailing `-- <command>` argv. When set, payload discovery uses
    /// [`crate::legislator::source_bind::discover_from_argv`] so `-c` / `--eval`
    /// is classified as [`crate::legislator::source_bind::PayloadKind::InlineEval`].
    pub command: Vec<String>,
}

/// Parsed arguments for the `generate-policy` subcommand.
#[derive(Debug)]
pub struct GenPolicyArgs {
    pub binary_path: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub verbose: u8,
    pub static_only: bool,
    pub unsafe_unsandboxed_discovery: bool,
    pub self_test: bool,
    pub project_dir: Option<PathBuf>,
    pub command: Vec<String>,
}

/// Parsed arguments for the `run-image` subcommand.
#[derive(Debug)]
pub struct RunImageArgs {
    pub engine: Option<EngineKind>,
    /// The isolation method the launch is confined by (`--isolation`,
    /// default `container`). Engine and isolation are separate choices:
    /// the engine is the host-side tooling, the isolation is the
    /// workload boundary the backend applies.
    pub isolation: Option<IsolationKind>,
    pub image: String,
    pub policy: Option<String>,
    pub log_dir: Option<String>,
    pub verbose: bool,
    pub allow_mutable_tag: bool,
    pub server: Option<String>,
    /// `--report <path>` — write the host-side launch report JSON here.
    pub report: Option<PathBuf>,
    /// `--runner-binary <path>` — host-side mcp-secure-runner mounted
    /// read-only over the image's entrypoint path. Without it (and no
    /// `MCP_SECURE_RUNNER_PATH` / auto-detected runner next to the
    /// binary), the image's embedded runner is used only when the image
    /// digest matches a policy `docker-manifest-hash` pin.
    pub runner_binary: Option<PathBuf>,
    /// `--max-frame-bytes <n>` — JSON-RPC frame cap for the guest
    /// runner's Auditor relay (`None` keeps the runner's default).
    pub max_frame_bytes: Option<usize>,
}

/// Parsed arguments for the `wrap-image` subcommand.
#[derive(Debug)]
pub struct WrapImageArgs {
    pub image: String,
    /// `--allow-mutable-tag` — permit a tag-only base image reference;
    /// the tag is resolved once and the generated `FROM` binds the
    /// resolved digest.
    pub allow_mutable_tag: bool,
    pub policy: Option<PathBuf>,
    pub tag: Option<String>,
    pub engine: Option<EngineKind>,
    pub runner_binary: Option<PathBuf>,
    pub output_dockerfile: Option<PathBuf>,
    pub no_cache: bool,
    pub server: Option<String>,
    /// `--crt-dll <path>` (repeatable) — MSVC redistributable DLLs to
    /// ship app-local with a Windows guest runner.
    pub crt_dlls: Vec<PathBuf>,
}

/// Parsed arguments for the `dns-gate` subcommand — the
/// policy-evaluating DNS resolver (name-layer enforcement). Both
/// `policy` and `upstream` are required: the gate exists to enforce a
/// name layer, and the resolver it forwards to must be an IP literal
/// so bootstrap never recurses through the gate itself.
#[derive(Debug)]
pub struct DnsGateArgs {
    /// `--policy <path>` (required) — the policy whose
    /// `defaults.network` / `network` name rules the gate evaluates.
    pub policy: Option<PathBuf>,
    /// `--upstream <ip>[:port]` (required) — resolver for allowed
    /// names (default port 53). Kept optional in the type so
    /// "unspecified" is representable: `run_dns_gate` refuses to
    /// start without an explicit upstream.
    pub upstream: Option<std::net::SocketAddr>,
    /// `--listen <ip>[:port]` — UDP+TCP bind address (default
    /// `127.0.0.1:1053`).
    pub listen: std::net::SocketAddr,
    /// `--server <name>` — bind a multi-server policy to one identity.
    pub server: Option<String>,
    /// `--refuse-rcode` — RCODE for policy-refused names.
    pub refusal: crate::dnsgate::Refusal,
    /// `--allowlist-export <path>` — write the TTL-scoped dynamic IP
    /// allow list snapshot after every registration batch, for an
    /// IP-layer consumer in another process.
    pub allowlist_export: Option<PathBuf>,
    /// `--audit-log <path>` — audit JSONL sink (required when the
    /// policy's `logging.fail_closed` is true).
    pub audit_log: Option<PathBuf>,
    /// `--audit-sync` — flush + fsync every audit record.
    pub audit_sync: bool,
    pub verbose: u8,
}

impl Default for DnsGateArgs {
    fn default() -> Self {
        Self {
            policy: None,
            upstream: None,
            listen: "127.0.0.1:1053".parse().unwrap(),
            server: None,
            refusal: crate::dnsgate::Refusal::Refused,
            allowlist_export: None,
            audit_log: None,
            audit_sync: false,
            verbose: 0,
        }
    }
}

/// Parsed arguments for the `unotify-run` subcommand — the PR-07 Linux
/// IP-layer PoC: spawn a workload under the ordinary Linux sandbox
/// pipeline plus a seccomp user-notification filter on `connect(2)`,
/// supervised in-process by `warden::unotify`.
#[derive(Debug, Default)]
pub struct UnotifyArgs {
    /// `--policy <path>` — the policy whose outbound IP rules the
    /// supervisor evaluates (`network.outbound` / `defaults.network`).
    pub policy: Option<PathBuf>,
    /// `--server <name>` — bind a multi-server policy to one identity.
    pub server: Option<String>,
    /// `--allowlist <path>` — watch a `dns-gate --allowlist-export`
    /// snapshot file for TTL-scoped dynamic IP grants.
    pub allowlist: Option<PathBuf>,
    /// `--audit-log <path>` — audit JSONL sink (required when the
    /// policy's `logging.fail_closed` is true).
    pub audit_log: Option<PathBuf>,
    /// `--audit-sync` — flush + fsync every audit record.
    pub audit_sync: bool,
    /// `--report <path>` — write the PoC capability/status report JSON.
    pub report: Option<PathBuf>,
    pub verbose: u8,
    /// Trailing `-- <command>` argv — the workload to supervise.
    pub command: Vec<String>,
}

/// Parsed arguments for the `namespaced-run` subcommand — the PR-09
/// Linux PoC: spawn a workload inside `userns+netns+mountns` whose only
/// egress device is a TUN; an in-process proxy terminates TCP (DNAT →
/// smoltcp → splice), relays UDP per datagram, and answers DNS through
/// the embedded gate — all policy-evaluated per flow.
#[derive(Debug, Default)]
pub struct NamespacedArgs {
    /// `--policy <path>` — the policy whose egress rules the proxy
    /// enforces (structured `proto=`/`port=` qualifiers included).
    pub policy: Option<PathBuf>,
    /// `--server <name>` — bind a multi-server policy to one identity.
    pub server: Option<String>,
    /// `--upstream <ip>[:port]` — required: the resolver the embedded
    /// DNS gate forwards allowed names to.
    pub upstream: Option<std::net::SocketAddr>,
    /// `--audit-log <path>` — audit JSONL sink (required when the
    /// policy's `logging.fail_closed` is true).
    pub audit_log: Option<PathBuf>,
    /// `--audit-sync` — flush + fsync every audit record.
    pub audit_sync: bool,
    /// `--report <path>` — write the PoC capability/status report JSON.
    pub report: Option<PathBuf>,
    pub verbose: u8,
    /// Trailing `-- <command>` argv — the workload to run namespaced.
    pub command: Vec<String>,
}

/// Parsed arguments for the `ebpf-run` subcommand — the PR-10 opt-in
/// Linux launch: the workload joins a private cgroup in `pre_exec` and
/// `BPF_CGROUP_INET4/6_CONNECT` programs enforce connect destinations
/// in-kernel; denies are observed through a ring buffer.
#[derive(Debug, Default)]
pub struct EbpfArgs {
    /// `--policy <path>` — the policy whose outbound IP rules the
    /// connect programs enforce (`network.outbound` / `defaults.network`).
    pub policy: Option<PathBuf>,
    /// `--server <name>` — bind a multi-server policy to one identity.
    pub server: Option<String>,
    /// `--allowlist <path>` — watch a `dns-gate --allowlist-export`
    /// snapshot file; the drain loop resyncs the grant maps on change.
    pub allowlist: Option<PathBuf>,
    /// `--audit-log <path>` — audit JSONL sink (required when the
    /// policy's `logging.fail_closed` is true).
    pub audit_log: Option<PathBuf>,
    /// `--audit-sync` — flush + fsync every audit record.
    pub audit_sync: bool,
    /// `--report <path>` — write the capability/status report JSON.
    pub report: Option<PathBuf>,
    /// `--privileged-workload` — explicit opt-in to run the workload
    /// with the launcher's credentials. Without it a root launch
    /// demotes to `SUDO_UID`/`SUDO_GID` before exec (and refuses when
    /// no invoking user can be identified).
    pub privileged_workload: bool,
    pub verbose: u8,
    /// Trailing `-- <command>` argv — the workload to enforce.
    pub command: Vec<String>,
}

/// Parsed arguments for the `macos-proxy-run` subcommand — the PR-11
/// macOS opt-in: `sandbox-exec` pins the workload's outbound TCP to a
/// loopback CONNECT proxy that evaluates name+IP destination rules
/// and dials outward itself (the payload is never inspected).
#[derive(Debug, Default)]
pub struct MacosProxyArgs {
    /// `--policy <path>` — the policy whose egress rules the proxy
    /// enforces (name rules on the CONNECT authority, IP rules on
    /// literals/resolved addresses, `proto=`/`port=` qualifiers
    /// included).
    pub policy: Option<PathBuf>,
    /// `--server <name>` — bind a multi-server policy to one identity.
    pub server: Option<String>,
    /// `--listen <port>` — loopback port for the CONNECT proxy
    /// (default `0` = kernel-assigned; an explicit value is for
    /// reproducible diagnostics).
    pub listen_port: u16,
    /// `--audit-log <path>` — audit JSONL sink (required when the
    /// policy's `logging.fail_closed` is true).
    pub audit_log: Option<PathBuf>,
    /// `--audit-sync` — flush + fsync every audit record.
    pub audit_sync: bool,
    /// `--report <path>` — write the capability/status report JSON.
    pub report: Option<PathBuf>,
    pub verbose: u8,
    /// Trailing `-- <command>` argv — the workload to run under the
    /// proxy-pinned profile.
    pub command: Vec<String>,
}

/// Parsed arguments for the `containerize` subcommand.
#[derive(Debug)]
pub struct ContainerizeArgs {
    pub source_dir: PathBuf,
    pub policy: PathBuf,
    pub tag: Option<String>,
    pub base_image: Option<String>,
    /// `--allow-mutable-tag` — permit a tag-only `--base-image`; the tag
    /// is resolved once and the generated `FROM` binds the resolved
    /// digest.
    pub allow_mutable_tag: bool,
    pub engine: Option<EngineKind>,
    pub output_dockerfile: Option<PathBuf>,
    pub server: Option<String>,
    /// `--crt-dll <path>` (repeatable) — MSVC redistributable DLLs to
    /// ship app-local with a Windows guest runner.
    pub crt_dlls: Vec<PathBuf>,
}

impl From<WrapImageArgs> for WrapOptions {
    fn from(args: WrapImageArgs) -> Self {
        Self {
            image: args.image,
            allow_mutable_tag: args.allow_mutable_tag,
            policy: args.policy,
            tag: args.tag,
            engine: args.engine,
            runner_binary: args.runner_binary,
            output_dockerfile: args.output_dockerfile,
            no_cache: args.no_cache,
            server: args.server,
            crt_dlls: args.crt_dlls,
        }
    }
}

impl From<RunImageArgs> for RunImageOptions {
    fn from(args: RunImageArgs) -> Self {
        Self {
            engine: args.engine,
            isolation: args.isolation,
            image: args.image,
            policy: args.policy.map(PathBuf::from),
            log_dir: args.log_dir,
            verbose: args.verbose,
            allow_mutable_tag: args.allow_mutable_tag,
            server: args.server,
            report: args.report,
            runner_binary: args.runner_binary,
            max_frame_bytes: args.max_frame_bytes,
        }
    }
}

impl From<ContainerizeArgs> for ContainerizeOptions {
    fn from(args: ContainerizeArgs) -> Self {
        Self {
            source_dir: args.source_dir,
            policy: args.policy,
            tag: args.tag,
            base_image: args.base_image,
            allow_mutable_tag: args.allow_mutable_tag,
            engine: args.engine,
            output_dockerfile: args.output_dockerfile,
            server: args.server,
            crt_dlls: args.crt_dlls,
        }
    }
}

/// Output format for the `inspect` subcommand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
    Kdl,
}

/// Parse command-line arguments using noargs.
///
/// Expected syntax:
/// ```text
///   mcp-writ run [--transport <type>] [--policy <path>] [-v] [--dry-run] [--audit-log <path>] -- <command> [args...]
///   mcp-writ inspect <binary> [--format human|json|kdl] [--output <path>] [-v]
///   mcp-writ inspect [OPTIONS] -- <command> [args...]
///   mcp-writ generate-policy [--binary <path>] [--output <path>] [-v] -- <mcp-server-command>
/// ```
pub fn parse_args() -> Result<CliOutput, CliError> {
    parse_from(std::env::args()) // nosemgrep: rust.lang.security.args.args
}

fn parse_from(args: impl Iterator<Item = String>) -> Result<CliOutput, CliError> {
    let all_args: Vec<String> = args.collect();

    // Split on `--` separator: everything after `--` is the trailing command.
    let dash_pos = all_args.iter().position(|a| a == "--");
    let (noargs_part, command) = match dash_pos {
        Some(pos) => (all_args[..pos].to_vec(), all_args[pos + 1..].to_vec()),
        None => (all_args, Vec::new()),
    };

    let mut raw = noargs::RawArgs::new(noargs_part.into_iter());
    raw.metadata_mut().app_name = env!("CARGO_PKG_NAME");
    raw.metadata_mut().app_description = "Secure runner for MCP servers";

    // --version
    if noargs::VERSION_FLAG.take(&mut raw).is_present() {
        return Ok(CliOutput::Info(format!(
            "{} {}\n",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        )));
    }

    // --help (activates help mode; finish() will produce help text)
    noargs::HELP_FLAG.take_help(&mut raw);

    // Subcommand: run
    let run_cmd = noargs::cmd("run")
        .doc("Run an MCP server with security policies applied")
        .take(&mut raw);

    // Subcommand: plan
    let plan_cmd = noargs::cmd("plan")
        .doc("Diagnose launch prerequisites and print the enforcement plan without starting the workload")
        .take(&mut raw);

    // Subcommand: inspect
    let inspect_cmd = noargs::cmd("inspect")
        .doc("Analyze an ELF/Mach-O binary or script and report its capabilities")
        .take(&mut raw);

    // Subcommand: generate-policy
    let gen_policy_cmd = noargs::cmd("generate-policy")
        .doc("Generate a policy KDL from binary analysis and tools/list")
        .take(&mut raw);

    // Subcommand: capability-matrix (machine-readable OS matrix, PR-13).
    // Deliberately NOT last: its dispatch branch below avoids
    // `raw.finish()`'s command check — `check_command_error` inspects
    // the *last* taken cmd, so calling it on a normal invocation would
    // make this subcommand depend on registration order (the N-01
    // regression: bare `capability-matrix` failed `command is not
    // specified` when a later `.take()` existed). Keeping later takes
    // makes the bare-invocation test in tests_parse.rs a real
    // regression check for that order-dependence.
    let capability_matrix_cmd = noargs::cmd("capability-matrix")
        .doc("Print the machine-readable per-OS capability matrix (JSON) — mechanism coverage, requirements, deficiencies")
        .take(&mut raw);

    // Subcommand: run-image
    let run_image_cmd = noargs::cmd("run-image")
        .doc("Run a secured container image with policy and log mounts")
        .take(&mut raw);

    // Subcommand: wrap-image
    let wrap_image_cmd = noargs::cmd("wrap-image")
        .doc("Wrap an existing container image with mcp-writ security layer")
        .take(&mut raw);

    // Subcommand: containerize
    let containerize_cmd = noargs::cmd("containerize")
        .doc("Build a secured container image from an MCP server source directory")
        .take(&mut raw);

    // Subcommand: dns-gate
    let dns_gate_cmd = noargs::cmd("dns-gate")
        .doc("Serve a policy-evaluating DNS resolver (name-layer enforcement)")
        .take(&mut raw);

    // Subcommand: unotify-run (Linux IP-layer PoC, PR-07)
    let unotify_cmd = noargs::cmd("unotify-run")
        .doc("Run a command under a seccomp user-notification supervisor that enforces connect(2) destinations (Linux PoC)")
        .take(&mut raw);

    // Subcommand: namespaced-run (Linux namespaced egress PoC, PR-09)
    let namespaced_cmd = noargs::cmd("namespaced-run")
        .doc("Run a command inside userns+netns+mountns with a TUN-fed TCP/UDP policy proxy (Linux PoC)")
        .take(&mut raw);

    // Subcommand: ebpf-run (Linux cgroup eBPF opt-in, PR-10)
    let ebpf_cmd = noargs::cmd("ebpf-run")
        .doc("Run a command in a private cgroup with in-kernel INET4/6_CONNECT egress enforcement (Linux opt-in, needs CAP_BPF+CAP_NET_ADMIN)")
        .take(&mut raw);

    // Subcommand: macos-proxy-run (macOS loopback CONNECT proxy, PR-11)
    let macos_proxy_cmd = noargs::cmd("macos-proxy-run")
        .doc("Run a command under sandbox-exec with outbound TCP pinned to a loopback CONNECT proxy that enforces name+IP destination rules (macOS opt-in)")
        .take(&mut raw);

    // Subcommand: check (policy drift re-verification, PR-14)
    let check_cmd = noargs::cmd("check")
        .doc("Re-verify a policy's integrity pins (binary/entrypoint/lockfile/docker-manifest/tools-list hashes) against the current artifacts and report drift as JSON")
        .take(&mut raw);

    // Subcommand: policy (composed-policy inspection, PR-24)
    let policy_cmd = noargs::cmd("policy")
        .doc("Inspect a composed policy: `policy resolve --policy <path>` prints the effective KDL and each field's provenance")
        .take(&mut raw);

    if run_cmd.is_present() {
        parse_run::parse_run_args(raw, command)
    } else if plan_cmd.is_present() {
        parse_plan::parse_plan_args(raw, command)
    } else if inspect_cmd.is_present() {
        parse_inspect::parse_inspect_args(raw, command)
    } else if gen_policy_cmd.is_present() {
        parse_gen_policy::parse_gen_policy_args(raw, command)
    } else if run_image_cmd.is_present() {
        parse_run_image::parse_run_image_args(raw)
    } else if wrap_image_cmd.is_present() {
        parse_wrap_image::parse_wrap_image_args(raw)
    } else if containerize_cmd.is_present() {
        parse_containerize::parse_containerize_args(raw)
    } else if dns_gate_cmd.is_present() {
        parse_dns_gate::parse_dns_gate_args(raw, command)
    } else if unotify_cmd.is_present() {
        parse_unotify::parse_unotify_args(raw, command)
    } else if namespaced_cmd.is_present() {
        parse_namespaced::parse_namespaced_args(raw, command)
    } else if ebpf_cmd.is_present() {
        parse_ebpf::parse_ebpf_args(raw, command)
    } else if macos_proxy_cmd.is_present() {
        parse_macos_proxy::parse_macos_proxy_args(raw, command)
    } else if capability_matrix_cmd.is_present() {
        // No options: any stray argument is a usage error; `--help`
        // prints the generated help. `finish()`'s command check would
        // re-introduce the last-registration dependency, so only the
        // help-mode path uses it (it returns before that check) and the
        // unexpected-argument check runs directly on the raw args.
        if raw.metadata().help_mode {
            let help = raw
                .finish()
                .map_err(|e| CliError::Parse(format!("{e:?}")))?
                .expect("help mode always returns help text");
            return Ok(CliOutput::Info(help.to_string()));
        }
        if let Some((_, stray)) = raw.remaining_args().next() {
            return Err(CliError::Parse(format!(
                "unexpected argument '{stray}' found"
            )));
        }
        if !command.is_empty() {
            return Err(CliError::Parse(
                "capability-matrix takes no command".to_string(),
            ));
        }
        Ok(CliOutput::CapabilityMatrix)
    } else if check_cmd.is_present() {
        parse_check::parse_check_args(raw, command)
    } else if policy_cmd.is_present() {
        parse_policy::parse_policy_args(raw)
    } else {
        if let Some(help) = raw
            .finish()
            .map_err(|e| CliError::Parse(format!("{e:?}")))?
        {
            return Ok(CliOutput::Info(help.to_string()));
        }
        Err(CliError::MissingSubcommand)
    }
}

fn parse_output_format(s: &str) -> Result<OutputFormat, CliError> {
    match s {
        "human" => Ok(OutputFormat::Human),
        "json" => Ok(OutputFormat::Json),
        "kdl" => Ok(OutputFormat::Kdl),
        other => Err(CliError::Parse(format!(
            "invalid output format '{other}', expected: human, json, or kdl"
        ))),
    }
}
