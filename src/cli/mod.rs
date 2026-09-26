use std::path::PathBuf;

use crate::container::engine::EngineKind;
use crate::container::options::{ContainerizeOptions, RunImageOptions, WrapOptions};
use crate::error::CliError;
use crate::verifier::fail_on::FailOn;

mod parse_containerize;
mod parse_gen_policy;
mod parse_inspect;
mod parse_plan;
mod parse_run;
mod parse_run_image;
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
    /// Informational output (--version or --help) to be printed and exited.
    Info(String),
}

/// Parsed arguments for the `run` subcommand.
#[derive(Debug)]
pub struct RunArgs {
    pub transport: String,
    pub policy: Option<PathBuf>,
    pub server: Option<String>,
    pub verbose: u8,
    pub dry_run: bool,
    /// CLI `--fail-on` when present. Env is resolved later (`CLI > env > high`).
    pub fail_on_cli: Option<FailOn>,
    pub audit_log: Option<PathBuf>,
    /// `--report <path>` — write the launch plan + observations + final
    /// result as one JSON object (never on MCP stdout).
    pub report: Option<PathBuf>,
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
    pub policy: Option<PathBuf>,
    pub server: Option<String>,
    pub verbose: u8,
    /// Image mode: engine override (auto-detect when `None`). Only
    /// meaningful with `image`.
    pub engine: Option<EngineKind>,
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
    /// A parse/semantic error captured for the machine-readable `invalid`
    /// result (e.g. `--image` combined with `-- <command>`).
    pub invalid_input: Option<String>,
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
    pub image: String,
    pub policy: Option<String>,
    pub log_dir: Option<String>,
    pub verbose: bool,
    pub allow_mutable_tag: bool,
    pub server: Option<String>,
    /// `--report <path>` — write the host-side launch report JSON here.
    pub report: Option<PathBuf>,
}

/// Parsed arguments for the `wrap-image` subcommand.
#[derive(Debug)]
pub struct WrapImageArgs {
    pub image: String,
    pub policy: Option<PathBuf>,
    pub tag: Option<String>,
    pub engine: Option<EngineKind>,
    pub runner_binary: Option<PathBuf>,
    pub output_dockerfile: Option<PathBuf>,
    pub no_cache: bool,
    pub server: Option<String>,
}

/// Parsed arguments for the `containerize` subcommand.
#[derive(Debug)]
pub struct ContainerizeArgs {
    pub source_dir: PathBuf,
    pub policy: PathBuf,
    pub tag: Option<String>,
    pub base_image: Option<String>,
    pub engine: Option<EngineKind>,
    pub output_dockerfile: Option<PathBuf>,
    pub server: Option<String>,
}

impl From<WrapImageArgs> for WrapOptions {
    fn from(args: WrapImageArgs) -> Self {
        Self {
            image: args.image,
            policy: args.policy,
            tag: args.tag,
            engine: args.engine,
            runner_binary: args.runner_binary,
            output_dockerfile: args.output_dockerfile,
            no_cache: args.no_cache,
            server: args.server,
        }
    }
}

impl From<RunImageArgs> for RunImageOptions {
    fn from(args: RunImageArgs) -> Self {
        Self {
            engine: args.engine,
            image: args.image,
            policy: args.policy.map(PathBuf::from),
            log_dir: args.log_dir,
            verbose: args.verbose,
            allow_mutable_tag: args.allow_mutable_tag,
            server: args.server,
            report: args.report,
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
            engine: args.engine,
            output_dockerfile: args.output_dockerfile,
            server: args.server,
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
    parse_from(std::env::args())
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
