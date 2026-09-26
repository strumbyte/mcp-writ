use crate::container::engine::EngineKind;
use crate::error::CliError;

use super::{CliOutput, RunImageArgs};

pub(super) fn parse_run_image_args(mut raw: noargs::RawArgs) -> Result<CliOutput, CliError> {
    // --engine docker|podman|buildah (optional; auto-detect if omitted)
    let engine_taken = noargs::opt("engine")
        .short('e')
        .doc("Container engine: docker, podman, or buildah (auto-detect if omitted)")
        .take(&mut raw);
    let engine = if engine_taken.is_value_present() {
        Some(
            engine_taken
                .value()
                .parse::<EngineKind>()
                .map_err(|e| CliError::Parse(e.to_string()))?,
        )
    } else if engine_taken.is_present() {
        return Err(CliError::Parse(
            "--engine requires a value: docker, podman, or buildah".to_string(),
        ));
    } else {
        None
    };

    // --policy <path> (optional; default: ./policy.kdl)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file (default: ./policy.kdl)")
        .take(&mut raw);
    let policy = if policy_taken.is_value_present() {
        Some(policy_taken.value().to_string())
    } else {
        None
    };

    // --log-dir <path> (optional)
    let log_dir_taken = noargs::opt("log-dir")
        .doc("Directory for container log files")
        .take(&mut raw);
    let log_dir = if log_dir_taken.is_value_present() {
        Some(log_dir_taken.value().to_string())
    } else {
        None
    };

    // -v / --verbose
    let verbose = noargs::flag("verbose")
        .short('v')
        .doc("Enable verbose output")
        .take(&mut raw)
        .is_present();

    let allow_mutable_tag = noargs::flag("allow-mutable-tag")
        .doc("Allow a tag-only image reference (default: require @sha256:<digest>)")
        .take(&mut raw)
        .is_present();

    let server_taken = noargs::opt("server")
        .doc("Server identity to bind in the mounted policy (required for multi-server policies)")
        .take(&mut raw);
    let server = if server_taken.is_value_present() {
        Some(server_taken.value().to_string())
    } else {
        None
    };

    // --report <path> (optional)
    let report_taken = noargs::opt("report")
        .doc(
            "Write the host-side launch report (plan, observations, final \
             result) as JSON to this path; a human summary goes to stderr",
        )
        .take(&mut raw);
    let report = if report_taken.is_value_present() && !report_taken.value().is_empty() {
        Some(std::path::PathBuf::from(report_taken.value()))
    } else if report_taken.is_present() {
        return Err(CliError::Parse("--report requires a file path".to_string()));
    } else {
        None
    };

    // Positional argument: <image>
    let image_arg = noargs::arg("<image>")
        .doc("Container image to run (e.g. my-mcp-server:latest)")
        .take(&mut raw);

    if let Some(help) = raw
        .finish()
        .map_err(|e| CliError::Parse(format!("{e:?}")))?
    {
        return Ok(CliOutput::Info(help.to_string()));
    }

    if !image_arg.is_present() {
        return Err(CliError::Parse(
            "run-image requires an image argument, e.g.: mcp-writ run-image my-image:latest"
                .to_string(),
        ));
    }

    Ok(CliOutput::RunImage(RunImageArgs {
        engine,
        image: image_arg.value().to_string(),
        policy,
        log_dir,
        verbose,
        allow_mutable_tag,
        server,
        report,
    }))
}
