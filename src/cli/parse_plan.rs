use std::path::PathBuf;

use crate::container::engine::EngineKind;

use super::{CliOutput, PlanArgs};

/// Record `msg` as the parse/semantic failure the `plan` command reports
/// as status `invalid` (exit 2).
fn invalid_args(mut args: PlanArgs, msg: String) -> CliOutput {
    args.invalid_input = Some(msg);
    CliOutput::Plan(args)
}

/// Parse `plan` arguments.
///
/// `plan` has two mutually exclusive modes:
///   native: `mcp-writ plan --policy <path> -- <command> [args...]`
///   image:  `mcp-writ plan --engine <engine> --image <ref> [--policy <path>]`
///
/// Unlike the other subcommands, this parser never returns `Err`: a
/// malformed invocation is a *result*, not a usage error — it is recorded
/// in `PlanArgs::invalid_input` so the command can emit the
/// machine-readable `invalid` status with exit code 2. `--help` output is
/// still honored via [`CliOutput::Info`].
pub(super) fn parse_plan_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, crate::error::CliError> {
    let mut args = PlanArgs::default();
    // A missing option value is deferred, not an early return: every
    // option — including --report — is parsed and stored before the
    // first error is reported, so an `invalid` result still honors a
    // requested report destination.
    let mut missing_value: Option<String> = None;

    // --policy <path> (optional)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file")
        .take(&mut raw);
    if policy_taken.is_value_present() && !policy_taken.value().is_empty() {
        args.policy = Some(PathBuf::from(policy_taken.value()));
    } else if policy_taken.is_present() {
        missing_value.get_or_insert_with(|| "--policy requires a file path".to_string());
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

    // --engine docker|podman|buildah (image mode only)
    let engine_taken = noargs::opt("engine")
        .short('e')
        .doc("Container engine: docker, podman, or buildah (auto-detect if omitted)")
        .take(&mut raw);
    let mut engine_error = None;
    if engine_taken.is_value_present() {
        match engine_taken.value().parse::<EngineKind>() {
            Ok(e) => args.engine = Some(e),
            Err(e) => engine_error = Some(e.to_string()),
        }
    } else if engine_taken.is_present() {
        missing_value.get_or_insert_with(|| {
            "--engine requires a value: docker, podman, or buildah".to_string()
        });
    }

    // --image <ref> (image mode)
    let image_taken = noargs::opt("image")
        .doc("Container image reference to plan a run-image for")
        .take(&mut raw);
    if image_taken.is_value_present() && !image_taken.value().is_empty() {
        args.image = Some(image_taken.value().to_string());
    } else if image_taken.is_present() {
        missing_value.get_or_insert_with(|| "--image requires an image reference".to_string());
    }

    // --allow-mutable-tag (image mode only)
    args.allow_mutable_tag = noargs::flag("allow-mutable-tag")
        .doc("Allow a tag-only image reference (default: require @sha256:<digest>)")
        .take(&mut raw)
        .is_present();

    // --report <path> (optional; default: the JSON result goes to stdout)
    let report_taken = noargs::opt("report")
        .doc("Write the plan result JSON to this path instead of stdout")
        .take(&mut raw);
    if report_taken.is_value_present() && !report_taken.value().is_empty() {
        args.report = Some(PathBuf::from(report_taken.value()));
    } else if report_taken.is_present() {
        missing_value.get_or_insert_with(|| "--report requires a file path".to_string());
    }

    // -v / --verbose
    args.verbose = if noargs::flag("verbose")
        .short('v')
        .doc("Increase log verbosity")
        .take(&mut raw)
        .is_present()
    {
        1u8
    } else {
        0u8
    };

    args.command = command;

    // A missing option value is reported before leftover-argument and
    // bad-value errors — the same precedence the early returns gave.
    if let Some(msg) = missing_value {
        return Ok(invalid_args(args, msg));
    }

    // Unknown/malformed flags surface here — for `plan` they are a
    // machine-readable `invalid` result, not a usage error. `--help`
    // still produces help text.
    match raw.finish() {
        Ok(Some(help)) => return Ok(CliOutput::Info(help.to_string())),
        Ok(None) => {}
        Err(e) => {
            return Ok(invalid_args(args, format!("unrecognized arguments: {e:?}")));
        }
    }

    if let Some(e) = engine_error {
        return Ok(invalid_args(args, format!("invalid --engine value: {e}")));
    }

    // Mode selection: --image and a trailing command are mutually
    // exclusive; exactly one is required.
    match (args.image.is_some(), args.command.is_empty()) {
        (true, false) => {
            return Ok(invalid_args(
                args,
                "--image and -- <command> are mutually exclusive: plan targets \
                 either a native command or a container image"
                    .to_string(),
            ));
        }
        (false, true) => {
            return Ok(invalid_args(
                args,
                "plan requires a target: -- <command> for a native launch or \
                 --image <ref> for a container image"
                    .to_string(),
            ));
        }
        _ => {}
    }
    if args.engine.is_some() && args.image.is_none() {
        return Ok(invalid_args(
            args,
            "--engine only applies together with --image".to_string(),
        ));
    }
    if args.allow_mutable_tag && args.image.is_none() {
        return Ok(invalid_args(
            args,
            "--allow-mutable-tag only applies together with --image".to_string(),
        ));
    }

    Ok(CliOutput::Plan(args))
}
