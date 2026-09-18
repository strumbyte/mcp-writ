use std::path::PathBuf;

use crate::container::engine::EngineKind;
use crate::error::CliError;

use super::{CliOutput, WrapImageArgs};

pub(super) fn parse_wrap_image_args(mut raw: noargs::RawArgs) -> Result<CliOutput, CliError> {
    // --policy <path> (optional)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file (KDL or TOML)")
        .take(&mut raw);
    let policy = if policy_taken.is_value_present() {
        Some(PathBuf::from(policy_taken.value()))
    } else {
        None
    };

    // --tag <tag> (optional; default: <image>-secured:latest)
    let tag_taken = noargs::opt("tag")
        .short('t')
        .doc("Output image tag (default: <image>-secured:latest)")
        .take(&mut raw);
    let tag = if tag_taken.is_value_present() {
        Some(tag_taken.value().to_string())
    } else {
        None
    };

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

    // --runner-binary <path> (optional)
    let runner_taken = noargs::opt("runner-binary")
        .doc("Path to mcp-secure-runner binary to embed in the image")
        .take(&mut raw);
    let runner_binary = if runner_taken.is_value_present() {
        Some(PathBuf::from(runner_taken.value()))
    } else {
        None
    };

    // --output-dockerfile <path> (optional; write Dockerfile and exit without building)
    let output_df_taken = noargs::opt("output-dockerfile")
        .doc("Write generated Dockerfile to path and exit (do not build)")
        .take(&mut raw);
    let output_dockerfile = if output_df_taken.is_value_present() {
        Some(PathBuf::from(output_df_taken.value()))
    } else {
        None
    };

    // --no-cache (flag)
    let no_cache = noargs::flag("no-cache")
        .doc("Disable build cache")
        .take(&mut raw)
        .is_present();

    let server_taken = noargs::opt("server")
        .doc("Server identity to bind into the image policy")
        .take(&mut raw);
    let server = if server_taken.is_value_present() {
        Some(server_taken.value().to_string())
    } else {
        None
    };

    // Positional argument: <image>
    let image_arg = noargs::arg("<image>")
        .doc("Source container image to wrap (e.g. my-mcp-server:latest)")
        .take(&mut raw);

    if let Some(help) = raw
        .finish()
        .map_err(|e| CliError::Parse(format!("{e:?}")))?
    {
        return Ok(CliOutput::Info(help.to_string()));
    }

    if !image_arg.is_present() {
        return Err(CliError::Parse(
            "wrap-image requires an image argument, e.g.: mcp-writ wrap-image my-mcp-server:latest"
                .to_string(),
        ));
    }

    Ok(CliOutput::WrapImage(WrapImageArgs {
        image: image_arg.value().to_string(),
        policy,
        tag,
        engine,
        runner_binary,
        output_dockerfile,
        no_cache,
        server,
    }))
}
