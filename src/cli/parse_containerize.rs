use std::path::PathBuf;

use crate::container::engine::EngineKind;
use crate::error::CliError;

use super::{CliOutput, ContainerizeArgs};

pub(super) fn parse_containerize_args(mut raw: noargs::RawArgs) -> Result<CliOutput, CliError> {
    // --source-dir <path> (required)
    let source_dir_taken = noargs::opt("source-dir")
        .short('s')
        .doc("Path to MCP server source directory (required)")
        .take(&mut raw);

    // --policy <path> (required)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to KDL policy file (required)")
        .take(&mut raw);

    // --tag <tag> (optional)
    let tag_taken = noargs::opt("tag")
        .short('t')
        .doc("Tag for the generated container image")
        .take(&mut raw);
    let tag = if tag_taken.is_value_present() {
        Some(tag_taken.value().to_string())
    } else {
        None
    };

    // --base-image <image> (optional; overrides runtime_detect auto-detection)
    let base_image_taken = noargs::opt("base-image")
        .short('b')
        .doc("Override base image (default: auto-detected from source)")
        .take(&mut raw);
    let base_image = if base_image_taken.is_value_present() {
        Some(base_image_taken.value().to_string())
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

    // --output-dockerfile <path> (optional; write Dockerfile and exit without building)
    let output_df_taken = noargs::opt("output-dockerfile")
        .doc("Write generated Dockerfile to path and exit (do not build)")
        .take(&mut raw);
    let output_dockerfile = if output_df_taken.is_value_present() {
        Some(PathBuf::from(output_df_taken.value()))
    } else {
        None
    };

    let server_taken = noargs::opt("server")
        .doc("Server identity to bind into the image policy")
        .take(&mut raw);
    let server = if server_taken.is_value_present() {
        Some(server_taken.value().to_string())
    } else {
        None
    };

    if let Some(help) = raw
        .finish()
        .map_err(|e| CliError::Parse(format!("{e:?}")))?
    {
        return Ok(CliOutput::Info(help.to_string()));
    }

    if !source_dir_taken.is_value_present() {
        return Err(CliError::Parse(
            "containerize requires --source-dir <path>".to_string(),
        ));
    }
    if !policy_taken.is_value_present() {
        return Err(CliError::Parse(
            "containerize requires --policy <path>".to_string(),
        ));
    }

    Ok(CliOutput::Containerize(ContainerizeArgs {
        source_dir: PathBuf::from(source_dir_taken.value()),
        policy: PathBuf::from(policy_taken.value()),
        tag,
        base_image,
        engine,
        output_dockerfile,
        server,
    }))
}
