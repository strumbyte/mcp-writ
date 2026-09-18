use std::path::PathBuf;

use crate::error::CliError;

use super::{CliOutput, InspectArgs};

pub(super) fn parse_inspect_args(
    mut raw: noargs::RawArgs,
    command: Vec<String>,
) -> Result<CliOutput, CliError> {
    // --format <human|json|kdl> (default: "human")
    let format_taken = noargs::opt("format")
        .short('f')
        .default("human")
        .doc("Output format: human, json, or kdl (default: human)")
        .take(&mut raw);
    let format = super::parse_output_format(format_taken.value())?;

    // --output <path> (optional)
    let output_taken = noargs::opt("output")
        .short('o')
        .doc("Write output to file instead of stdout")
        .take(&mut raw);
    let output = if output_taken.is_value_present() {
        Some(PathBuf::from(output_taken.value()))
    } else {
        None
    };

    // --project <dir> (optional; analyze project directory for permission hints)
    let project_taken = noargs::opt("project")
        .doc("Analyze project directory for permission hints")
        .take(&mut raw);
    let project_dir = if project_taken.is_value_present() {
        Some(PathBuf::from(project_taken.value()))
    } else {
        None
    };

    // -v / --verbose
    let verbose = if noargs::flag("verbose")
        .short('v')
        .doc("Increase log verbosity")
        .take(&mut raw)
        .is_present()
    {
        1u8
    } else {
        0u8
    };

    // Positional argument: <binary> (optional when `-- <command>` is present)
    let binary_arg = noargs::arg("<binary>")
        .doc("Path to the ELF binary or script to inspect (optional when `-- <command>` is given)")
        .take(&mut raw);

    if let Some(help) = raw
        .finish()
        .map_err(|e| CliError::Parse(format!("{e:?}")))?
    {
        return Ok(CliOutput::Info(help.to_string()));
    }

    let binary_path = if binary_arg.is_present() {
        PathBuf::from(binary_arg.value())
    } else if let Some(first) = command.first() {
        PathBuf::from(first)
    } else {
        return Err(CliError::Parse(
            "inspect requires a binary path argument or `-- <command>`".to_string(),
        ));
    };

    Ok(CliOutput::Inspect(InspectArgs {
        binary_path,
        project_dir,
        format,
        output,
        verbose,
        command,
    }))
}
