use std::path::PathBuf;

use super::{CliOutput, PolicyResolveArgs, ResolveFormat};

/// Record `msg` as the parse/semantic failure `policy resolve` reports
/// as status `invalid` (exit 2).
fn invalid_args(mut args: PolicyResolveArgs, msg: String) -> CliOutput {
    args.invalid_input = Some(msg);
    CliOutput::PolicyResolve(args)
}

/// Parse `policy` arguments — currently the `resolve` action:
///
/// ```text
///   mcp-writ policy resolve --policy <path> [--server <name>]
///                          [--env <value>] [--format kdl|json] [-v]
/// ```
///
/// Like `plan`/`check`, this parser never returns `Err`: a malformed
/// invocation is a *result* recorded in
/// `PolicyResolveArgs::invalid_input` so the command can emit the
/// machine-readable `invalid` status with exit code 2. `--help` output
/// is still honored via [`CliOutput::Info`].
///
/// `--env` supplies the value `when` blocks evaluate against — the
/// equivalent of `MCP_WRIT_ENV` for a resolution that may run for a
/// different environment than the launcher. When absent the ambient
/// `MCP_WRIT_ENV` applies, exactly as a launch load sees it.
pub(super) fn parse_policy_args(
    mut raw: noargs::RawArgs,
) -> Result<CliOutput, crate::error::CliError> {
    let mut args = PolicyResolveArgs::default();
    let mut missing_value = None;

    // Positional: the action (`resolve` — `policy` is a namespace for
    // policy-inspection actions; an unknown action is `invalid_input`).
    let action_arg = noargs::arg("<action>")
        .doc("Action to perform: resolve — print the composed (effective) policy")
        .take(&mut raw);
    if action_arg.is_present() {
        args.action = Some(action_arg.value().to_string());
    }

    // --policy <path> (required by the command semantics; absence is a
    // machine-readable `invalid` result, not a usage error)
    let policy_taken = noargs::opt("policy")
        .short('p')
        .doc("Path to policy file (required)")
        .take(&mut raw);
    if policy_taken.is_value_present() && !policy_taken.value().is_empty() {
        args.policy = Some(PathBuf::from(policy_taken.value()));
    } else if policy_taken.is_present() {
        missing_value.get_or_insert_with(|| "--policy requires a file path".to_string());
    }

    // --server <name> (optional — bind a multi-server policy to one
    // identity before resolving, the same --server `run` takes)
    let server_taken = noargs::opt("server")
        .doc("Server identity to bind from a multi-server policy")
        .take(&mut raw);
    if server_taken.is_value_present() && !server_taken.value().is_empty() {
        args.server = Some(server_taken.value().to_string());
    } else if server_taken.is_present() {
        missing_value.get_or_insert_with(|| "--server requires a server name".to_string());
    }

    // --env <value> (optional — the environment `when` blocks evaluate;
    // MCP_WRIT_ENV applies when the flag is absent)
    let env_taken = noargs::opt("env")
        .doc("Environment value `when` blocks resolve against (default: MCP_WRIT_ENV)")
        .take(&mut raw);
    if env_taken.is_value_present() {
        args.env = Some(env_taken.value().to_string());
    } else if env_taken.is_present() {
        missing_value.get_or_insert_with(|| "--env requires a value".to_string());
    }

    // --format <kdl|json> (default: kdl — the composed policy text on
    // stdout; json embeds it with provenance and warnings)
    let format_taken = noargs::opt("format")
        .short('f')
        .doc("Output format: kdl (default) or json")
        .take(&mut raw);
    let mut format_error = None;
    if format_taken.is_value_present() {
        match format_taken.value() {
            "kdl" => args.format = ResolveFormat::Kdl,
            "json" => args.format = ResolveFormat::Json,
            other => {
                format_error = Some(format!("invalid --format '{other}', expected: kdl or json"));
            }
        }
    } else if format_taken.is_present() {
        missing_value.get_or_insert_with(|| "--format requires a value: kdl or json".to_string());
    }

    // --version-diff — resolve the same documents under the other
    // composition-rules version (v2 vs v3) and report which effective
    // fields the rule change moves (PR-28).
    args.version_diff = noargs::flag("version-diff")
        .doc("Report effective-policy differences between v2 and v3 composition rules")
        .take(&mut raw)
        .is_present();

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

    if let Some(msg) = missing_value {
        return Ok(invalid_args(args, msg));
    }

    match raw.finish() {
        Ok(Some(help)) => return Ok(CliOutput::Info(help)),
        Ok(None) => {}
        Err(e) => {
            return Ok(invalid_args(args, format!("unrecognized arguments: {e:?}")));
        }
    }

    if let Some(e) = format_error {
        return Ok(invalid_args(args, e));
    }

    match args.action.as_deref() {
        None => {
            return Ok(invalid_args(
                args,
                "policy requires an action: `policy resolve --policy <path>`".to_string(),
            ));
        }
        Some("resolve") => {}
        Some(other) => {
            let msg = format!("unknown policy action '{other}': expected `resolve`");
            return Ok(invalid_args(args, msg));
        }
    }

    if args.policy.is_none() {
        return Ok(invalid_args(
            args,
            "policy resolve requires --policy <path>: resolution composes the \
             policy's extends/include/when layers into one effective document"
                .to_string(),
        ));
    }

    Ok(CliOutput::PolicyResolve(args))
}
