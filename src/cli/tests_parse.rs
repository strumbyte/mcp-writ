use super::*;

/// Test helper: parses a whitespace-delimited argument string.
/// Does NOT support quoted arguments (e.g., paths with spaces).
/// This is sufficient for test cases which use simple argument patterns.
fn args(s: &str) -> impl Iterator<Item = String> + use<> {
    s.split_whitespace()
        .map(String::from)
        .collect::<Vec<_>>()
        .into_iter()
}

fn unwrap_run(result: Result<CliOutput, CliError>) -> RunArgs {
    match result.expect("should parse") {
        CliOutput::Run(args) => args,
        other => panic!("expected Run, got {other:?}"),
    }
}

fn unwrap_inspect(result: Result<CliOutput, CliError>) -> InspectArgs {
    match result.expect("should parse") {
        CliOutput::Inspect(args) => args,
        other => panic!("expected Inspect, got {other:?}"),
    }
}

fn unwrap_gen_policy(result: Result<CliOutput, CliError>) -> GenPolicyArgs {
    match result.expect("should parse") {
        CliOutput::GeneratePolicy(args) => args,
        other => panic!("expected GeneratePolicy, got {other:?}"),
    }
}

#[test]
fn test_parse_basic_run() {
    let run_args = unwrap_run(parse_from(args("mcp-writ run -- echo hello")));
    assert_eq!(run_args.transport, "stdio");
    assert!(run_args.policy.is_none());
    assert!(run_args.server.is_none());
    assert_eq!(run_args.verbose, 0);
    assert_eq!(run_args.command, vec!["echo", "hello"]);
}

#[test]
fn test_parse_with_options() {
    let run_args = unwrap_run(parse_from(args(
        "mcp-writ run --transport stdio --policy /tmp/policy.kdl -v -- my-server --flag",
    )));
    assert_eq!(run_args.transport, "stdio");
    assert_eq!(run_args.policy, Some(PathBuf::from("/tmp/policy.kdl")));
    assert_eq!(run_args.verbose, 1);
    assert_eq!(run_args.command, vec!["my-server", "--flag"]);
}

#[test]
fn test_parse_run_server_selector() {
    let run_args = unwrap_run(parse_from(args(
        "mcp-writ run --server github -- echo hello",
    )));
    assert_eq!(run_args.server.as_deref(), Some("github"));
}

#[test]
fn test_parse_dry_run_flag() {
    let run_args = unwrap_run(parse_from(args("mcp-writ run --dry-run -- echo hello")));
    assert!(run_args.dry_run);
    assert_eq!(run_args.command, vec!["echo", "hello"]);
}

#[test]
fn test_parse_without_dry_run() {
    let run_args = unwrap_run(parse_from(args("mcp-writ run -- echo hello")));
    assert!(!run_args.dry_run);
    assert!(run_args.fail_on_cli.is_none());
}

#[test]
fn test_parse_fail_on_values() {
    for (raw, expected) in [
        ("high", FailOn::High),
        ("critical", FailOn::Critical),
        ("none", FailOn::None),
    ] {
        let run_args = unwrap_run(parse_from(args(&format!(
            "mcp-writ run --fail-on {raw} -- echo hello"
        ))));
        assert_eq!(run_args.fail_on_cli, Some(expected), "cli {raw}");
    }
}

#[test]
fn test_parse_fail_on_medium_rejected() {
    let result = parse_from(args("mcp-writ run --fail-on medium -- echo hello"));
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("medium"), "got: {err}");
    assert!(err.contains("high, critical, or none"), "got: {err}");
}

#[test]
fn test_parse_fail_on_unknown_rejected() {
    let result = parse_from(args("mcp-writ run --fail-on low -- echo hello"));
    assert!(result.is_err(), "unknown fail-on must fail closed");
}

#[test]
fn test_parse_fail_on_missing_value() {
    let result = parse_from(args("mcp-writ run --fail-on -- echo hello"));
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("--fail-on requires"), "got: {err}");
}

#[test]
fn test_parse_no_fail_alias_does_not_exist() {
    let result = parse_from(args("mcp-writ run --no-fail -- echo hello"));
    assert!(result.is_err(), "--no-fail must not be accepted");
    let err = format!("{:?}", result.unwrap_err());
    assert!(
        !err.contains("fail-on none"),
        "must not alias to --fail-on none: {err}"
    );
}

#[test]
fn test_run_help_documents_fail_on_and_omits_no_fail() {
    let result = parse_from(args("mcp-writ run --help"));
    match result {
        Ok(CliOutput::Info(help)) => {
            assert!(help.contains("--fail-on"), "help missing --fail-on: {help}");
            assert!(
                help.contains("dangerous"),
                "help must mark none as dangerous: {help}"
            );
            assert!(
                help.contains("not only CC-005"),
                "help must state High blast radius: {help}"
            );
            assert!(
                !help.contains("--no-fail"),
                "help must not advertise --no-fail: {help}"
            );
        }
        other => panic!("expected Info with help text, got {other:?}"),
    }
}

#[test]
fn test_parse_dry_run_with_other_flags() {
    let run_args = unwrap_run(parse_from(args(
        "mcp-writ run --dry-run --policy /tmp/policy.kdl -v -- my-server",
    )));
    assert!(run_args.dry_run);
    assert_eq!(run_args.policy, Some(PathBuf::from("/tmp/policy.kdl")));
    assert_eq!(run_args.verbose, 1);
}

#[test]
fn test_parse_audit_log_with_path() {
    let run_args = unwrap_run(parse_from(args(
        "mcp-writ run --audit-log /tmp/audit.jsonl -- echo hello",
    )));
    assert_eq!(run_args.audit_log, Some(PathBuf::from("/tmp/audit.jsonl")));
}

#[test]
fn test_parse_audit_log_missing_value() {
    // --audit-log without a value should produce a clear CLI error
    let result = parse_from(args("mcp-writ run --audit-log -- echo hello"));
    assert!(result.is_err(), "should fail when --audit-log has no value");
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("--audit-log requires"), "got: {err}");
}

#[test]
fn test_parse_policy_missing_value() {
    let result = parse_from(args("mcp-writ run --policy -- echo hello"));
    assert!(result.is_err(), "should fail when --policy has no value");
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("--policy requires"), "got: {err}");
}

#[test]
fn test_parse_server_missing_value() {
    let result = parse_from(args("mcp-writ run --server -- echo hello"));
    assert!(result.is_err(), "should fail when --server has no value");
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("--server requires"), "got: {err}");
}

#[test]
fn test_missing_subcommand() {
    let result = parse_from(args("mcp-writ -- echo"));
    assert!(result.is_err());
}

#[test]
fn test_missing_command() {
    let result = parse_from(args("mcp-writ run"));
    let err = result.unwrap_err();
    assert!(matches!(err, CliError::MissingCommand));
}

// ---------------------------------------------------------------
// inspect subcommand tests
// ---------------------------------------------------------------

#[test]
fn test_parse_inspect_basic() {
    let a = unwrap_inspect(parse_from(args("mcp-writ inspect /tmp/binary")));
    assert_eq!(a.binary_path, PathBuf::from("/tmp/binary"));
    assert_eq!(a.format, OutputFormat::Human);
    assert!(a.output.is_none());
    assert_eq!(a.verbose, 0);
}

#[test]
fn test_parse_inspect_json_format() {
    let a = unwrap_inspect(parse_from(args(
        "mcp-writ inspect --format json /tmp/binary",
    )));
    assert_eq!(a.binary_path, PathBuf::from("/tmp/binary"));
    assert_eq!(a.format, OutputFormat::Json);
}

#[test]
fn test_parse_inspect_kdl_format() {
    let a = unwrap_inspect(parse_from(args(
        "mcp-writ inspect --format kdl /tmp/binary",
    )));
    assert_eq!(a.format, OutputFormat::Kdl);
}

#[test]
fn test_parse_inspect_with_output() {
    let a = unwrap_inspect(parse_from(args(
        "mcp-writ inspect --output /tmp/out.txt /tmp/binary",
    )));
    assert_eq!(a.output, Some(PathBuf::from("/tmp/out.txt")));
    assert_eq!(a.binary_path, PathBuf::from("/tmp/binary"));
}

#[test]
fn test_parse_inspect_verbose() {
    let a = unwrap_inspect(parse_from(args("mcp-writ inspect -v /tmp/binary")));
    assert_eq!(a.verbose, 1);
}

#[test]
fn test_parse_inspect_invalid_format() {
    let result = parse_from(args("mcp-writ inspect --format xml /tmp/binary"));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("invalid output format"), "got: {err}");
}

#[test]
fn test_parse_inspect_with_project() {
    let a = unwrap_inspect(parse_from(args(
        "mcp-writ inspect --project /tmp/myproject /tmp/binary",
    )));
    assert_eq!(a.binary_path, PathBuf::from("/tmp/binary"));
    assert_eq!(a.project_dir, Some(PathBuf::from("/tmp/myproject")));
}

#[test]
fn test_parse_inspect_without_project() {
    let a = unwrap_inspect(parse_from(args("mcp-writ inspect /tmp/binary")));
    assert!(a.project_dir.is_none());
    assert!(a.command.is_empty());
}

#[test]
fn test_parse_inspect_inline_eval_via_dashdash() {
    let a = unwrap_inspect(parse_from(args("mcp-writ inspect -- python -c print(1)")));
    assert_eq!(a.binary_path, PathBuf::from("python"));
    assert_eq!(
        a.command,
        vec![
            "python".to_string(),
            "-c".to_string(),
            "print(1)".to_string()
        ]
    );
}

#[test]
fn test_parse_inspect_requires_path_or_command() {
    let result = parse_from(args("mcp-writ inspect"));
    assert!(result.is_err(), "inspect with no path and no -- command");
}

// ---------------------------------------------------------------
// generate-policy subcommand tests
// ---------------------------------------------------------------

#[test]
fn test_parse_generate_policy_basic() {
    let a = unwrap_gen_policy(parse_from(args("mcp-writ generate-policy -- echo hello")));
    assert!(a.binary_path.is_none());
    assert!(a.output.is_none());
    assert_eq!(a.verbose, 0);
    assert!(a.static_only);
    assert!(!a.unsafe_unsandboxed_discovery);
    assert!(!a.self_test);
    assert_eq!(a.command, vec!["echo", "hello"]);
    assert!(a.project_dir.is_none());
}

#[test]
fn test_parse_generate_policy_self_test() {
    let a = unwrap_gen_policy(parse_from(args(
        "mcp-writ generate-policy --self-test -- echo hello",
    )));
    assert!(a.self_test);
    assert!(a.static_only);
    assert!(!a.unsafe_unsandboxed_discovery);
}

#[test]
fn test_parse_generate_policy_with_project() {
    let a = unwrap_gen_policy(parse_from(args(
        "mcp-writ generate-policy --project /tmp/myproject -- echo hello",
    )));
    assert_eq!(a.project_dir, Some(PathBuf::from("/tmp/myproject")));
}

#[test]
fn test_parse_generate_policy_with_binary() {
    let a = unwrap_gen_policy(parse_from(args(
        "mcp-writ generate-policy --binary /tmp/bin -- echo hello",
    )));
    assert_eq!(a.binary_path, Some(PathBuf::from("/tmp/bin")));
    assert_eq!(a.command, vec!["echo", "hello"]);
}

#[test]
fn test_parse_generate_policy_with_output() {
    let a = unwrap_gen_policy(parse_from(args(
        "mcp-writ generate-policy --output /tmp/policy.kdl -- echo hello",
    )));
    assert_eq!(a.output, Some(PathBuf::from("/tmp/policy.kdl")));
}

#[test]
fn test_parse_generate_policy_verbose() {
    let a = unwrap_gen_policy(parse_from(args(
        "mcp-writ generate-policy -v -- echo hello",
    )));
    assert_eq!(a.verbose, 1);
}

#[test]
fn test_parse_generate_policy_missing_command() {
    let result = parse_from(args("mcp-writ generate-policy"));
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), CliError::MissingCommand));
}

#[test]
fn test_parse_generate_policy_live_discovery() {
    let a = unwrap_gen_policy(parse_from(args(
        "mcp-writ generate-policy --live-discovery -- echo hello",
    )));
    assert!(!a.static_only);
}

#[test]
fn test_parse_generate_policy_conflicting_discovery_flags() {
    let result = parse_from(args(
        "mcp-writ generate-policy --static-only --unsafe-unsandboxed-discovery -- echo hello",
    ));
    assert!(matches!(result, Err(CliError::Parse(_))));
}

#[test]
fn test_help_includes_all_subcommands() {
    let result = parse_from(args("mcp-writ --help"));
    match result {
        Ok(CliOutput::Info(help)) => {
            assert!(help.contains("run"), "help missing 'run': {help}");
            assert!(help.contains("inspect"), "help missing 'inspect': {help}");
            assert!(
                help.contains("generate-policy"),
                "help missing 'generate-policy': {help}"
            );
            assert!(
                help.contains("run-image"),
                "help missing 'run-image': {help}"
            );
            assert!(
                help.contains("wrap-image"),
                "help missing 'wrap-image': {help}"
            );
            assert!(
                help.contains("containerize"),
                "help missing 'containerize': {help}"
            );
        }
        other => panic!("expected Info with help text, got {other:?}"),
    }
}

// ---------------------------------------------------------------
// run-image subcommand tests
// ---------------------------------------------------------------

fn unwrap_run_image(result: Result<CliOutput, CliError>) -> RunImageArgs {
    match result.expect("should parse") {
        CliOutput::RunImage(args) => args,
        other => panic!("expected RunImage, got {other:?}"),
    }
}

#[test]
fn test_parse_run_image_basic() {
    let a = unwrap_run_image(parse_from(args("mcp-writ run-image my-image:latest")));
    assert!(a.engine.is_none());
    assert_eq!(a.image, "my-image:latest");
    assert!(a.policy.is_none());
    assert!(a.log_dir.is_none());
    assert!(!a.verbose);
    assert!(!a.allow_mutable_tag);
}

#[test]
fn test_parse_run_image_allow_mutable_tag() {
    let a = unwrap_run_image(parse_from(args(
        "mcp-writ run-image --allow-mutable-tag my-image:latest",
    )));
    assert!(a.allow_mutable_tag);
}

#[test]
fn test_parse_run_image_with_engine() {
    let a = unwrap_run_image(parse_from(args(
        "mcp-writ run-image --engine docker my-image",
    )));
    assert_eq!(a.engine, Some(EngineKind::Docker));
    assert_eq!(a.image, "my-image");
}

#[test]
fn test_parse_run_image_with_policy() {
    let a = unwrap_run_image(parse_from(args(
        "mcp-writ run-image --policy /tmp/policy.kdl my-image",
    )));
    assert_eq!(a.policy, Some("/tmp/policy.kdl".to_string()));
}

#[test]
fn test_parse_run_image_with_log_dir() {
    let a = unwrap_run_image(parse_from(args(
        "mcp-writ run-image --log-dir /tmp/logs my-image",
    )));
    assert_eq!(a.log_dir, Some("/tmp/logs".to_string()));
}

#[test]
fn test_parse_run_image_verbose() {
    let a = unwrap_run_image(parse_from(args("mcp-writ run-image -v my-image")));
    assert!(a.verbose);
}

#[test]
fn test_parse_run_image_all_options() {
    let a = unwrap_run_image(parse_from(args(
        "mcp-writ run-image --engine podman --policy /p.kdl --log-dir /logs -v my-img:v2",
    )));
    assert_eq!(a.engine, Some(EngineKind::Podman));
    assert_eq!(a.image, "my-img:v2");
    assert_eq!(a.policy, Some("/p.kdl".to_string()));
    assert_eq!(a.log_dir, Some("/logs".to_string()));
    assert!(a.verbose);
}

#[test]
fn test_parse_run_image_missing_image() {
    let result = parse_from(args("mcp-writ run-image"));
    assert!(result.is_err());
}

#[test]
fn test_parse_run_image_invalid_engine() {
    let result = parse_from(args("mcp-writ run-image --engine badengine my-image"));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("unknown engine kind"), "got: {err}");
}

// ---------------------------------------------------------------
// wrap-image subcommand tests
// ---------------------------------------------------------------

fn unwrap_wrap_image(result: Result<CliOutput, CliError>) -> WrapImageArgs {
    match result.expect("should parse") {
        CliOutput::WrapImage(args) => args,
        other => panic!("expected WrapImage, got {other:?}"),
    }
}

#[test]
fn test_parse_wrap_image_basic() {
    let a = unwrap_wrap_image(parse_from(args("mcp-writ wrap-image my-mcp-server:latest")));
    assert_eq!(a.image, "my-mcp-server:latest");
    assert!(a.policy.is_none());
    assert!(a.tag.is_none());
    assert!(a.engine.is_none());
    assert!(a.runner_binary.is_none());
    assert!(a.output_dockerfile.is_none());
    assert!(!a.no_cache);
}

#[test]
fn test_parse_wrap_image_with_policy() {
    let a = unwrap_wrap_image(parse_from(args(
        "mcp-writ wrap-image --policy /tmp/policy.kdl my-image",
    )));
    assert_eq!(a.policy, Some(PathBuf::from("/tmp/policy.kdl")));
    assert_eq!(a.image, "my-image");
}

#[test]
fn test_parse_wrap_image_with_tag() {
    let a = unwrap_wrap_image(parse_from(args(
        "mcp-writ wrap-image --tag my-secured:v2 my-image",
    )));
    assert_eq!(a.tag, Some("my-secured:v2".to_string()));
}

#[test]
fn test_parse_wrap_image_with_engine() {
    let a = unwrap_wrap_image(parse_from(args(
        "mcp-writ wrap-image --engine docker my-image",
    )));
    assert_eq!(a.engine, Some(EngineKind::Docker));
}

#[test]
fn test_parse_wrap_image_with_runner_binary() {
    let a = unwrap_wrap_image(parse_from(args(
        "mcp-writ wrap-image --runner-binary /usr/local/bin/mcp-secure-runner my-image",
    )));
    assert_eq!(
        a.runner_binary,
        Some(PathBuf::from("/usr/local/bin/mcp-secure-runner"))
    );
}

#[test]
fn test_parse_wrap_image_with_output_dockerfile() {
    let a = unwrap_wrap_image(parse_from(args(
        "mcp-writ wrap-image --output-dockerfile /tmp/Dockerfile my-image",
    )));
    assert_eq!(a.output_dockerfile, Some(PathBuf::from("/tmp/Dockerfile")));
}

#[test]
fn test_parse_wrap_image_no_cache() {
    let a = unwrap_wrap_image(parse_from(args("mcp-writ wrap-image --no-cache my-image")));
    assert!(a.no_cache);
}

#[test]
fn test_parse_wrap_image_all_options() {
    let a = unwrap_wrap_image(parse_from(args(
        "mcp-writ wrap-image --policy /p.kdl --tag secured:v1 --engine podman --runner-binary /runner --output-dockerfile /out/Dockerfile --no-cache my-img:latest",
    )));
    assert_eq!(a.image, "my-img:latest");
    assert_eq!(a.policy, Some(PathBuf::from("/p.kdl")));
    assert_eq!(a.tag, Some("secured:v1".to_string()));
    assert_eq!(a.engine, Some(EngineKind::Podman));
    assert_eq!(a.runner_binary, Some(PathBuf::from("/runner")));
    assert_eq!(a.output_dockerfile, Some(PathBuf::from("/out/Dockerfile")));
    assert!(a.no_cache);
}

#[test]
fn test_parse_wrap_image_missing_image() {
    let result = parse_from(args("mcp-writ wrap-image"));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("wrap-image requires an image"), "got: {err}");
}

#[test]
fn test_parse_wrap_image_invalid_engine() {
    let result = parse_from(args("mcp-writ wrap-image --engine badengine my-image"));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("unknown engine kind"), "got: {err}");
}

#[test]
fn test_parse_wrap_image_short_flags() {
    let a = unwrap_wrap_image(parse_from(args(
        "mcp-writ wrap-image -p /p.kdl -t tag:v1 -e docker my-image",
    )));
    assert_eq!(a.policy, Some(PathBuf::from("/p.kdl")));
    assert_eq!(a.tag, Some("tag:v1".to_string()));
    assert_eq!(a.engine, Some(EngineKind::Docker));
    assert_eq!(a.image, "my-image");
}

#[test]
fn test_parse_wrap_image_help() {
    let result = parse_from(args("mcp-writ wrap-image --help"));
    match result {
        Ok(CliOutput::Info(help)) => {
            assert!(help.contains("policy"), "help missing 'policy': {help}");
            assert!(help.contains("tag"), "help missing 'tag': {help}");
            assert!(help.contains("engine"), "help missing 'engine': {help}");
            assert!(
                help.contains("runner-binary"),
                "help missing 'runner-binary': {help}"
            );
            assert!(
                help.contains("output-dockerfile"),
                "help missing 'output-dockerfile': {help}"
            );
            assert!(help.contains("no-cache"), "help missing 'no-cache': {help}");
            assert!(help.contains("<image>"), "help missing '<image>': {help}");
        }
        other => panic!("expected Info with help text, got {other:?}"),
    }
}

// ---------------------------------------------------------------
// containerize subcommand tests
// ---------------------------------------------------------------

fn unwrap_containerize(result: Result<CliOutput, CliError>) -> ContainerizeArgs {
    match result.expect("should parse") {
        CliOutput::Containerize(args) => args,
        other => panic!("expected Containerize, got {other:?}"),
    }
}

#[test]
fn test_parse_containerize_basic() {
    let a = unwrap_containerize(parse_from(args(
        "mcp-writ containerize --source-dir /src/myapp --policy /tmp/policy.kdl",
    )));
    assert_eq!(a.source_dir, PathBuf::from("/src/myapp"));
    assert_eq!(a.policy, PathBuf::from("/tmp/policy.kdl"));
    assert!(a.tag.is_none());
    assert!(a.base_image.is_none());
    assert!(a.engine.is_none());
    assert!(a.output_dockerfile.is_none());
}

#[test]
fn test_parse_containerize_with_tag() {
    let a = unwrap_containerize(parse_from(args(
        "mcp-writ containerize --source-dir /src --policy /p.kdl --tag my-app:v1",
    )));
    assert_eq!(a.tag, Some("my-app:v1".to_string()));
}

#[test]
fn test_parse_containerize_with_base_image() {
    let a = unwrap_containerize(parse_from(args(
        "mcp-writ containerize --source-dir /src --policy /p.kdl --base-image node:20-slim",
    )));
    assert_eq!(a.base_image, Some("node:20-slim".to_string()));
}

#[test]
fn test_parse_containerize_with_output_dockerfile() {
    let a = unwrap_containerize(parse_from(args(
        "mcp-writ containerize --source-dir /src --policy /p.kdl --output-dockerfile /tmp/Dockerfile",
    )));
    assert_eq!(a.output_dockerfile, Some(PathBuf::from("/tmp/Dockerfile")));
}

#[test]
fn test_parse_containerize_with_engine() {
    let a = unwrap_containerize(parse_from(args(
        "mcp-writ containerize --source-dir /src --policy /p.kdl --engine docker",
    )));
    assert_eq!(a.engine, Some(EngineKind::Docker));
}

#[test]
fn test_parse_containerize_invalid_engine() {
    let result = parse_from(args(
        "mcp-writ containerize --source-dir /src --policy /p.kdl --engine badengine",
    ));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("unknown engine kind"), "got: {err}");
}

#[test]
fn test_parse_containerize_all_options() {
    let a = unwrap_containerize(parse_from(args(
        "mcp-writ containerize --source-dir /src/app --policy /p.kdl --tag app:v2 --base-image python:3.12-slim --engine podman --output-dockerfile /out/Dockerfile",
    )));
    assert_eq!(a.source_dir, PathBuf::from("/src/app"));
    assert_eq!(a.policy, PathBuf::from("/p.kdl"));
    assert_eq!(a.tag, Some("app:v2".to_string()));
    assert_eq!(a.base_image, Some("python:3.12-slim".to_string()));
    assert_eq!(a.engine, Some(EngineKind::Podman));
    assert_eq!(a.output_dockerfile, Some(PathBuf::from("/out/Dockerfile")));
}

#[test]
fn test_parse_containerize_short_flags() {
    let a = unwrap_containerize(parse_from(args(
        "mcp-writ containerize -s /src -p /p.kdl -t tag:v1 -b node:20 -e docker",
    )));
    assert_eq!(a.source_dir, PathBuf::from("/src"));
    assert_eq!(a.policy, PathBuf::from("/p.kdl"));
    assert_eq!(a.tag, Some("tag:v1".to_string()));
    assert_eq!(a.base_image, Some("node:20".to_string()));
    assert_eq!(a.engine, Some(EngineKind::Docker));
}

#[test]
fn test_parse_containerize_missing_source_dir() {
    let result = parse_from(args("mcp-writ containerize --policy /p.kdl"));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("--source-dir"), "got: {err}");
}

#[test]
fn test_parse_containerize_missing_policy() {
    let result = parse_from(args("mcp-writ containerize --source-dir /src"));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("--policy"), "got: {err}");
}

#[test]
fn test_parse_containerize_help() {
    let result = parse_from(args("mcp-writ containerize --help"));
    match result {
        Ok(CliOutput::Info(help)) => {
            assert!(
                help.contains("source-dir"),
                "help missing 'source-dir': {help}"
            );
            assert!(help.contains("policy"), "help missing 'policy': {help}");
            assert!(help.contains("tag"), "help missing 'tag': {help}");
            assert!(
                help.contains("base-image"),
                "help missing 'base-image': {help}"
            );
            assert!(help.contains("engine"), "help missing 'engine': {help}");
            assert!(
                help.contains("output-dockerfile"),
                "help missing 'output-dockerfile': {help}"
            );
        }
        other => panic!("expected Info with help text, got {other:?}"),
    }
}

// ─── plan / --report ─────────────────────────────────────────────────────

fn unwrap_plan(result: Result<CliOutput, CliError>) -> PlanArgs {
    match result.expect("should parse") {
        CliOutput::Plan(args) => args,
        other => panic!("expected Plan, got {other:?}"),
    }
}

#[test]
fn test_parse_run_report_path() {
    let run_args = unwrap_run(parse_from(args(
        "mcp-writ run --report /tmp/report.json -- echo hello",
    )));
    assert_eq!(run_args.report, Some(PathBuf::from("/tmp/report.json")));
}

#[test]
fn test_parse_run_report_requires_value() {
    let result = parse_from(args("mcp-writ run --report -- echo hello"));
    assert!(result.is_err());
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("--report requires"), "got: {err}");
}

#[test]
fn test_parse_run_without_report() {
    let run_args = unwrap_run(parse_from(args("mcp-writ run -- echo hello")));
    assert!(run_args.report.is_none());
}

#[test]
fn test_parse_plan_native_command() {
    let plan = unwrap_plan(parse_from(args(
        "mcp-writ plan --policy /tmp/policy.kdl -- node server.js",
    )));
    assert_eq!(plan.policy, Some(PathBuf::from("/tmp/policy.kdl")));
    assert_eq!(plan.command, vec!["node", "server.js"]);
    assert!(plan.image.is_none());
    assert!(plan.invalid_input.is_none());
}

#[test]
fn test_parse_plan_image_mode() {
    let plan = unwrap_plan(parse_from(args(
        "mcp-writ plan --engine docker --image app@sha256:abc --policy /tmp/p.kdl",
    )));
    assert_eq!(plan.engine, Some(EngineKind::Docker));
    assert_eq!(plan.image.as_deref(), Some("app@sha256:abc"));
    assert_eq!(plan.policy, Some(PathBuf::from("/tmp/p.kdl")));
    assert!(plan.invalid_input.is_none());
}

/// A malformed plan invocation is not a parser error — it is recorded for
/// the machine-readable  result (exit 2).
#[test]
fn test_parse_plan_no_target_is_invalid_not_error() {
    let plan = unwrap_plan(parse_from(args("mcp-writ plan --policy /tmp/p.kdl")));
    let msg = plan.invalid_input.expect("invalid_input must be recorded");
    assert!(msg.contains("requires a target"), "got: {msg}");
}

#[test]
fn test_parse_plan_image_and_command_is_invalid() {
    let plan = unwrap_plan(parse_from(args(
        "mcp-writ plan --image app@sha256:abc -- node server.js",
    )));
    let msg = plan.invalid_input.expect("invalid_input must be recorded");
    assert!(msg.contains("mutually exclusive"), "got: {msg}");
}

#[test]
fn test_parse_plan_engine_without_image_is_invalid() {
    let plan = unwrap_plan(parse_from(args(
        "mcp-writ plan --engine docker -- node s.js",
    )));
    let msg = plan.invalid_input.expect("invalid_input must be recorded");
    assert!(msg.contains("--engine"), "got: {msg}");
}

#[test]
fn test_parse_plan_unknown_flag_is_invalid() {
    let plan = unwrap_plan(parse_from(args("mcp-writ plan --bogus -- node s.js")));
    assert!(
        plan.invalid_input.is_some(),
        "unrecognized flags must record invalid_input"
    );
}

#[test]
fn test_parse_plan_report_path() {
    let plan = unwrap_plan(parse_from(args(
        "mcp-writ plan --report /tmp/plan.json -- node server.js",
    )));
    assert_eq!(plan.report, Some(PathBuf::from("/tmp/plan.json")));
}

#[test]
fn test_parse_run_image_report_path() {
    let result = parse_from(args(
        "mcp-writ run-image --report /tmp/r.json app@sha256:aaaa",
    ));
    match result.expect("should parse") {
        CliOutput::RunImage(args) => {
            assert_eq!(args.report, Some(PathBuf::from("/tmp/r.json")));
        }
        other => panic!("expected RunImage, got {other:?}"),
    }
}
