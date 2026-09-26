use crate::container::common::{
    self, BuildContext, build_image, validate_policy_path, write_dockerfile_to_path,
};
use crate::container::dockerfile::{DockerfileTemplate, EntrypointValue};
use crate::container::inspect::inspect_image;
use crate::container::options::WrapOptions;
use crate::container::presenter::BuildOutcome;
use crate::error::ContainerError;

/// Execute the full wrap-image flow: inspect → Dockerfile → build → tag.
///
/// Returns a [`BuildOutcome`] on success:
/// - For builds: `Built` carrying the output image tag.
/// - For `--output-dockerfile`: `DockerfileWritten` with the output path.
pub async fn wrap_image(options: &WrapOptions) -> Result<BuildOutcome, ContainerError> {
    // 1. Resolve runner binary and container engine
    let prereqs = common::resolve_prereqs(options.runner_binary.as_deref(), options.engine)
        .map_err(|e| ContainerError::BuildFailed(e.to_string()))?;

    // 2. Inspect source image for ENTRYPOINT/CMD and the guest OS — the
    // runner contract is a Linux guest at this stage: a Windows image is
    // an explicit refusal, and an undeterminable OS is never assumed.
    let metadata = inspect_image(prereqs.engine.as_ref(), &options.image).await?;
    crate::container::guest_report::check_guest_image_os(metadata.os.as_deref())
        .map_err(ContainerError::BuildFailed)?;

    // 3. Convert metadata to EntrypointValue
    let orig_entrypoint = vec_to_entrypoint(&metadata.entrypoint);
    let orig_cmd = vec_to_entrypoint(&metadata.cmd);

    // 4. Generate Dockerfile content — the embedded runner's capability
    // marker is recorded on the image env so run-image can tell a
    // report-capable build from a legacy one.
    let tmpl = DockerfileTemplate {
        base_image: options.image.clone(),
        runner_path: "mcp-secure-runner".to_string(),
        policy_path: "policy.kdl".to_string(),
        orig_entrypoint,
        orig_cmd,
        runner_caps: prereqs
            .runner_caps
            .as_ref()
            .map(|c| c.env_value())
            .unwrap_or_default(),
    };
    let dockerfile_content = tmpl.generate()?;

    // 5. --output-dockerfile: write Dockerfile and return (no build)
    if let Some(ref output_path) = options.output_dockerfile {
        write_dockerfile_to_path(output_path, &dockerfile_content)?;
        return Ok(BuildOutcome::DockerfileWritten {
            path: output_path.clone(),
        });
    }

    // 6. Resolve policy path (default: ./policy.kdl)
    let policy_path = validate_policy_path(options.policy.as_deref(), "policy.kdl")?;

    // The embedded guest contract is a Linux workload (the static-ELF
    // mcp-secure-runner), so the policy is accepted for a Linux target —
    // independent of the host OS the build runs on.
    let guest_target = crate::execution::ExecutionTarget::linux_container(
        crate::execution::EngineName::from_name(&prereqs.engine_name),
        // The substrate OS is not consulted for policy validation — the
        // guest contract is Linux regardless — so skip the `<cli> info`
        // probe and record it as unknown.
        None,
    );

    // 7. Create build context and populate it
    let ctx = BuildContext::new("wrap")?;
    ctx.copy_runner(&prereqs.runner_path)?;
    ctx.copy_policy_for_server(&policy_path, options.server.as_deref(), &guest_target)?;
    let dockerfile_path = ctx.write_dockerfile(&dockerfile_content)?;

    // 8. Determine output tag
    let tag = options
        .tag
        .clone()
        .unwrap_or_else(|| make_default_tag(&options.image));

    // 9. Build image
    let build_result = build_image(
        &prereqs.engine_name,
        &dockerfile_path,
        &tag,
        ctx.dir(),
        options.no_cache,
    )
    .await;

    // 10. Clean up temp dir (runs on both success and failure)
    ctx.cleanup();
    build_result?;

    eprintln!("{}", runner_capability_note(&prereqs.runner_caps));
    Ok(BuildOutcome::Built { tag })
}

/// Human note recording what the built image's runner can report —
/// generation success is not an observation of applied controls.
pub fn runner_capability_note(caps: &Option<crate::container::guest_report::RunnerCaps>) -> String {
    match caps {
        Some(c) if c.guest_report_capable() => format!(
            "runner v{}: guest report capability recorded on the image",
            c.version
        ),
        Some(c) => format!(
            "runner v{}: no guest report capability (run-image --report will refuse this image)",
            c.version
        ),
        None => "runner: no capability marker (legacy; run-image --report will refuse this image)"
            .to_string(),
    }
}

/// Convert `Option<Vec<String>>` to [`EntrypointValue`].
fn vec_to_entrypoint(v: &Option<Vec<String>>) -> EntrypointValue {
    match v {
        Some(parts) if !parts.is_empty() => EntrypointValue::Exec(parts.clone()),
        _ => EntrypointValue::None,
    }
}

/// Generate the default output tag: `<base>-secured:latest`.
///
/// Strips the existing tag (if any) while preserving registry/port prefixes.
fn make_default_tag(image: &str) -> String {
    // Find the image name segment (after the last '/')
    let last_slash = image.rfind('/').map(|p| p + 1).unwrap_or(0);
    let name_segment = &image[last_slash..];

    // Handle both :tag and @sha256:digest
    let base = if let Some(at_pos) = name_segment.find('@') {
        &image[..last_slash + at_pos]
    } else if let Some(colon_in_name) = name_segment.find(':') {
        &image[..last_slash + colon_in_name]
    } else {
        image
    };

    format!("{base}-secured:latest")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::dockerfile::DockerfileTemplate;

    // -- make_default_tag -----------------------------------------------------

    #[test]
    fn test_default_tag_with_tag() {
        assert_eq!(
            make_default_tag("my-image:latest"),
            "my-image-secured:latest"
        );
    }

    #[test]
    fn test_default_tag_without_tag() {
        assert_eq!(make_default_tag("my-image"), "my-image-secured:latest");
    }

    #[test]
    fn test_default_tag_with_version() {
        assert_eq!(make_default_tag("my-image:v2.1"), "my-image-secured:latest");
    }

    #[test]
    fn test_default_tag_with_registry() {
        assert_eq!(
            make_default_tag("registry.example.com/my-image:v2"),
            "registry.example.com/my-image-secured:latest"
        );
    }

    #[test]
    fn test_default_tag_with_registry_port() {
        assert_eq!(
            make_default_tag("localhost:5000/my-image:v1"),
            "localhost:5000/my-image-secured:latest"
        );
    }

    #[test]
    fn test_default_tag_with_registry_port_no_tag() {
        assert_eq!(
            make_default_tag("localhost:5000/my-image"),
            "localhost:5000/my-image-secured:latest"
        );
    }

    #[test]
    fn test_default_tag_with_nested_path() {
        assert_eq!(
            make_default_tag("ghcr.io/org/repo/image:sha-abc123"),
            "ghcr.io/org/repo/image-secured:latest"
        );
    }

    // -- vec_to_entrypoint ----------------------------------------------------

    #[test]
    fn test_vec_to_entrypoint_some_values() {
        let v = Some(vec!["node".to_string(), "server.js".to_string()]);
        match vec_to_entrypoint(&v) {
            EntrypointValue::Exec(parts) => {
                assert_eq!(parts, vec!["node", "server.js"]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn test_vec_to_entrypoint_single_value() {
        let v = Some(vec!["/docker-entrypoint.sh".to_string()]);
        match vec_to_entrypoint(&v) {
            EntrypointValue::Exec(parts) => {
                assert_eq!(parts, vec!["/docker-entrypoint.sh"]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn test_vec_to_entrypoint_empty_vec() {
        let v = Some(vec![]);
        match vec_to_entrypoint(&v) {
            EntrypointValue::None => {}
            other => panic!("expected None for empty vec, got {other:?}"),
        }
    }

    #[test]
    fn test_vec_to_entrypoint_none() {
        let v: Option<Vec<String>> = None;
        match vec_to_entrypoint(&v) {
            EntrypointValue::None => {}
            other => panic!("expected None, got {other:?}"),
        }
    }

    // -- Dockerfile generation integration ------------------------------------

    #[test]
    fn test_dockerfile_generation_with_entrypoint_and_cmd() {
        let tmpl = DockerfileTemplate {
            base_image: "my-mcp-server:latest".to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Exec(vec![
                "node".to_string(),
                "server.js".to_string(),
            ]),
            orig_cmd: EntrypointValue::Exec(vec!["--port".to_string(), "8080".to_string()]),
            runner_caps: String::new(),
        };
        let content = tmpl.generate().unwrap();

        assert!(content.contains("FROM my-mcp-server:latest"));
        assert!(content.contains("COPY mcp-secure-runner /usr/local/bin/mcp-secure-runner"));
        assert!(content.contains("COPY policy.kdl /etc/mcp-secure/policy.kdl"));
        assert!(content.contains("MCP_ORIG_ENTRYPOINT="));
        assert!(content.contains("MCP_ORIG_CMD="));
        assert!(content.contains("ENTRYPOINT [\"/usr/local/bin/mcp-secure-runner\"]"));
        assert!(content.contains("HEALTHCHECK NONE"));
        assert!(content.contains("MCP_WRIT_ENV=\"\""));
        assert!(content.contains("MCP_WRIT_SERVER=\"\""));
        assert!(content.contains("MCP_WRIT_FAIL_ON=\"\""));
    }

    #[test]
    fn test_dockerfile_generation_no_entrypoint_no_cmd() {
        let tmpl = DockerfileTemplate {
            base_image: "alpine:3.19".to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::None,
            orig_cmd: EntrypointValue::None,
            runner_caps: String::new(),
        };
        let content = tmpl.generate().unwrap();

        assert!(content.contains("FROM alpine:3.19"));
        assert!(content.contains("MCP_ORIG_ENTRYPOINT=\"\""));
        assert!(content.contains("MCP_ORIG_CMD=\"\""));
    }

    // -- output-dockerfile file write -----------------------------------------

    #[test]
    fn test_output_dockerfile_write() {
        let dir = std::env::temp_dir().join("mcp_writ_test_output_df");
        let _ = std::fs::create_dir_all(&dir);
        let output_path = dir.join("Dockerfile.test");

        let tmpl = DockerfileTemplate {
            base_image: "test-image:v1".to_string(),
            runner_path: "mcp-secure-runner".to_string(),
            policy_path: "policy.kdl".to_string(),
            orig_entrypoint: EntrypointValue::Exec(vec!["python".to_string()]),
            orig_cmd: EntrypointValue::Exec(vec!["app.py".to_string()]),
            runner_caps: String::new(),
        };
        let content = tmpl.generate().unwrap();

        std::fs::write(&output_path, &content).unwrap();
        let read_back = std::fs::read_to_string(&output_path).unwrap();
        assert_eq!(read_back, content);
        assert!(read_back.contains("FROM test-image:v1"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    // -- build_image command construction (buildah vs docker/podman) -----------
    // Tests for the get_build_subcommand helper function exported from common.rs.

    #[test]
    fn test_buildah_uses_bud_subcmd() {
        assert_eq!(super::common::get_build_subcommand("buildah"), "bud");
    }

    #[test]
    fn test_docker_uses_build_subcmd() {
        assert_eq!(super::common::get_build_subcommand("docker"), "build");
    }

    #[test]
    fn test_podman_uses_build_subcmd() {
        assert_eq!(super::common::get_build_subcommand("podman"), "build");
    }
}
