use std::path::PathBuf;

use crate::container::engine::resolve_engine;
use crate::container::options::RunImageOptions;
use crate::container::policy_export::{self, PolicyBindError};

/// Build the container run options (volume mounts).
fn build_run_options(
    policy_abs: &std::path::Path,
    log_dir_abs: Option<&std::path::Path>,
    server: Option<&str>,
) -> Vec<String> {
    let mut options = vec![
        "-v".to_string(),
        format!("{}:/etc/mcp-secure/policy.kdl:ro", policy_abs.display()),
    ];

    if let Some(log_dir) = log_dir_abs {
        options.push("-v".to_string());
        options.push(format!("{}:/var/log/mcp-secure", log_dir.display()));
    }

    if let Some(name) = server {
        options.push("-e".to_string());
        options.push(format!("MCP_WRIT_SERVER={name}"));
    }

    options
}

/// True when the image reference is pinned to an immutable digest.
pub fn image_ref_is_digest_pinned(image: &str) -> bool {
    image.contains("@sha256:")
}

struct TempPolicyDir {
    dir: PathBuf,
}

impl TempPolicyDir {
    fn new() -> Result<Self, std::io::Error> {
        let dir = crate::fspriv::create_private_tempdir("run-policy")?;
        Ok(Self { dir })
    }

    fn path(&self) -> &std::path::Path {
        &self.dir
    }
}

impl Drop for TempPolicyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Run a container image with policy and log volume mounts.
///
/// This function spawns a container using the resolved engine, mounts the policy
/// file and optional log directory, and transparently relays stdin/stdout between
/// the host and the container. On container exit, the process exits with the
/// container's exit code.
pub async fn run_image(options: &RunImageOptions) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Resolve container engine
    let engine = resolve_engine(options.engine)?;
    let engine_name = engine.name().to_string();

    if options.verbose {
        eprintln!("[run-image] engine: {}", engine_name);
    }

    if !options.allow_mutable_tag && !image_ref_is_digest_pinned(&options.image) {
        return Err(
            "refusing tag-only image reference; pin with @sha256:<digest> or pass --allow-mutable-tag"
                .into(),
        );
    }

    let meta = crate::container::inspect::inspect_image(engine.as_ref(), &options.image)
        .await
        .map_err(|e| format!("failed to inspect image: {e}"))?;
    let entrypoint = meta.entrypoint.as_deref().unwrap_or(&[]);
    if entrypoint.first().map(String::as_str) != Some("/usr/local/bin/mcp-secure-runner") {
        return Err(
            "image ENTRYPOINT[0] must be /usr/local/bin/mcp-secure-runner (wrap or containerize the image first)"
                .into(),
        );
    }

    // 2. Resolve policy file and generate self-contained KDL.
    //
    // The guest contract is a Linux workload: `mcp-secure-runner` is a
    // static ELF and the in-guest OS is Linux regardless of the CLI host,
    // so the policy is accepted against a Linux target here — never against
    // the host OS — and re-validated inside the guest by the runner.
    let guest_target = crate::execution::ExecutionTarget::linux_container(
        crate::execution::EngineName::from_name(&engine_name),
        // The substrate OS is not consulted for policy validation — the
        // guest contract is Linux regardless — so skip the `<cli> info`
        // probe and record it as unknown.
        None,
    );
    let policy_path = options
        .policy
        .as_deref()
        .unwrap_or_else(|| std::path::Path::new("./policy.kdl"));
    let policy_canonical = std::fs::canonicalize(policy_path)
        .map_err(|e| format!("policy file '{}': {e}", policy_path.display()))?;
    let base_dir = policy_canonical
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let bound = policy_export::load_and_bind_policy(
        &policy_canonical,
        options.server.as_deref(),
        &guest_target,
    )
    .map_err(|e| match e {
        PolicyBindError::Load(m) => {
            format!("failed to load policy '{}': {m}", policy_path.display())
        }
        PolicyBindError::Bind(m) => format!("failed to bind policy to server: {m}"),
    })?;
    let docker_hashes: Vec<_> = bound
        .hash_entries
        .iter()
        .filter(|e| e.hash_type == crate::policy::HashType::DockerManifest)
        .collect();
    if !docker_hashes.is_empty() {
        let actual = meta.digest.as_deref().unwrap_or("");
        if !docker_hashes.iter().any(|e| e.hash_value == actual) {
            return Err(format!(
                "image digest '{}' does not match any docker-manifest-hash in the policy",
                if actual.is_empty() {
                    "(missing)"
                } else {
                    actual
                }
            )
            .into());
        }
    }
    let self_contained_kdl = policy_export::inline_policy_to_kdl(&bound, base_dir, &guest_target)
        .map_err(|e| e.to_string())?;

    let temp_policy_dir =
        TempPolicyDir::new().map_err(|e| format!("failed to create temp dir for policy: {e}"))?;
    let temp_policy_path = temp_policy_dir.path().join("policy.kdl");
    std::fs::write(&temp_policy_path, self_contained_kdl)
        .map_err(|e| format!("failed to write self-contained policy: {e}"))?;
    let policy_abs = std::fs::canonicalize(&temp_policy_path)
        .map_err(|e| format!("failed to canonicalize temp policy path: {e}"))?;

    // 3. Resolve optional log directory
    let log_dir_abs = match &options.log_dir {
        Some(dir) => {
            let log_path = PathBuf::from(dir);
            if !log_path.exists() {
                std::fs::create_dir_all(&log_path)
                    .map_err(|e| format!("failed to create log dir '{}': {e}", dir))?;
            }
            Some(
                std::fs::canonicalize(&log_path)
                    .map_err(|e| format!("log directory '{}': {e}", dir))?,
            )
        }
        None => None,
    };

    // 4. Build run options
    let run_options = build_run_options(
        &policy_abs,
        log_dir_abs.as_deref(),
        options.server.as_deref(),
    );
    let options_refs: Vec<&str> = run_options.iter().map(|s| s.as_str()).collect();

    if options.verbose {
        eprintln!(
            "[run-image] {} run -i --rm {} {}",
            engine_name,
            run_options.join(" "),
            options.image
        );
    }

    // 5. Spawn container using engine.run abstraction
    let mut child = engine
        .run(&options.image, &options_refs, true)
        .await
        .map_err(|e| format!("failed to run container with {engine_name}: {e}"))?;

    // 6. Transparent stdin/stdout relay
    let child_stdin = child
        .stdin
        .take()
        .ok_or("failed to capture container stdin")?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or("failed to capture container stdout")?;

    // Relay host stdin → container stdin
    let stdin_handle = tokio::spawn(async move {
        let mut host_stdin = tokio::io::stdin();
        let mut sink = child_stdin;
        let _ = tokio::io::copy(&mut host_stdin, &mut sink).await;
    });

    // Relay container stdout → host stdout
    let stdout_handle = tokio::spawn(async move {
        let mut source = child_stdout;
        let mut host_stdout = tokio::io::stdout();
        let _ = tokio::io::copy(&mut source, &mut host_stdout).await;
    });

    // 7. Wait for container to exit
    let status = child
        .wait()
        .await
        .map_err(|e| format!("failed to wait for container: {e}"))?;

    // Clean up relay tasks
    stdin_handle.abort();
    let _ = stdout_handle.await;

    let code = status.code().unwrap_or(1);
    if code != 0 {
        Err(format!("container exited with code {}", code).into())
    } else {
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Resolve a path to an absolute path, using the current directory as base.
    fn resolve_path(path: &str) -> std::io::Result<PathBuf> {
        let p = PathBuf::from(path);
        if p.is_absolute() {
            Ok(p)
        } else {
            Ok(std::env::current_dir()?.join(p))
        }
    }

    fn production_run_args(
        image: &str,
        policy_abs: &std::path::Path,
        log_dir_abs: Option<&std::path::Path>,
    ) -> Vec<String> {
        let options = super::build_run_options(policy_abs, log_dir_abs, None);
        crate::container::engine::container_run_args(&options, image)
    }

    fn hardening_prefix() -> Vec<&'static str> {
        vec![
            "run",
            "-i",
            "--rm",
            "--no-healthcheck",
            "--entrypoint",
            "/usr/local/bin/mcp-secure-runner",
            "-e",
            "MCP_WRIT_ENV=",
            "-e",
            "MCP_WRIT_SKIP_SANDBOX=",
            "-e",
            "MCP_WRIT_SERVER=",
        ]
    }

    #[test]
    fn test_build_run_args_basic() {
        let policy = PathBuf::from("/tmp/policy.kdl");
        let args = production_run_args("my-image:latest", &policy, None);
        let mut expected: Vec<String> =
            hardening_prefix().into_iter().map(str::to_string).collect();
        expected.extend([
            "-v".into(),
            "/tmp/policy.kdl:/etc/mcp-secure/policy.kdl:ro".into(),
            "my-image:latest".into(),
        ]);
        assert_eq!(args, expected);
    }

    #[test]
    fn test_build_run_args_with_log_dir() {
        let policy = PathBuf::from("/etc/mcp/policy.kdl");
        let log_dir = PathBuf::from("/var/log/mcp");
        let args = production_run_args("secure-server:v2", &policy, Some(&log_dir));
        let mut expected: Vec<String> =
            hardening_prefix().into_iter().map(str::to_string).collect();
        expected.extend([
            "-v".into(),
            "/etc/mcp/policy.kdl:/etc/mcp-secure/policy.kdl:ro".into(),
            "-v".into(),
            "/var/log/mcp:/var/log/mcp-secure".into(),
            "secure-server:v2".into(),
        ]);
        assert_eq!(args, expected);
    }

    #[test]
    fn test_build_run_args_policy_mount_is_readonly() {
        let policy = PathBuf::from("/tmp/p.kdl");
        let args = production_run_args("img", &policy, None);
        let volume = args
            .iter()
            .find(|a| a.contains("policy.kdl") || a.contains("p.kdl"))
            .expect("policy volume");
        assert!(
            volume.ends_with(":ro"),
            "policy mount should be read-only: {volume}"
        );
    }

    #[test]
    fn test_build_run_args_image_is_last() {
        let policy = PathBuf::from("/tmp/p.kdl");
        let log_dir = PathBuf::from("/tmp/logs");
        let args = production_run_args("my-img", &policy, Some(&log_dir));
        assert_eq!(args.last().unwrap(), "my-img");
    }

    #[test]
    fn test_image_ref_is_digest_pinned() {
        assert!(image_ref_is_digest_pinned(
            "example.com/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ));
        assert!(!image_ref_is_digest_pinned("example.com/app:latest"));
        assert!(!image_ref_is_digest_pinned("example.com/app"));
    }

    #[test]
    fn test_resolve_path_absolute() {
        #[cfg(windows)]
        let abs_str = "C:\\absolute\\path";
        #[cfg(not(windows))]
        let abs_str = "/absolute/path";

        let result = resolve_path(abs_str);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from(abs_str));
    }

    #[test]
    fn test_resolve_path_relative() {
        let result = resolve_path("relative/path");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(resolved.is_absolute());
        assert!(resolved.ends_with("relative/path"));
    }
}
