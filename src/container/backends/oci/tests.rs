use super::*;
use crate::container::backends::ShareMount;
use crate::container::engine::{BuildahEngine, ContainerEngine, WslcEngine, container_run_args};
use crate::execution::{TargetArch, TargetOs};

fn spec(image: &str) -> LaunchSpec {
    LaunchSpec {
        isolation: IsolationKind::Container,
        image: Some(image.to_string()),
        command: None,
        guest_os: TargetOs::Linux,
        guest_arch: TargetArch::X86_64,
        image_os_version: None,
        shares: Vec::new(),
        env: Vec::new(),
        unit_id_file: None,
        unit_name: None,
    }
}

fn oci() -> OciBackend {
    // `check` never spawns the engine CLI — the buildah unit is a
    // convenient stand-in engine.
    OciBackend::new(Box::new(BuildahEngine::for_test("buildah")))
}

// -- typed launch conditions → arguments ----------------------------

fn production_run_args(
    image: &str,
    policy_abs: &std::path::Path,
    log_dir_abs: Option<&std::path::Path>,
) -> Vec<String> {
    let mut spec = spec(image);
    spec.shares.push(ShareMount {
        host: policy_abs.to_path_buf(),
        guest: "/etc/mcp-secure/policy.kdl".to_string(),
        writable: false,
        pin: None,
    });
    if let Some(dir) = log_dir_abs {
        spec.shares.push(ShareMount {
            host: dir.to_path_buf(),
            guest: "/var/log/mcp-secure".to_string(),
            writable: true,
            pin: None,
        });
    }
    let options = spec_run_options(&spec);
    container_run_args(&options, image)
}

fn hardening_prefix() -> Vec<&'static str> {
    vec![
        "run",
        "-i",
        "--rm",
        "--no-healthcheck",
        "-e",
        "MCP_WRIT_ENV=",
        "-e",
        "MCP_WRIT_SKIP_SANDBOX=",
        "-e",
        "MCP_WRIT_SERVER=",
        "-e",
        "MCP_WRIT_FAIL_ON=",
        "-e",
        "MCP_WRIT_LAUNCH_ID=",
        "-e",
        "MCP_WRIT_REPORT_OUT=",
        "-e",
        "MCP_WRIT_PROBE_LANDLOCK_ABI=",
        "-e",
        "MCP_WRIT_MAX_FRAME_BYTES=",
        "-e",
        "MCP_WRIT_POLICY_PATH=",
        "-e",
        "MCP_WRIT_AUDIT_DIR=",
        "-e",
        "MCP_WRIT_TEMP_DIR=",
        "-e",
        "MCP_WRIT_ALLOW_REPLACEABLE_PATHS=",
    ]
}

/// A canonicalized verbatim `\\?\C:\…` host path must render for
/// `-v` without the prefix — the engine's volume parser refuses the
/// verbatim spelling (`invalid volume specification`). Plain and
/// non-Windows paths pass through unchanged.
#[test]
fn share_host_path_strips_the_verbatim_prefix() {
    assert_eq!(
        host_share_path(std::path::Path::new(r"\\?\C:\pol\policydir")),
        r"C:\pol\policydir"
    );
    assert_eq!(
        host_share_path(std::path::Path::new(r"\\?\UNC\srv\share\dir")),
        r"\\srv\share\dir"
    );
    assert_eq!(
        host_share_path(std::path::Path::new(r"C:\pol\policydir")),
        r"C:\pol\policydir"
    );
    assert_eq!(
        host_share_path(std::path::Path::new("/tmp/policy")),
        "/tmp/policy"
    );
}

/// The spec-rendered `--entrypoint` pair — the guest contract's
/// runner path for the spec's Linux guest.
fn entrypoint_option() -> Vec<String> {
    vec![
        "--entrypoint".to_string(),
        crate::container::guest_layout::LINUX
            .runner_path
            .to_string(),
    ]
}

#[test]
fn spec_args_basic() {
    let spec_args = {
        let mut spec = spec("my-image:latest");
        spec.shares.push(ShareMount {
            host: PathBuf::from("/tmp/policy.kdl"),
            guest: "/etc/mcp-secure/policy.kdl".to_string(),
            writable: false,
            pin: None,
        });
        spec
    };
    let args = container_run_args(&spec_run_options(&spec_args), "my-image:latest");
    let mut expected: Vec<String> = hardening_prefix().into_iter().map(str::to_string).collect();
    expected.extend(entrypoint_option());
    expected.extend([
        "-v".into(),
        "/tmp/policy.kdl:/etc/mcp-secure/policy.kdl:ro".into(),
        "my-image:latest".into(),
    ]);
    assert_eq!(args, expected);
}

#[test]
fn spec_args_with_log_dir() {
    let policy = PathBuf::from("/etc/mcp/policy.kdl");
    let log_dir = PathBuf::from("/var/log/mcp");
    let args = production_run_args("secure-server:v2", &policy, Some(&log_dir));
    let mut expected: Vec<String> = hardening_prefix().into_iter().map(str::to_string).collect();
    expected.extend(entrypoint_option());
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
fn spec_args_with_report_share_env_and_cidfile() {
    let mut spec = spec("img");
    spec.shares.push(ShareMount {
        host: PathBuf::from("/tmp/policy.kdl"),
        guest: "/etc/mcp-secure/policy.kdl".to_string(),
        writable: false,
        pin: None,
    });
    spec.shares.push(ShareMount {
        host: PathBuf::from("/tmp/mcp-report"),
        guest: crate::container::guest_report::GUEST_REPORT_MOUNT_PATH.to_string(),
        writable: true,
        pin: None,
    });
    spec.env.push((
        crate::container::guest_report::REPORT_OUT_ENV.to_string(),
        crate::container::guest_report::GUEST_REPORT_MOUNT_PATH.to_string(),
    ));
    spec.env
        .push(("MCP_WRIT_SERVER".to_string(), "srv".to_string()));
    let launch_id = uuid::Uuid::nil();
    spec.env
        .push(("MCP_WRIT_LAUNCH_ID".to_string(), launch_id.to_string()));
    spec.unit_id_file = Some(PathBuf::from("/tmp/launch/container.id"));
    let args = container_run_args(&spec_run_options(&spec), "img");
    assert!(
        args.iter()
            .any(|a| a == "/tmp/mcp-report:/run/mcp-secure/report")
    );
    assert!(
        args.iter()
            .any(|a| a == "MCP_WRIT_REPORT_OUT=/run/mcp-secure/report")
    );
    assert!(args.iter().any(|a| a == "MCP_WRIT_SERVER=srv"));
    assert!(
        args.iter()
            .any(|a| a == &format!("MCP_WRIT_LAUNCH_ID={launch_id}"))
    );
    let cid_pos = args.iter().position(|a| a == "--cidfile").unwrap();
    assert_eq!(args[cid_pos + 1], "/tmp/launch/container.id");
}

#[test]
fn spec_args_policy_share_is_readonly() {
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

/// A caller-known `--name` is emitted when the spec carries one —
/// teardown can then name the unit even when the cidfile never
/// published the substrate id.
#[test]
fn spec_args_emit_caller_unit_name() {
    let mut s = spec("img");
    s.unit_name = Some("mcp-writ-deadbeef".to_string());
    let args = container_run_args(&spec_run_options(&s), "img");
    let pos = args.iter().position(|a| a == "--name").unwrap();
    assert_eq!(args[pos + 1], "mcp-writ-deadbeef");
    let without = container_run_args(&spec_run_options(&spec("img")), "img");
    assert!(!without.iter().any(|a| a == "--name"));
}

/// A stub engine for the share-swap tests: `run` performs the
/// attacker's filesystem move — the same instant the real substrate
/// would resolve the spelled mount source — then spawns a real
/// child so the launch proceeds to the post-attach checks.
/// `program` points at a script answering every lifecycle call with
/// an absent-unit marker so refused-launch teardown stays fast.
/// `#[allow(dead_code)]`: the enum is used only by the unix
/// share-swap tests, and `SwapBack`/`AncestorSwap` only by the
/// Linux launch-window ones.
#[allow(dead_code)]
enum SwapMode {
    /// Leave the path untouched — the clean control.
    None,
    /// Move the verified dir away and leave a replacement in place.
    Swap,
    /// Move away, replace, then restore — the path looks untouched
    /// afterwards; only the launch-window watch sees the swap.
    SwapBack,
    /// Repoint an ancestor above the share's parent: rename the
    /// ancestor directory away and rebuild the spelled path inside
    /// a fresh one — a parent-only watch would follow the moved
    /// object and never see it.
    AncestorSwap,
}

/// `#[allow(dead_code)]`: constructed only by the unix share-swap
/// tests — Windows compiles the fixture but never runs one.
#[allow(dead_code)]
struct SwapEngine {
    dir: PathBuf,
    backup: PathBuf,
    cli: PathBuf,
    mode: SwapMode,
}

/// `#[allow(dead_code)]`: `new` is called only from the unix tests.
#[allow(dead_code)]
impl SwapEngine {
    fn new(dir: PathBuf, backup: PathBuf, stage: &std::path::Path, mode: SwapMode) -> Self {
        let cli = stage.join("stub-engine.sh");
        // `inspect` resolves the unit until `rm` records it gone —
        // the take_stdio readiness probe sees an existing unit, and
        // refused-launch teardown confirms removal fast.
        std::fs::write(
            &cli,
            format!(
                "#!/bin/sh\n\
                 if [ \"$1\" = \"rm\" ]; then touch \"{0}/unit-gone\"; exit 0; fi\n\
                 if [ \"$1\" = \"inspect\" ] && [ ! -f \"{0}/unit-gone\" ]; then exit 0; fi\n\
                 echo 'Error: No such object: fake' >&2\n\
                 exit 1\n",
                stage.display()
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cli, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self {
            dir,
            backup,
            cli,
            mode,
        }
    }
}

impl ContainerEngine for SwapEngine {
    fn name(&self) -> &str {
        "docker"
    }
    fn program(&self) -> &str {
        self.cli.to_str().unwrap()
    }
    fn build<'a>(
        &'a self,
        _d: &'a str,
        _t: &'a str,
        _c: &'a str,
        _n: bool,
    ) -> crate::container::engine::BoxFuture<'a, Result<(), crate::container::engine::EngineError>>
    {
        unreachable!("the swap engine never builds")
    }
    fn inspect<'a>(
        &'a self,
        _i: &'a str,
    ) -> crate::container::engine::BoxFuture<
        'a,
        Result<String, crate::container::engine::EngineError>,
    > {
        unreachable!("the swap engine never inspects images")
    }
    fn tag<'a>(
        &'a self,
        _s: &'a str,
        _t: &'a str,
    ) -> crate::container::engine::BoxFuture<'a, Result<(), crate::container::engine::EngineError>>
    {
        unreachable!("the swap engine never tags")
    }
    fn remove_image<'a>(
        &'a self,
        _i: &'a str,
    ) -> crate::container::engine::BoxFuture<'a, Result<(), crate::container::engine::EngineError>>
    {
        unreachable!("the swap engine never removes images")
    }
    fn info<'a>(
        &'a self,
    ) -> crate::container::engine::BoxFuture<
        'a,
        Result<String, crate::container::engine::EngineError>,
    > {
        unreachable!("the swap engine never reports info")
    }
    fn run<'a>(
        &'a self,
        _i: &'a str,
        _a: &'a [&'a str],
        _s: bool,
    ) -> crate::container::engine::BoxFuture<
        'a,
        Result<tokio::process::Child, crate::container::engine::EngineError>,
    > {
        Box::pin(async move {
            // The filesystem move lands exactly where the real
            // daemon would resolve the mount spelling — after the
            // pre-launch verification, before the session proceeds.
            match self.mode {
                SwapMode::None => {}
                SwapMode::Swap => {
                    std::fs::rename(&self.dir, &self.backup).unwrap();
                    std::fs::create_dir(&self.dir).unwrap();
                }
                SwapMode::SwapBack => {
                    std::fs::rename(&self.dir, &self.backup).unwrap();
                    std::fs::create_dir(&self.dir).unwrap();
                    std::fs::remove_dir(&self.dir).unwrap();
                    std::fs::rename(&self.backup, &self.dir).unwrap();
                }
                SwapMode::AncestorSwap => {
                    // `dir` is <ancestor>/<mid>/<leaf>: move the
                    // ancestor away, rebuild the whole spelling
                    // inside a replacement ancestor, then restore
                    // the original — the leaf's parent object is
                    // never touched and the pinned ancestor is back
                    // in place afterwards, so only the component
                    // watch (not the identity re-check) can see it.
                    let leaf = self.dir.file_name().unwrap().to_os_string();
                    let mid_dir = self.dir.parent().unwrap();
                    let mid = mid_dir.file_name().unwrap().to_os_string();
                    let ancestor = mid_dir.parent().unwrap();
                    let escaped = ancestor.parent().unwrap().join(format!(
                        "{}-bak",
                        ancestor.file_name().unwrap().to_string_lossy()
                    ));
                    std::fs::rename(ancestor, &escaped).unwrap();
                    std::fs::create_dir_all(ancestor.join(&mid).join(&leaf)).unwrap();
                    std::fs::remove_dir_all(ancestor).unwrap();
                    std::fs::rename(&escaped, ancestor).unwrap();
                }
            }
            tokio::process::Command::new("sleep")
                .arg("30")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| crate::container::engine::EngineError::CommandFailed {
                    engine: "docker".to_string(),
                    message: format!("stub run spawn failed: {e}"),
                })
        })
    }
    fn is_available(&self) -> bool {
        true
    }
}

/// A share path swapped between the pre-launch verification and the
/// substrate's mount resolution must not be trusted: `run` performs
/// the replacement mid-launch, and the post-create re-check refuses
/// the session rather than letting the substituted directory stand
/// in as the mounted share.
#[cfg(unix)]
#[tokio::test]
async fn launch_refuses_share_replaced_before_mount() {
    let stage = tempfile::tempdir().unwrap();
    let dir = stage.path().join("logs");
    let backup = stage.path().join("logs-backup");
    std::fs::create_dir(&dir).unwrap();
    let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

    let mut s = spec("img");
    s.shares.push(ShareMount {
        host: dir.clone(),
        guest: "/var/log/mcp-secure".to_string(),
        writable: true,
        pin: Some(identity),
    });
    s.unit_name = Some("mcp-writ-test-share-swap".to_string());

    let backend = OciBackend::new(Box::new(SwapEngine::new(
        dir,
        backup,
        stage.path(),
        SwapMode::Swap,
    )));
    let outcome = backend.launch(&s).await;
    assert!(
        outcome.is_err(),
        "a share replaced before the mount resolves must refuse the launch"
    );
}

/// The attack the path re-check cannot see: the verified dir is
/// replaced and then restored inside the launch window, so the
/// spelled path names the right object again by the time a second
/// path check runs. The parent-directory watch still recorded the
/// move/create events — the launch must refuse.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn launch_refuses_share_swapped_back_in_window() {
    let stage = tempfile::tempdir().unwrap();
    let dir = stage.path().join("logs");
    let backup = stage.path().join("logs-backup");
    std::fs::create_dir(&dir).unwrap();
    let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

    let mut s = spec("img");
    s.shares.push(ShareMount {
        host: dir.clone(),
        guest: "/var/log/mcp-secure".to_string(),
        writable: true,
        pin: Some(identity),
    });
    s.unit_name = Some("mcp-writ-test-share-swapback".to_string());

    let backend = OciBackend::new(Box::new(SwapEngine::new(
        dir,
        backup,
        stage.path(),
        SwapMode::SwapBack,
    )));
    let outcome = backend.launch(&s).await;
    assert!(
        outcome.is_err(),
        "a repoint-and-restore inside the launch window must refuse"
    );
}

/// An ancestor repoint-and-restore: the directory above the
/// share's parent is swapped wholesale and then put back, so both
/// the leaf's own parent object and the pinned ancestor are in
/// place afterwards — the identity re-check sees the original,
/// and only the component watch's event stream can catch the
/// repoint. The launch must refuse.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn launch_refuses_share_ancestor_repoint() {
    let stage = tempfile::tempdir().unwrap();
    let dir = stage.path().join("outer").join("inner").join("logs");
    std::fs::create_dir_all(&dir).unwrap();
    let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

    let mut s = spec("img");
    s.shares.push(ShareMount {
        host: dir.clone(),
        guest: "/var/log/mcp-secure".to_string(),
        writable: true,
        pin: Some(identity),
    });
    s.unit_name = Some("mcp-writ-test-share-ancestor".to_string());

    let backend = OciBackend::new(Box::new(SwapEngine::new(
        dir,
        stage.path().join("unused"),
        stage.path(),
        SwapMode::AncestorSwap,
    )));
    let outcome = backend.launch(&s).await;
    assert!(
        outcome.is_err(),
        "an ancestor repoint inside the launch window must refuse"
    );
}

/// A drain that already fired must stay fired: the first failure
/// is retained so a later drain cannot consume the events and then
/// report the window clean.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn share_watch_drain_retains_first_failure() {
    let stage = tempfile::tempdir().unwrap();
    let dir = stage.path().join("logs");
    std::fs::create_dir(&dir).unwrap();
    let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

    let mut s = spec("img");
    s.shares.push(ShareMount {
        host: dir.clone(),
        guest: "/var/log/mcp-secure".to_string(),
        writable: true,
        pin: Some(identity),
    });

    let mut watch = crate::container::backends::begin_share_pin_watch(&s).unwrap();
    assert!(watch.drain().is_ok(), "a clean window drains");
    std::fs::rename(&dir, stage.path().join("logs-moved")).unwrap();
    assert!(watch.drain().is_err(), "the repoint must refuse");
    assert!(
        watch.drain().is_err(),
        "the consumed failure must stay refused on the next drain"
    );
}

/// The control for the swap tests: with the pinned dir left alone,
/// the launch proceeds — the arming/verifying/draining pipeline
/// itself must not refuse a clean window — and the final drain
/// inside `take_stdio` hands the pipes over.
#[cfg(unix)]
#[tokio::test]
async fn launch_with_stable_pinned_share_proceeds() {
    let stage = tempfile::tempdir().unwrap();
    let dir = stage.path().join("logs");
    let backup = stage.path().join("logs-backup");
    std::fs::create_dir(&dir).unwrap();
    let (_check, identity) = crate::fspriv::open_dir_pinned(&dir).unwrap();

    let mut s = spec("img");
    s.shares.push(ShareMount {
        host: dir.clone(),
        guest: "/var/log/mcp-secure".to_string(),
        writable: true,
        pin: Some(identity),
    });
    s.unit_name = Some("mcp-writ-test-share-stable".to_string());

    let backend = OciBackend::new(Box::new(SwapEngine::new(
        dir,
        backup,
        stage.path(),
        SwapMode::None,
    )));
    let mut handle = backend.launch(&s).await.unwrap();
    handle
        .take_stdio()
        .expect("a clean launch window must hand over stdio");
    handle.cleanup().await.unwrap();
}

#[test]
fn spec_args_image_is_last() {
    let policy = PathBuf::from("/tmp/p.kdl");
    let log_dir = PathBuf::from("/tmp/logs");
    let args = production_run_args("my-img", &policy, Some(&log_dir));
    assert_eq!(args.last().unwrap(), "my-img");
}

// -- check: spec combinations the OCI contract rejects --------------

#[tokio::test]
async fn oci_check_confirms_container() {
    let backend = oci();
    let check = backend.check(&spec("img")).await.expect("check passes");
    assert_eq!(check.verified, IsolationKind::Container);
    assert_eq!(check.unit, IsolationUnit::Container);
    assert_eq!(
        check.detail.as_deref(),
        Some("engine: buildah"),
        "the engine identity is part of the confirmation detail"
    );
}

#[tokio::test]
async fn oci_check_rejects_foreign_isolation() {
    let backend = oci();
    let mut spec = spec("img");
    spec.isolation = IsolationKind::Kata;
    let err = backend.check(&spec).await.unwrap_err();
    match err {
        BackendError::Unsupported(msg) => {
            assert!(msg.contains("kata"), "got: {msg}");
        }
        other => panic!("expected Unsupported, got: {other}"),
    }
}

#[tokio::test]
async fn oci_check_rejects_argv_only_workload() {
    let backend = oci();
    let mut spec = spec("img");
    spec.image = None;
    let err = backend.check(&spec).await.unwrap_err();
    assert!(matches!(err, BackendError::Unsupported(_)), "got: {err}");
}

/// The wslc session VM runs the host's architecture — a
/// foreign-arch spec refuses at `check` (no binfmt bridge in the
/// validated contract), and a host-arch spec's detail names the
/// shared session VM rather than implying a dedicated boundary.
#[tokio::test]
async fn oci_check_wslc_gates_arch_and_marks_shared_session() {
    let backend = OciBackend::new(Box::new(WslcEngine::for_test("wslc")));
    let mut s = spec("img");
    s.guest_arch = TargetArch::host();
    let check = backend.check(&s).await.expect("host arch passes");
    let detail = check.detail.expect("wslc records a detail");
    assert!(detail.contains("wslc"), "{detail}");
    assert!(
        detail.contains("shared session VM"),
        "unit=container must not imply a dedicated VM: {detail}"
    );
    let foreign = match TargetArch::host() {
        TargetArch::X86_64 => TargetArch::Aarch64,
        _ => TargetArch::X86_64,
    };
    s.guest_arch = foreign.clone();
    let err = backend.check(&s).await.unwrap_err();
    match err {
        BackendError::Unsupported(msg) => {
            assert!(msg.contains("session VM"), "{msg}");
            assert!(msg.contains(foreign.name()), "{msg}");
        }
        other => panic!("expected Unsupported, got: {other}"),
    }
}

/// The OCI runner contract is a Linux guest — the fixed
/// `--entrypoint /usr/local/bin/mcp-secure-runner` must never be
/// reused for a Windows guest.
#[tokio::test]
async fn oci_check_rejects_non_linux_guest() {
    let backend = oci();
    let mut spec = spec("img");
    spec.guest_os = TargetOs::Windows;
    let err = backend.check(&spec).await.unwrap_err();
    match err {
        BackendError::Unsupported(msg) => {
            assert!(msg.contains("windows"), "got: {msg}");
            assert!(msg.contains("mcp-secure-runner"), "got: {msg}");
        }
        other => panic!("expected Unsupported, got: {other}"),
    }
}

#[test]
fn oci_capabilities_declared() {
    let caps = oci().capabilities();
    assert!(caps.oci_image);
    assert!(!caps.argv_command);
    assert!(caps.stdio_pipes);
    assert!(caps.terminate);
    assert!(caps.host_shares);
    assert!(caps.guest_os.contains(&TargetOs::Linux));
    assert!(!caps.guest_os.contains(&TargetOs::Windows));
}
