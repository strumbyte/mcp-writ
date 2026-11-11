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

fn member<'text, 'raw>(
    v: nojson::RawJsonValue<'text, 'raw>,
    name: &str,
) -> nojson::RawJsonValue<'text, 'raw> {
    v.to_member(name).unwrap().required().unwrap()
}

fn pinned_image_options() -> RunImageOptions {
    RunImageOptions {
        engine: Some(EngineKind::Docker),
        isolation: None,
        image: "img@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            .to_string(),
        policy: None,
        log_dir: None,
        verbose: false,
        allow_mutable_tag: false,
        server: None,
        report: None,
        runner_binary: None,
        max_frame_bytes: None,
    }
}

/// A command-only isolation is refused before any engine or image
/// work — never an implicit fallback to a normal container, and the
/// refusal records itself on the report.
#[tokio::test]
async fn command_backend_refuses_image_before_engine_work() {
    let temp_dir = tempfile::tempdir().unwrap();
    let report_path = temp_dir.path().join("report.json");
    let options = RunImageOptions {
        isolation: Some(IsolationKind::WindowsSandbox),
        report: Some(report_path.clone()),
        ..pinned_image_options()
    };
    let err = run_image(&options)
        .await
        .expect_err("windows-sandbox is refused");
    assert!(err.to_string().contains("windows-sandbox"), "got: {err}");
    assert!(
        err.to_string().contains("requires a command payload"),
        "got: {err}"
    );

    // The failed report still carries the configured isolation and
    // shows the backend never confirmed it.
    let json = std::fs::read_to_string(&report_path).unwrap();
    let parsed = nojson::RawJson::parse(&json).unwrap();
    let root = parsed.value();
    let isolation = member(root, "isolation");
    assert_eq!(
        member(isolation, "configured").as_string_str().unwrap(),
        "windows-sandbox"
    );
    assert!(member(isolation, "verified").kind().is_null());
    assert!(member(isolation, "unit").kind().is_null());
    assert_eq!(
        member(root, "result").to_object().unwrap().count(),
        3,
        "status/detail/exit_code"
    );
}

/// The refusal identifies the command-only backend to the caller.
#[tokio::test]
async fn command_backend_image_refusal_identifies_backend() {
    let kind = IsolationKind::WindowsSandbox;
    let options = RunImageOptions {
        isolation: Some(kind),
        ..pinned_image_options()
    };
    let err = run_image(&options).await.expect_err("refuses");
    assert!(
        err.to_string().contains(kind.name()),
        "kind {}: {err}",
        kind.name()
    );
}

/// `hyperv` is implemented — it passes the "not implemented" gate.
/// On a non-Windows host the declared-capability gate refuses it
/// before any engine work (the substrate is Hyper-V on a Windows
/// docker daemon); on Windows it proceeds to engine resolution, so
/// the failure — if any — is downstream of the isolation gate
/// (docker absent, image foreign, or the guest-build gate).
#[tokio::test]
async fn hyperv_isolation_passes_the_implemented_gate() {
    let temp_dir = tempfile::tempdir().unwrap();
    let report_path = temp_dir.path().join("report.json");
    let options = RunImageOptions {
        isolation: Some(IsolationKind::HyperV),
        engine: Some(EngineKind::Docker),
        report: Some(report_path.clone()),
        ..pinned_image_options()
    };
    let err = run_image(&options).await.expect_err(
        "this test does not supply a launchable hyperv environment — the \
         run must fail somewhere after the implemented gate",
    );
    assert!(
        !err.to_string().contains("not implemented in this build"),
        "hyperv is implemented — it must not refuse as unimplemented: {err}"
    );
    if cfg!(target_os = "windows") {
        // Past the gate the run proceeds to engine resolution and
        // image/policy work — whatever fails there is a real
        // prerequisite, not an alias to the OCI container path.
        assert!(
            !err.to_string().contains("not supported on this host OS"),
            "the declared-capability gate only refuses off-Windows: {err}"
        );
    } else {
        assert!(
            err.to_string().contains("not supported on this host OS"),
            "hyperv needs a Windows host: {err}"
        );
    }
    // Either way the refusal is recorded: configured hyperv, never
    // verified (the backend never got to confirm).
    let json = std::fs::read_to_string(&report_path).unwrap();
    let parsed = nojson::RawJson::parse(&json).unwrap();
    let isolation = member(parsed.value(), "isolation");
    assert_eq!(
        member(isolation, "configured").as_string_str().unwrap(),
        "hyperv"
    );
    assert!(member(isolation, "verified").kind().is_null());
}

/// `apple-container` is implemented — it passes the "not
/// implemented" gate. On a non-macOS host the declared-capability
/// gate refuses it before any driver work (the substrate is a
/// macOS-only Virtualization.framework product); on macOS it
/// proceeds to driver resolution, so the failure — if any — is
/// downstream of the isolation gate (the `container` CLI absent, the
/// apiserver stopped, or the image foreign).
#[tokio::test]
async fn apple_isolation_passes_the_implemented_gate() {
    let temp_dir = tempfile::tempdir().unwrap();
    let report_path = temp_dir.path().join("report.json");
    let options = RunImageOptions {
        isolation: Some(IsolationKind::AppleContainer),
        engine: None, // the substrate's own `container` CLI drives it
        report: Some(report_path.clone()),
        ..pinned_image_options()
    };
    let err = run_image(&options).await.expect_err(
        "this test does not supply a launchable apple environment — the \
         run must fail somewhere after the implemented gate",
    );
    assert!(
        !err.to_string().contains("not implemented in this build"),
        "apple-container is implemented — it must not refuse as \
         unimplemented: {err}"
    );
    if cfg!(target_os = "macos") {
        // Past the gate the run proceeds to driver resolution and
        // image/policy work — whatever fails there is a real
        // prerequisite, not an alias to the OCI container path.
        assert!(
            !err.to_string().contains("not supported on this host OS"),
            "the declared-capability gate only refuses off-macOS: {err}"
        );
    } else {
        assert!(
            err.to_string().contains("not supported on this host OS"),
            "apple-container needs a macOS host: {err}"
        );
    }
    // Either way the refusal is recorded: configured apple-container,
    // never verified (the backend never got to confirm).
    let json = std::fs::read_to_string(&report_path).unwrap();
    let parsed = nojson::RawJson::parse(&json).unwrap();
    let isolation = member(parsed.value(), "isolation");
    assert_eq!(
        member(isolation, "configured").as_string_str().unwrap(),
        "apple-container"
    );
    assert!(member(isolation, "verified").kind().is_null());
}

/// `--engine` does not apply to a substrate-driven isolation — the
/// flag is refused rather than silently ignored, so a user who
/// passes `--engine podman --isolation apple-container` cannot
/// believe podman launched anything. (On non-macOS hosts the
/// host-OS gate still refuses first.)
#[tokio::test]
async fn apple_isolation_refuses_an_engine_flag() {
    let options = RunImageOptions {
        isolation: Some(IsolationKind::AppleContainer),
        engine: Some(EngineKind::Docker),
        ..pinned_image_options()
    };
    let err = run_image(&options).await.expect_err("refuses");
    if cfg!(target_os = "macos") {
        assert!(
            err.to_string().contains("--engine"),
            "--engine must be refused explicitly on a macOS host: {err}"
        );
    } else {
        assert!(
            err.to_string().contains("not supported on this host OS"),
            "the host-OS gate precedes the engine flag: {err}"
        );
    }
}

/// `kata` is implemented — it passes the "not implemented" gate. On
/// a non-Linux host the declared-capability gate refuses it before
/// any engine work (the validated stack needs dockerd + KVM); on
/// Linux it proceeds to engine resolution, so the failure — if any —
/// is downstream of the isolation gate (engine missing, image
/// absent, or the kata runtime unregistered).
#[tokio::test]
async fn kata_isolation_passes_the_implemented_gate() {
    let temp_dir = tempfile::tempdir().unwrap();
    let report_path = temp_dir.path().join("report.json");
    let options = RunImageOptions {
        isolation: Some(IsolationKind::Kata),
        engine: Some(EngineKind::Docker),
        report: Some(report_path.clone()),
        ..pinned_image_options()
    };
    let err = run_image(&options).await.expect_err(
        "this test does not supply a launchable kata environment — the \
         run must fail somewhere after the implemented gate",
    );
    assert!(
        !err.to_string().contains("not implemented in this build"),
        "kata is implemented — it must not refuse as unimplemented: {err}"
    );
    if cfg!(target_os = "linux") {
        // Past the gate the run proceeds to engine resolution and
        // image/policy work — whatever fails there is a real
        // prerequisite, not an alias to container.
        assert!(
            !err.to_string().contains("not supported on this host OS"),
            "the declared-capability gate only refuses off-Linux: {err}"
        );
    } else {
        assert!(
            err.to_string().contains("not supported on this host OS"),
            "kata needs a Linux host: {err}"
        );
    }
    // Either way the refusal is recorded: configured kata, never
    // verified (the backend never got to confirm).
    let json = std::fs::read_to_string(&report_path).unwrap();
    let parsed = nojson::RawJson::parse(&json).unwrap();
    let isolation = member(parsed.value(), "isolation");
    assert_eq!(
        member(isolation, "configured").as_string_str().unwrap(),
        "kata"
    );
    assert!(member(isolation, "verified").kind().is_null());
}

/// `container` (the default) does not refuse at the isolation gate —
/// the run proceeds to engine resolution and fails there on a host
/// without docker, which proves the isolation check passed it
/// through rather than rejecting it.
#[tokio::test]
async fn default_container_isolation_passes_the_gate() {
    let options = RunImageOptions {
        engine: Some(EngineKind::Buildah),
        ..pinned_image_options()
    };
    let err = run_image(&options).await.expect_err("buildah cannot run");
    // The refusal is the engine's, not the isolation gate's.
    assert!(
        !err.to_string().contains("not implemented in this build"),
        "isolation gate must pass container through, got: {err}"
    );
}

/// The resolved runner source sits outside the log share when its
/// configured spelling traverses a share-local symlink — the spelled
/// comparison must still refuse, since the workload can repoint the
/// link and seize the location the next launch resolves.
#[cfg(unix)]
#[test]
fn log_share_refuses_runner_spelled_through_share_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let share = dir.path().join("share");
    let real = dir.path().join("real");
    std::fs::create_dir_all(&share).unwrap();
    std::fs::create_dir_all(&real).unwrap();
    let runner = real.join("mcp-secure-runner");
    std::fs::write(&runner, b"#!").unwrap();
    std::os::unix::fs::symlink(&real, share.join("runner-parent")).unwrap();
    let spelled = share.join("runner-parent").join("mcp-secure-runner");
    let log_resolved = std::fs::canonicalize(&share).unwrap();

    // Sanity: the spelled path resolves outside the share — only the
    // spelled-chain comparison catches the overlap.
    let resolved = std::fs::canonicalize(&spelled).unwrap();
    assert!(!resolved.starts_with(&log_resolved));
    assert!(
        log_share_conflicts_artifact(&log_resolved, &spelled),
        "a runner spelled through a share-local symlink must conflict"
    );
    // The real object itself is honestly outside the share — clean.
    assert!(!log_share_conflicts_artifact(&log_resolved, &runner));
}

/// The plain overlap directions still hold: an artifact inside the
/// share refuses, an unrelated path stays clean, and a share inside a
/// sensitive ancestor refuses.
#[test]
fn log_share_overlap_directions() {
    let dir = tempfile::tempdir().unwrap();
    let share = dir.path().join("share");
    std::fs::create_dir_all(&share).unwrap();
    let log_resolved = std::fs::canonicalize(&share).unwrap();

    assert!(log_share_conflicts_artifact(
        &log_resolved,
        &share.join("policy.kdl")
    ));
    assert!(log_share_conflicts_artifact(&log_resolved, dir.path()));
    assert!(!log_share_conflicts_artifact(
        &log_resolved,
        &dir.path().join("elsewhere")
    ));
}

/// An unavailable `current_exe` (`/proc/self/exe` unreadable, a
/// renamed-away image) must abort the launch — the overlap check
/// cannot prove the running image is outside the share.
#[test]
fn current_exe_failure_aborts_launch() {
    let mut sensitive = Vec::new();
    let err = push_current_exe(
        &mut sensitive,
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no /proc/self/exe",
        )),
    )
    .expect_err("an unavailable executable path must abort");
    assert!(err.contains("cannot establish"), "{err}");
    assert!(sensitive.is_empty());

    // The success path keeps the resolved image in the sensitive set.
    push_current_exe(&mut sensitive, std::env::current_exe()).unwrap();
    assert_eq!(sensitive.len(), 1);
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
