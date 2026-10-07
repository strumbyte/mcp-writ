//! Unit tests for the engine layer — kind parsing, shared argv/probe
//! helpers, per-engine identities, resolution, and error display.

use super::*;

// -- EngineKind::from_str -------------------------------------------------

#[test]
fn engine_kind_from_str_docker() {
    assert_eq!(EngineKind::from_str("docker").unwrap(), EngineKind::Docker);
    assert_eq!(EngineKind::from_str("Docker").unwrap(), EngineKind::Docker);
    assert_eq!(EngineKind::from_str("DOCKER").unwrap(), EngineKind::Docker);
}

#[test]
fn engine_kind_from_str_podman() {
    assert_eq!(EngineKind::from_str("podman").unwrap(), EngineKind::Podman);
    assert_eq!(EngineKind::from_str("Podman").unwrap(), EngineKind::Podman);
}

#[test]
fn engine_kind_from_str_buildah() {
    assert_eq!(
        EngineKind::from_str("buildah").unwrap(),
        EngineKind::Buildah
    );
    assert_eq!(
        EngineKind::from_str("BUILDAH").unwrap(),
        EngineKind::Buildah
    );
}

#[test]
fn engine_kind_from_str_invalid() {
    let err = EngineKind::from_str("containerd").unwrap_err();
    match err {
        EngineError::UnknownKind(s) => assert_eq!(s, "containerd"),
        other => panic!("expected UnknownKind, got: {other}"),
    }
}

#[test]
fn engine_kind_from_str_wslc_recognized_but_not_aliased() {
    // `wslc` parses — the vocabulary knows the candidate. WSLC's
    // `container.exe` alias stays a parse error: it is not the
    // wslc CLI name, and `container` belongs to Apple's driver.
    assert_eq!(EngineKind::from_str("wslc").unwrap(), EngineKind::Wslc);
    assert_eq!(EngineKind::from_str("WSLC").unwrap(), EngineKind::Wslc);
    assert!(matches!(
        EngineKind::from_str("container"),
        Err(EngineError::UnknownKind(_))
    ));
    assert!(matches!(
        EngineKind::from_str("wsl-containers"),
        Err(EngineError::UnknownKind(_))
    ));
}

// -- engine_info_os -------------------------------------------------

#[test]
fn engine_info_os_recognizes_apple_status_shape() {
    let status = r#"{"status":"running","host":{"architecture":"arm64"}}"#;
    assert_eq!(
        engine_info_os("container", status),
        Some(crate::execution::TargetOs::Linux)
    );
    // A foreign CLI's JSON without Apple's `status` member is not
    // the apple substrate — the OS stays unknown rather than guessed.
    assert_eq!(engine_info_os("container", r#"{"OSType":"linux"}"#), None);
    assert_eq!(engine_info_os("container", "not json"), None);
}

// -- Engine names ---------------------------------------------------------

#[test]
fn docker_engine_name() {
    assert_eq!(DockerEngine.name(), "docker");
}

#[test]
fn podman_engine_name() {
    assert_eq!(PodmanEngine.name(), "podman");
}

#[test]
fn buildah_engine_name() {
    assert_eq!(BuildahEngine.name(), "buildah");
}

// -- BuildahEngine::run returns Unsupported -------------------------------

#[tokio::test]
async fn buildah_run_returns_unsupported() {
    let engine = BuildahEngine;
    let result = engine.run("some-image:latest", &["--help"], false).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        EngineError::Unsupported(msg) => {
            assert!(msg.contains("buildah"), "message should mention buildah");
        }
        other => panic!("expected Unsupported, got: {other}"),
    }
}

// -- resolve_engine -------------------------------------------------------

#[test]
fn resolve_engine_explicit_docker() {
    // With availability check, result depends on environment.
    let result = resolve_engine(Some(EngineKind::Docker));
    match result {
        Ok(engine) => assert_eq!(engine.name(), "docker"),
        Err(EngineError::NotAvailable(name)) => assert_eq!(name, "docker"),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

#[test]
fn resolve_engine_explicit_podman() {
    let result = resolve_engine(Some(EngineKind::Podman));
    match result {
        Ok(engine) => assert_eq!(engine.name(), "podman"),
        Err(EngineError::NotAvailable(name)) => assert_eq!(name, "podman"),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

#[test]
fn resolve_engine_explicit_buildah() {
    let result = resolve_engine(Some(EngineKind::Buildah));
    match result {
        Ok(engine) => assert_eq!(engine.name(), "buildah"),
        Err(EngineError::NotAvailable(name)) => assert_eq!(name, "buildah"),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

// -- WslcEngine -------------------------------------------------------

/// The `<subcmd> -f df -t tag [--no-cache] ctx` argument order the
/// engine build impls share — `--no-cache` sits between the tag
/// and the context dir, and `bud` swaps the subcommand.
#[test]
fn image_build_args_place_no_cache_before_context() {
    assert_eq!(
        image_build_args("build", "df", "img:tag", "ctx", true),
        ["build", "-f", "df", "-t", "img:tag", "--no-cache", "ctx"]
    );
    assert_eq!(
        image_build_args("bud", "df", "img:tag", "ctx", false),
        ["bud", "-f", "df", "-t", "img:tag", "ctx"]
    );
}

/// A stub CLI printing `body`'s command output — `.cmd` on Windows
/// (std spawns batch files through cmd.exe), a shell script
/// elsewhere.
fn cli_stub(body: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "mcp_writ_cli_stub_{}",
        uuid::Uuid::now_v7().simple()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    #[cfg(windows)]
    let (name, script) = ("stub.cmd", format!("{body}\r\n"));
    #[cfg(not(windows))]
    let (name, script) = ("stub.sh", format!("#!/bin/sh\n{body}\n"));
    let path = dir.join(name);
    std::fs::write(&path, script).unwrap();
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

/// A wedged CLI is bounded, not waited on forever —
/// `is_available`/`resolve_engine` are sync callers, so the probe
/// polls `try_wait` and kills the child at the deadline rather than
/// parking on a hung process.
#[test]
fn bounded_cli_output_times_out_a_wedged_cli() {
    // timeout.exe needs a console stdin — the bounded spawn pipes it,
    // so the stub must wedge without reading input (ping's ~1s/send
    // interval gives a console-free hang on any Windows image).
    #[cfg(windows)]
    let stub = cli_stub("@ping -n 30 127.0.0.1 >nul");
    #[cfg(not(windows))]
    let stub = cli_stub("sleep 60");
    let started = std::time::Instant::now();
    let result = bounded_cli_output(stub.to_str().unwrap(), &["--version"]);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "a wedged CLI must not stall the probe past its deadline"
    );
    match result {
        Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::TimedOut),
        Ok(out) => panic!("a wedged CLI must not answer: {out:?}"),
    }
}

/// The same bounded spawn returns a healthy CLI's answer — version
/// text on stdout, success status.
#[test]
fn bounded_cli_output_reads_the_answer() {
    #[cfg(windows)]
    let stub = cli_stub("@echo wslc 3.0.1.0");
    #[cfg(not(windows))]
    let stub = cli_stub("echo wslc 3.0.1.0");
    let out = bounded_cli_output(stub.to_str().unwrap(), &["--version"]).expect("the stub answers");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("wslc 3.0.1.0"));
}

/// A stub `wslc` CLI answering `--version` with `wslc <ver>` —
/// the fixture ignores every argument.
fn wslc_stub(version: &str) -> std::path::PathBuf {
    #[cfg(windows)]
    let body = format!("@echo wslc {version}");
    #[cfg(not(windows))]
    let body = format!("echo wslc {version}");
    cli_stub(&body)
}

/// Explicit-only resolution: the stub answering the validated line
/// resolves to a wslc engine whose identity is `wslc` while the
/// spawned program is the resolved path — never an auto-pick.
#[test]
fn resolve_engine_wslc_resolves_the_validated_line() {
    let _env = crate::warden::lock_process_env();
    let stub = wslc_stub("3.0.1.0");
    unsafe {
        std::env::set_var(crate::container::windows_probe::WSLC_EXE_ENV, &stub);
    }
    let engine = resolve_engine(Some(EngineKind::Wslc)).expect("the validated-line stub resolves");
    unsafe {
        std::env::remove_var(crate::container::windows_probe::WSLC_EXE_ENV);
    }
    assert_eq!(engine.name(), "wslc");
    assert_eq!(engine.program(), stub.to_string_lossy().as_ref());
    assert_eq!(engine.interrupt_signal(), Some("SIGINT"));
    assert!(engine.is_available());
}

/// A version off the validated line is an Unsupported refusal —
/// never a silent launch on an unverified contract.
#[test]
fn resolve_engine_wslc_refuses_an_unvalidated_version() {
    let _env = crate::warden::lock_process_env();
    for version in ["2.9.3.0", "3.1.0.0", "4.0.0.0", "3.0.0.0"] {
        let stub = wslc_stub(version);
        unsafe {
            std::env::set_var(crate::container::windows_probe::WSLC_EXE_ENV, &stub);
        }
        let result = resolve_engine(Some(EngineKind::Wslc));
        unsafe {
            std::env::remove_var(crate::container::windows_probe::WSLC_EXE_ENV);
        }
        match result {
            Err(EngineError::Unsupported(msg)) => {
                assert!(msg.contains("wslc"), "version {version}: {msg}");
                assert!(msg.contains("3.0"), "names the validated line: {msg}");
            }
            Ok(_) => panic!("version {version} must not resolve"),
            Err(other) => panic!("version {version}: expected Unsupported, got: {other}"),
        }
    }
}

/// No resolvable wslc is a distinct NotAvailable — the binary is
/// absent, not unsupported; the refusal is never a substitute
/// engine.
#[test]
fn resolve_engine_wslc_absent_is_not_available() {
    let _env = crate::warden::lock_process_env();
    // The override naming a missing file reads as absent — and
    // overrides the stock install path, so the refusal is
    // deterministic on every host.
    unsafe {
        std::env::set_var(
            crate::container::windows_probe::WSLC_EXE_ENV,
            r"C:\definitely-not-present\wslc.exe",
        );
    }
    let result = resolve_engine(Some(EngineKind::Wslc));
    unsafe {
        std::env::remove_var(crate::container::windows_probe::WSLC_EXE_ENV);
    }
    match result {
        Err(EngineError::NotAvailable(msg)) => {
            assert!(msg.contains("wslc"), "got: {msg}");
        }
        Ok(_) => panic!("an absent wslc must not resolve"),
        Err(other) => panic!("expected NotAvailable, got: {other}"),
    }
}

/// The wslc run-dialect pins: `--pull never` (a launch never
/// fetches — pull progress on stdout would corrupt the wire) and
/// an owned `--name`, spliced after `--no-healthcheck` and before
/// the env-clear list; spec options and the image keep their tail
/// positions.
#[test]
fn wslc_run_prefix_pins_pull_and_name() {
    let prefix = [
        "--pull".to_string(),
        "never".to_string(),
        "--name".to_string(),
        "unit-1".to_string(),
    ];
    let args = container_run_args_ext(&prefix, &["-e".to_string(), "K=V".to_string()], "img");
    assert_eq!(
        &args[..8],
        &[
            "run",
            "-i",
            "--rm",
            "--no-healthcheck",
            "--pull",
            "never",
            "--name",
            "unit-1"
        ]
    );
    assert_eq!(args[8], "-e");
    assert_eq!(args[9], "MCP_WRIT_ENV=");
    assert_eq!(args.last().unwrap(), "img");
    let env_pos = args.iter().position(|a| a == "K=V").unwrap();
    let cid_pos = args.iter().position(|a| a == "--pull").unwrap();
    assert!(env_pos > cid_pos, "spec options stay after the pins");
}

/// `wslc info --format json` — the `Server` member is the
/// session-manager signature; the substrate OS is linux by
/// construction, and a blob without `Server` claims nothing.
#[test]
fn engine_info_os_recognizes_wslc_server_shape() {
    let info = r#"{"Client":{"Version":"3.0.1.0"},"Server":{"SessionManagerVersion":"3.0.1","Sessions":[]}}"#;
    assert_eq!(
        engine_info_os("wslc", info),
        Some(crate::execution::TargetOs::Linux)
    );
    // A foreign CLI's docker-shaped blob is not the wslc answer.
    assert_eq!(engine_info_os("wslc", r#"{"OSType":"linux"}"#), None);
    assert_eq!(engine_info_os("wslc", "not json"), None);
}

/// `is_available` re-runs the version probe+gate: a stub on the
/// line answers true; an old line, a garbage answer, or a missing
/// binary answers false.
#[test]
fn wslc_is_available_reprobes_the_validated_line() {
    let good = wslc_stub("3.0.2.0");
    assert!(WslcEngine::for_test(good.to_str().unwrap()).is_available());
    let old = wslc_stub("2.4.12.0");
    assert!(!WslcEngine::for_test(old.to_str().unwrap()).is_available());
    assert!(!WslcEngine::for_test(r"C:\no\wslc.exe").is_available());
}

#[test]
fn resolve_engine_unavailable_returns_not_available() {
    // At least one of these engines is likely unavailable in the test env.
    // Verify that NotAvailable is returned (not a panic or wrong variant).
    let kinds = [EngineKind::Docker, EngineKind::Podman, EngineKind::Buildah];
    for kind in kinds {
        let result = resolve_engine(Some(kind));
        match &result {
            Ok(engine) => {
                // Engine is installed; verify it reports available
                assert!(engine.is_available());
            }
            Err(EngineError::NotAvailable(name)) => {
                assert!(!name.is_empty(), "engine name in error should not be empty");
            }
            Err(other) => panic!("expected Ok or NotAvailable for {kind:?}, got: {other}"),
        }
    }
}

// -- EngineError display --------------------------------------------------

#[test]
fn engine_error_display() {
    let err = EngineError::NotFound;
    assert_eq!(err.to_string(), "no container engine found on PATH");

    let err = EngineError::CommandFailed {
        engine: "docker".into(),
        message: "exit code 1".into(),
    };
    assert!(err.to_string().contains("docker"));
    assert!(err.to_string().contains("exit code 1"));

    let err = EngineError::UnknownKind("runc".into());
    assert!(err.to_string().contains("runc"));

    let err = EngineError::Unsupported("not implemented".into());
    assert!(err.to_string().contains("not implemented"));

    let err = EngineError::NotAvailable("podman".into());
    assert!(err.to_string().contains("podman"));
    assert!(err.to_string().contains("not available"));
}

// -- is_available does not panic ------------------------------------------

#[test]
fn is_available_does_not_panic() {
    // Verify the function runs without panicking, regardless of CLI presence
    let _ = DockerEngine.is_available();
    let _ = PodmanEngine.is_available();
    let _ = BuildahEngine.is_available();
}
