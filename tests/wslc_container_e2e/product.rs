//! Product-path legs (PR-29): the `mcp-writ` CLI itself driving
//! `--engine wslc`. The rest of the suite measured the raw substrate
//! contract; these legs verify the wired product path end to end —
//! engine resolution without a PATH-exported `wslc.exe`, the MCP wire
//! over `wslc run -i`, the isolation record (`engine=wslc`,
//! `substrate=container`, `unit=container`, shared-session detail),
//! entrypoint refusal, externally-signaled teardown, and `plan`'s
//! diagnostics on the same substrate.

use std::path::Path;
use std::process::Stdio;

use tokio::io::BufReader;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

/// The product binary under test — same convention as `tests/common`.
fn product() -> &'static str {
    env!("CARGO_BIN_EXE_mcp-writ")
}

/// The unit name a product launch owns — `mcp-writ-wslc-<12 hex>` set
/// by `WslcEngine::run`. `list -a --no-trunc` rows also carry the
/// image reference (`mcp-writ-wslc-probe-secure:test`) and a warm-up
/// unit may briefly appear (`mcp-writ-wslc-warm-<pid>`), so the match
/// is the exact unit-name shape, not the prefix alone.
async fn product_unit_name() -> Option<String> {
    let out = wslc_any(&[
        vec!["list".into(), "-a".into(), "--no-trunc".into()],
        vec![
            "container".into(),
            "list".into(),
            "-a".into(),
            "--no-trunc".into(),
        ],
    ])
    .await?;
    decode_cli(&out.stdout)
        .split_whitespace()
        .find(|t| {
            t.strip_prefix("mcp-writ-wslc-")
                .is_some_and(|s| s.len() == 12 && s.chars().all(|c| c.is_ascii_hexdigit()))
        })
        .map(str::to_string)
}

/// Build the `run-image` argv shared by the product legs: explicit
/// `--engine wslc` on the default container substrate, the fixture
/// policy, the mutable-tag waiver (the suite's own tag — not a
/// registry digest), the host report path, and the image last.
fn run_image_args(dirs: &SessionDirs, report: &Path, image: &str) -> Vec<String> {
    vec![
        "run-image".into(),
        "--engine".into(),
        "wslc".into(),
        "--allow-mutable-tag".into(),
        "--policy".into(),
        dirs.policy.display().to_string(),
        "--server".into(),
        "wslc-probe".into(),
        "--report".into(),
        report.display().to_string(),
        image.into(),
    ]
}

/// The full product path: resolve the engine off-PATH (install-dir
/// fallback), warm/attach the session, wire the MCP exchange over
/// `wslc run -i`, end on stdin EOF — then assert the report records
/// `engine=wslc`, `configured=verified=container`, `unit=container`
/// with the shared-session detail, the guest report attached, and no
/// leftover unit.
#[tokio::test]
async fn wslc_product_run_image() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_wslc_test(&reason);
        return;
    }
    let _g = SESSION_LOCK.lock().await;
    let Some(probe) = blocking(compiled_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    if blocking(ensure_base_pulled).await.is_none() {
        return;
    }
    let (_image, secure) = match shared_images(&runner, &probe).await {
        Ok(t) => t,
        Err(e) => {
            common::skip_wslc_test(&format!("image build failed: {e}"));
            return;
        }
    };
    let dirs = blocking(session_dirs).await;
    let report = dirs.report.join("report.json");

    let mut child = Command::new(product())
        .args(run_image_args(&dirs, &report, &secure))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("mcp-writ run-image failed to spawn");
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"wslc-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire
        .wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize never answered — provisioning chatter or a dead runner would surface here first");
    assert!(
        init.contains("\"result\""),
        "initialize must return a result: {init}"
    );
    wire.send(&request(
        1,
        "tools/call",
        "{\"name\":\"read_file\",\"arguments\":{\"path\":\"/etc/os-release\"}}",
    ))
    .await;
    let call = wire
        .wait_id(1, SESSION_TIMEOUT_SECS)
        .await
        .expect("tools/call never answered");
    assert!(call.contains("os-release"), "read_file: {call}");

    // stdin EOF ends the session — the runner unwinds and the unit is
    // reaped by the handle's cleanup, same as any other engine.
    wire.writer.take();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("mcp-writ did not exit after stdin EOF")
        .expect("wait failed");
    assert!(status.success(), "run-image exit: {status}");

    let report_json = std::fs::read_to_string(&report).expect("host report exists");
    for needle in [
        "\"engine\":\"wslc\"",
        "\"configured\":\"container\"",
        "\"verified\":\"container\"",
        "\"unit\":\"container\"",
        "shared session VM",
        "\"state\":\"received\"",
        "guest-report-1",
        "\"status\":\"exited\"",
    ] {
        assert!(report_json.contains(needle), "report missing {needle}");
    }

    // No mcp-writ-wslc-* unit survives the session.
    let listed = product_unit_name().await;
    assert!(
        listed.is_none(),
        "unit leaked after normal exit: {listed:?}"
    );

    std::fs::write(
        dirs._root.path().join("product.json"),
        format!(
            "{{\"test\":\"wslc_product_run_image\",\"exit\":{},\"unit\":{}}}",
            status.code().unwrap_or(-1),
            listed.map_or("null".into(), |u| json_str(&u)),
        ),
    )
    .unwrap();
}

/// The unwrapped probe image must be refused at the entrypoint gate —
/// never a launch that silently drops the runner contract — and the
/// failed run still writes its launch report.
#[tokio::test]
async fn wslc_product_refuses_unwrapped_image() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_wslc_test(&reason);
        return;
    }
    let _g = SESSION_LOCK.lock().await;
    let Some(probe) = blocking(compiled_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    if blocking(ensure_base_pulled).await.is_none() {
        return;
    }
    let (image, _secure) = match shared_images(&runner, &probe).await {
        Ok(t) => t,
        Err(e) => {
            common::skip_wslc_test(&format!("image build failed: {e}"));
            return;
        }
    };
    let dirs = blocking(session_dirs).await;
    let report = dirs.report.join("report.json");

    let out = bounded_cli(
        product(),
        &run_image_args(&dirs, &report, &image),
        SESSION_TIMEOUT_SECS,
    )
    .await
    .expect("run-image on the unwrapped image never returned");
    assert!(
        !out.status.success(),
        "an unwrapped image must refuse, got exit {:?}",
        out.status
    );
    let stderr = decode_cli(&out.stderr);
    assert!(
        stderr.contains("mcp-secure-runner"),
        "the entrypoint refusal names the runner contract: {stderr}"
    );
    let report_json = std::fs::read_to_string(&report).expect("failed run still reports");
    assert!(
        report_json.contains("\"engine\":\"wslc\""),
        "refusal report must record the requested engine"
    );
    assert!(
        product_unit_name().await.is_none(),
        "a refused launch leaves no unit"
    );
}

/// A unit-level `wslc kill -s SIGINT` while the product session is live
/// unwinds the runner (its interrupted unwind is the substrate's own
/// guarantee — the same signal the handle sends on Ctrl-C); the client
/// exits, the unit is reaped, the session survives.
#[tokio::test]
async fn wslc_product_external_sigint_ends_session() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_wslc_test(&reason);
        return;
    }
    let _g = SESSION_LOCK.lock().await;
    let Some(probe) = blocking(compiled_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    if blocking(ensure_base_pulled).await.is_none() {
        return;
    }
    let (_image, secure) = match shared_images(&runner, &probe).await {
        Ok(t) => t,
        Err(e) => {
            common::skip_wslc_test(&format!("image build failed: {e}"));
            return;
        }
    };
    let dirs = blocking(session_dirs).await;
    let report = dirs.report.join("report.json");

    let mut child = Command::new(product())
        .args(run_image_args(&dirs, &report, &secure))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("mcp-writ run-image failed to spawn");
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"wslc-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    wire.wait_id(0, SESSION_TIMEOUT_SECS)
        .await
        .expect("initialize never answered");

    // The owned unit name surfaces on `wslc list`.
    let unit = {
        let mut name = None;
        for _ in 0..120 {
            if let Some(n) = product_unit_name().await {
                name = Some(n);
                break;
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        name.expect("the launch's mcp-writ-wslc-* unit never listed")
    };
    assert!(
        unit_kill(&unit, "SIGINT").await,
        "wslc kill -s SIGINT on {unit} must be accepted"
    );

    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("mcp-writ did not exit after the unit was killed")
        .expect("wait failed");
    let _ = status; // exit code follows the unit's unwind — the session ends either way

    // The unit is gone and the session still serves other workloads.
    let reaped = poll(30, 500, || {
        let unit = unit.clone();
        async move { !unit_listed(&unit).await }
    })
    .await;
    assert!(reaped, "unit {unit} still listed after the kill");
    let report_json = std::fs::read_to_string(&report).expect("host report exists");
    assert!(
        report_json.contains("\"engine\":\"wslc\""),
        "the teardown report still records the wslc launch"
    );
}

/// `plan --engine wslc` on the same host: the engine resolves, the
/// WSL/WSLC environment checks emit, the runtime contract stays
/// honestly unprobed — and nothing claims a boundary the substrate
/// does not provide.
#[tokio::test]
async fn wslc_product_plan_diagnostics() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_wslc_test(&reason);
        return;
    }
    let _g = SESSION_LOCK.lock().await;
    let Some(probe) = blocking(compiled_probe).await else {
        return;
    };
    let Some(runner) = blocking(linux_runner).await else {
        return;
    };
    if blocking(ensure_base_pulled).await.is_none() {
        return;
    }
    let (_image, secure) = match shared_images(&runner, &probe).await {
        Ok(t) => t,
        Err(e) => {
            common::skip_wslc_test(&format!("image build failed: {e}"));
            return;
        }
    };
    let dirs = blocking(session_dirs).await;
    let out = bounded_cli(
        product(),
        &[
            "plan".to_string(),
            "--engine".to_string(),
            "wslc".to_string(),
            "--image".to_string(),
            secure.clone(),
            "--allow-mutable-tag".to_string(),
            "--policy".to_string(),
            dirs.policy.display().to_string(),
            "--server".to_string(),
            "wslc-probe".to_string(),
        ],
        SESSION_TIMEOUT_SECS,
    )
    .await
    .expect("plan never returned");
    assert!(
        out.status.success(),
        "plan on a resolved wslc host must be ready: {}",
        decode_cli(&out.stderr)
    );
    let text = decode_cli(&out.stdout);
    for needle in [
        "\"id\":\"engine.resolve\",\"status\":\"pass\"",
        "\"id\":\"wslc.cli\",\"status\":\"pass\"",
        "\"id\":\"engine.locality\",\"status\":\"pass\"",
        "\"id\":\"runner.entrypoint\",\"status\":\"pass\"",
        "\"engine\":\"wslc\"",
        "\"substrate\":\"container\"",
    ] {
        assert!(text.contains(needle), "plan missing {needle}");
    }
}

/// `run_cli` over an arbitrary program with the suite's bounded-spawn
/// contract (the `wslc_bounded` shape generalized — product invocations
/// need the same kill-on-timeout discipline).
async fn bounded_cli(prog: &str, args: &[String], secs: u64) -> Option<std::process::Output> {
    let prog = prog.to_string();
    let args = args.to_vec();
    blocking(move || {
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        run_cli(&prog, &refs, secs)
    })
    .await
}
