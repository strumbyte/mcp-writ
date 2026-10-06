//! Lifecycle and storage: stop/kill, CLI death, launch failure,
//! and the session store's on-disk footprint.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Instant;

use tokio::io::{AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

// ─── lifecycle: stop/kill, CLI death, launch failure ─────────────────

/// `wslc kill -s SIGINT` on the running unit must unwind the workload
/// (the runner forwards it, report records `interrupted`) and remove
/// the unit — while the session VM stays up for other units.
#[tokio::test]
async fn wslc_stop_terminates_and_cleans_up() {
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
    let (image, secure) = match shared_images(&runner, &probe).await {
        Ok(t) => t,
        Err(e) => {
            common::skip_wslc_test(&format!("image build failed: {e}"));
            return;
        }
    };
    let contract = mount_contract(&image).await;
    assert!(
        contract.dash_v || contract.long_mount,
        "no working mount form — cannot run the session"
    );

    let dirs = blocking(session_dirs).await;
    let name = format!("mcp-writ-wslc-stop-{}", std::process::id());
    let launch_id = uuid::Uuid::now_v7().to_string();
    let mut child = Command::new("wslc")
        .args(session_run_args(
            &dirs, &launch_id, &contract, &name, &secure,
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("wslc run failed to spawn");
    let _guard = UnitGuard(name.clone());
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
        .expect("initialize response never arrived — the runner is not live");
    assert!(
        init.contains("\"result\""),
        "initialize must return a result before the kill leg: {init}"
    );

    // Unit id for the record — `wslc inspect` names it.
    let unit_id = blocking({
        let name = name.clone();
        move || {
            run_cli(
                "wslc",
                &["inspect", &name, "--format", "json"],
                CLI_TIMEOUT_SECS,
            )
            .map(|o| decode_cli(&o.stdout))
            .unwrap_or_default()
        }
    })
    .await;

    let stop_t = Instant::now();
    assert!(
        unit_kill(&name, "SIGINT").await,
        "wslc kill -s SIGINT must be accepted"
    );
    let exited =
        poll(STOP_TIMEOUT_SECS, 500, || {
            let name = name.clone();
            async move {
                !unit_listed(&name).await || unit_state(&name).await.as_deref() != Some("running")
            }
        })
        .await;
    let stop_s = stop_t.elapsed().as_secs_f64();
    assert!(exited, "unit must leave the running state after SIGINT");

    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("attached wslc run did not exit after the unit was killed")
        .expect("wait failed");

    // The session stays up — other units still work.
    let (ok, _, _) = probe_run(&[], &image, &["exit-code", "0"]).await;
    assert!(ok, "session must still serve workloads after a unit kill");

    // The runner's interrupted report, if written before teardown.
    let interrupted = dirs
        .report
        .join("report.json")
        .exists()
        .then(|| std::fs::read_to_string(dirs.report.join("report.json")).unwrap_or_default())
        .map(|r| r.contains("interrupted"))
        .unwrap_or(false);

    let lifecycle = format!(
        "{{\"tier\":\"harness\",\"test\":\"wslc_stop_terminates_and_cleans_up\",\"unit\":{},\"inspect\":{},\"unit_exited\":{},\"cli_exit\":{},\"report_interrupted\":{},\"stop_s\":{stop_s:.3}}}",
        json_str(&name),
        json_str(&clip(&unit_id, 400)),
        exited,
        json_str(&format!("{status:?}")),
        interrupted,
    );
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();
}

/// CLI death and launch-time failures must not strand units or the
/// session: killing the `wslc run` client mid-session, a bad
/// entrypoint at launch, and `wslc exec` against a dead unit — each
/// records what the substrate actually does.
#[tokio::test]
async fn wslc_cli_death_and_launch_failure() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_wslc_test(&reason);
        return;
    }
    let _g = SESSION_LOCK.lock().await;
    let Some(probe) = blocking(compiled_probe).await else {
        return;
    };
    if blocking(ensure_base_pulled).await.is_none() {
        return;
    }
    let image = match probe_image(&probe).await {
        Ok(t) => t,
        Err(e) => {
            common::skip_wslc_test(&format!("probe image build failed: {e}"));
            return;
        }
    };
    let dirs = blocking(session_dirs).await;

    // ── CLI death mid-session ──────────────────────────────────────
    let name = format!("mcp-writ-wslc-clideath-{}", std::process::id());
    let mut child = Command::new("wslc")
        .args([
            "run",
            "-i",
            "--name",
            name.as_str(),
            image.as_str(),
            "sleep",
            "600",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("wslc run failed to spawn");
    // Named unit + guard: an assert panic between spawn and the
    // explicit cleanup below must not leak the (possibly
    // daemon-owned) unit.
    let _guard = UnitGuard(name.clone());
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    let armed = wire
        .wait_for_prefix("sleep=", SESSION_TIMEOUT_SECS)
        .await
        .expect("probe never armed — wslc -i did not relay stdout");
    assert!(
        armed.contains("sleep=armed"),
        "unexpected probe line: {armed}"
    );

    // Kill the client process — what happens to the unit is the
    // finding (daemon-owned like docker, or torn down with the CLI).
    child.kill().await.expect("kill wslc client");
    let _ = child.wait().await;
    let survived = poll(30, 1000, || {
        let name = name.clone();
        async move { unit_state(&name).await.as_deref() == Some("running") }
    })
    .await;
    let post_kill_state = unit_state(&name).await;
    // Clean up the owned unit either way.
    let removed = if survived || post_kill_state.is_some() {
        let _ = unit_kill(&name, "SIGKILL").await;
        unit_rm(&name).await
    } else {
        true
    };

    // ── launch failure: bad entrypoint ─────────────────────────────
    let bad_name = format!("mcp-writ-wslc-badlaunch-{}", std::process::id());
    let (ok, _out, err) = probe_run(
        &[
            "--name".into(),
            bad_name.clone(),
            "--entrypoint".into(),
            "/nonexistent".into(),
        ],
        &image,
        &["identity"],
    )
    .await;
    let launch_refused = !ok;
    let _ = unit_rm(&bad_name).await; // a failed run may leave a created unit

    // ── exec against a dead/absent unit ────────────────────────────
    let exec_out = wslc(&["exec", "mcp-writ-wslc-nonexistent", "true"]).await;
    let exec_refused = exec_out.map(|o| !o.status.success()).unwrap_or(true);

    let lifecycle = format!(
        "{{\"tier\":\"harness\",\"test\":\"wslc_cli_death_and_launch_failure\",\
         \"cli_kill_unit_survived\":{},\"post_kill_state\":{},\"unit_removed\":{},\
         \"bad_entrypoint_refused\":{},\"launch_err\":{},\"exec_dead_refused\":{}}}",
        survived,
        json_str(&format!("{post_kill_state:?}")),
        removed,
        launch_refused,
        json_str(&clip(&err, 300)),
        exec_refused,
    );
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle).unwrap();

    assert!(
        launch_refused,
        "a bad entrypoint must refuse at launch, not hang or fake-run"
    );
    assert!(exec_refused, "wslc exec against a missing unit must refuse");
    assert!(removed, "owned unit cleanup must succeed");
}

// ─── storage layout ──────────────────────────────────────────────────

/// Where wslc actually puts its state: the default session storage,
/// the settings file `wslc info` names, a dedicated session's VHD at
/// an explicit path, image digests, and drive deltas around a pull —
/// the D:-only cleanup boundary's evidence.
#[tokio::test]
async fn wslc_storage_layout() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_wslc_test(&reason);
        return;
    }
    let _g = SESSION_LOCK.lock().await;
    let Some(probe) = blocking(compiled_probe).await else {
        return;
    };
    if blocking(ensure_base_pulled).await.is_none() {
        return;
    }
    let image = match probe_image(&probe).await {
        Ok(t) => t,
        Err(e) => {
            common::skip_wslc_test(&format!("probe image build failed: {e}"));
            return;
        }
    };
    let dirs = blocking(session_dirs).await;

    let info = wslc_info_json().await.unwrap_or_else(|| "null".into());
    // `wslc images` — session-scoped image inventory incl. our tags.
    let images = wslc_any(&[vec!["images".into()], vec!["image".into(), "ls".into()]])
        .await
        .map(|o| decode_cli(&o.stdout))
        .unwrap_or_default();
    // `wslc image inspect <tag>` — the OCI record for digest evidence.
    let probe_inspect = wslc_any(&[vec!["image".into(), "inspect".into(), image.clone()]])
        .await
        .map(|o| decode_cli(&o.stdout))
        .unwrap_or_default();

    // Default session storage: %LOCALAPPDATA%\wslc subtree measure —
    // record the shape (dirs + sizes), never delete.
    let local_appdata = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("C:\\Users\\unknown\\AppData\\Local"));
    let wslc_dir = local_appdata.join("wslc");
    let default_store = blocking({
        let wslc_dir = wslc_dir.clone();
        move || dir_tree_listing(&wslc_dir, 3)
    })
    .await;

    // Free space on the drives that matter — work drive, %LOCALAPPDATA%
    // drive, and the session-storage drive. One bounded PowerShell call
    // per drive, off the async task.
    fn free_of(p: PathBuf) -> String {
        drive_letter(&p)
            .and_then(|l| blocking_powershell_free(&l))
            .map(|b| format!("{b}"))
            .unwrap_or_else(|| "unreadable".into())
    }
    let (fw, fl, fs_) = (
        blocking({
            let p = test_root();
            move || free_of(p)
        })
        .await,
        blocking({
            let p = local_appdata.clone();
            move || free_of(p)
        })
        .await,
        blocking({
            let p = session_storage_root();
            move || free_of(p)
        })
        .await,
    );
    let free_space = format!(
        "{{\"work\":{},\"localappdata\":{},\"session_storage\":{}}}",
        fw, fl, fs_
    );

    // Dedicated session storage at an explicit path: create, measure,
    // terminate, measure again — whether the VHD persists after the
    // session ends is the reuse-state finding.
    let sess_name = format!("mcp-writ-wslc-store-{}", std::process::id());
    let storage = session_storage_root().join(&sess_name);
    std::fs::create_dir_all(&storage).expect("session storage dir");
    let before = dir_listing(&storage);
    let mut enter = Command::new("wslc")
        .args([
            "system",
            "session",
            "enter",
            &storage.display().to_string(),
            "--name",
            &sess_name,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("wslc system session enter failed to spawn");
    let entered = poll(60, 1000, || {
        let name = sess_name.clone();
        async move { session_list_raw().await.contains(&name) }
    })
    .await;
    if let Some(mut stdin) = enter.stdin.take() {
        let _ = stdin.write_all(b"exit\n").await;
        let _ = stdin.flush().await;
    }
    let _ = timeout(Duration::from_secs(30), enter.wait()).await;
    if entered {
        let _ = wslc(&[
            "system",
            "session",
            "terminate",
            "--session",
            sess_name.as_str(),
        ])
        .await;
    }
    let after = dir_listing(&storage);

    let record = format!(
        "{{\"wslc_info\":{},\"images\":{},\"probe_inspect\":{},\
         \"default_store\":{},\"free_space_gib_or_bytes\":{},\
         \"dedicated\":{{\"name\":{},\"path\":{},\"entered\":{},\"before\":{},\"after\":{}}}}}",
        if info.trim_start().starts_with('{') {
            info.clone()
        } else {
            json_str(&info)
        },
        json_str(&images),
        json_str(&clip(&probe_inspect, 2000)),
        json_str(&default_store),
        free_space,
        json_str(&sess_name),
        json_str(&storage.display().to_string()),
        entered,
        json_str(&before),
        json_str(&after),
    );
    std::fs::write(dirs._root.path().join("storage.json"), record).expect("write storage.json");
}

/// Drive letter of a path (`D:\…` → `D`).
fn drive_letter(p: &Path) -> Option<String> {
    let s = p.to_string_lossy();
    let mut it = s.chars();
    let l = it.next()?;
    if it.next() == Some(':') && l.is_ascii_alphabetic() {
        Some(l.to_ascii_uppercase().to_string())
    } else {
        None
    }
}

/// Free bytes of a drive via a bounded PowerShell call — `wsl`-style
/// CLIs have no cross-platform equivalent, and the measurement is
/// evidence, not a gate.
fn blocking_powershell_free(letter: &str) -> Option<u64> {
    let script = format!("(Get-PSDrive -Name {letter}).Free");
    let out = run_cli(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &script],
        CLI_TIMEOUT_SECS,
    )?;
    decode_cli(&out.stdout).trim().parse().ok()
}

/// A bounded depth-limited listing (`path:size` per line) — the storage
/// shape record without enumerating whole trees.
fn dir_tree_listing(dir: &Path, depth: usize) -> String {
    fn walk(d: &Path, depth: usize, out: &mut Vec<String>, prefix: &str) {
        if depth == 0 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(d) else {
            return;
        };
        for e in rd.flatten().take(64) {
            let name = e.file_name().to_string_lossy().into_owned();
            let p = e.path();
            let size = e.metadata().map(|m| m.len()).unwrap_or(0);
            out.push(format!("{prefix}{name}:{size}"));
            if p.is_dir() {
                walk(&p, depth - 1, out, &format!("{prefix}{name}/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, depth, &mut out, "");
    if out.is_empty() {
        format!("absent-or-empty:{}", dir.display())
    } else {
        out.join("\n")
    }
}
