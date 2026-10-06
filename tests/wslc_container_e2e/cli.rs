//! Environment record and CLI capability map — what this host and
//! the `wslc` CLI surface actually are before workloads run.

use mcp_writ::execution::{TargetArch, TargetOs};

use crate::common;
use crate::support::*;

// ─── environment record ──────────────────────────────────────────────

/// Record the exact environment — versions, sessions, distros, the
/// settings file `wslc info` names, free space — before any workload
/// runs. This is the record the adoption decision cites.
#[tokio::test]
async fn wslc_environment_record() {
    if let Some(reason) = blocking(check_prereqs).await {
        common::skip_wslc_test(&reason);
        return;
    }
    let _g = SESSION_LOCK.lock().await;
    let dirs = blocking(session_dirs).await;

    let wsl_text = blocking(wsl_version_text).await;
    let wslc_text = blocking(wslc_version_text).await;
    let info = wslc_info_json().await.unwrap_or_else(|| "null".into());
    let sessions = session_list_raw().await;
    let distros = blocking(|| {
        run_cli("wsl.exe", &["-l", "-v"], CLI_TIMEOUT_SECS)
            .map(|o| decode_cli(&o.stdout))
            .unwrap_or_default()
    })
    .await;
    // `wslc system session run` — a command in the session VM context —
    // is the session-level guest probe; tolerate absence on previews.
    let session_uname = wslc(&["system", "session", "run", "uname", "-a"])
        .await
        .map(|o| {
            format!(
                "exit={} out={}",
                o.status.code().unwrap_or(-1),
                decode_cli(&o.stdout).replace('\n', " ").trim()
            )
        })
        .unwrap_or_else(|| "unavailable".into());

    let record = format!(
        "{{\"host\":{{\"os\":{},\"arch\":{},\"pid\":{}}},\
         \"wsl_version_text\":{},\"wslc_version_text\":{},\
         \"wslc_info\":{},\"sessions_before\":{},\"wsl_distros\":{},\
         \"session_run_uname\":{}}}",
        json_str(&format!(
            "{} {}",
            std::env::consts::OS,
            TargetOs::host().name()
        )),
        json_str(TargetArch::host().name()),
        std::process::id(),
        json_str(&wsl_text),
        json_str(&wslc_text),
        if info.trim_start().starts_with('{') {
            info.clone()
        } else {
            json_str(&info)
        },
        json_str(&sessions),
        json_str(&distros),
        json_str(&session_uname),
    );
    std::fs::write(dirs._root.path().join("host-identity.json"), record)
        .expect("write host-identity.json");
}

// ─── capability map ──────────────────────────────────────────────────

/// Measure the `wslc run` surface the product's launch contract needs.
/// Required legs assert; absent/preview args record — the map lands in
/// `capability-map.json` either way, and a required arg that is refused
/// fails the leg, not silently skipped.
#[tokio::test]
async fn wslc_cli_capability_map() {
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

    struct Leg {
        label: &'static str,
        args: Vec<String>,
        cmd: &'static [&'static str],
        /// What stdout must contain for the leg to count as honored
        /// (beyond exit 0). Empty → exit 0 suffices.
        expect_out: &'static str,
        /// `required` = the product contract needs it; `expect_refused`
        /// = a docker-ism WSLC must reject, not silently accept.
        required: bool,
        expect_refused: bool,
    }

    let mk = |label: &'static str,
              args: &[&'static str],
              cmd: &'static [&'static str],
              expect_out: &'static str,
              required: bool,
              refused: bool| Leg {
        label,
        args: args.iter().map(|s| s.to_string()).collect(),
        cmd,
        expect_out,
        required,
        expect_refused: refused,
    };

    // A real env file — `--env-file` acceptance is measured by delivery,
    // not by feeding the CLI a missing path (a missing file must fail
    // regardless of whether the flag exists).
    let env_file = dirs._root.path().join("wslc-e2e.env");
    std::fs::write(&env_file, "WSLC_E2E_MARK2=ok2\n").expect("env fixture");
    // The cidfile leg gets a real temp path; its write is checked after.
    let cidfile = dirs._root.path().join("cidfile.txt");

    let mut legs = vec![
        mk(
            "entrypoint",
            &["--entrypoint", "/usr/local/bin/wslc-probe"],
            &["identity"],
            "osrelease=",
            true,
            false,
        ),
        mk(
            "env-e",
            &["-e", "WSLC_E2E_MARK=ok"],
            &["print-env", "WSLC_E2E_MARK"],
            "ENV:WSLC_E2E_MARK=ok",
            true,
            false,
        ),
        mk(
            "name",
            &["--name", "mcp-writ-wslc-cap-name"],
            &["exit-code", "0"],
            "",
            true,
            false,
        ),
        mk(
            "no-healthcheck",
            &["--no-healthcheck"],
            &["exit-code", "0"],
            "",
            true,
            false,
        ),
        mk(
            "workdir",
            &["-w", "/tmp"],
            &["exit-code", "0"],
            "",
            true,
            false,
        ),
        mk("user", &["-u", "0"], &["exit-code", "0"], "", true, false),
        // `--network none` acceptance only — the deny semantics are
        // asserted inside the guest in wslc_network_semantics.
        mk(
            "network-none",
            &["--network", "none"],
            &["exit-code", "0"],
            "",
            true,
            false,
        ),
        mk(
            "memory-limit",
            &["-m", "512M"],
            &["exit-code", "0"],
            "",
            true,
            false,
        ),
        mk(
            "cpus-limit",
            &["--cpus", "1"],
            &["exit-code", "0"],
            "",
            true,
            false,
        ),
        mk(
            "env-file",
            &["--env-file", "ENVFILE-PLACEHOLDER"],
            &["print-env", "WSLC_E2E_MARK2"],
            "ENV:WSLC_E2E_MARK2=ok2",
            false,
            false,
        ),
        mk(
            "cidfile",
            &["--cidfile", "CIDFILE-PLACEHOLDER"],
            &["exit-code", "0"],
            "",
            false,
            false,
        ),
        mk(
            "label",
            &["-l", "mcp-writ-wslc=1"],
            &["exit-code", "0"],
            "",
            false,
            false,
        ),
        mk(
            "pull",
            &["--pull", "missing"],
            &["exit-code", "0"],
            "",
            false,
            false,
        ),
        // Docker-isms the contract must refuse, not silently accept.
        mk(
            "refuse-privileged",
            &["--privileged"],
            &["exit-code", "0"],
            "",
            false,
            true,
        ),
        mk(
            "refuse-cap-add",
            &["--cap-add", "SYS_ADMIN"],
            &["exit-code", "0"],
            "",
            false,
            true,
        ),
        mk(
            "refuse-device",
            &["--device", "/dev/null"],
            &["exit-code", "0"],
            "",
            false,
            true,
        ),
        mk(
            "refuse-platform",
            &["--platform", "linux/arm64"],
            &["exit-code", "0"],
            "",
            false,
            true,
        ),
        mk(
            "refuse-network-host",
            &["--network", "host"],
            &["exit-code", "0"],
            "",
            false,
            true,
        ),
        mk(
            "refuse-restart",
            &["--restart", "always"],
            &["exit-code", "0"],
            "",
            false,
            true,
        ),
        mk(
            "refuse-security-opt",
            &["--security-opt", "seccomp=unconfined"],
            &["exit-code", "0"],
            "",
            false,
            true,
        ),
    ];

    for leg in legs.iter_mut() {
        for a in leg.args.iter_mut() {
            if a == "CIDFILE-PLACEHOLDER" {
                *a = cidfile.display().to_string();
            } else if a == "ENVFILE-PLACEHOLDER" {
                *a = env_file.display().to_string();
            }
        }
    }

    let mut records = String::from("{\"legs\":[");
    let mut failures: Vec<String> = Vec::new();
    let mut first = true;
    for leg in &legs {
        let (ok, out, err) = probe_run(&leg.args, &image, leg.cmd).await;
        let mut honored = if leg.expect_refused {
            !ok
        } else if !ok {
            false
        } else {
            leg.expect_out.is_empty() || out.contains(leg.expect_out)
        };
        // cidfile: the flag's contract is a written unit id — check the
        // file actually appeared, not just that the run exited 0.
        if leg.label == "cidfile" && honored {
            honored = cidfile
                .exists()
                .then(|| std::fs::read_to_string(&cidfile).unwrap_or_default())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false);
        }
        let status = if honored {
            if leg.expect_refused { "refused" } else { "ok" }
        } else if leg.expect_refused {
            "accepted"
        } else {
            "refused-or-failed"
        };
        if leg.required && !honored {
            failures.push(format!(
                "required run-arg {}: status={status} err={}",
                leg.label,
                clip(&err, 300)
            ));
        }
        if leg.expect_refused && ok {
            failures.push(format!(
                "docker-ism {} was silently ACCEPTED (must be refused)",
                leg.label
            ));
        }
        if !first {
            records.push(',');
        }
        first = false;
        records.push_str(&format!(
            "{{\"label\":{},\"status\":{},\"stdout\":{},\"stderr\":{}}}",
            json_str(leg.label),
            json_str(status),
            json_str(&clip(&out, 400)),
            json_str(&clip(&err, 400)),
        ));
    }

    // Mount contract legs (also the session tests' input).
    let contract = mount_contract(&image).await;
    records.push_str(&format!(
        "],\"mount_contract\":{{\"dash_v\":{},\"long_mount\":{},\"file_mounts\":{},\"ro_honored\":{}}}}}",
        contract.dash_v, contract.long_mount, contract.file_mounts, contract.ro_honored
    ));
    if !(contract.dash_v || contract.long_mount) {
        failures.push("no working mount form (-v and --mount both failed)".into());
    }
    if !contract.ro_honored {
        failures.push("read-only mount flag not honored (write inside guest succeeded)".into());
    }
    std::fs::write(dirs._root.path().join("capability-map.json"), records)
        .expect("write capability-map.json");

    assert!(
        failures.is_empty(),
        "capability-map legs failed:\n{}",
        failures.join("\n")
    );
}
