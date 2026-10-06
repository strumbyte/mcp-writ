//! The stdio wire contract (bidirectional, EOF, exit codes,
//! non-TTY) and the runner-wrapped secure-image session.

use std::process::Stdio;
use std::time::Instant;

use tokio::io::BufReader;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use mcp_writ::container::guest_report;

use crate::common;
use crate::support::*;

// ─── stdio contract ──────────────────────────────────────────────────

/// Non-TTY bidirectional stdio: stdin in both directions, stdout vs
/// stderr separation, EOF propagation, exit-code fidelity, and the
/// absence of a controlling terminal — the launch contract's transport
/// layer, measured end-to-end through `wslc run -i`.
#[tokio::test]
async fn wslc_stdio_contract() {
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

    // 1. Bidirectional stdin + stdout, stderr kept separate, EOF → 0.
    // Named so a dropped/panicked leg is covered by UnitGuard and the
    // cleanup script's `mcp-writ-wslc-*` sweep; kill_on_drop reaps the
    // CLI itself.
    let echo_name = format!("mcp-writ-wslc-echo-{}", std::process::id());
    let mut child = Command::new(wslc_prog())
        .args([
            "run",
            "-i",
            "--rm",
            "--name",
            echo_name.as_str(),
            image.as_str(),
            "stdio-echo",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("wslc run failed to spawn");
    let _guard = UnitGuard(echo_name);
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };
    let stderr_task = {
        let mut err = child.stderr.take().unwrap();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = Vec::new();
            let _ = err.read_to_end(&mut buf).await;
            buf
        })
    };
    wire.send("hello-π-日本語").await;
    let echo = wire
        .wait_for_prefix("ECHO:", SESSION_TIMEOUT_SECS)
        .await
        .expect("no stdio-echo response — wslc -i did not relay the line");
    assert!(
        echo.contains("ECHO:hello-π-日本語"),
        "stdin→stdout relay must echo the line verbatim (UTF-8 incl. non-ASCII): {echo}"
    );
    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("stdio-echo did not exit after stdin EOF")
        .expect("wait failed");
    assert!(status.success(), "EOF must exit 0, got {status:?}");
    let stderr = decode_cli(&stderr_task.await.unwrap_or_default());
    assert!(
        stderr.contains("STDERR-MARK"),
        "probe's stderr marker must arrive on stderr: {stderr:?}"
    );
    assert!(
        !echo.contains("STDERR-MARK"),
        "stderr content must not leak onto stdout"
    );

    // 2. Exit-code fidelity.
    assert_eq!(
        wslc_last_code(&["run", "--rm", image.as_str(), "exit-code", "7"]).await,
        Some(7),
        "exit code must propagate (expected 7)"
    );

    // 3. Non-TTY launch: /dev/tty absent, fds are pipes.
    let (_, tty_out, _) = probe_run(&[], &image, &["tty-check"]).await;
    assert!(
        tty_out.contains("dev_tty=failed"),
        "non-TTY launch must leave /dev/tty unopenable: {tty_out}"
    );
    assert!(
        tty_out.contains("fd0=pipe:") || tty_out.contains("fd0=/dev/null"),
        "stdin must be a pipe/null under non-TTY launch: {tty_out}"
    );

    let record = format!(
        "{{\"echo\":{},\"stderr\":{},\"tty\":{}}}",
        json_str(&echo),
        json_str(&stderr),
        json_str(&tty_out)
    );
    std::fs::write(dirs._root.path().join("stdio-contract.json"), record)
        .expect("write stdio-contract.json");
}

/// `wslc` exit code for a finished one-shot. These args are `wslc
/// run` legs, so the session budget applies — not the 30s inventory
/// bound (a session-VM cold boot would misreport as a timeout).
async fn wslc_last_code(args: &[&str]) -> Option<i32> {
    wslc_bounded(args, SESSION_TIMEOUT_SECS)
        .await
        .map(|o| o.status.code().unwrap_or(-1))
}

// ─── the runner-wrapped session ──────────────────────────────────────

/// The validation session: `wslc run -i --rm` over the runner-wrapped
/// secure image — the same leg set and assertions as the Kata/Apple
/// sessions, so enforcement evidence attributes identically. A session
/// VM whose kernel cannot fully apply Landlock/seccomp makes the
/// runner refuse the launch — that refusal IS the adoption-relevant
/// finding and fails this test (fail-closed, evidence kept).
#[tokio::test]
async fn wslc_stdio_session() {
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
    let launch_id = uuid::Uuid::now_v7().to_string();
    let name = format!("mcp-writ-wslc-stdio-{}", std::process::id());
    let t0 = Instant::now();
    let mut child = Command::new(wslc_prog())
        .args(session_run_args(
            &dirs, &launch_id, &contract, &name, &secure,
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true)
        .spawn()
        .expect("wslc run failed to spawn — the session VM may be unusable");
    let _guard = UnitGuard(name.clone());
    let mut wire = Wire {
        lines: Vec::new(),
        reader: BufReader::new(child.stdout.take().unwrap()),
        writer: Some(child.stdin.take().unwrap()),
    };

    // initialize — the auditor pins the negotiated revision to exactly
    // 2025-11-25; anything else is a shape rejection.
    wire.send(&request(
        0,
        "initialize",
        "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"wslc-e2e\",\"version\":\"0\"}}",
    ))
    .await;
    let init = wire.wait_id(0, SESSION_TIMEOUT_SECS).await.expect(
        "initialize response never arrived — the session VM came up but \
         the runner failed to serve; runner stderr (inherited above) \
         names the cause. If the runner refused for unmet enforcement \
         (Landlock/seccomp below requirement), that refusal is the \
         adoption finding — see the session's report evidence",
    );
    let first_response_s = t0.elapsed().as_secs_f64();
    assert!(
        init.contains("\"result\"") && init.contains("\"protocolVersion\":\"2025-11-25\""),
        "initialize must return a pinned 2025-11-25 result, got: {init}"
    );

    // Host-side unit evidence while the workload runs.
    let listed = unit_listed(&name).await;
    assert!(listed, "the running unit must appear in `wslc list`");
    let state = unit_state(&name).await;
    assert_eq!(
        state.as_deref(),
        Some("running"),
        "wslc inspect must report the unit running, got {state:?}"
    );

    // Real-client ordering: initialized notification, then the internal
    // tools/list revalidation must settle before tool calls.
    wire.send("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}")
        .await;
    wire.send(&request(1, "tools/list", "{}")).await;
    let list = wire
        .wait_id(1, 60)
        .await
        .expect("tools/list response never arrived");
    assert!(
        list.contains("\"result\"") && list.contains("net_probe"),
        "tools/list must return the probe's tool inventory, got: {list}"
    );

    // Probe legs — identical set to kata/apple: each deny attributes to
    // a specific control layer.
    let legs: &[(i64, &str, &str)] = &[
        (2, "vm_identity", "{\"path\":\"/proc/self/status\"}"),
        (
            3,
            "create_file",
            "{\"path\":\"/workspace/wslc-ok.txt\",\"content\":\"wslc\"}",
        ),
        (4, "read_file", "{\"path\":\"/workspace/wslc-ok.txt\"}"),
        (5, "read_file", "{\"path\":\"/etc/shadow\"}"),
        (6, "chmod_666", "{\"path\":\"/workspace/wslc-ok.txt\"}"),
        (
            7,
            "net_probe",
            "{\"addr\":\"192.0.2.1:80\",\"path\":\"/proc/self/status\"}",
        ),
        (
            8,
            "create_file",
            "{\"path\":\"/etc/evil.txt\",\"content\":\"x\"}",
        ),
        (9, "read_file", "{\"path\":\"/etc/hostname\"}"),
        (10, "exec_shell", "{\"cmd\":\"id\"}"),
    ];
    for (id, name_, args) in legs {
        wire.send(&tool_call(*id, name_, args)).await;
    }
    wire.send(&request(11, "evil/method", "{}")).await;

    let mut got = std::collections::HashMap::new();
    for (id, ..) in legs.iter().chain([(11, "", "")].iter()) {
        let line = wire
            .wait_id(*id, 60)
            .await
            .unwrap_or_else(|| panic!("no response for id={id}"));
        got.insert(*id, line);
    }
    let last_response_s = t0.elapsed().as_secs_f64();

    wire.close_stdin();
    let status = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait())
        .await
        .expect("container did not exit after stdin EOF")
        .expect("wait failed");
    let exit_s = t0.elapsed().as_secs_f64();

    let text_of = |id: i64| got.get(&id).cloned().unwrap_or_default();

    // Guest identity: the session VM's kernel (≠ Windows host), the
    // probe's own enforcement state, virtiofs as the share mechanism —
    // and explicitly NOT the kata cmdline marker (this is a shared
    // session VM, not a per-unit VM claim).
    let ident = text_of(2);
    assert!(
        ident.contains("uname.osrelease=") && ident.contains("NoNewPrivs=1"),
        "vm_identity must report guest kernel + no_new_privs: {ident}"
    );
    assert!(
        ident.contains("Seccomp=2"),
        "guest must report an active seccomp filter: {ident}"
    );
    assert!(
        ident.contains("virtiofs_in_filesystems=true") || ident.contains("9p"),
        "guest must expose virtiofs/9p (the wslc share mechanism): {ident}"
    );
    assert!(
        ident.contains("cmdline_has_kata=false"),
        "session VM must not masquerade as a kata guest: {ident}"
    );

    assert!(
        text_of(3).contains("created /workspace/wslc-ok.txt"),
        "write inside the workspace grant must succeed: {}",
        text_of(3)
    );
    assert!(
        text_of(4).contains("opened /workspace/wslc-ok.txt"),
        "read inside the workspace grant must succeed: {}",
        text_of(4)
    );
    assert!(
        text_of(5).contains("secret-path overlay"),
        "secret paths must deny at the RPC layer: {}",
        text_of(5)
    );
    assert!(
        text_of(6).contains("Operation not permitted"),
        "chmod must hit the seccomp deny: {}",
        text_of(6)
    );
    assert!(
        text_of(7).contains("Operation not permitted") || text_of(7).contains("Permission denied"),
        "TCP connect must hit the network deny: {}",
        text_of(7)
    );
    assert!(
        text_of(8).contains("Permission denied"),
        "write outside the grants must hit Landlock: {}",
        text_of(8)
    );
    assert!(
        text_of(9).contains("Permission denied"),
        "read outside the grants must hit Landlock: {}",
        text_of(9)
    );
    assert!(
        text_of(10).contains("tool is not allowed"),
        "deny=#true tool must be refused by the auditor: {}",
        text_of(10)
    );
    assert!(
        text_of(11).contains("unknown-method"),
        "unknown method must be refused: {}",
        text_of(11)
    );

    assert!(
        status.success(),
        "guest session must exit 0 on stdin EOF, got {status:?}"
    );

    let report_path = dirs.report.join("report.json");
    let report = std::fs::read_to_string(&report_path)
        .unwrap_or_else(|e| panic!("guest report missing at {}: {e}", report_path.display()));
    guest_report::validate_guest_report_text(
        &report,
        uuid::Uuid::parse_str(&launch_id).unwrap(),
        Some(env!("CARGO_PKG_VERSION")),
    )
    .expect("guest report must carry this launch's id and runner identity");
    for needle in [
        "\"status\":\"exited\"",
        "\"os.fs\",\"layer\":\"os\",\"mechanism\":\"landlock\",\"state\":\"planned\"",
        "FullyEnforced",
        "no_new_privs confirmed",
        "seccomp program confirmed",
    ] {
        assert!(
            report.contains(needle),
            "guest report must contain {needle:?} — partial enforcement \
             is an adoption blocker, not a pass"
        );
    }

    let audit = std::fs::read_to_string(dirs.logs.join("audit.jsonl")).expect("audit log missing");
    assert!(
        audit.contains("tool_call.denied") && audit.contains("mcp_message.allowed"),
        "audit log must record allows and denies"
    );

    eprintln!(
        "wslc session evidence: first_response={first_response_s:.2}s \
         last_response={last_response_s:.2}s exit_after_eof={exit_s:.2}s"
    );
    let metrics = format!(
        "{{\"tier\":\"harness\",\"test\":\"wslc_stdio_session\",\"first_response_s\":{first_response_s:.3},\"last_response_s\":{last_response_s:.3},\"exit_s\":{exit_s:.3}}}",
    );
    std::fs::write(dirs._root.path().join("metrics.json"), metrics).unwrap();
}

// ─── MRTR + wire-level stress ────────────────────────────────────────

/// `_meta` marking a 2026-07-28 request with the `elicitation` client
/// capability the probe's `input_required` interim needs to clear the
/// MRTR gate. Mirrors `META_2026_ELICIT` in mcp_wire_e2e.rs.
const META_2026_ELICIT: &str = concat!(
    r#""_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","#,
    r#""io.modelcontextprotocol/clientCapabilities":{"elicitation":{}}}"#,
);

/// MRTR (2026-07-28 `input_required`) and transport-stress legs through
/// `wslc run -i` — same runner/proxy pipeline as the product wrap, so
/// the in-guest gate gets exercised end-to-end:
///   - allow path: `mrtr_probe` with the elicitation capability → the
///     interim forwards → a retry carrying `requestState` +
///     `inputResponses` completes;
///   - deny path: the same call without the capability → the interim is
///     refused (`-32001`) before it can reach the client;
///   - slow peer: `slow_echo` holds the response 2 s — the transport
///     must still deliver it;
///   - excessive output: `big_text` returns a 512 KiB frame — the
///     transport must deliver it whole.
///
/// The session is driven WITHOUT `initialize`: `initialize` pins the
/// wire to 2025-11-25, after which a `_meta`-marked request is a
/// mid-session version switch (denied `MetaVersion`). A session whose
/// first forwarded frame declares 2026-07-28 runs the whole wire at
/// 2026 — that is the MRTR-exercising configuration, matching the
/// substrate-independent wire tests.
#[tokio::test]
async fn wslc_mrtr_and_wire_stress() {
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
    let contract = mount_contract(&_image).await;
    assert!(
        contract.dash_v || contract.long_mount,
        "no working mount form — cannot run the session"
    );

    let dirs = blocking(session_dirs).await;
    // The MRTR policy (v2: mcp rules + input_responses) replaces the
    // copied v1 fixture — same sandbox contract underneath.
    std::fs::copy(fixtures_dir().join("policy_mrtr.kdl"), &dirs.policy)
        .expect("install policy_mrtr.kdl");

    let launch_id = uuid::Uuid::now_v7().to_string();
    let name = format!("mcp-writ-wslc-mrtr-{}", std::process::id());
    let mut child = Command::new(wslc_prog())
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

    // MRTR allow path — the interim result must reach the client.
    wire.send(&format!(
        "{}{}{}",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"mrtr_probe","arguments":{"path":"/proc/self/status"},"#,
        META_2026_ELICIT,
        "}}",
    ))
    .await;
    let interim = wire
        .wait_id(2, SESSION_TIMEOUT_SECS)
        .await
        .expect("mrtr_probe interim response never arrived");
    assert!(
        interim.contains("\"resultType\":\"input_required\"")
            && interim.contains("elicitation/create"),
        "the allowed interim result must reach the client verbatim: {interim}"
    );

    // MRTR retry: new id, requestState echoed, inputResponses keyed by
    // the server's request key — an independent tools/call at the gate.
    wire.send(&format!(
        "{}{}{}",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"mrtr_probe","arguments":{"path":"/proc/self/status"},"requestState":"wslc-seed","inputResponses":{"github_login":{"action":"accept","content":{"name":"octocat"}}},"#,
        META_2026_ELICIT,
        "}}",
    ))
    .await;
    let retry = wire
        .wait_id(3, 60)
        .await
        .expect("mrtr retry response never arrived");
    assert!(
        retry.contains("mrtr-ok") && retry.contains("github_login"),
        "retry with inputResponses must complete the call: {retry}"
    );

    // MRTR deny path — no elicitation capability declared on the
    // request: the interim is refused (-32001) rather than forwarded.
    wire.send(&format!(
        "{}{}{}",
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"mrtr_probe","arguments":{"path":"/proc/self/status"},"#,
        common::META_2026,
        "}}",
    ))
    .await;
    let denied = wire
        .wait_id(4, 60)
        .await
        .expect("mrtr_probe deny-path response never arrived");
    assert!(
        denied.contains("\"error\"") && !denied.contains("input_required"),
        "interim without the client capability must be denied, not forwarded: {denied}"
    );

    // Slow peer — a 2 s tool hold must still deliver through `run -i`.
    let t_slow = Instant::now();
    wire.send(&format!(
        "{}{}{}",
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"slow_echo","arguments":{"ms":2000,"path":"/proc/self/status"},"#,
        common::META_2026,
        "}}",
    ))
    .await;
    let slow = wire
        .wait_id(5, 60)
        .await
        .expect("slow_echo response never arrived");
    let slow_s = t_slow.elapsed().as_secs_f64();
    assert!(
        slow.contains("slept=2000"),
        "slow peer must still answer through the wslc relay: {slow}"
    );
    assert!(
        slow_s >= 1.8,
        "slow_echo answered suspiciously fast ({slow_s:.2}s) — the delay may not have run"
    );

    // Excessive output — a 512 KiB single-frame result must arrive whole.
    wire.send(&format!(
        "{}{}{}",
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"big_text","arguments":{"bytes":524288,"path":"/proc/self/status"},"#,
        common::META_2026,
        "}}",
    ))
    .await;
    let big = wire
        .wait_id(6, 120)
        .await
        .expect("big_text response never arrived");
    assert!(
        big.len() >= 520_000 && big.contains("BIGEND"),
        "512KiB frame must arrive whole, got {} bytes",
        big.len()
    );

    wire.close_stdin();
    let _ = timeout(Duration::from_secs(STOP_TIMEOUT_SECS), child.wait()).await;

    // The audit trail must show both MRTR outcomes: the forwarded
    // additional request AND the denied interim — the capability-less
    // call's `mcp_message.denied` events (`verdict=deny
    // reason=capability` on the additional-request and its response)
    // prove the interim was refused at the gate, not dropped in transit.
    let audit = std::fs::read_to_string(dirs.logs.join("audit.jsonl")).expect("audit log missing");
    assert!(
        audit.contains("additional-request") && audit.contains("elicitation/create"),
        "the allowed elicitation additional-request must be audited"
    );
    assert!(
        audit.contains("mcp_message.denied") && audit.contains("reason=capability"),
        "the capability-less interim must be audited as denied, got: {audit}"
    );

    let record = format!(
        "{{\"tier\":\"harness\",\"test\":\"wslc_mrtr_and_wire_stress\",\
         \"interim\":{},\"retry\":{},\"denied\":{},\
         \"slow_s\":{slow_s:.3},\"big_bytes\":{}}}",
        json_str(&clip(&interim, 400)),
        json_str(&clip(&retry, 400)),
        json_str(&clip(&denied, 400)),
        big.len(),
    );
    std::fs::write(dirs._root.path().join("mrtr.json"), record).expect("write mrtr.json");
}
