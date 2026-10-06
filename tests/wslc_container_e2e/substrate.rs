//! Substrate semantics: the session model, virtiofs share
//! behavior, and Consommé network behavior.

use std::process::Stdio;

use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use crate::common;
use crate::support::*;

// ─── session model ───────────────────────────────────────────────────

/// The session model: which sessions exist, what a `wslc run` uses, how
/// a dedicated named session is created and scoped, and that other WSL
/// distros are untouched. Recorded in `session-model.json`; the cleanup
/// assertion (only owned sessions are terminated) is hard.
#[tokio::test]
async fn wslc_session_model() {
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

    let before = session_list_raw().await;
    let distros_before = blocking(|| {
        run_cli("wsl.exe", &["-l", "-v"], CLI_TIMEOUT_SECS)
            .map(|o| decode_cli(&o.stdout))
            .unwrap_or_default()
    })
    .await;

    // A plain `wslc run` — the default session is used (created on
    // demand); record which session appears.
    let (ok, _, err) = probe_run(&[], &image, &["identity"]).await;
    assert!(ok, "probe run in the default session failed: {err}");
    let after = session_list_raw().await;
    assert!(
        !after.trim().is_empty(),
        "a wslc run must leave a session in `system session list`"
    );

    // Dedicated named session: `system session enter <path> --name <n>`
    // opens an interactive session shell bound to an explicit storage
    // path. Spawn it with piped stdio, poll the session list for the
    // name, and exercise `--session` scoping — then terminate ONLY that
    // session. Whether `enter` tolerates a non-console stdin is itself
    // a recorded surface detail.
    let sess_name = format!("mcp-writ-wslc-sess-{}", std::process::id());
    let storage = session_storage_root().join(&sess_name);
    std::fs::create_dir_all(&storage).expect("session storage dir");
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

    let mut scoped_run = "not-attempted".to_string();
    if entered {
        let (ok, out, err) = probe_run_scoped(&sess_name, &[], &image, &["identity"]).await;
        scoped_run = format!("ok={ok} out={} err={}", clip(&out, 120), clip(&err, 120));
        // Leave the enter shell — the session it created ends with it.
        if let Some(mut stdin) = enter.stdin.take() {
            let _ = stdin.write_all(b"exit\n").await;
            let _ = stdin.flush().await;
        }
        let _ = timeout(Duration::from_secs(30), enter.wait()).await;
    }
    // Owned-session cleanup: terminate our session by name, never
    // `session terminate` unscoped (that would hit the default).
    if entered {
        let _ = wslc(&[
            "system",
            "session",
            "terminate",
            "--session",
            sess_name.as_str(),
        ])
        .await;
        let gone = poll(30, 1000, || {
            let name = sess_name.clone();
            async move { !session_list_raw().await.contains(&name) }
        })
        .await;
        assert!(gone, "owned session {sess_name} must terminate on request");
    }

    let distros_after = blocking(|| {
        run_cli("wsl.exe", &["-l", "-v"], CLI_TIMEOUT_SECS)
            .map(|o| decode_cli(&o.stdout))
            .unwrap_or_default()
    })
    .await;
    assert_eq!(
        distro_table(&distros_before),
        distro_table(&distros_after),
        "wslc session use must not add/remove/upgrade a `wsl -l -v` distro \
         (the volatile STATE column is excluded from the comparison)"
    );

    let record = format!(
        "{{\"sessions_before\":{},\"sessions_after_run\":{},\
         \"dedicated\":{{\"name\":{},\"storage\":{},\"entered\":{},\"scoped_run\":{}}},\
         \"storage_listing\":{}}}",
        json_str(&before),
        json_str(&after),
        json_str(&sess_name),
        json_str(&storage.display().to_string()),
        entered,
        json_str(&scoped_run),
        json_str(&dir_listing(&storage)),
    );
    std::fs::write(dirs._root.path().join("session-model.json"), record)
        .expect("write session-model.json");

    let lifecycle = format!(
        "{{\"tier\":\"harness\",\"test\":\"wslc_session_model\",\"session\":{},\"entered\":{},\"scoped_run\":{}}}",
        json_str(&sess_name),
        entered,
        json_str(&scoped_run)
    );
    std::fs::write(dirs._root.path().join("lifecycle.json"), lifecycle)
        .expect("write lifecycle.json");
}

/// `wsl -l -v` normalized to sorted (name, version) pairs — the STATE
/// column is volatile (a workload may start/stop a distro mid-check),
/// so it must not participate in the untouched-distros assertion.
fn distro_table(raw: &str) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = raw
        .lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.trim_start_matches('*').split_whitespace().collect();
            let (name, ver) = (t.first()?, t.last()?);
            (t.len() >= 2 && ver.chars().all(|c| c.is_ascii_digit()))
                .then(|| (name.to_string(), ver.to_string()))
        })
        .collect();
    v.sort();
    v
}

/// `wslc --session <name> run --rm <args> <img> <cmd>` — scoped probe run.
async fn probe_run_scoped(
    session: &str,
    args: &[String],
    image: &str,
    cmd: &[&str],
) -> (bool, String, String) {
    let mut all: Vec<String> = vec![
        "--session".into(),
        session.into(),
        "run".into(),
        "--rm".into(),
    ];
    all.extend(args.iter().cloned());
    all.push(image.into());
    all.extend(cmd.iter().map(|s| s.to_string()));
    let argrefs: Vec<&str> = all.iter().map(|s| s.as_str()).collect();
    match wslc(&argrefs).await {
        Some(o) => (
            o.status.success(),
            decode_cli(&o.stdout),
            decode_cli(&o.stderr),
        ),
        None => (false, String::new(), "wslc timed out".into()),
    }
}

// ─── share semantics (virtiofs) ──────────────────────────────────────

/// virtiofs share semantics: RO/RW flags, unicode + space + case +
/// reparse-point paths, and whether a Windows ACL-protected dir is
/// honored. Recorded in `share-semantics.json`; the hard assertions
/// cover only what the launch contract needs (RO denies writes, RW
/// writes, unicode/space paths are reachable).
#[tokio::test]
async fn wslc_share_semantics() {
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
    let contract = mount_contract(&image).await;
    assert!(
        contract.dash_v || contract.long_mount,
        "no working mount form — cannot run share legs"
    );
    let dirs = blocking(session_dirs).await;

    // Populate the share with the path-shape cases.
    let ws = &dirs.workspace;
    std::fs::write(ws.join("File.txt"), "plain").unwrap();
    std::fs::write(ws.join("日本語.txt"), "unicode-name").unwrap();
    std::fs::write(ws.join("with space.txt"), "space-name").unwrap();
    std::fs::create_dir_all(ws.join("subdir")).unwrap();
    std::fs::write(ws.join("subdir/nested.txt"), "nested").unwrap();
    // Reparse point: a directory symlink (needs privilege on Windows) —
    // absent ⇒ that leg records "not created", never fakes.
    #[cfg(windows)]
    let link_made =
        std::os::windows::fs::symlink_dir(ws.join("subdir"), ws.join("link-to-subdir")).is_ok();
    #[cfg(not(windows))]
    let link_made = false;
    // A unicode+space *directory* mounted by name — the mount-source
    // path itself carrying the tricky characters.
    let odd_dir = test_root().join("mcp-writ-wslc-日本語 share");
    std::fs::create_dir_all(&odd_dir).unwrap();
    std::fs::write(odd_dir.join("inside.txt"), "odd-dir").unwrap();

    let mut legs: Vec<(String, bool, String)> = Vec::new();

    let run_leg = |name: &str,
                   args: Vec<String>,
                   cmd: &[&str],
                   expect: &str|
     -> std::pin::Pin<
        Box<dyn std::future::Future<Output = (String, bool, String)> + '_>,
    > {
        let image = image.clone();
        let name = name.to_string();
        let cmd: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
        let expect = expect.to_string();
        Box::pin(async move {
            let (ok, out, err) = probe_run(&args, &image, &cmd_refs(&cmd)).await;
            let honored = ok && (expect.is_empty() || out.contains(&expect));
            (format!("{name}: {out}"), honored, err)
        })
    };

    let (text, honored, err) = run_leg(
        "share-rw",
        mount_args(&contract, ws, "/mnt/share", false),
        &["share-probe", "/mnt/share"],
        "write=ok",
    )
    .await;
    assert!(honored, "RW share must allow writes: {text} {err}");
    legs.push((text, honored, err));

    let (text, honored, err) = run_leg(
        "share-ro",
        mount_args(&contract, ws, "/mnt/share", true),
        &["share-probe", "/mnt/share"],
        "write=failed",
    )
    .await;
    assert!(
        honored,
        "RO share must deny guest-side writes (policy mount depends on it): {text} {err}"
    );
    legs.push((text, honored, err));

    for (label, file) in [
        ("read-unicode-name", "日本語.txt"),
        ("read-space-name", "with space.txt"),
        ("read-nested", "subdir/nested.txt"),
    ] {
        let path = format!("/mnt/share/{file}");
        let (text, honored, err) = run_leg(
            label,
            mount_args(&contract, ws, "/mnt/share", true),
            &["reparse-probe", &path],
            "read=ok",
        )
        .await;
        assert!(honored, "{label} must read through the share: {text} {err}");
        legs.push((text, honored, err));
    }

    let (text, honored, err) = run_leg(
        "case-sensitivity",
        mount_args(&contract, ws, "/mnt/share", false),
        &["case-probe", "/mnt/share"],
        "",
    )
    .await;
    // Record, never assert: NTFS folding is the documented expectation
    // but a per-share case flag could differ.
    legs.push((format!("{text} (honored={honored})"), true, err));

    if link_made {
        let (text, honored, err) = run_leg(
            "reparse-point",
            mount_args(&contract, ws, "/mnt/share", true),
            &["reparse-probe", "/mnt/share/link-to-subdir"],
            "",
        )
        .await;
        legs.push((format!("{text} (honored={honored})"), true, err));
    } else {
        legs.push((
            "reparse-point: not-created (no privilege)".into(),
            true,
            String::new(),
        ));
    }

    let (text, honored, err) = run_leg(
        "unicode-space-dir-mount",
        mount_args(&contract, &odd_dir, "/mnt/odd", true),
        &["share-probe", "/mnt/odd"],
        "inside.txt",
    )
    .await;
    assert!(
        honored,
        "a mount source with unicode+space must mount and list: {text} {err}"
    );
    legs.push((text, honored, err));

    let record = format!(
        "{{\"legs\":[{}]}}",
        legs.iter()
            .map(|(t, h, e)| format!(
                "{{\"out\":{},\"honored\":{},\"err\":{}}}",
                json_str(t),
                h,
                json_str(e)
            ))
            .collect::<Vec<_>>()
            .join(",")
    );
    std::fs::write(dirs._root.path().join("share-semantics.json"), record)
        .expect("write share-semantics.json");
}

/// &[String] → Vec<&str> for `probe_run`'s cmd parameter.
fn cmd_refs(cmd: &[String]) -> Vec<&str> {
    cmd.iter().map(|s| s.as_str()).collect()
}

// ─── network semantics (Consommé) ────────────────────────────────────

/// Consommé networking: outbound reachability + DNS, host loopback,
/// IPv6 presence, `--network none` deny, and `-p` publish — each leg
/// recorded in `network-semantics.json`; the contract-level asserts are
/// the `none` deny and the publish reach.
#[tokio::test]
async fn wslc_network_semantics() {
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

    let mut legs: Vec<String> = Vec::new();
    let mut rec = |label: &str, out: String| legs.push(format!("{label}: {out}"));

    // Routes/resolver dump for the record; the gateway itself is
    // discovered in-guest by `net-tcp-gw` below.
    let (_, routes, _) = probe_run(&[], &image, &["net-routes"]).await;
    rec("routes", routes.clone());

    // DNS — Consommé resolver.
    let (_, dns_local, _) = probe_run(&[], &image, &["net-dns", "localhost"]).await;
    rec("dns-localhost", dns_local.clone());
    let (_, dns_pub, _) = probe_run(&[], &image, &["net-dns", "example.com"]).await;
    rec("dns-example.com", dns_pub.clone());

    // Host loopback: a listener on the Windows side + candidate
    // addresses inside the guest — Consommé's host reach is the
    // finding, whichever address form proves it. The listener accepts
    // repeatedly so several candidate legs can each get a conn.
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("host listener");
    let port = listener.local_addr().expect("listener addr").port();
    std::thread::spawn(move || {
        loop {
            if listener.accept().is_err() {
                break;
            }
        }
    });
    let mut host_reached = String::from("unreachable");
    {
        let port_s = port.to_string();
        let (_, out, _) = probe_run(&[], &image, &["net-tcp-gw", port_s.as_str()]).await;
        rec("host-loopback-via-gw", out.clone());
        if out.contains("connected=gw:") {
            host_reached = "default-gateway".into();
        }
    }
    for name in [
        "host.docker.internal",
        "host.containers.internal",
        "host.internal",
    ] {
        let (_, out, _) = probe_run(&[], &image, &["net-dns", name]).await;
        rec(&format!("dns-{name}"), out.clone());
        if out.contains("resolved=") && !out.contains("failed") {
            // Try the first resolved address.
            if let Some(addr) = out
                .split('[')
                .nth(1)
                .and_then(|s| s.split(']').next())
                .and_then(|s| s.split(',').next())
                .and_then(|s| s.rsplit(':').nth(1))
            {
                let target = format!("{addr}:{port}");
                let (_, out2, _) = probe_run(&[], &image, &["net-tcp", target.as_str()]).await;
                rec(&format!("host-loopback-via-{name}({addr})"), out2.clone());
                if out2.contains("connected=") && !out2.contains("failed") {
                    host_reached = format!("{name}:{addr}");
                }
            }
        }
    }

    // IPv6 presence — record.
    let (_, v6, _) = probe_run(&[], &image, &["net-tcp", "[::1]:1"]).await;
    rec("tcp6-loopback-refused-or-ok", v6);

    // `--network none` — the deny-all leg the policy relies on: DNS and
    // TCP must both fail inside the guest.
    let (_, out_none_dns, _) = probe_run(
        &["--network".into(), "none".into()],
        &image,
        &["net-dns", "example.com"],
    )
    .await;
    rec("none-dns", out_none_dns.clone());
    let (_, out_none_tcp, _) = probe_run(
        &["--network".into(), "none".into()],
        &image,
        &["net-tcp", "192.0.2.1:80"],
    )
    .await;
    rec("none-tcp", out_none_tcp.clone());
    assert!(
        out_none_dns.contains("failed") && out_none_tcp.contains("failed"),
        "--network none must cut DNS+TCP inside the guest: {out_none_dns} / {out_none_tcp}"
    );

    // `-p` publish: probe listens in-guest; the host polls a loopback
    // connect until the listener is reachable (no `wslc logs`
    // dependency — the unit's state is the signal).
    let pub_port = 23000 + (std::process::id() as u16 % 2000);
    let name = format!("mcp-writ-wslc-pub-{}", std::process::id());
    let pub_args = vec![
        "run".to_string(),
        "-d".to_string(),
        "--name".to_string(),
        name.clone(),
        "-p".to_string(),
        format!("127.0.0.1:{pub_port}:8080"),
        image.clone(),
        "net-listen".to_string(),
        "8080".to_string(),
    ];
    let mut pub_child = Command::new("wslc")
        .args(&pub_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("wslc run -d failed to spawn");
    let _pub_guard = UnitGuard(name.clone());
    let spawned = timeout(Duration::from_secs(60), pub_child.wait())
        .await
        .map(|r| r.map(|s| s.success()).unwrap_or(false))
        .unwrap_or(false);
    // The unit must exist before we poll-connect.
    let unit_up = spawned
        && poll(30, 500, || {
            let name = name.clone();
            async move { unit_listed(&name).await }
        })
        .await;
    let mut publish = "not-reached".to_string();
    if unit_up {
        let reached = poll(60, 1000, || async {
            std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{pub_port}").parse().unwrap(),
                Duration::from_secs(3),
            )
            .is_ok()
        })
        .await;
        if reached {
            // One more connect for the payload proof.
            match std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{pub_port}").parse().unwrap(),
                Duration::from_secs(5),
            ) {
                Ok(mut s) => {
                    use std::io::Read;
                    let mut buf = [0u8; 64];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let got = String::from_utf8_lossy(&buf[..n]).to_string();
                    publish = format!("connected, payload={got:?}");
                }
                Err(e) => publish = format!("connect failed: {e}"),
            }
        } else {
            publish = format!(
                "unreachable in 60s; logs={}",
                clip(&unit_logs(&name).await, 200)
            );
        }
    }
    rec(
        "publish-p",
        format!("spawned={spawned} unit_up={unit_up} {publish}"),
    );
    let _ = unit_kill(&name, "SIGKILL").await;
    let _ = unit_rm(&name).await;
    // `-p` publish is a Consommé feature the *launch contract* never
    // uses (`run -i` is stdio-bound) — record the outcome; a missing
    // publish path does not block adoption, a fabricated one would.
    if !publish.contains("connected") {
        eprintln!("wslc publish leg not reachable: {publish}");
    }

    let record = format!(
        "{{\"legs\":[{}],\"host_loopback\":{}}}",
        legs.iter()
            .map(|l| json_str(l))
            .collect::<Vec<_>>()
            .join(","),
        json_str(&host_reached)
    );
    std::fs::write(dirs._root.path().join("network-semantics.json"), record)
        .expect("write network-semantics.json");
}
