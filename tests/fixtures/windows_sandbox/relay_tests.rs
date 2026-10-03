//! Included in the Windows Sandbox integration target; no product entrypoint.
use super::*;

struct TransportSession {
    agent: ProcGuard,
    relay: Relay,
    dirs: WsbDirs,
}

fn transport_session(mode: &str) -> Option<TransportSession> {
    if let Some(reason) = check_host_prereqs() {
        common::skip_wsb_test(&reason);
        return None;
    }
    let agent = compiled_agent()?;
    static CHILD: OnceLock<Option<PathBuf>> = OnceLock::new();
    let child = CHILD
        .get_or_init(|| compiled_fixture("transport_child.rs", "transport-child.exe"))
        .as_ref()?;
    let dirs = session_dirs();
    let root = dirs._root.path();
    let stage = root.join("stage");
    let deny = root.join("deny");
    let tmp = root.join("tmp");
    let launch = uuid::Uuid::now_v7().to_string();
    let token = new_token();
    let port = pick_port();
    let config = relay_config(
        &launch,
        &token,
        port,
        &["127.0.0.1".into()],
        &[
            ("ro_dir", &dirs.ro),
            ("rw_dir", &dirs.rw),
            ("stage_dir", &stage),
            ("deny_dir", &deny),
            ("temp_dir", &tmp),
        ],
    );
    let real_runner = mode.starts_with("runner-");
    let runner = if real_runner {
        windows_runner()?
    } else {
        child.clone()
    };
    let probe = if real_runner {
        compiled_probe()?
    } else {
        child.clone()
    };
    let policy = if mode == "runner-audit-failure" {
        std::fs::create_dir_all(dirs.rw.join("logs/audit.jsonl")).unwrap();
        loopback_policy(&dirs, &stage, &deny)
    } else {
        mode.to_string()
    };
    std::fs::create_dir_all(&tmp).unwrap();
    stage_ro_dir(&dirs, &runner, &agent, &probe, &policy, &config);
    let agent = ProcGuard(
        Command::new(agent)
            .arg("--config")
            .arg(dirs.ro.join("relay-config.txt"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(
        wait_file(&dirs.rw.join("relay-hello.txt"), 20),
        "{:?}",
        relay_status_lines(&dirs.rw)
    );
    let relay = Relay::connect(&format!("127.0.0.1:{port}"), &launch, &token).unwrap();
    Some(TransportSession { agent, relay, dirs })
}

#[test]
fn wsb_relay_loopback_runner_failures_are_not_success() {
    for mode in ["runner-invalid-policy", "runner-audit-failure"] {
        let Some(mut session) = transport_session(mode) else {
            return;
        };
        session.relay.send_line(&request(0, "initialize", "{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"failure-test\",\"version\":\"0\"}}"));
        let code = session
            .relay
            .wait_exit(30)
            .expect("failed runner must send exit");
        assert!(code.is_some_and(|c| c != 0), "{mode}: {code:?}");
        assert!(
            session.relay.lines.is_empty(),
            "failed controls must not serve MCP"
        );
        assert!(!session.relay.stderr_bytes.is_empty());
        wait_agent(&mut session, 5);
    }
}

fn wait_agent(session: &mut TransportSession, secs: u64) {
    assert!(
        wait_until(secs, || session.agent.0.try_wait().unwrap().is_some()),
        "agent did not exit: {:?}",
        relay_status_lines(&session.dirs.rw)
    );
}

fn read_pid(path: &Path) -> u32 {
    assert!(wait_until(10, || std::fs::read_to_string(path)
        .is_ok_and(|s| s.parse::<u32>().is_ok())));
    std::fs::read_to_string(path).unwrap().parse().unwrap()
}

fn assert_pid_gone(pid: u32) {
    assert!(
        wait_until(10, || {
            let out = Command::new("tasklist")
                .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
                .output()
                .expect("tasklist");
            assert!(out.status.success());
            !String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|l| l.split(',').nth(1) == Some(&format!("\"{pid}\"")))
        }),
        "owned process {pid} leaked"
    );
}

#[test]
fn wsb_relay_loopback_large_frames_slow_reader() {
    let Some(mut session) = transport_session("echo") else {
        return;
    };
    let mut sender = session.relay.conn.try_clone().unwrap();
    let payload: Vec<u8> = (0..MAX_FRAME).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let send = std::thread::spawn(move || {
        for _ in 0..16 {
            write_frame(&mut sender, F_STDIN, &payload).unwrap();
        }
        write_frame(&mut sender, F_STDIN_EOF, b"").unwrap();
    });
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut received = 0;
    loop {
        assert!(Instant::now() < deadline, "slow-reader session wedged");
        match session.relay.reader.poll(&mut session.relay.conn).unwrap() {
            None => continue,
            Some((F_STDOUT, bytes)) => {
                for byte in bytes {
                    assert_eq!(byte, expected[received % MAX_FRAME]);
                    received += 1;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Some((F_EXIT, bytes)) => {
                assert_eq!(bytes, b"{\"code\":0}");
                break;
            }
            frame => panic!("unexpected transport frame {frame:?}"),
        }
    }
    send.join().unwrap();
    assert_eq!(received, 16 * MAX_FRAME);
    wait_agent(&mut session, 5);
}

#[test]
fn wsb_relay_loopback_stalled_output_is_bounded() {
    let Some(mut session) = transport_session("flood") else {
        return;
    };
    let child = read_pid(&session.dirs.rw.join("report/child.pid"));
    // Keep the socket open without reading. Sending and drain must time out.
    wait_agent(&mut session, 40);
    assert_pid_gone(child);
    let status = relay_status_lines(&session.dirs.rw).join("\n");
    assert!(
        status.contains("socket error") || status.contains("drain"),
        "{status}"
    );
}

#[test]
fn wsb_relay_loopback_stalled_input_is_bounded() {
    let Some(mut session) = transport_session("noinput") else {
        return;
    };
    let child = read_pid(&session.dirs.rw.join("report/child.pid"));
    let mut conn = session.relay.conn.try_clone().unwrap();
    let send = std::thread::spawn(move || {
        let bytes = vec![b'x'; MAX_FRAME];
        for _ in 0..64 {
            if write_frame(&mut conn, F_STDIN, &bytes).is_err() {
                return;
            }
        }
        panic!("64 MiB accepted from a stalled input without backpressure");
    });
    wait_agent(&mut session, 40);
    send.join().unwrap();
    assert_pid_gone(child);
    assert!(
        relay_status_lines(&session.dirs.rw)
            .join("\n")
            .contains("backpressure deadline")
    );
}

#[test]
fn wsb_relay_loopback_cancel_disconnect_and_agent_crash_reap_tree() {
    for action in ["cancel", "disconnect", "agent-crash", "eof-timeout"] {
        let Some(mut session) = transport_session("eof-hang") else {
            return;
        };
        let child = read_pid(&session.dirs.rw.join("report/child.pid"));
        let descendant = read_pid(&session.dirs.rw.join("report/descendant.pid"));
        session.relay.stdin_eof();
        match action {
            "cancel" => session.relay.try_send(F_CANCEL, b"").unwrap(),
            "disconnect" => session
                .relay
                .conn
                .shutdown(std::net::Shutdown::Both)
                .unwrap(),
            "agent-crash" => session.agent.0.kill().unwrap(),
            _ => {}
        }
        wait_agent(&mut session, 35);
        assert_pid_gone(child);
        assert_pid_gone(descendant);
    }
}

#[test]
fn wsb_relay_loopback_stderr_flood_is_drained_and_capped() {
    let Some(mut session) = transport_session("stderr") else {
        return;
    };
    assert_eq!(session.relay.wait_exit(30), Some(Some(0)));
    assert_eq!(session.relay.stderr_bytes.len(), 64 * 1024);
    assert_eq!(session.relay.lines, ["OK\n"]);
    wait_agent(&mut session, 5);
    assert_eq!(
        std::fs::metadata(session.dirs.rw.join("stderr.log"))
            .unwrap()
            .len(),
        256 * 1024
    );
}

#[test]
fn wsb_relay_loopback_invalid_session_frames_fail_closed() {
    for kind in [F_HELLO, 0xff, F_STDIN_EOF, F_CANCEL] {
        let Some(mut session) = transport_session("noinput") else {
            return;
        };
        session.relay.try_send(kind, b"invalid").unwrap();
        wait_agent(&mut session, 10);
        assert!(
            relay_status_lines(&session.dirs.rw)
                .join("\n")
                .contains("unexpected frame")
        );
    }
    let Some(mut session) = transport_session("noinput") else {
        return;
    };
    session
        .relay
        .conn
        .write_all(&[F_STDIN, 0, 0x10, 0, 1])
        .unwrap();
    wait_agent(&mut session, 10);
    assert!(
        relay_status_lines(&session.dirs.rw)
            .join("\n")
            .contains("1 MiB")
    );
}

#[test]
fn wsb_relay_loopback_partial_frame_deadline() {
    let Some(mut session) = transport_session("noinput") else {
        return;
    };
    session.relay.conn.write_all(&[F_STDIN, 0]).unwrap();
    wait_agent(&mut session, 30);
    assert!(
        relay_status_lines(&session.dirs.rw)
            .join("\n")
            .contains("frame deadline")
    );
}

#[test]
fn wsb_transport_fragmented_frame_survives_poll_timeouts() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let mut reader = FrameReader::default();
    for part in [&[F_STDOUT, 0][..], &[0, 0, 3][..], b"ab"] {
        client.write_all(part).unwrap();
        assert!(reader.poll(&mut server).unwrap().is_none());
    }
    client.write_all(b"c").unwrap();
    assert_eq!(
        reader.poll(&mut server).unwrap(),
        Some((F_STDOUT, b"abc".to_vec()))
    );
    write_frame(&mut client, F_EXIT, b"{}").unwrap();
    assert_eq!(
        reader.poll(&mut server).unwrap(),
        Some((F_EXIT, b"{}".to_vec()))
    );
    client.write_all(&[F_STDOUT, 0, 0x10, 0, 1]).unwrap();
    assert_eq!(
        reader.poll(&mut server).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
}

#[test]
fn wsb_transport_forged_agent_never_receives_host_credential() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let peer = std::thread::spawn(move || {
        let (mut server, _) = listener.accept().unwrap();
        write_frame(
            &mut server,
            F_PEER,
            hello("wrong-launch", "wrong-secret").as_bytes(),
        )
        .unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut byte = [0];
        match server.read(&mut byte) {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            result => panic!("host sent data or kept forged connection: {result:?}"),
        }
    });
    assert!(Relay::connect(&addr, &uuid::Uuid::now_v7().to_string(), &new_token()).is_err());
    peer.join().unwrap();
}

#[test]
fn wsb_transport_owned_id_cleanup_on_success_failure_and_timeout() {
    if let Some(reason) = check_host_prereqs() {
        common::skip_wsb_test(&reason);
        return;
    }
    let Some(stub) = compiled_fixture("wsb_cli_stub.rs", "wsb-cli-stub.exe") else {
        return;
    };
    for mode in [
        "ok",
        "fail",
        "timeout",
        "collision",
        "existing",
        "invalid-list",
    ] {
        let dir = tempfile::tempdir_in(test_root()).unwrap();
        let cli = dir.path().join("wsb-cli-stub.exe");
        std::fs::copy(&stub, &cli).unwrap();
        let id = uuid::Uuid::now_v7().to_string();
        let other = uuid::Uuid::now_v7().to_string();
        let ids = match mode {
            "collision" => format!("{{\"WindowsSandboxEnvironments\":[{{\"Id\":\"{id}\"}}]}}"),
            "existing" => format!("{{\"WindowsSandboxEnvironments\":[{{\"Id\":\"{other}\"}}]}}"),
            "invalid-list" => "{}".into(),
            // An unrelated JSON field must not be mistaken for an instance ID.
            _ => format!("{{\"WindowsSandboxEnvironments\":[],\"trace_id\":\"{id}\"}}"),
        };
        std::fs::write(dir.path().join("ids.txt"), ids).unwrap();
        let result = SandboxGuard::launch_with(cli, id.clone(), mode, Duration::from_secs(1));
        if mode == "ok" {
            result.unwrap().kill().unwrap();
        } else {
            assert!(result.is_err());
        }
        let calls = std::fs::read_to_string(dir.path().join("calls.txt")).unwrap();
        assert!(
            !calls.contains(&other),
            "other instance was targeted: {calls}"
        );
        if matches!(mode, "collision" | "existing" | "invalid-list") {
            assert!(!calls.contains("start") && !calls.contains("stop"));
        } else {
            assert_eq!(
                calls
                    .lines()
                    .filter(|l| l.starts_with("stop\t") && l.contains(&id))
                    .count(),
                1,
                "{calls}"
            );
        }
    }
}

/// Repeat the adverse pipe behaviors over the actual Default Switch and
/// mapped folders. The successful Warden/MCP path has its own VM test; these
/// transport fixtures deliberately bypass the runner to isolate pipe stalls.
#[test]
fn wsb_relay_sandbox_transport_lifecycle() {
    if let Some(reason) = check_sandbox_prereqs() {
        common::skip_wsb_test(&reason);
        return;
    }
    let Some(host_ip) = host_default_switch_ip() else {
        common::skip_wsb_test("no Default Switch IPv4");
        return;
    };
    let _vm_guard = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(agent) = compiled_agent() else {
        return;
    };
    let Some(child) = compiled_fixture("transport_child.rs", "transport-child.exe") else {
        return;
    };
    let Some(runner) = windows_runner() else {
        return;
    };
    let Some(probe) = compiled_probe() else {
        return;
    };
    for mode in [
        "echo",
        "flood",
        "noinput",
        "cancel",
        "disconnect",
        "eof-timeout",
        "crash",
        "runner-invalid-policy",
        "runner-audit-failure",
    ] {
        let dirs = session_dirs();
        let launch = uuid::Uuid::now_v7().to_string();
        let token = new_token();
        let port = pick_port();
        let policy = match mode {
            "cancel" | "disconnect" | "eof-timeout" => "eof-hang".to_string(),
            "runner-audit-failure" => {
                std::fs::create_dir_all(dirs.rw.join("logs/audit.jsonl")).unwrap();
                sandbox_policy()
            }
            _ => mode.to_string(),
        };
        let real = mode.starts_with("runner-");
        stage_ro_dir(
            &dirs,
            if real { &runner } else { &child },
            &agent,
            if real { &probe } else { &child },
            &policy,
            &sandbox_config(&launch, &token, port, &host_ip),
        );
        let mut sandbox = SandboxGuard::launch(&write_wsb_file(&dirs));
        let hello_path = dirs.rw.join("relay-hello.txt");
        assert!(
            wait_file(&hello_path, SANDBOX_BOOT_SECS),
            "{mode}: {:?}",
            relay_status_lines(&dirs.rw)
        );
        let addr = read_relay_hello(&hello_path).expect("guest endpoint");
        let mut relay = Relay::connect(&addr, &launch, &token).unwrap();
        match mode {
            "echo" => {
                let mut writer = relay.conn.try_clone().unwrap();
                let send = std::thread::spawn(move || {
                    write_frame(&mut writer, F_STDIN, &vec![b'x'; MAX_FRAME]).unwrap();
                    write_frame(&mut writer, F_STDIN_EOF, b"").unwrap();
                });
                let mut received = 0;
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    assert!(Instant::now() < deadline, "VM echo stalled");
                    match relay.reader.poll(&mut relay.conn).unwrap() {
                        None => {}
                        Some((F_STDOUT, bytes)) => {
                            assert!(bytes.iter().all(|b| *b == b'x'));
                            received += bytes.len();
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Some((F_EXIT, bytes)) => {
                            assert_eq!(bytes, b"{\"code\":0}");
                            break;
                        }
                        frame => panic!("unexpected VM echo frame: {frame:?}"),
                    }
                }
                send.join().unwrap();
                assert_eq!(received, MAX_FRAME);
            }
            "noinput" => {
                // This sender has the same complete-frame deadline as the agent.
                let mut writer = relay.conn.try_clone().unwrap();
                let send = std::thread::spawn(move || {
                    for _ in 0..64 {
                        if write_frame(&mut writer, F_STDIN, &vec![b'x'; MAX_FRAME]).is_err() {
                            return;
                        }
                    }
                    panic!("stalled VM accepted unbounded input");
                });
                send.join().unwrap();
            }
            "cancel" | "disconnect" | "eof-timeout" => {
                assert!(wait_file(&dirs.rw.join("report/descendant.pid"), 15));
                relay.stdin_eof();
                if mode == "cancel" {
                    relay.try_send(F_CANCEL, b"").unwrap();
                }
                if mode == "disconnect" {
                    relay.conn.shutdown(std::net::Shutdown::Both).unwrap();
                }
            }
            "crash" | "runner-invalid-policy" | "runner-audit-failure" => {
                let code = relay.wait_exit(30).expect("VM failure exit frame");
                assert!(code.is_some_and(|c| c != 0), "{mode}: {code:?}");
                assert!(relay.lines.is_empty(), "failed runner served MCP");
            }
            _ => {} // flood: deliberately stop reading until the agent times out
        }
        assert!(
            wait_until(40, || relay_status_lines(&dirs.rw)
                .iter()
                .any(|l| l.contains("done: child exit") || l.contains("fatal:"))),
            "{mode}: agent failed to terminate: {:?}",
            relay_status_lines(&dirs.rw)
        );
        stop_sandbox(&mut sandbox, &dirs);
        eprintln!("VM transport case {mode}: terminated and owned ID stopped");
    }
}
