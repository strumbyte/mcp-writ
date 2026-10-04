//! Acceptance through the actual command/payload product path.
use super::*;
use std::io::{BufRead, BufReader};

struct Product {
    child: ProcGuard,
    input: Option<std::process::ChildStdin>,
    output: std::sync::mpsc::Receiver<String>,
    dirs: WsbDirs,
    state: PathBuf,
    started: Instant,
}

impl Product {
    fn launch() -> Option<Self> {
        Self::launch_policy(sandbox_policy())
    }
    fn launch_policy(policy_text: String) -> Option<Self> {
        if let Some(reason) = check_sandbox_prereqs() {
            common::skip_wsb_test(&reason);
            return None;
        }
        let probe = compiled_probe()?;
        let dirs = session_dirs();
        std::fs::copy(probe, dirs.ro.join("server.exe")).unwrap();
        let policy = dirs._root.path().join("policy.kdl");
        std::fs::write(&policy, policy_text).unwrap();
        let state = dirs._root.path().join("state");
        std::fs::create_dir(&state).unwrap();
        host_memory_snapshot(&dirs.rw, "before");
        let started = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
            .args(["run", "--isolation", "windows-sandbox", "--sandbox-payload"])
            .arg(&dirs.ro)
            .arg("--sandbox-state")
            .arg(&state)
            .arg("--sandbox-runtime")
            .arg(
                Path::new(env!("CARGO_BIN_EXE_mcp-writ-wsb-relay"))
                    .parent()
                    .unwrap(),
            )
            .arg("--policy")
            .arg(policy)
            .arg("--report")
            .arg(dirs.rw.join("host-report.json"))
            .args(["--", "server.exe"])
            // Product must keep enforcement even when this host override exists.
            .env("MCP_WRIT_SKIP_SANDBOX", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(std::fs::File::create(dirs.rw.join("product-stderr.log")).unwrap())
            .spawn()
            .unwrap();
        let input = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let (tx, output) = std::sync::mpsc::sync_channel(8);
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else {
                    break;
                };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        Some(Self {
            child: ProcGuard(child),
            input,
            output,
            dirs,
            state,
            started,
        })
    }
    fn send(&mut self, text: &str) {
        writeln!(self.input.as_mut().unwrap(), "{text}").unwrap();
        self.input.as_mut().unwrap().flush().unwrap();
    }
    fn read(&self) -> String {
        let line = self
            .output
            .recv_timeout(Duration::from_secs(45))
            .unwrap_or_else(|e| {
                panic!(
                    "product response: {e}; stderr={}",
                    std::fs::read_to_string(self.dirs.rw.join("product-stderr.log"))
                        .unwrap_or_default()
                )
            });
        let json = nojson::RawJson::parse(&line).expect("MCP stdout must be pure JSON");
        assert_eq!(
            json.value()
                .to_member("jsonrpc")
                .unwrap()
                .required()
                .unwrap()
                .as_string_str()
                .unwrap(),
            "2.0"
        );
        line
    }
    fn rpc(&mut self, text: &str) -> String {
        self.send(text);
        self.read()
    }
    fn initialize(&mut self) {
        let response = self.rpc(&request(0, "initialize", r#"{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"pr24-product","version":"1"}}"#));
        assert!(response.contains("\"result\""), "{response}");
        self.send(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#);
        let list = self.rpc(&request(1, "tools/list", "{}"));
        assert!(list.contains("net_probe"), "{list}");
    }
    fn session_dir(&self) -> PathBuf {
        std::fs::read_dir(&self.state)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path()
    }
    fn id(&self) -> String {
        std::fs::read_to_string(self.session_dir().join("unit-id")).unwrap()
    }
    fn finish(&mut self) -> i32 {
        self.input.take();
        assert!(
            wait_until(30, || self.child.0.try_wait().unwrap().is_some()),
            "product did not terminate"
        );
        self.child.0.wait().unwrap().code().unwrap()
    }
    fn retain(&self) {
        // Retain evidence, excluding command payloads and credentials.
        if let Ok(entries) = std::fs::read_dir(self.state.clone()) {
            for entry in entries.flatten() {
                let session = entry.path();
                for file in ["launch-report.json", "unit-id"] {
                    let _ = std::fs::copy(session.join(file), self.dirs.rw.join(file));
                }
                copy_evidence(&session.join("rw"), &self.dirs.rw);
            }
        }
    }
}

fn copy_evidence(src: &Path, dst: &Path) {
    let Ok(entries) = std::fs::read_dir(src) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        // The same fixed records retained by WsbDirs. Never preserve relay-hello
        // or arbitrary workspace/RPC payloads as validation evidence.
        if ["report", "logs"].iter().any(|n| name == *n) && entry.path().is_dir() {
            std::fs::create_dir_all(dst.join(&name)).unwrap();
            for file in std::fs::read_dir(entry.path()).unwrap().flatten() {
                if file.file_type().unwrap().is_file() {
                    let _ = std::fs::copy(file.path(), dst.join(&name).join(file.file_name()));
                }
            }
        } else if ["relay-status.txt", "agent.log", "stderr.log"]
            .iter()
            .any(|n| name == *n)
        {
            let _ = std::fs::copy(entry.path(), dst.join(name));
        }
    }
}

impl Drop for Product {
    fn drop(&mut self) {
        self.input.take();
        // A failed assertion must not leak the VM, even if the host process
        // itself is no longer able to run its guard.
        let _ = self.child.0.kill();
        let _ = self.child.0.wait();
        if let Ok(entries) = std::fs::read_dir(&self.state) {
            for entry in entries.flatten() {
                if let Ok(id) = std::fs::read_to_string(entry.path().join("unit-id"))
                    && uuid::Uuid::parse_str(&id).is_ok()
                {
                    let _ = cli_output(
                        &wsb_cli(),
                        &["stop", "--id", &id, "--raw"],
                        Duration::from_secs(15),
                    );
                }
            }
        }
        let _ = wait_until(10, || sandbox_pids().is_ok_and(|p| p.is_empty()));
        self.retain();
    }
}

#[test]
fn wsb_product_stdio_restart_and_controls() {
    let _lock = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for sample in 0..3 {
        let Some(mut p) = Product::launch() else {
            return;
        };
        p.initialize();
        let contact = p.started.elapsed().as_secs_f64();
        assert!(contact < 30.0, "first contact budget: {contact}s");
        let identity = p.rpc(&tool_call(
            2,
            "vm_identity",
            r#"{"path":"C:/relay-rw/workspace"}"#,
        ));
        assert!(
            identity.contains("appcontainer=true") && identity.contains("in_job=true"),
            "{identity}"
        );
        std::fs::write(p.dirs.rw.join("guest-identity.json"), &identity).unwrap();
        let (guest_total_physical_bytes, _) = guest_memory_bytes(&identity);
        let memory_mib = guest_total_physical_bytes as f64 / (1024.0 * 1024.0);
        host_memory_snapshot(&p.dirs.rw, "during");
        for (id, name, args, required) in [
            (
                3,
                "create_file",
                r#"{"path":"C:/relay-rw/workspace/product.txt","content":"pr24"}"#,
                "result",
            ),
            (
                4,
                "read_file",
                r#"{"path":"C:/relay-rw/workspace/product.txt"}"#,
                "pr24",
            ),
            (
                5,
                "create_file",
                r#"{"path":"C:/Windows/pr24-denied.txt"}"#,
                "os error 5",
            ),
            (
                6,
                "net_probe",
                r#"{"path":"C:/relay-rw/workspace","addr":"192.0.2.1:80"}"#,
                "10013",
            ),
            (
                7,
                "env_probe",
                r#"{"path":"C:/relay-rw/workspace"}"#,
                "mcp_vars_present=[]",
            ),
            (8, "exec_shell", r#"{"cmd":"whoami"}"#, "error"),
            (
                9,
                "read_file",
                r#"{"path":"C:/relay-rw/workspace/.ssh/id_rsa"}"#,
                "error",
            ),
        ] {
            let response = p.rpc(&tool_call(id, name, args));
            assert!(response.contains(required), "{name}: {response}");
        }
        let unknown = p.rpc(&request(10, "unknown/request", "{}"));
        assert!(unknown.contains("error"), "{unknown}");
        let large = "z".repeat(900 * 1024);
        let echoed = p.rpc(&tool_call(
            11,
            "echo",
            &format!(r#"{{"path":"C:/relay-rw/workspace","text":"{large}"}}"#),
        ));
        assert!(echoed.contains(&large), "large JSON-RPC frame changed");
        let mut times = Vec::new();
        for id in 100..130 {
            let start = Instant::now();
            assert!(
                p.rpc(&tool_call(
                    id,
                    "echo",
                    r#"{"path":"C:/relay-rw/workspace","text":"ping"}"#
                ))
                .contains("ping")
            );
            times.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        times.sort_by(f64::total_cmp);
        let p95 = times[28];
        assert!(p95 < 20.0, "RPC p95 budget: {p95}ms");
        // An independent product invocation must refuse the existing VM.
        let other = Command::new(env!("CARGO_BIN_EXE_mcp-writ"))
            .args(["run", "--isolation", "windows-sandbox", "--", "server.exe"])
            .output()
            .unwrap();
        assert!(!other.status.success());
        assert!(String::from_utf8_lossy(&other.stderr).contains("existing Windows Sandbox"));
        let stop = Instant::now();
        assert_eq!(
            p.finish(),
            0,
            "{}",
            std::fs::read_to_string(p.dirs.rw.join("product-stderr.log")).unwrap()
        );
        let stop_s = stop.elapsed().as_secs_f64();
        host_memory_snapshot(&p.dirs.rw, "after");
        assert!(stop_s < 10.0, "stop budget: {stop_s}s");
        assert!(
            !listed_ids(
                &cli_output(&wsb_cli(), &["list", "--raw"], Duration::from_secs(15)).unwrap()
            )
            .unwrap()
            .contains(&uuid::Uuid::parse_str(&p.id()).unwrap())
        );
        assert!(
            !p.session_dir().join("ro").exists(),
            "staging/credentials must be removed"
        );
        p.retain();
        let report = std::fs::read_to_string(p.dirs.rw.join("host-report.json")).unwrap();
        assert!(
            report.contains("\"configured\":\"windows-sandbox\"")
                && report.contains("\"verified\":\"windows-sandbox\""),
            "{report}"
        );
        assert!(report.contains("\"state\":\"received\"") && report.contains("cleanup confirmed"));
        assert_report(
            &p.dirs,
            nojson::RawJson::parse(&report)
                .unwrap()
                .value()
                .to_member("launch_id")
                .unwrap()
                .required()
                .unwrap()
                .as_string_str()
                .unwrap(),
        );
        assert_audit(&p.dirs);
        std::fs::write(p.dirs.rw.join("metrics.json"), format!(r#"{{"tier":"product","sample":{sample},"contact_s":{contact},"rpc_p95_ms":{p95},"stop_s":{stop_s},"memory_mib":{memory_mib}}}"#)).unwrap();
        eprintln!(
            "PR24 product sample={sample} contact={contact:.3}s rpc_p95={p95:.3}ms stop={stop_s:.3}s"
        );
    }
}

#[test]
fn wsb_product_abnormal_exit_and_external_stop() {
    let _lock = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for external in [false, true] {
        let Some(mut p) = Product::launch() else {
            return;
        };
        p.initialize();
        if external {
            cli_output(
                &wsb_cli(),
                &["stop", "--id", &p.id(), "--raw"],
                Duration::from_secs(15),
            )
            .unwrap();
            assert!(
                wait_until(20, || p.child.0.try_wait().unwrap().is_some()),
                "external VM stop must terminate the host while stdin remains open"
            );
            assert_ne!(p.finish(), 0);
        } else {
            p.send(&tool_call(
                3,
                "exit_child",
                r#"{"path":"C:/relay-rw/workspace","code":3}"#,
            ));
            assert_eq!(p.finish(), 3);
        }
        let report = std::fs::read_to_string(p.dirs.rw.join("host-report.json")).unwrap();
        assert!(report.contains("cleanup confirmed"), "{report}");
    }
}

#[test]
fn wsb_product_missing_audit_fails_closed() {
    let _lock = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(mut p) = Product::launch() else {
        return;
    };
    p.initialize();
    // The guest logger owns this file while running; rename tests the final
    // required-channel check without changing policy or bypassing Warden.
    let audit = p.session_dir().join("rw/logs/audit.jsonl");
    std::fs::rename(&audit, audit.with_extension("moved")).unwrap();
    assert_ne!(p.finish(), 0);
    let report = std::fs::read_to_string(p.dirs.rw.join("host-report.json")).unwrap();
    assert!(
        report.contains("required guest audit file is missing"),
        "{report}"
    );
}

#[test]
fn wsb_product_v2_wire_and_missing_report() {
    let _lock = VM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let policy = sandbox_policy()
        .replace("policy version=1", "policy version=2")
        .replace(
            "server \"wsb-probe\" {",
            "server \"wsb-probe\" {\n mcp { allow \"elicitation/create\" }\n",
        );
    let Some(mut p) = Product::launch_policy(policy) else {
        return;
    };
    let modern_call = |id: i64, text: &str, caps: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"echo","arguments":{{"path":"C:/relay-rw/workspace","text":"{text}"}},"_meta":{{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{caps}}}}}}}"#
        )
    };
    let list = p.rpc(&request(
        0,
        "tools/list",
        &format!("{{{}}}", common::META_2026),
    ));
    assert!(list.contains("echo"), "{list}");
    let valid = p.rpc(&modern_call(1, "pr24/mrtr", r#"{"elicitation":{}}"#));
    assert!(
        valid.contains("input_required"),
        "explicit rule + original-request capability must pass: {valid}"
    );
    let denied = p.rpc(&modern_call(2, "pr24/mrtr", "{}"));
    assert!(
        denied.contains("-32001") && !denied.contains("input_required"),
        "{denied}"
    );
    let normal = p.rpc(&modern_call(3, "pr24/server-request", "{}"));
    assert!(
        normal.contains("pr24/server-request") && !normal.contains("sampling/createMessage"),
        "unsolicited server request leaked: {normal}"
    );
    let recovery = p.rpc(&modern_call(4, "still-usable", "{}"));
    assert!(recovery.contains("still-usable"), "{recovery}");
    let report_dir = p.session_dir().join("rw/report");
    std::fs::rename(
        &report_dir,
        report_dir.with_file_name("report-before-failure"),
    )
    .unwrap();
    std::fs::write(report_dir, "deliberate invalid report channel").unwrap();
    assert_ne!(p.finish(), 0);
    let report = std::fs::read_to_string(p.dirs.rw.join("host-report.json")).unwrap();
    assert!(
        report.contains("\"state\":\"missing\"") || report.contains("\"state\":\"invalid\""),
        "{report}"
    );
}
