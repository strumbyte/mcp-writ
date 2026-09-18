//! Policy self-test evidence and verdict classification.
//!
//! Linux: Warden OS-deny and Auditor policy errors are recorded independently.
//! JSON-RPC policy errors are never classified as `warden: pass`.

use std::path::PathBuf;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use mcp_writ::legislator::self_test::SpawnStatus;
use mcp_writ::legislator::self_test::{
    WardenVerdict, classify_warden_observation, evaluate_auditor_probes, is_policy_jsonrpc_error,
    run_self_test,
};
use mcp_writ::policy::kdl_loader::parse_kdl_policy;

#[cfg(target_os = "linux")]
use mcp_writ::auditor::checker;
#[cfg(target_os = "linux")]
use mcp_writ::legislator::self_test::{build_tools_call, prepare_warden_probe_policy};
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;

fn fixture_open_path_py() -> Vec<String> {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mcp_servers/open_path.py");
    if cfg!(windows) {
        vec![
            "py".to_string(),
            "-3".to_string(),
            path.to_string_lossy().into_owned(),
        ]
    } else {
        vec!["python3".to_string(), path.to_string_lossy().into_owned()]
    }
}

#[cfg(target_os = "linux")]
fn compile_open_path_server() -> Option<PathBuf> {
    static BIN: OnceLock<Option<PathBuf>> = OnceLock::new();
    BIN.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/mcp_servers/open_path_server.rs");
        let out =
            std::env::temp_dir().join(format!("mcp_writ_open_path_server_{}", std::process::id()));
        let status = Command::new("rustc")
            .args(["-O", "-o", out.to_str()?, src.to_str()?])
            .status()
            .ok()?;
        status.success().then_some(out)
    })
    .clone()
}

fn warden_probe_kdl() -> &'static str {
    r##"
policy version=1
defaults {
    filesystem {
        secret-overlay #false
        allow "/workspace/**" mode="read"
    }
    syscalls {
        allow "read" "write" "openat" "execve" "exit_group" "mmap" "brk" "close"
    }
}
logging level="info" fail_closed=#false
server "auto-generated" {
    tool "read_file" args_schema="{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}"
    tool "evil" deny=#true
}
"##
}

#[test]
fn jsonrpc_policy_error_is_never_warden_pass() {
    let line = r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"Policy violation: tool 'read_file' is not allowed (path not allowed)"}}"#;
    assert!(is_policy_jsonrpc_error(line));
    assert_eq!(
        classify_warden_observation(Some(line), None),
        WardenVerdict::Inconclusive
    );
}

#[test]
fn success_result_with_permission_denied_text_is_not_warden_pass() {
    let line =
        r#"{"jsonrpc":"2.0","id":10,"result":{"ok":true,"text":"permission denied / EACCES"}}"#;
    assert_eq!(
        classify_warden_observation(Some(line), None),
        WardenVerdict::Fail
    );
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn non_linux_marks_warden_skipped() {
    let report = run_self_test(
        warden_probe_kdl(),
        &fixture_open_path_py(),
        Duration::from_secs(8),
    )
    .await
    .expect("self-test should parse");
    let stderr = report.format_stderr();
    match report.warden {
        WardenVerdict::Skipped => {
            assert_eq!(
                report.spawn,
                SpawnStatus::Started,
                "skipped requires spawn started: {stderr}"
            );
            assert!(stderr.contains("warden: skipped"), "{stderr}");
            assert!(stderr.contains("spawn: started"), "{stderr}");
        }
        WardenVerdict::Inconclusive => {
            assert_ne!(
                report.spawn,
                SpawnStatus::Started,
                "spawn that never started should be inconclusive: {stderr}"
            );
            match report.spawn {
                SpawnStatus::Failed => {
                    assert!(stderr.contains("spawn: failed"), "{stderr}");
                    assert!(stderr.contains("server spawn failed"), "{stderr}");
                }
                SpawnStatus::NotAttempted => {
                    assert!(stderr.contains("spawn: not attempted"), "{stderr}");
                    assert!(!stderr.contains("server spawn failed"), "{stderr}");
                }
                SpawnStatus::Started => unreachable!(),
            }
        }
        other => panic!(
            "expected skipped or spawn-fail inconclusive, got {}: {stderr}",
            other.as_str()
        ),
    }
    assert!(!stderr.contains("warden: pass"), "{stderr}");
    assert!(
        stderr.contains("spawn:"),
        "report must record spawn vs skip: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_auditor_and_warden_are_independent() {
    let command = compile_open_path_server()
        .map(|bin| vec![bin.to_string_lossy().into_owned()])
        .unwrap_or_else(fixture_open_path_py);

    let report = run_self_test(warden_probe_kdl(), &command, Duration::from_secs(8))
        .await
        .expect("self-test should parse");

    let stderr = report.format_stderr();
    assert_eq!(
        report.auditor,
        mcp_writ::legislator::self_test::AuditorVerdict::Pass,
        "{stderr}"
    );
    assert!(
        report
            .auditor_probes
            .iter()
            .any(|p| p.name == "deny-tool" && p.passed && p.detail.contains("checker")),
        "auditor pass must be labeled as checker, not live proxy: {stderr}"
    );
    assert!(
        !stderr.lines().next().unwrap_or("").contains("warden"),
        "auditor line must not mention warden: {stderr}"
    );

    assert_ne!(
        report.warden,
        WardenVerdict::Fail,
        "child must not serve /etc/passwd: {stderr}"
    );
    assert!(
        matches!(
            report.warden,
            WardenVerdict::Pass | WardenVerdict::Inconclusive
        ),
        "Warden must be recorded independently (pass=SIGSYS, inconclusive=JSON-RPC only), got {}: {stderr}",
        report.warden.as_str()
    );
    assert!(
        stderr.contains("warden: pass") || stderr.contains("warden: inconclusive"),
        "{stderr}"
    );
    assert!(
        stderr.contains("probe-policy:") || stderr.contains("diagnostic overlay"),
        "report must distinguish the overlay policy: {stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn inherited_tool_fs_would_steal_warden_probe() {
    let loaded = parse_kdl_policy(warden_probe_kdl()).unwrap();
    let line = build_tools_call(1, "read_file", r#"{"path":"/etc/passwd"}"#);
    assert!(
        checker::check_request(&line, &loaded).is_err(),
        "defaults.filesystem inheritance must deny /etc/passwd at Auditor"
    );

    let prepared = prepare_warden_probe_policy(
        &loaded,
        Path::new("/tmp/mcp-writ-self-test-e2e"),
        &["echo".into()],
    );
    assert!(prepared.tools.iter().all(|t| t.fs.is_none()));
    assert!(checker::check_request(&line, &prepared).is_ok());
}

#[test]
fn deny_tool_probe_does_not_need_a_child() {
    let policy = parse_kdl_policy(warden_probe_kdl()).unwrap();
    let probes = evaluate_auditor_probes(&policy);
    assert!(probes.iter().any(|p| p.name == "deny-tool" && p.passed));
    assert!(
        probes
            .iter()
            .all(|p| p.detail.contains("checker") || p.skipped)
    );
    assert!(
        probes
            .iter()
            .all(|p| !p.detail.to_ascii_lowercase().contains("warden"))
    );
}
