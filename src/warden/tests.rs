use super::*;
use crate::policy::default_policy;

/// Mark the sandbox as already applied so unit tests do not call
/// `restrict_self()` / seccomp / native sandbox on the cargo test process.
fn mark_sandbox_applied(warden: &Warden) {
    warden.sandbox_applied.set(true);
}

#[test]
fn test_warden_new_with_default_policy() {
    let policy = default_policy();
    let warden = Warden::new(policy);
    assert_eq!(warden.policy().version, 1);
}

#[cfg(not(target_os = "linux"))]
#[test]
#[allow(deprecated)]
fn test_apply_sandbox_noop_on_non_linux() {
    // apply_sandbox is a deprecated no-op on every platform.
    let policy = default_policy();
    let warden = Warden::new(policy);
    assert!(warden.apply_sandbox().is_ok());
}

#[test]
#[allow(deprecated)]
fn test_apply_sandbox_is_noop() {
    let policy = default_policy();
    let warden = Warden::new(policy);
    assert!(warden.apply_sandbox().is_ok());
    assert!(warden.apply_sandbox().is_ok());
    assert!(
        !warden.sandbox_applied.get(),
        "apply_sandbox must not mark parent sandboxing as applied"
    );
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
#[test]
fn test_spawn_child_nonexistent_command() {
    let policy = default_policy();
    let warden = Warden::new(policy);
    #[cfg(target_os = "linux")]
    mark_sandbox_applied(&warden);
    let result = warden.spawn_child("__nonexistent_cmd_9999__", &[]);
    assert!(result.is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn test_spawn_child_nonexistent_command_macos() {
    // On macOS, sandbox-exec is found so spawn() succeeds,
    // but the wrapped nonexistent command exits with failure.
    let policy = default_policy();
    let warden = Warden::new(policy);
    let result = warden.spawn_child("__nonexistent_cmd_9999__", &[]);
    match result {
        Ok(mut child) => {
            let status = child.wait().expect("should be able to wait");
            assert!(!status.success(), "nonexistent command should fail");
        }
        Err(_) => {
            // sandbox-exec not available — acceptable on some environments
        }
    }
}

#[tokio::test]
async fn test_empty_argv_rejects_without_touching_os_controls() {
    let policy = default_policy();
    let warden = Warden::new(policy);
    let attempt = warden
        .spawn_child_async_exe_with_report(Path::new("child"), &[], &SpawnOptions::default(), false)
        .await;
    assert!(attempt.outcome.is_err());
    // The launch is rejected before the sandbox stage: OS controls
    // read `Skipped` — never left `Planned`, and never `Failed` by an
    // unrelated ruleset build (`build_plan` must not run the OS
    // grant builders for a rejected launch).
    for c in &attempt.report.plan.controls {
        if c.layer == crate::enforcement::ControlLayer::Os {
            assert!(
                matches!(
                    c.state,
                    crate::enforcement::ControlState::Skipped
                        | crate::enforcement::ControlState::NotApplicable
                        | crate::enforcement::ControlState::NotApplied
                ),
                "{} must not be Planned/Failed, got {:?}",
                c.id,
                c.state
            );
        }
    }
    assert!(attempt.report.plan.grants.is_empty());
    assert!(attempt.report.observations.is_empty());
}

/// `require_lifetime_boundary` defaults on — the supervised-launch
/// contract. An explicitly unsandboxed launch is outside the flag's
/// scope: the operator already waived every other enforcement by
/// choosing this route, so it still runs (best-effort).
#[test]
fn test_unsandboxed_launch_outside_boundary_scope() {
    let policy = default_policy();
    assert!(policy.sandbox.require_lifetime_boundary);
    let warden = Warden::new(policy);
    #[cfg(windows)]
    let (cmd, args) = (
        "cmd",
        vec!["/c".to_string(), "echo".to_string(), "ok".to_string()],
    );
    #[cfg(not(windows))]
    let (cmd, args) = ("echo", vec!["ok".to_string()]);
    let mut child = warden
        .spawn_unsandboxed(cmd, &args)
        .expect("unsandboxed launch is outside the flag's scope");
    let _ = child.wait();
}

/// Same scope on the async arm — the flag gates supervised launches,
/// not this route.
#[tokio::test]
async fn test_unsandboxed_async_launch_outside_boundary_scope() {
    let policy = default_policy();
    assert!(policy.sandbox.require_lifetime_boundary);
    let warden = Warden::new(policy);
    #[cfg(windows)]
    let argv = vec![
        "cmd".to_string(),
        "/c".to_string(),
        "echo".to_string(),
        "ok".to_string(),
    ];
    #[cfg(not(windows))]
    let argv = vec!["echo".to_string(), "ok".to_string()];
    let child = warden
        .spawn_unsandboxed_async_with(&argv, &SpawnOptions::default())
        .expect("unsandboxed launch is outside the flag's scope");
    drop(child);
}

#[test]
fn test_spawn_child_returns_piped_io() {
    let policy = default_policy();
    let warden = Warden::new(policy);
    mark_sandbox_applied(&warden);
    #[cfg(windows)]
    let (cmd, args) = (
        "cmd",
        vec!["/c".to_string(), "echo".to_string(), "hello".to_string()],
    );
    #[cfg(not(windows))]
    let (cmd, args) = ("echo", vec!["hello".to_string()]);
    let mut child = warden
        .spawn_child(cmd, &args)
        .expect("command should be spawnable");
    assert!(child.has_stdin());
    assert!(child.has_stdout());
    let _ = child.wait();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn test_spawn_report_records_verified_launch_for_running_child() {
    use crate::enforcement::{ControlPhase, ControlState, GrantSubject};

    // macOS provides no kernel-enforced descendant boundary, so the
    // default-on `require_lifetime_boundary` would refuse — declare
    // the waiver an operator would write.
    let mut policy = default_policy();
    policy.sandbox.require_lifetime_boundary = false;
    let warden = Warden::new(policy);
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "sleep 30".to_string(),
    ];
    let attempt = warden
        .spawn_child_async_exe_with_report(
            Path::new("/bin/sh"),
            &argv,
            &SpawnOptions::default(),
            false,
        )
        .await;
    let mut child = attempt.outcome.expect("sandboxed sh should spawn");
    let obs = &attempt.report.observations;

    // os.sandbox carries the build-phase preparation result and the
    // spawn-phase liveness result — in that order.
    let sandbox: Vec<_> = obs.iter().filter(|o| o.control == "os.sandbox").collect();
    assert_eq!(sandbox.len(), 2);
    assert_eq!(sandbox[0].phase, ControlPhase::Build);
    assert_eq!(sandbox[0].state, ControlState::Verified);
    assert_eq!(sandbox[1].phase, ControlPhase::Spawn);
    assert_eq!(sandbox[1].state, ControlState::Verified);

    // Kernel acceptance of the SBPL rules stays unobserved — a live
    // process is not upgraded into an applied claim.
    for id in ["os.fs", "os.net.outbound", "os.process"] {
        let o = obs.iter().find(|o| o.control == id).unwrap();
        assert_eq!(o.state, ControlState::Unknown, "{id}");
    }

    // The private TMPDIR grant carries its verified creation.
    let tmp = attempt
        .report
        .plan
        .grants
        .iter()
        .find(|g| matches!(g.subject, GrantSubject::PrivateTmpdir))
        .expect("private TMPDIR grant");
    assert_eq!(tmp.state, ControlState::Verified);

    let _ = child.kill().await;
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn test_spawn_report_flags_immediate_exit() {
    use crate::enforcement::{ControlPhase, ControlState};

    // `exit 3` dies inside the initial-exit window the same way a
    // rejected profile or an un-exec'able workload does: the exit
    // alone cannot distinguish them, so the launch control records
    // the status and reads Unknown, the rule domains stay Unknown,
    // and the spawn outcome itself is unaffected (the caller sees
    // the EOF).
    // Same default-on boundary waiver as the sibling test above.
    let mut policy = default_policy();
    policy.sandbox.require_lifetime_boundary = false;
    let warden = Warden::new(policy);
    let argv = vec![
        "/bin/sh".to_string(),
        "-c".to_string(),
        "exit 3".to_string(),
    ];
    let attempt = warden
        .spawn_child_async_exe_with_report(
            Path::new("/bin/sh"),
            &argv,
            &SpawnOptions::default(),
            false,
        )
        .await;
    let mut child = attempt.outcome.expect("spawn returns the child handle");
    let obs = &attempt.report.observations;

    let launch = obs
        .iter()
        .filter(|o| o.control == "os.sandbox")
        .find(|o| o.phase == ControlPhase::Spawn)
        .unwrap();
    assert_eq!(launch.state, ControlState::Unknown);
    assert!(
        launch.reason.as_deref().unwrap().contains("exit status: 3"),
        "{:?}",
        launch.reason
    );
    for id in ["os.fs", "os.net.outbound", "os.process"] {
        let o = obs.iter().find(|o| o.control == id).unwrap();
        assert_eq!(o.state, ControlState::Unknown, "{id}");
    }

    let status = match child.wait_for_natural_exit().await {
        NaturalExit::Exited(s) => s.unwrap(),
        #[cfg(target_os = "linux")]
        NaturalExit::SupervisionLost(_) => panic!("namespaced supervision lost in test"),
    };
    assert!(!status.success());
}
