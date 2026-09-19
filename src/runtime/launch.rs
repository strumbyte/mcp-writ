use crate::auditor::Auditor;
use crate::auditor::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::error::{AuditorError, WardenError};
use crate::policy::Policy;
use crate::verifier::fail_on::FailOn;
use crate::verifier::hash::{self, VerifyError};
use crate::warden::{RunningChild, Warden};

/// Per-binary inputs to [`launch`].
///
/// Callers resolve policy loading, `bind_to_server`, `FailOn`, and audit-log
/// requirements before calling. `skip_sandbox` is also computed by the caller:
/// this function never reads `MCP_WRIT_SKIP_SANDBOX` itself (the container
/// runner strips that variable before launch, and reading it here would break
/// image ENV handling and tests).
pub struct LaunchConfig {
    /// Command argv before path resolution (`argv[0]` is replaced with the
    /// resolved absolute path). Must be non-empty.
    pub argv: Vec<String>,
    pub policy: Policy,
    pub fail_on: FailOn,
    /// Forwarded to `Auditor::with_dry_run` (`mcp-secure-runner` passes false).
    pub dry_run: bool,
    /// Caller-computed sandbox skip (`mcp-writ run --dry-run` or
    /// `MCP_WRIT_SKIP_SANDBOX`; `mcp-secure-runner` always passes false).
    pub skip_sandbox: bool,
    /// Reason interpolated into `sandboxing disabled ({reason})`. Expected to
    /// be set when `skip_sandbox` is true.
    pub skip_reason: Option<&'static str>,
    /// First half of the post-spawn `tracing::info!` (`"{label}: {argv:?}"`).
    pub spawned_log_label: &'static str,
}

/// A spawned MCP server child plus its running Auditor relay task.
pub struct Launched {
    pub child: RunningChild,
    pub auditor_handle: tokio::task::JoinHandle<Result<(), AuditorError>>,
}

/// Failure at one step of [`launch`]. Callers render the message with their
/// own error prefix, shut down the audit logger, and exit.
pub enum LaunchError {
    /// `resolve_command_path` failed; `command` is the unresolved `argv[0]`.
    ResolveCommand {
        command: String,
        source: std::io::Error,
    },
    /// `verify_server_hashes` failed for `server_name`.
    VerifyServerHashes {
        server_name: String,
        source: VerifyError,
    },
    /// `bind_launched_workload` failed.
    BindLaunchedWorkload { source: VerifyError },
    /// `reverify_immediately_before_spawn` failed.
    ReverifyBeforeSpawn { source: VerifyError },
    /// Warden spawn failed; `argv` is the resolved launch argv.
    Spawn {
        argv: Vec<String>,
        source: WardenError,
    },
    /// `take_io` failed; ownership of the child is returned so the caller can
    /// kill/wait/drop in the usual order.
    TakeIo { child: RunningChild },
}

/// Shared sequence: resolve argv0 → verify hashes → bind → reverify → replace
/// `argv[0]` → Warden spawn → `take_io` → `Auditor` relay on a spawned task.
///
/// Ordering is fixed (verify → bind → reverify closes the TOCTOU gap).
/// Signal waiting and shutdown are NOT part of this function.
pub async fn launch(
    config: LaunchConfig,
    audit_logger: &AuditLogger,
) -> Result<Launched, LaunchError> {
    let LaunchConfig {
        argv,
        policy,
        fail_on,
        dry_run,
        skip_sandbox,
        skip_reason,
        spawned_log_label,
    } = config;

    let resolved_exe = match hash::resolve_command_path(&argv[0]) {
        Ok(p) => p,
        Err(source) => {
            return Err(LaunchError::ResolveCommand {
                command: argv[0].clone(),
                source,
            });
        }
    };
    if !policy.hash_entries.is_empty() {
        let server_names: std::collections::HashSet<_> = policy
            .hash_entries
            .iter()
            .map(|e| e.server_name.as_str())
            .collect();
        for s_name in server_names {
            if let Err(source) =
                hash::verify_server_hashes(s_name, &policy.hash_entries, audit_logger)
            {
                return Err(LaunchError::VerifyServerHashes {
                    server_name: s_name.to_string(),
                    source,
                });
            }
        }
        if let Err(source) =
            hash::bind_launched_workload(&argv, &resolved_exe, &policy.hash_entries, audit_logger)
        {
            return Err(LaunchError::BindLaunchedWorkload { source });
        }
        if let Err(source) = hash::reverify_immediately_before_spawn(
            &argv,
            &resolved_exe,
            &policy.hash_entries,
            audit_logger,
        ) {
            return Err(LaunchError::ReverifyBeforeSpawn { source });
        }
    }

    let mut launch_argv = argv;
    launch_argv[0] = resolved_exe.to_string_lossy().into_owned();

    let warden = Warden::new(policy.clone());
    if skip_sandbox {
        let reason = skip_reason.unwrap_or("unspecified");
        tracing::warn!("sandboxing disabled ({reason})");
    }
    let mut child = match if skip_sandbox {
        warden.spawn_unsandboxed_async(&launch_argv)
    } else {
        warden.spawn_child_async(&launch_argv)
    } {
        Ok(child) => child,
        Err(source) => {
            // The responsible component (Warden) and stage are inside
            // `source`; record the failure before returning so the JSONL
            // audit log carries the same fact stderr reports.
            let mut event = AuditEvent::new(
                uuid::Uuid::now_v7(),
                EventType::ServerError,
                Severity::High,
                Outcome::Failure,
                Action::Observed,
            );
            event.details = Some(format!("server spawn failed: {source}"));
            audit_logger.log(event);
            return Err(LaunchError::Spawn {
                argv: launch_argv,
                source,
            });
        }
    };
    tracing::info!("{spawned_log_label}: {launch_argv:?}");

    let (child_stdin, child_stdout) = match child.take_io() {
        Some(io) => io,
        None => return Err(LaunchError::TakeIo { child }),
    };

    let auditor = Auditor::new(policy, audit_logger.clone())
        .with_dry_run(dry_run)
        .with_fail_on(fail_on);
    let auditor_handle = tokio::spawn(async move { auditor.run(child_stdin, child_stdout).await });

    Ok(Launched {
        child,
        auditor_handle,
    })
}
