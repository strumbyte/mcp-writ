//! File-sink trust-boundary tests: `open_audit_sink` refusals and the
//! signal-driven reopen rotation path.

use super::super::*;
use super::{make_test_dir, make_test_event};
use uuid::Uuid;

// ─── Sink hardening (F18/F47) and field bounding (F68) ─────────────────

/// A planted symlink at the sink path must refuse the open — the audit
/// stream must never append through a link to an attacker-selected file.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_refuses_symlink_leaf() {
    let Some(dir) = make_test_dir("audit_sink_link") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let target = dir.join("sentinel.txt");
    std::fs::write(&target, b"sentinel").unwrap();
    let link = dir.join("audit.jsonl");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let result = AuditLogger::to_file(&link);
    assert!(result.is_err(), "symlink sink must be refused");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "sentinel",
        "refused open must not have written through the link"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A symlinked ancestor directory is just as redirecting — the trusted
/// openat walk must reject it before the leaf is even opened.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_refuses_symlinked_ancestor() {
    let Some(dir) = make_test_dir("audit_sink_ancestor") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let real_dir = dir.join("real");
    std::fs::create_dir(&real_dir).unwrap();
    let link_dir = dir.join("linked");
    std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();

    let path = link_dir.join("audit.jsonl");
    let result = AuditLogger::to_file(&path);
    assert!(
        result.is_err(),
        "a symlinked ancestor must refuse the sink open"
    );
    assert!(
        !real_dir.join("audit.jsonl").exists(),
        "refused open must not create the file through the link"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pre-existing sink with ambient (group/other-readable) permissions
/// is tightened to owner-only on the opened handle — security metadata
/// must not be left world-readable just because the operator pre-created
/// the file.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_tightens_existing_perms() {
    use std::os::unix::fs::PermissionsExt;
    let Some(dir) = make_test_dir("audit_sink_perms") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("audit.jsonl");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let logger = AuditLogger::to_file(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "existing sink must be tightened to 0600");
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// A non-regular sink (FIFO) must be refused — appending to a pipe
/// would block the writer or feed a reader that is not the audit trail.
#[cfg(unix)]
#[tokio::test]
async fn test_audit_sink_refuses_fifo() {
    let Some(dir) = make_test_dir("audit_sink_fifo") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("audit.jsonl");
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

    let result = AuditLogger::to_file(&path);
    assert!(result.is_err(), "FIFO sink must be refused");
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Sink reopen (PR-27, F-11) ────────────────────────────────────────

/// The in-band rotation marker a reopen carries — the same shape
/// `lifecycle::audit_reopened_event` builds, kept local so these
/// writer-level tests stay in the audit_log module.
fn reopen_marker() -> ReopenMarker {
    Box::new(|err| {
        let mut evt = AuditEvent::new(
            Uuid::now_v7(),
            EventType::AuditReopened,
            Severity::Info,
            if err.is_some() {
                Outcome::Failure
            } else {
                Outcome::Success
            },
            Action::Observed,
        );
        evt.details = Some(match err {
            Some(e) => format!("signal=sigusr1 error={e}"),
            None => "signal=sigusr1".to_string(),
        });
        evt
    })
}

/// The rotation contract: records queued before the reopen reach the
/// renamed old file, the reopen swaps the handle to a freshly opened
/// file at the audit path, and everything after continues there — with
/// the `audit.reopened` marker written in-band as the new file's first
/// record. Renames while the sink is open are a Unix semantic — the
/// Windows append handle does not grant delete sharing, so an external
/// rotator cannot move the file there.
#[cfg(unix)]
#[tokio::test]
async fn test_logger_reopen_continues_to_new_file() {
    let Some(dir) = make_test_dir("audit_reopen") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("audit.jsonl");
    let rotated = dir.join("audit.jsonl.1");

    let logger = AuditLogger::to_file(&path).unwrap();
    let mut pre = make_test_event();
    pre.details = Some("pre-rotation".to_string());
    logger.log_committed(pre).await.unwrap();

    std::fs::rename(&path, &rotated).unwrap();
    assert!(
        logger.reopen(reopen_marker()).await.unwrap(),
        "file sink must report a real reopen"
    );

    let mut post = make_test_event();
    post.details = Some("post-rotation".to_string());
    logger.log_committed(post).await.unwrap();
    let _ = logger.shutdown().await;

    let old = std::fs::read_to_string(&rotated).unwrap();
    assert!(old.contains("pre-rotation"), "old file: {old}");
    assert!(
        !old.contains("post-rotation"),
        "a post-rotation record must not land in the rotated file: {old}"
    );
    assert!(
        !old.contains("audit.reopened"),
        "the marker belongs to the new file: {old}"
    );
    let new = std::fs::read_to_string(&path).unwrap();
    let new_lines: Vec<&str> = new.lines().collect();
    assert_eq!(new_lines.len(), 2, "marker plus post record: {new}");
    assert!(
        new_lines[0].contains("\"event_type\":\"audit.reopened\""),
        "the marker is the new file's first record: {}",
        new_lines[0]
    );
    assert!(new_lines[0].contains("\"outcome\":\"success\""));
    assert!(
        new_lines[1].contains("post-rotation"),
        "new file must continue the stream: {new}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A reopen that fails the trust-boundary open — here the path was
/// replaced by a directory — keeps the old handle: records continue
/// into the previously opened file object while `writer_failed`
/// latches, so a fail-closed logger reports the session dead.
#[cfg(unix)]
#[tokio::test]
async fn test_logger_reopen_failure_keeps_old_sink() {
    let Some(dir) = make_test_dir("audit_reopen_fail") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("audit.jsonl");
    let rotated = dir.join("audit.jsonl.1");

    let logger = AuditLogger::to_file(&path).unwrap(); // fail_closed
    logger.log_committed(make_test_event()).await.unwrap();

    std::fs::rename(&path, &rotated).unwrap();
    std::fs::create_dir(&path).unwrap(); // a non-regular leaf refuses the reopen
    let err = logger.reopen(reopen_marker()).await.unwrap_err();
    assert!(
        matches!(err, crate::error::AuditorError::AuditUnavailable(_)),
        "expected AuditUnavailable, got: {err:?}"
    );
    assert!(logger.writer_failed(), "failed reopen must latch the fault");
    assert!(logger.is_failed(), "fail-closed logger must report failed");

    // The old handle still accepts records — the failed reopen did not
    // lose the sink's remaining stream.
    let mut post = make_test_event();
    post.details = Some("after-failed-reopen".to_string());
    logger.log(post);
    let _ = logger.shutdown().await;

    let old = std::fs::read_to_string(&rotated).unwrap();
    assert!(
        old.contains("after-failed-reopen"),
        "old file must keep receiving records: {old}"
    );
    // The failure marker was emitted in-band on the surviving handle.
    assert!(
        old.contains("\"event_type\":\"audit.reopened\""),
        "the failed reopen still records its marker: {old}"
    );
    assert!(
        old.contains("\"outcome\":\"failure\"") && old.contains("error="),
        "the failure marker carries the refusal: {old}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reopening the same path — no external rotation at all — swaps to an
/// equivalent handle and loses nothing.
#[tokio::test]
async fn test_logger_reopen_same_path_loses_nothing() {
    let Some(dir) = make_test_dir("audit_reopen_same") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("audit.jsonl");

    let logger = AuditLogger::to_file(&path).unwrap();
    logger.log_committed(make_test_event()).await.unwrap();
    assert!(logger.reopen(reopen_marker()).await.unwrap());
    let mut post = make_test_event();
    post.details = Some("still-here".to_string());
    logger.log_committed(post).await.unwrap();
    let _ = logger.shutdown().await;

    let body = std::fs::read_to_string(&path).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "both records plus the marker must survive: {body}"
    );
    assert!(lines[1].contains("\"event_type\":\"audit.reopened\""));
    assert!(body.contains("still-here"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A tracing sink has nothing to reopen, and a shut-down file sink
/// reports the same — neither is an error. `has_file_sink` tracks the
/// same liveness, so signal plumbing can skip registering a reopen
/// listener that could only no-op.
#[tokio::test]
async fn test_logger_reopen_without_file_sink() {
    let tracing_logger = AuditLogger::to_tracing();
    assert!(!tracing_logger.has_file_sink());
    assert!(!tracing_logger.reopen(reopen_marker()).await.unwrap());
    let _ = tracing_logger.shutdown().await;

    let Some(dir) = make_test_dir("audit_reopen_dead") else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let path = dir.join("audit.jsonl");
    let logger = AuditLogger::to_file(&path).unwrap();
    assert!(logger.has_file_sink());
    let _ = logger.shutdown().await;
    assert!(
        !logger.has_file_sink(),
        "shutdown retires the sink the signal path checks"
    );
    assert!(!logger.reopen(reopen_marker()).await.unwrap());
    let _ = std::fs::remove_dir_all(&dir);
}
