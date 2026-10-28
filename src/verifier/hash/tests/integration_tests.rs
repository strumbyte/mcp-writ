use super::super::*;
use std::path::PathBuf;

fn make_test_dir(label: &str) -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir =
        crate::testutil::real_temp_base().join(format!("mcp_writ_hash_int_{label}_{id}_{ts}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// An `AuditLogger::to_file` fixture must satisfy the sink's own
/// ancestry gate — a replaceable parent is exactly what
/// `open_audit_sink` refuses — so audit tests live under
/// `restricted_tempdir` and skip when the host offers no
/// write-restricted root.
fn audit_dir() -> Option<PathBuf> {
    crate::testutil::restricted_tempdir().map(|d| d.keep())
}

#[tokio::test]
async fn test_verify_server_hashes_all_match() {
    let Some(dir) = audit_dir() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let audit_path = dir.join("audit.jsonl");
    let bin_path = dir.join("server-bin");
    std::fs::write(&bin_path, b"binary content").unwrap();

    let actual_hash = hash_file(&bin_path).unwrap();

    let entries = vec![HashEntry {
        server_name: "my-server".to_string(),
        hash_type: HashType::Binary,
        hash_value: actual_hash,
        target: bin_path.to_string_lossy().to_string(),
        approved: Some("2026-02-20".to_string()),
    }];

    let logger = AuditLogger::to_file(&audit_path).unwrap();
    let result = verify_server_hashes("my-server", &entries, &logger);
    assert_eq!(result.unwrap(), VerifyResult::Verified);

    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&audit_path).unwrap();
    assert!(content.contains("\"event_type\":\"hash.verified\""));
    assert!(content.contains("my-server"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_verify_server_hashes_mismatch_blocks() {
    let Some(dir) = audit_dir() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let audit_path = dir.join("audit.jsonl");
    let bin_path = dir.join("server-bin");
    std::fs::write(&bin_path, b"modified binary").unwrap();

    let entries = vec![HashEntry {
        server_name: "my-server".to_string(),
        hash_type: HashType::Binary,
        hash_value: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .to_string(),
        target: bin_path.to_string_lossy().to_string(),
        approved: Some("2026-02-20".to_string()),
    }];

    let logger = AuditLogger::to_file(&audit_path).unwrap();
    let result = verify_server_hashes("my-server", &entries, &logger);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, VerifyError::Mismatch { .. }));

    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&audit_path).unwrap();
    assert!(content.contains("\"event_type\":\"hash.mismatch\""));
    assert!(content.contains("\"severity\":\"critical\""));
    assert!(content.contains("\"action\":\"denied\""));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_verify_server_hashes_no_entries_warns() {
    let Some(dir) = audit_dir() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let audit_path = dir.join("audit.jsonl");

    let entries: Vec<HashEntry> = vec![];

    let logger = AuditLogger::to_file(&audit_path).unwrap();
    let result = verify_server_hashes("my-server", &entries, &logger);
    assert_eq!(result.unwrap(), VerifyResult::NoEntries);

    let _ = logger.shutdown().await;

    // No audit events should be emitted (warning is via tracing, not audit log)
    let content = std::fs::read_to_string(&audit_path).unwrap_or_default();
    assert!(content.is_empty());

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_verify_server_hashes_file_not_found_blocks() {
    let Some(dir) = audit_dir() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let audit_path = dir.join("audit.jsonl");

    let entries = vec![HashEntry {
        server_name: "my-server".to_string(),
        hash_type: HashType::Binary,
        hash_value: "sha256:aaa".to_string(),
        target: "/nonexistent/binary".to_string(),
        approved: None,
    }];

    let logger = AuditLogger::to_file(&audit_path).unwrap();
    let result = verify_server_hashes("my-server", &entries, &logger);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), VerifyError::FileError { .. }));

    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&audit_path).unwrap();
    assert!(content.contains("\"event_type\":\"hash.mismatch\""));

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_verify_server_hashes_filters_by_server() {
    let Some(dir) = audit_dir() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let audit_path = dir.join("audit.jsonl");
    let bin_path = dir.join("server-bin");
    std::fs::write(&bin_path, b"content").unwrap();

    let actual_hash = hash_file(&bin_path).unwrap();

    let entries = vec![
        HashEntry {
            server_name: "server-a".to_string(),
            hash_type: HashType::Binary,
            hash_value: actual_hash,
            target: bin_path.to_string_lossy().to_string(),
            approved: None,
        },
        HashEntry {
            server_name: "server-b".to_string(),
            hash_type: HashType::Binary,
            hash_value: "sha256:wrong".to_string(),
            target: bin_path.to_string_lossy().to_string(),
            approved: None,
        },
    ];

    let logger = AuditLogger::to_file(&audit_path).unwrap();

    // Verifying server-a should succeed (correct hash)
    let result = verify_server_hashes("server-a", &entries, &logger);
    assert_eq!(result.unwrap(), VerifyResult::Verified);

    // Verifying server-b should fail (wrong hash)
    let result = verify_server_hashes("server-b", &entries, &logger);
    assert!(result.is_err());

    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_verify_server_hashes_multiple_entries() {
    let Some(dir) = audit_dir() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let audit_path = dir.join("audit.jsonl");
    let lock_path = dir.join("package-lock.json");
    let entry_path = dir.join("index.js");
    std::fs::write(&lock_path, b"lock content").unwrap();
    std::fs::write(&entry_path, b"entry content").unwrap();

    let lock_hash = hash_file(&lock_path).unwrap();
    let entry_hash = hash_file(&entry_path).unwrap();

    let entries = vec![
        HashEntry {
            server_name: "node-server".to_string(),
            hash_type: HashType::Lockfile,
            hash_value: lock_hash,
            target: lock_path.to_string_lossy().to_string(),
            approved: None,
        },
        HashEntry {
            server_name: "node-server".to_string(),
            hash_type: HashType::Entrypoint,
            hash_value: entry_hash,
            target: entry_path.to_string_lossy().to_string(),
            approved: None,
        },
    ];

    let logger = AuditLogger::to_file(&audit_path).unwrap();
    let result = verify_server_hashes("node-server", &entries, &logger);
    assert_eq!(result.unwrap(), VerifyResult::Verified);

    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&audit_path).unwrap();
    let verified_count = content.matches("\"event_type\":\"hash.verified\"").count();
    assert_eq!(verified_count, 2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_verify_server_hashes_stops_on_first_mismatch() {
    let Some(dir) = audit_dir() else {
        crate::testutil::skip_unless_required("no write-restricted root for audit fixture");
        return;
    };
    let audit_path = dir.join("audit.jsonl");
    let lock_path = dir.join("package-lock.json");
    let entry_path = dir.join("index.js");
    std::fs::write(&lock_path, b"lock content").unwrap();
    std::fs::write(&entry_path, b"entry content").unwrap();

    let entry_hash = hash_file(&entry_path).unwrap();

    let entries = vec![
        HashEntry {
            server_name: "node-server".to_string(),
            hash_type: HashType::Lockfile,
            hash_value: "sha256:wrong_hash".to_string(),
            target: lock_path.to_string_lossy().to_string(),
            approved: None,
        },
        HashEntry {
            server_name: "node-server".to_string(),
            hash_type: HashType::Entrypoint,
            hash_value: entry_hash,
            target: entry_path.to_string_lossy().to_string(),
            approved: None,
        },
    ];

    let logger = AuditLogger::to_file(&audit_path).unwrap();
    let result = verify_server_hashes("node-server", &entries, &logger);
    assert!(result.is_err());

    let _ = logger.shutdown().await;

    let content = std::fs::read_to_string(&audit_path).unwrap();
    // Only the mismatch event, no verified event for the second entry
    assert_eq!(
        content.matches("\"event_type\":\"hash.mismatch\"").count(),
        1
    );
    assert_eq!(
        content.matches("\"event_type\":\"hash.verified\"").count(),
        0
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_bind_launched_workload_rejects_unrelated_exe() {
    let dir = make_test_dir("bind_unrelated");
    let real = dir.join("real.bin");
    let other = dir.join("other.bin");
    std::fs::write(&real, b"real-bytes").unwrap();
    std::fs::write(&other, b"other-bytes").unwrap();
    let hash = hash_file(&real).unwrap();
    let entries = vec![HashEntry {
        server_name: "s".into(),
        hash_type: HashType::Binary,
        hash_value: hash,
        target: real.to_string_lossy().into_owned(),
        approved: None,
    }];
    let logger = AuditLogger::to_tracing();
    let err = bind_launched_workload(
        &[other.to_string_lossy().into_owned()],
        &other,
        &entries,
        &logger,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::UnboundWorkload { .. }));
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_bind_rejects_lockfile_only_hashes() {
    let dir = make_test_dir("bind_lockfile_only");
    let lock = dir.join("package-lock.json");
    std::fs::write(&lock, b"{}").unwrap();
    let hash = hash_file(&lock).unwrap();
    let entries = vec![HashEntry {
        server_name: "s".into(),
        hash_type: HashType::Lockfile,
        hash_value: hash,
        target: lock.to_string_lossy().into_owned(),
        approved: None,
    }];
    let exe = dir.join("app.bin");
    std::fs::write(&exe, b"bytes").unwrap();
    let logger = AuditLogger::to_tracing();
    let err = bind_launched_workload(
        &[exe.to_string_lossy().into_owned()],
        &exe,
        &entries,
        &logger,
    )
    .unwrap_err();
    assert!(matches!(err, VerifyError::UnboundWorkload { .. }));
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_bind_rejects_inline_eval_flags() {
    let dir = make_test_dir("bind_inline");
    let py = dir.join("python");
    std::fs::write(&py, b"interpreter").unwrap();
    let hash = hash_file(&py).unwrap();
    let entries = vec![HashEntry {
        server_name: "s".into(),
        hash_type: HashType::Binary,
        hash_value: hash,
        target: py.to_string_lossy().into_owned(),
        approved: None,
    }];
    let logger = AuditLogger::to_tracing();
    for argv in [
        vec![
            py.to_string_lossy().into_owned(),
            "-c".into(),
            "print(1)".into(),
        ],
        // Equals-form, clustered, and concatenated spellings classify the
        // same way — argv0 here is a `python`-named stub.
        vec![py.to_string_lossy().into_owned(), "--eval=x".into()],
        vec![py.to_string_lossy().into_owned(), "-Ecprint(1)".into()],
        vec![py.to_string_lossy().into_owned(), "-cprint(1)".into()],
    ] {
        let err = bind_launched_workload(&argv, &py, &entries, &logger).unwrap_err();
        assert!(
            matches!(err, VerifyError::UnboundWorkload { .. }),
            "{argv:?}"
        );
    }
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_bind_entrypoint_reports_ambiguous_boundary() {
    let dir = make_test_dir("bind_ambiguous");
    let node = dir.join("node");
    let script = dir.join("srv.js");
    std::fs::write(&node, b"node-bin").unwrap();
    std::fs::write(&script, b"console.log(1)").unwrap();
    let hash = hash_file(&script).unwrap();
    let entries = vec![HashEntry {
        server_name: "s".into(),
        hash_type: HashType::Entrypoint,
        hash_value: hash,
        target: script.to_string_lossy().into_owned(),
        approved: None,
    }];
    let logger = AuditLogger::to_tracing();
    // `--not-a-node-flag` may consume the script token, so the payload
    // boundary is ambiguous — the rejection names the blocking option.
    let argv = vec![
        node.to_string_lossy().into_owned(),
        "--not-a-node-flag".into(),
        script.to_string_lossy().into_owned(),
    ];
    let err = bind_launched_workload(&argv, &node, &entries, &logger).unwrap_err();
    match err {
        VerifyError::UnboundWorkload { reason, .. } => {
            assert!(reason.contains("--not-a-node-flag"), "{reason}");
            assert!(reason.contains("ambiguous"), "{reason}");
        }
        other => panic!("expected UnboundWorkload, got {other:?}"),
    }
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn test_bind_entrypoint_rehashes_payload_content() {
    let dir = make_test_dir("bind_ep_rehash");
    let node = dir.join("node");
    let script = dir.join("srv.js");
    std::fs::write(&node, b"node-bin").unwrap();
    std::fs::write(&script, b"console.log(1)").unwrap();
    let logger = AuditLogger::to_tracing();
    let argv = vec![
        node.to_string_lossy().into_owned(),
        script.to_string_lossy().into_owned(),
    ];

    // Correct pins bind — an interpreted launch needs both: the
    // interpreter's binary-hash and the script's entrypoint-hash.
    let ok = vec![
        HashEntry {
            server_name: "s".into(),
            hash_type: HashType::Binary,
            hash_value: hash_file(&node).unwrap(),
            target: node.to_string_lossy().into_owned(),
            approved: None,
        },
        HashEntry {
            server_name: "s".into(),
            hash_type: HashType::Entrypoint,
            hash_value: hash_file(&script).unwrap(),
            target: script.to_string_lossy().into_owned(),
            approved: None,
        },
    ];
    bind_launched_workload(&argv, &node, &ok, &logger).unwrap();

    // A pin for different content rejects on path correspondence alone:
    // the script must still hash to the pinned value at re-verify time.
    let stale = vec![HashEntry {
        server_name: "s".into(),
        hash_type: HashType::Entrypoint,
        hash_value: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            .into(),
        target: script.to_string_lossy().into_owned(),
        approved: None,
    }];
    let err = bind_launched_workload(&argv, &node, &stale, &logger).unwrap_err();
    assert!(
        matches!(
            err,
            VerifyError::Mismatch {
                hash_type: HashType::Entrypoint,
                ..
            }
        ),
        "{err:?}"
    );
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// F30 — an `entrypoint-hash`-only policy cannot launch an
/// interpreter: the pinned script would run on an unpinned image
/// while the pin list looked satisfied. The launch must fail closed
/// until a `binary-hash` binds the resolved interpreter too.
#[tokio::test]
async fn test_bind_entrypoint_only_refuses_unpinned_interpreter() {
    let dir = make_test_dir("bind_ep_only");
    let node = dir.join("node");
    let script = dir.join("srv.js");
    std::fs::write(&node, b"node-bin").unwrap();
    std::fs::write(&script, b"console.log(1)").unwrap();
    let entries = vec![HashEntry {
        server_name: "s".into(),
        hash_type: HashType::Entrypoint,
        hash_value: hash_file(&script).unwrap(),
        target: script.to_string_lossy().into_owned(),
        approved: None,
    }];
    let logger = AuditLogger::to_tracing();
    let argv = vec![
        node.to_string_lossy().into_owned(),
        script.to_string_lossy().into_owned(),
    ];
    let err = bind_launched_workload(&argv, &node, &entries, &logger).unwrap_err();
    match err {
        VerifyError::UnboundWorkload { reason, .. } => {
            assert!(reason.contains("binary-hash"), "{reason}");
            assert!(reason.contains("interpreter"), "{reason}");
        }
        other => panic!("expected UnboundWorkload, got {other:?}"),
    }
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// F3 — the payload boundary is only proven under a modeled option
/// grammar. A binary+entrypoint policy on an unmodeled executable
/// name (`worker`, indistinguishable from a renamed interpreter)
/// must not certify a boundary the generic scan guessed.
#[tokio::test]
async fn test_bind_refuses_payload_pin_on_unmodeled_exe() {
    let dir = make_test_dir("bind_unmodeled");
    let worker = dir.join("worker");
    let script = dir.join("srv.js");
    std::fs::write(&worker, b"interpreter-renamed").unwrap();
    std::fs::write(&script, b"console.log(1)").unwrap();
    let entries = vec![
        HashEntry {
            server_name: "s".into(),
            hash_type: HashType::Binary,
            hash_value: hash_file(&worker).unwrap(),
            target: worker.to_string_lossy().into_owned(),
            approved: None,
        },
        HashEntry {
            server_name: "s".into(),
            hash_type: HashType::Entrypoint,
            hash_value: hash_file(&script).unwrap(),
            target: script.to_string_lossy().into_owned(),
            approved: None,
        },
    ];
    let logger = AuditLogger::to_tracing();
    let argv = vec![
        worker.to_string_lossy().into_owned(),
        script.to_string_lossy().into_owned(),
    ];
    let err = bind_launched_workload(&argv, &worker, &entries, &logger).unwrap_err();
    match err {
        VerifyError::UnboundWorkload { reason, .. } => {
            assert!(reason.contains("modeled option grammar"), "{reason}");
        }
        other => panic!("expected UnboundWorkload, got {other:?}"),
    }
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// The same pins bind when the resolved executable names a modeled
/// interpreter family — the boundary the entrypoint pin relies on
/// is proven under that grammar.
#[tokio::test]
async fn test_bind_modeled_interpreter_binds() {
    let dir = make_test_dir("bind_modeled");
    let python = dir.join("python3");
    let script = dir.join("srv.py");
    std::fs::write(&python, b"py-bin").unwrap();
    std::fs::write(&script, b"print(1)").unwrap();
    let entries = vec![
        HashEntry {
            server_name: "s".into(),
            hash_type: HashType::Binary,
            hash_value: hash_file(&python).unwrap(),
            target: python.to_string_lossy().into_owned(),
            approved: None,
        },
        HashEntry {
            server_name: "s".into(),
            hash_type: HashType::Entrypoint,
            hash_value: hash_file(&script).unwrap(),
            target: script.to_string_lossy().into_owned(),
            approved: None,
        },
    ];
    let logger = AuditLogger::to_tracing();
    let argv = vec![
        python.to_string_lossy().into_owned(),
        script.to_string_lossy().into_owned(),
    ];
    bind_launched_workload(&argv, &python, &entries, &logger).unwrap();
    let _ = logger.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
