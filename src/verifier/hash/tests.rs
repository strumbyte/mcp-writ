use super::pin::open_pinned;
use super::*;
use std::path::PathBuf;

fn make_test_dir(label: &str) -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mcp_writ_hash_{label}_{id}_{ts}"));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_hash_file_empty() {
    let dir = make_test_dir("empty");
    let path = dir.join("empty.bin");
    std::fs::write(&path, b"").unwrap();

    let hash = hash_file(&path).unwrap();
    // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        hash,
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_hash_file_known_input() {
    let dir = make_test_dir("known");
    let path = dir.join("abc.txt");
    std::fs::write(&path, b"abc").unwrap();

    let hash = hash_file(&path).unwrap();
    // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert_eq!(
        hash,
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_hash_file_larger_than_buffer() {
    let dir = make_test_dir("large");
    let path = dir.join("large.bin");
    // Create a file larger than the 8KB buffer
    let data = vec![0xABu8; 32768]; // 32KB
    std::fs::write(&path, &data).unwrap();

    let hash = hash_file(&path).unwrap();
    assert!(hash.starts_with("sha256:"));
    assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_hash_file_nonexistent() {
    let result = hash_file(Path::new("/nonexistent/path/file.bin"));
    assert!(result.is_err());
}

#[test]
fn test_hash_file_format() {
    let dir = make_test_dir("format");
    let path = dir.join("test.txt");
    std::fs::write(&path, b"test data").unwrap();

    let hash = hash_file(&path).unwrap();
    assert!(hash.starts_with("sha256:"));
    let hex_part = &hash[7..];
    assert_eq!(hex_part.len(), 64);
    assert!(hex_part.chars().all(|c| c.is_ascii_hexdigit()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_verify_hash_match() {
    let dir = make_test_dir("verify_match");
    let path = dir.join("abc.txt");
    std::fs::write(&path, b"abc").unwrap();

    let expected = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert!(verify_hash(&path, expected).unwrap());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_verify_hash_mismatch() {
    let dir = make_test_dir("verify_mismatch");
    let path = dir.join("abc.txt");
    std::fs::write(&path, b"abc").unwrap();

    let wrong = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    assert!(!verify_hash(&path, wrong).unwrap());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_verify_hash_file_not_found() {
    let result = verify_hash(
        Path::new("/nonexistent"),
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    );
    assert!(result.is_err());
}

#[test]
fn test_hash_file_deterministic() {
    let dir = make_test_dir("deterministic");
    let path = dir.join("data.bin");
    std::fs::write(&path, b"deterministic test content").unwrap();

    let hash1 = hash_file(&path).unwrap();
    let hash2 = hash_file(&path).unwrap();
    assert_eq!(hash1, hash2);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_hash_target_as_str() {
    assert_eq!(HashTarget::Binary.as_str(), "binary");
    assert_eq!(HashTarget::Lockfile.as_str(), "lockfile");
    assert_eq!(HashTarget::Entrypoint.as_str(), "entrypoint");
    assert_eq!(HashTarget::DockerManifest.as_str(), "docker-manifest");
}

#[test]
fn test_hash_target_display() {
    assert_eq!(format!("{}", HashTarget::Binary), "binary");
    assert_eq!(format!("{}", HashTarget::Lockfile), "lockfile");
}

#[test]
fn test_verify_error_display_mismatch() {
    let err = VerifyError::Mismatch {
        hash_type: HashType::Binary,
        target: "/bin/server".to_string(),
        expected: "sha256:aaa".to_string(),
        actual: "sha256:bbb".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("binary-hash"));
    assert!(msg.contains("/bin/server"));
    assert!(msg.contains("sha256:aaa"));
    assert!(msg.contains("sha256:bbb"));
}

#[test]
fn test_verify_error_display_file_error() {
    let err = VerifyError::FileError {
        hash_type: HashType::Lockfile,
        target: "package-lock.json".to_string(),
        error: io::Error::new(io::ErrorKind::NotFound, "not found"),
    };
    let msg = err.to_string();
    assert!(msg.contains("lockfile-hash"));
    assert!(msg.contains("package-lock.json"));
}

#[test]
fn test_spawn_pin_accepts_stable_path() {
    let dir = make_test_dir("pin_ok");
    let exe = dir.join("server.bin");
    std::fs::write(&exe, b"verified bytes").unwrap();

    let exe_file = open_pinned(&exe).unwrap();
    let pin = SpawnPin::for_test(exe_file);
    assert!(pin.verify_spawn_path(&exe).is_ok());

    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pathname retargeted to a different object while the pin is
/// held must fail the final identity check — the swap-detection
/// half of the hash-to-exec guard. On Windows the held share mode
/// blocks the rename outright, so this exercises Unix semantics.
#[cfg(unix)]
#[test]
fn test_spawn_pin_detects_renamed_swap() {
    let dir = make_test_dir("pin_swap");
    let exe = dir.join("server.bin");
    std::fs::write(&exe, b"good").unwrap();

    let exe_file = open_pinned(&exe).unwrap();
    let pin = SpawnPin::for_test(exe_file);
    std::fs::rename(&exe, dir.join("original.bin")).unwrap();
    std::fs::write(&exe, b"evil").unwrap();

    assert!(
        pin.verify_spawn_path(&exe).is_err(),
        "a pathname swapped to a different object must fail"
    );

    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A held fd does not block writers on Unix — a rewrite through
/// the same inode leaves device+inode intact, so the recorded
/// metadata stamp is what catches the swapped bytes.
#[cfg(unix)]
#[test]
fn test_spawn_pin_detects_in_place_rewrite() {
    let dir = make_test_dir("pin_rewrite");
    let exe = dir.join("server.bin");
    std::fs::write(&exe, b"good").unwrap();

    let exe_file = open_pinned(&exe).unwrap();
    let pin = SpawnPin::for_test(exe_file);
    // Truncate-and-rewrite keeps the inode — only the stamp differs.
    std::fs::write(&exe, b"evil").unwrap();

    assert!(
        pin.verify_spawn_path(&exe).is_err(),
        "an in-place rewrite of the pinned object must fail"
    );

    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Windows pins carry no write/delete share: while the handle is
/// held the OS itself refuses the rename a swap needs.
#[cfg(windows)]
#[test]
fn test_spawn_pin_blocks_rename_while_held() {
    let dir = make_test_dir("pin_locked");
    let exe = dir.join("server.bin");
    std::fs::write(&exe, b"good").unwrap();

    let exe_file = open_pinned(&exe).unwrap();
    let pin = SpawnPin::for_test(exe_file);
    assert!(std::fs::rename(&exe, dir.join("moved.bin")).is_err());
    assert!(pin.verify_spawn_path(&exe).is_ok());

    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn test_hash_open_file_matches_path_hash() {
    let dir = make_test_dir("open_hash");
    let path = dir.join("f.bin");
    std::fs::write(&path, b"same bytes").unwrap();
    let mut file = open_pinned(&path).unwrap();
    assert_eq!(
        hash_open_file(&mut file).unwrap(),
        hash_file(&path).unwrap()
    );
    drop(file);
    let _ = std::fs::remove_dir_all(&dir);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Integration tests: verify_server_hashes + AuditLogger
// ═══════════════════════════════════════════════════════════════════════════════

mod integration_tests {
    use super::super::*;
    use std::path::PathBuf;

    fn make_test_dir(label: &str) -> PathBuf {
        let id = std::process::id();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("mcp_writ_hash_int_{label}_{id}_{ts}"));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn test_verify_server_hashes_all_match() {
        let dir = make_test_dir("all_match");
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

        logger.shutdown().await;

        let content = std::fs::read_to_string(&audit_path).unwrap();
        assert!(content.contains("\"event_type\":\"hash.verified\""));
        assert!(content.contains("my-server"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_verify_server_hashes_mismatch_blocks() {
        let dir = make_test_dir("mismatch");
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

        logger.shutdown().await;

        let content = std::fs::read_to_string(&audit_path).unwrap();
        assert!(content.contains("\"event_type\":\"hash.mismatch\""));
        assert!(content.contains("\"severity\":\"critical\""));
        assert!(content.contains("\"action\":\"denied\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_verify_server_hashes_no_entries_warns() {
        let dir = make_test_dir("no_entries");
        let audit_path = dir.join("audit.jsonl");

        let entries: Vec<HashEntry> = vec![];

        let logger = AuditLogger::to_file(&audit_path).unwrap();
        let result = verify_server_hashes("my-server", &entries, &logger);
        assert_eq!(result.unwrap(), VerifyResult::NoEntries);

        logger.shutdown().await;

        // No audit events should be emitted (warning is via tracing, not audit log)
        let content = std::fs::read_to_string(&audit_path).unwrap_or_default();
        assert!(content.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_verify_server_hashes_file_not_found_blocks() {
        let dir = make_test_dir("file_missing");
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

        logger.shutdown().await;

        let content = std::fs::read_to_string(&audit_path).unwrap();
        assert!(content.contains("\"event_type\":\"hash.mismatch\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_verify_server_hashes_filters_by_server() {
        let dir = make_test_dir("filter_server");
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

        logger.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_verify_server_hashes_multiple_entries() {
        let dir = make_test_dir("multi_entry");
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

        logger.shutdown().await;

        let content = std::fs::read_to_string(&audit_path).unwrap();
        let verified_count = content.matches("\"event_type\":\"hash.verified\"").count();
        assert_eq!(verified_count, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_verify_server_hashes_stops_on_first_mismatch() {
        let dir = make_test_dir("first_mismatch");
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

        logger.shutdown().await;

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
        logger.shutdown().await;
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
        logger.shutdown().await;
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
        logger.shutdown().await;
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
        logger.shutdown().await;
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

        // Correct pin binds.
        let ok = vec![HashEntry {
            server_name: "s".into(),
            hash_type: HashType::Entrypoint,
            hash_value: hash_file(&script).unwrap(),
            target: script.to_string_lossy().into_owned(),
            approved: None,
        }];
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
        logger.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
