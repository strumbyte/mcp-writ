use super::pin::open_pinned;
use super::*;
use std::path::PathBuf;

fn make_test_dir(label: &str) -> PathBuf {
    let id = std::process::id();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = crate::testutil::real_temp_base().join(format!("mcp_writ_hash_{label}_{id}_{ts}"));
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

/// The fd-exec plan snapshots the pinned bytes into an immutable object
/// and re-hashes the snapshot — a rewrite between pin creation and the
/// plan must fail closed rather than exec the new bytes.
#[cfg(unix)]
#[test]
fn test_fd_exec_plan_snapshot_binds_verified_bytes() {
    let dir = make_test_dir("pin_snap");
    let exe = dir.join("server.bin");
    std::fs::write(&exe, b"good").unwrap();

    let exe_file = open_pinned(&exe).unwrap();
    let pin = SpawnPin::for_test(exe_file);
    let argv = vec!["server".to_string()];
    let plan = pin.fd_exec_plan(&argv, &exe).unwrap();
    // The exec target spells the snapshot whose bytes equal the
    // verified content — prove it by hashing through the plan's path.
    use std::io::{Read, Seek};
    let mut staged = String::new();
    let mut staged_file = std::fs::File::open(plan.exe_path()).unwrap();
    // Rewind before reading: `/dev/fd/N` has dup semantics — an open
    // shares the snapshot's file description, which the digest pass
    // left at EOF. Both live spellings (Linux `/proc/self/fd/N`
    // re-open, macOS staged path) open a fresh description, so the
    // seek is a harmless no-op there; it stays because a shared-offset
    // spelling silently reads "" without it.
    staged_file.seek(std::io::SeekFrom::Start(0)).unwrap();
    staged_file.read_to_string(&mut staged).unwrap();
    assert_eq!(staged, "good");
    drop(plan);
    let _ = std::fs::remove_dir_all(&dir);

    // Mutate the pinned object after pin creation: the snapshot's
    // re-hash must fail the plan rather than bind the new bytes.
    let dir = make_test_dir("pin_snap_race");
    let exe = dir.join("server.bin");
    std::fs::write(&exe, b"good").unwrap();
    let exe_file = open_pinned(&exe).unwrap();
    let pin = SpawnPin::for_test(exe_file);
    std::fs::write(&exe, b"evil").unwrap();
    assert!(
        pin.fd_exec_plan(&argv, &exe).is_err(),
        "post-pin mutation must fail the snapshot digest check"
    );
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A payload-bound entrypoint launches by its *real path* — never an
/// fd or staged spelling — because the interpreter opens, realpaths,
/// and resolves imports relative to that name. The exe still gets the
/// snapshot spelling, and the payload argv position is re-spelled to
/// the resolved path the pin verified.
#[cfg(unix)]
#[test]
fn test_fd_exec_plan_entrypoint_launches_by_real_path() {
    let dir = make_test_dir("pin_entrypath");
    let exe = dir.join("interp.bin");
    let script = dir.join("server.mjs");
    std::fs::write(&exe, b"interp bytes").unwrap();
    std::fs::write(&script, b"import './tools.mjs'\n").unwrap();

    let exe_file = open_pinned(&exe).unwrap();
    let entry_file = open_pinned(&script).unwrap();
    let pin = SpawnPin::for_test_with_entry(exe_file, entry_file, script.clone());
    let argv = vec!["node".to_string(), script.to_string_lossy().into_owned()];
    let plan = pin.fd_exec_plan(&argv, &exe).unwrap();

    // The exe still rides the snapshot spelling — memfd fd on Linux,
    // owner-only staged path elsewhere — never the workload pathname.
    assert_ne!(
        plan.exe_path(),
        exe.as_path(),
        "the exe must keep its snapshot exec spelling"
    );
    assert_eq!(
        plan.exe_exec_mode(),
        if cfg!(target_os = "linux") {
            "fd"
        } else {
            "staged"
        }
    );
    assert_eq!(plan.entrypoint_exec_mode(), Some("path"));

    // The payload arg is re-spelled to the resolved real path — an
    // interpreter-readable spelling with its real directory intact.
    let rewritten = plan.exec_argv(&argv);
    assert_eq!(rewritten[0], "node");
    assert_eq!(rewritten[1], script.display().to_string());
    assert!(
        !rewritten[1].starts_with("/proc/self/fd") && !rewritten[1].starts_with("/dev/fd"),
        "the entrypoint must not be spelled through an fd path: {:?}",
        rewritten[1]
    );

    drop(plan);
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The real-path spelling still stands behind the pin's last check: a
/// payload script swapped or rewritten after pin creation fails the
/// launch the same way the exe check does.
#[cfg(unix)]
#[test]
fn test_spawn_pin_entrypoint_swap_fails() {
    let dir = make_test_dir("pin_entryswap");
    let exe = dir.join("interp.bin");
    let script = dir.join("server.mjs");
    std::fs::write(&exe, b"interp bytes").unwrap();
    std::fs::write(&script, b"entry").unwrap();

    let exe_file = open_pinned(&exe).unwrap();
    let entry_file = open_pinned(&script).unwrap();
    let pin = SpawnPin::for_test_with_entry(exe_file, entry_file, script.clone());
    assert!(pin.verify_spawn_path(&exe).is_ok());

    // A rename retargeting the entry path — caught by the held-object
    // identity check on the entrypoint half.
    std::fs::rename(&script, dir.join("original.mjs")).unwrap();
    std::fs::write(&script, b"evil").unwrap();
    assert!(
        pin.verify_spawn_path(&exe).is_err(),
        "a swapped payload path must fail the last check"
    );
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);

    // An in-place rewrite keeps the inode — the stamp catches it.
    let dir = make_test_dir("pin_entryrewrite");
    let exe = dir.join("interp.bin");
    let script = dir.join("server.mjs");
    std::fs::write(&exe, b"interp bytes").unwrap();
    std::fs::write(&script, b"entry").unwrap();
    let pin = SpawnPin::for_test_with_entry(
        open_pinned(&exe).unwrap(),
        open_pinned(&script).unwrap(),
        script.clone(),
    );
    std::fs::write(&script, b"evil").unwrap();
    assert!(
        pin.verify_spawn_path(&exe).is_err(),
        "an in-place rewrite of the payload must fail the last check"
    );
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The re-verifier resolves the argv payload spelling (`.`
/// components included), then re-spells argv with the *clean*
/// normalized path — an argv of `./server.py` must not surface in the
/// child as `/cwd/./server.py`. `..` is deliberately not collapsed:
/// a lexical pop could name a different object across symlinks.
#[cfg(unix)]
#[tokio::test]
async fn test_reverify_respells_normalized_entrypoint_path() {
    let dir = make_test_dir("pin_norm");
    let exe = dir.join("python3");
    let script = dir.join("server.py");
    std::fs::write(&exe, b"interp bytes").unwrap();
    std::fs::write(&script, b"entry").unwrap();

    let entries = vec![
        HashEntry {
            server_name: "s".to_string(),
            hash_type: HashType::Binary,
            hash_value: hash_file(&exe).unwrap(),
            target: exe.to_string_lossy().into_owned(),
            approved: None,
        },
        HashEntry {
            server_name: "s".to_string(),
            hash_type: HashType::Entrypoint,
            hash_value: hash_file(&script).unwrap(),
            target: script.to_string_lossy().into_owned(),
            approved: None,
        },
    ];
    let spelled = format!("{}/./server.py", dir.display());
    let argv = vec!["python3".to_string(), spelled];
    let logger = AuditLogger::to_tracing();
    let pin = reverify_immediately_before_spawn(&argv, &exe, &entries, &logger).unwrap();
    let plan = pin.fd_exec_plan(&argv, &exe).unwrap();
    let rewritten = plan.exec_argv(&argv);
    assert_eq!(rewritten[1], script.display().to_string());
    drop(plan);
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Linux namespaced handoff: a payload-bound plan carries a CLOEXEC
/// dup of the pinned entrypoint — `entrypoint_bind_pin` names the
/// descriptor, the resolved path init mounts the verified copy over,
/// and the digest init re-checks the bytes against, so the mount
/// anchors the pinned content rather than whatever the path happens
/// to name inside the namespace.
#[cfg(target_os = "linux")]
#[test]
fn test_fd_exec_plan_entrypoint_bind_pin_names_verified_object() {
    use std::os::unix::fs::MetadataExt;

    let dir = make_test_dir("pin_entrybind");
    let exe = dir.join("interp.bin");
    let script = dir.join("server.mjs");
    std::fs::write(&exe, b"interp bytes").unwrap();
    std::fs::write(&script, b"entry").unwrap();

    let pin = SpawnPin::for_test_with_entry(
        open_pinned(&exe).unwrap(),
        open_pinned(&script).unwrap(),
        script.clone(),
    );
    let argv = vec!["node".to_string(), script.to_string_lossy().into_owned()];
    let plan = pin.fd_exec_plan(&argv, &exe).unwrap();

    let Some((fd, target, sha)) = plan.entrypoint_bind_pin() else {
        panic!("a payload-bound pin must carry the namespaced bind-mount fd");
    };
    assert!(fd > 2);
    assert_eq!(target, script.as_path());
    // The digest the init re-check enforces is the script's content
    // hash — the same gate the parent's verify applied.
    assert_eq!(sha, hash_bytes(b"entry"));
    // The dup names the same object as the script — the property the
    // staged-copy mount relies on.
    let held = std::fs::metadata(format!("/proc/self/fd/{fd}")).unwrap();
    let named = std::fs::metadata(&script).unwrap();
    assert_eq!(held.dev(), named.dev());
    assert_eq!(held.ino(), named.ino());
    // It is *not* in the exe uncloak list — other launch routes must
    // not inherit a descriptor they never asked for.
    assert!(!plan.uncloak_fds().contains(&fd));

    drop(plan);
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// An exe-only pin has no entrypoint to bind-mount — the handoff
/// stays absent.
#[cfg(target_os = "linux")]
#[test]
fn test_fd_exec_plan_exe_only_has_no_bind_pin() {
    let dir = make_test_dir("pin_nobind");
    let exe = dir.join("server.bin");
    std::fs::write(&exe, b"verified bytes").unwrap();

    let pin = SpawnPin::for_test(open_pinned(&exe).unwrap());
    let argv = vec!["server".to_string()];
    let plan = pin.fd_exec_plan(&argv, &exe).unwrap();
    assert!(plan.entrypoint_bind_pin().is_none());
    drop(plan);
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The Windows entrypoint argv keeps the script's real path — the pin
/// (session-held share mode) is the guarantee, not a staged copy.
#[cfg(windows)]
#[test]
fn test_entrypoint_exec_argv_respells_real_path() {
    let dir = make_test_dir("pin_entrywin");
    let exe = dir.join("interp.exe");
    let script = dir.join("server.mjs");
    std::fs::write(&exe, b"interp bytes").unwrap();
    std::fs::write(&script, b"entry").unwrap();

    let pin = SpawnPin::for_test_with_entry(
        open_pinned(&exe).unwrap(),
        open_pinned(&script).unwrap(),
        script.clone(),
    );
    let argv = vec!["node".to_string(), script.to_string_lossy().into_owned()];
    let rewritten = pin.entrypoint_exec_argv(&argv, &exe).unwrap();
    assert_eq!(rewritten[1], script.display().to_string());
    drop(pin);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A cwd-joined payload path keeps no `\\?\` prefix — the argv
/// re-spelling hands the interpreter an ordinary spelling it can
/// realpath and resolve imports against.
#[cfg(windows)]
#[test]
fn test_simplify_verbatim_strips_prefix() {
    use super::pin::simplify_verbatim;
    assert_eq!(
        simplify_verbatim(PathBuf::from(r"\\?\C:\work\server.mjs")),
        PathBuf::from(r"C:\work\server.mjs")
    );
    assert_eq!(
        simplify_verbatim(PathBuf::from(r"\\?\UNC\srv\share\server.mjs")),
        PathBuf::from(r"\\srv\share\server.mjs")
    );
    // Ordinary spellings pass through untouched.
    assert_eq!(
        simplify_verbatim(PathBuf::from(r"C:\work\server.mjs")),
        PathBuf::from(r"C:\work\server.mjs")
    );
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
        let dir =
            crate::testutil::real_temp_base().join(format!("mcp_writ_hash_int_{label}_{id}_{ts}"));
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

        let _ = logger.shutdown().await;

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

        let _ = logger.shutdown().await;

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

        let _ = logger.shutdown().await;

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

        let _ = logger.shutdown().await;

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

        let _ = logger.shutdown().await;
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

        let _ = logger.shutdown().await;

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
}
