use std::fmt::{self, Write as _};
use std::io::{self, Read};
use std::path::Path;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::policy::{HashEntry, HashType};
use crate::workload::{argv_contains_inline_eval, first_payload_arg, same_file};

const BUFFER_SIZE: usize = 8192;

/// Classification of hash targets by server type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashTarget {
    /// Native ELF/Mach-O binary
    Binary,
    /// Lock file (package-lock.json, requirements.txt, poetry.lock)
    Lockfile,
    /// Entry point script (index.js, main.py)
    Entrypoint,
    /// Docker image manifest digest
    DockerManifest,
}

impl HashTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Binary => "binary",
            Self::Lockfile => "lockfile",
            Self::Entrypoint => "entrypoint",
            Self::DockerManifest => "docker-manifest",
        }
    }
}

impl fmt::Display for HashTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Compute SHA-256 hash of a file using 8KB streaming chunks.
/// Returns the hash in `sha256:<hex>` format.
pub fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format_sha256(hasher.finalize()))
}

/// Format digest bytes as `sha256:<lowercase hex>`.
/// sha2 0.11's `Output<Sha256>` no longer implements `LowerHex`.
pub(crate) fn format_sha256(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut out = String::with_capacity(7 + bytes.len() * 2);
    out.push_str("sha256:");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Verify a file's SHA-256 hash against an expected value.
/// Returns `Ok(true)` if hashes match, `Ok(false)` if they don't.
pub fn verify_hash(path: &Path, expected: &str) -> io::Result<bool> {
    let actual = hash_file(path)?;
    Ok(actual == expected)
}

/// Result of verifying hash entries for a server.
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyResult {
    /// All hash entries verified successfully.
    Verified,
    /// No hash entries found for this server (warn and allow).
    NoEntries,
}

/// Error when hash verification fails — the server should be blocked.
#[derive(Debug)]
pub enum VerifyError {
    /// Hash mismatch: the file exists but the hash differs from the policy.
    Mismatch {
        hash_type: HashType,
        target: String,
        expected: String,
        actual: String,
    },
    /// Target file could not be read.
    FileError {
        hash_type: HashType,
        target: String,
        error: io::Error,
    },
    /// The launched executable is not one of the verified hash targets.
    UnboundWorkload { executable: String, reason: String },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mismatch {
                hash_type,
                target,
                expected,
                actual,
            } => write!(
                f,
                "{} mismatch for '{}': expected {}, got {}",
                hash_type.as_str(),
                target,
                expected,
                actual
            ),
            Self::FileError {
                hash_type,
                target,
                error,
            } => write!(
                f,
                "{} target '{}' unreadable: {}",
                hash_type.as_str(),
                target,
                error
            ),
            Self::UnboundWorkload { executable, reason } => {
                write!(
                    f,
                    "launched executable '{executable}' is not bound to a verified hash target: {reason}"
                )
            }
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify all hash entries for a given server against their target files.
///
/// - If no entries exist for the server: logs a warning and returns `Ok(NoEntries)`.
/// - If all entries match: emits `HashVerified` audit events and returns `Ok(Verified)`.
/// - On first mismatch or file error: emits `HashMismatch` audit event and returns `Err`.
pub fn verify_server_hashes(
    server_name: &str,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
) -> Result<VerifyResult, VerifyError> {
    let entries: Vec<&HashEntry> = hash_entries
        .iter()
        .filter(|e| e.server_name == server_name)
        .collect();

    if entries.is_empty() {
        tracing::warn!(
            server = server_name,
            "No hash entries in policy for server; allowing startup"
        );
        return Ok(VerifyResult::NoEntries);
    }

    let correlation_id = Uuid::now_v7();

    for entry in &entries {
        let target_path = Path::new(&entry.target);

        let actual_hash = match hash_file(target_path) {
            Ok(h) => h,
            Err(error) => {
                let mut evt = AuditEvent::new(
                    correlation_id,
                    EventType::HashMismatch,
                    Severity::Critical,
                    Outcome::Failure,
                    Action::Denied,
                );
                evt.target_server = Some(server_name.to_string());
                evt.details = Some(format!(
                    "{} target '{}' unreadable: {}",
                    entry.hash_type.as_str(),
                    entry.target,
                    error
                ));
                audit_logger.log(evt);

                return Err(VerifyError::FileError {
                    hash_type: entry.hash_type,
                    target: entry.target.clone(),
                    error,
                });
            }
        };

        if actual_hash != entry.hash_value {
            let mut evt = AuditEvent::new(
                correlation_id,
                EventType::HashMismatch,
                Severity::Critical,
                Outcome::Failure,
                Action::Denied,
            );
            evt.target_server = Some(server_name.to_string());
            evt.details = Some(format!(
                "{} mismatch for '{}': expected {}, got {}",
                entry.hash_type.as_str(),
                entry.target,
                entry.hash_value,
                actual_hash
            ));
            audit_logger.log(evt);

            return Err(VerifyError::Mismatch {
                hash_type: entry.hash_type,
                target: entry.target.clone(),
                expected: entry.hash_value.clone(),
                actual: actual_hash,
            });
        }

        // Hash matches — emit success event
        let mut evt = AuditEvent::new(
            correlation_id,
            EventType::HashVerified,
            Severity::Info,
            Outcome::Success,
            Action::Allowed,
        );
        evt.target_server = Some(server_name.to_string());
        evt.details = Some(format!(
            "{} verified for '{}'",
            entry.hash_type.as_str(),
            entry.target
        ));
        audit_logger.log(evt);
    }

    Ok(VerifyResult::Verified)
}

/// After verifying configured hash entries, require the launched argv to
/// name those same objects (closes the verify-A-exec-B gap).
pub fn bind_launched_workload(
    argv: &[String],
    resolved_exe: &Path,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
) -> Result<(), VerifyError> {
    if hash_entries.is_empty() {
        return Ok(());
    }

    let identity_entries: Vec<&HashEntry> = hash_entries
        .iter()
        .filter(|e| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint))
        .collect();

    if identity_entries.is_empty() {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "hash entries exist but none are binary-hash or entrypoint-hash; \
                     lockfile/docker hashes cannot bind the launched process"
                .into(),
        });
    }

    if argv_contains_inline_eval(argv) {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason:
                "inline evaluation flags (-c/-e/--eval/--command) are not a hash-bindable workload"
                    .into(),
        });
    }

    let exe_hash = hash_file(resolved_exe).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;

    let mut matched_exe = false;
    for entry in &identity_entries {
        let target = Path::new(&entry.target);
        if same_file(target, resolved_exe) {
            if entry.hash_value != exe_hash {
                return Err(VerifyError::Mismatch {
                    hash_type: entry.hash_type,
                    target: entry.target.clone(),
                    expected: entry.hash_value.clone(),
                    actual: exe_hash,
                });
            }
            matched_exe = true;
        }
    }

    let has_binary = identity_entries
        .iter()
        .any(|e| e.hash_type == HashType::Binary);
    if has_binary && !matched_exe {
        let mut evt = AuditEvent::new(
            Uuid::now_v7(),
            EventType::HashMismatch,
            Severity::Critical,
            Outcome::Failure,
            Action::Denied,
        );
        evt.details = Some(format!(
            "launched '{}' is not a verified binary-hash target",
            resolved_exe.display()
        ));
        audit_logger.log(evt);
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "no binary-hash target canonicalizes to the launched executable".into(),
        });
    }

    for entry in identity_entries
        .iter()
        .filter(|e| e.hash_type == HashType::Entrypoint)
    {
        let target = Path::new(&entry.target);
        let found = same_file(target, resolved_exe)
            || first_payload_arg(argv).is_some_and(|arg| same_file(Path::new(arg), target));
        if !found {
            return Err(VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason: format!(
                    "entrypoint-hash target '{}' is not the launched executable or its first payload argument",
                    entry.target
                ),
            });
        }
    }

    Ok(())
}

/// Re-hash the launched executable immediately before spawn (TOCTOU close).
pub fn reverify_immediately_before_spawn(
    argv: &[String],
    resolved_exe: &Path,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
) -> Result<(), VerifyError> {
    bind_launched_workload(argv, resolved_exe, hash_entries, audit_logger)
}

#[cfg(test)]
mod tests {
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
}

// ═══════════════════════════════════════════════════════════════════════════════
// Integration tests: verify_server_hashes + AuditLogger
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod integration_tests {
    use super::*;
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
        let err = bind_launched_workload(
            &[
                py.to_string_lossy().into_owned(),
                "-c".into(),
                "print(1)".into(),
            ],
            &py,
            &entries,
            &logger,
        )
        .unwrap_err();
        assert!(matches!(err, VerifyError::UnboundWorkload { .. }));
        logger.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }
}
