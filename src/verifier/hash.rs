use std::fmt::{self, Write as _};
use std::io::{self, Read, Seek};
use std::path::Path;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::policy::{HashEntry, HashType};
use crate::workload::{
    argv_contains_inline_eval_with_exe, first_payload_arg_with_exe,
    payload_boundary_blocker_with_exe, same_file,
};

const BUFFER_SIZE: usize = 8192;

/// Open `path` for pinned verification — the returned handle stays held
/// through process creation. Windows opens it with `FILE_SHARE_READ |
/// FILE_SHARE_EXECUTE` only (no write/delete share), so while the pin is
/// held the verified object cannot be modified, renamed, or replaced —
/// the pathname cannot come to name different bytes before the loader
/// maps the image. Unix has no mandatory path locking, so the held fd
/// anchors [`same_open_object`]'s final identity re-check.
fn open_pinned(path: &Path) -> io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
        // Read sharing only — writes, renames, and deletes all fail
        // while the pin is held.
        opts.share_mode(FILE_SHARE_READ.0);
    }
    opts.open(path)
}

/// Hash an already-open file from its start — the digest covers the
/// object the handle names, not whatever the pathname resolves to next.
fn hash_open_file(file: &mut std::fs::File) -> io::Result<String> {
    file.seek(io::SeekFrom::Start(0))?;
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

/// Whether `path` still resolves to the same object as the open `file`
/// — device+inode on Unix, volume+file-index on Windows. The final
/// check a spawn path runs before exec'ing a pinned pathname.
fn same_open_object(path: &Path, file: &std::fs::File) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let Ok(held) = file.metadata() else {
            return false;
        };
        let Ok(named) = std::fs::metadata(path) else {
            return false;
        };
        held.dev() == named.dev() && held.ino() == named.ino()
    }
    #[cfg(windows)]
    {
        windows_file_identity(file) == fs_file_identity(path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path);
        true
    }
}

/// The object's recorded state at hash time — re-fetched from the held
/// descriptor at spawn verification. A held fd does not block writers
/// on Unix, so an in-place rewrite of a pinned file leaves the identity
/// check green while carrying unverified bytes; the stamp catches it.
#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

/// The recorded state of an open object at hash time. Unix keeps real
/// metadata; other platforms carry `()` — a held share mode already
/// blocks writers there, and the identity re-check covers retargeting.
#[cfg(unix)]
type OpenStamp = FileStamp;
#[cfg(not(unix))]
type OpenStamp = ();

#[cfg(unix)]
fn record_stamp(file: &std::fs::File) -> io::Result<OpenStamp> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    Ok(FileStamp {
        size: m.size(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
    })
}

#[cfg(not(unix))]
fn record_stamp(_file: &std::fs::File) -> io::Result<OpenStamp> {
    Ok(())
}

#[cfg(unix)]
fn stamp_unchanged(file: &std::fs::File, recorded: &OpenStamp) -> bool {
    record_stamp(file).is_ok_and(|stamp| stamp == *recorded)
}

#[cfg(not(unix))]
fn stamp_unchanged(_file: &std::fs::File, _recorded: &OpenStamp) -> bool {
    true
}

/// `(volume serial, file index)` for a Windows handle — the stable
/// object identity `MetadataExt::file_index` would give once stable.
#[cfg(windows)]
fn windows_file_identity(file: &std::fs::File) -> Option<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe {
        GetFileInformationByHandle(
            windows::Win32::Foundation::HANDLE(file.as_raw_handle() as _),
            &mut info,
        )
    }
    .ok()?;
    let index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Some((info.dwVolumeSerialNumber as u64, index))
}

#[cfg(windows)]
fn fs_file_identity(path: &Path) -> Option<(u64, u64)> {
    std::fs::File::open(path)
        .ok()
        .and_then(|f| windows_file_identity(&f))
}

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
    hash_open_file(&mut std::fs::File::open(path)?)
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
/// name those same objects — the verify-A-exec-B binding. A `binary-hash`
/// or `entrypoint-hash` target that canonicalizes to the resolved
/// executable is content-compared against the exe's digest; an
/// `entrypoint-hash` target matching the first payload argument is
/// re-hashed against its pin (`same_file` is path correspondence only,
/// so the payload match needs the content read).
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

    if argv_contains_inline_eval_with_exe(argv, Some(resolved_exe)) {
        return Err(VerifyError::UnboundWorkload {
            executable: resolved_exe.display().to_string(),
            reason: "inline evaluation flags (-c/-e/--eval/--command incl. attached \
                 and = spellings, -p/--print on node, -E on perl) are not a \
                 hash-bindable workload"
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
        // An entrypoint pinned at the executable was hash-compared in the
        // identity loop above. A payload match needs its own content check:
        // `same_file` compares canonicalized paths only, so path
        // correspondence alone would let a script swapped in after the
        // first verification launch under the stale pin.
        let payload_match = first_payload_arg_with_exe(argv, Some(resolved_exe))
            .is_some_and(|arg| same_file(Path::new(arg), target));
        let found = same_file(target, resolved_exe) || payload_match;
        if !found {
            // When the payload boundary is ambiguous the target may still
            // be a legitimately launched script — name the blocking option
            // so the report says why the boundary could not be resolved.
            let reason = match payload_boundary_blocker_with_exe(argv, Some(resolved_exe)) {
                Some(flag) => format!(
                    "entrypoint-hash target '{}' cannot be verified — option \
                     '{flag}' leaves the payload boundary ambiguous",
                    entry.target
                ),
                None => format!(
                    "entrypoint-hash target '{}' is not the launched executable or its first payload argument",
                    entry.target
                ),
            };
            return Err(VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason,
            });
        }
        if payload_match {
            let actual = hash_file(target).map_err(|error| VerifyError::FileError {
                hash_type: HashType::Entrypoint,
                target: entry.target.clone(),
                error,
            })?;
            if actual != entry.hash_value {
                return Err(VerifyError::Mismatch {
                    hash_type: entry.hash_type,
                    target: entry.target.clone(),
                    expected: entry.hash_value.clone(),
                    actual,
                });
            }
        }
    }

    Ok(())
}

/// The verified workload objects, held open across the spawn.
///
/// `reverify_immediately_before_spawn` returns this: the executable —
/// and any payload-matched entrypoint script — held open on a
/// replacement-preventing share mode (Windows) or as the fd anchoring
/// the final identity re-check (Unix). The caller keeps it alive until
/// the child process is created; dropping it earlier reopens the
/// hash-to-exec window.
pub struct SpawnPin {
    exe: std::fs::File,
    exe_stamp: OpenStamp,
    entrypoint: Option<PinnedEntry>,
}

/// A payload-matched entrypoint script, held open across the spawn.
struct PinnedEntry {
    /// The path the interpreter's spawn opens — the argv payload
    /// spelling resolved against the launch's working directory.
    path: std::path::PathBuf,
    file: std::fs::File,
    stamp: OpenStamp,
}

impl SpawnPin {
    /// The last identity check before the spawn opens the pathname —
    /// proves the path still resolves to the held (verified) object and
    /// that the object itself is unchanged since hashing. On Windows
    /// the held share mode already makes a swap fail; this also
    /// catches the Unix cases where a rename retargeted the path or a
    /// writer rewrote the pinned object between reverify and spawn.
    pub fn verify_spawn_path(&self, resolved_exe: &Path) -> Result<(), VerifyError> {
        if !same_open_object(resolved_exe, &self.exe) {
            return Err(VerifyError::Mismatch {
                hash_type: HashType::Binary,
                target: resolved_exe.display().to_string(),
                expected: "the pinned executable object".to_string(),
                actual: "pathname now resolves to a different object".to_string(),
            });
        }
        if !stamp_unchanged(&self.exe, &self.exe_stamp) {
            return Err(VerifyError::Mismatch {
                hash_type: HashType::Binary,
                target: resolved_exe.display().to_string(),
                expected: "the pinned executable object".to_string(),
                actual: "file modified after hashing".to_string(),
            });
        }
        if let Some(entry) = &self.entrypoint {
            if !same_open_object(&entry.path, &entry.file) {
                return Err(VerifyError::Mismatch {
                    hash_type: HashType::Entrypoint,
                    target: entry.path.display().to_string(),
                    expected: "the pinned entrypoint object".to_string(),
                    actual: "pathname now resolves to a different object".to_string(),
                });
            }
            if !stamp_unchanged(&entry.file, &entry.stamp) {
                return Err(VerifyError::Mismatch {
                    hash_type: HashType::Entrypoint,
                    target: entry.path.display().to_string(),
                    expected: "the pinned entrypoint object".to_string(),
                    actual: "file modified after hashing".to_string(),
                });
            }
        }
        Ok(())
    }
}

/// Re-run the binding checks immediately before spawn — the launched
/// executable and any payload-matched entrypoint script are re-hashed
/// once more, so a file swapped in after the initial verification fails
/// closed.
///
/// The returned [`SpawnPin`] keeps the verified objects open through
/// the spawn: on Windows the share mode makes modification/rename fail
/// while held, closing the hash-to-exec window; on Unix
/// [`SpawnPin::verify_spawn_path`] re-checks the path's object identity
/// immediately before exec, narrowing the window to the exec-internal
/// gap. Code the workload loads at run time stays unpinned.
pub fn reverify_immediately_before_spawn(
    argv: &[String],
    resolved_exe: &Path,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
) -> Result<SpawnPin, VerifyError> {
    bind_launched_workload(argv, resolved_exe, hash_entries, audit_logger)?;

    let identity_entries: Vec<&HashEntry> = hash_entries
        .iter()
        .filter(|e| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint))
        .collect();

    // Anchor the verified executable on a held handle and prove the
    // held bytes are the pinned bytes — the digest is computed from the
    // open object, not a pathname re-open.
    let mut exe_file = open_pinned(resolved_exe).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
    let held_exe = hash_open_file(&mut exe_file).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
    for entry in &identity_entries {
        if same_file(Path::new(&entry.target), resolved_exe) && entry.hash_value != held_exe {
            return Err(VerifyError::Mismatch {
                hash_type: entry.hash_type,
                target: entry.target.clone(),
                expected: entry.hash_value.clone(),
                actual: held_exe,
            });
        }
    }

    // A payload-matched entrypoint gets the same anchored treatment —
    // an interpreter's spawn opens the script by pathname, so the held
    // handle is what `verify_spawn_path` re-checks identity against.
    let mut entrypoint = None;
    for entry in identity_entries
        .iter()
        .filter(|e| e.hash_type == HashType::Entrypoint)
    {
        let target = Path::new(&entry.target);
        // The interpreter opens the argv spelling, not the manifest
        // target — resolve it the way the child's spawn does (a
        // relative path lands on the working directory the child
        // inherits) so the held handle and the re-check follow the
        // path the launch actually opens.
        let payload_path = first_payload_arg_with_exe(argv, Some(resolved_exe)).map(|arg| {
            let path = Path::new(arg);
            match std::env::current_dir() {
                Ok(cwd) if path.is_relative() => cwd.join(path),
                _ => path.to_path_buf(),
            }
        });
        let payload_match = payload_path.as_ref().is_some_and(|p| same_file(p, target));
        if !payload_match || same_file(target, resolved_exe) {
            continue;
        }
        let payload_path = payload_path.expect("payload_match implies a payload arg");
        let mut file = open_pinned(&payload_path).map_err(|error| VerifyError::FileError {
            hash_type: HashType::Entrypoint,
            target: entry.target.clone(),
            error,
        })?;
        // The argv spelling must name the manifest target's object —
        // a retarget between the same-file check and the pin open is a
        // mismatch, not a skip.
        if !same_open_object(target, &file) {
            return Err(VerifyError::Mismatch {
                hash_type: HashType::Entrypoint,
                target: entry.target.clone(),
                expected: "the manifest entrypoint object".to_string(),
                actual: "argv payload path resolves to a different object".to_string(),
            });
        }
        let held = hash_open_file(&mut file).map_err(|error| VerifyError::FileError {
            hash_type: HashType::Entrypoint,
            target: entry.target.clone(),
            error,
        })?;
        if held != entry.hash_value {
            return Err(VerifyError::Mismatch {
                hash_type: HashType::Entrypoint,
                target: entry.target.clone(),
                expected: entry.hash_value.clone(),
                actual: held,
            });
        }
        let stamp = record_stamp(&file).map_err(|error| VerifyError::FileError {
            hash_type: HashType::Entrypoint,
            target: entry.target.clone(),
            error,
        })?;
        entrypoint = Some(PinnedEntry {
            path: payload_path,
            file,
            stamp,
        });
    }

    let exe_stamp = record_stamp(&exe_file).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
    Ok(SpawnPin {
        exe: exe_file,
        exe_stamp,
        entrypoint,
    })
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

    #[test]
    fn test_spawn_pin_accepts_stable_path() {
        let dir = make_test_dir("pin_ok");
        let exe = dir.join("server.bin");
        std::fs::write(&exe, b"verified bytes").unwrap();

        let exe_file = open_pinned(&exe).unwrap();
        let pin = SpawnPin {
            exe_stamp: record_stamp(&exe_file).unwrap(),
            exe: exe_file,
            entrypoint: None,
        };
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
        let pin = SpawnPin {
            exe_stamp: record_stamp(&exe_file).unwrap(),
            exe: exe_file,
            entrypoint: None,
        };
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
        let pin = SpawnPin {
            exe_stamp: record_stamp(&exe_file).unwrap(),
            exe: exe_file,
            entrypoint: None,
        };
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
        let pin = SpawnPin {
            exe_stamp: record_stamp(&exe_file).unwrap(),
            exe: exe_file,
            entrypoint: None,
        };
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
