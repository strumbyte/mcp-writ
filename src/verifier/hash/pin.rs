//! Spawn-time pinning for verified workload objects: hold the hashed
//! executable — and any payload-matched entrypoint script — open through
//! process creation so the bytes the loader maps are the bytes that were
//! verified.

use std::io;
use std::path::Path;

use uuid::Uuid;

use super::{VerifyError, hash_file, hash_open_file};
use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::policy::{HashEntry, HashType};
use crate::workload::{
    argv_contains_inline_eval_with_exe, first_payload_arg_with_exe,
    payload_boundary_blocker_with_exe, same_file,
};

/// Open `path` for pinned verification — the returned handle stays held
/// through process creation. Windows opens it sharing `FILE_SHARE_READ`
/// only — write and delete sharing stay closed, so while the pin is
/// held the verified object cannot be modified, renamed, or replaced
/// and the pathname cannot come to name different bytes before the
/// loader maps the image. (No `FILE_SHARE_EXECUTE` share mode exists:
/// process creation needs only read sharing on the image, so
/// `FILE_SHARE_READ` alone does not block the spawn.) Unix has no
/// mandatory path locking, so the held fd anchors
/// [`same_open_object`]'s final identity re-check.
pub(crate) fn open_pinned(path: &Path) -> io::Result<std::fs::File> {
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
/// metadata; other platforms carry a zero-sized marker — a held share
/// mode already blocks writers there, and the identity re-check covers
/// retargeting. The marker is a named type rather than `()` so the
/// recorded-stamp bindings stay real values on every platform.
#[cfg(unix)]
type OpenStamp = FileStamp;
#[cfg(not(unix))]
struct OpenStamp;

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
    Ok(OpenStamp)
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

#[cfg(test)]
impl SpawnPin {
    /// A bare executable-only pin for tests — production pins are minted
    /// exclusively by `reverify_immediately_before_spawn`.
    pub(crate) fn for_test(exe: std::fs::File) -> Self {
        Self {
            exe_stamp: record_stamp(&exe).expect("record stamp"),
            exe,
            entrypoint: None,
        }
    }
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
    /// A swap landing between this check and the kernel's exec-time
    /// open is the residual gap documented on
    /// [`reverify_immediately_before_spawn`] — keep this call ordered
    /// last before the spawn.
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
/// gap. That residual gap is inherent to pathname-based `exec` — a swap
/// landing between the re-check and the kernel's own open still
/// resolves unverified bytes, and closing it fully would need fd-based
/// exec (`execveat`/`fexecve` via `/proc/self/fd`), which
/// `std::process::Command` cannot express; ordering the re-check last
/// is the mitigation boundary. Code the workload loads at run time
/// stays unpinned.
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
    // Stamp before hashing, not after: a held fd does not block writers
    // on Unix, so an in-place rewrite during the read must change the
    // stamp — recording only after hashing would accept unverified bytes.
    let exe_stamp = record_stamp(&exe_file).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
    let held_exe = hash_open_file(&mut exe_file).map_err(|error| VerifyError::FileError {
        hash_type: HashType::Binary,
        target: resolved_exe.display().to_string(),
        error,
    })?;
    if !stamp_unchanged(&exe_file, &exe_stamp) {
        return Err(VerifyError::Mismatch {
            hash_type: HashType::Binary,
            target: resolved_exe.display().to_string(),
            expected: "the pinned executable object".to_string(),
            actual: "file modified during hashing".to_string(),
        });
    }
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
        // Same ordering as the executable pin: stamp at open, re-check
        // after hashing so a mid-read rewrite fails closed.
        let stamp = record_stamp(&file).map_err(|error| VerifyError::FileError {
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
        if !stamp_unchanged(&file, &stamp) {
            return Err(VerifyError::Mismatch {
                hash_type: HashType::Entrypoint,
                target: entry.target.clone(),
                expected: "the pinned entrypoint object".to_string(),
                actual: "file modified during hashing".to_string(),
            });
        }
        entrypoint = Some(PinnedEntry {
            path: payload_path,
            file,
            stamp,
        });
    }

    Ok(SpawnPin {
        exe: exe_file,
        exe_stamp,
        entrypoint,
    })
}
