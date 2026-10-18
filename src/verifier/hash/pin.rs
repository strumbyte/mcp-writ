//! Spawn-time pinning for verified workload objects: hold the hashed
//! executable — and any payload-matched entrypoint script — open through
//! process creation so the bytes the loader maps are the bytes that were
//! verified.

use std::io;
use std::path::Path;
#[cfg(any(unix, windows))]
use std::path::PathBuf;

use uuid::Uuid;

use super::{VerifyError, hash_file, hash_open_file};
use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::policy::{HashEntry, HashType};
#[cfg(any(unix, windows))]
use crate::workload::first_payload_arg_index_with_exe;
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
    let mut matched_binary = false;
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
            matched_binary |= entry.hash_type == HashType::Binary;
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

    let payload_arg = first_payload_arg_with_exe(argv, Some(resolved_exe));
    let mut payload_bound = false;
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
        let payload_match = payload_arg.is_some_and(|arg| same_file(Path::new(arg), target));
        let at_exe = same_file(target, resolved_exe);
        let found = at_exe || payload_match;
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
        if payload_match && !at_exe {
            payload_bound = true;
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

    if payload_bound {
        // A payload-bound entrypoint makes this an interpreted launch:
        // the resolved executable is an interpreter reading a pinned
        // script. It needs its own `binary-hash` — an entrypoint-only
        // policy would execute an unpinned interpreter while the pin
        // list looks satisfied.
        if !matched_binary {
            let mut evt = AuditEvent::new(
                Uuid::now_v7(),
                EventType::HashMismatch,
                Severity::Critical,
                Outcome::Failure,
                Action::Denied,
            );
            evt.details = Some(format!(
                "launched interpreter '{}' has no binary-hash pin",
                resolved_exe.display()
            ));
            audit_logger.log(evt);
            return Err(VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason: "an entrypoint-hash pins the payload script, but no \
                         binary-hash binds the resolved interpreter — the \
                         launched image would execute unpinned"
                    .into(),
            });
        }
        // The payload boundary is only proven under a modeled option
        // grammar. A copied or hard-linked interpreter under an
        // unmodeled name reads a code-bearing flag where the generic
        // scan skipped an option, so the pinned script becomes a decoy
        // for code that actually runs — fail closed instead.
        if !crate::workload::exe_grammar_modeled(argv, Some(resolved_exe)) {
            return Err(VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason: "an entrypoint-hash pins the payload script, but the \
                         resolved executable has no modeled option grammar — \
                         the payload boundary cannot be proven for a renamed \
                         or unmodeled interpreter"
                    .into(),
            });
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
///
/// On Unix the pin also mints [`FdExecPlan`]: the spawn executes the
/// pinned object's snapshot — through an inherited `/proc/self/fd`
/// descriptor on Linux, through the staged copy's path in its
/// owner-only directory on the other Unixes — so the kernel maps the
/// pinned object itself and the pathname-to-exec race is closed, not
/// merely narrowed. Linux dups stay `CLOEXEC` in the parent; each
/// spawn path clears the flag inside its own `pre_exec`.
pub struct SpawnPin {
    exe: std::fs::File,
    exe_stamp: OpenStamp,
    /// The digest the exe's bytes hashed to under the held handle —
    /// [`fd_exec_plan`] re-hashes its sealed snapshot against this so
    /// an in-place rewrite between hashing and snapshotting fails
    /// closed instead of launching unverified bytes.
    #[cfg_attr(not(unix), allow(dead_code))]
    exe_digest: String,
    entrypoint: Option<PinnedEntry>,
}

#[cfg(test)]
impl SpawnPin {
    /// A bare executable-only pin for tests — production pins are minted
    /// exclusively by `reverify_immediately_before_spawn`.
    pub(crate) fn for_test(mut exe: std::fs::File) -> Self {
        Self {
            exe_stamp: record_stamp(&exe).expect("record stamp"),
            exe_digest: hash_open_file(&mut exe).expect("hash test exe"),
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
    /// The digest the script hashed to under the held handle.
    digest: String,
}

impl SpawnPin {
    /// The last identity check before the spawn opens the pathname —
    /// proves the path still resolves to the held (verified) object and
    /// that the object itself is unchanged since hashing. On Windows
    /// the held share mode already makes a swap fail; this also
    /// catches the Unix cases where a rename retargeted the path or a
    /// writer rewrote the pinned object between reverify and spawn.
    /// Exec itself no longer trusts the workload's pathname:
    /// `fd_exec_plan` names the pinned snapshot (descriptor spelling
    /// on Linux, staged path elsewhere), so this check pins the
    /// *decision* while the snapshot pins the *object* — keep this
    /// call ordered last before the spawn.
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

    /// The exec plan for this pin (Unix): every pinned object is
    /// snapshotted into an immutable object — a sealed memfd on Linux,
    /// an owner-only staged file elsewhere — whose bytes are re-hashed
    /// against the recorded digest. On Linux the exec target is the
    /// descriptor duplicated *with* `CLOEXEC` (`F_DUPFD_CLOEXEC`) and
    /// named through `/proc/self/fd`: the spawn clears `FD_CLOEXEC`
    /// inside the child's `pre_exec` so the descriptor survives that
    /// child's exec — and no concurrent sibling spawn can inherit it.
    /// Exec'ing the fd spelling makes the kernel map the held object
    /// itself: a pathname swap between verification and `execve` cannot
    /// reach the image or the pinned entrypoint, which is exactly the
    /// residual window `verify_spawn_path` can only narrow on a
    /// pathname exec.
    ///
    /// Non-Linux Unix has no exec'able fd spelling (`/dev/fd/N` cannot
    /// be `execve`'d on macOS), so the plan names the staged copy's
    /// path in its fresh owner-only directory — the same staged-object
    /// exec Windows performs for pinned entrypoints. The plan must
    /// stay alive until the child has exec'd: `snapshot_dirs` removal
    /// while a forked child sits between `pre_exec` and `execve` would
    /// unbind the target, so the launch paths keep the plan for the
    /// session rather than dropping it at `spawn()` return.
    ///
    /// Fail-closed: returns `Err` when a snapshot cannot be staged or a
    /// descriptor cannot be duplicated — the caller must not fall back
    /// to exec'ing the unresolved workload pathname after a pin was
    /// required.
    #[cfg(unix)]
    pub fn fd_exec_plan(
        &self,
        argv: &[String],
        resolved_exe: &Path,
    ) -> Result<FdExecPlan, VerifyError> {
        // A held fd still names the mutable inode on Unix, so without
        // the snapshot an in-place rewrite between verify and exec
        // could map unverified bytes; hashing the sealed/staged copy
        // proves the exec maps exactly the verified bytes.
        let mut snapshot_dirs: Vec<PathBuf> = Vec::new();
        let mut fd_target = |file: &std::fs::File,
                             digest: &str,
                             hash_type: HashType,
                             label: &str|
         -> Result<(PathBuf, Option<std::fs::File>), VerifyError> {
            let (snap, staging) = immutable_snapshot(file, digest, hash_type, label)?;
            // Linux execs the sealed memfd through an inherited
            // descriptor spelled `/proc/self/fd/N`. Other Unixes have
            // `/dev/fd` but cannot `execve` it (macOS devfs fd entries
            // are not exec'able vnodes), so they name the staged file's
            // path in its fresh owner-only directory instead — the same
            // staged-object exec Windows performs for pinned
            // entrypoints.
            if cfg!(target_os = "linux") {
                use std::os::unix::io::AsRawFd;
                let dir = fd_dir().ok_or_else(|| VerifyError::UnboundWorkload {
                    executable: resolved_exe.display().to_string(),
                    reason: "fd-based exec needs /proc/self/fd; /proc is absent".into(),
                })?;
                let dup = dup_inheritable(&snap).map_err(|error| VerifyError::FileError {
                    hash_type,
                    target: resolved_exe.display().to_string(),
                    error,
                })?;
                return Ok((
                    PathBuf::from(format!("{dir}/{}", dup.as_raw_fd())),
                    Some(dup),
                ));
            }
            let (snap_dir, object) = staging.ok_or(VerifyError::FileError {
                hash_type,
                target: resolved_exe.display().to_string(),
                error: io::Error::other("snapshot did not produce a staged path"),
            })?;
            snapshot_dirs.push(snap_dir);
            drop(snap);
            Ok((object, None))
        };
        let (exe_path, exe_held) =
            fd_target(&self.exe, &self.exe_digest, HashType::Binary, "executable")?;
        let mut held: Vec<std::fs::File> = exe_held.into_iter().collect();
        let entrypoint = match &self.entrypoint {
            Some(entry) => {
                // The argv position whose spelling resolved to the
                // pinned script — `exec_argv` rewrites it to the
                // pinned-object spelling so the interpreter opens the
                // verified bytes.
                let index = first_payload_arg_index_with_exe(argv, Some(resolved_exe)).ok_or_else(
                    || VerifyError::UnboundWorkload {
                        executable: resolved_exe.display().to_string(),
                        reason: "entrypoint pinned but the payload argv position is lost".into(),
                    },
                )?;
                let (path, entry_held) = fd_target(
                    &entry.file,
                    &entry.digest,
                    HashType::Entrypoint,
                    "entrypoint",
                )?;
                held.extend(entry_held);
                Some((index, path))
            }
            None => None,
        };
        Ok(FdExecPlan {
            exe_path,
            entrypoint,
            _held: held,
            snapshot_dirs,
        })
    }
}

/// Copy the bytes `file` names into an object a local writer cannot
/// modify, then prove the copy still hashes to `expected` — a source
/// rewritten between the earlier verification and this snapshot
/// produces a digest mismatch and the launch fails closed. The staged
/// object, not the original pathname, is what the child execs.
///
/// Linux uses a `memfd` sealed `WRITE|GROW|SHRINK|SEAL` — no principal,
/// not even this process, can change the bytes afterwards. Other Unix
/// targets stage into a fresh owner-only directory (a lower-trust
/// writer cannot reach inside) and keep the staged file open.
///
/// Returns `(snapshot, staging)` — `staging` is `Some((dir, object))`
/// only on the private-file path: the dir must outlive the child's
/// exec, and `object` is the exec/read spelling the plan hands to the
/// spawn on platforms without an exec'able fd directory.
#[cfg(unix)]
fn immutable_snapshot(
    file: &std::fs::File,
    expected: &str,
    hash_type: HashType,
    label: &str,
) -> Result<(std::fs::File, Option<(PathBuf, PathBuf)>), VerifyError> {
    let file_error = |error: io::Error| VerifyError::FileError {
        hash_type,
        target: label.to_string(),
        error,
    };
    let (mut snap, staging) = snapshot_object(file, label).map_err(file_error)?;
    let actual = hash_open_file(&mut snap).map_err(file_error)?;
    if actual != expected {
        return Err(VerifyError::Mismatch {
            hash_type,
            target: label.to_string(),
            expected: expected.to_string(),
            actual,
        });
    }
    Ok((snap, staging))
}

/// The Linux snapshot: a private `memfd` sealed against every write —
/// the object `/proc/self/fd/N` execs cannot change afterwards.
#[cfg(target_os = "linux")]
fn snapshot_object(
    file: &std::fs::File,
    label: &str,
) -> io::Result<(std::fs::File, Option<(PathBuf, PathBuf)>)> {
    use std::io::{Seek, Write};
    use std::os::unix::io::FromRawFd;

    const MFD_ALLOW_SEALING: u32 = 0x0002;
    let name = std::ffi::CString::new(format!("mcp-writ-{label}")).map_err(io::Error::other)?;
    let fd =
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), MFD_ALLOW_SEALING) as i32 };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut snap = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut source = file.try_clone()?;
    source.seek(io::SeekFrom::Start(0))?;
    io::copy(&mut source, &mut snap)?;
    snap.flush()?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((snap, None))
}

/// Non-Linux Unix has no sealed exec object and cannot exec an fd
/// spelling (`/dev/fd/N` is not an exec'able vnode on macOS): stage the
/// bytes into a fresh owner-only directory so a lower-trust principal
/// cannot reach the staged copy, and return its path — the child execs
/// the staged path itself, so the dir must outlive the child's exec
/// (the plan is held for the session, like the Windows staging pin).
#[cfg(all(unix, not(target_os = "linux")))]
fn snapshot_object(
    file: &std::fs::File,
    label: &str,
) -> io::Result<(std::fs::File, Option<(PathBuf, PathBuf)>)> {
    use std::io::{Seek, Write};

    let dir = crate::fspriv::create_private_tempdir("exec-snapshot")?;
    let path = dir.join("object");
    let staging = (|| -> io::Result<()> {
        let mut source = file.try_clone()?;
        source.seek(io::SeekFrom::Start(0))?;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        io::copy(&mut source, &mut out)?;
        out.flush()?;
        out.sync_all()?;
        use std::os::unix::fs::PermissionsExt;
        // The "executable" snapshot is exec'd through its path — it
        // needs the owner execute bit; the "entrypoint" snapshot is
        // only ever read, so it stays read-only.
        let mode = if label == "executable" { 0o500 } else { 0o400 };
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))?;
        Ok(())
    })();
    if staging.is_err() {
        let _ = std::fs::remove_dir_all(&dir);
    }
    staging?;
    let snap = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    Ok((snap, Some((dir, path))))
}

/// The Windows entrypoint binding: the interpreter opens its script by
/// pathname *after* process creation, so the held pin must outlive that
/// open — dropping it at spawn-return reopens the replace window. An
/// authenticated handshake does not exist for arbitrary payloads, so
/// the verified bytes are staged into a fresh owner-only directory and
/// the staged copy itself is held under the read-only share mode for
/// the whole session: the path the interpreter opens names bytes that
/// cannot be rewritten, renamed, or deleted while the pin lives.
/// `argv`'s payload argument is rewritten to the staged spelling.
#[cfg(windows)]
pub struct StagedEntrypoint {
    /// `argv` with the pinned payload arg replaced by the staged path.
    pub argv: Vec<String>,
    /// Held open with `FILE_SHARE_READ` only — the staged object cannot
    /// be modified or replaced while the session runs.
    _pinned: std::fs::File,
    /// Owner-only staging dir, removed when the session ends.
    dir: PathBuf,
}

#[cfg(windows)]
impl Drop for StagedEntrypoint {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(windows)]
impl SpawnPin {
    /// `Some` when the pin carries a payload-matched entrypoint script:
    /// stage its verified bytes and return the rewritten argv. The
    /// staged object is re-hashed against the recorded digest so a
    /// staged copy that diverged fails closed.
    pub fn stage_entrypoint_copy(
        &self,
        argv: &[String],
        resolved_exe: &Path,
    ) -> Result<Option<StagedEntrypoint>, VerifyError> {
        use std::io::{Seek, Write};

        let Some(entry) = &self.entrypoint else {
            return Ok(None);
        };
        let index =
            first_payload_arg_index_with_exe(argv, Some(resolved_exe)).ok_or_else(|| {
                VerifyError::UnboundWorkload {
                    executable: resolved_exe.display().to_string(),
                    reason: "entrypoint pinned but the payload argv position is lost".into(),
                }
            })?;
        let file_error = |error: io::Error| VerifyError::FileError {
            hash_type: HashType::Entrypoint,
            target: entry.path.display().to_string(),
            error,
        };
        let dir = crate::fspriv::create_private_tempdir("entrypoint").map_err(file_error)?;
        let name = entry
            .path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .filter(|n| !n.contains(['/', '\\', ':']))
            .unwrap_or_else(|| "payload".to_string());
        let staged_path = dir.join(name);
        let staged = (|| -> io::Result<()> {
            let mut source = entry.file.try_clone()?;
            source.seek(io::SeekFrom::Start(0))?;
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged_path)?;
            io::copy(&mut source, &mut out)?;
            out.flush()?;
            out.sync_all()?;
            Ok(())
        })();
        if let Err(error) = staged {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(file_error(error));
        }
        // Pin the staged copy — read-sharing only — and prove its bytes
        // are the verified bytes before argv points at it.
        let pinned = match open_pinned(&staged_path) {
            Ok(f) => f,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&dir);
                return Err(file_error(error));
            }
        };
        let mut check = pinned.try_clone().map_err(file_error)?;
        let actual = hash_open_file(&mut check).map_err(file_error)?;
        if actual != entry.digest {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(VerifyError::Mismatch {
                hash_type: HashType::Entrypoint,
                target: staged_path.display().to_string(),
                expected: entry.digest.clone(),
                actual,
            });
        }
        let mut rewritten = argv.to_vec();
        rewritten[index] = staged_path.display().to_string();
        Ok(Some(StagedEntrypoint {
            argv: rewritten,
            _pinned: pinned,
            dir,
        }))
    }
}

/// The exec spellings for a pinned launch (Unix): descriptor paths the
/// child's `pre_exec` uncloaks. Holds the duplicated `CLOEXEC` handles —
/// the plan must outlive the `Command::spawn` call it feeds.
#[cfg(unix)]
pub struct FdExecPlan {
    /// The exec spelling for the pinned executable's immutable
    /// snapshot: `/proc/self/fd/N` on Linux, the staged file's path in
    /// its owner-only directory on other Unixes.
    exe_path: PathBuf,
    /// `(argv index, spelling)` for the pinned entrypoint script's
    /// immutable snapshot — fd path on Linux, staged path elsewhere.
    entrypoint: Option<(usize, PathBuf)>,
    /// The duplicated `CLOEXEC` handles keeping the fd spellings
    /// resolvable until the child uncloaks and inherits them (Linux
    /// only — a path-spelled exec holds no descriptors).
    _held: Vec<std::fs::File>,
    /// Owner-only staging directories holding non-memfd snapshots.
    /// On Linux removal after `spawn()` returns is safe — the inherited
    /// fds name the objects, not the paths. On fd-exec-less Unix the
    /// path *is* the exec spelling, so the plan must stay alive until
    /// the child has exec'd — callers keep it for the session.
    snapshot_dirs: Vec<PathBuf>,
}

#[cfg(unix)]
impl Drop for FdExecPlan {
    fn drop(&mut self) {
        for dir in &self.snapshot_dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

#[cfg(unix)]
impl FdExecPlan {
    /// Exec spelling for the pinned executable — pass to
    /// `Command::new`/`spawn_*_exe` in place of the resolved path.
    pub fn exe_path(&self) -> &Path {
        &self.exe_path
    }

    /// `argv` with the pinned entrypoint's payload spelling replaced by
    /// its snapshot spelling (fd path on Linux, staged path elsewhere).
    /// `argv[0]` is untouched — the child still reads the caller's
    /// spelling (a venv `bin/python` keeps locating `pyvenv.cfg`).
    pub fn exec_argv(&self, argv: &[String]) -> Vec<String> {
        let mut out = argv.to_vec();
        if let Some((index, path)) = &self.entrypoint
            && let Some(arg) = out.get_mut(*index)
        {
            *arg = path.display().to_string();
        }
        out
    }

    /// Owner-only directories holding staged snapshots — the paths an
    /// exec/read spelling resolves through on fd-exec-less Unix. A
    /// sandboxed child needs the profile to grant read+exec on these
    /// (`SpawnOptions::exec_map_dirs`); empty on Linux where the
    /// spelling is a descriptor.
    pub fn staged_dirs(&self) -> &[PathBuf] {
        &self.snapshot_dirs
    }

    /// The duplicated descriptor numbers (Linux fd-exec only — empty
    /// where the exec spelling is a staged path). They carry
    /// `FD_CLOEXEC` (see `dup_inheritable`) — the spawn must clear the
    /// flag inside the child's `pre_exec`, never in the parent, so
    /// concurrent sibling spawns cannot inherit the pinned objects.
    pub fn uncloak_fds(&self) -> Vec<std::os::fd::RawFd> {
        use std::os::unix::io::AsRawFd;
        self._held.iter().map(|f| f.as_raw_fd()).collect()
    }
}

/// The fd-symlink directory an fd-exec spelling resolves through:
/// `/proc/self/fd` on Linux (the only Unix whose fd directory can be
/// `execve`'d — macOS/*BSD `/dev/fd` entries are devfs nodes that fail
/// `EACCES`/`EBADF` on exec, so non-Linux plans spell the staged path).
#[cfg(unix)]
fn fd_dir() -> Option<&'static str> {
    ["/proc/self/fd", "/dev/fd"]
        .into_iter()
        .find(|dir| Path::new(dir).is_dir())
}

/// Duplicate `file` onto a descriptor *with* `FD_CLOEXEC`
/// (`F_DUPFD_CLOEXEC`), so an unrelated child spawned concurrently
/// cannot inherit the pin. Each spawn path clears the flag inside its
/// own `pre_exec` — only the target child keeps the descriptor through
/// exec, where it execs through `/proc/self/fd/<n>`. The minimum fd is
/// 3 so a dup can never clobber stdio in the child.
#[cfg(unix)]
fn dup_inheritable(file: &std::fs::File) -> io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};

    // Safety: F_DUPFD_CLOEXEC copies the descriptor and sets FD_CLOEXEC
    // on the copy; the returned fd is owned and wrapped immediately.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

/// Re-run the binding checks immediately before spawn — the launched
/// executable and any payload-matched entrypoint script are re-hashed
/// once more, so a file swapped in after the initial verification fails
/// closed.
///
/// The returned [`SpawnPin`] keeps the verified objects open through
/// the spawn: on Windows the share mode makes modification/rename fail
/// while held, closing the hash-to-exec window; on Unix the spawn
/// execs through [`SpawnPin::fd_exec_plan`] — the hash-verified
/// snapshot itself (`/proc/self/fd` descriptor spelling on Linux,
/// staged owner-only copy elsewhere) — so the kernel maps the held
/// object and no workload-pathname lookup can resolve unverified bytes.
/// `verify_spawn_path`'s identity re-check still runs last so a
/// retargeted path fails the launch rather than silently mismatching
/// `argv`'s own resolution. Code the workload loads at run time stays
/// unpinned.
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
            digest: held,
        });
    }

    Ok(SpawnPin {
        exe: exe_file,
        exe_stamp,
        exe_digest: held_exe,
        entrypoint,
    })
}
