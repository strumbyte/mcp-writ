//! The Unix exec plan for a pinned launch: the executable snapshots
//! its pinned bytes into an immutable object — a sealed memfd spelled
//! `/proc/self/fd/N` on Linux, an owner-only staged copy elsewhere —
//! while a payload-bound entrypoint script keeps its real path so the
//! interpreter's module resolution still works.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::policy::HashType;
use crate::verifier::hash::{VerifyError, format_sha256};

use super::spawn::SpawnPin;

impl SpawnPin {
    /// The exec plan for this pin (Unix): the *executable* — under a
    /// pin always the image the kernel maps, never a script payload —
    /// is snapshotted into an immutable object, a sealed memfd on
    /// Linux or an owner-only staged file elsewhere, whose bytes are
    /// re-hashed against the recorded digest. On Linux the exec target
    /// is the descriptor duplicated *with* `CLOEXEC`
    /// (`F_DUPFD_CLOEXEC`) and named through `/proc/self/fd`: the
    /// spawn clears `FD_CLOEXEC` inside the child's `pre_exec` so the
    /// descriptor survives that child's exec — and no concurrent
    /// sibling spawn can inherit it. Exec'ing the fd spelling makes
    /// the kernel map the held object itself: a pathname swap between
    /// verification and `execve` cannot reach the image, which is
    /// exactly the residual window `verify_spawn_path` can only narrow
    /// on a pathname exec.
    ///
    /// A payload-bound *entrypoint script* is deliberately NOT routed
    /// through the snapshot: it launches through its real path. An
    /// interpreter opens its main module by name, realpaths it, and
    /// resolves sibling and relative imports (and Node's
    /// `node_modules` ancestor walk) from that directory — the
    /// `/proc/self/fd/N` spelling realpaths to `/memfd:… (deleted)`
    /// and fails outright; a staged copy in an empty owner-only
    /// directory has no siblings either. The script's exec-time
    /// guarantee is the pin itself: `verify_spawn_path`'s
    /// same-object + stamp re-check is the last gate before the
    /// spawn, and the residual — the interpreter's `open(2)` after
    /// process creation — is closed by the trust contract
    /// `reverify_immediately_before_spawn` requires of the script's
    /// path: owner/root-owned without group/other write, over
    /// write-restricted ancestors, so no lower-trust principal can
    /// swap the path nor rewrite the object in that window (the same
    /// contract a policy source stands under — see
    /// `fspriv::require_trusted_source_file`). The Linux namespaced
    /// route needs no permission argument at all: init re-hashes the
    /// pinned object and mounts a verified copy over the script's
    /// path inside its mount namespace, so the spelling resolves to
    /// the pinned content whatever the host pathname later names. On
    /// Windows the session-held share-mode pin also makes the object
    /// at that path unswappable.
    ///
    /// Non-Linux Unix has no exec'able fd spelling (`/dev/fd/N` cannot
    /// be `execve`'d on macOS), so the exe plan names the staged
    /// copy's path in its fresh owner-only directory. The plan must
    /// stay alive until the child has exec'd: `snapshot_dirs` removal
    /// while a forked child sits between `pre_exec` and `execve` would
    /// unbind the target, so the launch paths keep the plan for the
    /// session rather than dropping it at `spawn()` return.
    ///
    /// Fail-closed: returns `Err` when a snapshot cannot be staged or a
    /// descriptor cannot be duplicated — the caller must not fall back
    /// to exec'ing the unresolved workload pathname after a pin was
    /// required.
    pub fn fd_exec_plan(
        &self,
        argv: &[String],
        resolved_exe: &Path,
    ) -> Result<FdExecPlan, VerifyError> {
        // A held fd still names the mutable inode on Unix, so without
        // the snapshot an in-place rewrite between verify and exec
        // could map unverified bytes; hashing the sealed/staged copy
        // proves the exec maps exactly the verified bytes.
        let (snap, staging) =
            immutable_snapshot(&self.exe, &self.exe_digest, HashType::Binary, "executable")?;
        let mut snapshot_dirs: Vec<PathBuf> = Vec::new();
        // Linux execs the sealed memfd through an inherited descriptor
        // spelled `/proc/self/fd/N`. Other Unixes have `/dev/fd` but
        // cannot `execve` it (macOS devfs fd entries are not exec'able
        // vnodes), so they name the staged file's path in its fresh
        // owner-only directory instead.
        let (exe_path, exe_held) = if cfg!(target_os = "linux") {
            use std::os::unix::io::AsRawFd;
            let dir = fd_dir().ok_or_else(|| VerifyError::UnboundWorkload {
                executable: resolved_exe.display().to_string(),
                reason: "fd-based exec needs /proc/self/fd; /proc is absent".into(),
            })?;
            let dup = dup_inheritable(&snap).map_err(|error| VerifyError::FileError {
                hash_type: HashType::Binary,
                target: resolved_exe.display().to_string(),
                error,
            })?;
            (
                PathBuf::from(format!("{dir}/{}", dup.as_raw_fd())),
                vec![dup],
            )
        } else {
            let (snap_dir, object) = staging.ok_or(VerifyError::FileError {
                hash_type: HashType::Binary,
                target: resolved_exe.display().to_string(),
                error: io::Error::other("snapshot did not produce a staged path"),
            })?;
            snapshot_dirs.push(snap_dir);
            drop(snap);
            (object, Vec::new())
        };
        // The pinned entrypoint keeps its real path — see the doc
        // above. `exec_argv` re-spells the payload argv position to the
        // resolved path so the spawned interpreter opens the object
        // `verify_spawn_path` re-checked, not a relocated snapshot it
        // cannot resolve from.
        let entrypoint = self.entrypoint_exec_arg(argv, resolved_exe)?;
        // On Linux a CLOEXEC dup of the entrypoint's pin also rides
        // the plan: the namespaced init re-hashes the bytes it reads
        // through this descriptor and mounts the verified copy over
        // the payload path inside its mount namespace — the real-path
        // spelling stays while the content behind it is anchored to
        // the pinned object, closing the verify→exec window a
        // pathname launch can otherwise only narrow. It is kept
        // separate from the exe's `_held` list so a non-namespaced
        // spawn never uncloaks it; other Unixes have no consumer.
        let entrypoint_fd = if cfg!(target_os = "linux") {
            match &self.entrypoint {
                Some(e) => {
                    Some(
                        dup_inheritable(&e.file).map_err(|error| VerifyError::FileError {
                            hash_type: HashType::Entrypoint,
                            target: e.path.display().to_string(),
                            error,
                        })?,
                    )
                }
                None => None,
            }
        } else {
            None
        };
        Ok(FdExecPlan {
            exe_path,
            entrypoint,
            entrypoint_digest: self.entrypoint.as_ref().map(|e| e.digest.clone()),
            entrypoint_fd,
            _held: exe_held,
            snapshot_dirs,
        })
    }
}

/// Copy the bytes `file` names into an object a local writer cannot
/// modify, hashing the stream as it is copied — one read produces both
/// the staged object and its digest, and a source rewritten between
/// the earlier verification and this snapshot produces a digest
/// mismatch that fails the launch closed. The staged object, not the
/// original pathname, is what the child execs. Only the *executable*
/// rides this path — a payload-bound entrypoint is an interpreted
/// script, and the interpreter must see its real path.
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
    // The digest rides out of the copy — the bytes the child will exec
    // hashed `expected` at the moment they were written, so no second
    // read of the staged object is needed to say so.
    let (snap, staging, actual) = snapshot_object(file, label).map_err(file_error)?;
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

/// Copy `source`'s bytes into `dest`, hashing the stream as it passes —
/// one traversal produces both the staged object and the digest proving
/// the bytes copied are the pinned ones. `source` is a clone of the
/// held pin rewound to offset zero, so the held handle's own position
/// stays intact.
fn copy_and_hash(source: &mut std::fs::File, dest: &mut std::fs::File) -> io::Result<String> {
    use std::io::{Read, Write};

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        dest.write_all(&buffer[..n])?;
    }
    Ok(format_sha256(hasher.finalize()))
}

/// The staged snapshot: `(open snapshot file, staging, digest)` —
/// `staging` is `Some((dir, object))` only on the private-file path,
/// and `digest` is computed in [`copy_and_hash`] while the bytes are
/// copied.
type SnapshotObject = (std::fs::File, Option<(PathBuf, PathBuf)>, String);

/// The Linux snapshot: a private `memfd` sealed against every write —
/// the object `/proc/self/fd/N` execs cannot change afterwards.
#[cfg(target_os = "linux")]
fn snapshot_object(
    file: &std::fs::File,
    label: &str,
) -> io::Result<SnapshotObject> {
    use std::io::{Seek, Write};
    use std::os::unix::io::FromRawFd;

    const MFD_CLOEXEC: u32 = 0x0001;
    const MFD_ALLOW_SEALING: u32 = 0x0002;
    let name = std::ffi::CString::new(format!("mcp-writ-{label}")).map_err(io::Error::other)?;
    // Born close-on-exec: the exec target is the `dup_inheritable`
    // copy, so the sealed original stays out of unrelated children.
    let fd =
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                name.as_ptr(),
                MFD_CLOEXEC | MFD_ALLOW_SEALING,
            ) as i32
        };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let mut snap = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut source = file.try_clone()?;
    source.seek(io::SeekFrom::Start(0))?;
    let digest = copy_and_hash(&mut source, &mut snap)?;
    snap.flush()?;
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((snap, None, digest))
}

/// Non-Linux Unix has no sealed exec object and cannot exec an fd
/// spelling (`/dev/fd/N` is not an exec'able vnode on macOS): stage the
/// bytes into a fresh owner-only directory so a lower-trust principal
/// cannot reach the staged copy, and return its path — the child execs
/// the staged path itself, so the dir must outlive the child's exec
/// (the plan is held for the session).
#[cfg(all(unix, not(target_os = "linux")))]
fn snapshot_object(file: &std::fs::File, _label: &str) -> io::Result<SnapshotObject> {
    use std::io::{Seek, Write};

    let dir = crate::fspriv::create_private_tempdir("exec-snapshot")?;
    let path = dir.join("object");
    let staging = (|| -> io::Result<String> {
        let mut source = file.try_clone()?;
        source.seek(io::SeekFrom::Start(0))?;
        let mut out = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let digest = copy_and_hash(&mut source, &mut out)?;
        out.flush()?;
        out.sync_all()?;
        use std::os::unix::fs::PermissionsExt;
        // Only the executable snapshot is staged — it is exec'd through
        // its path, so it needs the owner execute bit. A payload-bound
        // entrypoint never comes through here: it launches by its real
        // path so the interpreter's module resolution keeps working.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500))?;
        Ok(digest)
    })();
    let digest = match staging {
        Ok(digest) => digest,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    let snap = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
    };
    Ok((snap, Some((dir, path)), digest))
}

/// The exec spellings for a pinned launch (Unix): the descriptor path
/// the child's `pre_exec` uncloaks for the executable snapshot, plus
/// the real path a pinned entrypoint script launches through. Holds
/// the duplicated `CLOEXEC` handles — the plan must outlive the
/// `Command::spawn` call it feeds.
pub struct FdExecPlan {
    /// The exec spelling for the pinned executable's immutable
    /// snapshot: `/proc/self/fd/N` on Linux, the staged file's path in
    /// its owner-only directory on other Unixes.
    exe_path: PathBuf,
    /// `(argv index, real path)` for the pinned entrypoint script —
    /// the script launches through its own resolved path so the
    /// interpreter's realpath and sibling/relative-import resolution
    /// keep working; the pin's `verify_spawn_path` re-check (run last
    /// before the spawn) is its exec-time guarantee.
    entrypoint: Option<(usize, PathBuf)>,
    /// The pinned entrypoint's `sha256:<hex>` — init's in-namespace
    /// re-hash of the fd's bytes must match before the staged copy is
    /// mounted (Linux only; travels the same env handoff as the fd).
    entrypoint_digest: Option<String>,
    /// CLOEXEC dup of the pinned entrypoint's file for the namespaced
    /// handoff (Linux only — `None` on other Unixes and when no
    /// entrypoint is pinned). Init reads the pinned object through
    /// this descriptor — the inode the parent verified, never the
    /// path — stages the bytes under the namespace's own tmpfs, and
    /// mounts the staged copy over the payload path (a direct
    /// `/proc/self/fd` bind cannot cross mount namespaces: the fd's
    /// vfsmount belongs to the parent's mount table). The descriptor
    /// number travels by env, not `uncloak_fds`, because only the
    /// init spawn uncloaks it — every other spawn path must leave the
    /// flag alone.
    entrypoint_fd: Option<std::fs::File>,
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

impl Drop for FdExecPlan {
    fn drop(&mut self) {
        for dir in &self.snapshot_dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

impl FdExecPlan {
    /// Exec spelling for the pinned executable — pass to
    /// `Command::new`/`spawn_*_exe` in place of the resolved path.
    pub fn exe_path(&self) -> &Path {
        &self.exe_path
    }

    /// `argv` with the pinned entrypoint's payload spelling replaced by
    /// its resolved real path — the script launches through the object
    /// `verify_spawn_path` re-checked, never a snapshot spelling an
    /// interpreter could not resolve from. `argv[0]` is untouched — the
    /// child still reads the spelling the expanded argv heads with (the
    /// caller's `argv[0]`, or the interpreter token a `#!` expansion
    /// puts there; a venv `bin/python` keeps locating `pyvenv.cfg`). The
    /// caller's script spelling is preserved at the payload position
    /// only when no entrypoint pin binds it — a pinned script's own
    /// argument is the resolved real path, not the caller's spelling.
    pub fn exec_argv(&self, argv: &[String]) -> Vec<String> {
        let mut out = argv.to_vec();
        if let Some((index, path)) = &self.entrypoint
            && let Some(arg) = out.get_mut(*index)
        {
            *arg = path.display().to_string();
        }
        out
    }

    /// The exec method the plan gives the pinned *executable*, for the
    /// audit record: `fd` (Linux — a sealed memfd spelled
    /// `/proc/self/fd/N`) or `staged` (other Unix — the snapshot copy
    /// in its owner-only directory).
    pub fn exe_exec_mode(&self) -> &'static str {
        if cfg!(target_os = "linux") {
            "fd"
        } else {
            "staged"
        }
    }

    /// `Some("path")` when a payload-bound entrypoint rides this plan —
    /// the interpreter opens the verified script's real path because a
    /// snapshot spelling cannot carry module resolution. `None` when
    /// no entrypoint was pinned.
    pub fn entrypoint_exec_mode(&self) -> Option<&'static str> {
        self.entrypoint.as_ref().map(|_| "path")
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
    /// The entrypoint's bind-mount dup is deliberately absent: only
    /// the namespaced init spawn uncloaks it.
    pub fn uncloak_fds(&self) -> Vec<std::os::fd::RawFd> {
        use std::os::unix::io::AsRawFd;
        self._held.iter().map(|f| f.as_raw_fd()).collect()
    }

    /// `(fd, real path, sha256)` for the namespaced entrypoint
    /// handoff — `Some` only on Linux with a payload-bound pin. Init
    /// reads the pinned object through the descriptor (never the
    /// path), re-hashes it against `sha256`, and mounts the verified
    /// bytes read-only over the path inside its mount namespace: the
    /// interpreter's open then reaches the pinned content even if a
    /// host-side swap retargeted the pathname — or rewrote the object
    /// — after `verify_spawn_path`. Other routes ignore this — their
    /// pathname exec keeps the re-check guarantee.
    pub fn entrypoint_bind_pin(&self) -> Option<(std::os::fd::RawFd, &Path, &str)> {
        let fd = self.entrypoint_fd.as_ref()?;
        let (_, path) = self.entrypoint.as_ref()?;
        let digest = self.entrypoint_digest.as_deref()?;
        use std::os::unix::io::AsRawFd;
        Some((fd.as_raw_fd(), path.as_path(), digest))
    }
}

/// The fd-symlink directory an fd-exec spelling resolves through:
/// `/proc/self/fd` on Linux (the only Unix whose fd directory can be
/// `execve`'d — macOS/*BSD `/dev/fd` entries are devfs nodes that fail
/// `EACCES`/`EBADF` on exec, so non-Linux plans spell the staged path).
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
