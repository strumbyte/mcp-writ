//! One-time trusted resolution of isolation drivers and OS helpers.
//!
//! An executable that prepares or attests a sandbox boundary must
//! never be reached through caller-mutable search order or a relative
//! spelling: a substituted binary would run with the launcher's full
//! host authority *before* any containment exists. Resolution here is
//! therefore once-only, validated, and *bound* — the validated object
//! is pinned by file identity at resolve time and re-verified
//! immediately before every spawn, so a binary replaced after
//! validation fails closed instead of running with launcher
//! privileges.
//!
//! Two provenance classes apply:
//!
//! - **`Admin`** (the default): every component of the resolved path
//!   may be replaced only by an administrator principal — on Unix a
//!   root-owned entry writable by neither group nor other; on Windows
//!   an object owned by SYSTEM/Administrators/TrustedInstaller whose
//!   DACL hands dangerous rights to no other trustee — so a
//!   caller-managed `PATH` entry can never supply the driver.
//! - **`Caller`**: the pre-hardening class — the caller's own files and
//!   sticky-protected shared dirs count as trusted. It applies only to
//!   explicit fixture overrides (`MCP_WRIT_*_EXE`) and to the unsafe
//!   `MCP_WRIT_ALLOW_REPLACEABLE_DRIVERS=1` development opt-out; it is
//!   never the PATH default.

use std::path::{Path, PathBuf};

/// Unsafe development opt-out: `MCP_WRIT_ALLOW_REPLACEABLE_DRIVERS=1`
/// downgrades driver resolution to the `Caller` class — a driver found
/// in a caller-managed `PATH` entry then validates. It exists for
/// test rigs and developer installs that intentionally run engines
/// from user-owned prefixes; a production launch must never set it,
/// since it re-opens exactly the pre-containment substitution this
/// module exists to close.
pub const ALLOW_REPLACEABLE_DRIVERS_ENV: &str = "MCP_WRIT_ALLOW_REPLACEABLE_DRIVERS";

/// Which principals may control a resolved driver's bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DriverTrust {
    /// Administrator-only provenance — the production default.
    Admin,
    /// Caller-manageable provenance — explicit fixture overrides and
    /// the unsafe [`ALLOW_REPLACEABLE_DRIVERS_ENV`] opt-out only.
    Caller,
}

impl DriverTrust {
    /// Whether the invoking user itself counts as a trusted principal —
    /// only the Windows ACL walk consumes it (the Unix walk matches on
    /// `self` directly).
    #[cfg(windows)]
    pub(crate) fn caller_ok(self) -> bool {
        matches!(self, DriverTrust::Caller)
    }
}

/// The provenance class for a driver resolution: `Caller` when an
/// explicit `override_env` is set (a fixture spelling names a path the
/// caller already controls) or the unsafe opt-out is armed; `Admin`
/// otherwise.
pub(crate) fn driver_trust(override_env: Option<&str>) -> DriverTrust {
    let caller = override_env.is_some_and(|e| std::env::var_os(e).is_some())
        || std::env::var_os(ALLOW_REPLACEABLE_DRIVERS_ENV).is_some_and(|v| v == "1");
    if caller {
        DriverTrust::Caller
    } else {
        DriverTrust::Admin
    }
}

/// Validate a candidate driver/helper path under the `Caller` class:
/// a canonical absolute path naming a real file no *different* user
/// can replace. Retained for explicit fixture overrides and discovered
/// helper paths — `resolve_cli` never applies it to a PATH hit.
///
/// - **Unix**: the file and every ancestor directory must be owned by
///   the caller or by root — and a root-owned entry must not be
///   world-writable (a group-writable admin dir like Homebrew's
///   `/usr/local` is accepted; an `o+w` shared dir never is).
/// - **Windows**: absolute + canonical + regular file, and the leaf
///   plus every ancestor must be owned by a trusted principal (the
///   caller, SYSTEM, Administrators, TrustedInstaller) with no DACL
///   grant that hands an untrusted trustee write/delete/ACL control —
///   the same "no different user can replace it" contract the Unix
///   walk enforces, expressed through SIDs instead of modes.
///
/// Errors name the rejected candidate class — callers must refuse,
/// never fall through to a later PATH entry (the same-name shadow is
/// the attack this closes). Validation without binding is exercised
/// by the class-split tests; production callers bind via
/// [`bind_driver`].
#[cfg(test)]
pub(crate) fn validate_driver_path(path: &Path) -> Result<PathBuf, String> {
    validate_driver_path_as(path, DriverTrust::Caller)
}

/// [`validate_driver_path`] under the `Admin` class: every component
/// must be replaceable only by an administrator principal — the caller
/// itself does *not* count.
#[cfg(test)]
pub(crate) fn validate_admin_driver_path(path: &Path) -> Result<PathBuf, String> {
    validate_driver_path_as(path, DriverTrust::Admin)
}

/// [`bind_driver`] minus the pin: validates `path` under `trust` and
/// returns the canonical spelling. Test-only — production resolution
/// always retains the bound object, never just the path.
#[cfg(test)]
fn validate_driver_path_as(path: &Path, trust: DriverTrust) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("'{}' is not an absolute path", path.display()));
    }
    let canon = path
        .canonicalize()
        .map_err(|e| format!("'{}' cannot be canonicalized: {e}", path.display()))?;
    let md = std::fs::metadata(&canon)
        .map_err(|e| format!("'{}' cannot be inspected: {e}", canon.display()))?;
    check_driver_candidate(&canon, None, &md, trust)?;
    Ok(canon)
}

/// The checks a resolved driver leaf and its ancestors must pass —
/// shared by [`validate_driver_path_as`] and [`bind_driver`]. When
/// `leaf_file` is a handle already open on the leaf, the leaf's own
/// metadata/owner/DACL are read *through the handle* so the object
/// checked is the object pinned, not whatever the path re-resolves to.
fn check_driver_candidate(
    canon: &Path,
    leaf_file: Option<&std::fs::File>,
    leaf_md: &std::fs::Metadata,
    trust: DriverTrust,
) -> Result<(), String> {
    if !leaf_md.is_file() {
        return Err(format!("'{}' is not a regular file", canon.display()));
    }
    #[cfg(any(unix, windows))]
    if let Some(bad) = driver_replacement_gap(canon, leaf_file, leaf_md, trust) {
        return Err(format!(
            "'{}' (or ancestor '{}') is replaceable by an untrusted principal — \
             a substituted driver runs before sandbox setup",
            canon.display(),
            bad.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if leaf_md.permissions().mode() & 0o111 == 0 {
            return Err(format!("'{}' is not executable", canon.display()));
        }
    }
    let _ = leaf_file;
    Ok(())
}

/// Unix gap check: the first path component — walking the file up
/// through its ancestors — that an untrusted principal could replace.
/// The leaf is judged by `leaf_md`, which callers sourcing from an open
/// handle bind to the pinned object rather than the spelling.
///
/// `Admin`: the owner must be root and no component may be writable
/// by group or other — group membership cannot *prove* administrator
/// provenance (group-file member lists miss primary-gid memberships
/// and NSS enumeration is routinely disabled), so `root:staff` /
/// `root:adm` style conventions are refused rather than trusted: any
/// member of a non-root-writable group could substitute the driver.
/// Same posture `sudo` applies to group-writable commands, and the
/// same result the Windows walk reaches by flagging every non-admin
/// trustee.
///
/// `Caller` (fixture/unsafe class): a component is a gap when it cannot
/// be inspected, is owned by neither the caller nor root, or is
/// world-writable (any entry, or an unsticky ancestor). Group-write is
/// not a gap — the caller's group shares the caller's authority.
#[cfg(unix)]
fn driver_replacement_gap(
    path: &Path,
    _leaf_file: Option<&std::fs::File>,
    leaf_md: &std::fs::Metadata,
    trust: DriverTrust,
) -> Option<PathBuf> {
    if unix_component_gap(leaf_md, true, trust) {
        return Some(path.to_path_buf());
    }
    let mut cur = path.parent();
    while let Some(p) = cur {
        match std::fs::metadata(p) {
            Ok(md) if unix_component_gap(&md, false, trust) => return Some(p.to_path_buf()),
            Ok(_) => {}
            // An unexaminable component may be replaceable by whoever
            // holds its parent — it counts rather than being skipped.
            Err(_) => return Some(p.to_path_buf()),
        }
        cur = p.parent();
    }
    None
}

#[cfg(unix)]
fn unix_component_gap(md: &std::fs::Metadata, leaf: bool, trust: DriverTrust) -> bool {
    use std::os::unix::fs::MetadataExt;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let euid = unsafe { libc::geteuid() };
    let owner = md.uid();
    let mode = md.mode();
    match trust {
        DriverTrust::Admin => owner != 0 || mode & 0o022 != 0,
        DriverTrust::Caller => {
            if owner != euid && owner != 0 {
                return true;
            }
            let world_writable = mode & 0o002 != 0;
            let sticky = mode & 0o1000 != 0;
            world_writable && (leaf || !sticky)
        }
    }
}

/// Windows gap check mirroring the Unix walk: the first component —
/// from the resolved leaf up through its ancestors — an *untrusted*
/// principal could replace. `caller_ok` carries the trust class:
/// `Admin` counts only administrator principals as trusted (a
/// caller-owned leaf already fails the owner check), `Caller` also
/// trusts the invoking user. A component is a gap when:
///
/// - its owner is not a trusted principal (`path_owner_is_trusted`, or
///   `handle_owner_is_trusted` on the pinned leaf — an unanswerable
///   owner question counts as a gap rather than a pass);
/// - the leaf file's DACL grants an untrusted trustee content-write,
///   delete, or ACL control (`dacl_grants_file_write`);
/// - an ancestor directory's DACL grants an untrusted trustee
///   delete/delete-child/ACL control
///   (`dir_dacl_grants_replace_rights`) — the rights to rename a
///   component out and plant a same-name substitute.
///
/// Grants to Administrators, SYSTEM, TrustedInstaller, or the
/// owner-delegating placeholders are not untrusted: they name the very
/// authority being validated, matching the Unix "owned by root" class.
#[cfg(windows)]
fn driver_replacement_gap(
    path: &Path,
    leaf_file: Option<&std::fs::File>,
    _leaf_md: &std::fs::Metadata,
    trust: DriverTrust,
) -> Option<PathBuf> {
    let caller_ok = trust.caller_ok();
    let leaf_ok = match leaf_file {
        Some(file) => matches!(
            (
                crate::fspriv::handle_owner_is_trusted(file, caller_ok),
                crate::fspriv::handle_dacl_grants_file_write(file, caller_ok)
            ),
            (Ok(true), Ok(false))
        ),
        None => matches!(
            (
                crate::fspriv::path_owner_is_trusted(path, caller_ok),
                crate::fspriv::dacl_grants_file_write(path, caller_ok)
            ),
            (Ok(true), Ok(false))
        ),
    };
    if !leaf_ok {
        return Some(path.to_path_buf());
    }
    let mut cur = path.parent();
    while let Some(p) = cur {
        let ok = matches!(
            (
                crate::fspriv::path_owner_is_trusted(p, caller_ok),
                crate::fspriv::dir_dacl_grants_replace_rights(p, caller_ok)
            ),
            (Ok(true), Ok(false))
        );
        if !ok {
            return Some(p.to_path_buf());
        }
        cur = p.parent();
    }
    None
}

/// A validated driver path *bound to the object it names*: the
/// canonical spelling plus the file identity captured at bind time.
/// [`verify`](Self::verify) re-opens the spelling and compares identity
/// immediately before every spawn, so an executable replaced after
/// resolution — rename-swap or in-place rewrite — fails closed instead
/// of running with launcher privileges. On Linux the spawn execs a
/// `/proc/self/fd` spelling of the pin — the leaf descriptor itself
/// for binaries (fully object-bound, no name lookup), and for `#!`
/// scripts a `F_DUPFD_CLOEXEC` dup of the pin's *parent-directory*
/// handle joined with the leaf name, so `$0` keeps a usable, bound
/// dirname for sibling loads. A script's leaf is necessarily resolved
/// by name — the kernel passes the spelling string to the
/// interpreter, which re-opens it — so no spelling can be fully
/// object-bound while `$0` stays usable; the pre-exec `fstatat`
/// re-check *narrows* that verify→exec window, and the pinned
/// directory's own write restriction (which the Admin ancestor rules
/// already enforce) is what keeps an unauthorized swap out entirely.
/// The exec descriptor is owned by the returned `Command`, so it
/// stays open and un-reused through the spawn. The retained pin
/// handle also denies share-write/share-delete on Windows while the
/// binding lives,
/// and on every platform holds `(dev, ino)`-level identity plus
/// size+mtime as the swap detectors — on Unix also the inode change
/// time, which `utimens` cannot restore, so a rewrite that preserves
/// size and mtime is still caught.
#[derive(Debug)]
pub struct BoundDriver {
    /// Canonical absolute spelling — the `Command` program and the path
    /// `verify` re-opens.
    path: PathBuf,
    /// Display spelling of `path` (lossy — the same spelling the
    /// engines previously carried as their `exe` string).
    spelling: String,
    /// `None` only in test constructs ([`for_test`](Self::for_test)).
    pin: Option<DriverPin>,
}

/// The pin state captured when a driver binds.
#[derive(Debug)]
struct DriverPin {
    identity: crate::fspriv::FileIdentity,
    len: u64,
    modified: std::time::SystemTime,
    /// Unix only: `(st_ctime, st_ctime_nsec)` — kernel-maintained inode
    /// change time that no userspace call can restore, so it catches
    /// both in-place rewrites and metadata touch-ups (chmod/chown)
    /// that preserve mtime. Windows needs no equivalent: the pin
    /// handle's share mode already denies write/delete for the
    /// binding's lifetime.
    #[cfg(unix)]
    changed: (i64, i64),
    /// Pinned parent directory — `Some` only for `#!` leaves. The
    /// script exec spelling resolves the leaf inside this object, so
    /// `$0`'s dirname stays a bound, usable location (binary leaves
    /// exec the leaf descriptor itself and need no dir pin).
    #[cfg(target_os = "linux")]
    dir_handle: Option<std::fs::File>,
    /// The leaf entry name inside `dir_handle` — the final component
    /// of the script exec spelling.
    #[cfg(target_os = "linux")]
    leaf_name: std::ffi::OsString,
    /// Retained open handle — the pinned object cannot be deleted or
    /// rewritten out from under verification while the binding lives.
    _handle: std::fs::File,
}

/// The `(ctime, ctime_nsec)` pair a unix `Metadata` reports — the
/// detector [`BoundDriver::verify`] adds on top of size+mtime.
#[cfg(unix)]
fn pin_change_time(md: &std::fs::Metadata) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (md.ctime(), md.ctime_nsec())
}

impl BoundDriver {
    /// The canonical path used for spawning and re-verification.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The program spelling for display and `Command` construction.
    pub fn program(&self) -> &str {
        &self.spelling
    }

    /// Re-open `path` and prove it still names the validated object —
    /// called by [`tokio_command`](Self::tokio_command) and
    /// [`std_command`](Self::std_command) immediately before every
    /// spawn so a replacement planted after resolution fails closed.
    /// File identity alone misses an in-place rewrite that preserves
    /// `(dev, ino)`, so size+mtime ride along as the byte-level swap
    /// detectors — and on unix ctime too, closing the "restore size and
    /// mtime" gap that the size/mtime pair alone leaves open.
    pub fn verify(&self) -> std::io::Result<()> {
        let Some(pin) = &self.pin else {
            return Ok(());
        };
        let (file, identity) = open_driver_pin(&self.path).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("'{}' cannot be re-verified: {e}", self.path.display()),
            )
        })?;
        let md = file.metadata()?;
        let same = identity == pin.identity
            && md.len() == pin.len
            && md.modified().ok() == Some(pin.modified);
        #[cfg(unix)]
        let same = same && pin_change_time(&md) == pin.changed;
        if !same {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "'{}' was replaced since it was validated",
                    self.path.display()
                ),
            ));
        }
        Ok(())
    }

    /// The spelling a spawned child execs, plus — on Linux — the
    /// descriptor it resolves through. A `#!` leaf needs a usable
    /// `$0`: the interpreter re-opens the spelling and scripts resolve
    /// siblings via `dirname $0`, so scripts get the *parent-directory*
    /// dup's `/proc/self/fd/N/<leaf>` spelling — the dirname binds the
    /// pinned directory object (the leaf name is re-verified pre-exec,
    /// see [`bind_exec_fd`]). Anything else execs a dup of the *leaf
    /// descriptor itself* — `/proc/self/fd/N` — fully object-bound,
    /// no name lookup remains. The dup is `F_DUPFD_CLOEXEC`: it stays
    /// close-on-exec in the parent — so no concurrent spawn inherits
    /// it — and [`bind_exec_fd`] clears the flag in the child only
    /// when an interpreter needs to re-open the spelling; a binary's
    /// fd resolves at `execve` and closes itself. [`finish_command`]
    /// parks the dup inside the returned command so it cannot be
    /// closed or its number reused while the command exists. Other
    /// platforms spawn the canonical path — Windows cannot be swapped
    /// while the pin's share mode lives, and unixes without fd-exec
    /// keep `verify`'s residual window, the narrowest portable bound.
    fn exec_program(&self) -> std::io::Result<(PathBuf, Option<std::fs::File>)> {
        #[cfg(target_os = "linux")]
        if let Some(pin) = &self.pin {
            use std::os::unix::io::{AsRawFd, FromRawFd};
            let (pin_fd, leaf) = match &pin.dir_handle {
                Some(dir) => (dir.as_raw_fd(), Some(&pin.leaf_name)),
                None => (pin._handle.as_raw_fd(), None),
            };
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let fd = unsafe { libc::fcntl(pin_fd, libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
            let file = unsafe { std::fs::File::from_raw_fd(fd) };
            let mut spelling = PathBuf::from(format!("/proc/self/fd/{fd}"));
            if let Some(leaf) = leaf {
                spelling.push(leaf);
            }
            return Ok((spelling, Some(file)));
        }
        Ok((self.path.clone(), None))
    }

    /// Move `fd` inside `cmd` so the exec descriptor stays open until
    /// the command is dropped — the `pre_exec` closure owns it: the fd
    /// is open in the parent when `spawn` forks and is inherited by
    /// the child. It stays CLOEXEC (see `exec_program`), so a binary's
    /// fd closes itself at `execve`; only for a *script* exec does the
    /// closure clear `FD_CLOEXEC` — in the child, after fork — so the
    /// interpreter can re-open the `$0` spelling, and the fd never
    /// becomes inheritable in the parent. For a script the closure
    /// also re-proves the leaf name in the pinned directory still
    /// names the validated object — `fstatat` on the dir fd, syscalls
    /// and field compares only, so the closure stays
    /// async-signal-safe. The check *narrows* — it does not close —
    /// the verify→execve window: a same-dir leaf swap needs write
    /// access on the pinned directory itself, which the ancestor rules
    /// already deny a Caller-class principal, so the residual race is
    /// outside the Admin threat model; a swap that has already landed
    /// still fails closed here rather than exec'ing the replacement.
    /// Leaf-fd execs (binaries) skip the check: the fd itself names
    /// the object, there is no lookup to re-verify.
    #[cfg(target_os = "linux")]
    fn bind_exec_fd(cmd: &mut std::process::Command, fd: std::fs::File, pin: &DriverPin) {
        use std::os::unix::io::AsRawFd;
        use std::os::unix::process::CommandExt;

        let dirfd = fd.as_raw_fd();
        let leaf_check = pin.dir_handle.is_some().then(|| {
            let name = std::ffi::CString::new(pin.leaf_name.as_encoded_bytes())
                .expect("leaf name cannot contain NUL");
            let (mtime_s, mtime_ns) = pin
                .modified
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| (d.as_secs() as i64, d.subsec_nanos() as i64))
                .unwrap_or_default();
            (
                name,
                pin.identity.device,
                pin.identity.index,
                pin.len,
                mtime_s,
                mtime_ns,
                pin.changed,
            )
        });
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe {
            cmd.pre_exec(move || {
                if let Some((name, dev, ino, len, mt_s, mt_ns, (ct_s, ct_ns))) = &leaf_check {
                    let mut st = std::mem::zeroed::<libc::stat>();
                    let rc = libc::fstatat(dirfd, name.as_ptr(), &mut st, 0);
                    if rc != 0
                        || st.st_dev != *dev
                        || st.st_ino != *ino
                        || st.st_size as u64 != *len
                        || st.st_mtime != *mt_s
                        || st.st_mtime_nsec != *mt_ns
                        || st.st_ctime != *ct_s
                        || st.st_ctime_nsec != *ct_ns
                    {
                        return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                    }
                    // The `#!` interpreter re-opens the `$0` spelling
                    // in the exec'd image — clear CLOEXEC only here,
                    // in the forked child, so the descriptor survives
                    // `execve` for that re-open without ever being
                    // inheritable in the parent.
                    if libc::fcntl(dirfd, libc::F_SETFD, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                let _fd = &fd;
                Ok(())
            });
        }
    }

    /// Keep argv[0] the canonical spelling — the fd spelling is an exec
    /// detail, not the identity the child should see.
    #[cfg(target_os = "linux")]
    fn apply_argv0(&self, cmd: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        cmd.arg0(&self.path);
    }

    /// Attach the exec descriptor and the argv[0] fixup for the exec
    /// spelling — a no-op off Linux, where `exec_fd` is always `None`.
    #[cfg(target_os = "linux")]
    fn finish_command(
        &self,
        mut cmd: std::process::Command,
        exec_fd: Option<std::fs::File>,
    ) -> std::process::Command {
        if let (Some(fd), Some(pin)) = (exec_fd, self.pin.as_ref()) {
            Self::bind_exec_fd(&mut cmd, fd, pin);
            self.apply_argv0(&mut cmd);
        }
        cmd
    }

    #[cfg(not(target_os = "linux"))]
    fn finish_command(
        &self,
        cmd: std::process::Command,
        _exec_fd: Option<std::fs::File>,
    ) -> std::process::Command {
        cmd
    }

    /// `verify`, then construct the spawnable command on the bound
    /// object — shared by [`tokio_command`](Self::tokio_command) and
    /// [`std_command`](Self::std_command). The returned command owns
    /// its exec descriptor, so the pinned object stays reachable until
    /// `spawn`/`output` completes even if this `BoundDriver` is
    /// dropped first.
    fn driver_command(&self) -> std::io::Result<std::process::Command> {
        self.verify()?;
        let (program, exec_fd) = self.exec_program()?;
        Ok(self.finish_command(std::process::Command::new(program), exec_fd))
    }

    /// `verify`, then build the spawnable async command on the bound
    /// object — the only way engine code may construct a driver
    /// `Command`.
    pub fn tokio_command(&self) -> std::io::Result<tokio::process::Command> {
        Ok(tokio::process::Command::from(self.driver_command()?))
    }

    /// [`tokio_command`](Self::tokio_command) for blocking spawns.
    pub fn std_command(&self) -> std::io::Result<std::process::Command> {
        self.driver_command()
    }

    /// An unbound spelling for engine tests that never spawn — `verify`
    /// is a no-op, matching the previous `exe: String` fixture.
    #[cfg(test)]
    pub(crate) fn for_test(spelling: &str) -> Self {
        Self {
            path: PathBuf::from(spelling),
            spelling: spelling.to_string(),
            pin: None,
        }
    }

    /// Pin `path` without provenance checks — tests that stage a fake
    /// driver to exercise the identity binding itself.
    #[cfg(test)]
    pub(crate) fn bind_for_test(path: &Path) -> Result<Self, String> {
        let canon = path
            .canonicalize()
            .map_err(|e| format!("'{}' cannot be canonicalized: {e}", path.display()))?;
        let (file, identity) = open_driver_pin(&canon)
            .map_err(|e| format!("'{}' cannot be opened: {e}", canon.display()))?;
        let md = file
            .metadata()
            .map_err(|e| format!("'{}' cannot be inspected: {e}", canon.display()))?;
        let modified = md
            .modified()
            .map_err(|e| format!("'{}' has no mtime: {e}", canon.display()))?;
        #[cfg(target_os = "linux")]
        let (dir_handle, leaf_name) = script_dir_pin(&canon, &file)?;
        Ok(Self {
            spelling: canon.to_string_lossy().into_owned(),
            path: canon.clone(),
            pin: Some(DriverPin {
                identity,
                len: md.len(),
                modified,
                #[cfg(unix)]
                changed: pin_change_time(&md),
                #[cfg(target_os = "linux")]
                dir_handle,
                #[cfg(target_os = "linux")]
                leaf_name,
                _handle: file,
            }),
        })
    }
}

/// Open the resolved driver leaf for pinning and identity capture:
/// unix opens `O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC` so a final-component
/// link fails `ELOOP` and a FIFO planted at the spelling cannot stall
/// the open; Windows opens with `FILE_SHARE_READ` only — denying
/// share-write/share-delete so the validated bytes cannot be replaced
/// or deleted while the pin lives.
#[cfg(unix)]
fn open_driver_pin(path: &Path) -> std::io::Result<(std::fs::File, crate::fspriv::FileIdentity)> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let identity = crate::fspriv::file_identity(&file)?;
    Ok((file, identity))
}

#[cfg(windows)]
fn open_driver_pin(path: &Path) -> std::io::Result<(std::fs::File, crate::fspriv::FileIdentity)> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)?;
    let identity = crate::fspriv::file_identity(&file)?;
    Ok((file, identity))
}

#[cfg(not(any(unix, windows)))]
fn open_driver_pin(path: &Path) -> std::io::Result<(std::fs::File, crate::fspriv::FileIdentity)> {
    let file = std::fs::OpenOptions::new().read(true).open(path)?;
    let identity = crate::fspriv::file_identity(&file)?;
    Ok((file, identity))
}

/// Pin the resolved driver's *parent directory* — a script's exec
/// spelling resolves the leaf inside this object, so an ancestor swap
/// cannot redirect the spawn and the child's `$0` keeps a usable,
/// bound dirname. `O_PATH` asks for no access at all — an
/// `O_RDONLY`-or-better open would refuse a search-only (`--x`)
/// directory, while the path-reference fd still works as the exec
/// spelling's dirfd and for `fstatat`. `O_NOFOLLOW` is belt and
/// suspenders: the canonical spelling's parent is already link-free,
/// a planted link would fail `ELOOP` rather than be traversed.
#[cfg(target_os = "linux")]
fn open_dir_pin(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("'{}' has no parent directory", path.display()),
        )
    })?;
    // `.read(true)` only satisfies `OpenOptions`' requirement that an
    // access mode be set — `O_RDONLY` contributes zero flag bits and
    // the kernel ignores access mode entirely under `O_PATH`, so no
    // read permission is demanded on the directory.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
}

/// Probe the pinned leaf and pin its parent directory when the leaf
/// is a `#!` script — the script exec spelling needs a usable `$0`
/// dirname (see [`BoundDriver::exec_program`]); binaries exec the
/// leaf descriptor itself and need no dir pin.
#[cfg(target_os = "linux")]
fn script_dir_pin(
    canon: &Path,
    file: &std::fs::File,
) -> Result<(Option<std::fs::File>, std::ffi::OsString), String> {
    use std::os::unix::fs::FileExt;
    let leaf_name = leaf_name_of(canon)?;
    let mut magic = [0u8; 2];
    file.read_at(&mut magic, 0)
        .map_err(|e| format!("'{}' cannot be probed: {e}", canon.display()))?;
    let dir = if magic == *b"#!" {
        Some(
            open_dir_pin(canon)
                .map_err(|e| format!("'{}' parent cannot be pinned: {e}", canon.display()))?,
        )
    } else {
        None
    };
    Ok((dir, leaf_name))
}

/// The leaf entry name of a resolved driver — the final component the
/// dir-pinned exec spelling appends. A canonical file path always has
/// one (only `/` lacks it, and `/` is not a regular file).
#[cfg(target_os = "linux")]
fn leaf_name_of(path: &Path) -> Result<std::ffi::OsString, String> {
    path.file_name()
        .map(|n| n.to_os_string())
        .ok_or_else(|| format!("'{}' has no leaf name", path.display()))
}

/// Whether the ambient temp hierarchy can host a Caller-class fixture
/// at all — probes the path the tests then stage into. A host whose
/// shared temp grants replace rights to other named principals
/// (sandboxed agent hosts are one example) refuses every path under
/// it, and that refusal *is* the contract; tests asserting Caller
/// acceptance gate on this so they skip honestly instead of failing.
#[cfg(test)]
pub(crate) fn ambient_temp_passes_caller(label: &str) -> bool {
    let Some(dir) = crate::fspriv::create_private_tempdir(label).ok() else {
        return false;
    };
    let probe = dir.join("probe");
    let ok = std::fs::write(&probe, b"x").is_ok()
        && {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o755)).is_ok()
            }
            #[cfg(not(unix))]
            {
                true
            }
        }
        && validate_driver_path(&probe).is_ok();
    let _ = std::fs::remove_dir_all(&dir);
    if !ok {
        eprintln!(
            "ambient temp hierarchy fails the Caller contract — a shared \
             temp dir is replaceable by other named principals"
        );
    }
    ok
}

/// Validate `path` and bind the validated object to a [`BoundDriver`]
/// — the entry point engine resolution uses when it already holds a
/// candidate spelling (a discovered install root or an override).
pub(crate) fn bind_driver(path: &Path, trust: DriverTrust) -> Result<BoundDriver, String> {
    if !path.is_absolute() {
        return Err(format!("'{}' is not an absolute path", path.display()));
    }
    let canon = path
        .canonicalize()
        .map_err(|e| format!("'{}' cannot be canonicalized: {e}", path.display()))?;
    let (file, identity) = open_driver_pin(&canon)
        .map_err(|e| format!("'{}' cannot be opened: {e}", canon.display()))?;
    let md = file
        .metadata()
        .map_err(|e| format!("'{}' cannot be inspected: {e}", canon.display()))?;
    check_driver_candidate(&canon, Some(&file), &md, trust)?;
    let modified = md
        .modified()
        .map_err(|e| format!("'{}' has no mtime: {e}", canon.display()))?;
    #[cfg(target_os = "linux")]
    let (dir_handle, leaf_name) = script_dir_pin(&canon, &file)?;
    Ok(BoundDriver {
        spelling: canon.to_string_lossy().into_owned(),
        path: canon.clone(),
        pin: Some(DriverPin {
            identity,
            len: md.len(),
            modified,
            #[cfg(unix)]
            changed: pin_change_time(&md),
            #[cfg(target_os = "linux")]
            dir_handle,
            #[cfg(target_os = "linux")]
            leaf_name,
            _handle: file,
        }),
    })
}

/// The env var naming an explicit driver path — `MCP_WRIT_DOCKER_EXE`,
/// `MCP_WRIT_PODMAN_EXE`, `MCP_WRIT_BUILDAH_EXE`,
/// `MCP_WRIT_CONTAINER_EXE`. Set, it *replaces* PATH resolution with
/// the spelled absolute path under the `Caller` class (the setter can
/// already control the process's own files); unset, PATH applies under
/// `Admin`.
fn driver_override_env(name: &str) -> String {
    format!("MCP_WRIT_{}_EXE", name.to_ascii_uppercase())
}

/// Resolve driver `name` to a *bound* executable:
///
/// 1. `MCP_WRIT_<NAME>_EXE` set → the spelled absolute path, bound
///    under the `Caller` class (an explicit fixture/operator pin; a
///    bad spelling is an error, never a fall-through).
/// 2. Otherwise the first `name` on PATH — bound under `Admin`: a hit
///    in a caller-managed directory refuses rather than falling
///    through to the next entry (the same-name shadow is the attack
///    this closes), and `MCP_WRIT_ALLOW_REPLACEABLE_DRIVERS=1` is the
///    only way a caller-managed PATH hit validates.
///
/// The returned [`BoundDriver`] is the *only* spelling every later
/// probe, build, launch, monitor, cleanup, and teardown may use —
/// `verify` re-checks identity at each spawn.
pub(crate) fn resolve_cli(name: &str) -> Result<BoundDriver, String> {
    let env = driver_override_env(name);
    let trust = driver_trust(Some(&env));
    if let Some(raw) = std::env::var_os(&env) {
        let spelled = PathBuf::from(raw);
        return bind_driver(&spelled, trust)
            .map_err(|e| format!("{env} '{}' is not a trusted driver: {e}", spelled.display()));
    }
    let found =
        crate::workload::search_path(name).ok_or_else(|| format!("'{name}' not found on PATH"))?;
    bind_driver(&found, trust).map_err(|e| {
        format!(
            "resolved '{name}' at '{}': {e} (an isolation driver must live under \
             an administrator-controlled root — set {env} to an explicit trusted \
             path, or {ALLOW_REPLACEABLE_DRIVERS_ENV}=1 to accept a \
             caller-managed driver)",
            found.display()
        )
    })
}

/// An OS-owned helper resolved to a [`BoundDriver`] by its
/// system-directory spelling — never through PATH or the current
/// directory. `rel` is the System32-relative path (`"tasklist.exe"`,
/// `"WindowsPowerShell\\v1.0\\powershell.exe"`). `None` off Windows or
/// when the resolved file fails administrator provenance — callers
/// turn that into their own refusal. The returned binding re-verifies
/// the object at every spawn the same way an engine driver does.
///
/// The system directory comes from `GetSystemDirectoryW` — the
/// kernel's own answer, not a caller-mutable `SystemRoot`. The x86-64
/// build is native on every supported Windows host, so the returned
/// directory *is* the native system directory — WOW64's Sysnative
/// distinction does not apply (a 32-bit process would need
/// `Sysnative`, but no such target ships).
/// The System32 *spelling* of a helper — the trusted directory joined
/// with `rel`, unvalidated and unbound. Candidate lists
/// (`windows_probe::helper_exe`) start here and apply their own
/// validation/binding; direct helper users want [`system32_exe`].
#[cfg(windows)]
pub(crate) fn system32_path(rel: &str) -> Option<PathBuf> {
    system_dir().map(|d| d.join(rel))
}

#[cfg(not(windows))]
pub(crate) fn system32_path(_rel: &str) -> Option<PathBuf> {
    None
}

#[cfg(windows)]
pub(crate) fn system32_exe(rel: &str) -> Option<BoundDriver> {
    bind_driver(&system32_path(rel)?, driver_trust(None)).ok()
}

#[cfg(not(windows))]
pub(crate) fn system32_exe(_rel: &str) -> Option<BoundDriver> {
    None
}

/// The kernel-reported System32 directory — `GetSystemDirectoryW`,
/// never `%SystemRoot%`.
#[cfg(windows)]
fn system_dir() -> Option<PathBuf> {
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
    let mut buf = vec![0u16; 32767];
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe { GetSystemDirectoryW(Some(&mut buf)) };
    if n == 0 || n as usize >= buf.len() {
        return None;
    }
    buf.truncate(n as usize);
    Some(PathBuf::from(String::from_utf16_lossy(&buf)))
}

/// The Store-WSL install root — the system `Program Files` directory
/// joined with `WSL`, an admin-writable-only location. `None` off
/// Windows (test builds may still shape the path so resolution logic
/// is exercised).
///
/// The directory comes from `SHGetKnownFolderPath(FOLDERID_ProgramFiles)`
/// — the shell's own answer, not a caller-mutable `ProgramFiles`
/// variable. Test builds keep the env spelling so fixtures can stage a
/// fake install root; it never reaches a shipped binary.
pub(crate) fn wsl_install_dir() -> Option<PathBuf> {
    if !cfg!(windows) && !cfg!(test) {
        return None;
    }
    #[cfg(all(windows, not(test)))]
    let root = program_files_dir()?;
    #[cfg(any(not(windows), test))]
    let root = std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
    Some(root.join("WSL"))
}

/// `%ProgramFiles%` without the environment —
/// `SHGetKnownFolderPath` answers the admin-writable install root the
/// shell itself reports, so a poisoned environment cannot retarget the
/// resolution.
#[cfg(all(windows, not(test)))]
fn program_files_dir() -> Option<PathBuf> {
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
    let raw =
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFiles, KF_FLAG_DEFAULT, None) }.ok()?;
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let text = unsafe { raw.to_string() }.ok();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { CoTaskMemFree(Some(raw.0 as *const std::ffi::c_void)) };
    text.map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A path under the caller's own writable directory is *their*
    /// file — it validates under the `Caller` class (fixture override
    /// semantics), and under `Admin` it is exactly the caller-managed
    /// provenance driver resolution must refuse. (On Windows the same
    /// two classes apply: caller-owned leaf + caller-owned ancestors
    /// pass `Caller`, fail `Admin`.)
    ///
    /// The fixture dir uses `create_private_tempdir` so the leaf's own
    /// DACL is owner-only; hosts whose *ambient* temp hierarchy grants
    /// replace rights to other named principals refuse the whole tree
    /// — the contract working — so the assertion gates on the ambient
    /// probe.
    #[test]
    fn caller_owned_path_trust_split() {
        if !ambient_temp_passes_caller("trusted-path") {
            return;
        }
        let dir = crate::fspriv::create_private_tempdir("trusted-path").expect("private tempdir");
        let exe = dir.join("tool");
        write_executable(&exe);
        assert!(
            validate_driver_path(&exe).is_ok(),
            "caller-owned file must pass the Caller class"
        );
        if !crate::fspriv::running_as_root() {
            assert!(
                validate_admin_driver_path(&exe).is_err(),
                "caller-owned file must fail the Admin class"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The production `bind_driver` path applies the same class split,
    /// reading the leaf's owner/DACL through the *open pin handle* —
    /// the object validated is the object retained. Same ambient
    /// gating as [`caller_owned_path_trust_split`].
    #[test]
    fn bind_driver_caller_class_split() {
        if !ambient_temp_passes_caller("trusted-path") {
            return;
        }
        let dir = crate::fspriv::create_private_tempdir("trusted-path").expect("private tempdir");
        let exe = dir.join("tool");
        write_executable(&exe);
        let bound = bind_driver(&exe, DriverTrust::Caller)
            .expect("caller-owned file must bind under the Caller class");
        assert!(bound.verify().is_ok());
        if !crate::fspriv::running_as_root() {
            assert!(
                bind_driver(&exe, DriverTrust::Admin).is_err(),
                "caller-owned file must not bind under the Admin class"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The admin class rejects a caller-managed component even when the
    /// leaf itself would be fine — the group-writable temp-dir shape is
    /// the exact caller tooling write surface the finding names.
    #[cfg(unix)]
    #[test]
    fn admin_class_refuses_group_writable_caller_dir() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o775)).unwrap();
        let exe = sub.join("tool");
        write_executable(&exe);
        assert!(validate_driver_path(&exe).is_ok(), "Caller class accepts");
        if !crate::fspriv::running_as_root() {
            assert!(
                validate_admin_driver_path(&exe).is_err(),
                "Admin class must refuse a caller-owned group-writable ancestor"
            );
        }
    }

    /// A relative spelling never reaches canonicalization — overrides
    /// and helper spellings must already be absolute.
    #[test]
    fn relative_path_refuses() {
        let err = validate_driver_path(Path::new("bin/tool")).unwrap_err();
        assert!(err.contains("absolute"), "{err}");
    }

    /// A world-writable ancestor without the sticky bit lets any user
    /// swap directory entries — caller ownership changes nothing about
    /// that. Exactly the shared-dir shape PATH resolution must not
    /// bless, under either trust class.
    #[cfg(unix)]
    #[test]
    fn world_writable_unsticky_ancestor_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o777)).unwrap();
        let exe = sub.join("tool");
        write_executable(&exe);
        assert!(validate_driver_path(&exe).is_err());
    }

    /// The same world-writable ancestor *with* the sticky bit is not a
    /// `Caller`-class replacement gap — `/tmp` semantics: entries
    /// cannot be renamed away by non-owners. `Admin` still refuses:
    /// world-write is never administrator provenance.
    #[cfg(unix)]
    #[test]
    fn world_writable_sticky_ancestor_trust_split() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let exe = sub.join("tool");
        write_executable(&exe);
        assert!(validate_driver_path(&exe).is_ok(), "Caller class accepts");
        assert!(
            validate_admin_driver_path(&exe).is_err(),
            "Admin refuses o+w"
        );
    }

    /// A world-writable resolved file can be rewritten by anyone —
    /// sticky ancestors do not protect file contents.
    #[cfg(unix)]
    #[test]
    fn world_writable_file_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_driver_path(&exe).is_err());
    }

    /// A non-executable regular file is never a driver.
    #[cfg(unix)]
    #[test]
    fn non_executable_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("tool");
        std::fs::write(&f, b"data").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = validate_driver_path(&f).unwrap_err();
        assert!(err.contains("executable"), "{err}");
    }

    /// The identity binding: a driver renamed away and recreated after
    /// binding fails `verify`, even though the spelling still resolves.
    #[cfg(not(windows))]
    #[test]
    fn bound_driver_detects_rename_swap() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        write_executable(&exe);
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        assert!(bound.verify().is_ok());
        // Atomic replace: move the pinned file aside and create a new
        // one at the same spelling — the identity changes.
        let swapped = dir.path().join("tool.old");
        std::fs::rename(&exe, &swapped).unwrap();
        write_executable(&exe);
        let err = bound.verify().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }

    /// Windows variant of [`bound_driver_detects_rename_swap`]: the
    /// pin's read-only share mode denies share-delete, so the rename
    /// that would stage a same-name replacement is refused outright —
    /// the bound object cannot be swapped and still verifies.
    #[cfg(windows)]
    #[test]
    fn bound_driver_detects_rename_swap() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        write_executable(&exe);
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        assert!(bound.verify().is_ok());
        let swapped = dir.path().join("tool.old");
        assert!(
            std::fs::rename(&exe, &swapped).is_err(),
            "the pin denies share-delete — the rename must be refused"
        );
        assert!(bound.verify().is_ok());
    }

    /// An in-place rewrite that keeps `(dev, ino)` still fails
    /// `verify` through the size/mtime detectors.
    #[cfg(not(windows))]
    #[test]
    fn bound_driver_detects_inplace_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        write_executable(&exe);
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        std::fs::write(&exe, b"#!/bin/sh\necho replaced\nexit 1\n").unwrap();
        let err = bound.verify().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    }

    /// Windows variant of [`bound_driver_detects_inplace_rewrite`]:
    /// the pin denies share-write, so the rewrite itself is refused —
    /// the pinned bytes cannot change under the binding.
    #[cfg(windows)]
    #[test]
    fn bound_driver_detects_inplace_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        write_executable(&exe);
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        assert!(
            std::fs::write(&exe, b"MZ replaced").is_err(),
            "the pin denies share-write — the rewrite must be refused"
        );
        assert!(bound.verify().is_ok());
    }

    /// `tokio_command`/`std_command` refuse to hand back a spawnable
    /// command once the bound object is gone — the spawn cannot be
    /// redirected to a replacement.
    #[cfg(not(windows))]
    #[tokio::test]
    async fn bound_driver_command_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        write_executable(&exe);
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        std::fs::remove_file(&exe).unwrap();
        write_executable(&exe);
        assert!(bound.std_command().is_err());
        assert!(bound.tokio_command().is_err());
    }

    /// Windows variant of [`bound_driver_command_fails_closed`]: the
    /// pin denies share-delete, so the removal is refused and the bound
    /// object survives — the commands keep building on the still-pinned
    /// file.
    #[cfg(windows)]
    #[tokio::test]
    async fn bound_driver_command_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        write_executable(&exe);
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        assert!(
            std::fs::remove_file(&exe).is_err(),
            "the pin denies share-delete — the removal must be refused"
        );
        assert!(bound.std_command().is_ok());
        assert!(bound.tokio_command().is_ok());
    }

    /// `verify` passes while the bound object is untouched — the
    /// pinned identity survives an unrelated rename beside it.
    #[test]
    fn bound_driver_verify_passes_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        write_executable(&exe);
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        let sibling = dir.path().join("other");
        std::fs::write(&sibling, b"x").unwrap();
        std::fs::rename(&sibling, dir.path().join("other2")).unwrap();
        assert!(bound.verify().is_ok());
    }

    /// Linux: `verify` narrows the substitution window to the gap
    /// between the identity re-check and `execve`; the spawned child
    /// execs the leaf *inside a pinned parent-directory descriptor*
    /// (`/proc/self/fd/N/<leaf>`) and the `pre_exec` hook re-proves
    /// that name still names the validated object. A swap landing
    /// after the command is built therefore fails the spawn closed —
    /// it can never run the replacement.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_spawn_execs_pinned_object_across_a_swap() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\necho pinned\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        // The command is built — verification passed — then the
        // path's object is swapped: the residual window the finding
        // names.
        let mut cmd = bound.std_command().unwrap();
        assert!(
            cmd.get_program()
                .to_string_lossy()
                .starts_with("/proc/self/fd/"),
            "linux spawn must exec through the pinned descriptor, not the path"
        );
        let swapped = dir.path().join("tool.old");
        std::fs::rename(&exe, &swapped).unwrap();
        std::fs::write(&exe, b"#!/bin/sh\necho swapped\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The path re-check fails closed for a swap that has already
        // landed — commands refuse rather than run either object.
        assert!(bound.std_command().is_err());
        assert!(bound.tokio_command().is_err());
        // And the already-built command cannot be redirected either:
        // the pre-exec fstatat inside the pinned directory sees the
        // leaf no longer names the pinned inode and aborts the spawn.
        assert!(
            cmd.output().is_err(),
            "a swapped leaf must fail the pre-exec identity check"
        );
    }

    /// The exec descriptor is owned by the returned command: dropping
    /// the `BoundDriver` closes its pin handles, but the command's
    /// non-CLOEXEC dup still resolves the pinned directory — the
    /// pinned script runs, and the shebang interpreter's own re-open
    /// of the `$0` spelling lands on the same bound object.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_command_outlives_the_binding() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\necho pinned\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let mut cmd = {
            let bound = BoundDriver::bind_for_test(&exe).unwrap();
            bound.std_command().unwrap()
            // `bound` drops here — leaf and directory pin handles close.
        };
        let out = cmd.output().unwrap();
        assert_eq!(out.stdout, b"pinned\n");
    }

    /// A `#!` driver's `$0` stays usable: `dirname "$0"` resolves the
    /// pinned directory, so a script loading a sibling file finds it
    /// inside the bound object — no reopening by an unverified path.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_shebang_resolves_siblings_through_the_pinned_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"#!/bin/sh\ncat \"$(dirname \"$0\")/lib.txt\"\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.path().join("lib.txt"), b"sibling-data\n").unwrap();
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        let out = bound.std_command().unwrap().output().unwrap();
        assert_eq!(
            out.stdout, b"sibling-data\n",
            "sibling lookup through $0 must land inside the pinned dir: {out:?}"
        );
    }

    /// A non-`#!` leaf has no `dirname` requirement: its exec
    /// spelling is the pinned leaf descriptor itself — a bare
    /// `/proc/self/fd/N` with no trailing name — so no directory
    /// lookup remains in the exec at all and there is no residual
    /// leaf-swap window to check.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_binary_execs_the_leaf_descriptor() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
        std::fs::write(&exe, b"\x7fELF-not-actually-loadable").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        let (program, fd) = bound.exec_program().unwrap();
        assert!(fd.is_some());
        let spelling = program.to_string_lossy();
        assert!(
            spelling
                .strip_prefix("/proc/self/fd/")
                .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit())),
            "binary exec must be the bare pinned-fd spelling, got {spelling:?}"
        );
    }

    /// A search-only (`--x`) parent still pins: `O_PATH` asks for no
    /// access bits, and the script exec spelling still resolves
    /// through the descriptor — an `O_RDONLY` open would have failed
    /// `EACCES` here.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_script_under_search_only_dir_binds_and_runs() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let exe = sub.join("tool");
        std::fs::write(&exe, b"#!/bin/sh\necho pinned\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o111)).unwrap();
        let bound = BoundDriver::bind_for_test(&exe).unwrap();
        let out = bound.std_command().unwrap().output().unwrap();
        assert_eq!(out.stdout, b"pinned\n");
        // Restore writability so the tempdir cleanup can remove `sub`.
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// `for_test` constructs an unbound spelling — `verify` is a no-op
    /// on a path that does not exist.
    #[test]
    fn for_test_driver_is_unbound() {
        let bound = BoundDriver::for_test("nonexistent-driver");
        assert!(bound.verify().is_ok());
        assert_eq!(bound.program(), "nonexistent-driver");
    }

    #[cfg(unix)]
    fn write_executable(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[cfg(windows)]
    fn write_executable(path: &Path) {
        std::fs::write(path, b"MZ").unwrap();
    }

    #[cfg(not(any(unix, windows)))]
    fn write_executable(path: &Path) {
        std::fs::write(path, b"x").unwrap();
    }
}
