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
//!   root-owned, non-world-writable entry whose group-write (if any)
//!   names a group the caller does not belong to; on Windows an object
//!   owned by SYSTEM/Administrators/TrustedInstaller whose DACL hands
//!   dangerous rights to no other trustee — so a caller-managed `PATH`
//!   entry can never supply the driver.
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
        || std::env::var_os(ALLOW_REPLACEABLE_DRIVERS_ENV)
            .is_some_and(|v| !v.is_empty() && v != "0");
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
/// `Admin`: the owner must be root; no component may be
/// world-writable; group-write counts only when it names a group the
/// caller is *not* in — a caller's own group lets the caller's
/// (potentially compromised) tooling rewrite the driver, so
/// `root:<caller-group> g+w` fails while the admin-group convention
/// (`root:staff`, Debian's `root:adm`) passes for non-members.
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
        DriverTrust::Admin => {
            owner != 0 || mode & 0o002 != 0 || (mode & 0o020 != 0 && caller_in_group(md.gid()))
        }
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

/// True when the process's egid or supplementary groups include `gid`.
#[cfg(unix)]
fn caller_in_group(gid: u32) -> bool {
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::getegid() } == gid {
        return true;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n <= 0 {
        return false;
    }
    let mut buf = vec![0 as libc::gid_t; n as usize];
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let got = unsafe { libc::getgroups(n, buf.as_mut_ptr()) };
    got > 0 && buf[..got as usize].contains(&gid)
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
/// of running with launcher privileges. The retained pin handle also
/// denies share-write/share-delete on Windows while the binding lives,
/// and on every platform holds `(dev, ino)`-level identity plus
/// size+mtime as the swap detectors.
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
    /// Retained open handle — the pinned object cannot be deleted or
    /// rewritten out from under verification while the binding lives.
    _handle: std::fs::File,
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
    /// detectors.
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

    /// `verify`, then build the spawnable async command on the bound
    /// path — the only way engine code may construct a driver
    /// `Command`.
    pub fn tokio_command(&self) -> std::io::Result<tokio::process::Command> {
        self.verify()?;
        Ok(tokio::process::Command::new(&self.path))
    }

    /// [`tokio_command`](Self::tokio_command) for blocking spawns.
    pub fn std_command(&self) -> std::io::Result<std::process::Command> {
        self.verify()?;
        Ok(std::process::Command::new(&self.path))
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
        Ok(Self {
            spelling: canon.to_string_lossy().into_owned(),
            path: canon,
            pin: Some(DriverPin {
                identity,
                len: md.len(),
                modified,
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
    Ok(BoundDriver {
        spelling: canon.to_string_lossy().into_owned(),
        path: canon,
        pin: Some(DriverPin {
            identity,
            len: md.len(),
            modified,
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
    #[test]
    fn caller_owned_path_trust_split() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("tool");
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
