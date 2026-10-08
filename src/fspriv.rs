//! Owner-only temporary directories for policy and build staging, plus
//! copy primitives that cannot be raced out of a staged source tree:
//! every copied file is opened without following a final-component link
//! and proven to resolve inside the canonicalized source root, and the
//! bytes stream from that same open handle — a pathname swapped for a
//! link mid-copy can never redirect the read to an out-of-tree target.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Create a new directory under the system temp dir with owner-only access.
///
/// Fails closed if the directory already exists or permissions cannot be set.
pub fn create_private_tempdir(label: &str) -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "mcp-writ-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&dir)?;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(&dir)?;
    }
    restrict_owner_only(&dir)?;
    Ok(dir)
}

/// Restrict `dir` to the current user. Unix sets mode 0700; Windows
/// applies a protected DACL granting the current user and SYSTEM —
/// the session credentials staged under a sandbox state directory must
/// not be readable by other local users just because the user-chosen
/// parent happens to have a permissive ACL. A failure refuses the
/// directory rather than leaving shared-readable state behind.
pub fn restrict_owner_only(dir: &Path) -> io::Result<()> {
    let meta = fs::symlink_metadata(dir)?;
    if meta.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("refusing to use symlink temp directory '{}'", dir.display()),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        let mode = fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(io::Error::other(format!(
                "failed to set owner-only permissions on '{}': mode {mode:o}",
                dir.display()
            )));
        }
    }
    #[cfg(windows)]
    restrict_owner_only_windows(dir)?;
    Ok(())
}

/// The Windows half of [`restrict_owner_only`]: replace `dir`'s DACL with
/// a protected one — no inherited entries — granting `GENERIC_ALL` to the
/// current process's user SID and to the local SYSTEM account. SYSTEM
/// stays in so OS-level services staging under the directory (a container
/// engine reading an exported policy mount, the Sandbox host stack) are
/// not locked out of data the product itself created. The entries inherit
/// to children, so files written later — including the relay credentials
/// under `ro/` — get the same restriction.
#[cfg(windows)]
fn restrict_owner_only_windows(dir: &Path) -> io::Result<()> {
    use std::ffi::c_void;

    use windows::Win32::Foundation::{CloseHandle, GENERIC_ALL, HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_IS_WELL_KNOWN_GROUP, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, CONTAINER_INHERIT_ACE, CreateWellKnownSid, DACL_SECURITY_INFORMATION,
        GetTokenInformation, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION, PSID,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{HSTRING, PWSTR};

    let os_err = |e: windows::core::Error| io::Error::other(e.to_string());

    // The session's own user SID via the process token — the ACE must
    // name the real user (an elevated process would otherwise grant the
    // Administrators group, not the account holding the credentials).
    let mut token = windows::Win32::Foundation::HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(os_err)?;
    let result = (|| {
        let mut need = 0u32;
        let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut need) };
        // TOKEN_USER contains a SID_AND_ATTRIBUTES pointer — the buffer
        // must be pointer-aligned, not merely byte-aligned.
        let mut user = vec![0usize; (need as usize).div_ceil(size_of::<usize>())];
        unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                Some(user.as_mut_ptr().cast()),
                need,
                &mut need,
            )
        }
        .map_err(os_err)?;
        // SAFETY: the buffer holds a TOKEN_USER whose Sid member points
        // into `user`, which outlives the ACL build below.
        let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };

        // SECURITY_MAX_SID_SIZE; CreateWellKnownSid fills caller memory,
        // nothing to free.
        let mut system = vec![0u8; 68];
        let mut size = system.len() as u32;
        unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                None,
                Some(PSID(system.as_mut_ptr().cast())),
                &mut size,
            )
        }
        .map_err(os_err)?;
        let system_sid = PSID(system.as_mut_ptr().cast());

        let inherit =
            windows::Win32::Security::ACE_FLAGS(CONTAINER_INHERIT_ACE.0 | OBJECT_INHERIT_ACE.0);
        let entry = |sid: PSID, trustee_type| EXPLICIT_ACCESS_W {
            grfAccessPermissions: GENERIC_ALL.0,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: inherit,
            Trustee: TRUSTEE_W {
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: trustee_type,
                ptstrName: PWSTR(sid.0 as *mut u16),
                ..Default::default()
            },
        };
        let entries = [
            entry(user_sid, TRUSTEE_IS_USER),
            entry(system_sid, TRUSTEE_IS_WELL_KNOWN_GROUP),
        ];
        let mut dacl: *mut ACL = std::ptr::null_mut();
        // A null old ACL builds a fresh list containing only our entries.
        unsafe { SetEntriesInAclW(Some(&entries), None, &mut dacl) }
            .ok()
            .map_err(os_err)?;
        // `\\?\` verbatim spellings fail the object-name lookup — strip
        // the prefix the same way the warden's grant path does.
        let text = dir.to_string_lossy();
        let name = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            format!(r"\\{rest}")
        } else {
            text.strip_prefix(r"\\?\").unwrap_or(&text).to_string()
        };
        let result = unsafe {
            SetNamedSecurityInfoW(
                &HSTRING::from(name),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        if !dacl.is_null() {
            unsafe {
                LocalFree(Some(HLOCAL(dacl as *mut c_void)));
            }
        }
        result.ok().map_err(os_err).map_err(|e| {
            io::Error::other(format!(
                "SetNamedSecurityInfoW for '{}': {e}",
                dir.display()
            ))
        })
    })();
    unsafe {
        let _ = CloseHandle(token);
    }
    result
}

/// What [`safe_copy_file`] did with one source entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafeCopyOutcome {
    /// Bytes copied from the verified open file.
    Copied(u64),
    /// A link or other non-regular entry — never followed, never copied.
    Skipped,
}

/// Deepest directory nesting [`safe_copy_dir`] recurses into before
/// refusing outright — a swapped link could otherwise loop the walk.
const MAX_COPY_DEPTH: usize = 64;

/// Open `src` without following a final-component link and copy it to
/// `dst`, but only while the opened object provably resolves inside
/// `canonical_root` (a `fs::canonicalize`d source directory).
///
/// The containment proof and the copy act on the same open handle, so a
/// pathname swapped for a link between the check and the read can never
/// pull in an out-of-tree file: the handle still names the object that
/// was verified. `Ok(SafeCopyOutcome::Skipped)` for links, devices,
/// pipes and other non-regular entries.
pub fn safe_copy_file(
    src: &Path,
    dst: &Path,
    canonical_root: &Path,
) -> io::Result<SafeCopyOutcome> {
    let Some(file) = open_no_follow(src)? else {
        return Ok(SafeCopyOutcome::Skipped);
    };
    let real = real_path_of(&file)?;
    if !real.starts_with(canonical_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing to copy '{}': resolves outside the staged root",
                src.display()
            ),
        ));
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut from = file;
    let mut out = fs::File::create(dst)?;
    let bytes = io::copy(&mut from, &mut out)?;
    // Carry the source mode (executables must stay executable).
    fs::set_permissions(dst, from.metadata()?.permissions())?;
    Ok(SafeCopyOutcome::Copied(bytes))
}

/// Recursively copy `src_dir`'s regular files into `dst_dir`, never
/// following links. Every leaf is verified by [`safe_copy_file`]: a
/// directory swapped for a link mid-walk cannot smuggle an out-of-tree
/// file in — its children fail the per-file containment proof even when
/// the enumeration itself was redirected. `skip_name` filters basenames
/// (e.g. `should_skip_build_entry`); `on_copied` receives each copied
/// file's byte count for callers enforcing size/count budgets.
pub fn safe_copy_dir(
    src_dir: &Path,
    dst_dir: &Path,
    canonical_root: &Path,
    depth: usize,
    skip_name: &dyn Fn(&str) -> bool,
    on_copied: &mut dyn FnMut(u64),
) -> io::Result<()> {
    if depth > MAX_COPY_DEPTH {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "directory nesting exceeds {MAX_COPY_DEPTH}: '{}'",
                src_dir.display()
            ),
        ));
    }
    fs::create_dir_all(dst_dir)?;
    for entry in fs::read_dir(src_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        if skip_name(&name.to_string_lossy()) {
            continue;
        }
        let kind = entry.file_type()?;
        let src = entry.path();
        let dst = dst_dir.join(&name);
        if kind.is_dir() {
            safe_copy_dir(&src, &dst, canonical_root, depth + 1, skip_name, on_copied)?;
        } else if kind.is_file() {
            match safe_copy_file(&src, &dst, canonical_root)? {
                SafeCopyOutcome::Copied(n) => on_copied(n),
                SafeCopyOutcome::Skipped => {}
            }
        }
        // Anything else — links, sockets, devices — is never followed.
    }
    Ok(())
}

/// Resolve `dir` for use as the `canonical_root` argument of the
/// safe-copy functions.
///
/// The root is resolved through the same handle-based primitive
/// [`real_path_of`] uses, so the containment `starts_with` compares
/// paths on one normalization basis. On Windows `fs::canonicalize`
/// expands 8.3 short-name components while `GetFinalPathNameByHandle`
/// keeps the spelling used at open — mixing the two either refuses
/// every copy or misjudges containment. Following links here is
/// correct: the user-supplied root resolves to its target, and every
/// leaf opened beneath it resolves through the same junction.
pub fn canonical_root(dir: &Path) -> io::Result<PathBuf> {
    let root = open_dir_handle(dir)?;
    real_path_of(&root)
}

/// Open a directory so [`real_path_of`] can resolve its true path.
#[cfg(unix)]
fn open_dir_handle(dir: &Path) -> io::Result<fs::File> {
    fs::File::open(dir)
}

/// Windows: directories need `FILE_FLAG_BACKUP_SEMANTICS` to open.
#[cfg(windows)]
fn open_dir_handle(dir: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(dir)
}

/// Read a whole file only when it fits within `limit` bytes — the read
/// is refused rather than truncated so analysis never silently runs on
/// a prefix. The metadata check is pre-allocated advice only: a file
/// grown past the check is still cut at `limit` and refused.
pub fn read_file_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    use std::io::Read;
    if fs::metadata(path)?.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file '{}' exceeds the {}-byte analysis limit",
                path.display(),
                limit
            ),
        ));
    }
    let mut bytes = Vec::new();
    let n = fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if n as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file '{}' exceeds the {}-byte analysis limit",
                path.display(),
                limit
            ),
        ));
    }
    Ok(bytes)
}

/// [`read_file_bounded`] for text inputs — the UTF-8 failure is the
/// same `InvalidData` error `fs::read_to_string` raises.
pub fn read_text_bounded(path: &Path, limit: u64) -> io::Result<String> {
    let bytes = read_file_bounded(path, limit)?;
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Open `path` for reading without following a final-component link.
/// `Ok(None)` when the entry is a link or other non-regular object.
/// `O_NONBLOCK` keeps a raced FIFO from blocking the open before the
/// file-type check can reject it.
#[cfg(unix)]
fn open_no_follow(path: &Path) -> io::Result<Option<fs::File>> {
    use std::os::unix::fs::OpenOptionsExt;
    match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(f) => {
            if f.metadata()?.is_file() {
                Ok(Some(f))
            } else {
                Ok(None)
            }
        }
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Windows: `FILE_FLAG_OPEN_REPARSE_POINT` opens the reparse point
/// itself rather than its target; the attributes then tell whether the
/// entry is a link/junction (skipped) or a real file.
#[cfg(windows)]
fn open_no_follow(path: &Path) -> io::Result<Option<fs::File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let meta = file.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !meta.is_file() {
        return Ok(None);
    }
    Ok(Some(file))
}

/// The real path of an open file — the same object the copy reads.
#[cfg(target_os = "linux")]
fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "macos")]
fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let rc = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    Ok(PathBuf::from(
        String::from_utf8_lossy(&buf[..end]).into_owned(),
    ))
}

#[cfg(windows)]
fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GETFINALPATHNAMEBYHANDLE_FLAGS, GetFinalPathNameByHandleW,
        VOLUME_NAME_DOS,
    };
    // FILE_NAME_NORMALIZED resolves every path component to its true
    // on-disk name — 8.3 short-name spellings, intermediate junctions
    // and case differences all collapse — so the containment
    // `starts_with` judges real locations, not open-time spellings.
    // Returns the `\\?\`-prefixed DOS path for the opened object.
    let mut buf = vec![0u16; 32 * 1024];
    let len = unsafe {
        GetFinalPathNameByHandleW(
            windows::Win32::Foundation::HANDLE(file.as_raw_handle() as _),
            &mut buf,
            GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0),
        )
    };
    if len == 0 || len as usize >= buf.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buf[..len as usize],
    )))
}

/// Names that must never be copied into a generated image context.
pub fn should_skip_build_entry(name: &str) -> bool {
    name.starts_with('.')
        || name == "node_modules"
        || name == "__pycache__"
        || name == "target"
        || name == ".git"
        || name == ".env"
        || name == ".venv"
        || name == "venv"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_tempdir_is_directory() {
        let dir = create_private_tempdir("test").unwrap();
        assert!(dir.is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn skip_nested_secrets() {
        assert!(should_skip_build_entry(".env"));
        assert!(should_skip_build_entry("node_modules"));
        assert!(!should_skip_build_entry("src"));
    }

    /// The Windows restriction is a real protected DACL — user + SYSTEM
    /// only — that children inherit, not a default-ACL no-op.
    #[cfg(windows)]
    #[test]
    fn windows_restriction_is_protected_owner_and_system_dacl() {
        use windows::Win32::Foundation::HLOCAL;
        use windows::Win32::Security::{
            ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        };
        use windows::core::HSTRING;

        let dir = create_private_tempdir("acl").unwrap();
        let child = dir.join("child.txt");
        fs::write(&child, "credentials").unwrap();

        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        unsafe {
            windows::Win32::Security::Authorization::GetNamedSecurityInfoW(
                &HSTRING::from(dir.to_string_lossy().as_ref()),
                windows::Win32::Security::Authorization::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            )
            .ok()
            .expect("DACL query");
            let mut control = 0u16;
            let mut revision = 0u32;
            windows::Win32::Security::GetSecurityDescriptorControl(sd, &mut control, &mut revision)
                .expect("SD control");
            assert_ne!(
                control & SE_DACL_PROTECTED.0,
                0,
                "session DACL must block inherited entries"
            );
            // SetEntriesInAclW splits each entry into a direct ACE and an
            // inherit-only (OI|CI|IO) ACE: user + SYSTEM twice over.
            assert_eq!((*dacl).AceCount, 4, "user + SYSTEM ACEs only");
            windows::Win32::Foundation::LocalFree(Some(HLOCAL(sd.0)));
        }
        // The restriction inherits to files created after it was applied.
        let mut child_dacl: *mut ACL = std::ptr::null_mut();
        let mut child_sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
        unsafe {
            windows::Win32::Security::Authorization::GetNamedSecurityInfoW(
                &HSTRING::from(child.to_string_lossy().as_ref()),
                windows::Win32::Security::Authorization::SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut child_dacl),
                None,
                &mut child_sd,
            )
            .ok()
            .expect("child DACL query");
            assert_eq!((*child_dacl).AceCount, 2, "children inherit the DACL");
            windows::Win32::Foundation::LocalFree(Some(HLOCAL(child_sd.0)));
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // ── safe_copy_file / safe_copy_dir ───────────────────────────────

    #[test]
    fn safe_copy_file_copies_contents() {
        let dir = create_private_tempdir("cp").unwrap();
        let src = dir.join("src.txt");
        fs::write(&src, b"payload bytes").unwrap();
        let dst = dir.join("nested").join("dst.txt");
        let root = canonical_root(&dir).unwrap();
        assert_eq!(
            safe_copy_file(&src, &dst, &root).unwrap(),
            SafeCopyOutcome::Copied(13)
        );
        assert_eq!(fs::read(&dst).unwrap(), b"payload bytes");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn safe_copy_file_refuses_outside_root() {
        let dir = create_private_tempdir("cp-out").unwrap();
        let outside = create_private_tempdir("cp-root").unwrap();
        let src = dir.join("src.txt");
        fs::write(&src, b"data").unwrap();
        let dst = outside.join("dst.txt");
        let wrong_root = canonical_root(&outside).unwrap();
        // A root that does not contain the source fails the containment
        // proof — the same check a swapped-in link trips.
        assert!(safe_copy_file(&src, &dst, &wrong_root).is_err());
        assert!(!dst.exists());
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&outside);
    }

    #[cfg(unix)]
    #[test]
    fn safe_copy_file_skips_symlink() {
        let dir = create_private_tempdir("cp-link").unwrap();
        let real = dir.join("real.txt");
        fs::write(&real, b"secret").unwrap();
        let link = dir.join("link.txt");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let dst = dir.join("dst.txt");
        let root = canonical_root(&dir).unwrap();
        assert_eq!(
            safe_copy_file(&link, &dst, &root).unwrap(),
            SafeCopyOutcome::Skipped
        );
        assert!(!dst.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn safe_copy_dir_skips_links_and_filtered_names() {
        let dir = create_private_tempdir("cpdir").unwrap();
        let src = dir.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("main.js"), "code").unwrap();
        fs::write(src.join("sub/helper.js"), "more").unwrap();
        fs::write(src.join(".env"), "SECRET=x").unwrap();
        std::os::unix::fs::symlink(&src, src.join("loop")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("evil")).unwrap();

        let dst = dir.join("dst");
        let root = canonical_root(&src).unwrap();
        safe_copy_dir(
            &src,
            &dst,
            &root,
            0,
            &|name| should_skip_build_entry(name),
            &mut |_| {},
        )
        .unwrap();

        assert!(dst.join("main.js").exists());
        assert!(dst.join("sub/helper.js").exists());
        assert!(!dst.join(".env").exists());
        assert!(!dst.join("loop").exists());
        assert!(!dst.join("evil").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_file_bounded_refuses_oversize() {
        let dir = create_private_tempdir("bounded").unwrap();
        let path = dir.join("f.bin");
        fs::write(&path, vec![0xABu8; 100]).unwrap();
        assert_eq!(read_file_bounded(&path, 100).unwrap().len(), 100);
        assert!(read_file_bounded(&path, 99).is_err());
        assert!(read_text_bounded(&path, 4).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
