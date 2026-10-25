//! Handle-bound filesystem primitives: opens that bind the *object*
//! rather than its spelling. A path raced to a link or a different
//! entry between a caller's check and the open cannot redirect the
//! returned handle, and [`real_path_of`] reports the same object's
//! true on-disk path — the basis every containment proof in this
//! module builds on.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Open `path` for reading without following a final-component link.
/// `Ok(None)` when the entry is a link or other non-regular object.
/// `O_NONBLOCK` keeps a raced FIFO from blocking the open before the
/// file-type check can reject it.
#[cfg(unix)]
pub(crate) fn open_no_follow(path: &Path) -> io::Result<Option<fs::File>> {
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
pub(crate) fn open_no_follow(path: &Path) -> io::Result<Option<fs::File>> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    // A missing path is an open error like on Unix — `Ok(None)` is
    // reserved for an entry that exists but is a link/non-regular.
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)?;
    let meta = file.metadata()?;
    if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 || !meta.is_file() {
        return Ok(None);
    }
    Ok(Some(file))
}

/// The real path of an open file — the same object the copy reads.
#[cfg(target_os = "linux")]
pub(crate) fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

#[cfg(target_os = "macos")]
pub(crate) fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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
pub(crate) fn real_path_of(file: &fs::File) -> io::Result<PathBuf> {
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
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

/// Open a directory so [`real_path_of`] can resolve its true path.
#[cfg(unix)]
pub(crate) fn open_dir_handle(dir: &Path) -> io::Result<fs::File> {
    fs::File::open(dir)
}

/// Windows: directories need `FILE_FLAG_BACKUP_SEMANTICS` to open.
#[cfg(windows)]
pub(crate) fn open_dir_handle(dir: &Path) -> io::Result<fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(dir)
}
