//! Pin anchoring primitives: the pinned open that holds a verified
//! object through process creation, and the held-object identity check
//! every spawn path runs before exec'ing a pinned pathname.

use std::io;
use std::path::Path;

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
pub(super) fn same_open_object(path: &Path, file: &std::fs::File) -> bool {
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
