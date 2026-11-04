//! Freshness stamps: the metadata recorded at hash time that lets a
//! held handle prove "unchanged" without a re-read — and the platform
//! rules for when that stamp may stand for the bytes and when it must
//! summon the digest instead.

use std::io;

/// The object's recorded state at hash time — re-fetched from the held
/// descriptor at spawn verification. A held fd does not block writers
/// on Unix, so an in-place rewrite of a pinned file leaves the identity
/// check green while carrying unverified bytes; the stamp catches it.
/// `recorded` is the wall clock at stamp time, not file state: it
/// bounds how fresh a ctime must look before the stamp may stand for
/// the bytes — see [`FileStamp::outside_timestamp_window`].
/// `ctime_kernel_owned` records whether the filesystem's clock is one
/// userspace cannot roll back — bookkeeping like `recorded`, not file
/// state, so `same_state` compares neither.
#[cfg(unix)]
#[derive(Clone, Copy)]
pub(crate) struct FileStamp {
    pub(crate) size: u64,
    pub(crate) mtime: i64,
    pub(crate) mtime_nsec: i64,
    pub(crate) ctime: i64,
    pub(crate) ctime_nsec: i64,
    pub(crate) recorded: std::time::SystemTime,
    pub(crate) ctime_kernel_owned: bool,
}

/// How stale a recorded ctime must be before a stamp may stand for the
/// object's bytes: a filesystem timestamp merges two writes that land
/// in the same tick, so a stamp whose recorded ctime sits inside one
/// granularity window of the wall clock at record time cannot prove a
/// same-tick rewrite did not merge into it. FAT-class filesystems tick
/// at 2 s — the bound covers the coarsest clock the pin can meet.
#[cfg(unix)]
const STAMP_GRANULARITY: std::time::Duration = std::time::Duration::from_secs(2);

/// The `f_type` values whose filesystems own their ctime: on a local,
/// kernel-managed filesystem the VFS bumps ctime on every change and
/// no userspace API rolls it back, so a stamp's recorded ctime can only
/// look unchanged when nothing was written. FUSE- and network-class
/// mounts report whatever their server fabricates, and vfat-class
/// mounts have no ctime at all (it mirrors the settable mtime) — both
/// let a rewrite restore the recorded stamp, so they are denied by
/// absence from this list, as is any magic not positively identified.
#[cfg(target_os = "linux")]
pub(crate) fn ftype_owns_ctime(magic: i128) -> bool {
    const EXT_SUPER: i128 = 0xEF53; // ext2/3/4
    const XFS: i128 = 0x5846_5342;
    const BTRFS: i128 = 0x9123_683E;
    const TMPFS: i128 = 0x0102_1994;
    const OVERLAYFS: i128 = 0x794C_7630;
    const F2FS: i128 = 0xF2F5_2010;
    const ZFS: i128 = 0x2FC1_2FC1;
    const JFS: i128 = 0x3153_464A;
    const REISERFS: i128 = 0x5265_4973;
    const BCACHEFS: i128 = 0xCA45_1A4E;
    const NILFS2: i128 = 0x3434;
    // Read-only filesystems: content cannot be rewritten at all, so the
    // stamp question is moot — trust their clock by construction.
    const SQUASHFS: i128 = 0x7371_7368;
    const EROFS: i128 = 0xE0F5_E1E0;
    matches!(
        magic,
        EXT_SUPER
            | XFS
            | BTRFS
            | TMPFS
            | OVERLAYFS
            | F2FS
            | ZFS
            | JFS
            | REISERFS
            | BCACHEFS
            | NILFS2
            | SQUASHFS
            | EROFS
    )
}

/// Whether the filesystem holding `file` owns its ctime — the guarantee
/// the stamp shortcut needs before the recorded ctime may stand for
/// the bytes. One `fstatfs` per stamp, no read.
#[cfg(target_os = "linux")]
pub(crate) fn ctime_clock_kernel_owned(file: &std::fs::File) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    if unsafe { libc::fstatfs(file.as_raw_fd(), buf.as_mut_ptr()) } != 0 {
        return false;
    }
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let buf = unsafe { buf.assume_init() };
    // `f_type` is signed on glibc and unsigned on musl — a widened
    // comparison keeps both spellings.
    ftype_owns_ctime(buf.f_type as i128)
}

/// Non-Linux Unix keeps no probe: the guarantee is unavailable, so the
/// stamp always falls to the re-hash path — the conservative behavior
/// this shortcut replaced.
#[cfg(all(unix, not(target_os = "linux")))]
fn ctime_clock_kernel_owned(_file: &std::fs::File) -> bool {
    false
}

#[cfg(unix)]
impl FileStamp {
    /// File-state equality — `recorded` and `ctime_kernel_owned` are
    /// bookkeeping about the stamp, not state, so neither is compared.
    fn same_state(&self, other: &FileStamp) -> bool {
        self.size == other.size
            && self.mtime == other.mtime
            && self.mtime_nsec == other.mtime_nsec
            && self.ctime == other.ctime
            && self.ctime_nsec == other.ctime_nsec
    }

    /// The recorded ctime as a `SystemTime`, when it converts.
    fn ctime_as_time(&self) -> Option<std::time::SystemTime> {
        use std::time::{Duration, UNIX_EPOCH};
        let nsec = self.ctime_nsec.clamp(0, 999_999_999) as u32;
        if self.ctime >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(self.ctime as u64, nsec))
        } else {
            UNIX_EPOCH.checked_sub(Duration::new(self.ctime.unsigned_abs(), nsec))
        }
    }

    /// Whether the stamp may stand for the object's bytes without a
    /// re-hash — true only when the filesystem owns its ctime (no
    /// userspace rollback) AND the recorded ctime sits more than
    /// [`STAMP_GRANULARITY`] behind the wall clock at record time, so
    /// any later write must land in a strictly newer tick and move the
    /// stamp. Without the clock guarantee, or inside the window where a
    /// same-tick rewrite could merge into the recorded tick, the caller
    /// must re-hash through the held handle and let the digest decide.
    pub(crate) fn outside_timestamp_window(&self) -> bool {
        self.ctime_kernel_owned
            && self.ctime_as_time().is_some_and(|ctime| {
                self.recorded
                    .duration_since(ctime)
                    .is_ok_and(|age| age > STAMP_GRANULARITY)
            })
    }
}

/// The recorded state of an open object at hash time. Unix keeps real
/// metadata; other platforms carry a zero-sized marker — a held share
/// mode already blocks writers there, and the identity re-check covers
/// retargeting. The marker is a named type rather than `()` so the
/// recorded-stamp bindings stay real values on every platform.
#[cfg(unix)]
pub(super) type OpenStamp = FileStamp;
#[cfg(not(unix))]
pub(super) struct OpenStamp;

#[cfg(unix)]
pub(super) fn record_stamp(file: &std::fs::File) -> io::Result<OpenStamp> {
    use std::os::unix::fs::MetadataExt;
    // Sample the wall clock first so `recorded` never post-dates the
    // state below — the window check only gets more conservative.
    let recorded = std::time::SystemTime::now();
    let m = file.metadata()?;
    Ok(FileStamp {
        size: m.size(),
        mtime: m.mtime(),
        mtime_nsec: m.mtime_nsec(),
        ctime: m.ctime(),
        ctime_nsec: m.ctime_nsec(),
        recorded,
        ctime_kernel_owned: ctime_clock_kernel_owned(file),
    })
}

#[cfg(not(unix))]
pub(super) fn record_stamp(_file: &std::fs::File) -> io::Result<OpenStamp> {
    Ok(OpenStamp)
}

#[cfg(unix)]
pub(super) fn stamp_unchanged(file: &std::fs::File, recorded: &OpenStamp) -> bool {
    record_stamp(file).is_ok_and(|stamp| stamp.same_state(recorded))
}

#[cfg(not(unix))]
pub(super) fn stamp_unchanged(_file: &std::fs::File, _recorded: &OpenStamp) -> bool {
    true
}

#[cfg(not(unix))]
impl OpenStamp {
    /// No granularity window to defend: the held share mode already
    /// blocks writers, so the stamp always stands.
    pub(super) fn outside_timestamp_window(&self) -> bool {
        true
    }
}
