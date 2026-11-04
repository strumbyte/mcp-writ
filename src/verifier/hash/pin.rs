//! Spawn-time pinning for verified workload objects: hold the hashed
//! executable — and any payload-matched entrypoint script — open through
//! process creation so the launched object is the verified one. A
//! *native* image execs an immutable snapshot of the pinned bytes; an
//! interpreted payload launches through its real path — an interpreter
//! resolves its main module and its imports relative to that path, which
//! a snapshot spelling cannot carry — and the held pin's last-moment
//! re-check is the exec-time guarantee there.

use std::io;
use std::path::Path;
#[cfg(any(unix, windows))]
use std::path::PathBuf;

#[cfg(unix)]
use sha2::{Digest, Sha256};
use uuid::Uuid;

#[cfg(unix)]
use super::format_sha256;
use super::{VerifyError, VerifyResult, hash_file, hash_open_file};
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
type OpenStamp = FileStamp;
#[cfg(not(unix))]
struct OpenStamp;

#[cfg(unix)]
fn record_stamp(file: &std::fs::File) -> io::Result<OpenStamp> {
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
fn record_stamp(_file: &std::fs::File) -> io::Result<OpenStamp> {
    Ok(OpenStamp)
}

#[cfg(unix)]
fn stamp_unchanged(file: &std::fs::File, recorded: &OpenStamp) -> bool {
    record_stamp(file).is_ok_and(|stamp| stamp.same_state(recorded))
}

#[cfg(not(unix))]
fn stamp_unchanged(_file: &std::fs::File, _recorded: &OpenStamp) -> bool {
    true
}

#[cfg(not(unix))]
impl OpenStamp {
    /// No granularity window to defend: the held share mode already
    /// blocks writers, so the stamp always stands.
    fn outside_timestamp_window(&self) -> bool {
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

/// The verified launch workload — one held pin per binary/entrypoint
/// hash entry, minted as the entries verified: the kept-open object,
/// the stamp recorded before hashing, and the verified digest. Bind
/// and reverify consume these instead of re-reading the targets by
/// pathname — their freshness proof is the held object's identity plus
/// its stamp, with a content re-hash only when the object provably
/// changed (D-6). Entries that bind nothing at launch (lockfile and
/// docker-manifest hashes) are verified but held by no pin.
///
/// Pins are index-aligned with the `hash_entries` slice the workload
/// verified against — bind/reverify must be handed the same slice.
pub struct VerifiedWorkload {
    pins: Vec<(usize, HeldTarget)>,
}

/// A launch-identity target verified under a held handle — see
/// [`VerifiedWorkload`]. `digest` equals `expected` whenever the pin is
/// healthy: verify enforced it and every freshness re-check restores
/// the invariant or fails.
struct HeldTarget {
    hash_type: HashType,
    /// `entry.target` — the manifest spelling, reused as the error
    /// label; the pin was opened through it at verify.
    target: String,
    /// `entry.hash_value` — the pinned digest.
    expected: String,
    file: std::fs::File,
    stamp: OpenStamp,
    /// The held object's verified digest — `expected`, restated.
    digest: String,
}

impl HeldTarget {
    /// Open `path` pinned, stamp it, hash the held object, and prove
    /// the stamp held across the read — the pinless mint: callers
    /// without a workload re-establish the same anchor a
    /// [`VerifiedWorkload`] pin carries. `expected` is the computed
    /// digest itself — a bare mint verifies no pin, only freshness.
    fn open_fresh(
        path: &Path,
        hash_type: HashType,
        target: String,
    ) -> Result<Self, VerifyError> {
        let mut file = open_pinned(path).map_err(|error| VerifyError::FileError {
            hash_type,
            target: target.clone(),
            error,
        })?;
        let stamp = record_stamp(&file).map_err(|error| VerifyError::FileError {
            hash_type,
            target: target.clone(),
            error,
        })?;
        let digest = hash_open_file(&mut file).map_err(|error| VerifyError::FileError {
            hash_type,
            target: target.clone(),
            error,
        })?;
        if !stamp_unchanged(&file, &stamp) {
            return Err(VerifyError::Mismatch {
                hash_type,
                target,
                expected: "a consistent read of the pinned object".to_string(),
                actual: "file modified during hashing".to_string(),
            });
        }
        Ok(Self {
            hash_type,
            target,
            expected: digest.clone(),
            file,
            stamp,
            digest,
        })
    }

    /// Freshness without a read on the happy path: `path` must still
    /// name the held object and the object's stamp must hold — the
    /// verified digest stands. A retargeted `path` re-pins on the
    /// object it now names and re-hashes it — the pathname re-read
    /// judgment this check replaces, where identical bytes re-anchor
    /// the pin and anything else is a mismatch. A changed stamp falls
    /// back to a content re-hash through the held handle — the stamp
    /// only *detects*; the digest still decides (D-6).
    fn revalidate(&mut self, path: &Path) -> Result<(), VerifyError> {
        if !same_open_object(path, &self.file) {
            let mut file = open_pinned(path).map_err(|error| self.file_error(error))?;
            let stamp = record_stamp(&file).map_err(|error| self.file_error(error))?;
            let actual = hash_open_file(&mut file).map_err(|error| self.file_error(error))?;
            if actual != self.expected {
                return Err(self.mismatch(actual));
            }
            self.file = file;
            self.stamp = stamp;
            self.digest = actual;
            return Ok(());
        }
        // The stamp shortcut holds only when the recorded ctime is
        // provably older than the record window — a stamp inside the
        // filesystem's timestamp granularity cannot rule out a
        // same-tick rewrite, so it falls to the digest like any moved
        // stamp.
        if stamp_unchanged(&self.file, &self.stamp) && self.stamp.outside_timestamp_window() {
            return Ok(());
        }
        // A moved stamp re-reads through the held handle — stamp the
        // object *before* the read and prove the stamp held across it,
        // so a mid-read rewrite cannot anchor the pin on hybrid bytes.
        let pre = record_stamp(&self.file).map_err(|error| self.file_error(error))?;
        let actual = hash_open_file(&mut self.file).map_err(|error| self.file_error(error))?;
        if !stamp_unchanged(&self.file, &pre) {
            return Err(VerifyError::Mismatch {
                hash_type: self.hash_type,
                target: self.target.clone(),
                expected: "a consistent read of the pinned object".to_string(),
                actual: "file modified during hashing".to_string(),
            });
        }
        if actual != self.expected {
            return Err(self.mismatch(actual));
        }
        self.stamp = pre;
        self.digest = actual;
        Ok(())
    }

    /// The strict form of [`Self::revalidate`]: `path` must still name
    /// the *held* object — a retarget is a mismatch outright rather
    /// than a re-pin, for callers where re-anchoring would silently
    /// bind a different object than the pin covered. Stamp handling is
    /// unchanged: a changed stamp re-hashes and the digest decides.
    fn revalidate_held(&mut self, path: &Path) -> Result<(), VerifyError> {
        if !same_open_object(path, &self.file) {
            return Err(VerifyError::Mismatch {
                hash_type: self.hash_type,
                target: self.target.clone(),
                expected: "the pinned object".to_string(),
                actual: "pathname now resolves to a different object".to_string(),
            });
        }
        if stamp_unchanged(&self.file, &self.stamp) && self.stamp.outside_timestamp_window() {
            return Ok(());
        }
        let pre = record_stamp(&self.file).map_err(|error| self.file_error(error))?;
        let actual = hash_open_file(&mut self.file).map_err(|error| self.file_error(error))?;
        if !stamp_unchanged(&self.file, &pre) {
            return Err(VerifyError::Mismatch {
                hash_type: self.hash_type,
                target: self.target.clone(),
                expected: "a consistent read of the pinned object".to_string(),
                actual: "file modified during hashing".to_string(),
            });
        }
        if actual != self.expected {
            return Err(self.mismatch(actual));
        }
        self.stamp = pre;
        self.digest = actual;
        Ok(())
    }

    fn file_error(&self, error: io::Error) -> VerifyError {
        VerifyError::FileError {
            hash_type: self.hash_type,
            target: self.target.clone(),
            error,
        }
    }

    fn mismatch(&self, actual: String) -> VerifyError {
        VerifyError::Mismatch {
            hash_type: self.hash_type,
            target: self.target.clone(),
            expected: self.expected.clone(),
            actual,
        }
    }
}

impl Default for VerifiedWorkload {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifiedWorkload {
    /// An empty workload — [`Self::verify_server_hashes`] fills it.
    pub fn new() -> Self {
        Self { pins: Vec::new() }
    }

    /// `verify_server_hashes` over `server_name`'s entries, minting a
    /// held pin for each launch-identity target (binary and entrypoint
    /// hashes): the target opens pinned, stamps before hashing, and is
    /// hashed through the kept handle — handle, stamp, and digest all
    /// stay with the workload so later stages never re-read the object
    /// by path. Other entry types hash by path as before. The
    /// `hash.verified` / `hash.mismatch` audit events are emitted at
    /// this stage — the only place they are.
    pub fn verify_server_hashes(
        &mut self,
        server_name: &str,
        hash_entries: &[HashEntry],
        audit_logger: &AuditLogger,
    ) -> Result<VerifyResult, VerifyError> {
        let entries: Vec<(usize, &HashEntry)> = hash_entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.server_name == server_name)
            .collect();

        if entries.is_empty() {
            tracing::warn!(
                server = server_name,
                "No hash entries in policy for server; allowing startup"
            );
            return Ok(VerifyResult::NoEntries);
        }

        let correlation_id = Uuid::now_v7();

        for (i, entry) in entries {
            let target_path = Path::new(&entry.target);
            let outcome = if matches!(
                entry.hash_type,
                HashType::Binary | HashType::Entrypoint
            ) {
                HeldTarget::mint(entry, target_path)
                    .map(|held| (held.digest.clone(), Some(held)))
            } else {
                hash_file(target_path)
                    .map(|digest| (digest, None))
                    .map_err(|error| VerifyError::FileError {
                        hash_type: entry.hash_type,
                        target: entry.target.clone(),
                        error,
                    })
            };

            let (actual_hash, held) = match outcome {
                Ok(pair) => pair,
                Err(source) => {
                    let mut evt = AuditEvent::new(
                        correlation_id,
                        EventType::HashMismatch,
                        Severity::Critical,
                        Outcome::Failure,
                        Action::Denied,
                    );
                    evt.target_server = Some(server_name.to_string());
                    evt.details = Some(match &source {
                        VerifyError::Mismatch {
                            expected, actual, ..
                        } => format!(
                            "{} mismatch for '{}': expected {}, got {}",
                            entry.hash_type.as_str(),
                            entry.target,
                            expected,
                            actual
                        ),
                        VerifyError::FileError { error, .. } => format!(
                            "{} target '{}' unreadable: {}",
                            entry.hash_type.as_str(),
                            entry.target,
                            error
                        ),
                        VerifyError::UnboundWorkload { .. } => {
                            unreachable!("the verify stage never binds")
                        }
                    });
                    audit_logger.log(evt);
                    return Err(source);
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

            if let Some(held) = held {
                self.pins.push((i, held));
            }
        }

        Ok(VerifyResult::Verified)
    }

    /// The held pin minted for `hash_entries[index]` — `None` when the
    /// entry carries no launch identity (lockfile/docker) or the
    /// workload was verified against a different slice.
    fn pin_for(&mut self, index: usize) -> Option<&mut HeldTarget> {
        self.pins
            .iter_mut()
            .find(|(i, _)| *i == index)
            .map(|(_, held)| held)
    }

    /// Take the held pin minted for `hash_entries[index]` — the spawn
    /// pin consumes the handle outright.
    fn take_pin(&mut self, index: usize) -> Option<HeldTarget> {
        self.pins
            .iter()
            .position(|(i, _)| *i == index)
            .map(|pos| self.pins.remove(pos).1)
    }
}

impl HeldTarget {
    /// Mint the verify-stage pin for `entry`: open `path` on the
    /// replacement-preventing share mode (Windows) or the identity
    /// anchor fd (Unix), stamp it, hash the held object, and prove the
    /// stamp held across the read so a mid-read rewrite cannot mint a
    /// pin over hybrid bytes.
    fn mint(entry: &HashEntry, path: &Path) -> Result<Self, VerifyError> {
        let mut held = Self::open_fresh(path, entry.hash_type, entry.target.clone())?;
        held.expected = entry.hash_value.clone();
        Ok(held)
    }
}

/// After verifying configured hash entries, require the launched argv to
/// name those same objects — the verify-A-exec-B binding. A `binary-hash`
/// or `entrypoint-hash` target that canonicalizes to the resolved
/// executable is content-compared against the exe's digest; an
/// `entrypoint-hash` target matching the first payload argument is
/// re-hashed against its pin (`same_file` is path correspondence only,
/// so the payload match needs the content read).
///
/// `verified` carries the held pins `verify_server_hashes` minted — one
/// per binary/entrypoint target — and the content judgment becomes the
/// held object's identity plus its recorded stamp: a full read happens
/// only when the object provably changed (a retargeted path or a stale
/// stamp — the stamp never substitutes for the digest, it summons it).
/// `None` keeps the historical pathname re-hash for callers holding no
/// pins (`run-image`-style paths and pinless tests).
pub fn bind_launched_workload(
    argv: &[String],
    resolved_exe: &Path,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
    verified: Option<&mut VerifiedWorkload>,
) -> Result<(), VerifyError> {
    if hash_entries.is_empty() {
        return Ok(());
    }
    let mut verified = verified;

    let identity_entries: Vec<(usize, &HashEntry)> = hash_entries
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint))
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

    // The exe's content digest — read once up front for pinless
    // callers, as before (the eager read also surfaces an unreadable
    // exe as `FileError` even when no entry matches it). With a
    // workload each covering entry's held pin proves the same fact
    // without a read; a stray pinless entry still falls back lazily.
    let mut exe_hash: Option<String> = None;
    if verified.is_none() {
        exe_hash = Some(hash_file(resolved_exe).map_err(|error| {
            VerifyError::FileError {
                hash_type: HashType::Binary,
                target: resolved_exe.display().to_string(),
                error,
            }
        })?);
    }

    let mut matched_exe = false;
    let mut matched_binary = false;
    for &(i, entry) in &identity_entries {
        let target = Path::new(&entry.target);
        if !same_file(target, resolved_exe) {
            continue;
        }
        match verified.as_deref_mut().and_then(|w| w.pin_for(i)) {
            Some(pin) => pin.revalidate(resolved_exe)?,
            None => {
                let actual = match exe_hash.clone() {
                    Some(h) => h,
                    None => {
                        let h = hash_file(resolved_exe).map_err(|error| {
                            VerifyError::FileError {
                                hash_type: HashType::Binary,
                                target: resolved_exe.display().to_string(),
                                error,
                            }
                        })?;
                        exe_hash = Some(h.clone());
                        h
                    }
                };
                if entry.hash_value != actual {
                    return Err(VerifyError::Mismatch {
                        hash_type: entry.hash_type,
                        target: entry.target.clone(),
                        expected: entry.hash_value.clone(),
                        actual,
                    });
                }
            }
        }
        matched_exe = true;
        matched_binary |= entry.hash_type == HashType::Binary;
    }

    let has_binary = identity_entries
        .iter()
        .any(|(_, e)| e.hash_type == HashType::Binary);
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
    for &(i, entry) in identity_entries
        .iter()
        .filter(|(_, e)| e.hash_type == HashType::Entrypoint)
    {
        let target = Path::new(&entry.target);
        // An entrypoint pinned at the executable was covered in the
        // identity loop above. A payload match needs its own freshness
        // proof: `same_file` compares canonicalized paths only, so path
        // correspondence alone would let a script swapped in after the
        // first verification launch under the stale pin — the held
        // pin's stamp (or its re-hash when the stamp moves) decides, or
        // the historical pathname read for pinless callers.
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
            match verified.as_deref_mut().and_then(|w| w.pin_for(i)) {
                Some(pin) => pin.revalidate(target)?,
                None => {
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
/// the final identity re-check (Unix). The caller keeps it alive for
/// the session: on Windows the interpreter opens a pinned entrypoint
/// by path *after* CreateProcess, so the share-mode pin must outlive
/// that open; dropping it earlier reopens the hash-to-exec window.
///
/// On Unix the pin also mints `FdExecPlan`: the *executable* —
/// always the image the kernel maps (`resolve_launch` already expands
/// a `#!` `argv[0]` to its interpreter launch under a pin, so the
/// resolved exe is never itself a script payload) — execs the pinned
/// object's snapshot: an inherited `/proc/self/fd` descriptor on
/// Linux, the staged copy's path in its owner-only directory on the
/// other Unixes. The kernel maps the held object itself and the
/// pathname-to-exec race is closed, not merely narrowed. Linux dups
/// stay `CLOEXEC` in the parent; each spawn path clears the flag
/// inside its own `pre_exec`.
///
/// A payload-bound *entrypoint script* launches differently — through
/// its real path: an interpreter realpaths its main module and
/// resolves sibling/relative imports from its directory, so an fd
/// spelling (`/proc/self/fd/N` realpaths to `/memfd:… (deleted)` —
/// Node's `realpathSync` fails outright, and `--preserve-symlinks-main`
/// only moves the failure to the sibling imports) or a staged copy in
/// an empty directory cannot carry the launch. The script's exec-time
/// guarantee is `verify_spawn_path`'s same-object + stamp re-check as
/// the last gate before spawn, on a path the pin's
/// `require_trusted_source_file` gate proved no lower-trust principal
/// can swap or rewrite — or, on the Linux namespaced route, the
/// stronger anchoring the init helper gives that path inside its
/// mount namespace (the pinned object's bytes re-hashed, staged onto
/// the namespace's private tmpfs, and mounted over the path).
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

    /// An exe pin plus a payload-pinned entrypoint script — the shape
    /// `reverify_immediately_before_spawn` produces for an
    /// `interpreter script …` launch.
    pub(crate) fn for_test_with_entry(
        exe: std::fs::File,
        entry: std::fs::File,
        entry_path: std::path::PathBuf,
    ) -> Self {
        let mut this = Self::for_test(exe);
        let digest = hash_open_file(&mut entry.try_clone().expect("dup test entry"))
            .expect("hash test entry");
        this.entrypoint = Some(PinnedEntry {
            path: entry_path,
            stamp: record_stamp(&entry).expect("record entry stamp"),
            digest,
            file: entry,
        });
        this
    }
}

/// A payload-matched entrypoint script, held open across the spawn.
struct PinnedEntry {
    /// The path the interpreter's spawn opens — the argv payload
    /// spelling resolved against the launch's working directory with
    /// `.` components stripped (`..` is deliberately kept: a lexical
    /// parent pop can name a different object across symlinks, while
    /// `.` always resolves in place). The script also launches
    /// *through this path* (a snapshot spelling cannot carry an
    /// interpreter's module resolution), so this is the exec spelling
    /// `entrypoint_exec_arg` rewrites argv to — and, on the Linux
    /// namespaced route, the mount target the pin's staged copy is
    /// mounted over.
    path: std::path::PathBuf,
    file: std::fs::File,
    /// The `sha256:<hex>` the manifest pinned — handed to the
    /// namespaced init so its in-namespace digest re-check mounts
    /// bytes that match the pin exactly (the digest travels by env;
    /// the object's bytes travel the fd).
    #[cfg_attr(not(unix), allow(dead_code))]
    digest: String,
    stamp: OpenStamp,
}

impl SpawnPin {
    /// The last identity check before the spawn — proves each pinned
    /// path still resolves to the held (verified) object and that the
    /// object itself is unchanged since hashing. On Windows the held
    /// share mode already makes a swap fail; this also catches the
    /// Unix cases where a rename retargeted the path or a writer
    /// rewrote the pinned object between reverify and spawn.
    ///
    /// For a payload-bound entrypoint this re-check *is* the
    /// exec-time guarantee: the interpreter opens the script's real
    /// path after the spawn returns, and this is the last proof that
    /// path still names the verified object (the residual — the
    /// interpreter's `open(2)` itself — is the window every import the
    /// workload loads already lives at). The Linux namespaced route
    /// closes even that residual: init re-hashes the pinned object and
    /// mounts a verified copy over the path inside its mount
    /// namespace, so the spelling resolves to the pinned content for
    /// the whole session. For the executable image the
    /// pathname is not exec'd at all: `fd_exec_plan` names the
    /// hash-verified snapshot, so the kernel maps the held object —
    /// this check pins the *decision* (a retargeted path still fails
    /// the launch) while exec itself is immune to a swap. Keep this
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

    /// `(argv index, real path)` for a payload-bound entrypoint pin:
    /// the resolved spelling of the verified script the interpreter
    /// will open. Payloads are never snapshot-exec'd — an interpreter
    /// realpaths its main module and resolves imports relative to its
    /// directory, which an inherited-fd or staged-copy spelling cannot
    /// carry — so the exec spelling is the real path and the pin's
    /// `verify_spawn_path` re-check (plus, on Windows, the
    /// session-held share mode) is the exec-time guarantee.
    #[cfg(any(unix, windows))]
    fn entrypoint_exec_arg(
        &self,
        argv: &[String],
        resolved_exe: &Path,
    ) -> Result<Option<(usize, PathBuf)>, VerifyError> {
        let Some(entry) = &self.entrypoint else {
            return Ok(None);
        };
        // The argv position whose spelling resolved to the pinned
        // script — `exec_argv`/`entrypoint_exec_argv` rewrites it to
        // the resolved real path so the interpreter opens the object
        // the pin verified.
        let index =
            first_payload_arg_index_with_exe(argv, Some(resolved_exe)).ok_or_else(|| {
                VerifyError::UnboundWorkload {
                    executable: resolved_exe.display().to_string(),
                    reason: "entrypoint pinned but the payload argv position is lost".into(),
                }
            })?;
        Ok(Some((index, entry.path.clone())))
    }

    /// `true` when this pin carries a payload-matched entrypoint
    /// script — i.e. the launch is interpreted.
    pub fn has_pinned_entrypoint(&self) -> bool {
        self.entrypoint.is_some()
    }

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
#[cfg(unix)]
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
#[cfg(unix)]
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

#[cfg(windows)]
impl SpawnPin {
    /// `argv` with a payload-bound entrypoint re-spelled to the pinned
    /// script's resolved real path. Windows never staged the payload:
    /// the interpreter opens its main module by path *after*
    /// CreateProcess and resolves sibling/relative imports (and Node's
    /// `node_modules` ancestor walk) from its directory — a copy in an
    /// empty staging dir cannot carry those, the same reason a pinned
    /// entrypoint is never snapshot-exec'd on Unix. The pin — held for
    /// the session — is the exec-time guarantee instead: the
    /// `FILE_SHARE_READ`-only share mode keeps the object at the real
    /// path the verified one while the interpreter re-opens it.
    /// Fail-closed: a payload arg position that cannot be re-found
    /// under the modeled grammar refuses the launch.
    pub fn entrypoint_exec_argv(
        &self,
        argv: &[String],
        resolved_exe: &Path,
    ) -> Result<Vec<String>, VerifyError> {
        let mut out = argv.to_vec();
        if let Some((index, path)) = self.entrypoint_exec_arg(argv, resolved_exe)?
            && let Some(arg) = out.get_mut(index)
        {
            *arg = path.display().to_string();
        }
        Ok(out)
    }
}

/// The exec spellings for a pinned launch (Unix): the descriptor path
/// the child's `pre_exec` uncloaks for the executable snapshot, plus
/// the real path a pinned entrypoint script launches through. Holds
/// the duplicated `CLOEXEC` handles — the plan must outlive the
/// `Command::spawn` call it feeds.
#[cfg(unix)]
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

/// Strip a Windows verbatim (`\\?\`) prefix when the path can be
/// spelled in the ordinary form: `current_dir` returns verbatim
/// spelling, so a cwd-joined payload path would otherwise surface in
/// the child's argv as `\\?\C:\…` — a valid but poorly-tested
/// interpreter spelling. `\\?\C:\x` simplifies to `C:\x` and
/// `\\?\UNC\srv\shr\x` to `\\srv\shr\x`; any other verbatim form
/// keeps its prefix (it may be the only spelling that resolves).
/// Identity unchanged on non-Windows.
pub(super) fn simplify_verbatim(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut components = path.components();
        let base = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::VerbatimDisk(drive) => Some(format!("{}:", drive as char)),
                Prefix::VerbatimUNC(server, share) => Some(format!(
                    "\\\\{}\\{}",
                    server.to_string_lossy(),
                    share.to_string_lossy()
                )),
                _ => None,
            },
            _ => None,
        };
        if let Some(base) = base {
            let mut out = PathBuf::from(base);
            out.extend(components);
            return out;
        }
    }
    path
}

/// Re-run the binding checks immediately before spawn — the launched
/// executable and any payload-matched entrypoint script re-prove the
/// pin once more, so a file swapped in after the initial verification
/// fails closed. With a `VerifiedWorkload` the proof is the held
/// object's identity plus its recorded stamp — the verified digest
/// stands without a read, and only an object that provably changed
/// (retargeted path or moved stamp) is re-hashed, the stamp summoning
/// the digest check rather than replacing it. Pinless callers get the
/// historical re-hash mint.
///
/// The returned [`SpawnPin`] keeps the verified objects open through
/// the spawn — and for the session: on Windows the share mode makes
/// modification/rename fail while held, and since a pinned entrypoint
/// is opened by its real path *after* CreateProcess, that hold is the
/// pin's exec-time guarantee there. On Unix the executable execs
/// through `SpawnPin::fd_exec_plan`'s hash-verified snapshot
/// (`/proc/self/fd` descriptor spelling on Linux, staged owner-only
/// copy elsewhere) so the kernel maps the held object itself, while a
/// payload-bound entrypoint launches by its real path — the same gate
/// every runtime import stands at, except on the Linux namespaced
/// route where init mounts a re-verified copy of the pinned bytes
/// over that path — with `verify_spawn_path`'s identity re-check
/// last so a retargeted path fails the launch rather than silently
/// mismatching `argv`'s own resolution. Code the workload loads at
/// run time stays unpinned.
///
/// `entrypoint_mount_handoff` marks that namespaced route: the caller
/// asserts init will bind the verified copy over the script's path
/// inside the child's mount namespace, so the host-side trusted-source
/// contract is not load-bearing for this launch and is skipped (the
/// pin, freshness proof, and mount handoff still bind the bytes).
/// Every other route passes `false` and keeps the full gate.
pub fn reverify_immediately_before_spawn(
    argv: &[String],
    resolved_exe: &Path,
    hash_entries: &[HashEntry],
    audit_logger: &AuditLogger,
    entrypoint_mount_handoff: bool,
    verified: Option<&mut VerifiedWorkload>,
) -> Result<SpawnPin, VerifyError> {
    let mut verified = verified;
    bind_launched_workload(
        argv,
        resolved_exe,
        hash_entries,
        audit_logger,
        verified.as_deref_mut(),
    )?;
    #[cfg(not(unix))]
    let _ = entrypoint_mount_handoff;

    let identity_entries: Vec<(usize, &HashEntry)> = hash_entries
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e.hash_type, HashType::Binary | HashType::Entrypoint))
        .collect();

    // The spawn pin anchors on the held handle the verify stage minted
    // for the first entry covering the resolved exe (bind already
    // proved a cover exists whenever pins bind this launch). Without a
    // workload the exe is opened pinned and hashed here — the
    // historical mint.
    let covering = identity_entries
        .iter()
        .map(|(i, _)| *i)
        .find(|i| same_file(Path::new(&hash_entries[*i].target), resolved_exe));
    let mut exe_held = match covering
        .and_then(|i| verified.as_deref_mut().and_then(|w| w.take_pin(i)))
    {
        Some(pin) => pin,
        None => HeldTarget::open_fresh(
            resolved_exe,
            HashType::Binary,
            resolved_exe.display().to_string(),
        )?,
    };
    // Freshness at mint: the held object must still digest to the pin
    // — identity plus stamp decide on the happy path; an object that
    // provably changed re-hashes through the held handle (the stamp
    // summons the digest check, it does not substitute for it — D-6).
    exe_held.revalidate_held(resolved_exe)?;
    for &(_, entry) in &identity_entries {
        if same_file(Path::new(&entry.target), resolved_exe) && entry.hash_value != exe_held.digest {
            return Err(VerifyError::Mismatch {
                hash_type: entry.hash_type,
                target: entry.target.clone(),
                expected: entry.hash_value.clone(),
                actual: exe_held.digest.clone(),
            });
        }
    }

    // A payload-matched entrypoint gets the same anchored treatment —
    // an interpreter's spawn opens the script by pathname, so the held
    // handle is what `verify_spawn_path` re-checks identity against.
    let mut entrypoint = None;
    for &(i, entry) in identity_entries
        .iter()
        .filter(|(_, e)| e.hash_type == HashType::Entrypoint)
    {
        let target = Path::new(&entry.target);
        // The interpreter opens the argv spelling, not the manifest
        // target — resolve it the way the child's spawn does (a
        // relative path lands on the working directory the child
        // inherits) so the held handle and the re-check follow the
        // path the launch actually opens. `.` components are stripped
        // so the exec spelling (and the namespaced bind-mount target)
        // is a clean path; `..` stays — popping it lexically could
        // name a different object across symlinks, while `.` always
        // resolves in place.
        let payload_path = first_payload_arg_with_exe(argv, Some(resolved_exe)).map(|arg| {
            let path = Path::new(arg);
            let joined = match std::env::current_dir() {
                Ok(cwd) if path.is_relative() => cwd.join(path),
                _ => path.to_path_buf(),
            };
            // `.` components normalize away (a leading one too — the
            // path is absolute after the join); `..` stays literal.
            simplify_verbatim(joined.components().collect::<PathBuf>())
        });
        let payload_match = payload_path.as_ref().is_some_and(|p| same_file(p, target));
        if !payload_match || same_file(target, resolved_exe) {
            continue;
        }
        let payload_path = payload_path.expect("payload_match implies a payload arg");
        // The interpreter re-opens the script by path *after* the
        // spawn — the held fd cannot close that residual natively
        // (the Linux namespaced route mounts a re-verified copy over
        // the path; Windows's held share mode blocks every mutation).
        // On a native Unix launch the guarantee that the child's open
        // sees the verified bytes is that no lower-trust principal can
        // swap the path nor rewrite the object between
        // `verify_spawn_path` and that open — the file must be
        // owner/root-owned without group/other write, and every
        // ancestor of the *spelled* payload path — the chain the
        // interpreter's open re-traverses — as well as the resolved
        // object's chain must deny untrusted replacement, the same
        // contract a policy source stands under. A script a
        // lower-trust principal could replace carries unverified
        // bytes past the pin — refuse rather than narrow the window.
        // The Linux namespaced route is the documented exception:
        // init's verified bind-mount over the path closes the window
        // without a permission argument, so the gate is skipped
        // there.
        #[cfg(unix)]
        if !entrypoint_mount_handoff {
            crate::fspriv::require_trusted_source_file(&payload_path).map_err(|error| {
                VerifyError::FileError {
                    hash_type: HashType::Entrypoint,
                    target: entry.target.clone(),
                    error,
                }
            })?;
        }
        let held = match verified
            .as_deref_mut()
            .and_then(|w| w.take_pin(i))
        {
            // The pin was minted on the manifest target; the child's
            // spawn opens the argv spelling — it must still name the
            // verified object (strict — the historical gate does not
            // re-anchor here either), then the stamp holds or the
            // held-handle re-hash decides.
            Some(mut pin) => {
                pin.revalidate_held(&payload_path)?;
                pin
            }
            // No held pin (pinless caller): open the argv spelling
            // pinned, prove it names the manifest object, then hash
            // the held bytes — the historical mint.
            None => {
                let mut file =
                    open_pinned(&payload_path).map_err(|error| VerifyError::FileError {
                        hash_type: HashType::Entrypoint,
                        target: entry.target.clone(),
                        error,
                    })?;
                let stamp = record_stamp(&file).map_err(|error| VerifyError::FileError {
                    hash_type: HashType::Entrypoint,
                    target: entry.target.clone(),
                    error,
                })?;
                if !same_open_object(target, &file) {
                    return Err(VerifyError::Mismatch {
                        hash_type: HashType::Entrypoint,
                        target: entry.target.clone(),
                        expected: "the manifest entrypoint object".to_string(),
                        actual: "argv payload path resolves to a different object".to_string(),
                    });
                }
                let digest = hash_open_file(&mut file).map_err(|error| {
                    VerifyError::FileError {
                        hash_type: HashType::Entrypoint,
                        target: entry.target.clone(),
                        error,
                    }
                })?;
                if digest != entry.hash_value {
                    return Err(VerifyError::Mismatch {
                        hash_type: HashType::Entrypoint,
                        target: entry.target.clone(),
                        expected: entry.hash_value.clone(),
                        actual: digest,
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
                HeldTarget {
                    hash_type: HashType::Entrypoint,
                    target: entry.target.clone(),
                    expected: entry.hash_value.clone(),
                    file,
                    stamp,
                    digest,
                }
            }
        };
        entrypoint = Some(PinnedEntry {
            path: payload_path,
            file: held.file,
            digest: entry.hash_value.clone(),
            stamp: held.stamp,
        });
    }

    Ok(SpawnPin {
        exe: exe_held.file,
        exe_stamp: exe_held.stamp,
        exe_digest: exe_held.digest,
        entrypoint,
    })
}
