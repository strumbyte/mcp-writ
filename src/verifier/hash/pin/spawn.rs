//! The reverify stage and the spawn pin it mints: the verified
//! workload objects re-proved immediately before spawn and held open
//! through it — the executable, and any payload-matched entrypoint
//! script launching through its real path.

use std::path::Path;
#[cfg(any(unix, windows))]
use std::path::PathBuf;

use crate::audit_log::AuditLogger;
use crate::policy::{HashEntry, HashType};
use crate::verifier::hash::{VerifyError, hash_open_file};
#[cfg(any(unix, windows))]
use crate::workload::first_payload_arg_index_with_exe;
use crate::workload::{first_payload_arg_with_exe, same_file};

use super::anchor::{open_pinned, same_open_object};
use super::bind::bind_launched_workload;
use super::stamp::{OpenStamp, record_stamp, stamp_unchanged};
use super::workload::{HeldTarget, VerifiedWorkload};

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
    pub(super) exe: std::fs::File,
    pub(super) exe_stamp: OpenStamp,
    /// The digest the exe's bytes hashed to under the held handle —
    /// [`fd_exec_plan`] re-hashes its sealed snapshot against this so
    /// an in-place rewrite between hashing and snapshotting fails
    /// closed instead of launching unverified bytes.
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) exe_digest: String,
    pub(super) entrypoint: Option<PinnedEntry>,
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
pub(super) struct PinnedEntry {
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
    pub(super) path: std::path::PathBuf,
    pub(super) file: std::fs::File,
    /// The `sha256:<hex>` the manifest pinned — handed to the
    /// namespaced init so its in-namespace digest re-check mounts
    /// bytes that match the pin exactly (the digest travels by env;
    /// the object's bytes travel the fd).
    #[cfg_attr(not(unix), allow(dead_code))]
    pub(super) digest: String,
    pub(super) stamp: OpenStamp,
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
    pub(super) fn entrypoint_exec_arg(
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

/// Strip a Windows verbatim (`\\?\`) prefix when the path can be
/// spelled in the ordinary form: `current_dir` returns verbatim
/// spelling, so a cwd-joined payload path would otherwise surface in
/// the child's argv as `\\?\C:\…` — a valid but poorly-tested
/// interpreter spelling. `\\?\C:\x` simplifies to `C:\x` and
/// `\\?\UNC\srv\shr\x` to `\\srv\shr\x`; any other verbatim form
/// keeps its prefix (it may be the only spelling that resolves).
/// Identity unchanged on non-Windows.
pub(crate) fn simplify_verbatim(path: PathBuf) -> PathBuf {
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
