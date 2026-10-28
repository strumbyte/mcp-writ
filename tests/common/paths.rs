//! Temp/audit paths and platform path spelling: the write-
//! restricted temp root, verbatim-prefix reduction, and the unique
//! audit-log path handed to spawned `mcp-writ run` processes.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

static AUDIT_DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
static AUDIT_SEQ: AtomicU64 = AtomicU64::new(0);

/// Real spelling of the system temp dir, resolving platform links such
/// as macOS's `/var` → `/private/var`. Paths under `$TMPDIR` are handed
/// to the spawned binary's audit sink, whose strict `O_NOFOLLOW`
/// ancestor walk refuses linked components — tests must spell them the
/// way the filesystem actually lays them out. The verbatim `\\?\`
/// prefix Windows canonicalize adds is stripped — device-namespace
/// spellings break `current_dir` and policy authorization.
pub fn real_temp_base() -> PathBuf {
    let base = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir()); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    plain_spelling(&base)
}

/// `tempfile::tempdir()` rooted at [`real_temp_base`].
pub fn real_tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .tempdir_in(real_temp_base())
        .expect("tempdir under the real temp base")
}

/// A `TempDir` under a root every ancestor of which passes the guard's
/// own replaceable-ancestry gate (`mcp_writ::fspriv::require_parent_write_restricted`).
/// The spawned binary evaluates the policy, audit, report, and
/// entrypoint paths its fixtures hand it through the same checks a
/// deployment runs — a shared %TEMP% or drvfs mount whose DACL grants
/// another principal replace access is refused by design, so fixtures
/// must live under a write-restricted root. `None` when no restricted
/// root exists; callers take the [`skip_e2e_test`] path.
/// Mirrors the crate-internal `testutil::restricted_tempdir`.
pub fn restricted_tempdir() -> Option<tempfile::TempDir> {
    let mut candidates = vec![real_temp_base()];
    for var in ["USERPROFILE", "HOME"] {
        if let Some(home) = std::env::var_os(var).map(PathBuf::from)
            && !candidates.contains(&home)
        {
            candidates.push(home);
        }
    }
    for base in candidates {
        // `tempdir_in` spells the returned path through `base` as given —
        // canonicalize it first so a linked env spelling cannot leave a
        // link component in the fixture path the ancestry walk inspects.
        let Ok(base) = base.canonicalize() else {
            eprintln!("restricted tempdir: cannot canonicalize {}", base.display());
            continue;
        };
        let base = plain_spelling(&base);
        #[cfg(windows)]
        if base.to_string_lossy().starts_with(r"\\") {
            eprintln!("restricted tempdir: {} is a UNC path", base.display());
            continue;
        }
        let dir = match tempfile::Builder::new().tempdir_in(&base) {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!(
                    "restricted tempdir: cannot create under {}: {e}",
                    base.display()
                );
                continue;
            }
        };
        let real = dir
            .path()
            .canonicalize()
            .unwrap_or_else(|_| dir.path().to_path_buf());
        // Inherited broad grants (a shared %TEMP%, an
        // `Authenticated Users:(OI)(CI)(M)` volume root) make the new
        // dir itself shared-writable — pin it owner-only first so the
        // ancestry probe below measures the parents, not inheritance.
        if let Err(e) = mcp_writ::fspriv::restrict_owner_only(&real) {
            eprintln!(
                "restricted tempdir: cannot restrict {}: {e}",
                real.display()
            );
            continue;
        }
        // Probe a *child* path so the fixture dir itself counts among
        // the ancestors the write-restriction walk inspects.
        if mcp_writ::fspriv::require_parent_write_restricted(&real.join("probe")).is_ok() {
            return Some(dir);
        }
    }
    None
}

/// Spell `posix` (a `/`-rooted test path) anchored on the filesystem
/// root of [`real_temp_base`] — `C:/x` on Windows, `/x` on unix — so
/// authorization resolution always hangs off a write-restricted root.
/// A bare `/x` qualifies to the *process* drive on Windows, and a
/// broad-writable root (a data volume's `Authenticated Users: Modify`)
/// makes `resolve_for_authorization` fail closed — correct, but it
/// makes a POSIX-literal test machine-dependent. Nothing is created or
/// stored under the temp dir; it is only read to locate that root.
/// Mirrors the crate-internal `pathutil::temp_root_abs`, which
/// `#[cfg(test)]` keeps out of reach for integration tests.
pub fn temp_root_abs(posix: &str) -> String {
    let anchor = real_temp_base()
        .ancestors()
        .last()
        .expect("temp dir has a filesystem root")
        .to_string_lossy()
        .replace('\\', "/");
    format!("{}{posix}", anchor.trim_end_matches('/'))
}

/// Unique fail-closed audit log path for spawned `mcp-writ run` processes.
pub fn next_audit_log_path() -> PathBuf {
    let dir = AUDIT_DIR.get_or_init(|| {
        tempfile::Builder::new()
            .prefix("mcp_writ_audit_")
            .tempdir_in(real_temp_base())
            .expect("failed to create audit log temp directory")
    });
    dir.path().join(format!(
        "audit-{}.jsonl",
        AUDIT_SEQ.fetch_add(1, Ordering::Relaxed)
    ))
}

/// Path to the compiled mcp-writ binary (from cargo build).
/// Strip a verbatim prefix, restoring the ordinary spelling:
/// `\\?\C:\x` → `C:\x` and `\\?\UNC\s\s\x` → `\\s\s\x`. The `\\?\UNC\`
/// case must be checked first — a bare `\\?\` strip would leave
/// `UNC\s\s\x`, which is not a path at all.
fn strip_verbatim(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else {
        s.strip_prefix(r"\\?\")
            .map(str::to_owned)
            .unwrap_or_else(|| s.to_owned())
    }
}

/// Ordinary drive-letter/share spelling of `p` (identity off Windows).
/// The authorization layer refuses device-namespace paths outright, so
/// a canonicalized path must be reduced before it reaches policy text
/// or a `PathBuf` consumer.
pub fn plain_spelling(p: &Path) -> PathBuf {
    PathBuf::from(strip_verbatim(&p.to_string_lossy()))
}

/// Policy-safe spelling of `p`: forward slashes and no `\\?\` verbatim
/// prefix. A canonicalized Windows path names the device namespace,
/// which the authorization layer refuses outright — reduce it before
/// it lands in a policy `allow` line.
pub fn policy_path_str(p: &Path) -> String {
    strip_verbatim(&p.to_string_lossy()).replace('\\', "/")
}
