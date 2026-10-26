//! Helpers shared by `#[cfg(test)]` modules across the crate.

use std::path::PathBuf;

/// Real spelling of the system temp dir, resolving platform links such
/// as macOS's `/var` → `/private/var`. Paths under `$TMPDIR` are handed
/// to the audit sink and other strict `O_NOFOLLOW` ancestor walks, which
/// refuse any linked component — tests must spell them the way the
/// filesystem actually lays them out. The verbatim `\\?\` prefix Windows
/// canonicalize adds is stripped — device-namespace spellings break
/// `current_dir` and policy authorization.
/// Strip the verbatim `\\?\`/`\\?\UNC\` prefix Windows `canonicalize`
/// adds — device-namespace spellings break `current_dir` and policy
/// authorization.
#[cfg(windows)]
fn plain_spelling(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{rest}"))
    } else {
        s.strip_prefix(r"\\?\").map(PathBuf::from).unwrap_or(path)
    }
}

pub(crate) fn real_temp_base() -> PathBuf {
    let base = std::env::temp_dir() // nosemgrep: rust.lang.security.temp-dir.temp-dir
        .canonicalize()
        .unwrap_or_else(|_| std::env::temp_dir()); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    #[cfg(windows)]
    let base = plain_spelling(base);
    base
}

/// `tempfile::tempdir()` rooted at [`real_temp_base`].
pub(crate) fn real_tempdir() -> std::io::Result<tempfile::TempDir> {
    tempfile::Builder::new().tempdir_in(real_temp_base())
}

/// A `TempDir` under a root every ancestor of which passes
/// [`crate::fspriv::require_parent_write_restricted`] — the
/// authorization layer's own demand on any path a test asks it to
/// resolve. `%TEMP%` is not such a root on hosts that share it with
/// lower-trust workers (a sandbox fleet granting `Modify` on the temp
/// dir makes every fixture beneath it unauthorizable — the refusal is
/// the contract working, not a testable resolution). Falls back to the
/// user's home/profile directory — owner-locked by default on unix and
/// Windows alike — and returns `Ok(None)` when no restricted root
/// exists, which callers treat as "this environment cannot run the
/// test".
pub(crate) fn restricted_tempdir() -> std::io::Result<Option<tempfile::TempDir>> {
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
        // canonicalize it first so a symlinked env spelling (a linked
        // $HOME, macOS `/var` → `/private/var`) cannot leave a link
        // component in the fixture path `resolve_for_authorization`
        // walks.
        let Ok(base) = base.canonicalize() else {
            eprintln!("restricted tempdir: cannot canonicalize {}", base.display());
            continue;
        };
        #[cfg(windows)]
        let base = plain_spelling(base);
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
        if let Err(e) = crate::fspriv::restrict_owner_only(&real) {
            eprintln!(
                "restricted tempdir: cannot restrict {}: {e}",
                real.display()
            );
            continue;
        }
        // Probe a *child* path so the fixture dir itself counts among
        // the ancestors the write-restriction walk inspects.
        if crate::fspriv::require_parent_write_restricted(&real.join("probe")).is_ok() {
            return Ok(Some(dir));
        }
    }
    Ok(None)
}
