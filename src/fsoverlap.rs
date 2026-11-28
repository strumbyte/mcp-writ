//! Path-overlap checks for filesystem grant spellings: reduce a policy
//! path — possibly glob-suffixed, relative, or naming a file that does
//! not exist yet — to a comparable absolute path, then test whether one
//! spelling's subtree covers another.
//!
//! Used wherever a launch must prove a workload's write grants cannot
//! reach a protected path: the audit sink (`audit_log::sink_guard`) and
//! the cgroup-lifetime/control plane (`warden::cgroup`). Both are
//! fail-closed consumers — an unresolvable spelling is treated as
//! "cannot be proven disjoint", never as "safe".

use std::path::{Component, Path, PathBuf};

/// True when `grant` is `target` or an ancestor of it — a write grant
/// on `grant` reaches `target`. Component-wise comparison, so
/// `/var/log/audit` never covers `/var/log/audit.jsonl`; on Windows the
/// fold is case-insensitive (the filesystem is) and normalizes a
/// leading `\\?\`/`\\?\UNC\` verbatim prefix — a canonicalized path and
/// its plain spelling name the same object, so comparing only the
/// stored form would miss containment whenever one side is verbatim
/// and the other is not.
pub fn path_covers(grant: &Path, target: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        let fold = |p: &Path| {
            p.components()
                .enumerate()
                .map(|(i, c)| {
                    let s = c.as_os_str().to_string_lossy().to_lowercase();
                    if i == 0 {
                        // `\\?\UNC\srv\shr` ≡ `\\srv\shr`, `\\?\C:` ≡ `C:`.
                        if let Some(rest) = s.strip_prefix(r"\\?\unc\") {
                            return format!(r"\\{rest}");
                        }
                        s.strip_prefix(r"\\?\").map(String::from).unwrap_or(s)
                    } else {
                        s
                    }
                })
                .collect::<Vec<_>>()
        };
        let g = fold(grant);
        let t = fold(target);
        t.len() >= g.len() && t[..g.len()] == g[..]
    }
    #[cfg(not(target_os = "windows"))]
    {
        target.starts_with(grant)
    }
}

/// Reduce a grant/path spelling to a comparable absolute path:
/// trailing glob wildcards reduce to the real base directory (the same
/// reduction the Landlock/AppContainer/SBPL grant builders apply), the
/// result is absolutized against the cwd, and the deepest existing
/// ancestor is canonicalized so symlinks in the surviving prefix are
/// resolved on both sides. `None` when the spelling cannot be made
/// absolute or carries an unresolvable mid-path glob.
pub fn resolve_grant_spelling(spelling: &str) -> Option<PathBuf> {
    grant_spellings(spelling).map(|(resolved, _lexical)| resolved)
}

/// Both comparable spellings of a grant path: `(resolved, lexical)`.
/// The resolved form follows symlinks to the real directory; the
/// lexical form keeps the caller's written ancestors (`.`,`..`
/// collapsed, links unfollowed). A coverage check that also refuses a
/// protected path spelled *through* a writable link must compare like
/// with like on both forms — on hosts where an ancestor is a system
/// symlink (macOS `/var` → `/private/var`, `/tmp` → `/private/tmp`)
/// the two differ, and only the lexical-vs-lexical comparison names
/// the directory chain the caller wrote.
pub fn grant_spellings(spelling: &str) -> Option<(PathBuf, PathBuf)> {
    let base = glob_base(spelling)?;
    let path = Path::new(base);
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().ok()?.join(path)
    };
    Some((canonicalize_deep(&abs), lexical_normalize(&abs)))
}

/// Collapse `.`/`..` components lexically — no filesystem access, no
/// symlink resolution. The spelled path keeps its link components
/// verbatim so a comparison still names the directories a caller
/// spelled, not whatever the links point at today.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for c in path.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

/// Absolutize `path` against the cwd and collapse `.`/`..` — the
/// *spelled* form of the path, with no symlink resolution. Kept
/// alongside the canonical target wherever a protected-path check must
/// also refuse a symlink sitting inside a writable directory.
pub fn absolutize_lexical(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };
    lexical_normalize(&abs)
}

/// Canonicalize the deepest existing ancestor of `path` and rejoin the
/// remaining tail — equivalent to `canonicalize` when the path exists,
/// and a stable, symlink-resolved spelling for not-yet-created files.
/// Nonexistent prefixes stay as written.
fn canonicalize_deep(path: &Path) -> PathBuf {
    // Lexically collapse `.`/`..` first so the ancestor walk sees real
    // names even when intermediate components do not exist.
    let normalized = lexical_normalize(path);
    let mut probe = normalized.as_path();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match probe.canonicalize() {
            Ok(c) => {
                let mut out = c;
                for t in tail.iter().rev() {
                    out.push(t);
                }
                return out;
            }
            Err(_) => match probe.file_name() {
                Some(name) => {
                    tail.push(name.to_os_string());
                    match probe.parent() {
                        Some(p) => probe = p,
                        None => return normalized,
                    }
                }
                None => return normalized,
            },
        }
    }
}

/// True when terminal-glob stripping consumes the entire spelling
/// (`/*`, `/**`, `/*/*`…): the grant builders reduce such a root glob
/// to an empty base directory and skip it, so the spelling contributes
/// nothing to the workload's effective write surface. Distinguishes the
/// provably-empty case from a spelling that is merely unresolvable
/// (mid-path wildcards), which `glob_base` reports identically as
/// `None` — fail-closed consumers may skip the former but must keep
/// refusing the latter.
pub fn reduces_to_empty_base(spelling: &str) -> bool {
    let mut p = spelling;
    if p.is_empty() {
        return false;
    }
    loop {
        if let Some(rest) = p.strip_suffix("/**") {
            p = rest;
        } else if let Some(rest) = p.strip_suffix("/*") {
            p = rest;
        } else {
            break;
        }
        if p.is_empty() {
            return true;
        }
    }
    false
}

/// Strip trailing glob wildcards (`/**`, `/*`, a bare `*`) so the
/// comparison uses the real directory the grant builder would open —
/// the same reduction `landlock_impl`'s `landlock_base_path` performs.
/// `None` for empty spellings or mid-path wildcards (a glob that cannot
/// reduce to a base directory); callers treat `None` as "cannot be
/// proven disjoint".
pub fn glob_base(spelling: &str) -> Option<&str> {
    // The spelling is literal path content: trimming here would make a
    // trailing-space component indistinguishable from its unspaced sibling
    // (significant on Unix and inside a Windows `\?\` verbatim path).
    let mut p = spelling;
    if p.is_empty() {
        return None;
    }
    // Only whole-component terminal wildcards reduce to a base. A
    // partial-component star (`/a/foo*`) is a literal character under
    // the Auditor's grammar, not a prefix grant on `foo`.
    loop {
        if let Some(rest) = p.strip_suffix("/**") {
            p = rest;
            continue;
        }
        if let Some(rest) = p.strip_suffix("/*") {
            p = rest;
            continue;
        }
        break;
    }
    // The wildcard scan skips a Windows `\\?\` verbatim prefix: its `?`
    // is namespace syntax, never a glob component. The spelled form is
    // kept whole rather than re-spelled without the prefix — a stripped
    // `\\?\…\audit.` would resolve to the *different* object `…\audit`
    // (non-verbatim resolution normalizes the trailing dot), and
    // `\\?\Volume{guid}\…` would degrade to a relative path resolved
    // against the cwd. Keeping the prefix lets `canonicalize` resolve
    // the same object the caller pins or mounts.
    if p.is_empty() || p[verbatim_prefix_len(p)..].contains(['*', '?']) {
        None
    } else {
        Some(p)
    }
}

/// Byte length of a `\\?\` verbatim prefix, or 0 — only the NT
/// backslash form (`canonicalize`'s output spelling and the form the
/// Win32/NT object manager treats as verbatim) is skipped; a `/`-spelled
/// variant keeps its components visible to the wildcard check.
/// `\\?\UNC\…` is covered by the `\\?\` form: the `UNC\server\share`
/// body still names literal components.
#[cfg(target_os = "windows")]
fn verbatim_prefix_len(s: &str) -> usize {
    usize::from(s.starts_with(r"\\?\")) * 4
}

#[cfg(not(target_os = "windows"))]
fn verbatim_prefix_len(_s: &str) -> usize {
    0
}
