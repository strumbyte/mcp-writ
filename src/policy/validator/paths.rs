//! FS-path spellings: normalization and subsumption for the allow/deny
//! lists. All comparisons run under explicit target-OS path rules - the
//! workload may target a different OS than the host running this check.

use crate::execution::TargetOs;

/// Normalize a filesystem path for allowlist/subpath comparison using the
/// path rules of the OS this process runs on. See `normalize_fs_pattern_for`.
pub fn normalize_fs_pattern(path: &str) -> String {
    normalize_fs_pattern_for(path, TargetOs::host())
}

/// Normalize a filesystem path for allowlist/subpath comparison under the
/// path rules of `os`:
/// - `\` counts as a separator only on Windows targets; on POSIX targets it
///   stays a literal filename character
/// - Strips trailing wildcards (e.g. '/**', '/*')
/// - Resolves '.' and '..' segments
/// - Strips trailing '/' (except root "/")
///
/// This is target-side *pattern* normalization — it never touches the host
/// filesystem (`pathutil` stays responsible for resolving host paths).
pub(crate) fn normalize_fs_pattern_for(path: &str, os: TargetOs) -> String {
    let unified = if os.separates_backslash() {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    let trimmed = if let Some(stripped) = unified.strip_suffix("/**") {
        stripped
    } else if let Some(stripped) = unified.strip_suffix("/*") {
        stripped
    } else {
        unified.trim_end_matches('*')
    };

    // Manual component walk: `std::path::Path::components` would apply the
    // *build host's* prefix/separator rules, which is exactly the mistake
    // this function must not make when validating for another OS. `/`
    // always separates here; a `X:` drive prefix is just a component.
    let mut segments: Vec<&str> = Vec::new();
    for seg in trimmed.split('/') {
        if seg.is_empty() {
            if segments.is_empty() {
                segments.push("");
            }
            continue;
        }
        if seg == "." {
            continue;
        }
        if seg == ".." {
            // `..` pops a regular segment but cannot climb past the
            // anchors: the root marker ("") or — on Windows targets — a
            // drive prefix (`C:`). Relative patterns collapse too, so
            // `a/../b` normalizes to `b`; popping only past index 1 would
            // leave the `a` behind.
            let anchored = segments
                .last()
                .is_some_and(|top| top.is_empty() || is_drive_prefix(top, os));
            if !anchored {
                segments.pop();
            }
            continue;
        }
        segments.push(seg);
    }
    if segments.is_empty() || (segments.len() == 1 && segments[0].is_empty()) {
        return "/".to_string();
    }
    segments.join("/")
}

/// `X:` drive-prefix component under the target's separator rules — a
/// `..` anchor on Windows targets only (`C:` is a normal component on
/// POSIX targets).
fn is_drive_prefix(seg: &str, os: TargetOs) -> bool {
    os.separates_backslash()
        && seg.len() == 2
        && seg.as_bytes()[0].is_ascii_alphabetic()
        && seg.as_bytes()[1] == b':'
}

/// Landlock rulesets are strictly additive within a layer (Linux Kernel documentation:
/// <https://docs.kernel.org/userspace-api/landlock.html#layers-of-file-path-access-rights>).
/// When a parent directory is allowed (or exact same path is allowed), a deny rule for a sub-path
/// beneath it cannot be carved out by Landlock. Such conflicting policies cannot provide kernel-level
/// confinement against compromised servers, so they are rejected at load/validation time.
///
/// Compatibility wrapper using the path rules of this process's OS; target-aware
/// validation goes through `is_strict_subpath_or_descendant_for`.
pub fn is_strict_subpath_or_descendant(allowed: &str, denied: &str) -> bool {
    is_strict_subpath_or_descendant_for(allowed, denied, TargetOs::host())
}

/// [`is_strict_subpath_or_descendant`] under the path rules of `os`.
pub(crate) fn is_strict_subpath_or_descendant_for(
    allowed: &str,
    denied: &str,
    os: TargetOs,
) -> bool {
    let a_norm = normalize_fs_pattern_for(allowed, os);
    let d_norm = normalize_fs_pattern_for(denied, os);

    // 1. Same entity / path collision: e.g. /data vs /data/**
    if path_components_equal(&a_norm, &d_norm, os) {
        return true;
    }

    // 2. Root allow covers everything
    if a_norm == "/" {
        return true;
    }

    // 3. Component-wise containment. `*` matches exactly one path component
    // so a wildcard allow such as `/data/*` detects denied descendants.
    path_covers(allowed, denied, os)
}

fn split_path_components(path: &str) -> Vec<&str> {
    path.split('/').filter(|part| !part.is_empty()).collect()
}

fn path_components_equal(left: &str, right: &str, os: TargetOs) -> bool {
    let l = split_path_components(left);
    let r = split_path_components(right);
    if l.len() != r.len() {
        return false;
    }
    l.iter().zip(r.iter()).all(|(a, b)| path_seg_eq(a, b, os))
}

/// Compare path components under the target's filesystem case rules:
/// case-insensitive on Windows and default-APFS macOS, case-sensitive
/// otherwise.
fn path_seg_eq(a: &str, b: &str, os: TargetOs) -> bool {
    if os.paths_case_insensitive() {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

pub(super) fn pattern_components(path: &str, os: TargetOs) -> Vec<String> {
    let unified = if os.separates_backslash() {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    let mut segments: Vec<String> = Vec::new();
    for comp in unified.split('/') {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            // Same anchor rule as `normalize_fs_pattern_for`: `..` cannot
            // pop a Windows drive prefix, so `C:/../x` stays rooted at the
            // `C:` component instead of collapsing to a relative `x`.
            if let Some(top) = segments.last()
                && !is_drive_prefix(top, os)
            {
                segments.pop();
            }
            continue;
        }
        segments.push(comp.to_string());
    }
    segments
}

/// True when the allow pattern covers the denied path.
///
/// `*` matches exactly one component. `**` matches the rest of the path.
/// A denied path that continues past a matched allow prefix is a descendant.
pub(super) fn path_covers(allowed: &str, denied: &str, os: TargetOs) -> bool {
    let allow_parts = pattern_components(allowed, os);
    let deny_parts = pattern_components(denied, os);
    if allow_parts.is_empty() {
        return false;
    }
    for (deny_index, allow_part) in allow_parts.iter().enumerate() {
        if allow_part == "**" {
            return true;
        }
        if deny_index >= deny_parts.len() {
            return false;
        }
        if allow_part != "*" && !path_seg_eq(allow_part, &deny_parts[deny_index], os) {
            return false;
        }
    }
    true
}
