//! Path identity helpers shared by Auditor authorization and policy validation.
//!
//! Authorization is performed on a resolved path (cwd-joined, lexically
//! normalized, and canonicalized when the object exists) rather than on the
//! original attacker-controlled string.

use std::net::Ipv4Addr;
use std::path::{Component, Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

/// Resolve `path` to the filesystem object the child would open from the
/// current working directory.
///
/// Relative `..` is applied against the cwd, not discarded. Symlinks are
/// followed when the path (or its nearest existing ancestor) exists.
pub fn resolve_for_authorization(path: &str) -> Result<String, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("cwd unavailable: {e}"))?;
    resolve_for_authorization_with_cwd(path, &cwd)
}

/// Like [`resolve_for_authorization`], but resolves relative paths against
/// `cwd` instead of the process working directory.
///
/// Diagnostics and tests use this to reproduce the Auditor's interpretation
/// for a child process whose working directory differs from the caller's.
/// In production the child inherits the guard's cwd, so both are identical.
pub fn resolve_for_authorization_with_cwd(path: &str, cwd: &Path) -> Result<String, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("empty or NUL-containing path".to_string());
    }
    let unified = unify_separators(path);
    // `\\server\share`, `//host/x`, and the `\\?\`/`\\.\` device
    // namespaces (all `//…` after separator unification) name objects a
    // host filesystem touch would resolve over the network — refuse
    // before any lookup rather than let authorization dial SMB.
    if cfg!(windows) && unified.starts_with("//") {
        return Err("UNC and device-namespace paths are not authorizable \
                    without a host filesystem touch"
            .to_string());
    }
    let joined = join_with(path, cwd)?;
    let mut lexical = lexical_normalize_path(&joined)?;
    // A root-relative `/foo` opens from the current drive on Windows —
    // qualify to that drive so deny matching and reparse-aware
    // canonicalization see the same object identity the child opens.
    // `/D:/x` spellings already carried their drive through
    // `lexical_normalize_path`; qualifying again would corrupt them.
    if cfg!(windows) && is_posix_absolute(&unified) && !lexical.is_absolute() {
        lexical = windows_drive_qualify(&lexical, cwd)?;
    }
    reject_replaceable_components(&lexical)?;
    let resolved = match std::fs::canonicalize(&lexical) {
        Ok(canon) => canon,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            resolve_via_existing_ancestor(&lexical)?
        }
        Err(e) => {
            return Err(format!(
                "path resolution failed for '{}': {e}",
                lexical.display()
            ));
        }
    };
    // The auditor forwards a string, not a handle — the authorization
    // cannot outlive a component another principal can swap, so every
    // ancestor of the resolved object must be write-restricted. Same-
    // principal mutation is irreducible without handle passing and is
    // the documented residual of this boundary. Operators who keep
    // workspaces under intentionally group-shared trees can accept the
    // swap race explicitly via `MCP_WRIT_ALLOW_REPLACEABLE_PATHS`.
    if !replaceable_paths_permitted() {
        crate::fspriv::require_parent_write_restricted(&resolved).map_err(|e| {
            format!(
                "path '{}' resolves through a replaceable component: {e} \
                 (set MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1 to accept the \
                 rename-swap race on every authorized path)",
                lexical.display()
            )
        })?;
    }
    Ok(to_match_string(&resolved))
}

/// The operator opt-out for the replaceable-ancestor refusal above:
/// `MCP_WRIT_ALLOW_REPLACEABLE_PATHS=1` restores pre-hardening behavior
/// — authorization binds a resolved *spelling* that a group- or
/// world-writable ancestor can retarget between the check and the
/// child's independent open. It exists for deployments that
/// deliberately run under group-shared trees; every authorized path
/// then carries the swap race. The symlink-component check
/// (`reject_replaceable_components`) is not covered — a retargetable
/// link is refused either way.
/// Spell `posix` (a `/`-rooted test path) anchored on the temp tree's
/// filesystem root — `C:/x` on Windows, `/x` on unix — so resolution
/// always hangs off a write-restricted root. A bare `/x` qualifies to
/// the *process* drive on Windows, and a broad-writable root (a data
/// volume's `Authenticated Users: Modify`) makes
/// [`resolve_for_authorization`] fail closed — the refusal is correct,
/// but it makes a POSIX-literal test machine-dependent.
#[cfg(test)]
pub(crate) fn temp_root_abs(posix: &str) -> String {
    let anchor = std::env::temp_dir()
        .ancestors()
        .last()
        .expect("temp dir has a filesystem root")
        .to_string_lossy()
        .replace('\\', "/");
    let anchor = anchor.strip_prefix("//?/").unwrap_or(&anchor);
    format!("{}{posix}", anchor.trim_end_matches('/'))
}

fn replaceable_paths_permitted() -> bool {
    std::env::var_os("MCP_WRIT_ALLOW_REPLACEABLE_PATHS").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Refuse a spelled path whose symlink components sit under a shared-
/// writable directory. The check binds a path string for only an
/// instant; a link a non-owner can retarget (or an attacker-owned link
/// in a sticky directory) lands the child's independent open on an
/// object policy never saw.
fn reject_replaceable_components(path: &Path) -> Result<(), String> {
    let mut cursor = PathBuf::new();
    for component in path.components() {
        match component {
            // Volumes and roots have no parent a rename could attack.
            Component::Prefix(_) | Component::RootDir => {
                cursor.push(component.as_os_str());
                continue;
            }
            _ => cursor.push(component.as_os_str()),
        }
        let Ok(meta) = std::fs::symlink_metadata(&cursor) else {
            continue;
        };
        if !meta.file_type().is_symlink() {
            continue;
        }
        let Some(parent) = cursor.parent() else {
            continue;
        };
        match crate::fspriv::dir_shared_writable(parent) {
            Ok(true) => {
                return Err(format!(
                    "component '{}' is a symbolic link under shared-writable '{}' \
                     — it can be retargeted after authorization",
                    cursor.display(),
                    parent.display()
                ));
            }
            Ok(false) => {}
            Err(e) => {
                return Err(format!(
                    "cannot verify the parent of link '{}': {e}",
                    cursor.display()
                ));
            }
        }
    }
    Ok(())
}

/// Map a root-relative `/x` spelling onto the current drive (`C:/x`) —
/// the object the child actually opens on Windows. A non-drive-qualified
/// cwd (UNC share or bare root) gives no local volume to qualify
/// against, so the spelling is refused rather than guessed.
fn windows_drive_qualify(lexical: &Path, cwd: &Path) -> Result<PathBuf, String> {
    let drive = cwd
        .components()
        .next()
        .and_then(|c| match c {
            Component::Prefix(p) => Some(p.as_os_str().to_string_lossy().into_owned()),
            _ => None,
        })
        .filter(|p| p.len() == 2 && p.ends_with(':'));
    let Some(drive) = drive else {
        return Err("root-relative path has no local drive to qualify against".to_string());
    };
    Ok(PathBuf::from(format!(
        "{drive}{}",
        lexical.to_string_lossy()
    )))
}

/// Canonicalize the nearest existing ancestor, then append every missing
/// component in order. This closes symlink escapes that skip intermediate
/// existing links when two or more trailing components are absent.
fn resolve_via_existing_ancestor(lexical: &Path) -> Result<PathBuf, String> {
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    let mut current = lexical.to_path_buf();
    loop {
        match std::fs::canonicalize(&current) {
            Ok(canon) => {
                let mut out = canon;
                for part in suffix.iter().rev() {
                    out.push(part);
                }
                return Ok(out);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(name) = current.file_name() else {
                    return Ok(lexical.to_path_buf());
                };
                suffix.push(name.to_os_string());
                if !current.pop() {
                    return Ok(lexical.to_path_buf());
                }
            }
            Err(e) => {
                return Err(format!(
                    "path resolution failed for '{}': {e}",
                    current.display()
                ));
            }
        }
    }
}

/// Join a possibly-relative path with the process cwd. Absolute paths are
/// returned unchanged (after `\` → `/` unification on the original).
///
/// POSIX-style roots (`/workspace/...`) stay POSIX even on Windows. Windows
/// treats a leading `/` as “current drive”, which would turn policy paths into
/// `D:/workspace` and break allow/deny matching.
pub fn join_with_cwd(path: &str) -> Result<PathBuf, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("cwd unavailable: {e}"))?;
    join_with(path, &cwd)
}

/// Join a possibly-relative path with an explicit base directory.
fn join_with(path: &str, cwd: &Path) -> Result<PathBuf, String> {
    let unified = unify_separators(path);
    if is_posix_absolute(&unified) {
        return Ok(PathBuf::from(&unified));
    }
    let p = PathBuf::from(&unified);
    if p.is_absolute() {
        return Ok(p);
    }
    Ok(cwd.join(p))
}

fn unify_separators(path: &str) -> String {
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.to_string()
    }
}

fn is_posix_absolute(path: &str) -> bool {
    path.starts_with('/') && !path.starts_with("//")
}

/// Lexically resolve `.` and `..` on an absolute or cwd-joined path.
/// `..` never silently disappears at a relative root; it pops a real
/// component or stays at the filesystem root.
pub fn lexical_normalize_path(path: &Path) -> Result<PathBuf, String> {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(p) => {
                out = PathBuf::new();
                out.push(p.as_os_str());
            }
            Component::RootDir => {
                out.push(Component::RootDir.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    // Absolute root: stay. Relative with no remaining
                    // component: keep `..` so it cannot be dropped.
                    if !out.has_root() {
                        out.push("..");
                    }
                }
            }
            Component::Normal(s) => {
                // `push` reparses a `C:`-shaped component as a drive
                // prefix and silently drops the leading root, corrupting
                // `/C:/x` (`file_uri_to_fs_path`'s drive spelling) into
                // the drive-relative `C:x`. Rebuild the drive root
                // instead so the path stays absolute.
                let text = s.to_string_lossy();
                if cfg!(windows)
                    && text.len() == 2
                    && text.ends_with(':')
                    && text.as_bytes()[0].is_ascii_alphabetic()
                    && out.has_root()
                    && out.components().all(|c| matches!(c, Component::RootDir))
                {
                    out = PathBuf::from(format!("{text}/"));
                } else {
                    out.push(s);
                }
            }
        }
    }
    if out.as_os_str().is_empty() {
        if path.has_root() {
            return Ok(PathBuf::from("/"));
        }
        return Ok(PathBuf::from("."));
    }
    Ok(out)
}

/// Normalize a path string for matching (absolute `..` resolution, no cwd).
///
/// Used by tests and by pattern matching when the input is already absolute.
pub fn lexical_normalize_str(path: &str) -> String {
    let unified = unify_separators(path);
    match lexical_normalize_path(Path::new(&unified)) {
        Ok(p) => to_match_string(&p),
        Err(_) => unified,
    }
}

/// Reduce a drive-qualified `C:/x` spelling to root-relative `/x` so
/// POSIX-flavored reserved lists still match resolved Windows paths.
/// Non-drive spellings are returned with separators unified.
pub fn strip_drive_prefix(path: &str) -> String {
    let unified = path.replace('\\', "/");
    if unified.len() >= 2
        && unified.as_bytes()[1] == b':'
        && unified.as_bytes()[0].is_ascii_alphabetic()
    {
        return unified[2..].to_string();
    }
    unified
}

/// True when `path` is inside `pattern` using prefix/glob semantics.
///
/// On Windows, path components are compared case-insensitively.
pub fn path_matches(path: &str, pattern: &str) -> bool {
    let Ok(normalized) = resolve_for_authorization(path) else {
        return false;
    };
    let Ok(match_pattern) = resolve_policy_pattern(pattern) else {
        return false;
    };
    segment_prefix_match(&normalized, &match_pattern)
}

/// Resolve the fixed prefix of a policy pattern to the same filesystem
/// identity as request paths, preserving every component after a wildcard.
/// In particular, do not follow symlinks beneath a wildcard grant.
pub fn resolve_policy_pattern(pattern: &str) -> Result<String, String> {
    if pattern.is_empty() || pattern.contains('\0') {
        return Err("empty or NUL-containing policy path".to_string());
    }
    let unified = unify_separators(pattern);
    let resolved = if let Some(wildcard) = unified.find('*') {
        let Some(separator) = unified[..wildcard].rfind('/') else {
            return Ok(normalize_pattern(&unified));
        };
        // Preserve the root separator: `C:` is relative to that drive's
        // working directory, whereas `C:/` names the drive root.
        let prefix = &unified[..=separator];
        let prefix = resolve_for_authorization(prefix)?;
        format!("{}{}", prefix.trim_end_matches('/'), &unified[separator..])
    } else {
        resolve_for_authorization(&unified)?
    };
    Ok(normalize_pattern(&resolved))
}

/// Match without filesystem access (lexical only). Prefer [`path_matches`]
/// at the authorization boundary.
pub fn path_matches_lexical(path: &str, pattern: &str) -> bool {
    let normalized = lexical_normalize_str(path);
    let match_pattern = normalize_pattern(pattern);
    segment_prefix_match(&normalized, &match_pattern)
}

fn normalize_pattern(pattern: &str) -> String {
    let unified = unify_separators(pattern);
    let stripped = unified.strip_suffix("/**").unwrap_or(&unified);
    lexical_normalize_str(stripped)
}

fn segment_prefix_match(path: &str, pattern: &str) -> bool {
    if pattern == "." {
        return false;
    }
    let path_segs = split_segments(path);
    let pat_segs = split_segments(pattern);
    if path_segs.len() < pat_segs.len() {
        return false;
    }
    for (i, ps) in pat_segs.iter().enumerate() {
        if *ps == "*" {
            continue;
        }
        if !seg_eq(path_segs[i], ps) {
            return false;
        }
    }
    true
}

fn split_segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect()
}

fn seg_eq(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
}

fn to_match_string(path: &Path) -> String {
    let mut s = if cfg!(windows) {
        path.to_string_lossy().replace('\\', "/")
    } else {
        path.to_string_lossy().into_owned()
    };
    // Windows `//?/C:/...` extended prefixes are reduced for matching.
    if let Some(rest) = s.strip_prefix("//?/") {
        s = rest.to_string();
    }
    s
}

/// True when two resolved paths name the same object for this platform.
pub fn paths_equal(a: &str, b: &str) -> bool {
    if cfg!(windows) {
        a.replace('\\', "/")
            .eq_ignore_ascii_case(&b.replace('\\', "/"))
    } else {
        a == b
    }
}

/// True when `value` begins with a `file:` scheme. Char-safe (never slices
/// UTF-8 at a raw byte index).
pub fn starts_with_file_scheme(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(
        (
            chars.next(),
            chars.next(),
            chars.next(),
            chars.next(),
            chars.next()
        ),
        (
            Some('f' | 'F'),
            Some('i' | 'I'),
            Some('l' | 'L'),
            Some('e' | 'E'),
            Some(':')
        )
    )
}

fn after_file_scheme(uri: &str) -> Option<&str> {
    if !starts_with_file_scheme(uri) {
        return None;
    }
    let rest_at = uri
        .char_indices()
        .nth(5)
        .map(|(i, _)| i)
        .unwrap_or(uri.len());
    uri.get(rest_at..)
}

/// True when `value` looks like a filesystem path rather than an opaque token.
pub fn looks_like_path(value: &str) -> bool {
    if value.is_empty() || value.contains('\0') {
        return false;
    }
    if value.contains("://") {
        return starts_with_file_scheme(value);
    }
    let has_sep = value.contains('/') || value.contains('\\');
    if !has_sep {
        return false;
    }
    value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with(".\\")
        || value.starts_with("..\\")
        || looks_like_windows_abs(value)
}

fn looks_like_windows_abs(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

/// True when `value` looks like a network target (URL or hostname).
///
/// `file:` URIs (including after bounded percent-decode) are filesystem
/// targets, not network hosts.
pub fn looks_like_network_target(value: &str) -> bool {
    if starts_with_file_scheme(value) {
        return false;
    }
    if let Ok(normalized) = normalize_fs_argument(value)
        && (starts_with_file_scheme(&normalized)
            || (looks_like_path(&normalized) && !normalized.contains("://")))
    {
        return false;
    }
    if value.contains("://") {
        return true;
    }
    if value.starts_with("//") && value.len() > 2 {
        return true;
    }
    false
}

/// Maximum percent-decode rounds for Auditor-time path arguments.
///
/// Caps double/triple encoding without an open-redirect style decode loop.
pub const PERCENT_DECODE_MAX_ROUNDS: usize = 8;

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode one layer of `%XX`. Malformed sequences are left unchanged.
pub fn percent_decode_once(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Controls / separators that can split `file` from `://` without being a
/// legitimate path-segment character the operator meant.
///
/// Stripped: ASCII C0 U+0001..=U+001F, DEL U+007F, C1 U+0080..=U+009F
/// (includes NEL U+0085), U+2028, U+2029. Space is kept. NUL (U+0000) is
/// **not** stripped — it stays a hard reject (fail-closed).
pub fn is_scheme_splitting_control(c: char) -> bool {
    let u = c as u32;
    (0x01..=0x1F).contains(&u)
        || u == 0x7F
        || (0x80..=0x9F).contains(&u)
        || c == '\u{2028}'
        || c == '\u{2029}'
}

/// Format / invisible characters that can still sit between `file` and `:`
/// after C0/C1 strip (fail-closed scheme sniff).
fn is_scheme_format_noise(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{E0001}'
            | '\u{E0020}'..='\u{E007F}'
    )
}

/// Remove scheme-splitting controls (not space). NUL is not stripped here.
pub fn strip_scheme_splitting_controls(input: &str) -> String {
    input
        .chars()
        .filter(|c| !is_scheme_splitting_control(*c))
        .collect()
}

/// Compact a URI for `file:` sniffing: drop splitting controls, Unicode
/// whitespace (`char::is_whitespace`: space, NBSP, EN/EM/THIN/HAIR, …), and
/// format noise so `file` + NBSP/space + `://` still becomes a filesystem path.
pub fn compact_uri_for_scheme_sniff(input: &str) -> String {
    input
        .chars()
        .filter(|c| {
            !is_scheme_splitting_control(*c) && !is_scheme_format_noise(*c) && !c.is_whitespace()
        })
        .collect()
}

fn nfkc(input: &str) -> String {
    input.nfkc().collect()
}

/// RFC 3986 scheme, ASCII only: `[A-Za-z][A-Za-z0-9+.-]*`.
pub fn is_ascii_uri_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

fn uri_scheme_slot(sniff: &str) -> Option<&str> {
    sniff.find("://").map(|idx| &sniff[..idx])
}

/// After decode + NFKC + compact, a `://` value whose scheme slot is not a
/// clean ASCII scheme is fail-closed for secret-overlay (confusables,
/// variation selectors, Braille blank, Hangul filler, …). Not a denylist.
pub fn uri_scheme_slot_is_dirty(raw: &str) -> bool {
    let decoded = match percent_decode_bounded(raw) {
        Ok(d) => nfkc(&d),
        Err(_) => return true,
    };
    let compacted = compact_uri_for_scheme_sniff(&decoded);
    let sniff = if compacted.contains("://") {
        compacted.as_str()
    } else if decoded.contains("://") {
        decoded.as_str()
    } else {
        return false;
    };
    match uri_scheme_slot(sniff) {
        Some(scheme) => !is_ascii_uri_scheme(scheme),
        None => true,
    }
}

fn decode_then_strip_c0(input: &str) -> Result<String, String> {
    let decoded = percent_decode_once(input);
    if decoded.contains('\0') {
        return Err("empty or NUL-containing path".to_string());
    }
    Ok(strip_scheme_splitting_controls(&decoded))
}

/// Iteratively percent-decode and strip scheme-splitting controls.
///
/// Each round is decode-once then strip, so `%0B` / `%0C` / `%250B` /
/// `%C2%85` become characters and are removed. Cap is
/// [`PERCENT_DECODE_MAX_ROUNDS`]. NUL or a still-changing input after the cap
/// is an error. Auditor argument normalization only.
pub fn percent_decode_bounded(input: &str) -> Result<String, String> {
    if input.contains('\0') {
        return Err("empty or NUL-containing path".to_string());
    }
    let mut current = strip_scheme_splitting_controls(input);
    for _ in 0..PERCENT_DECODE_MAX_ROUNDS {
        let next = decode_then_strip_c0(&current)?;
        if next == current {
            return Ok(current);
        }
        current = next;
    }
    let next = decode_then_strip_c0(&current)?;
    if next != current {
        return Err("percent-encoding did not stabilize within decode cap".to_string());
    }
    Ok(current)
}

fn strip_url_query_fragment(s: &str) -> &str {
    match s.find(['?', '#']) {
        Some(i) => &s[..i],
        None => s,
    }
}

fn strip_file_scheme(uri: &str) -> Option<&str> {
    after_file_scheme(uri)
}

/// Convert a `file:` URI to a filesystem path for Auditor matching.
///
/// Handles `file:///etc/passwd`, `file://localhost/etc/passwd`,
/// `file://127.0.0.1/etc/passwd`, `file://[::1]/etc/passwd`, and
/// `file:/etc/passwd`. Opaque forms (`file:etc/passwd`, `file:./…`,
/// `file:../…`) follow WHATWG special-scheme / Node `fileURLToPath`: the
/// remainder is treated as a path, `\` → `/`, a leading `/` is supplied,
/// and `.` / `..` are resolved — so those three become `/etc/passwd`.
/// Drive-letter forms (`/C:/…`) are kept. Query/fragment are stripped.
///
/// The `//` authority names a **host**, never a filesystem component.
/// A non-local authority — `file://host/share`, including Windows UNC
/// spellings `\\host\share` written as a file URI — returns `None`
/// rather than silently dropping the host and treating a remote path
/// as local. Callers must fail closed on `None` for `file:` input.
pub fn file_uri_to_fs_path(uri: &str) -> Option<String> {
    let rest = strip_url_query_fragment(strip_file_scheme(uri.trim())?);
    // Align with WHATWG file URL path: backslash is a separator.
    let rest = rest.replace('\\', "/");
    if let Some(after) = rest.strip_prefix("//") {
        if after.starts_with('/') {
            // `file:///path` — the authority is empty, the path is
            // local. But `file:////host/share` survives as
            // `//host/share`: the UNC spelling, whose leading `//`
            // names a remote share — reject it like any other non-local
            // authority instead of returning a UNC-form "local" path.
            if after.starts_with("//") {
                return None;
            }
            return Some(after.to_string());
        }
        let slash = after.find('/').unwrap_or(after.len());
        let authority = &after[..slash];
        if !is_local_file_authority(authority) {
            // `file://attacker/share` / UNC spellings: rejecting is the
            // only safe answer — the downstream consumer would treat
            // the stripped path as local while a URL parser would open
            // a share on the named host.
            return None;
        }
        let path = if slash < after.len() {
            &after[slash..]
        } else {
            ""
        };
        let path = strip_url_query_fragment(path);
        if path.is_empty() {
            return None;
        }
        // A local authority does not sanitize a UNC-form remainder:
        // `file://localhost//host/share` yields `//host/share`, which a
        // consumer would open as a remote share while the policy checks
        // it as a local path.
        if path.starts_with("//") {
            return None;
        }
        return Some(path.to_string());
    }
    if rest.starts_with('/') || looks_like_windows_abs(&rest) {
        return Some(rest);
    }
    // Opaque `file:etc/passwd` (no `//`, not already `/…` or drive).
    // WHATWG file is a special scheme: the path is `/` + remainder, then
    // `.` / `..` fold. This matches Node `fileURLToPath` for the reserved
    // `etc/passwd` family without depending on process cwd.
    if rest.is_empty() {
        return None;
    }
    Some(lexical_normalize_str(&format!("/{rest}")))
}

/// A `file://` authority that can only mean this machine — `localhost`
/// (any case, optional trailing root dot), the whole `127.0.0.0/8`
/// loopback range in any WHATWG IPv4 spelling (`127.1`, `0x7f.1`,
/// `2130706433`), or the `[::1]` loopback literal. Anything else —
/// remote hostnames, other IPs, empty-with-port — is non-local.
fn is_local_file_authority(authority: &str) -> bool {
    if let Some(inner) = authority
        .strip_prefix('[')
        .and_then(|a| a.strip_suffix(']'))
    {
        return inner
            .parse::<std::net::Ipv6Addr>()
            .is_ok_and(|v6| v6.is_loopback());
    }
    let lower = authority.to_ascii_lowercase();
    let lower = lower.trim_end_matches('.');
    lower == "localhost" || parse_ipv4_whatwg(lower).is_some_and(|v4| v4.is_loopback())
}

/// WHATWG IPv4-number: decimal, `0x`/`0X` hex (`0x` alone ⇒ 0), or a
/// leading-zero octal (`08`/`09` fail outright). `0` alone stays 0.
fn parse_ipv4_number(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        return if hex.is_empty() {
            Some(0)
        } else if hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            None
        };
    }
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return u64::from_str_radix(part, 8).ok();
    }
    part.parse::<u64>().ok()
}

/// WHATWG IPv4 parse: 1–4 `.`-separated numbers; non-final parts are
/// ≤255; the final part must fit the remaining width and folds
/// left-to-right at 256^k. `127.1`, `0x7f.1`, `2130706433`, and `1.256`
/// all produce one canonical address — `256.1.1.1` and `1.2.3.4.5`
/// produce none.
pub(crate) fn parse_ipv4_whatwg(host: &str) -> Option<Ipv4Addr> {
    let mut parts: Vec<&str> = host.split('.').collect();
    if parts.len() > 1 && parts.last().is_some_and(|p| p.is_empty()) {
        parts.pop();
    }
    if parts.is_empty() || parts.len() > 4 || parts.iter().any(|p| p.is_empty()) {
        return None;
    }
    let n = parts.len();
    let mut nums = Vec::with_capacity(n);
    for part in &parts {
        nums.push(parse_ipv4_number(part)?);
    }
    if nums[..n - 1].iter().any(|&v| v > 255) {
        return None;
    }
    let last = nums[n - 1];
    if last >= 256u64.pow(5 - n as u32) {
        return None;
    }
    let mut addr = last;
    for (i, v) in nums[..n - 1].iter().enumerate() {
        addr += v * 256u64.pow(3 - i as u32);
    }
    Some(Ipv4Addr::from(addr as u32))
}

/// `file:` with no `//` authority and a non-absolute remainder (`file:etc/passwd`).
pub fn is_opaque_file_uri(raw: &str) -> bool {
    let decoded = match percent_decode_bounded(raw) {
        Ok(d) => nfkc(&d),
        Err(_) => return false,
    };
    let compacted = compact_uri_for_scheme_sniff(&decoded);
    for candidate in [&decoded, &compacted] {
        if !starts_with_file_scheme(candidate) {
            continue;
        }
        let Some(rest) = after_file_scheme(candidate) else {
            continue;
        };
        let rest = strip_url_query_fragment(rest).replace('\\', "/");
        if rest.starts_with("//") || rest.starts_with('/') || looks_like_windows_abs(&rest) {
            return false;
        }
        if !rest.is_empty() {
            return true;
        }
    }
    false
}

/// Auditor-time filesystem argument normalization.
///
/// After bounded percent-decode + control strip: NFKC (so `ﬁle` / fullwidth
/// `ｆ` become `file`), then compact whitespace/format noise for `file:`
/// sniff only. Ordinary path arguments keep spaces (`/workspace/my file.txt`).
/// Does **not** close TOCTOU after `open`.
pub fn normalize_fs_argument(raw: &str) -> Result<String, String> {
    if raw.is_empty() {
        return Err("empty or NUL-containing path".to_string());
    }
    let decoded = nfkc(&percent_decode_bounded(raw)?);
    let compacted = compact_uri_for_scheme_sniff(&decoded);
    if let Some(from_uri) =
        file_uri_to_fs_path(&decoded).or_else(|| file_uri_to_fs_path(&compacted))
    {
        return Ok(nfkc(&percent_decode_bounded(&from_uri)?));
    }
    if starts_with_file_scheme(&decoded) || starts_with_file_scheme(&compacted) {
        // A `file:` value that produced no path — a non-local
        // `file://host` authority, a pathless URI — must fail closed:
        // falling back to the raw spelling would let a remote share
        // smuggle through the fs policy as an ordinary local name.
        return Err("file: URI does not name a local filesystem path".to_string());
    }
    Ok(decoded)
}

/// Well-known argument keys that carry filesystem targets (case-insensitive).
/// `*_path` / `*_paths` keys (e.g. `repo_path`, `output_path`) and their
/// camelCase spellings (`repoPath`, `outputPaths`) carry paths even when the
/// value is a bare name — it resolves against the server's working
/// directory like any other relative path. Spellings whose `Path`/`Paths`
/// stem ends in an uppercase `X`, plus the bare `xPath`/`xPaths`, are
/// excluded: they carry XPath expressions, not filesystem paths (whereas
/// `indexPath`/`sandboxPath` are real path fields).
pub fn is_path_field_name(key: &str) -> bool {
    is_exact_path_field_name(key) || is_suffixed_path_field_name(key)
}

/// Exact-name argument keys that carry filesystem targets
/// (case-insensitive).
fn is_exact_path_field_name(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "path"
            | "paths"
            | "file"
            | "filename"
            | "filepath"
            | "directory"
            | "dir"
            | "dest"
            | "destination"
            | "source"
            | "output"
            | "target"
            | "root"
            | "cwd"
    )
}

/// `*Path`-family suffix keys that carry filesystem targets —
/// `*_path`/`*_paths` (`repo_path`, `output_path`) and their camelCase
/// spellings (`repoPath`, `outputPaths`). Spellings whose `Path`/`Paths`
/// stem ends in an uppercase `X`, plus the bare `xPath`/`xPaths`, are
/// excluded: they carry XPath expressions, not filesystem paths (whereas
/// `indexPath`/`sandboxPath` are real path fields). The `jsonPath`/
/// `json_path` spellings are *not* excluded by name — a blanket
/// exemption would let `json_path = "/etc/passwd"` skip every path
/// check, so [`is_path_field_value`] filters JSONPath-expression
/// values instead: `jsonPath = "$.items"` is a query argument while
/// `jsonPath = "/data/out"` still checks as a filesystem path.
fn is_suffixed_path_field_name(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    lower.ends_with("_path")
        || lower.ends_with("_paths")
        || (key.ends_with("Path") && !(key.ends_with("XPath") || key == "xPath"))
        || (key.ends_with("Paths") && !(key.ends_with("XPaths") || key == "xPaths"))
}

/// `is_path_field_name` refined by the argument's value: a suffix-style
/// key whose value is a JSONPath expression (`$.items[0]`, `$[0]`, or a
/// bare `$`) is a query argument, not a filesystem target. Exact-name
/// path fields always count — `Path`/`Paths` are filesystem keys even
/// though they also satisfy the suffix test — and so does every
/// non-expression value: `outputJsonPath = "/data/out"` still checks as
/// a path.
pub fn is_path_field_value(key: &str, value: &str) -> bool {
    if is_exact_path_field_name(key) {
        return true;
    }
    is_suffixed_path_field_name(key) && !looks_like_jsonpath_expression(value)
}

/// JSONPath expression spellings: the root `$`, `$.member`, `$[index]`.
/// A value containing `/` or `\` is path-like — JSONPath members and
/// indices use `.`/`[..]`, so slashes mark a filesystem value that must
/// still reach inspection.
fn looks_like_jsonpath_expression(value: &str) -> bool {
    let v = value.trim_start();
    if v.contains('/') || v.contains('\\') {
        return false;
    }
    v == "$" || v.starts_with("$.") || v.starts_with("$[")
}

/// Well-known argument keys that carry network targets (case-insensitive).
///
/// Beyond the URL/host set, common selector aliases — `addr`, `peer`,
/// `proxy`, `upstream`, `server`, `address`, `relay` and their plurals —
/// so a bare host under any of these names still reaches the network
/// policy instead of falling through unrecognized.
pub fn is_network_field_name(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "url"
            | "urls"
            | "host"
            | "hosts"
            | "hostname"
            | "endpoint"
            | "endpoints"
            | "uri"
            | "uris"
            | "origin"
            | "origins"
            | "addr"
            | "addrs"
            | "address"
            | "addresses"
            | "peer"
            | "peers"
            | "proxy"
            | "proxies"
            | "upstream"
            | "upstreams"
            | "server"
            | "servers"
            | "relay"
            | "relays"
            | "socket"
            | "sockets"
            | "broker"
            | "brokers"
            | "ip"
            | "ips"
            | "ip_address"
            | "ipaddress"
            | "ipaddr"
            | "ip_addr"
            | "domain"
            | "domains"
            | "domain_name"
            | "domainname"
            | "host_name"
            | "destinationip"
            | "destination_ip"
            | "targetip"
            | "target_ip"
            | "hostaddress"
            | "dns"
            | "dns_name"
            | "remote"
            | "remote_addr"
            | "remoteaddr"
            | "dial"
            | "connect"
            | "connection"
            | "redirect"
            | "bind"
            | "listen"
            | "listener"
    )
}

/// True when `value` is an unambiguous network endpoint spelling — an
/// IP literal, bracketed IPv6 (with or without a port), or a
/// `host:port` authority — regardless of the argument key it sits
/// under. Bare DNS names are deliberately excluded: a token like
/// `server: "prod"` resolves through the network field vocabulary, not
/// value shape, because a dotted-less token is as likely an opaque
/// identifier as an address.
pub fn looks_like_host_or_socket(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v.contains('\0') || v.contains(['/', '\\', ' ']) {
        return false;
    }
    if v.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some(rest) = v.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        if rest[..end].parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        return match rest.get(end + 1..) {
            None | Some("") => true,
            Some(tail) => tail.strip_prefix(':').is_some_and(valid_port),
        };
    }
    // `host:port` — host is an IP literal or a DNS-shaped name, port a
    // bare number. More than one colon without brackets is ambiguous
    // (unbracketed IPv6+port), so only the single-colon form counts.
    let Some((host, port)) = v.rsplit_once(':') else {
        return false;
    };
    if host.contains(':') {
        return false;
    }
    valid_port(port) && (host.parse::<std::net::IpAddr>().is_ok() || dns_name_shape(host))
}

fn valid_port(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 5
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u32>().is_ok_and(|p| p <= 65535)
}

/// DNS name spelling — a single- or multi-label name within hostname
/// limits. Used for the host part of `host:port` and for bare values
/// on recognized network fields; a bare token is never a network
/// target by shape alone.
pub(crate) fn dns_name_shape(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.bytes().any(|b| b.is_ascii_alphabetic())
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Well-known argument keys that carry opaque payload data rather than
/// resource selectors (case-insensitive). Under a restricted tool
/// contract a string on any *other* unrecognized key is an unverifiable
/// selector candidate and fails closed — these names declare the
/// fields whose values need no resource interpretation. Path- and
/// endpoint-shaped values classify as targets before this list is
/// consulted, so `content: "/etc/passwd"` still evaluates as a path;
/// the exemption covers free text that merely *mentions* a path-like
/// token (`prompt: "read ./report.txt"`).
///
/// `name`, `key`, and similar handles are deliberately absent: an
/// opaque-looking identifier on a restricted tool can be the selector
/// itself (`create {name: "report.txt"}` beside an allowed `path`
/// decoy), so those values must survive classification. The same
/// applies to identity- and credential-shaped keys — `id`, `user`,
/// `token`, `secret`, `password`, `auth`: a server-side `id` *is* a
/// resource selector (`{"id": "a/b"}` names exactly what an fs rule
/// mediates), and a credential field the contract never declared must
/// not pass a restricted tool unchecked.
pub fn is_known_payload_field_name(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "content"
            | "contents"
            | "text"
            | "data"
            | "body"
            | "payload"
            | "message"
            | "msg"
            | "command"
            | "cmd"
            | "args"
            | "arguments"
            | "query"
            | "sql"
            | "code"
            | "script"
            | "input"
            | "stdin"
            | "value"
            | "values"
            | "description"
            | "pattern"
            | "regex"
            | "format"
            | "encoding"
            | "charset"
            | "mode"
            | "type"
            | "header"
            | "headers"
            | "label"
            | "labels"
            | "tag"
            | "tags"
            | "version"
            | "status"
            | "state"
            | "filter"
            | "sort"
            | "order"
            | "limit"
            | "offset"
            | "count"
            | "depth"
            | "timeout"
            | "interval"
            | "debug"
            | "verbose"
            | "dryrun"
            | "dry_run"
            | "force"
            | "recursive"
            | "overwrite"
            | "append"
            | "newline"
            | "separator"
            | "delimiter"
            | "quote"
            | "escape"
            | "language"
            | "locale"
            | "timezone"
            | "indent"
            | "env"
            | "environment"
            | "options"
            | "flags"
            | "comment"
            | "reason"
            | "level"
            | "severity"
            | "color"
            | "colour"
            | "owner"
            | "group"
            | "uid"
            | "gid"
            | "pid"
            | "note"
            | "notes"
            | "title"
            | "subject"
            | "summary"
            | "prompt"
            | "question"
            | "answer"
            | "response"
            | "action"
            | "operation"
            | "op"
            | "task"
            | "method"
            | "verb"
            | "direction"
            | "protocol"
            | "scheme"
            | "transport"
    )
}

/// True when an unclassified argument string could still select a
/// filesystem or network resource — a token carrying separator,
/// authority, or expansion punctuation (`a/b`, `C:\x`, `h:80`,
/// `~/.ssh`, `$V/x`, `u@h`), or a dot (`..`, `.env`, `a.b`,
/// `10.0.0.1`, `notes.txt`). A bare word without punctuation is
/// irreducibly ambiguous with payload text — it stays forwardable
/// rather than denying every ordinary argument on a restricted tool.
pub fn selector_plausible(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v.contains('\0') {
        return false;
    }
    if v.contains(['/', '\\', ':', '~', '$', '%', '@']) {
        return true;
    }
    v.contains('.')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn drive_root_glob_is_independent_of_working_directory() {
        let cwd = std::env::current_dir().unwrap();
        let root = cwd.ancestors().last().unwrap().to_str().unwrap();
        // A root-wide grant must include the root itself, even when the
        // process is running in a subdirectory on that same drive.
        assert!(path_matches(root, &format!("{root}**")));
        assert!(path_matches(
            root,
            &format!("{}**", root.replace('\\', "/"))
        ));
    }

    #[test]
    fn absolute_traversal_is_resolved_not_dropped() {
        assert_eq!(
            lexical_normalize_str("/workspace/../../etc/passwd"),
            "/etc/passwd"
        );
        assert_eq!(lexical_normalize_str("/workspace/../tmp"), "/tmp");
        assert_eq!(lexical_normalize_str("/a/b/c/../../d"), "/a/d");
    }

    /// `/D:/x` is the `file_uri_to_fs_path` spelling for `file:///D:/x`:
    /// normalization must keep it drive-qualified, not collapse it to
    /// drive-relative `D:x` (the `PathBuf::push` prefix replacement).
    #[cfg(windows)]
    #[test]
    fn root_relative_drive_spelling_keeps_its_drive() {
        assert_eq!(lexical_normalize_str("/D:/work/x"), "D:/work/x");
        assert_eq!(lexical_normalize_str("/D:"), "D:/");
        assert_eq!(lexical_normalize_str("/D:/a/../b"), "D:/b");
    }

    #[test]
    fn relative_traversal_joins_cwd() {
        // A private cwd: resolution now refuses paths whose ancestors a
        // non-owner principal could replace, and the ambient cwd may be
        // one (shared mounts, group checkouts).
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().canonicalize().unwrap();
        let cwd = cwd.as_path();
        let resolved = resolve_for_authorization_with_cwd("data/../../secret", cwd).unwrap();
        let expected = to_match_string(&lexical_normalize_path(&cwd.join("secret")).unwrap());
        // `secret` as a sibling of cwd, not `data/secret`.
        assert!(
            resolved.ends_with("/secret")
                || resolved.ends_with("\\secret")
                || resolved.ends_with("secret"),
            "resolved={resolved} expected suffix of {expected}"
        );
        assert!(
            !resolved.contains("/data/"),
            "data segment should be popped: {resolved}"
        );
    }

    #[test]
    fn path_matches_blocks_escape_from_workspace() {
        assert!(!path_matches_lexical(
            "/workspace/../../etc/passwd",
            "/workspace"
        ));
        assert!(path_matches_lexical("/workspace/src/main.rs", "/workspace"));
    }

    #[cfg(unix)]
    #[test]
    fn policy_aliases_preserve_wildcards_without_granting_symlink_escapes() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(real.join("user")).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let alias = dir.path().join("alias");
        symlink(&real, &alias).unwrap();
        symlink(&outside, real.join("escape")).unwrap();

        let pattern = format!("{}/*/note.txt", alias.display());
        assert!(path_matches(
            &real.join("user/note.txt").to_string_lossy(),
            &pattern
        ));
        assert!(!path_matches(
            &outside.join("note.txt").to_string_lossy(),
            &pattern
        ));
        assert!(!path_matches(
            &alias.join("escape/note.txt").to_string_lossy(),
            &format!("{}/**", alias.display()),
        ));
    }

    #[test]
    fn invalid_policy_patterns_fail_closed() {
        assert!(resolve_policy_pattern("").is_err());
        assert!(resolve_policy_pattern("/workspace/\0").is_err());
    }

    #[test]
    fn path_field_names_cover_snake_and_camel() {
        for key in [
            "repo_path",
            "output_paths",
            "repoPath",
            "outputPaths",
            "srcPath",
            // A lowercase x inside a longer stem is still a path field.
            "indexPath",
            "sandboxPath",
            // Compound keys ending in a JSONPath spelling are still
            // filesystem path fields — only the exact `jsonPath`/`json_path`
            // spellings carry expressions.
            "outputJsonPath",
            "output_json_path",
            // Even the exact JSONPath spellings count by name: a plain
            // file path under `jsonPath`/`json_path` must reach the path
            // checks — `is_path_field_value` filters the expression
            // values instead.
            "jsonPath",
            "jsonPaths",
            "JsonPath",
            "JSONPath",
            "json_path",
            "json_paths",
        ] {
            assert!(is_path_field_name(key), "{key}");
        }
        // Substrings and unrelated suffixes do not count. `XPath`/`xpath`
        // carry XPath expressions, not filesystem paths — the exclusion is
        // a stem ending in uppercase X, or the bare lowercase `x` stem.
        for key in [
            "pathology",
            "myPath2",
            "paths2",
            "xpath",
            "xpaths",
            "XPath",
            "XPaths",
            "xPath",
            "xPaths",
            "nodeXPath",
            "nodeXPaths",
        ] {
            assert!(!is_path_field_name(key), "{key}");
        }
    }

    #[test]
    fn jsonpath_expression_values_are_not_fs_paths() {
        // A `*Path`-suffixed key carrying a JSONPath expression is a
        // query argument — the value, not the key spelling, decides.
        // That includes the exact `jsonPath`/`json_path` spellings,
        // which are no longer exempted by name.
        for (key, value) in [
            ("outputJsonPath", "$.items[0]"),
            ("output_json_path", "$[0]"),
            ("outputPaths", "$"),
            ("repo_path", " $.data.path "),
            ("jsonPath", "$.items[0]"),
            ("JSONPath", "$[0]"),
            ("json_path", "$.data.items"),
            ("json_paths", "$"),
        ] {
            assert!(!is_path_field_value(key, value), "{key}={value}");
        }
        // Non-expression values on the same keys still check as paths —
        // a plain file path under a `jsonPath` key must reach the path
        // checks — and exact-name fields are never exempted. A value
        // carrying a path separator is path-like even on a `$.`-style
        // prefix — `$. /../x` is a filesystem value, not a JSONPath
        // expression.
        for (key, value) in [
            ("outputJsonPath", "/data/out.json"),
            ("outputJsonPath", "reports/daily.json"),
            ("jsonPath", "/etc/passwd"),
            ("JsonPath", "../secret"),
            ("json_path", "data/out.json"),
            ("json_paths", "/workspace/a"),
            ("repo_path", "$. /../x"),
            ("path", "$.items"),
            ("output", "$.x"),
            // `Path`/`Paths` are exact names that *also* satisfy the
            // suffix test — the expression exemption must not swallow them.
            ("Path", "$.items"),
            ("Paths", "$[0]"),
        ] {
            assert!(is_path_field_value(key, value), "{key}={value}");
        }
        // The key-only classification is unchanged.
        assert!(is_path_field_name("outputJsonPath"));
    }

    #[test]
    fn payload_field_names_exclude_selector_shaped_keys() {
        // Opaque payload keys stay exempt — a restricted tool forwards
        // free text on them without resource interpretation.
        for key in [
            "content", "text", "data", "body", "message", "prompt", "value",
        ] {
            assert!(is_known_payload_field_name(key), "{key}");
        }
        // Identity-, credential-, and handle-shaped keys are not
        // payload: a server can resolve them as resource selectors, so
        // a restricted tool must classify (and where selector-plausible,
        // refuse) their values instead of exempting them by name.
        for key in [
            "id",
            "user",
            "username",
            "name",
            "key",
            "token",
            "secret",
            "password",
            "auth",
            "credential",
            "credentials",
        ] {
            assert!(!is_known_payload_field_name(key), "{key}");
        }
    }

    #[test]
    fn windows_case_insensitive_segments() {
        if cfg!(windows) {
            assert!(segment_prefix_match("C:/Secret/Key.pem", "c:/secret"));
        } else {
            assert!(!segment_prefix_match("/Secret/Key.pem", "/secret"));
        }
    }

    #[test]
    fn posix_absolute_does_not_pick_up_windows_drive() {
        // Anchor on the temp tree's filesystem root so the outcome does
        // not depend on the process drive's DACL — a broad-writable
        // data volume makes root-level resolution fail closed.
        let anchor = PathBuf::from(temp_root_abs("/"));
        let resolved =
            resolve_for_authorization_with_cwd("/workspace/src/main.rs", &anchor).unwrap();
        if cfg!(windows) {
            // Root-relative `/workspace` opens on the anchor drive —
            // `windows_drive_qualify` makes the authorized spelling the
            // same `C:\...` object the child opens, so deny matching
            // sees the real identity (F52 contract).
            let drive = temp_root_abs("");
            assert!(
                resolved
                    .replace('\\', "/")
                    .starts_with(&format!("{drive}/workspace")),
                "root-relative path must qualify to the anchor drive: {resolved}"
            );
        } else {
            assert!(
                resolved.starts_with("/workspace"),
                "POSIX absolute path must not become a drive path: {resolved}"
            );
        }
        assert!(path_matches_lexical("/workspace/src/main.rs", "/workspace"));
    }

    #[test]
    fn looks_like_path_examples() {
        assert!(looks_like_path("/etc/passwd"));
        assert!(looks_like_path("../secret"));
        assert!(looks_like_path("file:///tmp/a"));
        assert!(!looks_like_path("hello"));
        assert!(!looks_like_path("https://example.com/x"));
    }

    #[test]
    fn looks_like_network_excludes_file_uri() {
        assert!(!looks_like_network_target("file:///etc/passwd"));
        assert!(!looks_like_network_target("FILE://localhost/etc/passwd"));
        assert!(looks_like_network_target("https://example.com/x"));
    }

    #[test]
    fn percent_decode_dot_and_letter() {
        assert_eq!(
            percent_decode_bounded("/workspace/%2essh/id_rsa").unwrap(),
            "/workspace/.ssh/id_rsa"
        );
        assert_eq!(
            percent_decode_bounded("/workspace/.%73sh/id_rsa").unwrap(),
            "/workspace/.ssh/id_rsa"
        );
        assert_eq!(
            percent_decode_bounded("/workspace/%252essh/id_rsa").unwrap(),
            "/workspace/.ssh/id_rsa"
        );
    }

    #[test]
    fn percent_decode_cap_rejects_unstable() {
        // 10 nested encodings of '.' (`%2e` → `%252e` → …) exceed the cap.
        let mut s = "%2e".to_string();
        for _ in 0..9 {
            s = s.replace('%', "%25");
        }
        let encoded = format!("/workspace/{s}ssh");
        let err = percent_decode_bounded(&encoded).unwrap_err();
        assert!(err.contains("stabilize"), "got: {err}");
    }

    #[test]
    fn file_uri_variants_to_fs_path() {
        assert_eq!(
            file_uri_to_fs_path("file:///etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file://localhost/etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file://127.0.0.1/etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file://[::1]/etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("FILE:/etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file://localhost\\etc\\passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file://\\etc\\passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            normalize_fs_argument("file://localhost%5Cetc%5Cpasswd").unwrap(),
            "/etc/passwd"
        );
        assert_eq!(
            normalize_fs_argument("%66ile://localhost\\etc\\passwd").unwrap(),
            "/etc/passwd"
        );
        // Drive-letter form stays a drive path (not collapsed to /etc/…).
        assert_eq!(
            file_uri_to_fs_path("file:///C:\\Windows\\win.ini").as_deref(),
            Some("/C:/Windows/win.ini")
        );
        assert_eq!(
            normalize_fs_argument("file://localhost/etc/passwd").unwrap(),
            "/etc/passwd"
        );
        assert_eq!(
            normalize_fs_argument("%66ile://localhost/etc/passwd").unwrap(),
            "/etc/passwd"
        );
        // Opaque file: (no //) — WHATWG / Node fileURLToPath → /etc/passwd.
        assert_eq!(
            file_uri_to_fs_path("file:etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file:etc\\passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file:./etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert_eq!(
            file_uri_to_fs_path("file:../etc/passwd").as_deref(),
            Some("/etc/passwd")
        );
        assert!(is_opaque_file_uri("file:etc/passwd"));
        assert!(is_opaque_file_uri("file:etc\\passwd"));
        assert!(is_opaque_file_uri("file:./etc/passwd"));
        assert!(is_opaque_file_uri("file:../etc/passwd"));
        assert!(!is_opaque_file_uri("file:///etc/passwd"));
        assert!(!is_opaque_file_uri("file:/etc/passwd"));
        assert!(!is_opaque_file_uri("/workspace/notes.txt"));
        for opaque in [
            "file:etc/passwd",
            "file:etc\\passwd",
            "file:./etc/passwd",
            "file:../etc/passwd",
        ] {
            assert_eq!(
                normalize_fs_argument(opaque).unwrap(),
                "/etc/passwd",
                "opaque file: must normalize: {opaque:?}"
            );
        }
        assert!(!looks_like_network_target("%66ile://localhost/etc/passwd"));
        assert!(starts_with_file_scheme(
            &percent_decode_bounded("%66ile://localhost/etc/passwd").unwrap()
        ));
        for sneaky in [
            "file\t://localhost/etc/passwd",
            "file\n://localhost/etc/passwd",
            "file\r://localhost/etc/passwd",
            "file%0A://localhost/etc/passwd",
            "file%09://localhost/etc/passwd",
            "file%0D://localhost/etc/passwd",
            "%66ile%0A://localhost/etc/passwd",
            "file%0B://localhost/etc/passwd",
            "file%0C://localhost/etc/passwd",
            "file%250B://localhost/etc/passwd",
            "file%C2%85://localhost/etc/passwd",
            "file\u{2028}://localhost/etc/passwd",
            "file\u{2029}://localhost/etc/passwd",
            "file\u{00A0}://localhost/etc/passwd",
            "file%C2%A0://localhost/etc/passwd",
            "file%E2%80%82://localhost/etc/passwd",
            "file ://localhost/etc/passwd",
            "file%20://localhost/etc/passwd",
            "\u{FB01}le://localhost/etc/passwd",
            "%EF%BD%86ile://localhost/etc/passwd",
        ] {
            assert_eq!(
                normalize_fs_argument(sneaky).unwrap(),
                "/etc/passwd",
                "C0/percent file URI must normalize: {sneaky:?}"
            );
            assert!(
                !looks_like_network_target(sneaky),
                "must not stay a network URL: {sneaky:?}"
            );
        }
        // Non-local and UNC-form authorities never yield a local path.
        for remote in [
            "file://host/share/x",
            "file://192.168.1.5/share",
            // `file:////host/share` collapses to `//host/share` — the
            // UNC spelling that must not pass as a local path either.
            "file:////host/share",
            "file:////attacker/etc/passwd",
            "file:////",
            // A *local* authority does not sanitize a UNC-form
            // remainder — `//host/share` must not come back as a path.
            "file://localhost//host/share",
            "file://localhost//host",
            "file://127.0.0.1//attacker/etc/passwd",
            "file://[::1]//host/share",
        ] {
            assert_eq!(
                file_uri_to_fs_path(remote),
                None,
                "remote/UNC authority must be rejected: {remote:?}"
            );
            assert!(
                normalize_fs_argument(remote).is_err(),
                "remote file URI must fail closed: {remote:?}"
            );
        }
    }

    #[test]
    fn file_scheme_sniff_is_char_safe_with_zwsp() {
        let sneaky = "file\u{200b}://localhost/etc/passwd";
        assert!(!starts_with_file_scheme(sneaky));
        // Must not panic on a mid-codepoint-length prefix.
        let _ = looks_like_network_target(sneaky);
        let _ = looks_like_path(sneaky);
        let _ = file_uri_to_fs_path(sneaky);
        assert_eq!(
            normalize_fs_argument(sneaky).unwrap(),
            "/etc/passwd",
            "ZWSP between file and :// must compact to a file URI"
        );
    }

    #[test]
    fn dirty_scheme_slot_is_class_based() {
        assert!(uri_scheme_slot_is_dirty(
            "f\u{0456}le://localhost/etc/passwd"
        ));
        assert!(uri_scheme_slot_is_dirty("f%D1%96le://localhost/etc/passwd"));
        assert!(uri_scheme_slot_is_dirty(
            "f\u{03B9}le://localhost/etc/passwd"
        ));
        assert!(uri_scheme_slot_is_dirty(
            "fil\u{0435}://localhost/etc/passwd"
        ));
        assert!(uri_scheme_slot_is_dirty(
            "file\u{FE0F}://localhost/etc/passwd"
        ));
        assert!(!uri_scheme_slot_is_dirty("file://localhost/etc/passwd"));
        assert!(!uri_scheme_slot_is_dirty("https://example.com/x"));
        assert!(!uri_scheme_slot_is_dirty("/workspace/notes.txt"));
        assert!(!is_ascii_uri_scheme("f\u{0456}le"));
        assert!(is_ascii_uri_scheme("file"));
        assert!(is_ascii_uri_scheme("https"));
    }

    #[test]
    fn space_in_ordinary_path_is_kept() {
        assert_eq!(
            percent_decode_bounded("/workspace/my file.txt").unwrap(),
            "/workspace/my file.txt"
        );
        assert_eq!(
            normalize_fs_argument("/workspace/my file.txt").unwrap(),
            "/workspace/my file.txt"
        );
    }

    #[cfg(windows)]
    #[test]
    fn unc_and_device_spellings_refuse_before_any_filesystem_touch() {
        // F4: `\\host\share`, `//host/share`, `\\?\UNC\…`, and `\\.\…`
        // must never reach canonicalize — authorization stays lexical
        // and the deny lands without an SMB lookup.
        for spelling in [
            "\\\\attacker.example\\share\\name",
            "//attacker.example/share/name",
            "\\\\?\\UNC\\attacker.example\\share",
            "\\\\.\\pipe\\x",
            "\\\\?\\C:\\windows",
        ] {
            assert!(
                resolve_for_authorization(spelling).is_err(),
                "{spelling} must refuse before resolution"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn root_relative_path_qualifies_to_current_drive() {
        // F52: `/x` opens from the current drive on Windows — the
        // resolved identity must be drive-qualified and canonicalized,
        // so a deny on `D:/dir` covers `/dir` spellings too. The
        // qualification itself is pure: the drive comes from the cwd.
        let cwd = std::env::current_dir().unwrap();
        let drive = cwd.to_string_lossy().replace('\\', "/");
        let drive = &drive[..2];
        assert!(drive.ends_with(':'), "test expects a drive cwd");
        let qualified = windows_drive_qualify(Path::new("/nonexistent-suffix-xyz"), &cwd)
            .expect("a drive cwd qualifies a root-relative spelling");
        assert_eq!(
            qualified.to_string_lossy().replace('\\', "/"),
            format!("{drive}/nonexistent-suffix-xyz"),
        );
        // The full authorization resolve walks the qualified path's
        // ancestors — including the drive root — so anchor the cwd on
        // the temp tree's root instead of the process drive, whose DACL
        // may legitimately refuse a root-level entry (fail-closed) and
        // silently skip the deny-match contract.
        let anchor = PathBuf::from(temp_root_abs("/"));
        let resolved =
            resolve_for_authorization_with_cwd("/nonexistent-suffix-xyz", &anchor).unwrap();
        let anchor_drive = temp_root_abs("");
        assert_eq!(resolved, format!("{anchor_drive}/nonexistent-suffix-xyz"));
        // A drive-qualified deny covers the root-relative spelling.
        assert!(path_matches(
            &resolved,
            &format!("{anchor_drive}/nonexistent-suffix-xyz")
        ));
        assert!(path_matches(&resolved, &format!("{anchor_drive}/**")));
    }

    #[cfg(unix)]
    #[test]
    fn f67_symlink_under_shared_writable_parent_is_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, b"x").unwrap();
        // A group/world-writable directory without the sticky bit lets
        // any principal delete and recreate `link` after the check.
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        symlink(&target, shared.join("link")).unwrap();

        let spelled = shared.join("link").to_string_lossy().into_owned();
        let err = resolve_for_authorization_with_cwd(&spelled, dir.path())
            .expect_err("symlink under a shared-writable parent must be refused");
        assert!(
            err.contains("symbolic link") || err.contains("replaceable"),
            "unexpected refusal: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn f67_symlink_under_sticky_shared_parent_is_refused() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        // Sticky shared dirs (`/tmp`) still let a link's *owner* swap it
        // post-check — an attacker-owned link there is replaceable.
        let dir = tempfile::tempdir().unwrap();
        let sticky = dir.path().join("sticky");
        std::fs::create_dir(&sticky).unwrap();
        std::fs::set_permissions(&sticky, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let target = dir.path().join("t");
        std::fs::write(&target, b"x").unwrap();
        symlink(&target, sticky.join("l")).unwrap();

        let spelled = sticky.join("l").to_string_lossy().into_owned();
        assert!(
            resolve_for_authorization_with_cwd(&spelled, dir.path()).is_err(),
            "link under a sticky shared-writable parent must be refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn f67_replaceable_ancestor_fails_closed() {
        use std::os::unix::fs::PermissionsExt;

        // The resolved object itself is safe, but an ancestor any
        // principal can rename re-binds the whole spelling.
        let dir = tempfile::tempdir().unwrap();
        let swappable = dir.path().join("swappable");
        std::fs::create_dir_all(swappable.join("inner")).unwrap();
        std::fs::write(swappable.join("inner/f"), b"x").unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let spelled = swappable.join("inner/f").to_string_lossy().into_owned();
        let err = resolve_for_authorization_with_cwd(&spelled, dir.path())
            .expect_err("path through a replaceable ancestor must be refused");
        assert!(err.contains("replaceable"), "unexpected refusal: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn f67_missing_suffix_under_replaceable_ancestor_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let spelled = dir
            .path()
            .join("not-created-yet/deep/file")
            .to_string_lossy()
            .into_owned();
        assert!(
            resolve_for_authorization_with_cwd(&spelled, dir.path()).is_err(),
            "missing suffix under a replaceable ancestor must be refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn f67_private_ancestors_still_resolve() {
        use std::os::unix::fs::symlink;

        // Control case: a symlink whose parent is owner-only, plus
        // ordinary private dirs, keep authorizing normally.
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("real");
        std::fs::create_dir(&inside).unwrap();
        std::fs::write(inside.join("f"), b"x").unwrap();
        symlink(&inside, dir.path().join("alias")).unwrap();

        let spelled = dir.path().join("alias/f").to_string_lossy().into_owned();
        let resolved = resolve_for_authorization_with_cwd(&spelled, dir.path()).unwrap();
        assert!(resolved.ends_with("real/f"), "resolved={resolved}");
    }
}
