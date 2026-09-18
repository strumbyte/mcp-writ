//! Path identity helpers shared by Auditor authorization and policy validation.
//!
//! Authorization is performed on a resolved path (cwd-joined, lexically
//! normalized, and canonicalized when the object exists) rather than on the
//! original attacker-controlled string.

use std::path::{Component, Path, PathBuf};

use unicode_normalization::UnicodeNormalization;

/// Resolve `path` to the filesystem object the child would open from the
/// current working directory.
///
/// Relative `..` is applied against the cwd, not discarded. Symlinks are
/// followed when the path (or its nearest existing ancestor) exists.
pub fn resolve_for_authorization(path: &str) -> Result<String, String> {
    if path.is_empty() || path.contains('\0') {
        return Err("empty or NUL-containing path".to_string());
    }
    let joined = join_with_cwd(path)?;
    let lexical = lexical_normalize_path(&joined)?;
    // Windows `canonicalize` maps `/foo` onto the current drive. Keep POSIX
    // request paths lexical so they compare against POSIX policy patterns.
    if cfg!(windows) && is_posix_absolute(&unify_separators(path)) {
        return Ok(to_match_string(&lexical));
    }
    match std::fs::canonicalize(&lexical) {
        Ok(canon) => Ok(to_match_string(&canon)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(to_match_string(&resolve_via_existing_ancestor(&lexical)?))
        }
        Err(e) => Err(format!(
            "path resolution failed for '{}': {e}",
            lexical.display()
        )),
    }
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
    let unified = unify_separators(path);
    if is_posix_absolute(&unified) {
        return Ok(PathBuf::from(&unified));
    }
    let p = PathBuf::from(&unified);
    if p.is_absolute() {
        return Ok(p);
    }
    let cwd = std::env::current_dir().map_err(|e| format!("cwd unavailable: {e}"))?;
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
            Component::Normal(s) => out.push(s),
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

/// True when `path` is inside `pattern` using prefix/glob semantics.
///
/// On Windows, path components are compared case-insensitively.
pub fn path_matches(path: &str, pattern: &str) -> bool {
    let normalized = match resolve_for_authorization(path) {
        Ok(n) => n,
        Err(_) => lexical_normalize_str(path),
    };
    let match_pattern = normalize_pattern(pattern);
    segment_prefix_match(&normalized, &match_pattern)
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
pub fn file_uri_to_fs_path(uri: &str) -> Option<String> {
    let rest = strip_url_query_fragment(strip_file_scheme(uri.trim())?);
    // Align with WHATWG file URL path: backslash is a separator.
    let rest = rest.replace('\\', "/");
    if let Some(after) = rest.strip_prefix("//") {
        if after.starts_with('/') {
            return Some(after.to_string());
        }
        let slash = after.find('/').unwrap_or(after.len());
        let path = if slash < after.len() {
            &after[slash..]
        } else {
            ""
        };
        let path = strip_url_query_fragment(path);
        if path.is_empty() {
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
    Ok(decoded)
}

/// Well-known argument keys that carry filesystem targets (case-insensitive).
pub fn is_path_field_name(key: &str) -> bool {
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

/// Well-known argument keys that carry network targets (case-insensitive).
pub fn is_network_field_name(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "url" | "urls" | "host" | "hosts" | "hostname" | "endpoint" | "uri" | "origin"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absolute_traversal_is_resolved_not_dropped() {
        assert_eq!(
            lexical_normalize_str("/workspace/../../etc/passwd"),
            "/etc/passwd"
        );
        assert_eq!(lexical_normalize_str("/workspace/../tmp"), "/tmp");
        assert_eq!(lexical_normalize_str("/a/b/c/../../d"), "/a/d");
    }

    #[test]
    fn relative_traversal_joins_cwd() {
        let cwd = std::env::current_dir().unwrap();
        let resolved = resolve_for_authorization("data/../../secret").unwrap();
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
        let resolved = resolve_for_authorization("/workspace/src/main.rs").unwrap();
        assert!(
            resolved.starts_with("/workspace"),
            "POSIX absolute path must not become a drive path: {resolved}"
        );
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
}
