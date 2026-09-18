//! Secret-path overlay for tool arguments and manifest checks.
//!
//! Well-known secret paths are denied even when an explicit allow glob would
//! match. Matching uses Auditor-time argument normalization: bounded
//! percent-decode, `file:` URI → filesystem path, then NFKC, lexical `.`/`..`
//! folding, separator normalization, and partial canonicalize (existing
//! ancestors + symlink follow). Uncreated reserved names (`.ssh`, `.env`, …)
//! still match.
//!
//! Percent-encoding (`%2e`, `%73`, `%66ile:`, double-encoding), scheme-
//! splitting control strip (ASCII C0 except NUL, DEL, C1 including NEL,
//! U+2028/U+2029; `%0B`/`%0C`/`%250B`/`%C2%85`), Unicode whitespace compact
//! for `file:` sniff (NBSP, EN/EM/THIN/HAIR, ASCII space), NFKC scheme morphs
//! (`ﬁle`, fullwidth `ｆ`), and `file://` authority variants must not bypass
//! this overlay. URI scheme slots must be ASCII
//! `[A-Za-z][A-Za-z0-9+.-]*`; anything else (`fіle://`, `f%D1%96le://`,
//! variation selectors in the scheme) is fail-closed under overlay — not a
//! per-codepoint denylist. Ordinary path arguments keep spaces. That is
//! argument normalization at `tools/call` check time. Replacement between
//! that check and the child's `open` (TOCTOU) remains Warden's job. Reserved
//! names are matched ASCII-case-insensitively. Opaque `file:` forms without
//! `//` or a leading `/` (`file:etc/passwd`, `file:etc\passwd`,
//! `file:./etc/passwd`, `file:../etc/passwd`) are converted like Node
//! `fileURLToPath` and must hit this overlay; leftover opaque `file:` that
//! is not already `/…` or a drive form is fail-closed DENY, not ALLOW.

use unicode_normalization::UnicodeNormalization;

use crate::pathutil;

/// Default-on patterns that an ordinary allow glob cannot override.
///
/// `.env.example` is intentionally excluded from `**/.env.*`.
const RESERVED_ABS_FILES: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/sudoers"];
const RESERVED_DIR_NAMES: &[&str] = &[".ssh", ".gnupg"];
const RESERVED_AWS_FILE: &str = "credentials";
const RESERVED_AWS_DIR: &str = ".aws";
const RESERVED_ENV: &str = ".env";
const ENV_EXAMPLE: &str = ".env.example";

/// Advertised-text lure needles shared with CC-015. Keep in lockstep with the
/// overlay reserved set. `.env.example` is not a lure.
pub fn secret_overlay_lure_literals() -> &'static [&'static str] {
    &[
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        ".ssh",
        ".gnupg",
        ".aws/credentials",
        ".env",
    ]
}

/// True when `token` is the excluded `.env.example` name (ASCII case-insensitive).
pub fn is_env_example_token(token: &str) -> bool {
    token.eq_ignore_ascii_case(ENV_EXAMPLE)
}

/// Invisible / format characters that must not appear in a path argument.
fn path_has_invisible_unicode(path: &str) -> bool {
    path.chars().any(|c| {
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
    })
}

fn nfkc(input: &str) -> String {
    input.nfkc().collect()
}

fn last_segment(path: &str) -> Option<&str> {
    path.rsplit('/').find(|s| !s.is_empty() && *s != ".")
}

fn segments(path: &str) -> Vec<&str> {
    path.split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect()
}

fn reserved_windows_homes() -> Vec<String> {
    let mut homes = Vec::new();
    if let Ok(profile) = std::env::var("USERPROFILE") {
        homes.push(pathutil::lexical_normalize_str(&profile.replace('\\', "/")));
    }
    if let Ok(home) = std::env::var("HOME") {
        homes.push(pathutil::lexical_normalize_str(&home.replace('\\', "/")));
    }
    homes
}

/// Reserved secret names are matched ASCII-case-insensitively so
/// `FILE://…/ETC/PASSWD` still hits `/etc/passwd`. Ordinary allow-glob
/// matching stays platform case rules and is not affected.
fn reserved_eq(a: &str, b: &str) -> bool {
    pathutil::paths_equal(a, b) || a.eq_ignore_ascii_case(b)
}

fn matches_reserved_form(normalized: &str) -> bool {
    let unified = normalized.replace('\\', "/");
    let unified_l = unified.to_ascii_lowercase();
    for reserved in RESERVED_ABS_FILES {
        if reserved_eq(&unified, reserved)
            || pathutil::path_matches_lexical(&unified, reserved)
            || pathutil::path_matches_lexical(&unified_l, reserved)
        {
            return true;
        }
        let trimmed = reserved.trim_start_matches('/');
        if reserved_eq(&unified, trimmed) || reserved_eq(&unified_l, trimmed) {
            return true;
        }
    }

    let segs = segments(&unified);
    for (i, seg) in segs.iter().enumerate() {
        if RESERVED_DIR_NAMES.iter().any(|n| reserved_eq(seg, n)) {
            return true;
        }
        if reserved_eq(seg, RESERVED_AWS_DIR)
            && segs
                .get(i + 1)
                .is_some_and(|next| reserved_eq(next, RESERVED_AWS_FILE))
        {
            return true;
        }
        if reserved_eq(seg, RESERVED_ENV) {
            return true;
        }
        let seg_l = seg.to_ascii_lowercase();
        if seg_l.starts_with(".env.") && !reserved_eq(seg, ENV_EXAMPLE) {
            return true;
        }
    }

    if let Some(last) = last_segment(&unified) {
        if reserved_eq(last, RESERVED_ENV) {
            return true;
        }
        let last_l = last.to_ascii_lowercase();
        if last_l.starts_with(".env.") && !reserved_eq(last, ENV_EXAMPLE) {
            return true;
        }
    }

    for home in reserved_windows_homes() {
        for name in RESERVED_DIR_NAMES {
            let prefix = format!("{home}/{name}");
            if pathutil::path_matches_lexical(&unified, &prefix)
                || pathutil::path_matches_lexical(&unified_l, &prefix.to_ascii_lowercase())
                || reserved_eq(&unified, &prefix)
            {
                return true;
            }
        }
        let aws = format!("{home}/{RESERVED_AWS_DIR}/{RESERVED_AWS_FILE}");
        if reserved_eq(&unified, &aws) || reserved_eq(&unified_l, &aws.to_ascii_lowercase()) {
            return true;
        }
        let env = format!("{home}/{RESERVED_ENV}");
        if reserved_eq(&unified, &env) || reserved_eq(&unified_l, &env.to_ascii_lowercase()) {
            return true;
        }
    }

    false
}

fn reserved_after_normalize(path: &str) -> bool {
    if path.is_empty() || path.contains('\0') {
        return false;
    }
    let nfkc_raw = nfkc(path);
    let lexical = pathutil::lexical_normalize_str(&nfkc_raw);
    if matches_reserved_form(&lexical) {
        return true;
    }
    if let Ok(resolved) = pathutil::resolve_for_authorization(&nfkc_raw) {
        let resolved_nfkc = nfkc(&resolved);
        if matches_reserved_form(&resolved_nfkc)
            || matches_reserved_form(&pathutil::lexical_normalize_str(&resolved_nfkc))
        {
            return true;
        }
    }
    false
}

/// True when `path` names a reserved secret after Auditor-time normalize + NFKC.
pub fn is_secret_path(path: &str) -> bool {
    if path.is_empty() || path.contains('\0') {
        return false;
    }
    if reserved_after_normalize(path) {
        return true;
    }
    match pathutil::normalize_fs_argument(path) {
        Ok(normalized) => reserved_after_normalize(&normalized),
        // Unstable percent-encoding / NUL after decode: treat as reserved
        // so overlay fails closed rather than allowing a bypass.
        Err(_) => true,
    }
}

/// Overlay evaluation for one extracted filesystem argument.
///
/// Returns `Err(reason)` when the path is NUL, contains invisible Unicode, or
/// matches the reserved set. Percent-decode and `file:` URI conversion happen
/// here (Auditor-time). Does not claim to close TOCTOU.
pub fn overlay_denies(path: &str) -> Result<(), String> {
    if path.is_empty() || path.contains('\0') {
        return Err("empty or NUL-containing path".to_string());
    }
    let normalized = match pathutil::normalize_fs_argument(path) {
        Ok(n) => n,
        Err(e) => {
            return Err(format!("path '{path}' rejected by secret-overlay ({e})"));
        }
    };
    if path_has_invisible_unicode(path) || path_has_invisible_unicode(&normalized) {
        return Err(format!(
            "path '{path}' contains invisible Unicode and is rejected by secret-overlay"
        ));
    }
    if reserved_after_normalize(path) || reserved_after_normalize(&normalized) {
        return Err(format!(
            "path '{path}' matches the secret-path overlay (beats explicit allow)"
        ));
    }
    // Confusable / non-ASCII scheme slot (`fіle://`, VS in scheme, …):
    // fail-closed. Do not ALLOW as a URL that skips overlay.
    if pathutil::uri_scheme_slot_is_dirty(path) || pathutil::uri_scheme_slot_is_dirty(&normalized) {
        return Err(format!(
            "path '{path}' has a non-ASCII or invalid URI scheme and is rejected by secret-overlay"
        ));
    }
    // Opaque `file:etc/passwd` (no //, not already /… or drive): fail-closed.
    if pathutil::is_opaque_file_uri(path) || pathutil::is_opaque_file_uri(&normalized) {
        return Err(format!(
            "path '{path}' is an opaque file: URI and is rejected by the secret-path overlay"
        ));
    }
    Ok(())
}

/// Create a symlink that resolves to a reserved secret. Unix uses `/etc/passwd`.
/// Windows uses a reserved name under `dir` (`.ssh/id_rsa`) so the test does
/// not require `/etc/passwd`. Privilege failures are returned as `Err`.
#[cfg(test)]
pub(crate) fn try_create_secret_symlink(
    dir: &std::path::Path,
) -> Result<std::path::PathBuf, String> {
    let link = dir.join("innocent.txt");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc/passwd", &link).map_err(|e| e.to_string())?;
        Ok(link)
    }
    #[cfg(windows)]
    {
        let secret_dir = dir.join(".ssh");
        std::fs::create_dir_all(&secret_dir).map_err(|e| e.to_string())?;
        let secret_file = secret_dir.join("id_rsa");
        std::fs::write(&secret_file, b"dummy").map_err(|e| e.to_string())?;
        if std::os::windows::fs::symlink_file(&secret_file, &link).is_ok() {
            return Ok(link);
        }
        let link_dir = dir.join("innocent_dir");
        std::os::windows::fs::symlink_dir(&secret_dir, &link_dir).map_err(|e| e.to_string())?;
        Ok(link_dir.join("id_rsa"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = link;
        Err("symlink overlay test is not supported on this platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncreated_ssh_under_workspace_is_secret() {
        assert!(is_secret_path("/workspace/.ssh/id_rsa"));
        assert!(is_secret_path("/workspace/.ssh"));
    }

    #[test]
    fn ordinary_workspace_file_is_not_secret() {
        assert!(!is_secret_path("/workspace/notes.txt"));
        assert!(!is_secret_path("/workspace/src/main.rs"));
    }

    #[test]
    fn env_family() {
        assert!(is_secret_path("/workspace/.env"));
        assert!(is_secret_path("/workspace/.env.local"));
        assert!(!is_secret_path("/workspace/.env.example"));
    }

    #[test]
    fn etc_reserved_files() {
        assert!(is_secret_path("/etc/passwd"));
        assert!(is_secret_path("/etc/shadow"));
        assert!(is_secret_path("/etc/sudoers"));
        assert!(!is_secret_path("/workspace/mirror/etc/passwd"));
        assert!(!is_secret_path("https://example.com/etc/passwd"));
    }

    #[test]
    fn gnupg_and_aws() {
        assert!(is_secret_path("/home/user/.gnupg/secring.gpg"));
        assert!(is_secret_path("/home/user/.aws/credentials"));
        assert!(!is_secret_path("/home/user/.aws/config"));
    }

    #[test]
    fn nfkc_fullwidth_slash_still_matches() {
        // U+FF0F FULLWIDTH SOLIDUS → `/` under NFKC
        let sneaky = "\u{ff0f}etc\u{ff0f}passwd";
        assert!(is_secret_path(sneaky));
    }

    #[test]
    fn invisible_unicode_is_denied() {
        let err = overlay_denies("/workspace/notes\u{200B}.txt").unwrap_err();
        assert!(err.contains("invisible Unicode"), "got: {err}");
    }

    #[test]
    fn nul_is_denied() {
        let err = overlay_denies("/workspace/a\0b").unwrap_err();
        assert!(err.contains("NUL"), "got: {err}");
    }

    #[test]
    fn percent_encoded_ssh_is_secret() {
        assert!(is_secret_path("/workspace/%2essh/id_rsa"));
        assert!(is_secret_path("/workspace/.%73sh/id_rsa"));
        assert!(is_secret_path("/workspace/%252essh/id_rsa"));
        assert!(overlay_denies("/workspace/%2essh/id_rsa").is_err());
        assert!(overlay_denies("/workspace/.%73sh/id_rsa").is_err());
    }

    #[test]
    fn file_uri_localhost_etc_passwd_is_secret() {
        assert!(is_secret_path("file://localhost/etc/passwd"));
        assert!(is_secret_path("file:///etc/passwd"));
        assert!(is_secret_path("file://127.0.0.1/etc/passwd"));
        assert!(overlay_denies("file://localhost/etc/passwd").is_err());
        assert!(is_secret_path("%66ile://localhost/etc/passwd"));
        assert!(overlay_denies("%66ile://localhost/etc/passwd").is_err());
        assert!(overlay_denies("%66ile://127.0.0.1/etc/passwd").is_err());
        assert!(overlay_denies("%66ile://localhost/workspace/.ssh/id_rsa").is_err());
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
            assert!(
                overlay_denies(sneaky).is_err(),
                "WHATWG C0 / encoded C0 must hit overlay: {sneaky:?}"
            );
        }
        assert!(is_secret_path("FILE://localhost/ETC/PASSWD"));
        assert!(is_secret_path("/ETC/PASSWD"));
        assert!(!is_secret_path("/workspace/Notes.txt"));
        assert!(overlay_denies("f\u{0456}le://localhost/etc/passwd").is_err());
        assert!(overlay_denies("f%D1%96le://localhost/etc/passwd").is_err());
        assert!(overlay_denies("file\u{FE0F}://localhost/etc/passwd").is_err());
        for sneaky in [
            "file://localhost\\etc\\passwd",
            "file://\\etc\\passwd",
            "%66ile://localhost\\etc\\passwd",
            "file://localhost%5Cetc%5Cpasswd",
        ] {
            assert!(
                overlay_denies(sneaky).is_err(),
                "backslash file: URI must hit overlay: {sneaky:?}"
            );
        }
        for sneaky in [
            "file:etc/passwd",
            "file:etc\\passwd",
            "file:./etc/passwd",
            "file:../etc/passwd",
        ] {
            assert!(
                is_secret_path(sneaky),
                "opaque file: must be reserved: {sneaky:?}"
            );
            assert!(
                overlay_denies(sneaky).is_err(),
                "opaque file: URI must hit overlay: {sneaky:?}"
            );
        }
        assert!(!is_secret_path("/workspace/notes.txt"));
    }

    #[test]
    fn symlink_to_secret_is_denied() {
        let dir = tempfile::tempdir().unwrap();
        match try_create_secret_symlink(dir.path()) {
            Ok(link) => {
                let path = link.to_str().expect("symlink path is utf-8");
                assert!(
                    is_secret_path(path),
                    "symlink to secret must match overlay: {path}"
                );
            }
            Err(e) => {
                eprintln!("secret-path symlink overlay test skipped: {e}");
            }
        }
    }
}
