//! Helpers shared by `#[cfg(test)]` modules across the crate.

use std::path::PathBuf;

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

/// Real spelling of the system temp dir, resolving platform links such
/// as macOS's `/var` → `/private/var`. Paths under `$TMPDIR` are handed
/// to the audit sink and other strict `O_NOFOLLOW` ancestor walks, which
/// refuse any linked component — tests must spell them the way the
/// filesystem actually lays them out.
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

/// Report a skipped test — `SKIP:` on stderr, like
/// `tests/common::skip_e2e_test` — or fail it outright when the
/// verification job marks unexecuted tests as failures
/// (`MCP_WRIT_REQUIRE_E2E_TESTS=1`). That env is set at workflow level
/// on every CI verification job, so it also covers the
/// `cargo test --lib --bins` unit-test legs: a lib test that cannot
/// build its fixture is an unexecuted test too and must not pass
/// silently there.
pub(crate) fn skip_unless_required(reason: &str) {
    assert!(
        std::env::var("MCP_WRIT_REQUIRE_E2E_TESTS").as_deref() != Ok("1"),
        "test prerequisite failed: {reason} (MCP_WRIT_REQUIRE_E2E_TESTS=1)"
    );
    eprintln!("SKIP: {reason}");
}

/// A `TempDir` under a root every ancestor of which passes
/// [`crate::fspriv::require_parent_write_restricted`] — the
/// authorization layer's own demand on any path a test asks it to
/// resolve. `%TEMP%` is not such a root on hosts that share it with
/// lower-trust workers (a sandbox fleet granting `Modify` on the temp
/// dir makes every fixture beneath it unauthorizable — the refusal is
/// the contract working, not a testable resolution). Falls back to the
/// user's home/profile directory — owner-locked by default on unix and
/// Windows alike — and returns `None` when no restricted root
/// exists, which callers treat as "this environment cannot run the
/// test" via [`skip_unless_required`].
pub(crate) fn restricted_tempdir() -> Option<tempfile::TempDir> {
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
        // A UNC root — a roaming-profile %TEMP%/%USERPROFILE%, or a
        // junction canonicalized onto a share — can pass the DACL probe
        // below yet is never authorizable: `resolve_for_authorization`
        // refuses `\\server\share` before any lookup. Treat it as no
        // candidate so callers take the optional-skip path.
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
            return Some(dir);
        }
    }
    None
}

/// Argument-string corpus shared by the PR-03 differential tests —
/// exercises every branch the classification fast paths must preserve:
/// opaque tokens (the fast path's domain), single-punctuation boundary
/// variants, encodings, Unicode confusables, controls, NUL, and
/// selector spellings for each key vocabulary.
pub(crate) fn argument_classification_corpus() -> Vec<String> {
    let mut v: Vec<String> = [
        // Opaque ASCII tokens — the fast path's domain.
        "hello",
        "prod-server",
        "a1_-+=,;x",
        "UPPER",
        "  padded  ",
        "x y",
        "[bracket]",
        "{opaque}",
        "tok#frag",
        "tok?query",
        "*wild*",
        "line1'quote",
        "say\"hi",
        // One selector-significant byte inside an opaque token.
        "a.b",
        "..",
        ".",
        ".env",
        ".ENV",
        ".env.local",
        ".env.example",
        ".ssh",
        ".gnupg",
        ".aws",
        "credentials",
        "id_rsa",
        "a..b",
        "10.0.0.1",
        "256.1.1.1",
        "1.2.3.4.5",
        "v1.2",
        "a/b",
        "./rel",
        "../up",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/private/etc/passwd",
        "etc/passwd",
        "a\\b",
        "C:\\x",
        "C:/x",
        "\\\\server\\share",
        "/workspace/notes.txt",
        "/workspace/.env",
        "/home/user/.aws/credentials",
        "/home/u/.aws/config",
        "/w/.ssh/id_rsa",
        "x:y",
        "h:80",
        "C:x",
        "a:b:c",
        ":8080",
        "[::1]",
        "[::1]:443",
        "[::g]",
        "[]:80",
        "~",
        "~/x",
        "~root/x",
        "$V",
        "$V/x",
        "u@h",
        "@scope",
        "a%b",
        "%41",
        "%GG",
        "%",
        "%%",
        "%00",
        "a%0Ab",
        "%252e",
        "%2e%2e/x",
        "%66ile:///etc/passwd",
        "file:///etc/passwd",
        "FILE:///ETC/PASSWD",
        "file://localhost/etc/passwd",
        "file://127.0.0.1/etc/passwd",
        "file://[::1]/etc/passwd",
        "file://evil.com/etc/passwd",
        "file:etc/passwd",
        "file:./etc/passwd",
        "file:../etc/passwd",
        "file:////host/share",
        "file://localhost//host/share",
        "file://localhost/etc/passwd?x=1",
        "file:///etc/passwd#frag",
        "file \t://localhost/etc/passwd",
        "file%0A://localhost/etc/passwd",
        "file%250B://localhost/etc/passwd",
        "file\u{00A0}://localhost/etc/passwd",
        "\u{FB01}le:///etc/passwd",
        "f\u{0456}le:///etc/passwd",
        "%EF%BD%86ile:///etc/passwd",
        "%66ile%0A://localhost/etc/passwd",
        // NFKC introduces the `%` escape *after* the bounded decode ran
        // (fullwidth `％` → `%`) — only a second normalization pass
        // reveals the `file:` URI / `..` path underneath.
        "\u{ff05}66ile://localhost/etc/passwd",
        "\u{ff05}2e\u{ff05}2e/x",
        "https://example.com",
        "http://h/x",
        "ftp://h",
        "a://b",
        "//host/share",
        "//a",
        "://",
        "x://y",
        // Network shapes.
        "localhost",
        "example.com",
        "sub.example.com",
        "a-b.example.com",
        "127.0.0.1",
        "::1",
        "1.2.3.4",
        "hostname",
        // Non-dotted IPv4 spellings (`inet_aton` accepts them, Rust's
        // `IpAddr` does not) — plain tokens that still route through
        // the key vocabulary's host-vs-URL call, not the value-shape
        // host/socket test.
        "2130706433",
        "0x7f000001",
        // Payload-ish.
        "read ./report.txt",
        "hello world",
        "line\nbreak",
        "tab\tsep",
        "{\"j\":1}",
        "[1,2]",
        // Controls / edge bytes.
        "",
        " ",
        "   ",
        "\t",
        "\n",
        "a\u{0001}b",
        "a\u{007f}b",
        "a\u{0085}b",
        "a\u{2028}b",
        "a\u{2029}b",
        "a\0b",
        "\0",
        // Unicode.
        "caf\u{00e9}",
        "\u{ff21}\u{ff22}",
        "\u{200b}x",
        "x\u{00a0}y",
        "\u{ff0f}etc\u{ff0f}passwd",
        "\u{ff45}\u{ff54}\u{ff43}\u{ff0f}\u{ff50}\u{ff41}\u{ff53}\u{ff53}\u{ff57}\u{ff44}",
        "n\u{0303}ame",
        "e\u{0301}",
        "\u{034f}x",
        "\u{feff}x",
        "\u{180e}x",
        "$.items[0]",
        "$[0]",
        "$",
        "$.x",
        "x$",
        "$x",
        "$[",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    // Size-scaled boundary variants — the byte-scan fast path must not
    // change the verdict at any length.
    for prefix in ["A", "A B", "-", "_", "[", "x"] {
        for tail in [
            "", ".", "/", "\\", ":", "~", "$", "%", "@", "..", "x", "\u{ff41}",
        ] {
            v.push(format!("{}{}{}", prefix.repeat(700), tail, "z".repeat(9)));
        }
    }
    v.push("A".repeat(4096));
    v.push(format!("{}.env", "A".repeat(500)));
    v.push(format!("{}/x", "A".repeat(500)));
    v.push(format!("file://localhost/{}", "A".repeat(500)));
    v.push(format!("{}.env{}", "%".repeat(30), "A".repeat(500)));
    v
}

/// Set `dir`'s DACL from an SDDL string as a protected DACL, so the
/// fixture's trust state is exactly the spelled one regardless of the
/// ACEs the parent would otherwise hand down. Applying it propagates
/// to existing children (their inherited ACEs are stripped), so
/// fixtures that need a readable child apply the DACL before creating
/// the child and give the ACEs OI/CI inheritance.
#[cfg(windows)]
pub(crate) fn set_dacl_from_sddl(dir: &std::path::Path, sddl: &str) {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
    };
    use windows::core::HSTRING;

    let mut sd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&HSTRING::from(sddl), 1, &mut sd, None)
    }
    .unwrap_or_else(|e| panic!("SDDL '{sddl}' must parse: {e}"));
    let mut present = windows::core::BOOL(0);
    let mut defaulted = windows::core::BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }
        .unwrap_or_else(|e| panic!("GetSecurityDescriptorDacl: {e}"));
    assert!(present.as_bool(), "fixture SDDL must carry a DACL");
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    let result = unsafe {
        SetNamedSecurityInfoW(
            &HSTRING::from(dir.to_string_lossy().as_ref()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    result
        .ok()
        .unwrap_or_else(|e| panic!("SetNamedSecurityInfoW for '{}': {e}", dir.display()));
}
