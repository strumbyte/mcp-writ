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
    // one (shared mounts, group checkouts — a sandbox fleet's %TEMP%
    // grants `Modify` to its workers). With no write-restricted root
    // anywhere, the fixture itself is unauthorizable and there is
    // nothing to exercise.
    let Some(dir) = crate::testutil::restricted_tempdir() else {
        crate::testutil::skip_unless_required(
            "no write-restricted root for authorization fixtures",
        );
        return;
    };
    let cwd = dir.path().canonicalize().unwrap();
    let cwd = cwd.as_path();
    let resolved = resolve_for_authorization_with_cwd("data/../../secret", cwd).unwrap();
    let expected =
        to_match_string(&lexical_normalize_path(&cwd.parent().unwrap().join("secret")).unwrap());
    // `secret` as a sibling of cwd, not `data/secret`.
    assert_eq!(resolved, expected);
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
    let resolved = resolve_for_authorization_with_cwd("/workspace/src/main.rs", &anchor).unwrap();
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
    let resolved = resolve_for_authorization_with_cwd("/nonexistent-suffix-xyz", &anchor).unwrap();
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

#[test]
fn share_root_exemption_is_scoped_to_registered_descendants() {
    // A host-mounted share root (a WSB mapped folder, a container
    // bind mount) reports replaceable from inside the guest by
    // contract — only the host can retarget it, and the host is the
    // trusted launch party. Registering the root exempts paths
    // beneath it from the ancestry walk; the exemption is
    // component-scoped, never a string-prefix match.
    let dir = tempfile::tempdir().unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir(&workspace).unwrap();
    let parent = dir.path().parent().unwrap().to_path_buf();

    crate::fspriv::register_share_root(dir.path());

    let canonical = std::fs::canonicalize(&workspace).unwrap();
    assert!(crate::fspriv::path_under_share_root(&canonical));
    assert!(crate::fspriv::path_under_share_root(&workspace));
    // The root's own parent and a suffix-sibling spelling must not
    // match.
    assert!(!crate::fspriv::path_under_share_root(&parent));
    let prefix_sibling = parent.join(format!(
        "{}2",
        dir.path().file_name().unwrap().to_string_lossy()
    ));
    assert!(!crate::fspriv::path_under_share_root(&prefix_sibling));
    // The authorization resolve accepts the descendant — on a
    // shared-writable temp tree this is the only way it can pass.
    let spelling = workspace.display().to_string().replace('\\', "/");
    resolve_for_authorization(&spelling)
        .unwrap_or_else(|e| panic!("descendant of a registered share root must resolve: {e}"));
}
