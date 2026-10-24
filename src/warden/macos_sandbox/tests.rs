use super::*;
use crate::policy::default_policy;

// ---------------------------------------------------------------
// extract_port
// ---------------------------------------------------------------

#[test]
fn test_extract_port_host_colon_port() {
    assert_eq!(extract_local_port("localhost:8080").unwrap(), Some(8080));
    assert_eq!(extract_local_port("*:443").unwrap(), Some(443));
}

#[test]
fn test_extract_port_colon_port() {
    assert_eq!(extract_local_port(":80").unwrap(), Some(80));
}

#[test]
fn test_extract_port_plain_number() {
    assert_eq!(extract_local_port("80").unwrap(), Some(80));
}

#[test]
fn test_extract_port_invalid() {
    assert!(extract_local_port("not-a-port").is_err());
    assert_eq!(extract_local_port("").unwrap(), None);
}

#[test]
fn test_extract_port_rejects_remote_host() {
    assert!(extract_local_port("api.example.com:443").is_err());
    assert!(extract_local_port("https://evil.example").is_err());
}

#[test]
fn test_extract_port_bare_ipv6_loopback() {
    assert_eq!(extract_local_port("::1").unwrap(), None);
    assert_eq!(extract_local_port("[::1]").unwrap(), None);
    assert_eq!(extract_local_port("[::1]:8080").unwrap(), Some(8080));
}

#[test]
fn test_extract_port_bare_ipv6_is_never_host_port() {
    // A bare multi-colon string is a v6 literal, not host:port —
    // `::1:8080` is the v6 address `::1:8080`, not `::1` port
    // 8080. Any non-loopback literal is a remote host and must
    // refuse, exactly like a remote name.
    assert!(extract_local_port("::1:8080").is_err());
    assert!(extract_local_port("::1:443").is_err());
    assert!(extract_local_port("2001:db8::1").is_err());
    // The loopback literal itself stays port-less.
    assert_eq!(extract_local_port("::1").unwrap(), None);
}

#[test]
fn test_is_explicit_loopback_host_classifies_stored_forms() {
    // The host identity the parser stores: `host="::1"` is the
    // loopback literal; `host="::1:8080"` is the *non-loopback*
    // v6 address `::1:8080` — never `::1` with a port.
    assert!(is_explicit_loopback_host("::1"));
    assert!(is_explicit_loopback_host("[::1]"));
    assert!(is_explicit_loopback_host("[::1]:8080"));
    assert!(is_explicit_loopback_host("localhost"));
    assert!(is_explicit_loopback_host("localhost:8080"));
    assert!(is_explicit_loopback_host("127.0.0.1"));
    assert!(is_explicit_loopback_host("127.0.0.1:80"));
    assert!(!is_explicit_loopback_host("::1:8080"));
    assert!(!is_explicit_loopback_host("::1:443"));
    assert!(!is_explicit_loopback_host("2001:db8::1"));
    assert!(!is_explicit_loopback_host("*:443"));
    assert!(!is_explicit_loopback_host("443"));
    assert!(!is_explicit_loopback_host("api.example.com:443"));
}

// ---------------------------------------------------------------
// escape_sbpl_path
// ---------------------------------------------------------------

#[test]
fn test_escape_no_special_chars() {
    assert_eq!(
        escape_sbpl_path("/usr/local/bin")
            .expect("failed to escape sbpl path for no special chars"),
        "/usr/local/bin"
    );
}

#[test]
fn test_escape_quotes() {
    assert_eq!(
        escape_sbpl_path("/path/with\"quotes\"").expect("failed to escape sbpl path for quotes"),
        "/path/with\\\"quotes\\\""
    );
}

#[test]
fn test_escape_backslash() {
    assert_eq!(
        escape_sbpl_path("/path\\back").expect("failed to escape sbpl path for backslash"),
        "/path\\\\back"
    );
}

#[test]
fn test_escape_supported_control_chars() {
    assert_eq!(
        escape_sbpl_path("/path\nwith\nnewlines").unwrap(),
        "/path\\nwith\\nnewlines"
    );
    assert_eq!(
        escape_sbpl_path("/path\twith\ttabs").unwrap(),
        "/path\\twith\\ttabs"
    );
    assert_eq!(
        escape_sbpl_path("/path\rwith\rreturns").unwrap(),
        "/path\\rwith\\rreturns"
    );
}

#[test]
fn test_escape_rejects_nul() {
    let result = escape_sbpl_path("/path\0with_nul");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("U+0000"),
        "error should mention the codepoint: {msg}"
    );
}

#[test]
fn test_escape_rejects_other_control_chars() {
    // BEL (U+0007)
    let result = escape_sbpl_path("/path\x07bel");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("U+0007"),
        "error should mention the codepoint: {msg}"
    );

    // ESC (U+001B)
    let result = escape_sbpl_path("/path\x1besc");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("U+001B"),
        "error should mention the codepoint: {msg}"
    );

    // DEL (U+007F)
    let result = escape_sbpl_path("/path\x7Fdel");
    assert!(result.is_err());
    let msg = format!("{}", result.unwrap_err());
    assert!(
        msg.contains("U+007F"),
        "error should mention the codepoint: {msg}"
    );
}

// ---------------------------------------------------------------
// generate_sbpl — structure
// ---------------------------------------------------------------

#[test]
fn test_sbpl_starts_with_version_and_deny_default() {
    let policy = default_policy();
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.starts_with("(version 1)\n(deny default)\n"));
}

#[test]
fn test_sbpl_contains_essential_operations() {
    let policy = default_policy();
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow process-fork)"));
    assert!(sbpl.contains("(allow process-exec)"));
    assert!(sbpl.contains("(allow signal (target self))"));
    assert!(sbpl.contains("(allow sysctl-read)"));
    assert!(sbpl.contains("(allow process-info* (target same-sandbox))"));
}

#[test]
fn test_sbpl_contains_system_library_reads() {
    let policy = default_policy();
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow file-read* (subpath \"/usr/lib\"))"));
    assert!(sbpl.contains("(allow file-read* (subpath \"/System/Library\"))"));
    assert!(sbpl.contains("(allow file-read* (subpath \"/usr/share\"))"));
    // Dynamic library mapping
    assert!(sbpl.contains("(allow file-map-executable (subpath \"/usr/lib\"))"));
    assert!(sbpl.contains("(allow file-map-executable (subpath \"/System/Library\"))"));
    // Executable binary paths
    assert!(sbpl.contains("(subpath \"/bin\")"));
    assert!(sbpl.contains("(subpath \"/usr/bin\")"));
}

#[test]
fn test_sbpl_contains_dev_nodes() {
    let policy = default_policy();
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow file-read* (literal \"/dev/null\"))"));
    assert!(sbpl.contains("(allow file-read* (literal \"/dev/urandom\"))"));
}

#[test]
fn test_sbpl_contains_tmp_paths() {
    let policy = default_policy();
    let sbpl = generate_sbpl_with_tmpdir(&policy, "/private/tmp/mcp-writ-test-tmp").unwrap();
    assert!(
        sbpl.contains(
            "(allow file-read* file-write* (subpath \"/private/tmp/mcp-writ-test-tmp\"))"
        )
    );
    assert!(!sbpl.contains("(allow file-read* file-write* (subpath \"/private/tmp\"))"));
    assert!(!sbpl.contains("(allow file-read* file-write* (subpath \"/tmp\"))"));
    assert!(!sbpl.contains("(subpath \"/etc\")"));
    assert!(sbpl.contains("(literal \"/etc/hosts\")"));
}

#[test]
fn test_sbpl_contains_mach_services() {
    let policy = default_policy();
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("com.apple.system.logger"));
    assert!(sbpl.contains("com.apple.mDNSResponder"));
    assert!(sbpl.contains("com.apple.trustd"));
    assert!(sbpl.contains("com.apple.secinitd"));
    assert!(sbpl.contains("com.apple.system.opendirectoryd.libinfo"));
}

// ---------------------------------------------------------------
// generate_sbpl — filesystem policy
// ---------------------------------------------------------------

#[test]
fn test_sbpl_read_only_paths() {
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/opt/data".to_string(), "/usr/local/share".to_string()];
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow file-read* (subpath \"/opt/data\"))"));
    assert!(sbpl.contains("(allow file-read* (subpath \"/usr/local/share\"))"));
}

#[test]
fn test_sbpl_read_write_paths() {
    let mut policy = default_policy();
    // "/var/data" canonicalizes to "/private/var/data" on macOS —
    // the kernel matches resolved vnode paths, so the profile must
    // carry the resolved form.
    policy.fs.read_write = vec!["/var/data".to_string()];
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/private/var/data\"))"));
}

#[test]
fn test_grant_overlapping_denied_path_rejected() {
    // `/etc` canonicalizes to `/private/etc` on macOS, so a spelled
    // grant that cleared the load-time conflict check can still reach
    // a denied subtree — the emitted `(allow …)` line would reopen it.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/etc".to_string()];
    policy.fs.denied_paths = vec!["/private/etc/mcp-writ-denied".to_string()];
    let err = generate_sbpl(&policy).expect_err("grant covering a denied path must fail");
    assert!(
        err.to_string().contains("overlaps denied path"),
        "got: {err}"
    );

    let mut policy = default_policy();
    policy.fs.read_write = vec!["/private/etc/mcp-writ-denied/sub".to_string()];
    policy.fs.denied_paths = vec!["/etc/mcp-writ-denied".to_string()];
    let err = generate_sbpl(&policy).expect_err("grant inside a denied path must fail");
    assert!(
        err.to_string().contains("overlaps denied path"),
        "got: {err}"
    );

    // Distinct spellings that canonicalize to the same path — the
    // grant re-allows the denial verbatim. `is_strict_subpath_or_
    // descendant_for` already catches equality (case-insensitively
    // under the macOS component rules), and a case-only difference
    // between canonicalized spellings must reject identically.
    assert!(
        reject_denied_grant(
            "/private/etc/mcp-writ-denied",
            "/private/etc/mcp-writ-denied",
            &["/private/etc/mcp-writ-denied".to_string()],
        )
        .is_err(),
        "canonical-equal grant must be rejected"
    );
    assert!(
        reject_denied_grant(
            "/private/etc/MCP-WRIT-DENIED",
            "/private/etc/MCP-WRIT-DENIED",
            &["/private/etc/mcp-writ-denied".to_string()],
        )
        .is_err(),
        "case-variant canonical-equal grant must be rejected"
    );
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/etc/mcp-writ-denied".to_string()];
    policy.fs.denied_paths = vec!["/private/etc/mcp-writ-denied".to_string()];
    let err = generate_sbpl(&policy)
        .expect_err("grant canonicalizing to the denied path itself must fail");
    assert!(
        err.to_string().contains("overlaps denied path"),
        "got: {err}"
    );
}

#[test]
fn test_sbpl_canonicalizes_symlinked_grant_prefix() {
    // A policy path under /tmp (a symlink to /private/tmp) must emit
    // the resolved subpath, including ancestors for traversal —
    // otherwise the grant silently matches nothing.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/tmp/mcp-writ-nonexistent-dir".to_string()];
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(
        sbpl.contains("(allow file-read* (subpath \"/private/tmp/mcp-writ-nonexistent-dir\"))")
    );
    assert!(sbpl.contains("(allow file-read-metadata (literal \"/private/tmp\"))"));
    // /tmp is a symlink to private/tmp — following it requires
    // file-read-data on the link vnode itself, not just metadata.
    assert!(sbpl.contains("(allow file-read* (literal \"/tmp\"))"));
}

#[test]
fn test_grant_records_canonical_path_with_spelled_reason() {
    // The recorded grant must name the path the SBPL line actually
    // grants (the canonical form); when canonicalization rewrote it,
    // the spelled policy path stays in the reason.
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/tmp/mcp-writ-nonexistent-dir".to_string()];
    let (sbpl, grants) = sbpl_profile(&policy, "/private/tmp/mcp-writ-unused", &[]).unwrap();
    assert!(
        sbpl.contains("(allow file-read* (subpath \"/private/tmp/mcp-writ-nonexistent-dir\"))")
    );
    let grant = grants
        .iter()
        .find(|g| {
            matches!(
                &g.subject,
                GrantSubject::FsPath { path, .. }
                    if path == "/private/tmp/mcp-writ-nonexistent-dir"
            )
        })
        .expect("grant must carry the canonical path");
    assert_eq!(grant.origin, GrantOrigin::Policy);
    assert_eq!(
        grant.reason.as_deref(),
        Some("canonicalized from /tmp/mcp-writ-nonexistent-dir")
    );
}

#[test]
fn test_sbpl_path_escaping_in_policy() {
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/path/with\"quotes".to_string()];
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow file-read* (subpath \"/path/with\\\"quotes\"))"));
}

#[test]
fn test_sbpl_rejects_control_char_in_policy_path() {
    let mut policy = default_policy();
    policy.fs.read_only = vec!["/path/\x07evil".to_string()];
    assert!(generate_sbpl(&policy).is_err());

    let mut policy = default_policy();
    policy.fs.read_write = vec!["/path/\0nul".to_string()];
    assert!(generate_sbpl(&policy).is_err());
}

// ---------------------------------------------------------------
// generate_sbpl — executable-map grants
// ---------------------------------------------------------------

#[test]
fn test_sbpl_exec_policy_paths_map_executable() {
    let mut policy = default_policy();
    policy.fs.executable = vec!["/opt/homebrew".to_string()];
    let (sbpl, grants) = sbpl_profile(&policy, "/private/tmp/mcp-writ-unused", &[]).unwrap();
    assert!(
        sbpl.contains("(allow file-read* file-map-executable (subpath \"/opt/homebrew\"))"),
        "got: {sbpl}"
    );
    let grant = grants
        .iter()
        .find(|g| {
            matches!(
                &g.subject,
                GrantSubject::FsPath { path, access: FsAccess::Execute }
                    if path == "/opt/homebrew"
            )
        })
        .expect("exec grant must be recorded");
    assert_eq!(grant.origin, GrantOrigin::Policy);
}

#[test]
fn test_sbpl_exec_policy_path_denied_overlap_rejected() {
    let mut policy = default_policy();
    policy.fs.executable = vec!["/private/etc/mcp-writ-denied/bin".to_string()];
    policy.fs.denied_paths = vec!["/etc/mcp-writ-denied".to_string()];
    let err = generate_sbpl(&policy).expect_err("exec grant inside a denied path must fail");
    assert!(
        err.to_string().contains("overlaps denied path"),
        "got: {err}"
    );
}

#[test]
fn test_sbpl_exec_map_dirs_emit() {
    // Runtime-derived code roots land as read+map-executable
    // subpath grants with Runtime origin — never write.
    let dirs = [PathBuf::from("/opt/tools"), PathBuf::from("/opt/tools/lib")];
    let (sbpl, grants) =
        sbpl_profile(&default_policy(), "/private/tmp/mcp-writ-unused", &dirs).unwrap();
    assert!(
        sbpl.contains("(allow file-read* file-map-executable (subpath \"/opt/tools\"))"),
        "got: {sbpl}"
    );
    assert!(
        sbpl.contains("(allow file-read* file-map-executable (subpath \"/opt/tools/lib\"))"),
        "got: {sbpl}"
    );
    assert!(!sbpl.contains("file-write* (subpath \"/opt/tools"));
    for d in &dirs {
        let grant = grants
            .iter()
            .find(|g| {
                matches!(
                    &g.subject,
                    GrantSubject::FsPath { path, access: FsAccess::Execute }
                        if path == &d.to_string_lossy().into_owned()
                )
            })
            .unwrap_or_else(|| panic!("missing grant for {}", d.display()));
        assert_eq!(grant.origin, GrantOrigin::Runtime);
    }
}

#[test]
fn test_exec_map_dir_denied_overlap_rejected() {
    // A derived/staged dir that canonicalizes into a denied subtree
    // must not reopen it — the same guard policy paths get.
    let mut policy = default_policy();
    policy.fs.denied_paths = vec!["/opt/secrets".to_string()];
    let dirs = [PathBuf::from("/opt/secrets/staged")];
    assert!(sbpl_profile(&policy, "/private/tmp/mcp-writ-unused", &dirs).is_err());
}

#[test]
fn test_exec_map_dir_writable_overlap() {
    // An exec dir inside a writable path — or a staged dir inside
    // the writable TMPDIR — means the code root itself is writable:
    // the drop-and-run channel no narrowing can close, so the
    // launch is refused. Runtime-derived roots skip load-time
    // validation, so the guard runs here on canonical spellings.
    let mut policy = default_policy();
    policy.fs.read_write = vec!["/opt/build".to_string()];
    for dirs in [
        vec![PathBuf::from("/opt/build/out")], // exec inside write
        vec![PathBuf::from("/opt/build")],     // exec == write
    ] {
        let err = sbpl_profile(&policy, "/private/tmp/mcp-writ-unused", &dirs).unwrap_err();
        assert!(err.to_string().contains("drop-and-run"), "got: {err}");
    }
    let dirs = [PathBuf::from("/private/tmp/mcp-writ-unused/staged")];
    assert!(sbpl_profile(&policy, "/private/tmp/mcp-writ-unused", &dirs).is_err());

    // A writable path strictly inside an exec dir is the mirror
    // case — the script's own dir blessed for code, holding a
    // writable scratch child. The writable subtree keeps its
    // declared coverage; exec-map is carved back out of it, so the
    // launch proceeds with the channel still closed.
    let dirs = [PathBuf::from("/opt")];
    let (sbpl, _grants) = sbpl_profile(&policy, "/private/tmp/mcp-writ-unused", &dirs).unwrap();
    assert!(
        sbpl.contains("(deny file-map-executable (subpath \"/opt/build\"))"),
        "writable subtree must be carved out of exec-map: {sbpl}"
    );
    assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/opt/build\"))"));
    assert!(sbpl.contains("(allow file-read* file-map-executable (subpath \"/opt\"))"));

    // Non-overlapping dirs still pass.
    let dirs = [PathBuf::from("/opt/toolchain")];
    assert!(sbpl_profile(&policy, "/private/tmp/mcp-writ-unused", &dirs).is_ok());
}

#[test]
fn test_private_tmpdir_never_map_executable() {
    // The writable TMPDIR must never carry file-map-executable —
    // that combination is the drop-and-run channel.
    let tmp = "/private/tmp/mcp-writ-test-tmp-noexec";
    let sbpl = generate_sbpl_with_tmpdir(&default_policy(), tmp).unwrap();
    assert!(sbpl.contains(&format!(
        "(allow file-read* file-write* (subpath \"{tmp}\"))"
    )));
    assert!(
        !sbpl.contains(&format!("file-map-executable (subpath \"{tmp}\")")),
        "TMPDIR must not be executable-mappable: {sbpl}"
    );
    assert!(
        !sbpl.contains("file-write* file-map-executable"),
        "no line may combine write with map-executable: {sbpl}"
    );
}

// ---------------------------------------------------------------
// code_map_dirs — workload code-map derivation
// ---------------------------------------------------------------

/// Minimal Mach-O bytes (arm64 MH_EXECUTE) carrying the given
/// LC_LOAD_DYLIB / LC_RPATH load commands — enough for goblin to
/// enumerate `libs`/`rpaths` without a real toolchain.
fn fake_macho(libs: &[&str], rpaths: &[&str]) -> Vec<u8> {
    let mut cmds = Vec::new();
    for lib in libs {
        let name = lib.as_bytes();
        let start = cmds.len();
        let size = 24 + ((name.len() + 1 + 7) & !7);
        cmds.extend_from_slice(&0xcu32.to_le_bytes()); // LC_LOAD_DYLIB
        cmds.extend_from_slice(&(size as u32).to_le_bytes());
        cmds.extend_from_slice(&24u32.to_le_bytes()); // name offset
        cmds.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        cmds.extend_from_slice(&0u32.to_le_bytes()); // current_version
        cmds.extend_from_slice(&0u32.to_le_bytes()); // compat_version
        cmds.extend_from_slice(name);
        cmds.push(0);
        cmds.resize(start + size, 0);
    }
    for rp in rpaths {
        let name = rp.as_bytes();
        let start = cmds.len();
        let size = 8 + ((name.len() + 1 + 7) & !7);
        cmds.extend_from_slice(&0x8000_001cu32.to_le_bytes()); // LC_RPATH
        cmds.extend_from_slice(&(size as u32).to_le_bytes());
        cmds.extend_from_slice(&8u32.to_le_bytes()); // path offset
        cmds.extend_from_slice(name);
        cmds.push(0);
        cmds.resize(start + size, 0);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&0xfeedfacfu32.to_le_bytes()); // MH_MAGIC_64
    out.extend_from_slice(&0x0100_000cu32.to_le_bytes()); // CPU_TYPE_ARM64
    out.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
    out.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    out.extend_from_slice(&((libs.len() + rpaths.len()) as u32).to_le_bytes());
    out.extend_from_slice(&(cmds.len() as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&cmds);
    out
}

fn write_fake_macho(path: &Path, libs: &[&str], rpaths: &[&str]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, fake_macho(libs, rpaths)).unwrap();
}

fn fresh_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("mcp-writ-codemapt-{}-{}", tag, std::process::id())); // nosemgrep: rust.lang.security.temp-dir.temp-dir
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn test_expand_dyld_var_forms() {
    let loader = Path::new("/pkg/bin");
    let exe = Path::new("/app/bin");
    assert_eq!(
        expand_dyld_var("@loader_path/../lib/libx.dylib", loader, exe),
        PathBuf::from("/pkg/bin/../lib/libx.dylib")
    );
    assert_eq!(
        expand_dyld_var("@executable_path/../lib/libx.dylib", loader, exe),
        PathBuf::from("/app/bin/../lib/libx.dylib")
    );
    assert_eq!(
        expand_dyld_var("/usr/lib/libx.dylib", loader, exe),
        PathBuf::from("/usr/lib/libx.dylib")
    );
    // Bare "@rpath/…" is not expanded here — dep_candidates does it.
    assert_eq!(
        expand_dyld_var("@rpath/libx.dylib", loader, exe),
        PathBuf::from("@rpath/libx.dylib")
    );
}

#[test]
fn test_dep_candidates_rpath() {
    let rpaths = vec![PathBuf::from("/pkg/lib"), PathBuf::from("/pkg/deps")];
    let cands = dep_candidates(
        "@rpath/libbar.dylib",
        Path::new("/pkg/bin"),
        Path::new("/app/bin"),
        &rpaths,
    );
    assert!(cands.contains(&PathBuf::from("/pkg/lib/libbar.dylib")));
    assert!(cands.contains(&PathBuf::from("/pkg/deps/libbar.dylib")));
    // dyld's fallback roots ride along — /usr/local/lib carries
    // operator-installed libraries, /usr/lib the shared cache.
    assert!(cands.contains(&PathBuf::from("/usr/local/lib/libbar.dylib")));
    assert!(cands.contains(&PathBuf::from("/usr/lib/libbar.dylib")));
}

#[test]
fn test_code_root_for_layout_and_base() {
    let dir = fresh_dir("roots").canonicalize().unwrap();
    let pkg = dir.join("pkg");
    std::fs::create_dir_all(pkg.join("bin")).unwrap();
    std::fs::create_dir_all(pkg.join("lib")).unwrap();
    let tool = pkg.join("bin").join("tool");
    std::fs::write(&tool, b"x").unwrap();

    // …/bin/tool climbs to the package root.
    assert_eq!(code_root_for(&tool, false), Some(pkg.clone()));
    // A file directly in the package dir grants its own parent.
    let misc = pkg.join("misc.dat");
    std::fs::write(&misc, b"x").unwrap();
    assert_eq!(code_root_for(&misc, false), Some(pkg.clone()));
    // Payload layout: dist/server.py climbs to the project root.
    let dist = pkg.join("proj").join("dist");
    std::fs::create_dir_all(&dist).unwrap();
    let script = dist.join("server.py");
    std::fs::write(&script, b"x").unwrap();
    assert_eq!(
        code_root_for(&script, true),
        Some(pkg.join("proj")),
        "payload under dist/ must bless the project root"
    );
    // Without the payload flag, only dist/ itself is granted.
    assert_eq!(code_root_for(&script, false), Some(dist));

    // Base-covered and shallow paths derive nothing.
    assert_eq!(code_root_for(Path::new("/usr/bin/true"), false), None);
    assert_eq!(code_root_for(Path::new("/usr/lib/libx.dylib"), false), None);
}

#[test]
fn test_code_map_dirs_derives_package_root() {
    let dir = fresh_dir("walk").canonicalize().unwrap();
    // tmp/pkg/bin/tool depends (absolute) on tmp/pkg/lib/libfoo.dylib
    let lib = dir.join("pkg").join("lib").join("libfoo.dylib");
    write_fake_macho(&lib, &[], &[]);
    let lib_spelled = lib.to_string_lossy().into_owned();
    let exe = dir.join("pkg").join("bin").join("tool");
    write_fake_macho(&exe, &[&lib_spelled], &[]);

    let roots = code_map_dirs(&exe, &[exe.to_string_lossy().into_owned()]);
    assert!(
        roots.contains(&dir.join("pkg")),
        "exe bin/ climb and dep lib/ climb must land the package root; got {roots:?}"
    );
}

#[test]
fn test_code_map_dirs_rpath_loader_path() {
    let dir = fresh_dir("rpath").canonicalize().unwrap();
    // exe: app/bin/tool, LC_RPATH=@loader_path/../lib, dep=@rpath/libbar.dylib
    let lib = dir.join("app").join("lib").join("libbar.dylib");
    write_fake_macho(&lib, &[], &[]);
    let exe = dir.join("app").join("bin").join("tool");
    write_fake_macho(&exe, &["@rpath/libbar.dylib"], &["@loader_path/../lib"]);

    let roots = code_map_dirs(&exe, &[exe.to_string_lossy().into_owned()]);
    assert!(
        roots.contains(&dir.join("app")),
        "@rpath via @loader_path LC_RPATH must resolve; got {roots:?}"
    );
}

#[test]
fn test_code_map_dirs_cycle_and_missing_terminate() {
    let dir = fresh_dir("cycle").canonicalize().unwrap();
    let a = dir.join("pkg").join("lib").join("a.dylib");
    let b = dir.join("pkg").join("lib").join("b.dylib");
    write_fake_macho(&a, &[&b.to_string_lossy()], &[]);
    write_fake_macho(&b, &[&a.to_string_lossy()], &[]);
    let exe = dir.join("pkg").join("bin").join("tool");
    write_fake_macho(
        &exe,
        &[&a.to_string_lossy(), "/nonexistent/libgone.dylib"],
        &[],
    );

    // Cycle: a→b→a must terminate via the seen-set; the missing
    // dep is skipped, not fatal — and the package root still lands.
    let roots = code_map_dirs(&exe, &[exe.to_string_lossy().into_owned()]);
    assert!(roots.contains(&dir.join("pkg")), "got {roots:?}");
}

#[test]
fn test_code_map_dirs_system_binary_needs_nothing() {
    // /usr/bin/true links only /usr/lib/libSystem.B.dylib — the base
    // profile already covers it, so derivation must stay empty.
    let roots = code_map_dirs(Path::new("/usr/bin/true"), &["/usr/bin/true".to_string()]);
    assert!(roots.is_empty(), "system-only closure: got {roots:?}");
}

#[test]
fn test_code_map_dirs_xcselect_shim_maps_clt() {
    // A /usr/bin-style shim linking libxcselect re-execs inside the
    // CommandLineTools tree at runtime — the dep walk cannot see it.
    let dir = fresh_dir("xcselect").canonicalize().unwrap();
    let exe = dir.join("pkg").join("bin").join("python3");
    write_fake_macho(&exe, &["/usr/lib/libxcselect.dylib"], &[]);

    let roots = code_map_dirs(&exe, &[exe.to_string_lossy().into_owned()]);
    if Path::new(CLT_ROOT).is_dir() {
        assert!(
            roots.contains(&PathBuf::from(CLT_ROOT)),
            "libxcselect dep must bless the CLT tree; got {roots:?}"
        );
    } else {
        assert!(!roots.contains(&PathBuf::from(CLT_ROOT)));
    }
}

#[test]
fn test_code_map_dirs_interpreter_payload_project_root() {
    // venv/bin/python3 + a payload under proj/dist → both the venv
    // root and the project root (vendored addons beside dist/) land.
    let dir = fresh_dir("payload").canonicalize().unwrap();
    let exe = dir.join("venv").join("bin").join("python3");
    write_fake_macho(&exe, &[], &[]);
    let script = dir.join("proj").join("dist").join("server.py");
    std::fs::create_dir_all(script.parent().unwrap()).unwrap();
    std::fs::write(&script, b"print('hi')").unwrap();

    let argv = vec![
        exe.to_string_lossy().into_owned(),
        script.to_string_lossy().into_owned(),
    ];
    let roots = code_map_dirs(&exe, &argv);
    assert!(
        roots.contains(&dir.join("venv")),
        "interpreter bin/ climb must land the venv root; got {roots:?}"
    );
    assert!(
        roots.contains(&dir.join("proj")),
        "payload dist/ climb must land the project root; got {roots:?}"
    );
}

#[test]
fn test_code_map_dirs_homebrew_binary_derives_prefix() {
    // Real-machine check: a Homebrew binary's dep closure pulls in
    // /opt/homebrew — the grant CI could never exercise without an
    // installed package tree. Skips on hosts without Homebrew.
    let py = Path::new("/opt/homebrew/bin/python3");
    if !py.exists() {
        return;
    }
    let roots = code_map_dirs(py, &["python3".to_string(), "-V".to_string()]);
    assert!(
        roots.contains(&PathBuf::from("/opt/homebrew")),
        "Homebrew dep closure must bless its prefix; got {roots:?}"
    );
}

// ---------------------------------------------------------------
// staged_exec_dyld_fallback_dirs — relocated-exe rpath recovery
// ---------------------------------------------------------------

#[test]
fn test_dyld_fallback_dirs_restore_executable_path_rpaths() {
    // Shared-build layout: real/bin/tool links @rpath/libnode.dylib with
    // LC_RPATH=@executable_path/../lib. Staged into an empty dir the
    // exe's rpaths would resolve against the staging dir; the fallback
    // list must name the real install's lib dir instead.
    let dir = fresh_dir("dyldfb").canonicalize().unwrap();
    let real_lib = dir.join("real").join("lib");
    std::fs::create_dir_all(&real_lib).unwrap();
    write_fake_macho(&real_lib.join("libnode.dylib"), &[], &[]);
    let real_exe = dir.join("real").join("bin").join("node");
    write_fake_macho(
        &real_exe,
        &["@rpath/libnode.dylib"],
        &["@executable_path/../lib"],
    );
    let stage = dir.join("stage");
    std::fs::create_dir_all(&stage).unwrap();
    let staged = stage.join("object");
    std::fs::copy(&real_exe, &staged).unwrap();

    let dirs = staged_exec_dyld_fallback_dirs(&staged, &real_exe);
    assert_eq!(
        dirs,
        vec![real_lib.clone()],
        "@executable_path/../lib must expand against the real exe dir; got {dirs:?}"
    );
}

#[test]
fn test_dyld_fallback_dirs_skip_absolute_and_missing() {
    let dir = fresh_dir("dyldfb_skip").canonicalize().unwrap();
    let real_exe = dir.join("real").join("bin").join("tool");
    // Absolute rpath resolves unchanged (no restore needed); the
    // missing dir contributes nothing.
    write_fake_macho(
        &real_exe,
        &[],
        &["/usr/lib", "@executable_path/../no_such_lib"],
    );
    let staged = dir.join("stage").join("object");
    std::fs::create_dir_all(staged.parent().unwrap()).unwrap();
    std::fs::copy(&real_exe, &staged).unwrap();

    let dirs = staged_exec_dyld_fallback_dirs(&staged, &real_exe);
    assert!(
        dirs.iter().all(|d| d.is_dir()),
        "only existing dirs belong in the fallback list; got {dirs:?}"
    );
    assert!(
        dirs.iter().all(|d| d != Path::new("/usr/lib")),
        "absolute rpaths are not relabeled; got {dirs:?}"
    );
}

#[test]
fn test_exec_a_command_plain_without_fallback() {
    assert_eq!(
        exec_a_command(&[]),
        "builtin exec -a \"$0\" \"$@\"",
        "no fallback dirs must keep the historical wrapper string"
    );
}

#[test]
fn test_exec_a_command_exports_fallback() {
    let dirs = vec![
        PathBuf::from("/opt/hostedtoolcache/node/22.23.3/arm64/lib"),
        PathBuf::from("/Users/o'brien/sdk/lib"),
    ];
    let cmd = exec_a_command(&dirs);
    assert!(
        cmd.starts_with("export DYLD_FALLBACK_LIBRARY_PATH='"),
        "fallback dirs must be re-exported inside the wrapper; got {cmd}"
    );
    assert!(
        cmd.contains("/opt/hostedtoolcache/node/22.23.3/arm64/lib"),
        "the real lib dir must appear; got {cmd}"
    );
    assert!(
        cmd.contains("o'\\''brien"),
        "embedded quotes must be shell-escaped; got {cmd}"
    );
    assert!(
        cmd.ends_with("builtin exec -a \"$0\" \"$@\""),
        "the exec-a tail must be preserved; got {cmd}"
    );
}

#[test]
fn test_dyld_fallback_dirs_unreadable_or_unparseable() {
    // A staged file that is not Mach-O (or unreadable) yields no dirs —
    // a monolithic exe needs no fallback, and the parse is best-effort.
    let dir = fresh_dir("dyldfb_plain").canonicalize().unwrap();
    let staged = dir.join("object");
    std::fs::write(&staged, b"not a mach-o").unwrap();
    let real_exe = dir.join("real").join("bin").join("tool");
    write_fake_macho(&real_exe, &[], &[]);
    assert!(staged_exec_dyld_fallback_dirs(&staged, &real_exe).is_empty());
    assert!(staged_exec_dyld_fallback_dirs(&dir.join("missing"), &real_exe).is_empty());
}

// ---------------------------------------------------------------
// generate_sbpl — network policy
// ---------------------------------------------------------------

#[test]
fn test_sbpl_network_deny_all_no_allowed() {
    let policy = default_policy();
    // deny_all_others = true, allowed = []
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(!sbpl.contains("(allow network-outbound)"));
    assert!(!sbpl.contains("(allow network-bind)"));
}

#[test]
fn test_sbpl_network_deny_all_with_specific_ports() {
    let mut policy = default_policy();
    policy.network.outbound.deny_all_others = true;
    policy.network.outbound.allowed = vec!["localhost:443".to_string(), "*:80".to_string()];
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:443\"))"));
    assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:80\"))"));
    // Must NOT have blanket allow
    assert!(!sbpl.contains("(allow network-outbound)\n"));
    assert!(!sbpl.contains("(allow network-bind)"));
}

#[test]
fn test_sbpl_network_allow_all() {
    let mut policy = default_policy();
    policy.network.outbound.deny_all_others = false;
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow network-outbound)\n"));
    assert!(!sbpl.contains("(allow network-bind)"));
}

#[test]
fn test_sbpl_network_allow_all_with_inbound() {
    let mut policy = default_policy();
    policy.network.outbound.deny_all_others = false;
    policy.network.inbound.allow_listen = true;
    let sbpl = generate_sbpl(&policy).unwrap();
    assert!(sbpl.contains("(allow network-outbound)\n"));
    assert!(sbpl.contains("(allow network-bind)"));
}

#[test]
fn test_sbpl_network_rejects_remote_hostname() {
    let mut policy = default_policy();
    policy.network.outbound.allowed = vec!["api.example.com:443".to_string()];
    assert!(generate_sbpl(&policy).is_err());
}

// ---------------------------------------------------------------
// Integration tests (macOS only)
// ---------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn test_sandbox_blocks_write_outside_allowed() {
    let policy = default_policy();
    let test_file = std::env::current_dir()
        .unwrap()
        .join("_sandbox_write_deny_test");

    // Clean up from any previous failed run
    let _ = std::fs::remove_file(&test_file);

    let mut child = spawn_sandboxed(
        &policy,
        "/bin/sh",
        &[
            "-c".to_string(),
            format!("echo denied > '{}' 2>/dev/null", test_file.display()),
        ],
    )
    .expect("sandbox-exec should spawn");

    let _ = child.wait();

    let blocked = !test_file.exists();
    let _ = std::fs::remove_file(&test_file);
    assert!(blocked, "sandbox should block writes outside allowed paths");
}

#[cfg(target_os = "macos")]
#[test]
fn test_sandbox_allows_tmp_write() {
    use std::io::Read;

    let policy = default_policy();

    let mut child = spawn_sandboxed(
            &policy,
            "/bin/sh",
            &[
                "-c".to_string(),
                "echo allowed > \"$TMPDIR/mcp_writ_sandbox_allow_test\" && cat \"$TMPDIR/mcp_writ_sandbox_allow_test\"".to_string(),
            ],
        )
        .expect("sandbox-exec should spawn");

    let mut output = String::new();
    child
        .stdout
        .as_mut()
        .unwrap()
        .read_to_string(&mut output)
        .ok();
    let status = child.wait().expect("sandboxed shell should exit");
    assert!(status.success(), "sandboxed shell failed: {status}");

    assert!(
        output.trim().contains("allowed"),
        "sandbox should allow writes to private TMPDIR, got: {output}"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn test_sandbox_blocks_network_when_denied() {
    use std::net::TcpListener;

    // Bind a local TCP listener so we know the port is reachable
    // outside the sandbox — this proves the sandbox is what blocks
    // the connection, not a missing listener.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let port = listener.local_addr().unwrap().port();

    // Default policy: deny_all_others=true, allowed=[]
    // → SBPL will NOT contain (allow network-outbound) for any TCP port
    let policy = default_policy();

    let mut child = spawn_sandboxed(
        &policy,
        "/bin/sh",
        &[
            "-c".to_string(),
            format!("nc -z -w 2 127.0.0.1 {} 2>/dev/null", port),
        ],
    )
    .expect("sandbox-exec should spawn");

    let status = child.wait().expect("should be able to wait");
    drop(listener);

    assert!(
        !status.success(),
        "sandbox should block TCP connection to 127.0.0.1:{port} when deny_all_others=true"
    );
}

// ---------------------------------------------------------------
// sbpl_profile_with_egress — CONNECT-proxy mode (PR-11)
// ---------------------------------------------------------------

fn proxy_sbpl(policy: &Policy) -> (String, Vec<ProcessGrant>) {
    sbpl_profile_with_egress(
        policy,
        "/private/tmp/mcp-writ-proxy-test",
        EgressProfile::ConnectProxy { proxy_port: 18099 },
        &[],
    )
    .expect("proxy-mode profile should build")
}

#[test]
fn test_proxy_mode_pins_outbound_to_proxy_port() {
    let policy = default_policy();
    let (sbpl, grants) = proxy_sbpl(&policy);
    // The only remote endpoint is the loopback CONNECT proxy.
    assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:18099\"))"));
    // No unrestricted outbound, no bind, no inbound, no resolver.
    assert!(!sbpl.contains("(allow network-outbound)\n"));
    assert!(!sbpl.contains("network-bind"));
    assert!(!sbpl.contains("network-inbound"));
    assert!(!sbpl.contains("mDNSResponder"));
    let proxy_grant = grants
        .iter()
        .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "connect_proxy"))
        .expect("proxy pin must be recorded as a grant");
    assert_eq!(proxy_grant.origin, GrantOrigin::Runtime);
}

#[test]
fn test_proxy_mode_never_widens_on_open_posture() {
    // deny_all_others=false must NOT relax the pin — the whole
    // point of the route is that the proxy decides egress.
    let mut policy = default_policy();
    policy.network.outbound.deny_all_others = false;
    let (sbpl, _) = proxy_sbpl(&policy);
    assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:18099\"))"));
    assert!(!sbpl.contains("(allow network-outbound)\n"));
}

#[test]
fn test_proxy_mode_remote_host_becomes_skipped_not_error() {
    // A remote hostname that the native path refuses to map is
    // not a build failure in proxy mode — the proxy enforces it.
    let mut policy = default_policy();
    policy.network.outbound.allowed = vec!["api.example.com:443".to_string()];
    let (sbpl, grants) = proxy_sbpl(&policy);
    assert!(sbpl.contains("localhost:18099"));
    assert!(!sbpl.contains("api.example.com"));
    let entry = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { name, .. } if name.as_str() == "api.example.com:443"))
            .expect("remote host rule must be recorded");
    assert_eq!(entry.state, ControlState::Skipped);
    assert!(
        entry
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("CONNECT proxy")),
        "skip reason must name the enforcing mechanism: {entry:?}"
    );
    // The same policy still errors on the native path.
    assert!(sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test", &[]).is_err());
}

#[test]
fn test_proxy_mode_keeps_localhost_rules_and_marks_cidrs() {
    let mut policy = default_policy();
    policy.network.outbound.allowed = vec!["localhost:8080".to_string()];
    policy.network.outbound.allowed_cidrs = vec!["203.0.113.0/24".to_string()];
    let (sbpl, grants) = proxy_sbpl(&policy);
    // Both loopback endpoints allowed: the proxy + the declared rule.
    assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:18099\"))"));
    assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"));
    let cidr_grant = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "net_destination_cidr"))
            .expect("cidr rule must be recorded");
    assert_eq!(cidr_grant.state, ControlState::Skipped);
    assert!(
        cidr_grant
            .reason
            .as_deref()
            .is_some_and(|r| r.contains("CONNECT proxy"))
    );
}

#[test]
fn test_proxy_mode_only_explicit_loopback_gets_a_direct_rule() {
    // Bare-port and `*`-wildcard entries name a wider destination
    // set than loopback — proxy mode routes them to the CONNECT
    // proxy (Skipped), never to a direct `localhost:port` grant.
    // Grant names are the effective spelling — a bare `"443"` is
    // the wildcard-destination rule `*:443`.
    for (entry, grant_name) in [
        ("443", "*:443"),
        ("*:443", "*:443"),
        (":443", ":443"),
        ("example.com:443", "example.com:443"),
    ] {
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec![entry.to_string()];
        let (sbpl, grants) = proxy_sbpl(&policy);
        assert!(
            !sbpl.contains("localhost:443"),
            "'{entry}' must not emit a direct loopback rule in proxy mode"
        );
        let skipped = grants
                .iter()
                .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == grant_name))
                .unwrap_or_else(|| panic!("'{entry}' must be recorded as skipped"));
        assert_eq!(skipped.state, ControlState::Skipped);
        assert!(
            skipped
                .reason
                .as_deref()
                .is_some_and(|r| r.contains("CONNECT proxy"))
        );
    }
    // Explicit loopback endpoints still map to direct rules.
    for (entry, port) in [
        ("localhost:8080", 8080),
        ("127.0.0.1:80", 80),
        ("[::1]:8080", 8080),
    ] {
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec![entry.to_string()];
        let (sbpl, _) = proxy_sbpl(&policy);
        assert!(
            sbpl.contains(&format!(
                "(allow network-outbound (remote tcp \"localhost:{port}\"))"
            )),
            "'{entry}' must emit a direct loopback rule in proxy mode"
        );
    }
    // A bare `::1:8080` is the v6 literal `::1:8080`, never
    // `::1` port 8080 — proxy mode routes it to the CONNECT
    // proxy (which judges it as the v6 it is), not to a direct
    // loopback grant on the host's port 8080.
    let mut policy = default_policy();
    policy.network.outbound.allowed = vec!["::1:8080".to_string()];
    let (sbpl, grants) = proxy_sbpl(&policy);
    assert!(
        !sbpl.contains("localhost:8080"),
        "'::1:8080' must not emit a direct loopback rule in proxy mode: {sbpl}"
    );
    let skipped = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "::1:8080"))
            .expect("'::1:8080' must be recorded as skipped");
    assert_eq!(skipped.state, ControlState::Skipped);
}

#[test]
fn test_proxy_mode_allow_listen_is_loopback_only() {
    let mut policy = default_policy();
    policy.network.inbound.allow_listen = true;
    let (sbpl, grants) = proxy_sbpl(&policy);
    assert!(sbpl.contains("(allow network-bind (local tcp \"localhost:*\"))"));
    assert!(sbpl.contains("(allow network-inbound (local tcp \"localhost:*\"))"));
    assert!(!sbpl.contains("(allow network-bind)\n"));
    let bind = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "network_bind" && name.contains("loopback-only")))
            .expect("loopback-only bind grant must be recorded");
    assert_eq!(bind.state, ControlState::Planned);
}

#[test]
fn test_native_mode_unchanged_under_egress_split() {
    // The native path must behave exactly as before the
    // EgressProfile split — same rules, same mDNS grant, same
    // remote-host refusal.
    let mut policy = default_policy();
    policy.network.outbound.allowed = vec!["localhost:443".to_string()];
    let (sbpl, grants) = sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test", &[]).unwrap();
    assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:443\"))"));
    assert!(!sbpl.contains("localhost:18099"));
    assert!(sbpl.contains("mDNSResponder"));
    assert!(grants.iter().all(
        |g| !matches!(&g.subject, GrantSubject::Rule { kind, .. } if *kind == "connect_proxy")
    ));
}

// ---------------------------------------------------------------
// Parsed-policy emit — `egress_rules` carries the qualifiers the
// folded `allowed` list cannot (a parsed `localhost:8080` loses
// its port in `allowed`; bare-port/scoped-wildcard rules exist
// only in `egress_rules`).
// ---------------------------------------------------------------

fn parsed_policy(net_rules: &str) -> Policy {
    crate::policy::kdl_loader::parse_kdl_policy(&format!(
        "policy version=1\ndefaults {{\n    network {{\n{net_rules}    }}\n}}\n"
    ))
    .expect("fixture policy parses")
}

#[test]
fn test_parsed_localhost_port_rule_emits_in_both_modes() {
    // A *parsed* `allow host="localhost:8080"` folds its port out
    // of `allowed` — the emit must still produce the documented
    // `(remote tcp "localhost:8080")` rule in both modes.
    let policy = parsed_policy("        allow host=\"localhost:8080\"\n        deny host=\"*\"\n");
    let (sbpl, _) = sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test", &[]).unwrap();
    assert!(
        sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"),
        "native mode must emit the parsed localhost:port rule: {sbpl}"
    );
    let (sbpl, _) = proxy_sbpl(&policy);
    assert!(
        sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"),
        "proxy mode must emit the parsed localhost:port rule: {sbpl}"
    );
}

#[test]
fn test_parsed_bare_port_rule_emits_native_and_routes_in_proxy() {
    // `allow host="443"` exists only in `egress_rules` — the
    // native emit must produce `localhost:443`; proxy mode routes
    // it to the CONNECT proxy (not an explicit loopback endpoint).
    let policy = parsed_policy("        allow host=\"443\"\n        deny host=\"*\"\n");
    let (sbpl, _) = sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test", &[]).unwrap();
    assert!(
        sbpl.contains("(allow network-outbound (remote tcp \"localhost:443\"))"),
        "native mode must emit the bare-port rule: {sbpl}"
    );
    let (sbpl, grants) = proxy_sbpl(&policy);
    assert!(
        !sbpl.contains("(remote tcp \"localhost:443\")"),
        "proxy mode must not emit a direct :443 rule: {sbpl}"
    );
    let skipped = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "*:443"))
            .expect("the bare-port rule must be recorded as skipped");
    assert_eq!(skipped.state, ControlState::Skipped);
}

#[test]
fn test_parsed_ipv6_loopback_rules_emit_and_nonloopback_v6_does_not() {
    // The parser stores `[::1]:8080` and `host="::1" port=8080`
    // as the bare literal `::1` plus a port qualifier — both must
    // emit the declared `localhost:8080` rule in both modes.
    for rule in ["allow host=\"[::1]:8080\"", "allow host=\"::1\" port=8080"] {
        let policy = parsed_policy(&format!("        {rule}\n        deny host=\"*\"\n"));
        for (label, (sbpl, _)) in [
            (
                "native",
                sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test", &[]).unwrap(),
            ),
            ("proxy", proxy_sbpl(&policy)),
        ] {
            assert!(
                sbpl.contains("(allow network-outbound (remote tcp \"localhost:8080\"))"),
                "{label} mode must emit '{rule}' as localhost:8080: {sbpl}"
            );
        }
    }
    // `host="::1:8080"` is the non-loopback v6 literal
    // `::1:8080`, not `::1` port 8080 — proxy mode routes it to
    // the CONNECT proxy (which judges the v6 as written), and the
    // native path refuses it like any remote host.
    let policy = parsed_policy("        allow host=\"::1:8080\"\n        deny host=\"*\"\n");
    assert!(
        sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test", &[]).is_err(),
        "native mode must refuse a remote v6 literal, not map it to localhost"
    );
    let (sbpl, grants) = proxy_sbpl(&policy);
    assert!(
        !sbpl.contains("localhost:8080"),
        "proxy mode must not grant host loopback for the v6 literal: {sbpl}"
    );
    let skipped = grants
            .iter()
            .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "::1:8080"))
            .expect("the v6 rule must be recorded as skipped");
    assert_eq!(skipped.state, ControlState::Skipped);
}

#[test]
fn test_udp_only_localhost_rule_never_widens_to_tcp() {
    // `proto=udp` on a loopback endpoint must not emit `remote
    // tcp` — SBPL cannot carry the qualifier, so the rule stays
    // unemitted rather than granting a TCP reach it never
    // declared. Both modes.
    let policy = parsed_policy(
        "        allow host=\"localhost:5353\" proto=\"udp\"\n        deny host=\"*\"\n",
    );
    for (label, (sbpl, grants)) in [
        (
            "native",
            sbpl_profile(&policy, "/private/tmp/mcp-writ-proxy-test", &[]).unwrap(),
        ),
        ("proxy", proxy_sbpl(&policy)),
    ] {
        assert!(
            !sbpl.contains("localhost:5353"),
            "{label} mode must not widen proto=udp to remote tcp: {sbpl}"
        );
        let skipped = grants
                .iter()
                .find(|g| matches!(&g.subject, GrantSubject::Rule { kind, name } if *kind == "tcp_host" && name == "localhost:5353"))
                .unwrap_or_else(|| panic!("{label} mode must record the udp rule"));
        assert_eq!(skipped.state, ControlState::Skipped);
    }
}
