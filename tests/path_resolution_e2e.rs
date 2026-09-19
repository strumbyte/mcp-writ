//! P3-B: Auditor interpretation vs actual filesystem access.
//!
//! Three groups:
//!
//! 1. **Interpretation comparison** — the fixture is spawned directly
//!    (unsandboxed) with a known cwd. For each request the test reproduces
//!    what the Auditor resolves (`checker::extract_fs_targets` →
//!    `normalize_fs_argument` → `resolve_for_authorization_with_cwd`) and
//!    compares it with the object the fixture actually opened, identified by
//!    handle identity (dev/ino on Unix, volume/file_index on Windows) plus
//!    the canonical path — never by re-normalizing the input string.
//!    Divergences are asserted as recorded facts, not hidden.
//!
//! 2. **OS boundary** — a sandboxed `mcp-writ run`. An `open_env` call whose
//!    arguments carry no filesystem target passes the Auditor, but the
//!    server-internal open of C (outside the OS policy grant) must still
//!    fail at the OS.
//!
//! 3. **Process-shared permission** — same sandboxed run. B is granted to
//!    the whole process (a different purpose than the `read_file` tool's fs
//!    policy), so a server-internal open reaches B through `open_env` even
//!    though `read_file` could not name B. This is a design constraint of
//!    process-level sandboxing, recorded — not a Warden per-tool denial.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::time::{Duration, timeout};

use mcp_writ::auditor::checker;
use mcp_writ::pathutil;

mod common;

const TIMEOUT_SECS: u64 = 20;

struct ChildGuard(tokio::process::Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.start_kill();
    }
}

// ─── test layout ─────────────────────────────────────────────────────────────

/// A (tool-authorized dir), A' (shared-prefix sibling), B (process-level
/// grant for a different purpose), C (outside the OS grant). All under one
/// canonicalized temp root with distinct marker contents.
struct Layout {
    _root: TempDir,
    a_dir: PathBuf,
    a_sibling_dir: PathBuf,
    b_dir: PathBuf,
    _c_dir: PathBuf,
    a_marker: PathBuf,
    _a_sibling_marker: PathBuf,
    b_marker: PathBuf,
    c_secret: PathBuf,
    a_marker_text: String,
    a_sibling_text: String,
    b_marker_text: String,
    c_secret_text: String,
}

fn layout() -> Layout {
    let temp = tempfile::Builder::new()
        .prefix("mcp_writ_p3b_")
        .tempdir()
        .expect("tempdir");
    // Canonicalize once so resolved paths compare cleanly with the fixture's
    // `std::fs::canonicalize` output (8.3 short names on Windows temp paths).
    // `temp` keeps ownership so cleanup still runs at drop.
    let root = temp.path().canonicalize().expect("canonical temp root");
    let a_dir = root.join("allowed_a");
    let a_sibling_dir = root.join("allowed_a_extra");
    let b_dir = root.join("granted_b");
    let c_dir = root.join("outside_c");
    for d in [&a_dir, &a_sibling_dir, &b_dir, &c_dir] {
        std::fs::create_dir_all(d).expect("mkdir");
    }
    let uniq = format!("{}-{}", std::process::id(), marker_nanos());
    let a_marker_text = format!("MARKER-A-{uniq}");
    let a_sibling_text = format!("MARKER-AX-{uniq}");
    let b_marker_text = format!("MARKER-B-{uniq}");
    let c_secret_text = format!("SECRET-C-{uniq}");

    let a_marker = a_dir.join("marker.txt");
    let a_sibling_marker = a_sibling_dir.join("marker.txt");
    let b_marker = b_dir.join("marker.txt");
    let c_secret = c_dir.join("data_c.bin");
    std::fs::write(&a_marker, format!("{a_marker_text}\n")).expect("write A marker");
    std::fs::write(&a_sibling_marker, format!("{a_sibling_text}\n")).expect("write A' marker");
    std::fs::write(&b_marker, format!("{b_marker_text}\n")).expect("write B marker");
    std::fs::write(&c_secret, format!("{c_secret_text}\n")).expect("write C data");

    Layout {
        _root: temp,
        a_dir,
        a_sibling_dir,
        b_dir,
        _c_dir: c_dir,
        a_marker,
        _a_sibling_marker: a_sibling_marker,
        b_marker,
        c_secret,
        a_marker_text,
        a_sibling_text,
        b_marker_text,
        c_secret_text,
    }
}

fn marker_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

// ─── fixture binary ─────────────────────────────────────────────────────────

/// Compile `open_path_server.rs` once per test binary (shared helper).
fn compiled_fixture() -> Option<PathBuf> {
    common::compiled_open_path_fixture()
}

// ─── object identity ─────────────────────────────────────────────────────────

/// OS-level identity of the object a path names: (dev, ino) on Unix,
/// (volume_serial, file_index) on Windows. `None` where unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdent(u64, u64);

#[cfg(unix)]
fn identity_of(path: &Path) -> Option<FileIdent> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(FileIdent(m.dev(), m.ino()))
}

#[cfg(windows)]
mod win_ident {
    use std::os::windows::io::RawHandle;

    /// BY_HANDLE_FILE_INFORMATION with FILETIME members modeled as u32
    /// pairs (FILETIME is 4-byte-aligned; a Rust u64 would shift the layout).
    #[repr(C)]
    #[derive(Default)]
    pub struct ByHandleInfo {
        pub attributes: u32,
        pub creation_lo: u32,
        pub creation_hi: u32,
        pub access_lo: u32,
        pub access_hi: u32,
        pub write_lo: u32,
        pub write_hi: u32,
        pub volume_serial: u32,
        pub size_high: u32,
        pub size_low: u32,
        pub num_links: u32,
        pub index_high: u32,
        pub index_low: u32,
    }

    unsafe extern "system" {
        pub fn GetFileInformationByHandle(h: RawHandle, info: *mut ByHandleInfo) -> i32;
    }
}

#[cfg(windows)]
fn identity_of(path: &Path) -> Option<FileIdent> {
    use std::os::windows::io::AsRawHandle;
    let f = std::fs::File::open(path).ok()?;
    let mut info = win_ident::ByHandleInfo::default();
    // Safety: `info` is a valid out-buffer; the handle is open for the call.
    let ok = unsafe { win_ident::GetFileInformationByHandle(f.as_raw_handle(), &mut info) };
    if ok == 0 {
        return None;
    }
    let index = ((info.index_high as u64) << 32) | info.index_low as u64;
    Some(FileIdent(info.volume_serial as u64, index))
}

#[cfg(not(any(unix, windows)))]
fn identity_of(_path: &Path) -> Option<FileIdent> {
    None
}

// ─── JSON response helpers (nojson) ─────────────────────────────────────────

fn sc<'j>(json: &'j nojson::RawJson<'j>) -> Option<nojson::RawJsonValue<'j, 'j>> {
    json.value()
        .to_member("result")
        .ok()?
        .optional()?
        .to_member("structuredContent")
        .ok()?
        .optional()
}

fn sc_str<'j>(json: &'j nojson::RawJson<'j>, keys: &[&str]) -> Option<String> {
    let mut v = sc(json)?;
    for k in keys {
        v = v.to_member(k).ok()?.optional()?;
    }
    v.to_unquoted_string_str().ok().map(|s| s.into_owned())
}

fn sc_num<'j>(json: &'j nojson::RawJson<'j>, keys: &[&str]) -> Option<u64> {
    let mut v = sc(json)?;
    for k in keys {
        v = v.to_member(k).ok()?.optional()?;
    }
    v.as_raw_str().trim().parse().ok()
}

fn sc_ok(json: &nojson::RawJson) -> Option<bool> {
    let v = sc(json)?.to_member("ok").ok()?.optional()?;
    Some(v.as_boolean_str().ok()? == "true")
}

fn is_error_result(json: &nojson::RawJson) -> bool {
    json.value()
        .to_member("result")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|r| r.to_member("isError").ok().and_then(|m| m.optional()))
        .and_then(|v| v.as_boolean_str().ok())
        == Some("true")
}

/// Handle identity reported by the fixture (`dev/ino` or `volume/file_index`).
fn reported_ident(json: &nojson::RawJson) -> Option<FileIdent> {
    if let (Some(d), Some(i)) = (sc_num(json, &["dev"]), sc_num(json, &["ino"])) {
        return Some(FileIdent(d, i));
    }
    if let (Some(v), Some(i)) = (sc_num(json, &["volume"]), sc_num(json, &["file_index"])) {
        return Some(FileIdent(v, i));
    }
    None
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn call_line(id: u64, tool: &str, args: &str) -> String {
    format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"tools/call\",\
         \"params\":{{\"name\":\"{tool}\",\"arguments\":{args}}}}}"
    )
}

/// Path-string comparison tolerant of `\\?\` verbatim prefixes and
/// platform case rules.
fn same_path(a: &str, b: &str) -> bool {
    pathutil::paths_equal(&strip_verbatim(a), &strip_verbatim(b))
}

fn strip_verbatim(p: &str) -> String {
    let s = p.replace('\\', "/");
    s.strip_prefix("//?/").map(str::to_string).unwrap_or(s)
}

// ─── Auditor interpretation ──────────────────────────────────────────────────

/// Reproduce what the Auditor resolves for every filesystem target in
/// `line` as seen from `cwd`.
///
/// `extract_fs_targets` already applies `normalize_fs_argument` once;
/// `authorize_one_path` normalizes again before resolving, so this mirrors
/// the real check order: normalize → cwd-join + lexical + canonicalize.
fn auditor_resolved(line: &str, cwd: &Path) -> Vec<String> {
    checker::extract_fs_targets(line)
        .iter()
        .filter_map(|target| {
            let normalized = pathutil::normalize_fs_argument(target).ok()?;
            pathutil::resolve_for_authorization_with_cwd(&normalized, cwd).ok()
        })
        .collect()
}

/// Assert the Auditor-resolved path and the fixture's open report name the
/// same object: canonical equality plus OS handle identity.
fn assert_same_object(resolved: &str, resp: &str, ctx: &str) {
    let json = nojson::RawJson::parse(resp).expect("fixture response must be JSON");
    assert_eq!(
        sc_ok(&json),
        Some(true),
        "{ctx}: fixture open failed: {resp}"
    );
    let canonical = sc_str(&json, &["canonical"]).unwrap_or_default();
    assert!(
        same_path(&canonical, resolved),
        "{ctx}: auditor resolved '{resolved}' but the open reached '{canonical}'"
    );
    let expected = identity_of(Path::new(resolved));
    let reported = reported_ident(&json);
    assert_eq!(
        expected, reported,
        "{ctx}: handle identity differs (resolved={resolved})"
    );
}

// ─── direct fixture session ─────────────────────────────────────────────────

struct FixtureSession {
    _guard: ChildGuard,
    stdin: tokio::process::ChildStdin,
    reader: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    seq: u64,
}

impl FixtureSession {
    async fn spawn(exe: &Path, cwd: &Path, envs: &[(&str, &Path)]) -> Option<Self> {
        let mut cmd = Command::new(exe);
        cmd.current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                common::skip_e2e_test(&format!("fixture spawn failed: {e}"));
                return None;
            }
        };
        let stdin = child.stdin.take().expect("fixture stdin");
        let stdout = child.stdout.take().expect("fixture stdout");
        Some(Self {
            _guard: ChildGuard(child),
            stdin,
            reader: BufReader::new(stdout).lines(),
            seq: 0,
        })
    }

    fn next_call(&mut self, tool: &str, args: &str) -> String {
        self.seq += 1;
        call_line(self.seq, tool, args)
    }

    async fn send_line(&mut self, line: &str) {
        self.stdin
            .write_all(line.as_bytes())
            .await
            .expect("write request");
        self.stdin.write_all(b"\n").await.expect("write newline");
        self.stdin.flush().await.expect("flush request");
    }

    /// Send a pre-built request line and read its response. The same `line`
    /// string is what `auditor_resolved` evaluates — pass the identical
    /// bytes, not a rebuilt equivalent.
    async fn send_and_recv(&mut self, line: &str) -> String {
        self.send_line(line).await;
        self.recv_line().await
    }

    async fn recv_line(&mut self) -> String {
        timeout(Duration::from_secs(TIMEOUT_SECS), async {
            loop {
                match self.reader.next_line().await {
                    Ok(Some(l)) if l.starts_with("{\"jsonrpc\"") => return l,
                    Ok(Some(_)) => continue,
                    Ok(None) => panic!("fixture closed stdout"),
                    Err(e) => panic!("fixture stdout error: {e}"),
                }
            }
        })
        .await
        .expect("fixture response timeout")
    }

    async fn call(&mut self, tool: &str, args: &str) -> String {
        let line = self.next_call(tool, args);
        self.send_line(&line).await;
        self.recv_line().await
    }
}

// ─── 1. interpretation comparison ───────────────────────────────────────────

#[tokio::test]
async fn interpretation_agrees_on_common_forms() {
    let Some(exe) = compiled_fixture() else {
        return;
    };
    let lay = layout();
    let Some(mut fx) = FixtureSession::spawn(&exe, &lay.a_dir, &[]).await else {
        return;
    };

    // ── absolute path ────────────────────────────────────────────────
    let args = format!("{{\"path\":{}}}", json_str(&lay.a_marker.to_string_lossy()));
    let line = call_line(100, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    let resp = fx.send_and_recv(&line).await;
    assert_same_object(&resolved[0], &resp, "absolute path");
    assert_eq!(sc_str(&parse(&resp), &["kind"]).as_deref(), Some("file"));
    assert!(
        resp.contains(&lay.a_marker_text),
        "marker content must reach the client: {resp}"
    );

    // ── relative `.` ─────────────────────────────────────────────────
    let args = "{\"path\":\"./marker.txt\"}".to_string();
    let line = call_line(101, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    let resp = fx.send_and_recv(&line).await;
    assert_same_object(&resolved[0], &resp, "relative ./");
    assert!(
        same_path(&resolved[0], &lay.a_marker.to_string_lossy()),
        "'./marker.txt' from cwd=A must resolve to the A marker: {resolved:?}"
    );

    // ── `..` escape into B (interpretation agrees; no enforcement here) ──
    let args = format!("{{\"path\":{}}}", json_str("../granted_b/marker.txt"));
    let line = call_line(102, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    let resp = fx.send_and_recv(&line).await;
    assert_same_object(&resolved[0], &resp, "dotdot into B");
    assert!(
        resp.contains(&lay.b_marker_text),
        "B marker content expected: {resp}"
    );
    // The resolved object is NOT inside an A-scoped tool grant — recorded so
    // the comparison documents interpretation vs enforcement separately.
    let a_glob = format!("{}/**", lay.a_dir.to_string_lossy().replace('\\', "/"));
    assert!(
        !pathutil::path_matches_lexical(&resolved[0], &a_glob),
        "B marker must not match '{a_glob}': {resolved:?}"
    );

    // ── shared-prefix sibling (allowed_a vs allowed_a_extra) ──────────
    let args = format!("{{\"path\":{}}}", json_str("../allowed_a_extra/marker.txt"));
    let line = call_line(103, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    let resp = fx.send_and_recv(&line).await;
    assert_same_object(&resolved[0], &resp, "shared-prefix sibling");
    assert!(resp.contains(&lay.a_sibling_text), "A' content: {resp}");
    assert!(
        !pathutil::path_matches_lexical(&resolved[0], &a_glob),
        "sibling must not match '{a_glob}' despite the shared name prefix"
    );

    // ── Unicode name ─────────────────────────────────────────────────
    let uni = lay.a_dir.join("日本語-マーカー.txt");
    std::fs::write(&uni, "UNICODE-MARKER\n").expect("write unicode marker");
    let args = format!("{{\"path\":{}}}", json_str(&uni.to_string_lossy()));
    let line = call_line(104, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    let resp = fx.send_and_recv(&line).await;
    assert_same_object(&resolved[0], &resp, "unicode name");

    // ── nonexistent tail + create destination ─────────────────────────
    let args = "{\"path\":\"missing/deep/file.txt\"}".to_string();
    let line = call_line(105, "ident", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    // The nearest existing ancestor is A itself, so the resolved path is a
    // lexical path under A even though nothing exists there.
    let resp = fx.send_and_recv(&line).await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(false), "ident on missing: {resp}");
    assert_eq!(
        sc_str(&json, &["error"]).as_deref(),
        Some("ENOENT"),
        "missing tail must report ENOENT: {resp}"
    );
    assert!(
        same_path(
            &resolved[0],
            &lay.a_dir.join("missing/deep/file.txt").to_string_lossy()
        ),
        "nonexistent tail must resolve lexically under A: {resolved:?}"
    );

    let args = "{\"path\":\"created_here.txt\",\"content\":\"CREATED-CONTENT\"}".to_string();
    let line = call_line(106, "create_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    let resp = fx.send_and_recv(&line).await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(true), "create: {resp}");
    // Created object lives where the resolved path said it would.
    let created_canonical = sc_str(&json, &["canonical"]).unwrap_or_default();
    assert!(
        same_path(&created_canonical, &resolved[0]),
        "created object at '{created_canonical}' vs resolved '{:?}'",
        resolved[0]
    );
    // Parent identity proves the creation site, not a normalized string.
    // Unix reports dev/ino for the parent dir; Windows stat-fields carry no
    // handle identity for dirs, so the canonical path is compared instead.
    let parent_canonical = sc_str(&json, &["parent", "canonical"]).unwrap_or_default();
    assert!(
        same_path(&parent_canonical, &lay.a_dir.to_string_lossy()),
        "create parent must be A itself: {parent_canonical}"
    );
    if let (Some(d), Some(i)) = (
        sc_num(&json, &["parent", "dev"]),
        sc_num(&json, &["parent", "ino"]),
    ) {
        assert_eq!(
            Some(FileIdent(d, i)),
            identity_of(&lay.a_dir),
            "create parent identity must be A itself"
        );
    }
}

#[tokio::test]
async fn interpretation_records_encoding_divergences() {
    let Some(exe) = compiled_fixture() else {
        return;
    };
    let lay = layout();
    let Some(mut fx) = FixtureSession::spawn(&exe, &lay.a_dir, &[]).await else {
        return;
    };

    // ── JSON `\uXXXX` escape: both sides decode identically ────────────
    let args = "{\"path\":\"\\u002e/marker.txt\"}".to_string();
    let line = call_line(200, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    let resp = fx.send_and_recv(&line).await;
    assert_same_object(&resolved[0], &resp, "json \\u002e escape");

    // ── percent-encoding: Auditor normalizes, the server does not ──────
    // `%6darker%2etxt` decodes to `marker.txt` for the Auditor (bounded
    // percent-decode is an authorization-time transform), but the fixture
    // opens the literal name → ENOENT. The divergence is the recorded fact.
    let args = "{\"path\":\"%6darker%2etxt\"}".to_string();
    let line = call_line(201, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    assert!(
        same_path(&resolved[0], &lay.a_marker.to_string_lossy()),
        "Auditor must decode %6darker%2etxt to the A marker: {resolved:?}"
    );
    let resp = fx.send_and_recv(&line).await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(false), "percent literal open: {resp}");
    assert_eq!(
        sc_str(&json, &["error"]).as_deref(),
        Some("ENOENT"),
        "fixture does not percent-decode: {resp}"
    );

    // ── file: URI: Auditor converts to a path; the server does not ─────
    let uri = if cfg!(windows) {
        // file:///D:/path — drive form; strip the canonical \\?\ verbatim
        // prefix first, it is not valid inside a URI.
        let plain = lay
            .a_marker
            .to_string_lossy()
            .strip_prefix("\\\\?\\")
            .map(str::to_string)
            .unwrap_or_else(|| lay.a_marker.to_string_lossy().into_owned());
        format!("file:///{}", plain.replace('\\', "/"))
    } else {
        format!("file://{}", lay.a_marker.to_string_lossy())
    };
    let args = format!("{{\"path\":{}}}", json_str(&uri));
    let line = call_line(202, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    let resp = fx.send_and_recv(&line).await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(false), "file URI literal open: {resp}");
    #[cfg(not(windows))]
    assert!(
        same_path(&resolved[0], &lay.a_marker.to_string_lossy()),
        "Auditor must map the file URI onto the A marker: {resolved:?}"
    );
    #[cfg(windows)]
    assert!(
        resolved[0].ends_with("/marker.txt") || resolved[0].ends_with("\\marker.txt"),
        "Auditor normalized the file URI to a path: {resolved:?}"
    );

    // ── NUL: Auditor cannot normalize; server cannot open ──────────────
    // `classify_target_string` pushes the raw value when normalization
    // fails; the test-side normalize+resolve then drops it — mirroring the
    // real check which denies "could not be normalized".
    let args = "{\"path\":\"a\\u0000b\"}".to_string();
    let line = call_line(203, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert!(
        resolved.is_empty(),
        "NUL-containing path must be unresolvable for the Auditor: {resolved:?}"
    );
    let resp = fx.send_and_recv(&line).await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(false), "NUL open: {resp}");

    // ── case mismatch: platform FS decides ────────────────────────────
    let args = "{\"path\":\"MARKER.TXT\"}".to_string();
    let line = call_line(204, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    let resp = fx.send_and_recv(&line).await;
    let json = parse(&resp);
    if cfg!(windows) {
        // Case-insensitive FS: both sides reach the same object.
        assert_same_object(&resolved[0], &resp, "case-insensitive match");
    } else {
        // Case-sensitive FS: auditor resolves lexically, open fails ENOENT.
        assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
        assert_eq!(sc_ok(&json), Some(false), "case-sensitive miss: {resp}");
        assert_eq!(sc_str(&json, &["error"]).as_deref(), Some("ENOENT"));
    }
}

#[tokio::test]
async fn symlink_resolution_and_wait_file_barrier() {
    let Some(exe) = compiled_fixture() else {
        return;
    };
    let lay = layout();
    let link = lay.a_dir.join("link.txt");
    if !make_symlink(&lay.b_marker, &link) {
        common::skip_e2e_test("symlink creation unavailable (privilege/developer mode)");
        return;
    }
    let Some(mut fx) = FixtureSession::spawn(&exe, &lay.a_dir, &[]).await else {
        return;
    };

    // ── static link: auditor follows it to B/marker; the open agrees ──
    let args = format!("{{\"path\":{}}}", json_str(&link.to_string_lossy()));
    let line = call_line(300, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
    assert!(
        same_path(&resolved[0], &lay.b_marker.to_string_lossy()),
        "auditor must resolve the link to the B marker: {resolved:?}"
    );
    let resp = fx.send_and_recv(&line).await;
    assert_same_object(&resolved[0], &resp, "static symlink");
    assert!(resp.contains(&lay.b_marker_text), "B content: {resp}");

    // ── ident: lstat sees the link, stat sees the target ───────────────
    let resp = fx.call("ident", &args).await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(true), "ident: {resp}");
    assert_eq!(
        sc_str(&json, &["lstat", "kind"]).as_deref(),
        Some("symlink"),
        "lstat must report the link itself: {resp}"
    );
    assert_eq!(
        sc_str(&json, &["stat", "kind"]).as_deref(),
        Some("file"),
        "stat must report the target: {resp}"
    );

    // ── post-check swap (TOCTOU): barrier fixes the order ─────────────
    // Point the link at the A marker so the Auditor's interpretation at
    // request time names the A marker.
    std::fs::remove_file(&link).expect("remove link");
    assert!(make_symlink(&lay.a_marker, &link), "re-create link");
    let barrier = lay.b_dir.join("barrier_go");
    let args = format!(
        "{{\"path\":{},\"barrier\":{}}}",
        json_str(&link.to_string_lossy()),
        json_str(&barrier.to_string_lossy())
    );
    let line = call_line(301, "wait_file", &args);
    // The Auditor resolves NOW — before the swap. `path` → A marker;
    // `barrier` (also extracted as an fs target) → B/barrier.
    let resolved_at_check = auditor_resolved(&line, &lay.a_dir);
    assert!(
        resolved_at_check
            .iter()
            .any(|r| same_path(r, &lay.a_marker.to_string_lossy())),
        "auditor resolved the pre-swap target: {resolved_at_check:?}"
    );
    fx.send_line(&line).await;
    // The fixture cannot open until the barrier exists — deterministic order.
    std::fs::remove_file(&link).expect("remove link for swap");
    assert!(make_symlink(&lay.c_secret, &link), "swap link to C");
    std::fs::write(&barrier, b"go").expect("create barrier");
    let resp = fx.recv_line().await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(true), "wait_file open: {resp}");
    let canonical = sc_str(&json, &["canonical"]).unwrap_or_default();
    assert!(
        same_path(&canonical, &lay.c_secret.to_string_lossy()),
        "the open must reach the swapped target C: {resp}"
    );
    assert_eq!(
        reported_ident(&json),
        identity_of(&lay.c_secret),
        "handle identity must be C, not the auditor-resolved A marker"
    );
    assert!(
        resp.contains(&lay.c_secret_text),
        "C content proves the swapped object was read: {resp}"
    );
    assert!(
        !same_path(&canonical, &lay.a_marker.to_string_lossy()),
        "post-check swap must produce a different object than the check"
    );
}

#[cfg(unix)]
fn make_symlink(target: &Path, link: &Path) -> bool {
    std::os::unix::fs::symlink(target, link).is_ok()
}

#[cfg(windows)]
fn make_symlink(target: &Path, link: &Path) -> bool {
    if target.is_dir() {
        std::os::windows::fs::symlink_dir(target, link).is_ok()
    } else {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}

#[cfg(not(any(unix, windows)))]
fn make_symlink(_target: &Path, _link: &Path) -> bool {
    false
}

// ─── Windows-only forms ──────────────────────────────────────────────────────

#[cfg(windows)]
#[tokio::test]
async fn windows_verbatim_and_plain_drive_forms() {
    let Some(exe) = compiled_fixture() else {
        return;
    };
    let lay = layout();
    let Some(mut fx) = FixtureSession::spawn(&exe, &lay.a_dir, &[]).await else {
        return;
    };

    // `lay.a_marker` is already canonical — `\\?\D:\...` on Windows.
    // (a) verbatim input reaches the same object even though the Auditor's
    // match-string strips the prefix;
    // (b) plain `D:\` input also reaches the same object.
    for (label, input) in [
        ("verbatim", lay.a_marker.to_string_lossy().into_owned()),
        (
            "plain drive",
            lay.a_marker
                .to_string_lossy()
                .strip_prefix("\\\\?\\")
                .map(str::to_string)
                .unwrap_or_else(|| lay.a_marker.to_string_lossy().into_owned()),
        ),
    ] {
        let args = format!("{{\"path\":{}}}", json_str(&input));
        let line = call_line(400, "read_file", &args);
        let resolved = auditor_resolved(&line, &lay.a_dir);
        assert_eq!(resolved.len(), 1, "{label}: resolved={resolved:?}");
        assert!(
            same_path(&resolved[0], &lay.a_marker.to_string_lossy()),
            "{label} input must resolve to the marker: {resolved:?}"
        );
        let resp = fx.send_and_recv(&line).await;
        let json = parse(&resp);
        assert_eq!(sc_ok(&json), Some(true), "{label} open: {resp}");
        assert_eq!(
            reported_ident(&json),
            identity_of(&lay.a_marker),
            "{label} open must reach the same object: {resp}"
        );
    }

    // UNC: skipped — the runbook restricts UNC to managed targets and this
    // test controls no share. Record the decision.
    eprintln!("NOTE: UNC form skipped (no managed verification share)");
}

#[cfg(windows)]
#[tokio::test]
async fn windows_junction_and_drive_relative_forms() {
    let Some(exe) = compiled_fixture() else {
        return;
    };
    let lay = layout();
    let Some(mut fx) = FixtureSession::spawn(&exe, &lay.a_dir, &[]).await else {
        return;
    };

    // ── junction: static reparse point to B — both sides reach B ──────
    // `mklink /J` needs no elevated privilege, unlike file symlinks.
    let jlink = lay.a_dir.join("jlink");
    let status = std::process::Command::new("cmd")
        .args([
            "/c",
            "mklink",
            "/J",
            &jlink.to_string_lossy(),
            &lay.b_dir.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            common::skip_e2e_test("junction creation unavailable");
        }
    }
    if jlink.exists() {
        let via_link = jlink.join("marker.txt");
        let args = format!("{{\"path\":{}}}", json_str(&via_link.to_string_lossy()));
        let line = call_line(410, "read_file", &args);
        let resolved = auditor_resolved(&line, &lay.a_dir);
        assert_eq!(resolved.len(), 1, "resolved={resolved:?}");
        assert!(
            same_path(&resolved[0], &lay.b_marker.to_string_lossy()),
            "auditor must resolve the junction to the B marker: {resolved:?}"
        );
        let resp = fx.send_and_recv(&line).await;
        assert_same_object(&resolved[0], &resp, "junction to B");
        assert!(
            resp.contains(&lay.b_marker_text),
            "B content via junction: {resp}"
        );
    }

    // ── drive-relative `C:name`: a recorded divergence ────────────────
    // The Auditor joins a non-absolute input to the child cwd lexically,
    // while Windows resolves `C:name` against the drive's current
    // directory — the same object as `.` here. Interpretation and actual
    // access disagree; the mismatch is the recorded fact.
    let drive_letter = lay
        .a_marker
        .to_string_lossy()
        .strip_prefix("\\\\?\\")
        .and_then(|s| s.chars().next())
        .unwrap_or('C');
    let drive_rel = format!("{drive_letter}:marker.txt");
    let args = format!("{{\"path\":{}}}", json_str(&drive_rel));
    let line = call_line(411, "read_file", &args);
    let resolved = auditor_resolved(&line, &lay.a_dir);
    let resp = fx.send_and_recv(&line).await;
    let json = parse(&resp);
    assert_eq!(sc_ok(&json), Some(true), "drive-relative open: {resp}");
    let canonical = sc_str(&json, &["canonical"]).unwrap_or_default();
    assert!(
        same_path(&canonical, &lay.a_marker.to_string_lossy()),
        "drive-relative open reaches the cwd's marker: {resp}"
    );
    if let [r] = resolved.as_slice() {
        assert!(
            !same_path(r, &canonical),
            "drive-relative input is a recorded interpretation/access divergence: \
             auditor={r:?} actual={canonical}"
        );
    } else {
        eprintln!(
            "NOTE: auditor produced no fs target for drive-relative input \
             ({drive_rel}); divergence recorded"
        );
    }
}

// ─── 2+3. sandboxed OS boundary & process-shared permission ─────────────────

/// `mcp-writ run` spawn helper for the sandboxed test: no
/// `MCP_WRIT_SKIP_SANDBOX` so the Warden actually applies.
fn spawn_guard_sandboxed(
    policy_path: &Path,
    audit_log: &Path,
    child_argv: &[String],
    extra_env: &[(&str, &str)],
) -> tokio::process::Child {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_mcp-writ"));
    cmd.args([
        "run",
        "--transport",
        "stdio",
        "--policy",
        policy_path.to_str().expect("policy path utf-8"),
        "--audit-log",
        audit_log.to_str().expect("audit path utf-8"),
        "--",
    ]);
    cmd.args(child_argv);
    // A parent-level skip var must not leak into the evidence run.
    cmd.env_remove("MCP_WRIT_SKIP_SANDBOX");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn mcp-writ binary - did you run `cargo build`?")
}

/// Filesystem grants for the sandboxed run, split by OS grant semantics:
/// Linux Landlock `PathBeneath` covers a whole subtree, while the Windows
/// AppContainer DACL grant is per-object (non-recursive) so individual
/// files must be named.
fn sandbox_fs_allows(lay: &Layout, exe: &Path) -> String {
    let f = |p: &Path| p.to_string_lossy().replace('\\', "/");
    let mut out = String::new();
    if cfg!(unix) {
        // Landlock PathBeneath covers the whole subtree beneath a granted
        // directory. Runtime dirs are needed for the dynamically linked exe.
        for dir in [&lay.a_dir, &lay.b_dir] {
            out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(dir)));
        }
        if let Some(exe_dir) = exe.parent() {
            out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(exe_dir)));
        }
        for dir in [
            "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev",
        ] {
            if Path::new(dir).exists() {
                out.push_str(&format!("        allow \"{dir}\" mode=\"read\"\n"));
            }
        }
    } else if cfg!(windows) {
        // Per-object DACL grants: the executable image, the directories for
        // traversal, and each file the child must actually open. C is named
        // nowhere — the OS boundary case depends on that.
        for path in [
            exe.to_path_buf(),
            lay.a_dir.clone(),
            lay.a_marker.clone(),
            lay.b_dir.clone(),
            lay.b_marker.clone(),
        ] {
            out.push_str(&format!("        allow \"{}\" mode=\"read\"\n", f(&path)));
        }
    }
    out
}

fn sandboxed_policy(lay: &Layout, exe: &Path) -> String {
    let fs_allows = sandbox_fs_allows(lay, exe);
    let a_glob = format!("{}/**", lay.a_dir.to_string_lossy().replace('\\', "/"));
    let syscalls = if cfg!(unix) {
        concat!(
            "    syscalls {\n",
            "        allow \"read\" \"write\" \"close\" \"openat\" \"open\" \"newfstatat\" \"stat\" ",
            "\"fstat\" \"lstat\" \"lseek\" \"mmap\" \"mprotect\" \"munmap\" \"brk\" ",
            "\"rt_sigaction\" \"rt_sigprocmask\" \"rt_sigreturn\" \"ioctl\" \"pread64\" ",
            "\"pwrite64\" \"readv\" \"writev\" \"getcwd\" \"chdir\" \"fcntl\" \"flock\" ",
            "\"fsync\" \"dup\" \"dup2\" \"dup3\" \"pipe\" \"pipe2\" \"clone\" \"clone3\" ",
            "\"execve\" \"exit\" \"exit_group\" \"wait4\" \"kill\" \"getpid\" \"getppid\" ",
            "\"getuid\" \"getgid\" \"geteuid\" \"getegid\" \"setsid\" \"sigaltstack\" ",
            "\"futex\" \"nanosleep\" \"clock_gettime\" \"clock_nanosleep\" \"getrandom\" ",
            "\"prctl\" \"arch_prctl\" \"set_tid_address\" \"set_robust_list\" ",
            "\"sched_getaffinity\" \"sched_yield\" \"madvise\" \"prlimit64\" \"rseq\" ",
            "\"getdents64\" \"access\" \"readlink\" \"epoll_create1\" \"epoll_ctl\" ",
            "\"epoll_pwait\" \"epoll_wait\" \"poll\" \"select\"\n",
            "    }\n"
        )
    } else {
        ""
    };
    format!(
        "policy version=1\ndefaults {{\n    filesystem {{\n        secret-overlay #true\n{fs_allows}    }}\n{syscalls}}}\nlogging level=\"info\" fail_closed=#false\nserver \"path-resolution\" {{\n    tool \"read_file\" {{\n        filesystem {{\n            allow \"{a_glob}\"\n        }}\n    }}\n    tool \"open_env\" {{\n        filesystem {{\n            allow none=#true\n            require-path #false\n        }}\n    }}\n}}\n"
    )
}

async fn send_and_recv(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    request: &str,
) -> String {
    send_and_recv_opt(stdin, reader, request)
        .await
        .expect("mcp-writ stdout closed before a response")
}

async fn send_and_recv_opt(
    stdin: &mut tokio::process::ChildStdin,
    reader: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    request: &str,
) -> Option<String> {
    stdin
        .write_all(format!("{request}\n").as_bytes())
        .await
        .ok()?;
    stdin.flush().await.ok()?;
    timeout(Duration::from_secs(TIMEOUT_SECS), async {
        loop {
            match reader.next_line().await {
                Ok(Some(line)) if line.starts_with("{\"jsonrpc\"") => return Some(line),
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

fn parse(resp: &str) -> nojson::RawJson<'_> {
    nojson::RawJson::parse(resp).expect("response must be JSON")
}

fn json_has_error(resp: &str) -> bool {
    parse(resp)
        .value()
        .to_member("error")
        .ok()
        .and_then(|m| m.optional())
        .is_some()
}

fn error_message(resp: &str) -> String {
    parse(resp)
        .value()
        .to_member("error")
        .expect("error")
        .required()
        .expect("error present")
        .to_member("message")
        .expect("message")
        .required()
        .expect("message present")
        .to_unquoted_string_str()
        .expect("message string")
        .into_owned()
}

/// Kill the guard and drain its stderr for the skip diagnostic. Awaiting the
/// stderr task without killing first would hang while the child runs.
async fn kill_and_drain(
    mut child: tokio::process::Child,
    stderr_task: tokio::task::JoinHandle<String>,
) -> String {
    let _ = child.start_kill();
    let _ = child.wait().await;
    timeout(Duration::from_secs(5), stderr_task)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or_default()
}

#[tokio::test]
async fn sandboxed_os_boundary_and_process_shared_access() {
    let Some(exe) = compiled_fixture() else {
        return;
    };
    let lay = layout();

    // Runbook precondition: C is readable by the ordinary user pre-sandbox.
    assert!(
        std::fs::read(&lay.c_secret).is_ok(),
        "C must be readable without the sandbox (the deny must come from the OS grant boundary)"
    );

    // Place the fixture inside a dedicated bin dir so the OS grant covers
    // the executable image on every platform (per-object on Windows,
    // subtree on Landlock).
    let bin_dir = lay.a_sibling_dir.join("bin");
    std::fs::create_dir_all(&bin_dir).expect("bin dir");
    let exe_in_scope = bin_dir.join(exe.file_name().expect("fixture file name"));
    std::fs::copy(&exe, &exe_in_scope).expect("stage fixture exe");

    let dir = tempfile::Builder::new()
        .prefix("mcp_writ_p3b_policy_")
        .tempdir()
        .expect("policy tempdir");
    let policy_path = dir.path().join("policy.kdl");
    std::fs::write(&policy_path, sandboxed_policy(&lay, &exe_in_scope)).expect("write policy");
    let audit_log = common::next_audit_log_path();

    let mut child = spawn_guard_sandboxed(
        &policy_path,
        &audit_log,
        &[exe_in_scope.to_string_lossy().into_owned()],
        &[
            (
                "MCP_WRIT_FIXTURE_INTERNAL_PATH",
                lay.c_secret.to_string_lossy().as_ref(),
            ),
            (
                "MCP_WRIT_FIXTURE_B_PATH",
                lay.b_marker.to_string_lossy().as_ref(),
            ),
        ],
    );
    let mut stdin = child.stdin.take().expect("guard stdin");
    let stdout = child.stdout.take().expect("guard stdout");
    let mut stderr = child.stderr.take().expect("guard stderr");
    let stderr_task = tokio::spawn(async move {
        let mut buf = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut stderr, &mut buf)
            .await
            .ok();
        buf
    });
    let mut reader = BufReader::new(stdout).lines();

    // tools/list sanity — also exercises manifest verification end to end.
    let list_req = r#"{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}}"#;
    let list_resp = send_and_recv_opt(&mut stdin, &mut reader, list_req).await;
    let Some(list_resp) = list_resp else {
        let stderr = kill_and_drain(child, stderr_task).await;
        common::skip_e2e_test(&format!(
            "sandboxed spawn produced no tools/list response; stderr: {stderr}"
        ));
        return;
    };
    assert!(
        !json_has_error(&list_resp),
        "tools/list must pass manifest verification: {list_resp}"
    );

    // ── control: read_file{A} — Auditor allow + OS allow ─────────────
    let req_a = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":11,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":{}}}}}}}",
        json_str(&lay.a_marker.to_string_lossy())
    );
    let resp_a = send_and_recv_opt(&mut stdin, &mut reader, &req_a).await;
    let Some(resp_a) = resp_a else {
        let stderr = kill_and_drain(child, stderr_task).await;
        common::skip_e2e_test(&format!("sandboxed control call failed; stderr: {stderr}"));
        return;
    };
    if json_has_error(&resp_a) {
        let stderr = kill_and_drain(child, stderr_task).await;
        common::skip_e2e_test(&format!(
            "sandboxed control call denied; resp={resp_a} stderr={stderr}"
        ));
        return;
    }
    {
        let json = parse(&resp_a);
        assert_eq!(
            sc_ok(&json),
            Some(true),
            "control read_file(A) must succeed: {resp_a}"
        );
        assert!(
            resp_a.contains(&lay.a_marker_text),
            "control must return A marker content: {resp_a}"
        );
    }

    // ── Auditor deny: read_file{B} — inside the process grant but
    //    outside the tool's fs policy ──────────────────────────────────
    let req_b = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":12,\"method\":\"tools/call\",\"params\":{{\"name\":\"read_file\",\"arguments\":{{\"path\":{}}}}}}}",
        json_str(&lay.b_marker.to_string_lossy())
    );
    let resp_b = send_and_recv(&mut stdin, &mut reader, &req_b).await;
    assert!(
        json_has_error(&resp_b),
        "B must be auditor-denied: {resp_b}"
    );
    let msg = error_message(&resp_b);
    assert!(
        msg.contains("allowed paths") || msg.contains("fs"),
        "expected tool fs denial, got: {msg}"
    );

    // ── OS boundary: open_env{C} — no fs target in args, so the Auditor
    //    passes it; the OS must still deny the internal open ────────────
    let req_c =
        "{\"jsonrpc\":\"2.0\",\"id\":13,\"method\":\"tools/call\",\"params\":{\"name\":\"open_env\",\"arguments\":{}}}".to_string();
    let resp_c = send_and_recv(&mut stdin, &mut reader, &req_c).await;
    {
        let json = parse(&resp_c);
        assert!(
            !json_has_error(&resp_c),
            "open_env is a tool result, not a protocol error: {resp_c}"
        );
        assert!(
            is_error_result(&json),
            "internal open of C must surface isError: {resp_c}"
        );
        assert_eq!(sc_ok(&json), Some(false), "open_env(C) must fail: {resp_c}");
        assert_eq!(
            sc_str(&json, &["error"]).as_deref(),
            Some("EACCES"),
            "C must be denied at the OS boundary (EACCES): {resp_c}"
        );
        assert!(
            !resp_c.contains(&lay.c_secret_text),
            "C content must never reach the client: {resp_c}"
        );
    }

    // ── process-shared permission: open_env{B} — the same tool reaches
    //    B through a server-internal path because the process grant
    //    covers it. Design constraint, recorded. ───────────────────────
    let req_b_env =
        "{\"jsonrpc\":\"2.0\",\"id\":14,\"method\":\"tools/call\",\"params\":{\"name\":\"open_env\",\"arguments\":{\"env\":\"MCP_WRIT_FIXTURE_B_PATH\"}}}".to_string();
    let resp_b_env = send_and_recv(&mut stdin, &mut reader, &req_b_env).await;
    {
        let json = parse(&resp_b_env);
        assert_eq!(
            sc_ok(&json),
            Some(true),
            "internal open of B must succeed under the process grant: {resp_b_env}"
        );
        assert!(
            resp_b_env.contains(&lay.b_marker_text),
            "B content reachable via process-shared permission: {resp_b_env}"
        );
        let env_path = sc_str(&json, &["env_path"]).unwrap_or_default();
        assert!(
            same_path(&env_path, &lay.b_marker.to_string_lossy()),
            "env_path must name B: {env_path}"
        );
    }

    // ── audit evidence: denied event carries the request id ───────────
    drop(stdin);
    let _ = timeout(Duration::from_secs(TIMEOUT_SECS), child.wait()).await;
    let audit = std::fs::read_to_string(&audit_log).unwrap_or_default();
    let denied = audit
        .lines()
        .find(|l| l.contains("\"event_type\":\"tool_call.denied\""))
        .unwrap_or_else(|| panic!("audit log missing tool_call.denied: {audit}"));
    let denied_json = parse(denied);
    let request_id = denied_json
        .value()
        .to_member("request_id")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|v| v.to_unquoted_string_str().ok().map(|s| s.into_owned()));
    assert_eq!(
        request_id.as_deref(),
        Some("12"),
        "denied event must carry the client request id: {denied}"
    );
    assert!(
        denied.contains("\"target_tool\":\"read_file\""),
        "denied event must name the tool: {denied}"
    );
}
