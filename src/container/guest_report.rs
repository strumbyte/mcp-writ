//! Guest-side launch-report channel and runner capability detection.
//!
//! The container contract is a Linux guest whose PID 1 is
//! `mcp-secure-runner`. Guest-side controls (OS sandbox, auditor, RPC
//! enforcement) are not observable from the host, so the runner writes
//! its own [`crate::enforcement::LaunchReport`] into a dedicated
//! bind-mounted directory and the host attaches it — verbatim and marked
//! as guest-self-reported — to its own launch report.
//!
//! Capability discovery works across OS/arch without executing the
//! runner: the runner binary embeds a NUL-terminated
//! `MCP_WRIT_RUNNER_CAPS:` marker scanned by `wrap-image`/`containerize`
//! at build time, recorded on the image as a `MCP_WRIT_RUNNER_CAPS` env
//! entry, and read back by `run-image` via image inspect. An image with
//! no parseable marker is treated as a *legacy* runner everywhere —
//! never as "unknown but probably capable".

use std::path::Path;
use std::time::{Duration, Instant};

use crate::enforcement::GuestRunnerIdentity;
use crate::execution::{TargetArch, TargetOs};

/// Guest-side mount point for the report handoff directory. Kept
/// separate from the read-only policy mount (`/etc/mcp-secure`) and the
/// optional audit-log mount (`/var/log/mcp-secure`): the runner writes
/// here, everything else it only reads.
pub const GUEST_REPORT_MOUNT_PATH: &str = "/run/mcp-secure/report";

/// File name the runner writes inside the report mount.
pub const GUEST_REPORT_FILENAME: &str = "report.json";

/// Runtime env var carrying the report directory to the runner. Cleared
/// by `container_run_args` like every other `MCP_WRIT_*` channel var so
/// an image cannot bake a redirection target in.
pub const REPORT_OUT_ENV: &str = "MCP_WRIT_REPORT_OUT";

/// Image `ENV` name recording the embedded runner's capabilities.
pub const RUNNER_CAPS_ENV: &str = "MCP_WRIT_RUNNER_CAPS";

/// Prefix of the capability marker embedded in the runner binary.
pub const RUNNER_CAPS_MARKER_PREFIX: &str = "MCP_WRIT_RUNNER_CAPS:";

/// Capability token claiming the dedicated report channel (v1).
pub const GUEST_REPORT_CAP: &str = "guest-report-1";

/// Hard cap on a guest report file — reports are validated, not trusted.
pub const MAX_GUEST_REPORT_BYTES: u64 = 8 * 1024 * 1024;

/// Bounded wait for the report file after the container exits: the guest
/// process has already exited, so this only covers delayed mount
/// visibility, not runner latency. Tests use a short deadline so the
/// missing/late-arrival paths stay cheap to exercise.
#[cfg(not(test))]
const GUEST_REPORT_WAIT: Duration = Duration::from_secs(3);
#[cfg(test)]
const GUEST_REPORT_WAIT: Duration = Duration::from_millis(250);

/// Byte cap on the scanned marker value in a runner binary.
const MARKER_VALUE_LIMIT: usize = 1024;

/// The capability marker this workspace's runner embeds — prefix, JSON
/// body, NUL terminator. The host scans runner binaries for this exact
/// byte sequence.
pub const RUNNER_CAPS_MARKER: &str = concat!(
    "MCP_WRIT_RUNNER_CAPS:{\"v\":\"",
    env!("CARGO_PKG_VERSION"),
    "\",\"caps\":[\"guest-report-1\"]}\0"
);

/// Capabilities a runner binary claims, scanned from its marker or
/// parsed back from an image's `MCP_WRIT_RUNNER_CAPS` env entry.
#[derive(Debug, Clone, PartialEq)]
pub struct RunnerCaps {
    /// Runner crate version (`v` field of the marker JSON).
    pub version: String,
    /// Claimed capability tokens (`caps` array).
    pub capabilities: Vec<String>,
}

impl RunnerCaps {
    /// Whether the runner claims the dedicated report channel.
    pub fn guest_report_capable(&self) -> bool {
        self.capabilities.iter().any(|c| c == GUEST_REPORT_CAP)
    }

    /// Canonical `KEY=value` env entry recorded on built images.
    pub fn env_value(&self) -> String {
        nojson::object(|f| {
            f.member("v", self.version.as_str())?;
            f.member(
                "caps",
                nojson::array(|f| {
                    for c in &self.capabilities {
                        f.element(c.as_str())?;
                    }
                    Ok(())
                }),
            )
        })
        .to_string()
    }

    /// The identity recorded on guest-written reports and on the host
    /// report's `guest.runner` member.
    pub fn identity(&self) -> GuestRunnerIdentity {
        GuestRunnerIdentity {
            version: self.version.clone(),
            capabilities: self.capabilities.clone(),
        }
    }
}

/// The capability declaration of the runner this build produces — the
/// same values [`RUNNER_CAPS_MARKER`] embeds in the binary.
pub fn this_runner_identity() -> GuestRunnerIdentity {
    GuestRunnerIdentity {
        version: env!("CARGO_PKG_VERSION").to_string(),
        capabilities: vec![GUEST_REPORT_CAP.to_string()],
    }
}

/// Find the NUL-terminated `MCP_WRIT_RUNNER_CAPS:` marker in a runner
/// binary and parse its JSON body. `None` on a binary without a marker —
/// the legacy-runner case, not an error.
pub fn scan_runner_caps(binary: &[u8]) -> Option<RunnerCaps> {
    let prefix = RUNNER_CAPS_MARKER_PREFIX.as_bytes();
    let start = binary.windows(prefix.len()).position(|w| w == prefix)? + prefix.len();
    let rest = &binary[start..];
    let end = rest
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(rest.len())
        .min(MARKER_VALUE_LIMIT);
    let text = std::str::from_utf8(&rest[..end]).ok()?;
    parse_caps_json(text)
}

/// Runner capabilities recorded on the image by `wrap-image` /
/// `containerize`. `None` when the marker env is absent, empty, or
/// unparseable — all indistinguishable from a pre-report-channel build.
pub fn caps_from_image_env(env: &[String]) -> Option<RunnerCaps> {
    let prefix = format!("{RUNNER_CAPS_ENV}=");
    for entry in env {
        if let Some(value) = entry.strip_prefix(prefix.as_str()) {
            if value.is_empty() {
                return None;
            }
            return parse_caps_json(value);
        }
    }
    None
}

/// Parse `{"v": "...", "caps": ["...", ...]}` — tolerant of unknown keys
/// and string arrays only.
fn parse_caps_json(text: &str) -> Option<RunnerCaps> {
    let json = nojson::RawJson::parse(text).ok()?;
    let root = json.value();
    if root.kind() != nojson::JsonValueKind::Object {
        return None;
    }
    let version = string_member(&root, "v")?;
    let caps_val = root.to_member("caps").ok().and_then(|m| m.optional())?;
    let mut capabilities = Vec::new();
    for el in caps_val.to_array().ok()? {
        capabilities.push(el.to_unquoted_string_str().ok()?.into_owned());
    }
    Some(RunnerCaps {
        version,
        capabilities,
    })
}

/// Decide the workload OS from the inspected image and enforce the guest
/// contract — only Linux images run `mcp-secure-runner`. Windows images
/// are an explicit, named refusal; an undeterminable OS is refused too
/// rather than assumed.
pub fn check_guest_image_os(os: Option<&str>) -> Result<TargetOs, String> {
    match os.map(|s| s.trim().to_ascii_lowercase()) {
        Some(os) if os == "linux" => Ok(TargetOs::Linux),
        Some(os) if os == "windows" => Err(
            "windows images are not supported: the runner contract is a Linux guest \
             (wrap a Linux image instead)"
                .to_string(),
        ),
        Some(os) => Err(format!(
            "unsupported image OS '{os}': only linux images support the runner contract"
        )),
        None => Err(
            "image OS could not be determined; only linux images support the runner contract"
                .to_string(),
        ),
    }
}

/// Map an image-reported architecture to a `TargetArch`, preserving
/// unknown names (`arm/v7`, `ppc64le`, …) instead of collapsing them.
pub fn image_target_arch(arch: Option<&str>) -> TargetArch {
    match arch.map(|s| s.trim().to_ascii_lowercase()) {
        Some(a) if a == "amd64" || a == "x86_64" => TargetArch::X86_64,
        Some(a) if a == "arm64" || a == "aarch64" => TargetArch::Aarch64,
        Some(a) => TargetArch::Other(a),
        None => TargetArch::Other("unknown".to_string()),
    }
}

/// Detect a remote engine endpoint configured via the standard
/// endpoint env vars (`DOCKER_HOST`, `CONTAINER_HOST`, `CONTAINER_SSHKEY`).
/// Bind mounts of host temp paths cannot reach a daemon on another
/// machine, so a remote endpoint is refused before any mount is built.
/// Context-based remotes that never touch these vars stay a documented
/// limitation — the spawn fails naturally instead of mounting the wrong
/// host's paths.
pub fn remote_daemon_hint(engine_name: &str) -> Option<String> {
    remote_daemon_hint_for(engine_name, |var| std::env::var(var).ok())
}

fn remote_daemon_hint_for(
    engine_name: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Option<String> {
    let vars: &[&str] = match engine_name {
        "docker" => &["DOCKER_HOST"],
        "podman" => &["CONTAINER_HOST", "CONTAINER_SSHKEY"],
        _ => &[],
    };
    for var in vars {
        let Some(value) = lookup(var) else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if *var == "CONTAINER_SSHKEY" {
            return Some(format!(
                "{var} is set: the podman endpoint is a remote ssh host"
            ));
        }
        for scheme in ["tcp://", "ssh://", "http://", "https://"] {
            if value.to_ascii_lowercase().starts_with(scheme) {
                return Some(format!(
                    "{var}={value} points at a remote daemon; host bind mounts cannot reach it"
                ));
            }
        }
    }
    None
}

/// Result of collecting the guest report file after container exit.
#[derive(Debug, Clone, PartialEq)]
pub enum GuestReportRead {
    /// Validated report JSON (verbatim text).
    Received(String),
    /// No file appeared within the bounded wait.
    Missing(String),
    /// A file existed but failed validation.
    Invalid(String),
}

/// Read and validate `report.json` written by the in-guest runner.
///
/// The bounded wait covers delayed mount visibility only — the guest
/// process already exited when this runs. The size cap plus content
/// checks (launch id, runner identity, schema) keep a hostile or
/// crashing workload from flooding or spoofing the record; the content
/// itself stays guest-self-reported regardless.
pub async fn read_guest_report(
    dir: &Path,
    launch_id: uuid::Uuid,
    expected_runner_version: Option<&str>,
) -> GuestReportRead {
    let path = dir.join(GUEST_REPORT_FILENAME);
    let deadline = Instant::now() + GUEST_REPORT_WAIT;
    let file_len = loop {
        // The report area is guest-writable: a symlink or special file
        // there is not a report, and a symlink must never be followed
        // into host paths. symlink_metadata inspects the entry itself.
        match std::fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_symlink() => {
                return GuestReportRead::Invalid(
                    "report path is a symlink; refusing to follow it".to_string(),
                );
            }
            Ok(m) if m.is_file() => break m.len(),
            Ok(_) => {
                return GuestReportRead::Invalid(
                    "report path exists but is not a regular file".to_string(),
                );
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                return GuestReportRead::Missing(format!(
                    "no {GUEST_REPORT_FILENAME} appeared in the report mount within {}ms",
                    GUEST_REPORT_WAIT.as_millis()
                ));
            }
        }
    };
    if file_len > MAX_GUEST_REPORT_BYTES {
        return GuestReportRead::Invalid(format!(
            "report file exceeds the {MAX_GUEST_REPORT_BYTES}-byte limit"
        ));
    }
    // The declared length already passed the cap, but the read is still
    // limited to one byte past the limit in case the file grew between
    // the metadata check and the open.
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            return GuestReportRead::Invalid(format!("could not open report file: {e}"));
        }
    };
    let mut limited = std::io::Read::take(file, MAX_GUEST_REPORT_BYTES + 1);
    let mut bytes = Vec::new();
    if let Err(e) = std::io::Read::read_to_end(&mut limited, &mut bytes) {
        return GuestReportRead::Invalid(format!("could not read report file: {e}"));
    }
    if bytes.len() as u64 > MAX_GUEST_REPORT_BYTES {
        return GuestReportRead::Invalid(format!(
            "report file exceeds the {MAX_GUEST_REPORT_BYTES}-byte limit"
        ));
    }
    let text = match String::from_utf8(bytes) {
        Ok(t) => t,
        Err(e) => {
            return GuestReportRead::Invalid(format!("report file is not UTF-8: {e}"));
        }
    };
    match validate_guest_report_text(&text, launch_id, expected_runner_version) {
        Ok(()) => GuestReportRead::Received(text),
        Err(detail) => GuestReportRead::Invalid(detail),
    }
}

/// Validate a guest report file's content: schema version, the launch id
/// this host issued, and a runner self-declaration consistent with what
/// the image recorded. Any mismatch is `Err(detail)` — the file was
/// transported but cannot be trusted as this launch's record.
pub fn validate_guest_report_text(
    text: &str,
    launch_id: uuid::Uuid,
    expected_runner_version: Option<&str>,
) -> Result<(), String> {
    let json =
        nojson::RawJson::parse(text).map_err(|e| format!("guest report is not valid JSON: {e}"))?;
    let root = json.value();
    if root.kind() != nojson::JsonValueKind::Object {
        return Err("guest report is not a JSON object".to_string());
    }
    match string_member(&root, "schema_version").as_deref() {
        Some(crate::enforcement::LAUNCH_REPORT_SCHEMA_VERSION) => {}
        other => {
            return Err(format!(
                "guest report schema_version is {other:?}, expected \"1\""
            ));
        }
    }
    match string_member(&root, "launch_id") {
        Some(id) if id == launch_id.to_string() => {}
        Some(id) => {
            return Err(format!("guest report carries a different launch_id ({id})"));
        }
        None => return Err("guest report carries no launch_id".to_string()),
    }
    let runner = root
        .to_member("guest_runner")
        .ok()
        .and_then(|m| m.optional())
        .ok_or_else(|| "guest report carries no guest_runner identity".to_string())?;
    let version = string_member(&runner, "version")
        .ok_or_else(|| "guest_runner identity has no version".to_string())?;
    if let Some(expected) = expected_runner_version
        && expected != version
    {
        return Err(format!(
            "guest runner version '{version}' does not match the image-recorded '{expected}'"
        ));
    }
    let mut claims_cap = false;
    if let Some(caps) = runner
        .to_member("capabilities")
        .ok()
        .and_then(|m| m.optional())
        && let Ok(arr) = caps.to_array()
    {
        for el in arr {
            if let Ok(s) = el.to_unquoted_string_str()
                && s.as_ref() == GUEST_REPORT_CAP
            {
                claims_cap = true;
            }
        }
    }
    if !claims_cap {
        return Err(format!(
            "guest runner does not claim the {GUEST_REPORT_CAP} capability"
        ));
    }
    Ok(())
}

/// Decode a string member of `obj`, tolerating a missing or `null` value.
fn string_member(obj: &nojson::RawJsonValue<'_, '_>, name: &str) -> Option<String> {
    let v = obj.to_member(name).ok().and_then(|m| m.optional())?;
    v.to_unquoted_string_str()
        .ok()
        .map(|s| s.into_owned())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps_json(v: &str, caps: &str) -> String {
        format!("{{\"v\":\"{v}\",\"caps\":[{caps}]}}")
    }

    #[test]
    fn scan_finds_marker_in_binary_blob() {
        let mut blob = b"\x7fELF noise".to_vec();
        blob.extend_from_slice(RUNNER_CAPS_MARKER.as_bytes());
        blob.extend_from_slice(b" more \x01\x02 binary");
        let caps = scan_runner_caps(&blob).expect("marker should be found");
        assert_eq!(caps.version, env!("CARGO_PKG_VERSION"));
        assert!(caps.guest_report_capable());
    }

    #[test]
    fn scan_absent_marker_is_none() {
        assert_eq!(scan_runner_caps(b"#!/bin/sh\nexec \"$@\"\n"), None);
        // Truncated marker body (no NUL, no JSON) is also a miss.
        let mut blob = RUNNER_CAPS_MARKER_PREFIX.as_bytes().to_vec();
        blob.extend_from_slice(b"{\"v\":");
        assert_eq!(scan_runner_caps(&blob), None);
    }

    #[test]
    fn caps_env_roundtrip() {
        let caps = RunnerCaps {
            version: "0.5.0".to_string(),
            capabilities: vec![GUEST_REPORT_CAP.to_string()],
        };
        let entry = format!("{RUNNER_CAPS_ENV}={}", caps.env_value());
        let parsed = caps_from_image_env(&[entry]).expect("env value parses");
        assert_eq!(parsed, caps);
        assert_eq!(parsed.identity().version, "0.5.0");
    }

    #[test]
    fn caps_env_absent_empty_and_broken_are_legacy() {
        assert_eq!(caps_from_image_env(&[]), None);
        assert_eq!(caps_from_image_env(&[format!("{RUNNER_CAPS_ENV}=")]), None);
        assert_eq!(
            caps_from_image_env(&[format!("{RUNNER_CAPS_ENV}=not-json")]),
            None
        );
        assert_eq!(
            caps_from_image_env(&[format!("{RUNNER_CAPS_ENV}={{\"v\":\"1\"}}")]),
            None
        );
    }

    #[test]
    fn caps_without_guest_report_capability() {
        let caps = parse_caps_json(&caps_json("1.0", "\"other-cap\"")).unwrap();
        assert!(!caps.guest_report_capable());
    }

    #[test]
    fn guest_os_gate() {
        assert_eq!(check_guest_image_os(Some("linux")), Ok(TargetOs::Linux));
        assert_eq!(check_guest_image_os(Some(" Linux ")), Ok(TargetOs::Linux));
        let w = check_guest_image_os(Some("windows")).unwrap_err();
        assert!(w.contains("windows"), "{w}");
        let o = check_guest_image_os(Some("freebsd")).unwrap_err();
        assert!(o.contains("unsupported image OS"), "{o}");
        let n = check_guest_image_os(None).unwrap_err();
        assert!(n.contains("could not be determined"), "{n}");
    }

    #[test]
    fn image_arch_mapping() {
        assert_eq!(image_target_arch(Some("amd64")), TargetArch::X86_64);
        assert_eq!(image_target_arch(Some("arm64")), TargetArch::Aarch64);
        assert_eq!(
            image_target_arch(Some("arm/v7")),
            TargetArch::Other("arm/v7".to_string())
        );
        assert_eq!(
            image_target_arch(None),
            TargetArch::Other("unknown".to_string())
        );
    }

    #[test]
    fn remote_hint_schemes() {
        let get = |v: &str| match v {
            "DOCKER_HOST" => Some("tcp://192.0.2.10:2375".to_string()),
            _ => None,
        };
        assert!(remote_daemon_hint_for("docker", get).is_some());

        let local = |v: &str| match v {
            "DOCKER_HOST" => Some("unix:///var/run/docker.sock".to_string()),
            _ => None,
        };
        assert_eq!(remote_daemon_hint_for("docker", local), None);
        assert_eq!(remote_daemon_hint_for("docker", |_| None), None);

        let ssh = |v: &str| match v {
            "CONTAINER_SSHKEY" => Some("/home/u/.ssh/id".to_string()),
            _ => None,
        };
        assert!(remote_daemon_hint_for("podman", ssh).is_some());

        let ssh_host = |v: &str| match v {
            "CONTAINER_HOST" => Some("ssh://u@build/run/podman.sock".to_string()),
            _ => None,
        };
        assert!(remote_daemon_hint_for("podman", ssh_host).is_some());
    }

    fn guest_report_json(launch_id: &str, version: &str) -> String {
        format!(
            "{{\"schema_version\":\"1\",\"launch_id\":\"{launch_id}\",\
             \"guest_runner\":{{\"version\":\"{version}\",\"capabilities\":[\"{GUEST_REPORT_CAP}\"]}}}}"
        )
    }

    #[test]
    fn validate_accepts_matching_report() {
        let id = uuid::Uuid::now_v7().to_string();
        let text = guest_report_json(&id, "0.5.0");
        let uuid = uuid::Uuid::parse_str(&id).unwrap();
        validate_guest_report_text(&text, uuid, Some("0.5.0")).unwrap();
        validate_guest_report_text(&text, uuid, None).unwrap();
    }

    #[test]
    fn validate_rejects_wrong_launch_id() {
        let text = guest_report_json(&uuid::Uuid::now_v7().to_string(), "0.5.0");
        let err =
            validate_guest_report_text(&text, uuid::Uuid::now_v7(), Some("0.5.0")).unwrap_err();
        assert!(err.contains("different launch_id"), "{err}");
    }

    #[test]
    fn validate_rejects_runner_version_mismatch() {
        let id = uuid::Uuid::now_v7();
        let text = guest_report_json(&id.to_string(), "0.4.0");
        let err = validate_guest_report_text(&text, id, Some("0.5.0")).unwrap_err();
        assert!(err.contains("does not match"), "{err}");
    }

    #[test]
    fn validate_rejects_bad_schema_and_format() {
        let id = uuid::Uuid::now_v7();
        let bad_schema = guest_report_json(&id.to_string(), "0.5.0")
            .replace("\"schema_version\":\"1\"", "\"schema_version\":\"2\"");
        assert!(validate_guest_report_text(&bad_schema, id, Some("0.5.0")).is_err());
        assert!(validate_guest_report_text("[1,2]", id, None).is_err());
        assert!(validate_guest_report_text("not json", id, None).is_err());
        // No capability claim → not a report-capable writer.
        let no_cap = format!(
            "{{\"schema_version\":\"1\",\"launch_id\":\"{id}\",\
             \"guest_runner\":{{\"version\":\"0.5.0\",\"capabilities\":[]}}}}"
        );
        assert!(validate_guest_report_text(&no_cap, id, None).is_err());
    }

    #[tokio::test]
    async fn read_accepts_valid_report_file() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::now_v7();
        std::fs::write(
            dir.path().join(GUEST_REPORT_FILENAME),
            guest_report_json(&id.to_string(), "0.5.0"),
        )
        .unwrap();
        let read = read_guest_report(dir.path(), id, Some("0.5.0")).await;
        assert!(matches!(read, GuestReportRead::Received(_)), "{read:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn read_rejects_symlink_report() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::now_v7();
        std::os::unix::fs::symlink("/etc/hostname", dir.path().join(GUEST_REPORT_FILENAME))
            .unwrap();
        let read = read_guest_report(dir.path(), id, None).await;
        match read {
            GuestReportRead::Invalid(d) => assert!(d.contains("symlink"), "{d}"),
            other => panic!("symlink must be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_rejects_non_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::now_v7();
        std::fs::create_dir(dir.path().join(GUEST_REPORT_FILENAME)).unwrap();
        let read = read_guest_report(dir.path(), id, None).await;
        match read {
            GuestReportRead::Invalid(d) => assert!(d.contains("regular file"), "{d}"),
            other => panic!("a directory must be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_rejects_oversized_report() {
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::now_v7();
        let mut bytes = vec![b' '; MAX_GUEST_REPORT_BYTES as usize - 10];
        bytes.extend_from_slice(b"01234567890");
        std::fs::write(dir.path().join(GUEST_REPORT_FILENAME), bytes).unwrap();
        let read = read_guest_report(dir.path(), id, None).await;
        match read {
            GuestReportRead::Invalid(d) => assert!(d.contains("limit"), "{d}"),
            other => panic!("oversized report must be refused, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_missing_after_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let read = read_guest_report(dir.path(), uuid::Uuid::now_v7(), None).await;
        match read {
            GuestReportRead::Missing(d) => {
                assert!(d.contains(GUEST_REPORT_FILENAME), "{d}")
            }
            other => panic!("an absent report must read as missing, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn read_picks_up_late_arriving_report() {
        // The deadline covers delayed mount visibility: a file landing
        // inside the wait window is still collected.
        let dir = tempfile::tempdir().unwrap();
        let id = uuid::Uuid::now_v7();
        let path = dir.path().join(GUEST_REPORT_FILENAME);
        let text = guest_report_json(&id.to_string(), "0.5.0");
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            std::fs::write(path, text).unwrap();
        });
        let read = read_guest_report(dir.path(), id, Some("0.5.0")).await;
        assert!(matches!(read, GuestReportRead::Received(_)), "{read:?}");
    }
}
