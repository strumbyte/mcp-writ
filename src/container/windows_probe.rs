//! Windows/WSL environment probes behind `plan`'s version and
//! capability checks (PR-27).
//!
//! Every probe here is a **bounded read**: a fixed deadline, a capped
//! output read, and queries only — `--version`, `query`, `-l -v`,
//! `Get-AppxPackage`. Nothing runs `wsl --update`, enables a Windows
//! feature, starts a distro/VM/session, pulls an image, or elevates;
//! when a fact can only be proven by starting something (a WSLC
//! session, a distro's live kernel), the caller's check reports it as
//! unverified rather than guessing.
//!
//! The report keeps three evidence tiers distinct and never merges
//! them:
//!
//! - **presence** — `wsl.exe`/`wslc.exe` resolved on PATH (or the
//!   CurrentVersion key answered) — the binary/registry artifact.
//! - **version facts** — what the CLI actually reported: the WSL
//!   *product* version and packaged guest kernel (`wsl --version`),
//!   each distro's WSL-1/2 *mode* (`wsl -l -v` — a distro property,
//!   never the product version), the `wslc.exe` version string, the
//!   Windows Sandbox *Store package* version (`Get-AppxPackage`, kept
//!   separate from the `wsb.exe` client string the backend gate
//!   validates), and the host edition/build/arch.
//! - **runtime contract** — session/container start, stdio, the real
//!   API surface. Not probed by `plan`; recorded as unverified.
//!
//! `wslc.exe` is resolved by that name only — never the `container.exe`
//! alias, which names Apple's substrate driver and must not be
//! conflated with it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;

/// Bound on each diagnostic subprocess — a wedged CLI must not stall
/// `plan`.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Per-stream output cap — version/listing output is small; a flood
/// stays bounded.
const OUTPUT_CAP: u64 = 64 * 1024;

/// Executable overrides for the diagnostics harness — same pattern as
/// `MCP_WRIT_WSB_EXE`. Each points a probe at a fixture binary instead
/// of the PATH resolution; unset on a production host.
pub const WSL_EXE_ENV: &str = "MCP_WRIT_WSL_EXE";
pub const WSLC_EXE_ENV: &str = "MCP_WRIT_WSLC_EXE";
pub const REG_EXE_ENV: &str = "MCP_WRIT_REG_EXE";
pub const PWSH_EXE_ENV: &str = "MCP_WRIT_PWSH_EXE";

/// The minimum WSL product version that ships `wslc.exe` — Microsoft's
/// documented floor for WSL Containers is WSL ≥ 2.9.3; the first
/// verification baseline this project plans to adopt is 3.0.1.
pub const WSLC_MIN_WSL: (u64, u64, u64) = (2, 9, 3);

/// What one bounded read-only probe observed. The tiers stay distinct
/// in a report: absent on PATH is not a launch failure, a launch
/// failure is not an answer, and an answer is not a verified runtime
/// contract.
#[derive(Debug)]
pub enum ProbeOutcome {
    /// The executable did not resolve — a PATH/registry absence.
    Absent,
    /// Spawn failed, the deadline elapsed, output overflowed, or the
    /// process exited non-zero — the contract was not exercised.
    Failed(String),
    /// Exited 0; the payload is decoded stdout (UTF-16 aware), capped.
    Answered(String),
}

/// Resolve the executable a probe spawns: the diagnostics override when
/// set (on any host — it points at a fixture), else a PATH lookup that
/// only runs on Windows. A non-Windows host without the override
/// resolves to `None` — `plan` never spawns Windows tools there. An
/// override that does not name an existing file reads as *absent*, not
/// as a spawn failure: the presence tier means a resolved entity.
fn probe_exe(env_var: &str, name: &str) -> Option<PathBuf> {
    if let Some(path) = std::env::var_os(env_var) {
        let path = PathBuf::from(path);
        return path.is_file().then_some(path);
    }
    if cfg!(windows) {
        return crate::workload::search_path(name);
    }
    None
}

/// The `wsl.exe` binary — `MCP_WRIT_WSL_EXE` overrides for fixtures.
pub fn find_wsl() -> Option<PathBuf> {
    probe_exe(WSL_EXE_ENV, "wsl")
}

/// The `wslc.exe` binary — `MCP_WRIT_WSLC_EXE` overrides. The
/// `container` alias is never tried: that name is Apple's substrate
/// driver, not WSL Containers.
pub fn find_wslc() -> Option<PathBuf> {
    probe_exe(WSLC_EXE_ENV, "wslc")
}

/// `wsl.exe --version` — the product/kernel version contract. Inbox
/// WSL exits non-zero on `--version`: a `Failed`, not an `Absent` —
/// presence of the binary and the version contract stay separate.
pub async fn wsl_version(exe: &Path) -> ProbeOutcome {
    run_probe(exe, &["--version"]).await
}

/// `wsl.exe -l -v` — the registered distros and each one's WSL-1/2
/// mode. Read-only: it lists registrations without launching anything.
pub async fn wsl_distros(exe: &Path) -> ProbeOutcome {
    run_probe(exe, &["-l", "-v"]).await
}

/// `wslc.exe --version` — the WSL Containers CLI's self-reported
/// version. An answered CLI is still only the presence/version tier —
/// the runtime contract stays unprobed.
pub async fn wslc_version(exe: &Path) -> ProbeOutcome {
    run_probe(exe, &["--version"]).await
}

/// `powershell Get-AppxPackage` — the Windows Sandbox *Store package*
/// name/version, a separate record from the `wsb.exe --version` client
/// string the backend prerequisite validates.
pub async fn wsb_store_version() -> ProbeOutcome {
    let Some(exe) = probe_exe(PWSH_EXE_ENV, "powershell") else {
        return ProbeOutcome::Absent;
    };
    run_probe(
        &exe,
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-AppxPackage -Name 'Microsoft.WindowsSandbox*' | Select-Object -First 1 \
             | ForEach-Object { $_.Name + ' ' + $_.Version }",
        ],
    )
    .await
}

/// `reg query` the CurrentVersion key — the host's edition, display
/// version, and build (`CurrentBuild` + `UBR`). One bounded read-only
/// spawn on Windows; `Absent` elsewhere.
pub async fn host_edition() -> ProbeOutcome {
    let Some(exe) = probe_exe(REG_EXE_ENV, "reg") else {
        return ProbeOutcome::Absent;
    };
    run_probe(
        &exe,
        &[
            "query",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
        ],
    )
    .await
}

/// Run `exe args` read-only with bounded wall time and capped streams.
/// `WSL_UTF8=1` asks `wsl.exe` for UTF-8 on builds that honor it; the
/// decoder still accepts the UTF-16 replies other builds emit.
async fn run_probe(exe: &Path, args: &[&str]) -> ProbeOutcome {
    let mut command = tokio::process::Command::new(exe);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("WSL_UTF8", "1")
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(e) => return ProbeOutcome::Failed(format!("spawn failed: {e}")),
    };
    let Some(stdout) = child.stdout.take() else {
        return ProbeOutcome::Failed("missing probe stdout".into());
    };
    let Some(stderr) = child.stderr.take() else {
        return ProbeOutcome::Failed("missing probe stderr".into());
    };
    let mut stdout = stdout.take(OUTPUT_CAP + 1);
    let mut stderr = stderr.take(OUTPUT_CAP + 1);
    let mut out = Vec::new();
    let mut err = Vec::new();
    // A stream flooding past the cap must end the probe *now*: a writer
    // that keeps producing blocks on the pipe we stopped draining, so
    // parking on `wait()` would misreport the overflow as a timeout.
    // Encoding overflow as the join's error arm lets `try_join!` fail
    // fast — the child is killed without waiting for its exit.
    enum Stop {
        Io(std::io::Error),
        OverCap,
    }
    let wait = async { child.wait().await.map_err(Stop::Io) };
    let read_out = async {
        match stdout.read_to_end(&mut out).await {
            Ok(_) if out.len() > OUTPUT_CAP as usize => Err(Stop::OverCap),
            Ok(_) => Ok(()),
            Err(e) => Err(Stop::Io(e)),
        }
    };
    let read_err = async {
        match stderr.read_to_end(&mut err).await {
            Ok(_) if err.len() > OUTPUT_CAP as usize => Err(Stop::OverCap),
            Ok(_) => Ok(()),
            Err(e) => Err(Stop::Io(e)),
        }
    };
    let joined = tokio::time::timeout(PROBE_TIMEOUT, async {
        tokio::try_join!(wait, read_out, read_err)
    })
    .await;
    let (status, _, _) = match joined {
        Ok(Ok(joined)) => joined,
        Ok(Err(Stop::OverCap)) => {
            let _ = child.kill().await;
            return ProbeOutcome::Failed(format!("output exceeds {} KiB", OUTPUT_CAP / 1024));
        }
        Ok(Err(Stop::Io(e))) => {
            let _ = child.kill().await;
            return ProbeOutcome::Failed(format!("read failed: {e}"));
        }
        Err(_) => {
            let _ = child.kill().await;
            return ProbeOutcome::Failed(format!("no answer within {}s", PROBE_TIMEOUT.as_secs()));
        }
    };
    if !status.success() {
        let tail = decode_cli_text(&err);
        let tail = tail.trim();
        return ProbeOutcome::Failed(if tail.is_empty() {
            format!("exited {status}")
        } else {
            format!("exited {status}: {}", abbreviate(tail, 200))
        });
    }
    ProbeOutcome::Answered(decode_cli_text(&out))
}

/// Decode probe output that may be UTF-16 — some `wsl.exe` replies are
/// UTF-16LE when piped, even with `WSL_UTF8` set on older builds. A BOM
/// wins; otherwise a NUL-byte density in the first bytes selects
/// UTF-16LE (the only flavor wsl emits); anything else is UTF-8.
pub fn decode_cli_text(bytes: &[u8]) -> String {
    if let Some(body) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16_le(body);
    }
    if let Some(body) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let sample = bytes.len().min(256);
    if sample >= 8 {
        let zeros = bytes[..sample].iter().filter(|&&b| b == 0).count();
        // A UTF-16LE ASCII-heavy stream is ~50% NUL bytes; UTF-8 has
        // none. The loose threshold keeps CJK-heavy UTF-16 covered —
        // the ASCII scaffolding (labels, digits) still zeroes out.
        if zeros * 4 > sample {
            return decode_utf16_le(bytes);
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

fn decode_utf16_le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    String::from_utf16_lossy(&units).replace('\0', "")
}

/// The fields `wsl --version` carries — every one optional; an
/// unrecognized layout simply records nothing rather than claiming a
/// version.
#[derive(Debug, Default)]
pub struct WslVersion {
    /// `WSL version:` — the *product* (Store package) version, e.g.
    /// "3.0.1". Never a distro's WSL-1/2 mode.
    pub product: Option<String>,
    /// `Kernel version:` — the packaged WSL2 guest kernel.
    pub kernel: Option<String>,
    /// `Windows version:` — the host build as WSL reports it.
    pub windows: Option<String>,
}

/// Parse `wsl --version` output — `Key: value` lines. Labels are
/// matched on stable substrings (`wsl`, `kernel`, `windows`) rather
/// than the full English label so localized output still parses; an
/// unknown shape yields all-`None`, which the caller must not read as
/// a version.
pub fn parse_wsl_version(text: &str) -> WslVersion {
    let mut parsed = WslVersion::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let key = key.trim().to_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if key.contains("kernel") || key.contains("カーネル") {
            parsed.kernel = Some(value.to_string());
        } else if key.contains("wsl") {
            // "WSL version" / "WSL バージョン" — the product line.
            // `wslg` (and any other wsl* component) is not the product.
            if key.contains("wslg") {
                continue;
            }
            if parsed.product.is_none() {
                parsed.product = Some(value.to_string());
            }
        } else if key.contains("windows") {
            parsed.windows = Some(value.to_string());
        }
    }
    parsed
}

/// One `wsl -l -v` row — the per-distro *mode* (1 or 2), which is a
/// distro property and never the WSL product version.
#[derive(Debug)]
pub struct WslDistro {
    pub name: String,
    /// The distro's WSL mode — 1 or 2. `None` only via parse paths
    /// that never reach construction; kept as the column's value.
    pub mode: Option<u8>,
    /// The `*` marker — the default distro.
    pub is_default: bool,
}

/// Parse `wsl -l -v` output positionally: a data row ends in the mode
/// digit (1|2); anything else — the localized header ("NAME STATE
/// VERSION", "名前 状態 バージョン", …) or prose — is skipped. Names
/// may contain spaces; state is a single localized token the report
/// does not record.
pub fn parse_wsl_distros(text: &str) -> Vec<WslDistro> {
    let mut distros = Vec::new();
    for line in text.lines() {
        let mut fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let mut is_default = false;
        if fields.first() == Some(&"*") {
            is_default = true;
            fields.remove(0);
        }
        let Some(mode) = fields
            .last()
            .and_then(|s| s.parse::<u8>().ok())
            .filter(|m| matches!(m, 1 | 2))
        else {
            continue;
        };
        let name = match fields.len() {
            0 | 1 => continue,
            2 => fields[0].to_string(),
            _ => fields[..fields.len() - 2].join(" "),
        };
        if name.is_empty() {
            continue;
        }
        distros.push(WslDistro {
            name,
            mode: Some(mode),
            is_default,
        });
    }
    distros
}

/// Windows edition facts from `reg query` of the CurrentVersion key —
/// value names and the `REG_SZ`/`REG_DWORD` type columns are stable
/// ASCII on every locale; only the value text is localized.
#[derive(Debug, Default)]
pub struct WindowsEdition {
    /// `ProductName` — e.g. "Windows 11 Pro".
    pub product_name: Option<String>,
    /// `EditionID` — e.g. "Professional".
    pub edition_id: Option<String>,
    /// `DisplayVersion` — e.g. "25H2".
    pub display_version: Option<String>,
    /// `CurrentBuild` — e.g. "26200".
    pub current_build: Option<String>,
    /// `UBR` (update build revision) — e.g. 9457.
    pub ubr: Option<u32>,
}

impl WindowsEdition {
    /// `CurrentBuild.UBR` — the "26200.9457" form evidence cites.
    pub fn build(&self) -> Option<String> {
        match (&self.current_build, self.ubr) {
            (Some(build), Some(ubr)) => Some(format!("{build}.{ubr}")),
            (Some(build), None) => Some(build.clone()),
            _ => None,
        }
    }
}

/// Parse a `reg query` dump of `HKLM\SOFTWARE\Microsoft\Windows NT\
/// CurrentVersion`: `<name> <REG_*> <value>` rows.
pub fn parse_current_version_key(text: &str) -> WindowsEdition {
    let mut out = WindowsEdition::default();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(ty)) = (fields.next(), fields.next()) else {
            continue;
        };
        let value = fields.collect::<Vec<_>>().join(" ");
        match (name, ty) {
            ("ProductName", "REG_SZ") => out.product_name = Some(value),
            ("EditionID", "REG_SZ") => out.edition_id = Some(value),
            ("DisplayVersion", "REG_SZ") => out.display_version = Some(value),
            ("CurrentBuild", "REG_SZ") => out.current_build = Some(value),
            ("UBR", "REG_DWORD") => {
                out.ubr = u32::from_str_radix(value.trim_start_matches("0x"), 16).ok();
            }
            _ => {}
        }
    }
    out
}

/// Numeric dotted-version floor check — `None` when the text is not a
/// plain numeric tuple (an unparseable version never proves a floor).
pub fn version_at_least(text: &str, minimum: (u64, u64, u64)) -> Option<bool> {
    let mut parts = Vec::new();
    for comp in text.trim().split('.') {
        match comp.parse::<u64>() {
            Ok(n) => parts.push(n),
            Err(_) => return None,
        }
    }
    if !(2..=4).contains(&parts.len()) {
        return None;
    }
    Some((parts[0], parts[1], parts.get(2).copied().unwrap_or(0)) >= minimum)
}

/// Truncate a probe detail for the check line — keeps one line, caps
/// the length so a noisy answer can't flood the report.
pub fn abbreviate(text: &str, max: usize) -> String {
    let mut out: String = text.chars().take(max).collect();
    if text.chars().count() > max {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
    }

    #[test]
    fn decode_cli_text_handles_utf8_and_utf16() {
        assert_eq!(
            decode_cli_text(b"WSL version: 3.0.1\n"),
            "WSL version: 3.0.1\n"
        );
        assert_eq!(decode_cli_text(b""), "");
        let with_bom = [&[0xFF, 0xFE], utf16le("abc").as_slice()].concat();
        assert_eq!(decode_cli_text(&with_bom), "abc");
        assert_eq!(
            decode_cli_text(&utf16le("WSL version: 3.0.1\r\n")),
            "WSL version: 3.0.1\r\n"
        );
        let ja = utf16le("WSL バージョン: 3.0.1\r\nカーネル バージョン: 5.15\r\n");
        let decoded = decode_cli_text(&ja);
        assert!(decoded.contains("WSL"), "{decoded}");
        assert!(decoded.contains("3.0.1"), "{decoded}");
    }

    #[test]
    fn parse_wsl_version_extracts_product_kernel_windows() {
        let text = "WSL version: 3.0.1\r\nKernel version: 6.6.36.3-1\r\n\
                    WSLg version: 1.0.65\r\nMSRDC version: 1.2.5716\r\n\
                    Windows version: 10.0.26200.9457\r\n";
        let v = parse_wsl_version(text);
        assert_eq!(v.product.as_deref(), Some("3.0.1"));
        assert_eq!(v.kernel.as_deref(), Some("6.6.36.3-1"));
        assert_eq!(v.windows.as_deref(), Some("10.0.26200.9457"));
    }

    #[test]
    fn parse_wsl_version_japanese_labels() {
        let v = parse_wsl_version(
            "WSL バージョン: 2.4.12.0\nカーネル バージョン: 5.15.167.4-1\nWindows バージョン: 10.0.22631\n",
        );
        assert_eq!(v.product.as_deref(), Some("2.4.12.0"));
        assert_eq!(v.kernel.as_deref(), Some("5.15.167.4-1"));
        assert_eq!(v.windows.as_deref(), Some("10.0.22631"));
    }

    #[test]
    fn parse_wsl_version_unknown_shape_claims_nothing() {
        let v = parse_wsl_version("garbage\nno version here\n");
        assert!(v.product.is_none() && v.kernel.is_none() && v.windows.is_none());
        let v = parse_wsl_version("");
        assert!(v.product.is_none());
    }

    #[test]
    fn parse_wsl_distros_positional_and_localized() {
        let text = "  NAME              STATE     VERSION\r\n* Ubuntu-24.04      Running   2\r\n  docker-desktop    Stopped   2\r\n  legacy            Stopped   1\r\n";
        let d = parse_wsl_distros(text);
        assert_eq!(d.len(), 3);
        assert!(d[0].is_default && d[0].name == "Ubuntu-24.04" && d[0].mode == Some(2));
        assert_eq!(d[2].mode, Some(1));
        // Japanese header + state are still skipped structurally.
        let ja = "  名前              状態      バージョン\r\n* Ubuntu            実行中     2\r\n";
        let d = parse_wsl_distros(ja);
        assert_eq!(d.len(), 1);
        assert!(d[0].is_default && d[0].mode == Some(2));
        // Empty and garbage inputs claim no distros.
        assert!(parse_wsl_distros("").is_empty());
        assert!(parse_wsl_distros("random prose\nno digits here\n").is_empty());
    }

    #[test]
    fn parse_current_version_key_records_edition_build() {
        let text = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\r\n\
                    \r\n    ProductName    REG_SZ    Windows 11 Pro\r\n\
                    \x20   EditionID    REG_SZ    Professional\r\n\
                    \x20   DisplayVersion    REG_SZ    25H2\r\n\
                    \x20   CurrentBuild    REG_SZ    26200\r\n\
                    \x20   UBR    REG_DWORD    0x24f1\r\n";
        let e = parse_current_version_key(text);
        assert_eq!(e.product_name.as_deref(), Some("Windows 11 Pro"));
        assert_eq!(e.edition_id.as_deref(), Some("Professional"));
        assert_eq!(e.display_version.as_deref(), Some("25H2"));
        assert_eq!(e.build().as_deref(), Some("26200.9457"));
        assert!(parse_current_version_key("").product_name.is_none());
    }

    #[test]
    fn version_floor_compares_numeric_tuples() {
        assert_eq!(version_at_least("3.0.1", WSLC_MIN_WSL), Some(true));
        assert_eq!(version_at_least("2.9.3", WSLC_MIN_WSL), Some(true));
        assert_eq!(version_at_least("2.9.4.1", WSLC_MIN_WSL), Some(true));
        assert_eq!(version_at_least("2.4.12.0", WSLC_MIN_WSL), Some(false));
        assert_eq!(version_at_least("unknown", WSLC_MIN_WSL), None);
        assert_eq!(version_at_least("", WSLC_MIN_WSL), None);
    }
}
