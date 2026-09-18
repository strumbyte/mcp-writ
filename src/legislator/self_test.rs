//! Policy self-test harness for `generate-policy --self-test`.
//!
//! Collects **limited execution evidence** for a generated draft:
//! - Auditor: JSON-RPC policy errors (deny tool / out-of-schema / secret path).
//!   Never labeled as Warden evidence.
//! - Warden (Linux): `pass` only on SIGSYS after handshake + control call.
//!   JSON-RPC text (including fabricated `EACCES`) is `inconclusive`.
//!   Spawn that was never attempted is reported as `not attempted`, not
//!   `failed`. Other OS: `skipped` when the child starts, else `inconclusive`.
//!
//! This is not a proof of complete enforcement. RCE canaries are not used.
//! Spawn always goes through [`crate::warden::Warden::spawn_child_async_with`]
//! (the `run` path) with a restricted environment. Never
//! `--unsafe-unsandboxed-discovery`.

use std::io::{self, Write};
use std::path::PathBuf;
use std::time::Duration;

pub use super::self_test_auditor::{
    build_tools_call, evaluate_auditor_probes, is_policy_jsonrpc_error,
};
pub use super::self_test_warden::{classify_warden_observation, prepare_warden_probe_policy};

use super::self_test_warden::collect_warden_evidence;

/// Default overall self-test budget.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(8);

/// Path used for the Linux Warden probe. Must stay outside the Landlock grant.
pub const WARDEN_PROBE_PATH: &str = "/etc/passwd";

/// Exit code after a draft was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelfTestExit {
    /// Auditor evidence collected; Warden pass or skipped.
    EvidenceOk = 0,
    /// Ran, but evidence was missing or contradictory.
    Insufficient = 2,
}

/// How the Auditor probe set went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditorVerdict {
    Pass,
    Fail,
}

impl AuditorVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }
}

/// How the Warden probe went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WardenVerdict {
    Pass,
    Fail,
    Inconclusive,
    Skipped,
}

impl WardenVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Inconclusive => "inconclusive",
            Self::Skipped => "skipped",
        }
    }
}

/// Whether a child process was launched for evidence collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnStatus {
    /// No process was started (missing reader/tool, empty argv, Auditor reject).
    NotAttempted,
    /// `Warden::spawn_child*` succeeded.
    Started,
    /// Spawn was attempted and returned an error.
    Failed,
}

impl SpawnStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAttempted => "not attempted",
            Self::Started => "started",
            Self::Failed => "failed",
        }
    }
}

/// One Auditor probe result. The report line for the set is `auditor: pass/fail`
/// and must never contain the word `warden`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditorProbe {
    pub name: &'static str,
    pub passed: bool,
    pub skipped: bool,
    pub detail: String,
}

impl AuditorProbe {
    pub(crate) fn pass(name: &'static str, detail: String) -> Self {
        Self {
            name,
            passed: true,
            skipped: false,
            detail,
        }
    }

    pub(crate) fn fail(name: &'static str, detail: String) -> Self {
        Self {
            name,
            passed: false,
            skipped: false,
            detail,
        }
    }

    pub(crate) fn skip(name: &'static str, detail: String) -> Self {
        Self {
            name,
            passed: false,
            skipped: true,
            detail,
        }
    }
}

/// Collected self-test evidence for a generated draft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfTestReport {
    pub auditor: AuditorVerdict,
    pub auditor_probes: Vec<AuditorProbe>,
    pub warden: WardenVerdict,
    pub warden_detail: String,
    pub spawn: SpawnStatus,
    pub spawn_detail: String,
    pub warden_policy_notes: String,
    pub verified: String,
    pub unverified: String,
}

impl SelfTestReport {
    pub fn exit(&self) -> SelfTestExit {
        match (self.auditor, self.warden) {
            (AuditorVerdict::Pass, WardenVerdict::Pass | WardenVerdict::Skipped) => {
                SelfTestExit::EvidenceOk
            }
            _ => SelfTestExit::Insufficient,
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.exit() as i32
    }

    /// Stderr report. The `auditor:` line never contains `warden`.
    pub fn format_stderr(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("auditor: {}\n", self.auditor.as_str()));
        for probe in &self.auditor_probes {
            let status = match (probe.skipped, probe.passed) {
                (true, _) => "skipped",
                (false, true) => "pass",
                (false, false) => "fail",
            };
            out.push_str(&format!("  {}: {status} ({})\n", probe.name, probe.detail));
        }
        out.push_str(&format!("warden: {}\n", self.warden.as_str()));
        if !self.warden_detail.is_empty() {
            out.push_str(&format!("  {}\n", self.warden_detail));
        }
        out.push_str(&format!(
            "  spawn: {} ({})\n",
            self.spawn.as_str(),
            if self.spawn_detail.is_empty() {
                match self.spawn {
                    SpawnStatus::Started => "child started",
                    SpawnStatus::Failed => "no detail",
                    SpawnStatus::NotAttempted => "not attempted",
                }
            } else {
                self.spawn_detail.as_str()
            }
        ));
        if !self.warden_policy_notes.is_empty() {
            out.push_str(&format!("  probe-policy: {}\n", self.warden_policy_notes));
        }
        out.push_str(&format!("verified: {}\n", self.verified));
        out.push_str(&format!("unverified: {}\n", self.unverified));
        out
    }
}

/// Failures that happen before evidence can be classified (generate/parse).
#[derive(Debug)]
pub enum SelfTestError {
    Parse(String),
    Io(io::Error),
}

impl std::fmt::Display for SelfTestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "failed to parse generated policy: {e}"),
            Self::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SelfTestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Parse(_) => None,
        }
    }
}

impl From<io::Error> for SelfTestError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// Write `draft_kdl` to a temp file, load it, collect Auditor + Warden evidence.
///
/// Spawn uses the `run` Warden path and a restricted environment (PATH + private
/// TMPDIR). Never `--unsafe-unsandboxed-discovery`.
pub async fn run_self_test(
    draft_kdl: &str,
    command: &[String],
    timeout: Duration,
) -> Result<SelfTestReport, SelfTestError> {
    let work = create_self_test_dir()?;
    let draft_path = work.join("draft.kdl");
    std::fs::write(&draft_path, draft_kdl)?;

    let policy = crate::policy::loader::load_policy(&draft_path)
        .and_then(|p| p.bind_to_server(None))
        .map_err(|e| SelfTestError::Parse(e.to_string()))?;

    let auditor_probes = evaluate_auditor_probes(&policy);
    let auditor = auditor_verdict(&auditor_probes);

    let tmpdir = work.join("tmp");
    std::fs::create_dir_all(&tmpdir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmpdir, std::fs::Permissions::from_mode(0o700));
    }

    let (warden, warden_detail, spawn, spawn_detail, warden_policy_notes) =
        collect_warden_evidence(&policy, command, &tmpdir, timeout).await;

    let (verified, unverified) = scope_text(
        auditor,
        &auditor_probes,
        warden,
        &warden_detail,
        spawn,
        &warden_policy_notes,
    );
    let _ = std::fs::remove_dir_all(&work);
    Ok(SelfTestReport {
        auditor,
        auditor_probes,
        warden,
        warden_detail,
        spawn,
        spawn_detail,
        warden_policy_notes,
        verified,
        unverified,
    })
}

fn create_self_test_dir() -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "mcp-writ-self-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

pub(crate) fn auditor_verdict(probes: &[AuditorProbe]) -> AuditorVerdict {
    let deny_ok = probes
        .iter()
        .any(|p| p.name == "deny-tool" && p.passed && !p.skipped);
    let all_ok = probes.iter().all(|p| p.skipped || p.passed);
    if deny_ok && all_ok {
        AuditorVerdict::Pass
    } else {
        AuditorVerdict::Fail
    }
}

fn scope_text(
    auditor: AuditorVerdict,
    probes: &[AuditorProbe],
    warden: WardenVerdict,
    warden_detail: &str,
    spawn: SpawnStatus,
    warden_policy_notes: &str,
) -> (String, String) {
    let mut verified = Vec::new();
    if auditor == AuditorVerdict::Pass {
        for p in probes {
            if p.passed {
                verified.push(format!("{} checker policy error", p.name));
            }
        }
    }
    match warden {
        WardenVerdict::Pass => verified.push(format!(
            "Linux SIGSYS OS-deny on {WARDEN_PROBE_PATH} ({warden_detail})"
        )),
        WardenVerdict::Skipped => {}
        WardenVerdict::Fail | WardenVerdict::Inconclusive => {}
    }

    let mut unverified = vec![
        "complete policy effectiveness (this is limited probe evidence)".to_string(),
        "Auditor probes are checker::check_request, not a live proxy observation".to_string(),
        "non-Linux OS-deny (Seatbelt / LPAC); SIGSYS is Linux-only".to_string(),
        "syscalls and paths not covered by the probes".to_string(),
        "TOCTOU between Auditor check and open (Warden's job at runtime)".to_string(),
        "RCE canaries (intentionally not implemented)".to_string(),
        "JSON-RPC EACCES/isError text from the child is not Warden evidence".to_string(),
    ];
    if spawn == SpawnStatus::Failed {
        unverified.insert(0, "server spawn failed".to_string());
    }
    if !warden_policy_notes.is_empty() {
        unverified.push(format!(
            "Warden probe used a diagnostic overlay, not the original draft ({warden_policy_notes})"
        ));
    }
    match warden {
        WardenVerdict::Skipped => {
            unverified.insert(0, "Warden OS-deny skipped on this OS".to_string());
        }
        WardenVerdict::Inconclusive => {
            unverified.insert(0, format!("Warden OS-deny inconclusive: {warden_detail}"));
        }
        WardenVerdict::Fail => {
            unverified.insert(0, format!("Warden OS-deny failed: {warden_detail}"));
        }
        WardenVerdict::Pass => {}
    }

    let verified = if verified.is_empty() {
        "(none)".to_string()
    } else {
        verified.join("; ")
    };
    (verified, unverified.join("; "))
}

/// Print the stderr report. Split so tests can inspect the string.
pub fn eprint_report(report: &SelfTestReport) {
    let text = report.format_stderr();
    let _ = io::stderr().write_all(text.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::kdl_loader::parse_kdl_policy;

    fn draft_with_read_file_schema() -> crate::policy::Policy {
        let kdl = r##"
            policy version=1
            defaults {
                filesystem {
                    secret-overlay #true
                }
            }
            server "auto-generated" {
                tool "read_file" side_effect="read_only" args_schema="{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}"
                tool "evil" deny=#true
            }
        "##;
        parse_kdl_policy(kdl).unwrap()
    }

    #[test]
    fn auditor_report_line_never_mentions_warden() {
        let policy = draft_with_read_file_schema();
        let probes = evaluate_auditor_probes(&policy);
        let report = SelfTestReport {
            auditor: auditor_verdict(&probes),
            auditor_probes: probes,
            warden: WardenVerdict::Skipped,
            warden_detail: String::new(),
            spawn: SpawnStatus::Started,
            spawn_detail: "child started".to_string(),
            warden_policy_notes: String::new(),
            verified: "deny-tool".to_string(),
            unverified: "OS-deny".to_string(),
        };
        let stderr = report.format_stderr();
        let auditor_line = stderr.lines().next().expect("auditor line");
        assert_eq!(auditor_line, "auditor: pass");
        assert!(
            !auditor_line.to_ascii_lowercase().contains("warden"),
            "{auditor_line}"
        );
        for probe in &report.auditor_probes {
            assert!(
                !probe.detail.to_ascii_lowercase().contains("warden"),
                "{}",
                probe.detail
            );
            assert!(
                !probe.name.to_ascii_lowercase().contains("warden"),
                "{}",
                probe.name
            );
        }
    }

    #[test]
    fn exit_codes_match_evidence() {
        let ok = SelfTestReport {
            auditor: AuditorVerdict::Pass,
            auditor_probes: vec![],
            warden: WardenVerdict::Pass,
            warden_detail: String::new(),
            spawn: SpawnStatus::Started,
            spawn_detail: String::new(),
            warden_policy_notes: String::new(),
            verified: String::new(),
            unverified: String::new(),
        };
        assert_eq!(ok.exit_code(), 0);

        let skipped = SelfTestReport {
            warden: WardenVerdict::Skipped,
            ..ok.clone()
        };
        assert_eq!(skipped.exit_code(), 0);

        let missing = SelfTestReport {
            warden: WardenVerdict::Inconclusive,
            ..ok
        };
        assert_eq!(missing.exit_code(), 2);
    }

    #[test]
    fn spawn_report_distinguishes_unattempted_from_failed() {
        let base = SelfTestReport {
            auditor: AuditorVerdict::Pass,
            auditor_probes: vec![],
            warden: WardenVerdict::Inconclusive,
            warden_detail: "no file-reading tool for control call".to_string(),
            spawn: SpawnStatus::NotAttempted,
            spawn_detail: "no file-reading tool for control call".to_string(),
            warden_policy_notes: String::new(),
            verified: String::new(),
            unverified: String::new(),
        };
        let skipped_spawn = base.format_stderr();
        assert!(
            skipped_spawn.contains("spawn: not attempted"),
            "{skipped_spawn}"
        );
        assert!(!skipped_spawn.contains("spawn: failed"), "{skipped_spawn}");
        let (_, unverified) = scope_text(
            AuditorVerdict::Pass,
            &[],
            WardenVerdict::Inconclusive,
            "no file-reading tool",
            SpawnStatus::NotAttempted,
            "",
        );
        assert!(!unverified.contains("server spawn failed"), "{unverified}");

        let failed = SelfTestReport {
            spawn: SpawnStatus::Failed,
            spawn_detail: "Warden spawn failed: os error".to_string(),
            ..base
        };
        let failed_stderr = failed.format_stderr();
        assert!(failed_stderr.contains("spawn: failed"), "{failed_stderr}");
        let (_, unverified) = scope_text(
            AuditorVerdict::Pass,
            &[],
            WardenVerdict::Inconclusive,
            "Warden spawn failed",
            SpawnStatus::Failed,
            "",
        );
        assert!(unverified.contains("server spawn failed"), "{unverified}");
    }

    #[test]
    fn parse_failure_is_self_test_error() {
        let err = parse_kdl_policy("not kdl")
            .err()
            .map(|e| SelfTestError::Parse(e.to_string()))
            .unwrap();
        assert!(matches!(err, SelfTestError::Parse(_)));
    }
}
