//! IronContext CC-001〜015 detectors for `tools/list` manifests.
//!
//! CC-001〜010 follow IronContext `docs/RULES.md` (May 2026 CVE pack) with the
//! approved surface expansions (title / annotations / outputSchema / `_meta`,
//! HTML-comment CC-001, U+2060–206F in CC-002, CC-007 property-key match).
//! CC-011〜015 are the approved product expansion. Further IDs need a written
//! proposal and review. Severities are not raised or lowered. Critical / High
//! findings are `blocking`; Medium findings are warnings only.

use uuid::Uuid;

use crate::audit_log::{Action, AuditEvent, AuditLogger, EventType, Outcome, Severity};
use crate::tool_def::ToolDefinition;
use crate::verifier::fail_on::FailOn;
use crate::verifier::manifest_rules::{
    detect_cc001, detect_cc002, detect_cc003, detect_cc004, detect_cc005, detect_cc006,
    detect_cc007, detect_cc008, detect_cc009, detect_cc010, detect_cc011, detect_cc012,
    detect_cc013, detect_cc014, detect_cc015,
};

/// Product rule identifiers. The current set is CC-001–015. New IDs need a
/// written proposal and review; do not invent extras in-tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestRule {
    Cc001,
    Cc002,
    Cc003,
    Cc004,
    Cc005,
    Cc006,
    Cc007,
    Cc008,
    Cc009,
    Cc010,
    Cc011,
    Cc012,
    Cc013,
    Cc014,
    Cc015,
}

impl ManifestRule {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cc001 => "CC-001",
            Self::Cc002 => "CC-002",
            Self::Cc003 => "CC-003",
            Self::Cc004 => "CC-004",
            Self::Cc005 => "CC-005",
            Self::Cc006 => "CC-006",
            Self::Cc007 => "CC-007",
            Self::Cc008 => "CC-008",
            Self::Cc009 => "CC-009",
            Self::Cc010 => "CC-010",
            Self::Cc011 => "CC-011",
            Self::Cc012 => "CC-012",
            Self::Cc013 => "CC-013",
            Self::Cc014 => "CC-014",
            Self::Cc015 => "CC-015",
        }
    }
}

/// IronContext severity. Critical / High block `run`; Medium does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestSeverity {
    Critical,
    High,
    Medium,
}

impl ManifestSeverity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
        }
    }

    pub fn is_blocking(self) -> bool {
        match self {
            Self::Critical | Self::High => true,
            Self::Medium => false,
        }
    }

    fn audit_severity(self) -> Severity {
        match self {
            Self::Critical => Severity::Critical,
            Self::High => Severity::High,
            Self::Medium => Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestFinding {
    pub rule: ManifestRule,
    pub severity: ManifestSeverity,
    pub tool_name: String,
    pub detail: String,
    pub blocking: bool,
}

/// Caps on attacker-controlled strings rendered from a finding —
/// findings are duplicated into audit records and the blocking-reason
/// message, so a manifest could otherwise amplify one bad input into
/// unbounded diagnostic output. The caps apply to display only: the
/// stored `tool_name` is the complete identifier `findings_by_tool` and
/// `tool_has_blocking` match against — truncating it would orphan the
/// finding from the tool it names.
const MAX_FINDING_NAME_CHARS: usize = 160;
const MAX_FINDING_DETAIL_CHARS: usize = 512;

fn bound_finding_text(text: String, cap: usize) -> String {
    if text.chars().count() <= cap {
        return text;
    }
    text.chars().take(cap).collect()
}

impl ManifestFinding {
    pub(crate) fn new(
        rule: ManifestRule,
        severity: ManifestSeverity,
        tool_name: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            rule,
            severity,
            tool_name: tool_name.into(),
            detail: bound_finding_text(detail.into(), MAX_FINDING_DETAIL_CHARS),
            blocking: severity.is_blocking(),
        }
    }
}

/// Scan every tool in a (pagination-assembled) `tools/list` set.
pub fn scan_manifest(tools: &[ToolDefinition]) -> Vec<ManifestFinding> {
    let mut findings = Vec::new();
    for tool in tools {
        for finding in [
            detect_cc001(tool),
            detect_cc002(tool),
            detect_cc003(tool),
            detect_cc004(tool),
            detect_cc005(tool),
            detect_cc006(tool),
            detect_cc007(tool),
            detect_cc008(tool),
            detect_cc009(tool),
            detect_cc010(tool),
            detect_cc011(tool),
            detect_cc013(tool),
            detect_cc014(tool),
            detect_cc015(tool),
        ]
        .into_iter()
        .flatten()
        {
            findings.push(finding);
        }
    }
    findings.extend(detect_cc012(tools));
    findings
}

/// Human-readable abort reason for findings that effectively block under the default dial.
pub fn format_blocking_reason(findings: &[ManifestFinding]) -> Option<String> {
    format_blocking_reason_for(findings, FailOn::DEFAULT)
}

/// Human-readable abort reason for findings that effectively block under `fail_on`.
pub fn format_blocking_reason_for(findings: &[ManifestFinding], fail_on: FailOn) -> Option<String> {
    let blocking: Vec<&ManifestFinding> = findings
        .iter()
        .filter(|f| fail_on.effective_blocks(f.severity))
        .collect();
    if blocking.is_empty() {
        return None;
    }
    let mut out = String::from("manifest scan blocked:");
    const MAX_REPORTED: usize = 8;
    for f in blocking.iter().take(MAX_REPORTED) {
        out.push_str(&format!(
            " {} ({}) on tool \"{}\" — {}",
            f.rule.as_str(),
            f.severity.as_str(),
            bound_finding_text(f.tool_name.clone(), MAX_FINDING_NAME_CHARS),
            f.detail
        ));
    }
    if blocking.len() > MAX_REPORTED {
        out.push_str(&format!(
            "; and {} more findings",
            blocking.len() - MAX_REPORTED
        ));
    }
    Some(out)
}

/// First-seen decision for `run` at the default `--fail-on high` threshold.
pub fn first_seen_blocks(tools: &[ToolDefinition]) -> Option<String> {
    first_seen_blocks_for(tools, FailOn::DEFAULT)
}

/// First-seen decision for `run`. RIS is never consulted.
pub fn first_seen_blocks_for(tools: &[ToolDefinition], fail_on: FailOn) -> Option<String> {
    format_blocking_reason_for(&scan_manifest(tools), fail_on)
}

/// Audit every finding at the default `--fail-on high` threshold.
///
/// `server_name` is the resolved upstream identity; `None` records no
/// `target_server` rather than a synthetic placeholder.
pub fn log_manifest_scan(
    server_name: Option<&str>,
    findings: &[ManifestFinding],
    audit_logger: &AuditLogger,
) {
    log_manifest_scan_for(server_name, findings, audit_logger, FailOn::DEFAULT);
}

/// Audit every finding. `blocking=` stays rule-intrinsic; action/outcome follow the dial.
///
/// `server_name` is the resolved upstream identity; `None` records no
/// `target_server` rather than a synthetic placeholder.
pub fn log_manifest_scan_for(
    server_name: Option<&str>,
    findings: &[ManifestFinding],
    audit_logger: &AuditLogger,
    fail_on: FailOn,
) {
    for finding in findings {
        let effective_blocks = fail_on.effective_blocks(finding.severity);
        let demoted = fail_on.demotes(finding.blocking, finding.severity);
        let correlation_id = Uuid::now_v7();
        let mut evt = AuditEvent::new(
            correlation_id,
            EventType::ManifestFinding,
            finding.severity.audit_severity(),
            if effective_blocks {
                Outcome::Failure
            } else {
                Outcome::Success
            },
            if effective_blocks {
                Action::Denied
            } else {
                Action::Observed
            },
        );
        evt.target_server = server_name.map(str::to_string);
        evt.target_tool = Some(finding.tool_name.clone());
        evt.details = Some(if demoted {
            format!(
                "{} {} blocking={} effective_blocking=false effective_action={} fail_on={} {}",
                finding.rule.as_str(),
                finding.severity.as_str(),
                finding.blocking,
                fail_on.effective_action(finding.severity),
                fail_on.as_str(),
                finding.detail
            )
        } else {
            format!(
                "{} {} blocking={} {}",
                finding.rule.as_str(),
                finding.severity.as_str(),
                finding.blocking,
                finding.detail
            )
        });
        audit_logger.log(evt);
    }
}

#[cfg(test)]
mod tests;
