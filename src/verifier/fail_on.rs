//! Run-time CC abort threshold (`--fail-on` / `MCP_WRIT_FAIL_ON`).
//!
//! Rule-intrinsic `ManifestFinding.blocking` is unchanged. This dial only
//! decides whether a finding aborts `run`.

use super::manifest::ManifestSeverity;

/// Environment variable that sets the dial when `--fail-on` is omitted.
pub const FAIL_ON_ENV: &str = "MCP_WRIT_FAIL_ON";

/// Startup stderr warning for `fail-on none`. Must not be readable as “abort”.
pub const NONE_STARTUP_WARNING: &str = "Warning: fail-on none never aborts on CC findings (Critical/High are audited only). This is dangerous.";

/// Minimum CC severity that aborts `mcp-writ run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailOn {
    /// Today's default: Critical and High abort; Medium is observed.
    High,
    /// Only Critical aborts. Every High finding is warn/audit (`observed`).
    Critical,
    /// Never abort on CC findings. Critical and High are audited only.
    None,
}

impl FailOn {
    /// Omitted CLI and empty/unset env resolve here.
    pub const DEFAULT: Self = Self::High;

    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Critical => "critical",
            Self::None => "none",
        }
    }

    /// Parse an exact `high|critical|none` token. Unknown values fail closed.
    pub fn parse(raw: &str) -> Result<Self, FailOnParseError> {
        match raw {
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            "none" => Ok(Self::None),
            other => Err(FailOnParseError {
                value: other.to_string(),
            }),
        }
    }

    /// Precedence: CLI > env > default `high`. Empty env is unset.
    pub fn resolve(cli: Option<&str>, env: Option<&str>) -> Result<Self, FailOnParseError> {
        if let Some(raw) = cli {
            return Self::parse(raw);
        }
        match env {
            None | Some("") => Ok(Self::DEFAULT),
            Some(raw) => Self::parse(raw),
        }
    }

    /// Resolve using the process environment (`MCP_WRIT_FAIL_ON`).
    pub fn resolve_from_process_env(cli: Option<&str>) -> Result<Self, FailOnParseError> {
        match std::env::var(FAIL_ON_ENV) {
            Ok(value) => Self::resolve(cli, Some(&value)),
            Err(std::env::VarError::NotPresent) => Self::resolve(cli, None),
            Err(std::env::VarError::NotUnicode(_)) => Err(FailOnParseError {
                value: "<non-utf8>".to_string(),
            }),
        }
    }

    /// Whether this severity aborts `run` under the dial.
    pub fn effective_blocks(self, severity: ManifestSeverity) -> bool {
        match self {
            Self::High => {
                matches!(
                    severity,
                    ManifestSeverity::Critical | ManifestSeverity::High
                )
            }
            Self::Critical => matches!(severity, ManifestSeverity::Critical),
            Self::None => false,
        }
    }

    /// Rule-intrinsic blocking that the dial demotes to observe.
    pub fn demotes(self, rule_blocking: bool, severity: ManifestSeverity) -> bool {
        rule_blocking && !self.effective_blocks(severity)
    }

    pub fn effective_action(self, severity: ManifestSeverity) -> &'static str {
        if self.effective_blocks(severity) {
            "denied"
        } else {
            "observed"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailOnParseError {
    pub value: String,
}

impl std::fmt::Display for FailOnParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid fail-on value '{}'; expected high, critical, or none",
            self.value
        )
    }
}

impl std::error::Error for FailOnParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_only_locked_tokens() {
        assert_eq!(FailOn::parse("high").unwrap(), FailOn::High);
        assert_eq!(FailOn::parse("critical").unwrap(), FailOn::Critical);
        assert_eq!(FailOn::parse("none").unwrap(), FailOn::None);
        for bad in ["medium", "low", "HIGH", "Critical", " ", "true", ""] {
            assert!(FailOn::parse(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn resolve_precedence_cli_over_env_over_default() {
        assert_eq!(FailOn::resolve(None, None).unwrap(), FailOn::High);
        assert_eq!(FailOn::resolve(None, Some("")).unwrap(), FailOn::High);
        assert_eq!(
            FailOn::resolve(None, Some("critical")).unwrap(),
            FailOn::Critical
        );
        assert_eq!(
            FailOn::resolve(Some("high"), Some("none")).unwrap(),
            FailOn::High
        );
        assert_eq!(
            FailOn::resolve(Some("none"), Some("high")).unwrap(),
            FailOn::None
        );
        assert!(FailOn::resolve(None, Some("medium")).is_err());
        assert!(FailOn::resolve(Some("medium"), Some("high")).is_err());
    }

    #[test]
    fn effective_blocks_matches_locked_matrix() {
        assert!(FailOn::High.effective_blocks(ManifestSeverity::Critical));
        assert!(FailOn::High.effective_blocks(ManifestSeverity::High));
        assert!(!FailOn::High.effective_blocks(ManifestSeverity::Medium));

        assert!(FailOn::Critical.effective_blocks(ManifestSeverity::Critical));
        assert!(!FailOn::Critical.effective_blocks(ManifestSeverity::High));
        assert!(!FailOn::Critical.effective_blocks(ManifestSeverity::Medium));

        assert!(!FailOn::None.effective_blocks(ManifestSeverity::Critical));
        assert!(!FailOn::None.effective_blocks(ManifestSeverity::High));
        assert!(!FailOn::None.effective_blocks(ManifestSeverity::Medium));
    }

    #[test]
    fn demotes_high_and_none_critical_only() {
        assert!(FailOn::Critical.demotes(true, ManifestSeverity::High));
        assert!(!FailOn::Critical.demotes(true, ManifestSeverity::Critical));
        assert!(FailOn::None.demotes(true, ManifestSeverity::Critical));
        assert!(FailOn::None.demotes(true, ManifestSeverity::High));
        assert!(!FailOn::High.demotes(true, ManifestSeverity::High));
        assert!(!FailOn::High.demotes(false, ManifestSeverity::Medium));
    }
}
