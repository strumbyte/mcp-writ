use std::fmt;
use std::path::PathBuf;

use crate::legislator::project_hints::ProjectHint;

/// Successful outcome of a wrap-image / containerize execution.
///
/// Execution code returns this instead of a display string; the
/// `Display` impl is the thin presenter that produces the exact text
/// historically printed to stdout.
#[derive(Debug)]
pub enum BuildOutcome {
    /// An image was built; carries the output image tag.
    Built { tag: String },
    /// `--output-dockerfile` wrote the Dockerfile without building.
    DockerfileWritten { path: PathBuf },
}

impl fmt::Display for BuildOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Built { tag } => write!(f, "{tag}"),
            Self::DockerfileWritten { path } => {
                write!(f, "Dockerfile written to {}", path.display())
            }
        }
    }
}

/// Format project permission hints for stderr.
///
/// Returns an empty string when no permissions were detected, in which
/// case the caller must not print anything. The output is advisory only.
pub fn format_project_hints_stderr(hint: &ProjectHint) -> String {
    if hint.detected_permissions.is_empty() {
        return String::new();
    }
    let mut out = format!(
        "[project-hints] {} project, {} permission(s) detected\n",
        hint.project_type,
        hint.detected_permissions.len()
    );
    for h in &hint.detected_permissions {
        out.push_str(&format!(
            "  [{:>6}] {} — {}\n",
            h.confidence,
            h.permission,
            crate::termutil::sanitize_for_terminal(&h.evidence)
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_outcome_display() {
        assert_eq!(
            BuildOutcome::Built {
                tag: "my-image-secured:latest".to_string()
            }
            .to_string(),
            "my-image-secured:latest"
        );
        assert_eq!(
            BuildOutcome::DockerfileWritten {
                path: PathBuf::from("out/Dockerfile")
            }
            .to_string(),
            "Dockerfile written to out/Dockerfile"
        );
    }

    #[test]
    fn test_format_project_hints_stderr_empty() {
        let hint = ProjectHint {
            project_type: crate::legislator::project_hints::ProjectType::Unknown,
            detected_permissions: vec![],
            entry_points: vec![],
            confidence_summary: crate::legislator::heuristics::Confidence::Low,
        };
        assert_eq!(format_project_hints_stderr(&hint), "");
    }
}
