use std::path::{Component, Path};
use std::sync::LazyLock;

use regex_lite::Regex;

use super::heuristics::{Confidence, Permission};
use super::project_hints_node::analyze_node_project;
use super::project_hints_python::analyze_python_project;
use super::project_hints_shell::analyze_shell_project;
use super::source_bind::{PayloadKind, discover_from_argv};

pub use super::project_hints_python::parse_requirements_txt;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Detected project type based on manifest files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectType {
    NodeJs,
    Python,
    Shell,
    Unknown,
}

impl std::fmt::Display for ProjectType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NodeJs => write!(f, "nodejs"),
            Self::Python => write!(f, "python"),
            Self::Shell => write!(f, "shell"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

/// How the permission hint was discovered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintSource {
    /// Found in package.json / requirements.txt / pyproject.toml.
    DependencyList,
    /// Found via require/import in source code.
    SourceImport,
    /// Found as a command in a shell script.
    ShellCommand,
}

impl std::fmt::Display for HintSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DependencyList => write!(f, "dependency_list"),
            Self::SourceImport => write!(f, "source_import"),
            Self::ShellCommand => write!(f, "shell_command"),
        }
    }
}

/// A single permission hint discovered by static analysis.
#[derive(Debug, Clone)]
pub struct PermissionHint {
    pub permission: Permission,
    pub confidence: Confidence,
    pub source: HintSource,
    /// Human-readable evidence string.
    pub evidence: String,
}

/// Aggregated project analysis result.
#[derive(Debug, Clone)]
pub struct ProjectHint {
    pub project_type: ProjectType,
    pub detected_permissions: Vec<PermissionHint>,
    pub entry_points: Vec<String>,
    pub confidence_summary: Confidence,
}

// ─────────────────────────────────────────────────────────────────────────────
// Regex patterns (LazyLock following project convention)
// ─────────────────────────────────────────────────────────────────────────────

// Shell shebang pattern
static SHEBANG_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^#!\s*/(?:usr/(?:local/)?)?(?:bin/(?:env\s+)?)?(\w+)").expect("valid regex")
});

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Analyze a project directory and produce permission hints.
///
/// The analysis pipeline:
/// 1. Detect project type (package.json → Node, pyproject.toml → Python, shebang → Shell)
/// 2. Parse dependency files
/// 3. Map dependencies → permission hints via knowledge base
/// 4. Scan entry-point source files for dangerous imports/commands
/// 5. Return `ProjectHint`
pub fn analyze_project(project_dir: &Path) -> ProjectHint {
    let project_type = detect_project_type(project_dir);
    let mut hints = Vec::new();
    let mut entry_points = Vec::new();

    match project_type {
        ProjectType::NodeJs => {
            analyze_node_project(project_dir, &mut hints, &mut entry_points);
        }
        ProjectType::Python => {
            analyze_python_project(project_dir, &mut hints, &mut entry_points);
        }
        ProjectType::Shell => {
            analyze_shell_project(project_dir, &mut hints, &mut entry_points);
        }
        ProjectType::Unknown => {}
    }

    let confidence_summary = summarize_confidence(&hints);

    ProjectHint {
        project_type,
        detected_permissions: hints,
        entry_points,
        confidence_summary,
    }
}

/// Resolve the project directory for `generate-policy`.
///
/// Explicit `--project` wins. Otherwise the parent of the first payload
/// script (same payload rule as Verifier) is used. There is **no** CWD
/// fallback — a bare binary with no script yields `None` so we do not
/// mis-analyze an unrelated tree.
pub fn resolve_project_dir_for_policy(
    explicit: Option<&Path>,
    command: &[String],
) -> Option<std::path::PathBuf> {
    if let Some(dir) = explicit {
        return Some(dir.to_path_buf());
    }
    match discover_from_argv(command).kind {
        PayloadKind::Source { path, .. } => {
            let parent = path.parent()?;
            if parent.as_os_str().is_empty() {
                return Some(std::path::PathBuf::from("."));
            }
            Some(parent.to_path_buf())
        }
        PayloadKind::Native | PayloadKind::InlineEval { .. } | PayloadKind::Unresolved { .. } => {
            None
        }
    }
}

/// Format project hints as a human-readable string for CLI output.
pub fn format_project_hints(hint: &ProjectHint) -> String {
    let mut out = String::new();
    out.push_str("── Project Hints ──────────────────────────────────────\n");
    out.push_str(&format!("Project type: {}\n", hint.project_type));
    out.push_str(&format!("Confidence:   {}\n", hint.confidence_summary));

    if !hint.entry_points.is_empty() {
        out.push_str("\nEntry points:\n");
        for ep in &hint.entry_points {
            out.push_str(&format!("  {ep}\n"));
        }
    }

    if !hint.detected_permissions.is_empty() {
        out.push_str(&format!(
            "\nDetected permissions ({}):\n",
            hint.detected_permissions.len()
        ));
        for h in &hint.detected_permissions {
            out.push_str(&format!(
                "  [{:>6}] {:18} ({}) {}\n",
                h.confidence, h.permission, h.source, h.evidence
            ));
        }
    } else {
        out.push_str("\nNo permission hints detected.\n");
    }

    out
}

// ─────────────────────────────────────────────────────────────────────────────
// Project type detection
// ─────────────────────────────────────────────────────────────────────────────

fn detect_project_type(dir: &Path) -> ProjectType {
    if dir.join("package.json").exists() {
        ProjectType::NodeJs
    } else if dir.join("pyproject.toml").exists() || dir.join("requirements.txt").exists() {
        ProjectType::Python
    } else if has_shell_entry(dir) {
        ProjectType::Shell
    } else {
        ProjectType::Unknown
    }
}

/// Check if the directory contains a shell script entry point.
fn has_shell_entry(dir: &Path) -> bool {
    // Check common entry-point names
    for name in &["run.sh", "start.sh", "main.sh", "entrypoint.sh", "index.sh"] {
        let path = dir.join(name);
        if path.exists()
            && let Ok(content) = std::fs::read_to_string(&path)
            && let Some(first_line) = content.lines().next()
            && SHEBANG_RE.is_match(first_line)
        {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Push `candidate` onto `entry_points` only when it is a safe relative path
/// whose canonical form still resolves inside `dir` — rejects `..`,
/// absolute paths, and symlink escapes. A crafted manifest field (e.g.
/// package.json `main` or pyproject `[project.scripts]`) must not be able to
/// point the analysis outside the project tree. Rejections are logged at
/// debug level rather than silently dropped.
pub(crate) fn push_safe_entry_point(dir: &Path, candidate: &str, entry_points: &mut Vec<String>) {
    let is_safe_relative = Path::new(candidate)
        .components()
        .all(|c| matches!(c, Component::Normal(_) | Component::CurDir));
    if !is_safe_relative {
        tracing::debug!(path = %candidate, "entry point rejected: not a safe relative path");
        return;
    }
    let resolves_inside = dir.canonicalize().is_ok_and(|root| {
        dir.join(candidate)
            .canonicalize()
            .is_ok_and(|resolved| resolved.starts_with(root))
    });
    if resolves_inside {
        entry_points.push(candidate.to_string());
    } else {
        tracing::debug!(path = %candidate, "entry point rejected: does not resolve inside project dir");
    }
}

fn summarize_confidence(hints: &[PermissionHint]) -> Confidence {
    if hints.is_empty() {
        return Confidence::Low;
    }
    // Return the highest confidence found
    hints
        .iter()
        .map(|h| h.confidence)
        .max()
        .unwrap_or(Confidence::Low)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup_temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("create temp dir")
    }

    // ── Project type detection ─────────────────────────────────────────────

    #[test]
    fn test_detect_nodejs_project() {
        let dir = setup_temp_dir();
        fs::write(dir.path().join("package.json"), "{}").unwrap();
        assert_eq!(detect_project_type(dir.path()), ProjectType::NodeJs);
    }

    #[test]
    fn test_detect_python_project_pyproject() {
        let dir = setup_temp_dir();
        fs::write(dir.path().join("pyproject.toml"), "[project]\nname = \"x\"").unwrap();
        assert_eq!(detect_project_type(dir.path()), ProjectType::Python);
    }

    #[test]
    fn test_detect_python_project_requirements() {
        let dir = setup_temp_dir();
        fs::write(dir.path().join("requirements.txt"), "flask\n").unwrap();
        assert_eq!(detect_project_type(dir.path()), ProjectType::Python);
    }

    #[test]
    fn test_detect_shell_project() {
        let dir = setup_temp_dir();
        fs::write(dir.path().join("run.sh"), "#!/bin/bash\necho hi\n").unwrap();
        assert_eq!(detect_project_type(dir.path()), ProjectType::Shell);
    }

    #[test]
    fn test_detect_unknown_project() {
        let dir = setup_temp_dir();
        assert_eq!(detect_project_type(dir.path()), ProjectType::Unknown);
    }

    // ── Integration-style tests ────────────────────────────────────────────

    #[test]
    fn test_full_node_project_analysis() {
        let dir = setup_temp_dir();
        let pkg = r#"{
            "name": "mcp-filesystem-server",
            "main": "dist/index.js",
            "dependencies": {
                "express": "^4.18.0",
                "ws": "^8.0.0",
                "better-sqlite3": "^9.0.0"
            }
        }"#;
        let source = r#"
const express = require('express');
const { spawn } = require('child_process');
const fs = require('fs');
"#;
        fs::write(dir.path().join("package.json"), pkg).unwrap();
        fs::create_dir_all(dir.path().join("dist")).unwrap();
        fs::write(dir.path().join("dist/index.js"), source).unwrap();

        let result = analyze_project(dir.path());
        assert_eq!(result.project_type, ProjectType::NodeJs);
        assert!(!result.detected_permissions.is_empty());
        assert!(result.entry_points.contains(&"dist/index.js".to_string()));

        let perms: Vec<&Permission> = result
            .detected_permissions
            .iter()
            .map(|h| &h.permission)
            .collect();
        assert!(perms.contains(&&Permission::NetworkOutbound));
        assert!(perms.contains(&&Permission::DatabaseAccess));
        assert!(perms.contains(&&Permission::ProcessExec));
        assert!(perms.contains(&&Permission::FileRead));
    }

    #[test]
    fn test_full_shell_project_analysis() {
        let dir = setup_temp_dir();
        let script =
            "#!/bin/bash\ncurl https://api.example.com/data > /tmp/data.json\neval \"$COMMAND\"\n";
        fs::write(dir.path().join("run.sh"), script).unwrap();

        let result = analyze_project(dir.path());
        assert_eq!(result.project_type, ProjectType::Shell);
        assert!(result.entry_points.contains(&"run.sh".to_string()));

        let perms: Vec<&Permission> = result
            .detected_permissions
            .iter()
            .map(|h| &h.permission)
            .collect();
        assert!(perms.contains(&&Permission::NetworkOutbound));
        assert!(perms.contains(&&Permission::ProcessExec));
    }

    #[test]
    fn test_confidence_summary() {
        let hints = vec![
            PermissionHint {
                permission: Permission::FileRead,
                confidence: Confidence::Low,
                source: HintSource::DependencyList,
                evidence: "test".to_string(),
            },
            PermissionHint {
                permission: Permission::NetworkOutbound,
                confidence: Confidence::High,
                source: HintSource::DependencyList,
                evidence: "test".to_string(),
            },
        ];
        assert_eq!(summarize_confidence(&hints), Confidence::High);
    }

    #[test]
    fn test_confidence_summary_empty() {
        assert_eq!(summarize_confidence(&[]), Confidence::Low);
    }

    // ── push_safe_entry_point ──────────────────────────────────────────────

    #[test]
    fn test_push_safe_entry_point_accepts_relative() {
        let dir = setup_temp_dir();
        fs::create_dir_all(dir.path().join("src")).unwrap();
        fs::write(dir.path().join("src/index.js"), "// x").unwrap();

        let mut eps = Vec::new();
        push_safe_entry_point(dir.path(), "src/index.js", &mut eps);
        assert_eq!(eps, vec!["src/index.js".to_string()]);
    }

    #[test]
    fn test_push_safe_entry_point_rejects_parent_dir() {
        let dir = setup_temp_dir();
        let mut eps = Vec::new();
        push_safe_entry_point(dir.path(), "../outside.js", &mut eps);
        push_safe_entry_point(dir.path(), "a/../../outside.js", &mut eps);
        assert!(eps.is_empty());
    }

    #[test]
    fn test_push_safe_entry_point_rejects_absolute() {
        let dir = setup_temp_dir();
        let mut eps = Vec::new();
        push_safe_entry_point(dir.path(), "/etc/passwd", &mut eps);
        assert!(eps.is_empty());
    }

    #[test]
    fn test_push_safe_entry_point_rejects_missing_file() {
        let dir = setup_temp_dir();
        let mut eps = Vec::new();
        push_safe_entry_point(dir.path(), "does/not/exist.js", &mut eps);
        assert!(eps.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn test_push_safe_entry_point_rejects_symlink_escape() {
        let dir = setup_temp_dir();
        let outside = setup_temp_dir();
        fs::write(outside.path().join("evil.js"), "// evil").unwrap();
        std::os::unix::fs::symlink(outside.path().join("evil.js"), dir.path().join("link.js"))
            .unwrap();

        let mut eps = Vec::new();
        push_safe_entry_point(dir.path(), "link.js", &mut eps);
        assert!(eps.is_empty());
    }

    #[test]
    fn test_unknown_project_empty_hints() {
        let dir = setup_temp_dir();
        let result = analyze_project(dir.path());
        assert_eq!(result.project_type, ProjectType::Unknown);
        assert!(result.detected_permissions.is_empty());
        assert!(result.entry_points.is_empty());
    }

    #[test]
    fn test_resolve_project_dir_explicit_wins() {
        let resolved = resolve_project_dir_for_policy(
            Some(Path::new("/explicit/proj")),
            &["python".into(), "/other/server.py".into()],
        );
        assert_eq!(resolved, Some(std::path::PathBuf::from("/explicit/proj")));
    }

    #[test]
    fn test_resolve_project_dir_payload_parent() {
        let resolved = resolve_project_dir_for_policy(
            None,
            &["python".into(), "/tmp/myproj/server.py".into()],
        );
        assert_eq!(resolved, Some(std::path::PathBuf::from("/tmp/myproj")));
    }

    #[test]
    fn test_resolve_project_dir_no_cwd_fallback() {
        let resolved = resolve_project_dir_for_policy(None, &["echo".into(), "hello".into()]);
        assert!(
            resolved.is_none(),
            "subcommand argv must not use CWD, got {resolved:?}"
        );
        let native_serve =
            resolve_project_dir_for_policy(None, &["native-server".into(), "serve".into()]);
        assert!(
            native_serve.is_none(),
            "native-server serve must not use CWD, got {native_serve:?}"
        );
        let none = resolve_project_dir_for_policy(None, &["myserver".into()]);
        assert!(none.is_none(), "bare binary must not use CWD, got {none:?}");
    }
}
