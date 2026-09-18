use std::path::Path;
use std::sync::LazyLock;

use regex_lite::Regex;

use super::heuristics::{Confidence, Permission};
use super::project_hints::{HintSource, PermissionHint};

/// (command_pattern, permission, confidence, is_critical)
const SHELL_KNOWLEDGE_BASE: &[(&str, Permission, Confidence, bool)] = &[
    // Network
    ("curl", Permission::NetworkOutbound, Confidence::High, false),
    ("wget", Permission::NetworkOutbound, Confidence::High, false),
    ("nc", Permission::NetworkOutbound, Confidence::High, false),
    (
        "netcat",
        Permission::NetworkOutbound,
        Confidence::High,
        false,
    ),
    ("ssh", Permission::NetworkOutbound, Confidence::High, false),
    ("scp", Permission::NetworkOutbound, Confidence::High, false),
    (
        "rsync",
        Permission::NetworkOutbound,
        Confidence::High,
        false,
    ),
    (
        "dig",
        Permission::NetworkOutbound,
        Confidence::Medium,
        false,
    ),
    (
        "nslookup",
        Permission::NetworkOutbound,
        Confidence::Medium,
        false,
    ),
    ("ftp", Permission::NetworkOutbound, Confidence::High, false),
    ("sftp", Permission::NetworkOutbound, Confidence::High, false),
    (
        "socat",
        Permission::NetworkOutbound,
        Confidence::High,
        false,
    ),
    (
        "telnet",
        Permission::NetworkOutbound,
        Confidence::High,
        false,
    ),
    // File write
    ("rm", Permission::FileWrite, Confidence::High, false),
    ("mv", Permission::FileWrite, Confidence::High, false),
    ("cp", Permission::FileWrite, Confidence::High, false),
    ("chmod", Permission::FileWrite, Confidence::High, false),
    ("chown", Permission::FileWrite, Confidence::High, false),
    ("mkdir", Permission::FileWrite, Confidence::Medium, false),
    ("shred", Permission::FileWrite, Confidence::High, false),
    ("ln", Permission::FileWrite, Confidence::Medium, false),
    ("touch", Permission::FileWrite, Confidence::Low, false),
    ("tee", Permission::FileWrite, Confidence::Medium, false),
    // Process exec
    ("kill", Permission::ProcessExec, Confidence::High, false),
    ("pkill", Permission::ProcessExec, Confidence::High, false),
    ("nohup", Permission::ProcessExec, Confidence::High, false),
    ("crontab", Permission::ProcessExec, Confidence::High, false),
    (
        "systemctl",
        Permission::ProcessExec,
        Confidence::High,
        false,
    ),
    // Package managers (network + file write)
    ("apt", Permission::NetworkOutbound, Confidence::High, false),
    ("pip", Permission::NetworkOutbound, Confidence::High, false),
    ("npm", Permission::NetworkOutbound, Confidence::High, false),
    ("brew", Permission::NetworkOutbound, Confidence::High, false),
    (
        "cargo",
        Permission::NetworkOutbound,
        Confidence::High,
        false,
    ),
    // Containers
    ("docker", Permission::ProcessExec, Confidence::High, false),
    ("podman", Permission::ProcessExec, Confidence::High, false),
    ("kubectl", Permission::ProcessExec, Confidence::High, false),
    // Critical (code execution primitives)
    ("eval", Permission::ProcessExec, Confidence::High, true),
    ("exec", Permission::ProcessExec, Confidence::High, true),
];

// Shell pipe-to-interpreter patterns (critical)
static PIPE_EXEC_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|zsh|python|perl|ruby)").expect("valid regex")
});

// Shell command pattern: match command at start of line or after pipe/semicolon/&&/||
static SHELL_CMD_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|[|;&]\s*)(\w+)").expect("valid regex"));

pub(crate) fn analyze_shell_project(
    dir: &Path,
    hints: &mut Vec<PermissionHint>,
    entry_points: &mut Vec<String>,
) {
    let shell_files = ["run.sh", "start.sh", "main.sh", "entrypoint.sh", "index.sh"];

    for name in &shell_files {
        let path = dir.join(name);
        if path.exists() {
            entry_points.push(name.to_string());
            if let Ok(content) = std::fs::read_to_string(&path) {
                scan_shell_script(&content, hints);
            }
        }
    }
}

fn scan_shell_script(content: &str, hints: &mut Vec<PermissionHint>) {
    for (line_number, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Check for pipe-to-interpreter (critical, sanitized: no raw source in evidence)
        if PIPE_EXEC_RE.is_match(trimmed) {
            hints.push(PermissionHint {
                permission: Permission::ProcessExec,
                confidence: Confidence::High,
                source: HintSource::ShellCommand,
                evidence: format!(
                    "Critical: pipe-to-interpreter pattern at line {}",
                    line_number + 1
                ),
            });
            // Also add network hint for the download part
            hints.push(PermissionHint {
                permission: Permission::NetworkOutbound,
                confidence: Confidence::High,
                source: HintSource::ShellCommand,
                evidence: format!(
                    "Critical: pipe-to-interpreter pattern at line {}",
                    line_number + 1
                ),
            });
            continue;
        }

        // Extract commands from line
        for cap in SHELL_CMD_RE.captures_iter(trimmed) {
            if let Some(m) = cap.get(1) {
                let cmd = m.as_str();
                lookup_shell_knowledge_base(cmd, line_number + 1, hints);
            }
        }
    }
}

fn lookup_shell_knowledge_base(cmd: &str, line_number: usize, hints: &mut Vec<PermissionHint>) {
    for &(pattern, ref perm, conf, is_critical) in SHELL_KNOWLEDGE_BASE {
        if cmd == pattern {
            let evidence = if is_critical {
                format!("Critical shell command: {cmd} at line {line_number}")
            } else {
                format!("Shell command: {cmd} at line {line_number}")
            };
            hints.push(PermissionHint {
                permission: perm.clone(),
                confidence: conf,
                source: HintSource::ShellCommand,
                evidence,
            });

            // Package managers also imply FileWrite
            if matches!(
                cmd,
                "apt" | "pip" | "npm" | "brew" | "cargo" | "docker" | "podman" | "kubectl"
            ) {
                hints.push(PermissionHint {
                    permission: Permission::FileWrite,
                    confidence: Confidence::Medium,
                    source: HintSource::ShellCommand,
                    evidence: format!(
                        "Shell command (file side-effect): {cmd} at line {line_number}"
                    ),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_curl_pipe_bash_critical() {
        let mut hints = Vec::new();
        let script = "#!/bin/bash\ncurl https://example.com/install.sh | bash\n";
        scan_shell_script(script, &mut hints);

        let has_critical_exec = hints
            .iter()
            .any(|h| h.permission == Permission::ProcessExec && h.evidence.contains("Critical"));
        assert!(
            has_critical_exec,
            "curl|bash should produce Critical ProcessExec"
        );

        let has_network = hints
            .iter()
            .any(|h| h.permission == Permission::NetworkOutbound);
        assert!(has_network, "curl|bash should also produce NetworkOutbound");
    }

    #[test]
    fn test_shell_wget_pipe_sh() {
        let mut hints = Vec::new();
        let script = "#!/bin/bash\nwget -O- https://example.com/setup | sh\n";
        scan_shell_script(script, &mut hints);

        let has_critical = hints
            .iter()
            .any(|h| h.permission == Permission::ProcessExec && h.evidence.contains("Critical"));
        assert!(has_critical, "wget|sh should produce Critical ProcessExec");
    }

    #[test]
    fn test_shell_comments_ignored() {
        let mut hints = Vec::new();
        let script = "#!/bin/bash\n# curl https://example.com | bash\n# rm -rf /\necho hello\n";
        scan_shell_script(script, &mut hints);

        // Comments should be skipped, only 'echo' remains (not in knowledge base)
        assert!(
            hints.is_empty(),
            "Comments should be ignored, got {} hints",
            hints.len()
        );
    }

    #[test]
    fn test_shell_command_detection() {
        let mut hints = Vec::new();
        let script =
            "#!/bin/bash\ncurl https://api.example.com/data\nrm -rf /tmp/cache\nkill -9 1234\n";
        scan_shell_script(script, &mut hints);

        let perms: Vec<&Permission> = hints.iter().map(|h| &h.permission).collect();
        assert!(perms.contains(&&Permission::NetworkOutbound));
        assert!(perms.contains(&&Permission::FileWrite));
        assert!(perms.contains(&&Permission::ProcessExec));
    }

    #[test]
    fn test_shell_evidence_includes_line_number() {
        let mut hints = Vec::new();
        // Multi-line script with curl|bash on line 3
        let script = "#!/bin/bash\necho hello\ncurl https://example.com/install.sh | bash\n";
        scan_shell_script(script, &mut hints);

        // Find the critical hint produced by curl|bash
        let critical_hint = hints
            .iter()
            .find(|h| h.permission == Permission::ProcessExec && h.evidence.contains("Critical"));
        assert!(
            critical_hint.is_some(),
            "Should have critical ProcessExec hint"
        );
        // Assert that evidence contains the correct line number (line 3)
        let hint = critical_hint.unwrap();
        assert!(
            hint.evidence.contains("line 3"),
            "Evidence should contain 'line 3', got: {}",
            hint.evidence
        );
    }

    #[test]
    fn test_shell_package_managers_dual_permission() {
        let mut hints = Vec::new();
        let script = "#!/bin/bash\nnpm install express\n";
        scan_shell_script(script, &mut hints);

        let perms: Vec<&Permission> = hints.iter().map(|h| &h.permission).collect();
        assert!(
            perms.contains(&&Permission::NetworkOutbound),
            "npm should imply NetworkOutbound"
        );
        assert!(
            perms.contains(&&Permission::FileWrite),
            "npm should imply FileWrite"
        );
    }
}
