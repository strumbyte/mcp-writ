use crate::inspector::elf_parser::SymbolProfile;
use crate::inspector::slicer::ResolvedSyscall;
use crate::inspector::strings::StringFindings;

/// High-risk syscall names that indicate process execution capability.
pub(super) const PROCESS_SYSCALLS: &[&str] =
    &["execve", "execveat", "fork", "vfork", "clone", "clone3"];

/// Syscall names that indicate network capability.
const NETWORK_SYSCALLS: &[&str] = &["socket", "connect", "bind", "listen", "accept", "accept4"];

/// Returns `true` if the symbol profile contains Go or Rust syscall wrapper imports.
fn has_syscall_wrapper(symbols: &SymbolProfile) -> bool {
    symbols
        .imports
        .iter()
        .any(|i| i.name.contains("runtime.Syscall") || i.name.contains("syscall::syscall"))
}

pub(super) fn compute_risk_score(
    symbols: &SymbolProfile,
    syscalls: &[ResolvedSyscall],
    findings: &StringFindings,
) -> u32 {
    let mut score: u32 = 0;

    // execve/fork/clone syscall detected: +30
    if syscalls.iter().any(|s| {
        s.syscall_name
            .as_deref()
            .is_some_and(|n| PROCESS_SYSCALLS.contains(&n))
    }) {
        score += 30;
    }

    // socket/connect syscall detected: +20
    if syscalls.iter().any(|s| {
        s.syscall_name
            .as_deref()
            .is_some_and(|n| NETWORK_SYSCALLS.contains(&n))
    }) {
        score += 20;
    }

    // Network symbol imports: +15
    if symbols.risk_flags.network {
        score += 15;
    }

    // Process symbol imports: +15
    if symbols.risk_flags.process {
        score += 15;
    }

    // Crypto symbol imports: +5
    if symbols.risk_flags.crypto {
        score += 5;
    }

    // External URL detected: +10
    if !findings.urls.is_empty() {
        score += 10;
    }

    // Environment variable reference detected: +5
    if !findings.env_vars.is_empty() {
        score += 5;
    }

    // /etc/ path reference: +10
    if findings.paths.iter().any(|p| p.starts_with("/etc/")) {
        score += 10;
    }

    // /home/ path reference: +5
    if findings.paths.iter().any(|p| p.starts_with("/home/")) {
        score += 5;
    }

    // Stripped binary: +10
    if symbols.is_stripped {
        score += 10;
    }

    // Go/Rust syscall wrapper detection: +5
    if has_syscall_wrapper(symbols) {
        score += 5;
    }

    score.min(100)
}

pub(super) fn risk_level(score: u32) -> &'static str {
    match score {
        0..=25 => "Low",
        26..=50 => "Medium",
        51..=75 => "High",
        _ => "Critical",
    }
}

pub(super) fn build_risk_summary(
    symbols: &SymbolProfile,
    syscalls: &[ResolvedSyscall],
    findings: &StringFindings,
) -> Vec<String> {
    let mut summary = Vec::new();

    // Process execution
    let process_names: Vec<&str> = syscalls
        .iter()
        .filter_map(|s| s.syscall_name.as_deref())
        .filter(|n| PROCESS_SYSCALLS.contains(n))
        .collect();
    if !process_names.is_empty() {
        summary.push(format!(
            "Process execution capability detected ({})",
            process_names.join(", ")
        ));
    }

    // Network access
    let net_names: Vec<&str> = syscalls
        .iter()
        .filter_map(|s| s.syscall_name.as_deref())
        .filter(|n| NETWORK_SYSCALLS.contains(n))
        .collect();
    if !net_names.is_empty() {
        summary.push(format!(
            "Network access capability detected ({})",
            net_names.join(", ")
        ));
    }

    // Sensitive file paths
    let sensitive: Vec<&str> = findings
        .paths
        .iter()
        .filter(|p| p.starts_with("/etc/") || p.starts_with("/home/"))
        .map(String::as_str)
        .collect();
    if !sensitive.is_empty() {
        summary.push(format!(
            "Sensitive file paths referenced ({})",
            sensitive.join(", ")
        ));
    }

    // Crypto
    if symbols.risk_flags.crypto {
        summary.push("Cryptographic library usage detected".to_string());
    }

    // Stripped binary
    if symbols.is_stripped {
        summary.push("Binary is stripped (reduced analysis visibility)".to_string());
    }

    // Go/Rust syscall wrappers
    if has_syscall_wrapper(symbols) {
        summary.push("Go/Rust syscall wrapper detected".to_string());
    }

    // URLs
    if !findings.urls.is_empty() {
        summary.push(format!(
            "External URLs detected ({})",
            findings.urls.join(", ")
        ));
    }

    // Environment variables
    if !findings.env_vars.is_empty() {
        summary.push(format!(
            "Environment variable references detected ({})",
            findings.env_vars.join(", ")
        ));
    }

    summary
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inspector::elf_parser::RiskCategory;
    use crate::inspector::profile::test_support::make_profile;
    use crate::inspector::slicer::Resolution;

    // ---- Risk score tests ----

    #[test]
    fn test_risk_score_empty_profile() {
        let profile = make_profile(vec![], vec![], vec![], vec![], vec![], vec![], false);
        assert_eq!(profile.risk_score, 0);
    }

    #[test]
    fn test_risk_score_execve_syscall() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![(0x1000, Some(59), Some("execve"), Resolution::Resolved)],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 30);
    }

    #[test]
    fn test_risk_score_socket_syscall() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![(0x1000, Some(41), Some("socket"), Resolution::Resolved)],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 20);
    }

    #[test]
    fn test_risk_score_network_imports() {
        let profile = make_profile(
            vec![],
            vec![("socket", RiskCategory::Network)],
            vec![],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 15);
    }

    #[test]
    fn test_risk_score_process_imports() {
        let profile = make_profile(
            vec![],
            vec![("execve", RiskCategory::Process)],
            vec![],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 15);
    }

    #[test]
    fn test_risk_score_crypto_imports() {
        let profile = make_profile(
            vec![],
            vec![("SSL_connect", RiskCategory::Crypto)],
            vec![],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 5);
    }

    #[test]
    fn test_risk_score_urls() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![],
            vec!["https://evil.com"],
            vec![],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 10);
    }

    #[test]
    fn test_risk_score_env_vars() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["API_KEY"],
            false,
        );
        assert_eq!(profile.risk_score, 5);
    }

    #[test]
    fn test_risk_score_etc_path() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["/etc/passwd"],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 10);
    }

    #[test]
    fn test_risk_score_home_path() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["/home/user/.ssh/id_rsa"],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 5);
    }

    #[test]
    fn test_risk_score_stripped() {
        let profile = make_profile(vec![], vec![], vec![], vec![], vec![], vec![], true);
        assert_eq!(profile.risk_score, 10);
    }

    #[test]
    fn test_risk_score_capped_at_100() {
        // Combine everything to exceed 100
        let profile = make_profile(
            vec!["libc.so.6"],
            vec![
                ("socket", RiskCategory::Network),
                ("execve", RiskCategory::Process),
                ("SSL_connect", RiskCategory::Crypto),
            ],
            vec![
                (0x1000, Some(59), Some("execve"), Resolution::Resolved),
                (0x2000, Some(41), Some("socket"), Resolution::Resolved),
            ],
            vec!["https://evil.com"],
            vec!["/etc/passwd", "/home/user/data"],
            vec!["SECRET_KEY"],
            true,
        );
        assert!(profile.risk_score <= 100);
        // 30 + 20 + 15 + 15 + 5 + 10 + 5 + 10 + 5 + 10 = 125 → capped to 100
        assert_eq!(profile.risk_score, 100);
    }

    #[test]
    fn test_risk_score_go_wrapper() {
        let profile = make_profile(
            vec![],
            vec![("runtime.Syscall", RiskCategory::Safe)],
            vec![],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert_eq!(profile.risk_score, 5);
    }

    #[test]
    fn test_risk_level_low() {
        assert_eq!(risk_level(0), "Low");
        assert_eq!(risk_level(25), "Low");
    }

    #[test]
    fn test_risk_level_medium() {
        assert_eq!(risk_level(26), "Medium");
        assert_eq!(risk_level(50), "Medium");
    }

    #[test]
    fn test_risk_level_high() {
        assert_eq!(risk_level(51), "High");
        assert_eq!(risk_level(75), "High");
    }

    #[test]
    fn test_risk_level_critical() {
        assert_eq!(risk_level(76), "Critical");
        assert_eq!(risk_level(100), "Critical");
    }

    // ---- Risk summary tests ----

    #[test]
    fn test_risk_summary_process_execution() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![(0x1000, Some(59), Some("execve"), Resolution::Resolved)],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert!(
            profile
                .risk_summary
                .iter()
                .any(|s| s.contains("Process execution capability"))
        );
    }

    #[test]
    fn test_risk_summary_network_access() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![(0x1000, Some(41), Some("socket"), Resolution::Resolved)],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert!(
            profile
                .risk_summary
                .iter()
                .any(|s| s.contains("Network access capability"))
        );
    }

    #[test]
    fn test_risk_summary_sensitive_paths() {
        let profile = make_profile(
            vec![],
            vec![],
            vec![],
            vec![],
            vec!["/etc/passwd"],
            vec![],
            false,
        );
        assert!(
            profile
                .risk_summary
                .iter()
                .any(|s| s.contains("Sensitive file paths"))
        );
    }

    #[test]
    fn test_risk_summary_stripped() {
        let profile = make_profile(vec![], vec![], vec![], vec![], vec![], vec![], true);
        assert!(profile.risk_summary.iter().any(|s| s.contains("stripped")));
    }

    #[test]
    fn test_risk_summary_empty() {
        let profile = make_profile(vec![], vec![], vec![], vec![], vec![], vec![], false);
        assert!(profile.risk_summary.is_empty());
    }

    #[test]
    fn test_risk_summary_go_wrapper() {
        let profile = make_profile(
            vec![],
            vec![("runtime.Syscall", RiskCategory::Safe)],
            vec![],
            vec![],
            vec![],
            vec![],
            false,
        );
        assert!(
            profile
                .risk_summary
                .iter()
                .any(|s| s.contains("Go/Rust syscall wrapper"))
        );
    }
}
