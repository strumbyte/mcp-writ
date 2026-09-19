//! macOS sandbox implementation using `sandbox-exec` and SBPL.
//!
//! Generates deny-default SBPL profiles from the existing [`Policy`] struct
//! and spawns child processes via `sandbox-exec -p <profile> -- <command>`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

#[cfg(unix)]
use libc::{SIGKILL, kill as libc_kill};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::error::WardenError;
use crate::policy::Policy;

fn is_local_hostname(name: &str) -> bool {
    name == "localhost" || name == "*" || name == "127.0.0.1" || name == "[::1]" || name == "::1"
}

/// Extract a port number from a host string.
///
/// Supports formats: `"localhost:8080"`, `"*:443"`, `":80"`, `"127.0.0.1:80"`,
/// or plain `"8080"`. Remote hostnames are not converted to localhost.
fn extract_local_port(host: &str) -> Result<Option<u16>, WardenError> {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if let Ok(port) = trimmed.parse::<u16>() {
        return Ok(if port == 0 { None } else { Some(port) });
    }
    let lower = trimmed.to_ascii_lowercase();
    // Check the whole string before splitting on ':'. Bare IPv6 loopback
    // "::1" would otherwise become (":", "1") via rsplit_once.
    if is_local_hostname(&lower) {
        return Ok(None);
    }
    let (name, port_part) = if let Some((h, p)) = lower.rsplit_once(':') {
        (h, Some(p))
    } else {
        (lower.as_str(), None)
    };
    let local = is_local_hostname(name) || name.is_empty();
    if !local {
        return Err(WardenError::sandbox_setup(
            crate::error::SandboxStage::Policy,
            format!(
                "macOS SBPL cannot pin remote host '{trimmed}'; refuse rather than mapping to localhost"
            ),
        ));
    }
    match port_part {
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .map(Some)
            .ok_or_else(|| {
                WardenError::sandbox_setup(
                    crate::error::SandboxStage::Policy,
                    format!("invalid local port in '{trimmed}'"),
                )
            }),
        None => Ok(None),
    }
}

/// Escape a path for embedding in an SBPL string literal.
///
/// Only produces escapes that SBPL (TinyScheme) actually supports:
/// `\\`, `\"`, `\n`, `\r`, `\t`. Returns an error if the path contains
/// control characters that SBPL cannot represent (NUL or 0x01–0x1F
/// other than `\n`, `\r`, `\t`), since emitting unsupported escapes
/// would cause the sandbox rule to match a different path than intended.
fn escape_sbpl_path(path: &str) -> Result<String, WardenError> {
    let mut result = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '\\' => result.push_str("\\\\"),
            '"' => result.push_str("\\\""),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if (c as u32) <= 0x1F || (c as u32) == 0x7F => {
                return Err(WardenError::sandbox_setup(
                    crate::error::SandboxStage::Policy,
                    format!(
                        "escape_sbpl_path: path contains control character U+{:04X} \
                         which SBPL cannot represent",
                        c as u32
                    ),
                ));
            }
            c => result.push(c),
        }
    }
    Ok(result)
}

/// Generate a deny-default SBPL profile from the given policy.
#[cfg(test)]
pub fn generate_sbpl(policy: &Policy) -> Result<String, WardenError> {
    generate_sbpl_with_tmpdir(policy, "/private/tmp/mcp-writ-unused")
}

/// Generate SBPL that permits writes only under `tmpdir` (a private directory).
pub fn generate_sbpl_with_tmpdir(policy: &Policy, tmpdir: &str) -> Result<String, WardenError> {
    let mut p = String::with_capacity(2048);

    // --- Base: deny-default ---
    p.push_str("(version 1)\n(deny default)\n");

    // --- Essential process operations ---
    p.push_str("(allow process-fork)\n");
    p.push_str("(allow process-exec)\n");
    p.push_str("(allow signal (target self))\n");
    p.push_str("(allow process-info* (target same-sandbox))\n");
    p.push_str("(allow sysctl-read)\n");

    // --- System library reads (required by most processes) ---
    p.push_str("(allow file-read* (subpath \"/usr/lib\"))\n");
    p.push_str("(allow file-read* (subpath \"/System/Library\"))\n");
    p.push_str("(allow file-read* (subpath \"/usr/share\"))\n");

    // --- Dynamic library/framework mapping (required by dyld) ---
    p.push_str("(allow file-map-executable (subpath \"/usr/lib\"))\n");
    p.push_str("(allow file-map-executable (subpath \"/System/Library\"))\n");

    // --- Executable binary paths (required for exec to load binaries) ---
    p.push_str("(allow file-read-data file-read-metadata (subpath \"/bin\"))\n");
    p.push_str("(allow file-read-data file-read-metadata (subpath \"/sbin\"))\n");
    p.push_str("(allow file-read-data file-read-metadata (subpath \"/usr/bin\"))\n");
    p.push_str("(allow file-read-data file-read-metadata (subpath \"/usr/sbin\"))\n");
    p.push_str("(allow file-read-data file-read-metadata (subpath \"/usr/libexec\"))\n");

    // --- Standard config and metadata paths ---
    p.push_str("(allow file-read* (literal \"/etc/hosts\"))\n");
    p.push_str("(allow file-read* (literal \"/etc/resolv.conf\"))\n");
    p.push_str("(allow file-read* (literal \"/private/etc/hosts\"))\n");
    p.push_str("(allow file-read* (literal \"/private/etc/resolv.conf\"))\n");
    p.push_str("(allow file-read* (literal \"/\"))\n");

    // --- Symlink resolution metadata ---
    p.push_str("(allow file-read-metadata (literal \"/var\"))\n");

    // --- Device nodes ---
    p.push_str("(allow file-read* (literal \"/dev/null\"))\n");
    p.push_str("(allow file-read* (literal \"/dev/urandom\"))\n");
    p.push_str("(allow file-read* (literal \"/dev/random\"))\n");
    p.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
    p.push_str("(allow file-read-data file-write-data (subpath \"/dev/fd\"))\n");

    // --- Private TMPDIR only (no shared /tmp or /private/tmp) ---
    let escaped_tmp = escape_sbpl_path(tmpdir)?;
    p.push_str(&format!(
        "(allow file-read* file-write* (subpath \"{escaped_tmp}\"))\n"
    ));

    // --- IOKit (required for basic system queries) ---
    p.push_str("(allow iokit-open (iokit-registry-entry-class \"RootDomainUserClient\"))\n");

    // --- Mach services (required for basic operation) ---
    p.push_str("(allow mach-lookup\n");
    p.push_str("  (global-name \"com.apple.system.logger\")\n");
    p.push_str("  (global-name \"com.apple.system.opendirectoryd.libinfo\")\n");
    p.push_str("  (global-name \"com.apple.system.DirectoryService.libinfo_v1\")\n");
    p.push_str("  (global-name \"com.apple.trustd\")\n");
    p.push_str("  (global-name \"com.apple.trustd.agent\")\n");
    p.push_str("  (global-name \"com.apple.cfprefsd.daemon\")\n");
    p.push_str("  (global-name \"com.apple.cfprefsd.agent\")\n");
    p.push_str("  (global-name \"com.apple.logd\")\n");
    p.push_str("  (global-name \"com.apple.secinitd\")\n");
    p.push_str("  (global-name \"com.apple.bsd.dirhelper\"))\n");

    // --- Syslog socket (required for logging) ---
    p.push_str("(allow network-outbound (literal \"/private/var/run/syslog\"))\n");

    // --- Policy: read-only paths ---
    for path in &policy.fs.read_only {
        let escaped = escape_sbpl_path(path)?;
        p.push_str(&format!("(allow file-read* (subpath \"{escaped}\"))\n"));
    }

    // --- Policy: read-write paths ---
    for path in &policy.fs.read_write {
        let escaped = escape_sbpl_path(path)?;
        p.push_str(&format!(
            "(allow file-read* file-write* (subpath \"{escaped}\"))\n"
        ));
    }

    // --- Network rules ---
    if policy.network.outbound.deny_all_others {
        for host in &policy.network.outbound.allowed {
            if let Some(port) = extract_local_port(host)? {
                p.push_str(&format!(
                    "(allow network-outbound (remote tcp \"localhost:{port}\"))\n"
                ));
            }
        }
    } else {
        p.push_str("(allow network-outbound)\n");
        if policy.network.inbound.allow_listen {
            p.push_str("(allow network-bind)\n");
        }
    }

    // --- DNS resolution (allow mDNSResponder for name resolution) ---
    p.push_str("(allow mach-lookup (global-name \"com.apple.mDNSResponder\"))\n");

    Ok(p)
}

/// Per-launch private directory used as TMPDIR inside the sandbox.
/// Removed when dropped (kept alive by the child wrapper).
pub struct PrivateTmpDir {
    path: PathBuf,
}

impl PrivateTmpDir {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateTmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Create a per-launch private directory used as TMPDIR inside the sandbox.
pub fn create_private_tmpdir() -> Result<PrivateTmpDir, WardenError> {
    let dir = std::env::temp_dir().join(format!(
        "mcp-writ-sbx-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).map_err(|e| {
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("failed to create private TMPDIR: {e}"),
        )
    })?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
            let _ = std::fs::remove_dir_all(&dir);
            WardenError::sandbox_setup(
                crate::error::SandboxStage::Prepare,
                format!("failed to restrict private TMPDIR permissions: {e}"),
            )
        })?;
    }
    // SBPL matches the real path. On macOS, /var/folders is reached
    // through /private/var/folders, so retain the canonical private path.
    let canonical = dir.canonicalize().map_err(|e| {
        let _ = std::fs::remove_dir(&dir);
        WardenError::sandbox_setup(
            crate::error::SandboxStage::Prepare,
            format!("failed to resolve private TMPDIR: {e}"),
        )
    })?;
    Ok(PrivateTmpDir { path: canonical })
}

/// Child process plus the private TMPDIR that must outlive it.
pub struct MacosChild {
    child: Child,
    _tmpdir: PrivateTmpDir,
}

impl MacosChild {
    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        #[cfg(unix)]
        unsafe {
            let _ = libc_kill(-(self.child.id() as i32), SIGKILL);
        }
        self.child.kill()
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }
}

impl std::ops::Deref for MacosChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl std::ops::DerefMut for MacosChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

impl Drop for MacosChild {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => {}
            _ => {
                let _ = self.kill();
                let _ = self.child.wait();
            }
        }
    }
}

/// Spawn a child process sandboxed via `sandbox-exec`.
pub fn spawn_sandboxed(
    policy: &Policy,
    command: &str,
    args: &[String],
) -> Result<MacosChild, WardenError> {
    let tmpdir = create_private_tmpdir()?;
    let sbpl = generate_sbpl_with_tmpdir(policy, tmpdir.path().to_string_lossy().as_ref())?;

    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-p")
        .arg(&sbpl)
        .arg("--")
        .arg(command)
        .args(args)
        .env("TMPDIR", tmpdir.path())
        .env("TMP", tmpdir.path())
        .env("TEMP", tmpdir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    let child = cmd.spawn().map_err(WardenError::ProcessSpawn)?;
    Ok(MacosChild {
        child,
        _tmpdir: tmpdir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default_policy;

    // ---------------------------------------------------------------
    // extract_port
    // ---------------------------------------------------------------

    #[test]
    fn test_extract_port_host_colon_port() {
        assert_eq!(extract_local_port("localhost:8080").unwrap(), Some(8080));
        assert_eq!(extract_local_port("*:443").unwrap(), Some(443));
    }

    #[test]
    fn test_extract_port_colon_port() {
        assert_eq!(extract_local_port(":80").unwrap(), Some(80));
    }

    #[test]
    fn test_extract_port_plain_number() {
        assert_eq!(extract_local_port("80").unwrap(), Some(80));
    }

    #[test]
    fn test_extract_port_invalid() {
        assert!(extract_local_port("not-a-port").is_err());
        assert_eq!(extract_local_port("").unwrap(), None);
    }

    #[test]
    fn test_extract_port_rejects_remote_host() {
        assert!(extract_local_port("api.example.com:443").is_err());
        assert!(extract_local_port("https://evil.example").is_err());
    }

    #[test]
    fn test_extract_port_bare_ipv6_loopback() {
        assert_eq!(extract_local_port("::1").unwrap(), None);
        assert_eq!(extract_local_port("[::1]").unwrap(), None);
        assert_eq!(extract_local_port("[::1]:8080").unwrap(), Some(8080));
    }

    // ---------------------------------------------------------------
    // escape_sbpl_path
    // ---------------------------------------------------------------

    #[test]
    fn test_escape_no_special_chars() {
        assert_eq!(
            escape_sbpl_path("/usr/local/bin")
                .expect("failed to escape sbpl path for no special chars"),
            "/usr/local/bin"
        );
    }

    #[test]
    fn test_escape_quotes() {
        assert_eq!(
            escape_sbpl_path("/path/with\"quotes\"")
                .expect("failed to escape sbpl path for quotes"),
            "/path/with\\\"quotes\\\""
        );
    }

    #[test]
    fn test_escape_backslash() {
        assert_eq!(
            escape_sbpl_path("/path\\back").expect("failed to escape sbpl path for backslash"),
            "/path\\\\back"
        );
    }

    #[test]
    fn test_escape_supported_control_chars() {
        assert_eq!(
            escape_sbpl_path("/path\nwith\nnewlines").unwrap(),
            "/path\\nwith\\nnewlines"
        );
        assert_eq!(
            escape_sbpl_path("/path\twith\ttabs").unwrap(),
            "/path\\twith\\ttabs"
        );
        assert_eq!(
            escape_sbpl_path("/path\rwith\rreturns").unwrap(),
            "/path\\rwith\\rreturns"
        );
    }

    #[test]
    fn test_escape_rejects_nul() {
        let result = escape_sbpl_path("/path\0with_nul");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+0000"),
            "error should mention the codepoint: {msg}"
        );
    }

    #[test]
    fn test_escape_rejects_other_control_chars() {
        // BEL (U+0007)
        let result = escape_sbpl_path("/path\x07bel");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+0007"),
            "error should mention the codepoint: {msg}"
        );

        // ESC (U+001B)
        let result = escape_sbpl_path("/path\x1besc");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+001B"),
            "error should mention the codepoint: {msg}"
        );

        // DEL (U+007F)
        let result = escape_sbpl_path("/path\x7Fdel");
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(
            msg.contains("U+007F"),
            "error should mention the codepoint: {msg}"
        );
    }

    // ---------------------------------------------------------------
    // generate_sbpl — structure
    // ---------------------------------------------------------------

    #[test]
    fn test_sbpl_starts_with_version_and_deny_default() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.starts_with("(version 1)\n(deny default)\n"));
    }

    #[test]
    fn test_sbpl_contains_essential_operations() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow process-fork)"));
        assert!(sbpl.contains("(allow process-exec)"));
        assert!(sbpl.contains("(allow signal (target self))"));
        assert!(sbpl.contains("(allow sysctl-read)"));
        assert!(sbpl.contains("(allow process-info* (target same-sandbox))"));
    }

    #[test]
    fn test_sbpl_contains_system_library_reads() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (subpath \"/usr/lib\"))"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/System/Library\"))"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/usr/share\"))"));
        // Dynamic library mapping
        assert!(sbpl.contains("(allow file-map-executable (subpath \"/usr/lib\"))"));
        assert!(sbpl.contains("(allow file-map-executable (subpath \"/System/Library\"))"));
        // Executable binary paths
        assert!(sbpl.contains("(subpath \"/bin\")"));
        assert!(sbpl.contains("(subpath \"/usr/bin\")"));
    }

    #[test]
    fn test_sbpl_contains_dev_nodes() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (literal \"/dev/null\"))"));
        assert!(sbpl.contains("(allow file-read* (literal \"/dev/urandom\"))"));
    }

    #[test]
    fn test_sbpl_contains_tmp_paths() {
        let policy = default_policy();
        let sbpl = generate_sbpl_with_tmpdir(&policy, "/private/tmp/mcp-writ-test-tmp").unwrap();
        assert!(sbpl.contains(
            "(allow file-read* file-write* (subpath \"/private/tmp/mcp-writ-test-tmp\"))"
        ));
        assert!(!sbpl.contains("(allow file-read* file-write* (subpath \"/private/tmp\"))"));
        assert!(!sbpl.contains("(allow file-read* file-write* (subpath \"/tmp\"))"));
        assert!(!sbpl.contains("(subpath \"/etc\")"));
        assert!(sbpl.contains("(literal \"/etc/hosts\")"));
    }

    #[test]
    fn test_sbpl_contains_mach_services() {
        let policy = default_policy();
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("com.apple.system.logger"));
        assert!(sbpl.contains("com.apple.mDNSResponder"));
        assert!(sbpl.contains("com.apple.trustd"));
        assert!(sbpl.contains("com.apple.secinitd"));
        assert!(sbpl.contains("com.apple.system.opendirectoryd.libinfo"));
    }

    // ---------------------------------------------------------------
    // generate_sbpl — filesystem policy
    // ---------------------------------------------------------------

    #[test]
    fn test_sbpl_read_only_paths() {
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/opt/data".to_string(), "/usr/local/share".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (subpath \"/opt/data\"))"));
        assert!(sbpl.contains("(allow file-read* (subpath \"/usr/local/share\"))"));
    }

    #[test]
    fn test_sbpl_read_write_paths() {
        let mut policy = default_policy();
        policy.fs.read_write = vec!["/var/data".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* file-write* (subpath \"/var/data\"))"));
    }

    #[test]
    fn test_sbpl_path_escaping_in_policy() {
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/path/with\"quotes".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow file-read* (subpath \"/path/with\\\"quotes\"))"));
    }

    #[test]
    fn test_sbpl_rejects_control_char_in_policy_path() {
        let mut policy = default_policy();
        policy.fs.read_only = vec!["/path/\x07evil".to_string()];
        assert!(generate_sbpl(&policy).is_err());

        let mut policy = default_policy();
        policy.fs.read_write = vec!["/path/\0nul".to_string()];
        assert!(generate_sbpl(&policy).is_err());
    }

    // ---------------------------------------------------------------
    // generate_sbpl — network policy
    // ---------------------------------------------------------------

    #[test]
    fn test_sbpl_network_deny_all_no_allowed() {
        let policy = default_policy();
        // deny_all_others = true, allowed = []
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(!sbpl.contains("(allow network-outbound)"));
        assert!(!sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_deny_all_with_specific_ports() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = true;
        policy.network.outbound.allowed = vec!["localhost:443".to_string(), "*:80".to_string()];
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:443\"))"));
        assert!(sbpl.contains("(allow network-outbound (remote tcp \"localhost:80\"))"));
        // Must NOT have blanket allow
        assert!(!sbpl.contains("(allow network-outbound)\n"));
        assert!(!sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_allow_all() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = false;
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow network-outbound)\n"));
        assert!(!sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_allow_all_with_inbound() {
        let mut policy = default_policy();
        policy.network.outbound.deny_all_others = false;
        policy.network.inbound.allow_listen = true;
        let sbpl = generate_sbpl(&policy).unwrap();
        assert!(sbpl.contains("(allow network-outbound)\n"));
        assert!(sbpl.contains("(allow network-bind)"));
    }

    #[test]
    fn test_sbpl_network_rejects_remote_hostname() {
        let mut policy = default_policy();
        policy.network.outbound.allowed = vec!["api.example.com:443".to_string()];
        assert!(generate_sbpl(&policy).is_err());
    }

    // ---------------------------------------------------------------
    // Integration tests (macOS only)
    // ---------------------------------------------------------------

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_blocks_write_outside_allowed() {
        let policy = default_policy();
        let test_file = std::env::current_dir()
            .unwrap()
            .join("_sandbox_write_deny_test");

        // Clean up from any previous failed run
        let _ = std::fs::remove_file(&test_file);

        let mut child = spawn_sandboxed(
            &policy,
            "/bin/sh",
            &[
                "-c".to_string(),
                format!("echo denied > '{}' 2>/dev/null", test_file.display()),
            ],
        )
        .expect("sandbox-exec should spawn");

        let _ = child.wait();

        let blocked = !test_file.exists();
        let _ = std::fs::remove_file(&test_file);
        assert!(blocked, "sandbox should block writes outside allowed paths");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_allows_tmp_write() {
        use std::io::Read;

        let policy = default_policy();

        let mut child = spawn_sandboxed(
            &policy,
            "/bin/sh",
            &[
                "-c".to_string(),
                "echo allowed > \"$TMPDIR/mcp_writ_sandbox_allow_test\" && cat \"$TMPDIR/mcp_writ_sandbox_allow_test\"".to_string(),
            ],
        )
        .expect("sandbox-exec should spawn");

        let mut output = String::new();
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_string(&mut output)
            .ok();
        let status = child.wait().expect("sandboxed shell should exit");
        assert!(status.success(), "sandboxed shell failed: {status}");

        assert!(
            output.trim().contains("allowed"),
            "sandbox should allow writes to private TMPDIR, got: {output}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_sandbox_blocks_network_when_denied() {
        use std::net::TcpListener;

        // Bind a local TCP listener so we know the port is reachable
        // outside the sandbox — this proves the sandbox is what blocks
        // the connection, not a missing listener.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
        let port = listener.local_addr().unwrap().port();

        // Default policy: deny_all_others=true, allowed=[]
        // → SBPL will NOT contain (allow network-outbound) for any TCP port
        let policy = default_policy();

        let mut child = spawn_sandboxed(
            &policy,
            "/bin/sh",
            &[
                "-c".to_string(),
                format!("nc -z -w 2 127.0.0.1 {} 2>/dev/null", port),
            ],
        )
        .expect("sandbox-exec should spawn");

        let status = child.wait().expect("should be able to wait");
        drop(listener);

        assert!(
            !status.success(),
            "sandbox should block TCP connection to 127.0.0.1:{port} when deny_all_others=true"
        );
    }
}
