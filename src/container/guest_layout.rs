//! Guest-OS-scoped launch contract: the filesystem paths, host→guest
//! channel environment variables, and runner distribution names that
//! `wrap-image` / `containerize` generate, the in-guest
//! `mcp-secure-runner` consumes, and `run-image` mounts into the
//! container.
//!
//! The three sides must agree on every constant in a [`GuestLayout`]:
//! a Dockerfile that places the runner at one path while `run-image`
//! mounts the policy at a different base is a broken contract. Keeping
//! the constants in one table — indexed by the image's declared guest
//! OS — is what lets the Windows guest contract share the machinery
//! without the Linux contract inheriting Windows spellings.

use crate::execution::TargetOs;

/// The default directory a Windows image's runner directory needs the
/// MSVC redistributable copied into (app-local placement — Server Core
/// carries no `VCRUNTIME140.dll`).
pub const WINDOWS_CRT_DLLS: &[&str] = &["vcruntime140.dll", "vcruntime140_1.dll"];

/// The per-guest-OS filesystem/env contract the image, the runner
/// binary, and the launch path share. `&'static`: layouts are literals,
/// never constructed at runtime.
#[derive(Debug)]
pub struct GuestLayout {
    /// The guest OS this layout describes (the image's `Os`, the OS the
    /// workload process runs under).
    pub guest_os: TargetOs,
    /// Guest path the runner binary is copied to by the generated
    /// Dockerfile — also the image's ENTRYPOINT[0].
    pub runner_path: &'static str,
    /// Context-file name the runner binary is copied into under the
    /// build directory (no `.exe` — the Dockerfile's COPY line appends
    /// it when the guest spells filenames that way).
    pub runner_context_name: &'static str,
    /// Guest directory the embedded/mounted policy lives in —
    /// `C:/etc/mcp-secure` on Windows, `/etc/mcp-secure` on Linux.
    /// On Windows this is a *directory* mount: single-file binds are
    /// not portable across Windows container engines, so the launch
    /// mounts the policy's directory and the file name is fixed.
    pub policy_dir: &'static str,
    /// The filename inside [`Self::policy_dir`] the runner reads —
    /// mounted as a file on Linux, as the directory member on Windows.
    pub policy_name: &'static str,
    /// Guest directory `containerize` copies the workload sources into —
    /// `WORKDIR` and the `COPY` destination base.
    pub app_dir: &'static str,
    /// Guest directory the runner's own audit log lands in (`--log-dir`
    /// or the launch's log mount).
    pub log_dir: &'static str,
    /// Guest directory the guest launch report is written under.
    pub report_dir: &'static str,
    /// Guest directory the workload's TMPDIR-family variables are
    /// pointed at (a private temp the AppContainer DACL grants).
    pub workload_temp: &'static str,
    /// Env var carrying the (host) path of the mounted policy file —
    /// set by `run-image`, consumed by the runner before it strips the
    /// variable from the workload environment.
    pub policy_path_env: &'static str,
    /// Env var carrying the guest path of the audit-log directory.
    pub audit_dir_env: &'static str,
    /// Env var carrying the guest path the workload's TMPDIR-family is
    /// redirected to — the runner synthesizes it inside the guest.
    pub temp_dir_env: &'static str,
    /// Report-file name inside [`Self::report_dir`] the runner writes
    /// and the host reads back.
    pub report_name: &'static str,
    /// Env var the runner embeds a JSON capability marker in —
    /// `MCP_WRIT_RUNNER_CAPS`; the generated image ENV line records it
    /// so `run-image` can tell a report-capable runner from a legacy
    /// one without executing it.
    pub caps_env: &'static str,
    /// Runner distribution-name stem for this guest —
    /// `mcp-secure-runner-linux` / `mcp-secure-runner-windows`. The
    /// released filename is `{stem}-{arch-tag}{ext}` (e.g.
    /// `mcp-secure-runner-windows-amd64.exe`).
    pub runner_stem: &'static str,
    /// Filename extension guest executables carry (`.exe` on Windows,
    /// empty on Linux).
    pub exe_suffix: &'static str,
}

/// The Linux guest contract — the existing container path. Path
/// spellings are the ones the `run-image` launch and the Dockerfile
/// generator already shared before this table existed.
pub const LINUX: GuestLayout = GuestLayout {
    guest_os: TargetOs::Linux,
    runner_path: "/usr/local/bin/mcp-secure-runner",
    runner_context_name: "mcp-secure-runner",
    policy_dir: "/etc/mcp-secure",
    policy_name: "policy.kdl",
    app_dir: "/app",
    log_dir: "/var/log/mcp-secure",
    report_dir: "/run/mcp-secure/report",
    workload_temp: "/tmp",
    policy_path_env: "MCP_WRIT_POLICY_PATH",
    audit_dir_env: "MCP_WRIT_AUDIT_DIR",
    temp_dir_env: "MCP_WRIT_TEMP_DIR",
    report_name: "report.json",
    caps_env: "MCP_WRIT_RUNNER_CAPS",
    runner_stem: "mcp-secure-runner-linux",
    exe_suffix: "",
};

/// The Windows guest contract — the paths PR-20 validated under
/// Hyper-V isolation, spelled with an explicit `C:/` drive so nothing
/// depends on the process CWD the way a bare `/etc/...` would.
pub const WINDOWS: GuestLayout = GuestLayout {
    guest_os: TargetOs::Windows,
    runner_path: "C:/mcp-secure/mcp-secure-runner.exe",
    runner_context_name: "mcp-secure-runner.exe",
    policy_dir: "C:/etc/mcp-secure",
    policy_name: "policy.kdl",
    app_dir: "C:/app",
    log_dir: "C:/var/log/mcp-secure",
    report_dir: "C:/run/mcp-secure/report",
    workload_temp: "C:/Windows/Temp",
    policy_path_env: "MCP_WRIT_POLICY_PATH",
    audit_dir_env: "MCP_WRIT_AUDIT_DIR",
    temp_dir_env: "MCP_WRIT_TEMP_DIR",
    report_name: "report.json",
    caps_env: "MCP_WRIT_RUNNER_CAPS",
    runner_stem: "mcp-secure-runner-windows",
    exe_suffix: ".exe",
};

/// The full path of the mounted policy file under `policy_dir`.
pub fn policy_file(layout: &GuestLayout) -> String {
    format!("{}/{}", layout.policy_dir, layout.policy_name)
}

/// The released runner filename for `arch`, or `None` when the
/// guest/arch pair is unsupported (Windows only ships amd64 for now —
/// refusing beats a silent alias to a binary the guest cannot run).
pub fn runner_dist_name(
    layout: &GuestLayout,
    arch: &crate::execution::TargetArch,
) -> Option<String> {
    use crate::execution::TargetArch;
    let tag = match (layout.guest_os, arch) {
        (_, TargetArch::X86_64) => "amd64",
        (TargetOs::Linux, TargetArch::Aarch64) => "arm64",
        _ => return None,
    };
    Some(format!("{}-{tag}{}", layout.runner_stem, layout.exe_suffix))
}

/// The image's declared guest OS as a guest layout, or an actionable
/// error: the two contracts this codebase knows are Linux (the OCI
/// container path) and Windows (the Hyper-V unit). An undeterminable
/// or other OS is refused rather than assumed into either contract.
pub fn for_image_os(os: Option<&str>) -> Result<&'static GuestLayout, String> {
    match os.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
        Some("linux") => Ok(&LINUX),
        Some("windows") => Ok(&WINDOWS),
        Some(other) => Err(format!(
            "unsupported image OS '{other}': the runner contract covers \
             linux and windows guests; wrap or containerize the image \
             with a base whose declared OS is one of those"
        )),
        None => Err(
            "image declares no OS metadata; cannot pick a guest contract \
             (refusing rather than assuming Linux or Windows)"
                .into(),
        ),
    }
}

/// The layout for the guest OS `run-image` already launched under —
/// used where the *running* guest's OS is known rather than the
/// image's declared metadata.
pub fn for_guest_os(os: TargetOs) -> Option<&'static GuestLayout> {
    match os {
        TargetOs::Linux => Some(&LINUX),
        TargetOs::Windows => Some(&WINDOWS),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_layout_is_the_existing_contract() {
        let l = &LINUX;
        assert_eq!(l.guest_os, TargetOs::Linux);
        assert_eq!(l.runner_path, "/usr/local/bin/mcp-secure-runner");
        assert_eq!(policy_file(l), "/etc/mcp-secure/policy.kdl");
        assert_eq!(l.runner_context_name, "mcp-secure-runner");
        assert_eq!(
            runner_dist_name(l, &crate::execution::TargetArch::X86_64),
            Some("mcp-secure-runner-linux-amd64".to_string())
        );
        assert_eq!(
            runner_dist_name(l, &crate::execution::TargetArch::Aarch64),
            Some("mcp-secure-runner-linux-arm64".to_string())
        );
    }

    #[test]
    fn windows_layout_matches_the_hyperv_record() {
        // The PR-20 fixture mounted `C:\etc\mcp-secure` / `C:\var\log\mcp-secure`
        // / `C:\run\mcp-secure\report` and placed the runner under
        // `C:/mcp-secure/` — this table must produce exactly those paths.
        let l = &WINDOWS;
        assert_eq!(l.guest_os, TargetOs::Windows);
        assert_eq!(l.runner_path, "C:/mcp-secure/mcp-secure-runner.exe");
        assert_eq!(policy_file(l), "C:/etc/mcp-secure/policy.kdl");
        assert_eq!(l.report_dir, "C:/run/mcp-secure/report");
        assert_eq!(l.log_dir, "C:/var/log/mcp-secure");
        assert_eq!(l.runner_context_name, "mcp-secure-runner.exe");
        assert_eq!(
            runner_dist_name(l, &crate::execution::TargetArch::X86_64),
            Some("mcp-secure-runner-windows-amd64.exe".to_string())
        );
        // No arm64 Windows runner yet — refused, never aliased.
        assert_eq!(
            runner_dist_name(l, &crate::execution::TargetArch::Aarch64),
            None
        );
    }

    #[test]
    fn image_os_mapping() {
        assert_eq!(
            for_image_os(Some("linux")).unwrap().guest_os,
            TargetOs::Linux
        );
        assert_eq!(
            for_image_os(Some(" Linux ")).unwrap().guest_os,
            TargetOs::Linux
        );
        assert_eq!(
            for_image_os(Some("windows")).unwrap().guest_os,
            TargetOs::Windows
        );
        assert!(for_image_os(Some("freebsd")).is_err());
        assert!(for_image_os(None).is_err());
    }
}
