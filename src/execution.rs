//! Where a policy workload actually runs.
//!
//! These are leaf value types (layer 0 — see `docs/modules.md`): they must
//! not depend on `policy`, `runtime`, `warden`, or `container`. Policy
//! validation, launch planning, and reporting all decide against the
//! *workload* target recorded here, never against the CLI host's build OS.

/// Operating system the workload will run under.
///
/// `Other` exists so [`TargetOs::host`] can describe hosts without dedicated
/// policy semantics; it is intentionally not reachable through
/// [`TargetOs::parse`] — an unrecognized target name is an explicit error,
/// never a silent default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetOs {
    Windows,
    Linux,
    MacOs,
    /// An OS with no dedicated policy semantics. Generic checks still run
    /// and path handling falls back to POSIX rules (`/` separators,
    /// case-sensitive components).
    Other(&'static str),
}

impl TargetOs {
    /// The OS this process was built for.
    pub fn host() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Other(std::env::consts::OS)
        }
    }

    /// Parse an explicit target OS name. Unknown names are rejected — the
    /// caller must not fall back to the host OS when the user asked for a
    /// target we cannot reason about.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.trim().to_ascii_lowercase().as_str() {
            "windows" => Ok(Self::Windows),
            "linux" => Ok(Self::Linux),
            "macos" | "darwin" => Ok(Self::MacOs),
            other => Err(format!(
                "unknown target OS '{other}' (supported: windows, linux, macos)"
            )),
        }
    }

    /// Stable lowercase name for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::Windows => "windows",
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Other(name) => name,
        }
    }

    /// Whether `\` separates path components on this target.
    ///
    /// POSIX targets treat `\` as a literal filename character, so a pattern
    /// such as `a\b` must not be reinterpreted as `a/b`.
    pub fn separates_backslash(self) -> bool {
        matches!(self, Self::Windows)
    }

    /// Whether filesystem path components compare case-insensitively on
    /// this target's default filesystem (NTFS / default APFS).
    pub fn paths_case_insensitive(self) -> bool {
        matches!(self, Self::Windows | Self::MacOs)
    }
}

/// CPU architecture the workload will run on.
///
/// Carried on [`ExecutionTarget`] for reporting and future arch-dependent
/// rules; policy validation currently does not branch on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TargetArch {
    X86_64,
    Aarch64,
    /// Any other architecture (`std::env::consts::ARCH` value on the host).
    Other(&'static str),
}

impl TargetArch {
    /// The architecture this process was built for.
    pub fn host() -> Self {
        match std::env::consts::ARCH {
            "x86_64" => Self::X86_64,
            "aarch64" => Self::Aarch64,
            other => Self::Other(other),
        }
    }

    /// Stable name for diagnostics.
    pub fn name(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Other(name) => name,
        }
    }
}

/// How the workload is executed relative to this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionSubstrate {
    /// Spawned directly on this machine's OS.
    Native,
    /// Runs inside a container image (the in-guest `mcp-secure-runner`).
    Container,
    /// Runs inside a VM or stronger sandbox boundary (future work).
    Vm,
}

/// Container engine identity as a leaf value.
///
/// Conversion to and from `container::EngineKind` lives in the `container`
/// module so this module stays a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EngineName {
    Docker,
    Podman,
    Buildah,
}

impl EngineName {
    /// Parse an engine CLI name (`docker`, `podman`, `buildah`).
    /// Unknown engines return `None` — the identity is optional context,
    /// not a gate.
    pub fn from_name(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "docker" => Some(Self::Docker),
            "podman" => Some(Self::Podman),
            "buildah" => Some(Self::Buildah),
            _ => None,
        }
    }

    /// Engine CLI name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::Buildah => "buildah",
        }
    }
}

/// The execution context a policy is validated and applied for.
///
/// Distinguishes the CLI host OS, the execution-infrastructure OS, and the
/// workload's own OS/architecture so that, for example, a Windows host can
/// validate a policy for a Linux container guest without applying
/// Windows-specific restrictions to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionTarget {
    /// OS of the machine running this CLI process.
    pub host_os: TargetOs,
    /// OS of the substrate the workload is launched through (container
    /// engine host, VM monitor, …). For native runs this is `host_os`.
    pub substrate_os: TargetOs,
    /// OS the workload itself runs under. Policy representability and
    /// target-path semantics are decided against this value.
    pub workload_os: TargetOs,
    /// Workload CPU architecture.
    pub workload_arch: TargetArch,
    /// Execution method (native child, container, VM).
    pub substrate: ExecutionSubstrate,
    /// Container engine identity when `substrate == Container`.
    pub engine: Option<EngineName>,
}

impl ExecutionTarget {
    /// The workload runs directly on this machine's OS — the context every
    /// native (non-container) launch and compatibility wrapper uses.
    pub fn native() -> Self {
        Self {
            host_os: TargetOs::host(),
            substrate_os: TargetOs::host(),
            workload_os: TargetOs::host(),
            workload_arch: TargetArch::host(),
            substrate: ExecutionSubstrate::Native,
            engine: None,
        }
    }

    /// The workload runs inside a Linux container guest — the existing
    /// contract of `wrap`, `containerize`, and `run-image` (the embedded
    /// `mcp-secure-runner` is a Linux ELF; the guest OS is Linux regardless
    /// of the host OS).
    pub fn linux_container(engine: Option<EngineName>) -> Self {
        Self {
            host_os: TargetOs::host(),
            substrate_os: TargetOs::host(),
            workload_os: TargetOs::Linux,
            // The container contract runs same-arch images; arch-specific
            // rules would need the image platform, which is out of scope.
            workload_arch: TargetArch::host(),
            substrate: ExecutionSubstrate::Container,
            engine,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_target_matches_build_cfg() {
        let expected = if cfg!(windows) {
            TargetOs::Windows
        } else if cfg!(target_os = "linux") {
            TargetOs::Linux
        } else if cfg!(target_os = "macos") {
            TargetOs::MacOs
        } else {
            TargetOs::Other(std::env::consts::OS)
        };
        assert_eq!(TargetOs::host(), expected);
    }

    #[test]
    fn parse_known_target_names() {
        assert_eq!(TargetOs::parse("windows").unwrap(), TargetOs::Windows);
        assert_eq!(TargetOs::parse(" Linux ").unwrap(), TargetOs::Linux);
        assert_eq!(TargetOs::parse("MACOS").unwrap(), TargetOs::MacOs);
        assert_eq!(TargetOs::parse("darwin").unwrap(), TargetOs::MacOs);
    }

    #[test]
    fn parse_rejects_unknown_target_names() {
        for name in ["", "win32", "freebsd", "plan9"] {
            let err = TargetOs::parse(name).unwrap_err();
            assert!(err.contains("unknown target OS"), "got: {err}");
            assert!(err.contains(name) || name.is_empty(), "got: {err}");
        }
    }

    #[test]
    fn native_target_uses_host_os() {
        let target = ExecutionTarget::native();
        assert_eq!(target.workload_os, TargetOs::host());
        assert_eq!(target.host_os, TargetOs::host());
        assert_eq!(target.substrate_os, TargetOs::host());
        assert_eq!(target.substrate, ExecutionSubstrate::Native);
        assert_eq!(target.engine, None);
    }

    #[test]
    fn linux_container_target_is_linux_workload() {
        let target = ExecutionTarget::linux_container(Some(EngineName::Docker));
        assert_eq!(target.workload_os, TargetOs::Linux);
        assert_eq!(target.substrate, ExecutionSubstrate::Container);
        assert_eq!(target.engine, Some(EngineName::Docker));
        assert_eq!(target.host_os, TargetOs::host());
    }

    #[test]
    fn engine_name_round_trip() {
        for (name, expected) in [
            ("docker", EngineName::Docker),
            ("Podman", EngineName::Podman),
            ("buildah", EngineName::Buildah),
        ] {
            assert_eq!(EngineName::from_name(name), Some(expected));
            assert_eq!(EngineName::from_name(expected.name()), Some(expected));
        }
        assert_eq!(EngineName::from_name("containerd"), None);
    }

    #[test]
    fn path_semantics_per_target() {
        assert!(TargetOs::Windows.separates_backslash());
        assert!(TargetOs::Windows.paths_case_insensitive());
        assert!(!TargetOs::Linux.separates_backslash());
        assert!(!TargetOs::Linux.paths_case_insensitive());
        assert!(TargetOs::MacOs.paths_case_insensitive());
        assert!(!TargetOs::Other("freebsd").separates_backslash());
        assert!(!TargetOs::Other("freebsd").paths_case_insensitive());
    }
}
