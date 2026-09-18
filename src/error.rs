use std::fmt;

pub use orfail::{Failure, OrFail};

#[derive(Debug)]
pub enum McpWritError {
    Policy(PolicyError),
    Warden(WardenError),
    Auditor(AuditorError),
    Inspector(InspectorError),
    Container(ContainerError),
    Io(std::io::Error),
    Cli(CliError),
}

impl fmt::Display for McpWritError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Policy(e) => write!(f, "Policy error: {e}"),
            Self::Warden(e) => write!(f, "Warden error: {e}"),
            Self::Auditor(e) => write!(f, "Auditor error: {e}"),
            Self::Inspector(e) => write!(f, "Inspector error: {e}"),
            Self::Container(e) => write!(f, "Container error: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::Cli(e) => write!(f, "CLI error: {e}"),
        }
    }
}

impl std::error::Error for McpWritError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Policy(e) => Some(e),
            Self::Warden(e) => Some(e),
            Self::Auditor(e) => Some(e),
            Self::Inspector(e) => Some(e),
            Self::Container(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Cli(e) => Some(e),
        }
    }
}

impl From<PolicyError> for McpWritError {
    fn from(e: PolicyError) -> Self {
        Self::Policy(e)
    }
}

impl From<WardenError> for McpWritError {
    fn from(e: WardenError) -> Self {
        Self::Warden(e)
    }
}

impl From<AuditorError> for McpWritError {
    fn from(e: AuditorError) -> Self {
        Self::Auditor(e)
    }
}

impl From<InspectorError> for McpWritError {
    fn from(e: InspectorError) -> Self {
        Self::Inspector(e)
    }
}

impl From<ContainerError> for McpWritError {
    fn from(e: ContainerError) -> Self {
        Self::Container(e)
    }
}

impl From<std::io::Error> for McpWritError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CliError> for McpWritError {
    fn from(e: CliError) -> Self {
        Self::Cli(e)
    }
}

#[derive(Debug)]
pub enum PolicyError {
    FileRead(std::io::Error),
    KdlParse(String),
    Validation(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileRead(e) => write!(f, "Failed to read policy file: {e}"),
            Self::KdlParse(e) => write!(f, "Failed to parse policy KDL: {e}"),
            Self::Validation(e) => write!(f, "Invalid policy: {e}"),
        }
    }
}

impl std::error::Error for PolicyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FileRead(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum WardenError {
    SandboxSetup(String),
    ProcessSpawn(std::io::Error),
}

impl fmt::Display for WardenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SandboxSetup(e) => write!(f, "Sandbox setup failed: {e}"),
            Self::ProcessSpawn(e) => write!(f, "Process spawn failed: {e}"),
        }
    }
}

impl std::error::Error for WardenError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ProcessSpawn(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum AuditorError {
    JsonRpcParse(String),
    ToolNotAllowed { tool: String },
    PolicyViolation(String),
    Io(std::io::Error),
    FrameTooLarge { bytes: usize, limit: usize },
    AuditUnavailable(String),
}

impl fmt::Display for AuditorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::JsonRpcParse(e) => write!(f, "JSON-RPC parse error: {e}"),
            Self::ToolNotAllowed { tool } => {
                write!(f, "Policy violation: tool '{tool}' is not allowed")
            }
            Self::PolicyViolation(e) => write!(f, "Policy violation: {e}"),
            Self::Io(e) => write!(f, "IO error: {e}"),
            Self::FrameTooLarge { bytes, limit } => {
                write!(
                    f,
                    "JSON-RPC frame exceeds {limit} bytes ({bytes} read without newline)"
                )
            }
            Self::AuditUnavailable(e) => write!(f, "audit log unavailable: {e}"),
        }
    }
}

impl std::error::Error for AuditorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum CliError {
    MissingSubcommand,
    MissingCommand,
    Parse(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSubcommand => write!(
                f,
                "missing subcommand, expected 'run', 'inspect', 'generate-policy', 'run-image', or 'wrap-image'"
            ),
            Self::MissingCommand => {
                write!(
                    f,
                    "missing command after '--', e.g.: mcp-writ run -- <command> [args...]"
                )
            }
            Self::Parse(e) => write!(f, "argument parse error: {e}"),
        }
    }
}

impl std::error::Error for CliError {}

#[derive(Debug)]
pub enum InspectorError {
    FileRead(std::io::Error),
    ParseError(String),
    UnsupportedFormat(String),
}

impl fmt::Display for InspectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileRead(e) => write!(f, "Failed to read binary file: {e}"),
            Self::ParseError(e) => write!(f, "Binary parse error: {e}"),
            Self::UnsupportedFormat(e) => write!(f, "Unsupported binary format: {e}"),
        }
    }
}

impl std::error::Error for InspectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::FileRead(e) => Some(e),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum ContainerError {
    DockerfileGeneration(String),
    InspectExec(String),
    InspectParse(String),
    RunnerResolve(String),
    BuildFailed(String),
    RuntimeDetect(String),
}

impl fmt::Display for ContainerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DockerfileGeneration(e) => write!(f, "Dockerfile generation failed: {e}"),
            Self::InspectExec(e) => write!(f, "Image inspect failed: {e}"),
            Self::InspectParse(e) => write!(f, "Image inspect parse failed: {e}"),
            Self::RunnerResolve(e) => write!(f, "Runner resolve failed: {e}"),
            Self::BuildFailed(e) => write!(f, "Image build failed: {e}"),
            Self::RuntimeDetect(e) => write!(f, "Runtime detection failed: {e}"),
        }
    }
}

impl std::error::Error for ContainerError {}
