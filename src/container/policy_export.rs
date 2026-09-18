use std::fmt;
use std::path::Path;

use crate::policy::Policy;

/// Failure of one stage of the self-contained policy export.
///
/// Carries the inner error message; callers attach their own context
/// prefix when converting to their error type.
#[derive(Debug)]
pub enum PolicyExportError {
    /// `load_policy` failed.
    Load(String),
    /// `bind_to_server` failed.
    Bind(String),
    /// `inlined_schemas` failed.
    Inline(String),
}

impl fmt::Display for PolicyExportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(m) => write!(f, "failed to load policy: {m}"),
            Self::Bind(m) => write!(f, "failed to bind policy to server: {m}"),
            Self::Inline(m) => write!(f, "failed to inline schema: {m}"),
        }
    }
}

impl std::error::Error for PolicyExportError {}

/// Load a policy file and bind it to a single server identity.
///
/// Does not inline schemas: callers that need to inspect the bound
/// policy (e.g. docker-manifest-hash checks) run this before inlining.
pub fn load_and_bind_policy(
    policy_path: &Path,
    server: Option<&str>,
) -> Result<Policy, PolicyExportError> {
    let effective_policy = crate::policy::loader::load_policy(policy_path)
        .map_err(|e| PolicyExportError::Load(e.to_string()))?;
    effective_policy
        .bind_to_server(server)
        .map_err(|e| PolicyExportError::Bind(e.to_string()))
}

/// Inline `@file` args_schema references relative to `base_dir` and
/// serialize the result to a self-contained KDL string.
pub fn inline_policy_to_kdl(bound: &Policy, base_dir: &Path) -> Result<String, PolicyExportError> {
    let inlined = bound
        .inlined_schemas(base_dir)
        .map_err(PolicyExportError::Inline)?;
    Ok(inlined.to_kdl())
}

/// Export a policy as a self-contained KDL string:
/// `load_policy` → `bind_to_server` → `inlined_schemas` → `to_kdl`.
///
/// The result contains no `extends` and no `@schema.json` references.
pub fn export_self_contained_kdl(
    policy_path: &Path,
    server: Option<&str>,
) -> Result<String, PolicyExportError> {
    let bound = load_and_bind_policy(policy_path, server)?;
    let base_dir = policy_path.parent().unwrap_or_else(|| Path::new("."));
    inline_policy_to_kdl(&bound, base_dir)
}
