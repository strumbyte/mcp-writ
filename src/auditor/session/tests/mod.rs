use crate::policy::deputy::{DeputyRule, KnownShape};

mod extract;
mod flow;
mod state;
mod traversal_encoding;

/// The rules the compat-mapped discovery tools carry.
pub(super) const DISCOVER_RULES: &[DeputyRule] = &[DeputyRule::Shape(KnownShape::McpListResult)];
