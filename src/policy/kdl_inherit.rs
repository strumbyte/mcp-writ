use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kdl::KdlDocument;

use super::Policy;
use super::kdl_parse::{parse_kdl_policy_with_profiles, parse_profiles};
use super::merge::PolicyLayer;
use crate::error::PolicyError;

use super::MAX_POLICY_FILE_BYTES;

/// Inheritance traversal ceilings — a cyclic-but-visited-dodging or
/// simply enormous extends/include graph must exhaust a budget rather
/// than the loader stack and address space. `visited` already blocks
/// true cycles; these bound acyclic fan-out and aggregate input.
const MAX_INHERIT_DEPTH: usize = 32;
const MAX_INHERIT_FILES: usize = 256;
const MAX_INHERIT_BYTES: u64 = 16 * 1024 * 1024;

/// Monotonic counters shared across one policy load — `visited`
/// entries are removed on the way back up the recursion, so the set
/// cannot double as the file counter.
#[derive(Default)]
struct InheritBudget {
    files: usize,
    bytes: u64,
}

/// Internal recursive loader that handles extends, include, and when directives
/// with circular-reference detection via a visited set plus traversal budgets.
pub(crate) fn load_kdl_policy_internal(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
) -> Result<Policy, PolicyError> {
    let mut profiles = HashMap::new();
    let mut budget = InheritBudget::default();
    load_kdl_policy_recursive(path, visited, env, &mut profiles, &mut budget, 0)
}

fn load_kdl_policy_recursive(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
    profiles: &mut HashMap<String, PolicyLayer>,
    budget: &mut InheritBudget,
    depth: usize,
) -> Result<Policy, PolicyError> {
    Ok(load_kdl_policy_recursive_with_doc(path, visited, env, profiles, budget, depth)?.0)
}

fn load_kdl_policy_recursive_with_doc(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
    profiles: &mut HashMap<String, PolicyLayer>,
    budget: &mut InheritBudget,
    depth: usize,
) -> Result<(Policy, KdlDocument), PolicyError> {
    if depth >= MAX_INHERIT_DEPTH {
        return Err(PolicyError::Validation(format!(
            "inheritance depth limit ({MAX_INHERIT_DEPTH}) exceeded at '{}'",
            path.display(),
        )));
    }
    let canonical = path.canonicalize().map_err(PolicyError::FileRead)?;
    if !visited.insert(canonical.clone()) {
        return Err(PolicyError::Validation(format!(
            "circular reference detected: '{}'",
            path.display(),
        )));
    }
    budget.files += 1;
    if budget.files > MAX_INHERIT_FILES {
        return Err(PolicyError::Validation(format!(
            "inheritance file limit ({MAX_INHERIT_FILES}) exceeded at '{}'",
            path.display(),
        )));
    }

    let content = crate::fspriv::read_bounded_text(path, MAX_POLICY_FILE_BYTES)
        .map_err(PolicyError::FileRead)?;
    budget.bytes += content.len() as u64;
    if budget.bytes > MAX_INHERIT_BYTES {
        return Err(PolicyError::Validation(format!(
            "inheritance aggregate byte limit ({MAX_INHERIT_BYTES}) exceeded at '{}'",
            path.display(),
        )));
    }
    let doc: KdlDocument = content
        .parse()
        .map_err(|e: kdl::KdlError| PolicyError::KdlParse(e.to_string()))?;

    let base_dir = path.parent().unwrap_or(Path::new("."));

    // ── Step 1: Process `extends "base.kdl"` ──────────────────────
    let mut policy = if let Some(extends_node) = doc.get("extends") {
        let base_name = extends_node
            .get(0)
            .and_then(|v| v.as_string())
            .ok_or_else(|| {
                PolicyError::KdlParse("extends node must have a file path argument".into())
            })?;
        let base_path = base_dir.join(base_name);
        load_kdl_policy_recursive(&base_path, visited, env, profiles, budget, depth + 1)?
    } else {
        Policy::default()
    };

    // ── Step 2: Process `include "extra.kdl"` ─────────────────────
    for node in doc.nodes() {
        if node.name().to_string() != "include" {
            continue;
        }
        let inc_name = node.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
            PolicyError::KdlParse("include node must have a file path argument".into())
        })?;
        let inc_path = base_dir.join(inc_name);
        let (included, inc_doc) = load_kdl_policy_recursive_with_doc(
            &inc_path,
            visited,
            env,
            profiles,
            budget,
            depth + 1,
        )?;
        merge_into_policy(&mut policy, &included, &inc_doc);
        if included.confused_deputy_protection {
            policy.confused_deputy_protection = true;
        }
        if included.trajectory {
            policy.trajectory = true;
        }
        if included.logging.level != "info" && policy.logging.level == "info" {
            policy.logging.level = included.logging.level;
        }
    }

    // ── Step 3: Parse current document ────────────────────────────
    let doc_profiles = parse_profiles(&doc)?;
    profiles.extend(doc_profiles);

    let this_policy = parse_kdl_policy_with_profiles(&content, profiles, Some(base_dir))?;

    // If this file has an extends, merge current on top of base+includes.
    // Otherwise, current IS the base.
    if doc.get("extends").is_some()
        || doc
            .nodes()
            .iter()
            .any(|n| n.name().to_string() == "include")
    {
        merge_into_policy(&mut policy, &this_policy, &doc);
    } else {
        policy = this_policy;
    }

    // ── Step 4: Process `when environment="xxx" { ... }` ──────────
    apply_when_overrides(&doc, &mut policy, env, profiles, Some(base_dir))?;
    rematerialize_inherited_defaults(&mut policy);

    // Remove from visited so sibling includes from a parent don't false-trigger
    visited.remove(&canonical);

    Ok((policy, doc))
}

mod overlay;

use overlay::{apply_when_overrides, merge_into_policy};
pub(crate) use overlay::{rematerialize_inherited_defaults, tool_fs_base, tool_network_base};

#[cfg(test)]
mod tests;
