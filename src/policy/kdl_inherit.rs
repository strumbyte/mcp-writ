use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kdl::KdlDocument;

use super::Policy;
use super::kdl_parse::{parse_kdl_policy_with_profiles, parse_profiles};
use super::merge::PolicyLayer;
use crate::error::PolicyError;

use super::{MAX_POLICY_FILE_BYTES, MAX_SUPPORTED_VERSION, MIN_SUPPORTED_VERSION};

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
/// `markers` collects `// REVIEW` comments from every file the traversal
/// reads (entry file plus `extends`/`include` ancestors).
pub(crate) fn load_kdl_policy_internal(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
    markers: &mut Vec<super::review::ReviewMarker>,
) -> Result<Policy, PolicyError> {
    let mut profiles = HashMap::new();
    let mut budget = InheritBudget::default();
    let (policy, _decl, pending) = load_kdl_policy_recursive_with_decl(
        path,
        visited,
        env,
        &mut profiles,
        &mut budget,
        markers,
        0,
    )?;
    // Deferred warnings fire once, against the merged policy the whole
    // load produced — not against each file's intermediate state.
    pending.emit(&policy);
    Ok(policy)
}

/// Returns the merged policy plus the declarations this subtree made —
/// which fields this file, its `extends`/`include` ancestors, and its
/// matching `when` blocks actually wrote. An `include` consumer merges
/// on that view, so ancestor- and `when`-derived values are not lost by
/// looking only at the included file's own nodes.
///
/// `visited` bookkeeping lives here so the canonical path is unwound
/// on *every* exit — an erroring load must not leave the path in the
/// set and trip a false circular-reference on a later traversal.
fn load_kdl_policy_recursive_with_decl(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
    profiles: &mut HashMap<String, PolicyLayer>,
    budget: &mut InheritBudget,
    markers: &mut Vec<super::review::ReviewMarker>,
    depth: usize,
) -> Result<(Policy, OverlayDecl, PendingWarnings), PolicyError> {
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
    let result = load_kdl_policy_subtree(path, visited, env, profiles, budget, markers, depth);
    visited.remove(&canonical);
    result
}

/// Body of [`load_kdl_policy_recursive_with_decl`] — the file's own
/// bookkeeping is done, so this reads and merges the subtree. Warnings
/// the merges raised stay pending and travel back with the result; the
/// root of the load emits them against the final merged policy.
fn load_kdl_policy_subtree(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
    profiles: &mut HashMap<String, PolicyLayer>,
    budget: &mut InheritBudget,
    markers: &mut Vec<super::review::ReviewMarker>,
    depth: usize,
) -> Result<(Policy, OverlayDecl, PendingWarnings), PolicyError> {
    budget.files += 1;
    if budget.files > MAX_INHERIT_FILES {
        return Err(PolicyError::Validation(format!(
            "inheritance file limit ({MAX_INHERIT_FILES}) exceeded at '{}'",
            path.display(),
        )));
    }

    let content = crate::fspriv::read_bounded_text(path, MAX_POLICY_FILE_BYTES)
        .map_err(PolicyError::FileRead)?;
    markers.extend(crate::policy::review::scan_review_markers(path, &content));
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
    // The base subtree's declarations carry through: an `include` of
    // this file must see what its ancestors declared, not just this
    // file's own nodes.
    let (mut policy, mut decl, base_pending) = if let Some(extends_node) = doc.get("extends") {
        let base_name = extends_node
            .get(0)
            .and_then(|v| v.as_string())
            .ok_or_else(|| {
                PolicyError::KdlParse("extends node must have a file path argument".into())
            })?;
        let base_path = base_dir.join(base_name);
        load_kdl_policy_recursive_with_decl(
            &base_path,
            visited,
            env,
            profiles,
            budget,
            markers,
            depth + 1,
        )?
    } else {
        (
            Policy::default(),
            OverlayDecl::default(),
            PendingWarnings::default(),
        )
    };

    // Warnings are deferred to the end of the whole load — a later
    // file may still close a listener grant or restore a weakened
    // posture, so nothing emits against this file's intermediate
    // state. Entries this file's own merges raise join the pending set
    // that returns to the caller.
    let mut pending = base_pending;

    // ── Step 2: Process `include "extra.kdl"` ─────────────────────
    for node in doc.nodes() {
        if node.name().to_string() != "include" {
            continue;
        }
        let inc_name = node.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
            PolicyError::KdlParse("include node must have a file path argument".into())
        })?;
        let inc_path = base_dir.join(inc_name);
        let (included, inc_decl, inc_pending) = load_kdl_policy_recursive_with_decl(
            &inc_path,
            visited,
            env,
            profiles,
            budget,
            markers,
            depth + 1,
        )?;
        pending.absorb(inc_pending);
        let posture = SecurityPosture::capture(&policy);
        let had_listen = policy.network.inbound.allow_listen;
        merge_into_policy(&mut policy, &included, &inc_decl);
        for weakened in posture.weakened(&policy) {
            pending.push_weakened(&inc_path, weakened);
        }
        if had_listen && inc_decl.network && !inc_decl.network_inbound {
            pending.push_inbound(&inc_path);
        }
        decl.merge(&inc_decl);
    }

    // ── Step 3: Parse current document ────────────────────────────
    let doc_profiles = parse_profiles(&doc)?;
    profiles.extend(doc_profiles);

    let this_policy = parse_kdl_policy_with_profiles(&content, profiles, Some(base_dir))?;

    // Every file in the chain declares a supported `policy version` —
    // otherwise an ancestor's unknown version would ride the child's.
    if !(MIN_SUPPORTED_VERSION..=MAX_SUPPORTED_VERSION).contains(&this_policy.version) {
        return Err(PolicyError::Validation(format!(
            "unsupported policy version {}, expected {MIN_SUPPORTED_VERSION}..={MAX_SUPPORTED_VERSION} in '{}'",
            this_policy.version,
            path.display(),
        )));
    }
    let doc_decl = OverlayDecl::for_doc(&doc);

    // If this file has an extends, merge current on top of base+includes.
    // Otherwise, current IS the base.
    if doc.get("extends").is_some()
        || doc
            .nodes()
            .iter()
            .any(|n| n.name().to_string() == "include")
    {
        let posture = SecurityPosture::capture(&policy);
        let had_listen = policy.network.inbound.allow_listen;
        merge_into_policy(&mut policy, &this_policy, &doc_decl);
        for weakened in posture.weakened(&policy) {
            pending.push_weakened(path, weakened);
        }
        if had_listen && doc_decl.network && !doc_decl.network_inbound {
            pending.push_inbound(path);
        }
    } else {
        policy = this_policy;
    }
    decl.merge(&doc_decl);

    // ── Step 4: Process `when environment="xxx" { ... }` ──────────
    let posture = SecurityPosture::capture(&policy);
    let when_decl = apply_when_overrides(
        &doc,
        &mut policy,
        env,
        profiles,
        Some(base_dir),
        path,
        &mut pending,
    )?;
    for weakened in posture.weakened(&policy) {
        pending.push_weakened(path, weakened);
    }
    decl.merge(&when_decl);
    rematerialize_inherited_defaults(&mut policy);

    Ok((policy, decl, pending))
}

mod overlay;

use overlay::{
    OverlayDecl, PendingWarnings, SecurityPosture, apply_when_overrides, merge_into_policy,
};
pub(crate) use overlay::{rematerialize_inherited_defaults, tool_fs_base, tool_network_base};

#[cfg(test)]
mod tests;
