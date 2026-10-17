use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kdl::KdlDocument;

use super::Policy;
use super::kdl_parse::{parse_kdl_policy_with_profiles, parse_profiles};
use super::merge::PolicyLayer;
use super::provenance::{LoadDiagnostics, Provenance};
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

/// State threaded through one whole load — the profile table every
/// file contributes to and reads, the schema warnings the strict pass
/// collects, the provenance write log, and the file that first defined
/// each profile (so a redefinition can name what it replaced).
struct LoadCx<'a> {
    profiles: &'a mut HashMap<String, PolicyLayer>,
    markers: &'a mut Vec<super::review::ReviewMarker>,
    warnings: &'a mut Vec<super::provenance::LoadWarning>,
    prov: &'a mut Provenance,
    profile_files: &'a mut HashMap<String, PathBuf>,
}

/// Internal recursive loader that handles extends, include, and when directives
/// with circular-reference detection via a visited set plus traversal budgets.
/// Returns the merged policy plus everything the load learned besides it —
/// `// REVIEW` markers, schema warnings, replacement/posture warnings — and
/// attaches the composition's provenance write log to the policy.
pub(crate) fn load_kdl_policy_internal(
    path: &Path,
    visited: &mut HashSet<PathBuf>,
    env: &str,
) -> Result<(Policy, LoadDiagnostics), PolicyError> {
    let mut profiles = HashMap::new();
    let mut profile_files = HashMap::new();
    let mut budget = InheritBudget::default();
    let mut diagnostics = LoadDiagnostics::default();
    let mut prov = Provenance::default();
    let (mut policy, _decl, pending) = {
        let mut cx = LoadCx {
            profiles: &mut profiles,
            markers: &mut diagnostics.review_markers,
            warnings: &mut diagnostics.warnings,
            prov: &mut prov,
            profile_files: &mut profile_files,
        };
        load_kdl_policy_recursive_with_decl(path, visited, env, &mut cx, &mut budget, 0)?
    };
    // Deferred warnings fire once, against the merged policy the whole
    // load produced — not against each file's intermediate state.
    pending.collect(&policy, &mut diagnostics.warnings);
    let provenance = std::sync::Arc::new(prov.finish());
    // Replacements are read off the final write log — a restore or a
    // deny-prune between the replace and the end of the load does not
    // retract the loss the records attest.
    diagnostics
        .warnings
        .extend(provenance.replacement_warnings());
    policy.provenance = Some(provenance);
    Ok((policy, diagnostics))
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
    cx: &mut LoadCx<'_>,
    budget: &mut InheritBudget,
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
    let result = load_kdl_policy_subtree(path, visited, env, cx, budget, depth);
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
    cx: &mut LoadCx<'_>,
    budget: &mut InheritBudget,
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
    cx.markers
        .extend(crate::policy::review::scan_review_markers(path, &content));
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
        load_kdl_policy_recursive_with_decl(&base_path, visited, env, cx, budget, depth + 1)?
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
    // A weakening is only meaningful against an established base:
    // `Policy::default()` alone is the loader's seed, not a posture an
    // operator declared. The first include onto it establishes the
    // base rather than weakening it — like the file's own document at
    // step 3 — so the posture capture starts once `extends` or an
    // earlier include has put real values in place.
    let mut base_established = doc.get("extends").is_some();
    for node in doc.nodes() {
        if node.name().to_string() != "include" {
            continue;
        }
        let inc_name = node.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
            PolicyError::KdlParse("include node must have a file path argument".into())
        })?;
        let inc_path = base_dir.join(inc_name);
        let (included, inc_decl, inc_pending) =
            load_kdl_policy_recursive_with_decl(&inc_path, visited, env, cx, budget, depth + 1)?;
        pending.absorb(inc_pending);
        let posture = base_established.then(|| SecurityPosture::capture(&policy));
        let had_listen = policy.network.inbound.allow_listen;
        merge_into_policy(&mut policy, &included, &inc_decl, &inc_path, cx.prov);
        if let Some(posture) = posture {
            for weakened in posture.weakened(&policy) {
                pending.push_weakened(&inc_path, weakened);
            }
        }
        if had_listen && inc_decl.network && !inc_decl.network_inbound {
            pending.push_inbound(&inc_path);
        }
        decl.merge(&inc_decl);
        base_established = true;
    }

    // ── Step 3: Parse current document ────────────────────────────
    let doc_profiles = parse_profiles(&doc)?;
    // A profile redefinition replaces the earlier layer wholesale —
    // record it so the effective policy can name both writers.
    for name in doc_profiles.keys() {
        let line = doc
            .nodes()
            .iter()
            .find(|n| {
                n.name().value() == "profile"
                    && n.get(0).and_then(|v| v.as_string()) == Some(name.as_str())
            })
            .and_then(|n| node_line(&content, n));
        match cx.profile_files.get(name) {
            Some(prev) => {
                let existing = cx.profiles.get(name);
                let count = existing.map(layer_entry_count).unwrap_or(0);
                // Not a silent loss: a same-file redeclaration is
                // already a schema finding, an identical layer loses
                // nothing, and an empty earlier layer has no entries
                // to drop — record the plain write instead.
                if prev.as_path() == path || existing == doc_profiles.get(name) || count == 0 {
                    cx.prov.set(format!("profile {name:?}"), path, line);
                } else {
                    cx.prov.replace_profile(name, path, line, prev, count);
                }
            }
            None => cx.prov.set(format!("profile {name:?}"), path, line),
        }
        cx.profile_files.insert(name.clone(), path.to_path_buf());
    }
    cx.profiles.extend(doc_profiles);

    let this_policy = parse_kdl_policy_with_profiles(&content, cx.profiles, Some(base_dir))?;

    // Every file in the chain declares a supported `policy version` —
    // otherwise an ancestor's unknown version would ride the child's.
    if !(MIN_SUPPORTED_VERSION..=MAX_SUPPORTED_VERSION).contains(&this_policy.version) {
        return Err(PolicyError::Validation(format!(
            "unsupported policy version {}, expected {MIN_SUPPORTED_VERSION}..={MAX_SUPPORTED_VERSION} in '{}'",
            this_policy.version,
            path.display(),
        )));
    }
    // Schema strictness: v2 refuses declarations the grammar would drop
    // silently; v1 keeps the lax parse but warns for each one.
    crate::policy::kdl_strict::check_doc_schema(
        &doc,
        path,
        &content,
        this_policy.version,
        cx.warnings,
    )?;
    let doc_decl = OverlayDecl::for_doc(&doc, path, &content);

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
        merge_into_policy(&mut policy, &this_policy, &doc_decl, path, cx.prov);
        for weakened in posture.weakened(&policy) {
            pending.push_weakened(path, weakened);
        }
        if had_listen && doc_decl.network && !doc_decl.network_inbound {
            pending.push_inbound(path);
        }
    } else {
        // A single-document load takes the parse result as-is — merging
        // would normalize the declared lists (deny pruning, rule sort).
        // The provenance log still needs this file's writes, so run the
        // same merge against a discarded seed.
        let mut sink = Policy::default();
        merge_into_policy(&mut sink, &this_policy, &doc_decl, path, cx.prov);
        policy = this_policy;
    }
    decl.merge(&doc_decl);

    // ── Step 4: Process `when environment="xxx" { ... }` ──────────
    let posture = SecurityPosture::capture(&policy);
    let when_decl = apply_when_overrides(
        &doc,
        &mut policy,
        env,
        cx.profiles,
        Some(base_dir),
        path,
        &content,
        &mut pending,
        cx.prov,
    )?;
    for weakened in posture.weakened(&policy) {
        pending.push_weakened(path, weakened);
    }
    decl.merge(&when_decl);
    rematerialize_inherited_defaults(&mut policy);

    Ok((policy, decl, pending))
}

/// The entries a profile layer carries — the count a redefinition's
/// `replaced` reports for the layer it dropped.
fn layer_entry_count(layer: &PolicyLayer) -> usize {
    let mut n = 0;
    if let Some(fs) = &layer.fs {
        n += fs.allowed_paths.len() + fs.denied_paths.len();
    }
    if let Some(sc) = &layer.syscalls {
        n += sc.allowed.len() + sc.denied.len();
    }
    if let Some(net) = &layer.network {
        n += net.allowed_hosts.len()
            + net.allowed_cidrs.len()
            + net.denied_hosts.len()
            + net.denied_cidrs.len()
            + net.egress_rules.len();
    }
    n
}

mod overlay;

use overlay::{
    OverlayDecl, PendingWarnings, SecurityPosture, apply_when_overrides, merge_into_policy,
};
pub(crate) use overlay::{
    node_line, rematerialize_inherited_defaults, tool_fs_base, tool_network_base,
};

#[cfg(test)]
mod tests;
