//! Overlay-merge semantics for extends/include/when: how an overlay document
//! field set merges onto a base Policy, and how the final per-tool grants are
//! rematerialized from the merged defaults.

use std::path::Path;

use kdl::{KdlDocument, KdlNode};

use crate::policy::provenance::Provenance;
use crate::policy::validator::deny_pattern_covers;

mod decl;
mod merge;
mod posture;
mod tool;
mod when;

pub(super) use decl::OverlayDecl;
pub(super) use merge::merge_into_policy;
#[cfg(test)]
pub(super) use posture::WeakenedPosture;
pub(super) use posture::{PendingWarnings, SecurityPosture};
pub(crate) use tool::{rematerialize_inherited_defaults, tool_fs_base, tool_network_base};
pub(super) use when::apply_when_overrides;

/// True when a deny spelling in `denies` covers `allow` — the deny-wins
/// predicate the additive OS rulesets require (no negative rules exist
/// to carve a covered allow back out).
pub(super) fn fs_deny_covers(denies: &[String], allow: &str) -> bool {
    denies.iter().any(|d| deny_pattern_covers(d, allow))
}

/// Retain/report step the allow-list pruning passes share: drop every
/// `list` entry `covered` flags and record the prune under `field`, so
/// the deny-wins and narrower-grant passes cannot drift apart.
pub(super) fn prune_covered(
    list: &mut Vec<String>,
    covered: impl Fn(&String) -> bool,
    prov: &mut Provenance,
    field: &str,
    file: &Path,
    line: Option<u32>,
) {
    let dropped: Vec<String> = list.iter().filter(|p| covered(p)).cloned().collect();
    list.retain(|p| !dropped.contains(p));
    if !dropped.is_empty() {
        prov.prune(field, file, line, dropped);
    }
}

/// The 1-based line a node starts on inside its source text — `None`
/// when the span lies outside the content (should not happen for a
/// document parsed from it).
pub(crate) fn node_line(content: &str, node: &KdlNode) -> Option<u32> {
    let offset = node.span().offset();
    (offset <= content.len())
        .then(|| content[..offset].bytes().filter(|b| *b == b'\n').count() as u32 + 1)
}

/// The provenance field key for a tool declaration — server-scoped
/// tools are `server "s".tool "t"`; unscoped (never produced by the
/// grammar, kept for completeness) are `tool "t"`.
pub(crate) fn tool_key(server: Option<&str>, name: &str) -> String {
    match server {
        Some(s) => format!("server {s:?}.tool {name:?}"),
        None => format!("tool {name:?}"),
    }
}

/// A bare `allow host="*"` / `deny host="*"` inside `defaults.network`
/// declares the outbound posture; the same spelling carrying `proto=`/
/// `port=` is a scoped rule, not a posture — mirroring the parser's
/// posture test.
pub(super) fn declares_network_posture(net_children: &KdlDocument) -> bool {
    net_children.nodes().iter().any(|n| {
        matches!(n.name().value(), "allow" | "deny")
            && n.get("host").and_then(|v| v.as_string()) == Some("*")
            && n.get("proto").is_none()
            && n.get("port").is_none()
    })
}
