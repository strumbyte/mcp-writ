//! Composition-rules version diff — the engine behind
//! `policy resolve --version-diff` (PR-28), shared with `check`'s
//! version-3 migration preview (PR-36).
//!
//! Replays a policy's load under the other composition-rules version
//! and reports which effective fields the rule change moves — union-
//! vs-replace defaults, deny pruning, profile composition. The
//! simulated load only changes merge semantics; declaration grammar
//! stays at each file's declared version, so a v3 document never gets
//! rejected for carrying v3 syntax while the diff counts what v2 rules
//! would have granted.

use std::collections::BTreeMap;
use std::path::Path;

use crate::execution::ExecutionTarget;
use crate::policy::Policy;
use crate::policy::kdl_loader::load_kdl_policy_for_target_scanned_rules;

/// One effective-field difference between the declared-rules load and
/// the simulated other-rules load.
pub struct VersionFieldDiff {
    pub field: String,
    /// Sorted effective value under the document's declared rules.
    pub declared: Vec<String>,
    /// Sorted effective value under the simulated other rules version.
    pub simulated: Vec<String>,
}

/// The `--version-diff` result: either the field list, or the simulated
/// load's failure (a document that the other rules version cannot
/// compose — e.g. strict-shape validation — is itself the finding).
pub enum VersionDiff {
    Diff {
        declared: u32,
        simulated: u32,
        fields: Vec<VersionFieldDiff>,
    },
    SimFailed {
        declared: u32,
        simulated: u32,
        reason: String,
    },
}

impl VersionDiff {
    /// `kdl`-mode rendering — one `//` comment header plus one line per
    /// moved field, safe to keep inline ahead of the document.
    pub fn comment_lines(&self) -> Vec<String> {
        let (declared, simulated) = match self {
            Self::Diff {
                declared,
                simulated,
                ..
            }
            | Self::SimFailed {
                declared,
                simulated,
                ..
            } => (*declared, *simulated),
        };
        let mut lines = Vec::new();
        match self {
            Self::Diff { fields, .. } => {
                lines.push(format!(
                    "version-diff: declared v{declared} vs simulated v{simulated} — \
                     {} field(s) differ",
                    fields.len()
                ));
                for d in fields {
                    lines.push(format!(
                        "version-diff: {}: v{declared}={:?} v{simulated}={:?}",
                        d.field, d.declared, d.simulated
                    ));
                }
            }
            Self::SimFailed { reason, .. } => {
                lines.push(format!(
                    "version-diff: simulated v{simulated} load failed: {reason}"
                ));
            }
        }
        lines
            .into_iter()
            .map(|l| {
                // Field values carry declared spellings — every code
                // point KDL counts as a newline (including U+2028/29,
                // which `sanitize_for_terminal` misses) must not end
                // the `//` comment and reparse as policy nodes.
                crate::termutil::escape_kdl_comment(&l)
            })
            .collect()
    }
}

/// Replay the load under the other composition-rules version and diff
/// the two effective policies field-by-field. Declared v3 simulates v2
/// (and vice versa); the diff says nothing when no effective field
/// moves — composition without overlaps looks identical either way.
/// `server` is the same binding selector the caller applied to
/// `declared` so the simulated policy is compared at the same scope.
pub fn compute_version_diff(
    policy_path: &Path,
    env: &str,
    server: Option<&str>,
    declared: &Policy,
) -> VersionDiff {
    let declared_version = declared.version;
    let sim_version = if declared_version >= 3 { 2 } else { 3 };
    match load_kdl_policy_for_target_scanned_rules(
        policy_path,
        env,
        &ExecutionTarget::native(),
        Some(sim_version),
    )
    .and_then(|(p, _)| p.bind_to_server(server))
    {
        Ok(simulated) => {
            let a = effective_field_map(declared);
            let b = effective_field_map(&simulated);
            let mut fields = Vec::new();
            for (k, dv) in &a {
                let sv = b.get(k).cloned().unwrap_or_default();
                if *dv != sv {
                    fields.push(VersionFieldDiff {
                        field: k.clone(),
                        declared: dv.clone(),
                        simulated: sv,
                    });
                }
            }
            for (k, sv) in &b {
                if !a.contains_key(k) {
                    fields.push(VersionFieldDiff {
                        field: k.clone(),
                        declared: Vec::new(),
                        simulated: sv.clone(),
                    });
                }
            }
            VersionDiff::Diff {
                declared: declared_version,
                simulated: sim_version,
                fields,
            }
        }
        Err(e) => VersionDiff::SimFailed {
            declared: declared_version,
            simulated: sim_version,
            reason: crate::termutil::sanitize_for_terminal(&format!("{e}")),
        },
    }
}

/// Flatten a composed policy to `{field -> sorted values}` so the two
/// rules versions can be compared entry-for-entry. Only effective
/// grants and postures appear — declaration bookkeeping (`*_explicit`,
/// `replace` flags) is exactly what the version diff abstracts away.
fn effective_field_map(policy: &Policy) -> BTreeMap<String, Vec<String>> {
    use crate::policy::EgressRule;
    let mut m: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut put = |k: &str, mut v: Vec<String>| {
        v.sort();
        v.dedup();
        m.insert(k.to_string(), v);
    };
    let scalar = |v: bool| vec![v.to_string()];

    put("defaults.filesystem.read-only", policy.fs.read_only.clone());
    put(
        "defaults.filesystem.read-write",
        policy.fs.read_write.clone(),
    );
    put(
        "defaults.filesystem.executable",
        policy.fs.executable.clone(),
    );
    put("defaults.filesystem.denied", policy.fs.denied_paths.clone());
    put(
        "defaults.filesystem.secret-overlay",
        scalar(policy.fs.secret_overlay),
    );
    put("defaults.syscalls.allowed", policy.syscalls.allowed.clone());
    put("defaults.syscalls.denied", policy.syscalls.denied.clone());
    put(
        "defaults.network.allow",
        policy
            .network
            .outbound
            .allowed
            .iter()
            .cloned()
            .chain(
                policy
                    .network
                    .outbound
                    .allowed_cidrs
                    .iter()
                    .map(|c| format!("cidr:{c}")),
            )
            .collect(),
    );
    put(
        "defaults.network.deny",
        policy
            .network
            .outbound
            .denied_hosts
            .iter()
            .cloned()
            .chain(
                policy
                    .network
                    .outbound
                    .denied_cidrs
                    .iter()
                    .map(|c| format!("cidr:{c}")),
            )
            .collect(),
    );
    put(
        "defaults.network.deny-all-others",
        scalar(policy.network.outbound.deny_all_others),
    );
    put(
        "defaults.network.inbound",
        scalar(policy.network.inbound.allow_listen),
    );
    put(
        "defaults.network.egress",
        policy
            .network
            .outbound
            .egress_rules
            .iter()
            .map(EgressRule::describe)
            .collect(),
    );
    put(
        "defaults.environment.allowed",
        policy.environment.allowed.clone(),
    );
    put(
        "defaults.environment.restrict",
        scalar(policy.environment.restrict && !policy.environment.inherit_parent),
    );

    for tool in &policy.tools {
        let key = match &tool.server {
            Some(s) => format!("server \"{s}\" tool \"{}\"", tool.name),
            None => format!("tool \"{}\"", tool.name),
        };
        put(&format!("{key}.allowed"), scalar(tool.allowed));
        if let Some(ref side) = tool.side_effect {
            put(&format!("{key}.side-effect"), vec![side.clone()]);
        }
        if let Some(ref fs) = tool.fs {
            put(
                &format!("{key}.filesystem.allowed"),
                fs.allowed_paths.clone(),
            );
            put(
                &format!("{key}.filesystem.read-only"),
                fs.read_only_paths.clone(),
            );
            put(
                &format!("{key}.filesystem.read-write"),
                fs.read_write_paths.clone(),
            );
            put(&format!("{key}.filesystem.denied"), fs.denied_paths.clone());
            if let Some(rp) = fs.require_path {
                put(&format!("{key}.filesystem.require-path"), scalar(rp));
            }
        }
        if let Some(ref sc) = tool.syscalls {
            put(&format!("{key}.syscalls.allowed"), sc.allowed.clone());
            put(&format!("{key}.syscalls.denied"), sc.denied.clone());
        }
        if let Some(ref net) = tool.network {
            put(
                &format!("{key}.network.allow"),
                net.allowed_hosts
                    .iter()
                    .cloned()
                    .chain(net.allowed_cidrs.iter().map(|c| format!("cidr:{c}")))
                    .collect(),
            );
            put(
                &format!("{key}.network.deny"),
                net.denied_hosts
                    .iter()
                    .cloned()
                    .chain(net.denied_cidrs.iter().map(|c| format!("cidr:{c}")))
                    .collect(),
            );
            put(
                &format!("{key}.network.egress"),
                net.egress_rules.iter().map(EgressRule::describe).collect(),
            );
        }
    }
    m
}
