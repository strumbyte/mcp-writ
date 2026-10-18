//! Overlay-merge semantics for extends/include/when: how an overlay document
//! field set merges onto a base Policy, and how the final per-tool grants are
//! rematerialized from the merged defaults.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kdl::{KdlDocument, KdlNode};

use crate::error::PolicyError;
use crate::policy::kdl_parse::{
    Defaults, defaults_to_layer, parse_deputy_node, parse_environment_node, parse_fs_allows,
    parse_logging_fail_closed, parse_network_rules, parse_process_exec_allowed,
    parse_server_hashes, parse_server_mcp_rules, parse_servers, parse_syscall_allows,
    parse_tool_fs, parse_tool_network, parse_tool_syscalls, parse_tools_list_hashes,
    parse_trajectory, resolve_tool_args_schema, unique_child, validate_logging_level,
    validate_tool_shape_v2,
};
use crate::policy::merge::PolicyLayer;
use crate::policy::provenance::{DeclOrigin, LoadWarning, LoadWarningKind, Provenance};
use crate::policy::validator::deny_pattern_covers;

/// True when a deny spelling in `denies` covers `allow` — the deny-wins
/// predicate the additive OS rulesets require (no negative rules exist
/// to carve a covered allow back out).
fn fs_deny_covers(denies: &[String], allow: &str) -> bool {
    denies.iter().any(|d| deny_pattern_covers(d, allow))
}
use crate::policy::{
    EnvironmentPolicy, FsPolicy, FsToolPolicy, InputResponsesMode, NetworkPolicy, Policy,
    ToolNetworkPolicy, ToolPolicy, ToolSyscallPolicy, TrajectoryRule,
};

/// Which optional fields the overlay side declared — computed from the
/// overlay document itself for a same-file (`extends`) merge, or
/// accumulated across the included file's whole subtree (its
/// `extends`/`include` ancestors plus matching `when` blocks) for an
/// `include` merge. The subtree view keeps ancestor- and `when`-derived
/// values from silently dropping: node presence in the one included
/// file cannot see them.
#[derive(Debug, Default, Clone)]
pub(super) struct OverlayDecl {
    pub(super) transport: bool,
    pub(super) logging: bool,
    pub(super) sandbox: bool,
    pub(super) confused_deputy_protection: bool,
    pub(super) trajectory: bool,
    /// A `defaults { filesystem { … } }` block — gates `secret-overlay`
    /// (omitted on a declared block stays default-on, fail-secure).
    pub(super) defaults_filesystem: bool,
    /// A `defaults.network` block carrying children — re-touching
    /// network without restating `inbound` while a listener grant is
    /// in force widens silently, so the merge warns. A childless
    /// `network` node declares nothing (posture and `inbound` both
    /// require children), so it does not flag.
    pub(super) network: bool,
    /// A bare `allow host="*"` / `deny host="*"` posture node inside
    /// `defaults.network` — the only declaration that moves
    /// `deny_all_others`.
    pub(super) network_posture: bool,
    /// An `inbound` child inside `defaults.network` — the only
    /// declaration that moves `inbound.allow_listen`.
    pub(super) network_inbound: bool,
    /// Where each declared field's node lives — file plus the 1-based
    /// line of the declaring node. Keys: `policy`, `transport`,
    /// `logging`, `sandbox`, `confused_deputy_protection`, `trajectory`,
    /// `defaults.filesystem`, `defaults.syscalls`, `defaults.network`,
    /// `defaults.environment`, `server "s"`, `server "s".tool "t"`,
    /// `profile "name"`. Across an include merge the origins travel
    /// with the decl, so a replacement recorded at the boundary names
    /// the file and node that actually wrote the overlay value.
    pub(super) origins: HashMap<String, DeclOrigin>,
}

/// The 1-based line a node starts on inside its source text — `None`
/// when the span lies outside the content (should not happen for a
/// document parsed from it).
pub(crate) fn node_line(content: &str, node: &KdlNode) -> Option<u32> {
    let offset = node.span().offset();
    (offset <= content.len())
        .then(|| content[..offset].bytes().filter(|b| *b == b'\n').count() as u32 + 1)
}

/// The line the `server "name"` node starts on — attribution for the
/// entries `parse_server_*` collect from inside it (`mcp` rules,
/// hash entries, tools-list pins).
fn server_node_line(doc: &KdlDocument, content: &str, server_name: Option<&str>) -> Option<u32> {
    doc.nodes()
        .iter()
        .find(|n| {
            n.name().value() == "server" && n.get(0).and_then(|v| v.as_string()) == server_name
        })
        .and_then(|n| node_line(content, n))
}

/// The flat allow-side items a tool `network` block carries — hosts,
/// cidrs, and the `describe`d allow rules. One ordering feeds the
/// merge provenance, the new-tool seed, and rematerialization.
fn tool_net_allow_items(net: &ToolNetworkPolicy) -> Vec<String> {
    net.allowed_hosts
        .iter()
        .cloned()
        .chain(net.allowed_cidrs.iter().cloned())
        .chain(
            net.egress_rules
                .iter()
                .filter(|r| r.allow)
                .map(|r| r.describe()),
        )
        .collect()
}

/// The flat deny-side counterpart of [`tool_net_allow_items`].
fn tool_net_deny_items(net: &ToolNetworkPolicy) -> Vec<String> {
    net.denied_hosts
        .iter()
        .cloned()
        .chain(net.denied_cidrs.iter().cloned())
        .chain(
            net.egress_rules
                .iter()
                .filter(|r| !r.allow)
                .map(|r| r.describe()),
        )
        .collect()
}

/// Whether `item` — a flat host, a flat `addr/prefix` cidr, or an
/// `EgressRule::describe` spelling — is covered by `denied_hosts` /
/// `denied_cidrs`: the deny-wins test that decides whether a
/// rematerialized drop is a declared deny's consequence (`prune`) or
/// a silent replacement (`replace`). `unix=` opt-ins sit outside the
/// host/IP deny model and are never deny-covered.
fn net_item_covered_by_deny(item: &str, denied_hosts: &[String], denied_cidrs: &[String]) -> bool {
    let first = item.split_whitespace().next().unwrap_or(item);
    let (cidr, dest) = match first.split_once('=') {
        Some(("host", v)) => (false, v),
        Some(("cidr", v)) => (true, v),
        Some(("unix", _)) => return false,
        // Flat entries carry no `kind=`: an `addr/prefix` is a cidr,
        // anything else is a name-layer host.
        _ => (
            crate::policy::host::analyze_policy_cidr(first).is_ok(),
            first,
        ),
    };
    if cidr {
        // The IP-layer deny set — `denied_cidrs` plus IP literals in
        // `denied_hosts`, the same set `apply_tool_network_deny_precedence`
        // reduces against.
        let denied_ip: Vec<String> = denied_cidrs
            .iter()
            .cloned()
            .chain(denied_hosts.iter().filter_map(|h| {
                h.parse::<std::net::IpAddr>()
                    .ok()
                    .map(crate::policy::host::ip_literal_cidr)
            }))
            .collect();
        denied_hosts.iter().any(|d| d == "*")
            || denied_ip
                .iter()
                .any(|d| crate::policy::host::cidr_covers(d, dest))
    } else {
        denied_hosts
            .iter()
            .any(|d| crate::policy::host_covered_by_deny(dest, d))
    }
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

impl OverlayDecl {
    /// Declarations in a top-level policy document.
    pub(super) fn for_doc(doc: &KdlDocument, file: &Path, content: &str) -> Self {
        let mut decl = Self {
            transport: doc.get("transport").is_some(),
            ..Self::default()
        };
        for node in doc.nodes() {
            let origin = DeclOrigin {
                file: file.to_path_buf(),
                line: node_line(content, node),
            };
            match node.name().value() {
                "policy"
                | "transport"
                | "logging"
                | "sandbox"
                | "confused_deputy_protection"
                | "trajectory" => {
                    decl.origins.insert(node.name().value().to_string(), origin);
                }
                "server" => {
                    let server_name = node.get(0).and_then(|v| v.as_string()).map(String::from);
                    if let Some(ref s) = server_name {
                        decl.origins.insert(format!("server {s:?}"), origin.clone());
                    }
                    if let Some(children) = node.children() {
                        for child in children.nodes() {
                            if child.name().value() == "tool"
                                && let Some(t) = child.get(0).and_then(|v| v.as_string())
                            {
                                decl.origins.insert(
                                    tool_key(server_name.as_deref(), t),
                                    DeclOrigin {
                                        file: file.to_path_buf(),
                                        line: node_line(content, child),
                                    },
                                );
                            }
                        }
                    }
                }
                "profile" => {
                    if let Some(name) = node.get(0).and_then(|v| v.as_string()) {
                        decl.origins.insert(format!("profile {name:?}"), origin);
                    }
                }
                _ => {}
            }
        }
        decl.absorb_shared(doc, file, content);
        decl
    }

    /// Declarations inside a matching `when` block's children — the
    /// fields `apply_overrides_from_doc` can apply. `transport` is not
    /// one of them, so it stays unset.
    fn for_when_children(children: &KdlDocument, file: &Path, content: &str) -> Self {
        let mut decl = Self::default();
        decl.absorb_shared(children, file, content);
        // Origins for the server-side overrides the when path applies —
        // tool merges inside `when` attribute to the tool nodes here.
        for node in children.nodes() {
            if node.name().value() != "server" {
                continue;
            }
            let server_name = node.get(0).and_then(|v| v.as_string()).map(String::from);
            if let Some(sc) = node.children() {
                for child in sc.nodes() {
                    if child.name().value() == "tool"
                        && let Some(t) = child.get(0).and_then(|v| v.as_string())
                    {
                        decl.origins.insert(
                            tool_key(server_name.as_deref(), t),
                            DeclOrigin {
                                file: file.to_path_buf(),
                                line: node_line(content, child),
                            },
                        );
                    }
                }
            }
        }
        decl
    }

    /// Flags both scopes share: every overlay-able top-level node other
    /// than `transport`, plus the `defaults` children gates and the
    /// origins for the nodes that set them.
    fn absorb_shared(&mut self, doc: &KdlDocument, file: &Path, content: &str) {
        for name in [
            "logging",
            "sandbox",
            "confused_deputy_protection",
            "trajectory",
        ] {
            if let Some(node) = doc.get(name) {
                match name {
                    "logging" => self.logging = true,
                    "sandbox" => self.sandbox = true,
                    "confused_deputy_protection" => self.confused_deputy_protection = true,
                    _ => self.trajectory = true,
                }
                self.origins.insert(
                    name.to_string(),
                    DeclOrigin {
                        file: file.to_path_buf(),
                        line: node_line(content, node),
                    },
                );
            }
        }
        if let Some(defaults) = doc.get("defaults").and_then(|d| d.children()) {
            for name in ["filesystem", "syscalls", "network", "environment"] {
                if let Some(node) = defaults.get(name) {
                    self.origins.insert(
                        format!("defaults.{name}"),
                        DeclOrigin {
                            file: file.to_path_buf(),
                            line: node_line(content, node),
                        },
                    );
                }
            }
            self.defaults_filesystem |= defaults.get("filesystem").is_some();
            // `network` needs children to declare anything — a bare
            // node moves no value, so it must not trigger the
            // inherited-inbound warning either.
            if let Some(net_children) = defaults.get("network").and_then(|n| n.children()) {
                self.network = true;
                self.network_inbound |= net_children.get("inbound").is_some();
                self.network_posture |= declares_network_posture(net_children);
            }
        }
    }

    /// Union another scope's declarations into this one — origins take
    /// the later scope's entries: the declaration applied last is the
    /// writer a replace should name.
    pub(super) fn merge(&mut self, other: &Self) {
        self.transport |= other.transport;
        self.logging |= other.logging;
        self.sandbox |= other.sandbox;
        self.confused_deputy_protection |= other.confused_deputy_protection;
        self.trajectory |= other.trajectory;
        self.defaults_filesystem |= other.defaults_filesystem;
        self.network |= other.network;
        self.network_posture |= other.network_posture;
        self.network_inbound |= other.network_inbound;
        self.origins
            .extend(other.origins.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    /// The origin recorded for `key`, or the merge's file with no line
    /// (a flag can be set by a subtree whose node position was not
    /// tracked — fall back to the file being merged).
    pub(super) fn origin<'a>(&'a self, key: &str, file: &'a Path) -> (&'a Path, Option<u32>) {
        self.origins
            .get(key)
            .map(|o| (o.file.as_path(), o.line))
            .unwrap_or((file, None))
    }
}

/// Record a newly declared tool's per-field contents — only the
/// fields the tool itself declared (`*_explicit`). Entries the merge
/// materialized from defaults are attributed to the defaults' own
/// writers via `sources`; entries the sources do not know — the tool's
/// own declarations or ones a profile/`server-defaults` layer carried —
/// fall back to `origin` (the tool declaration site). Fields the tool
/// did not declare are materialized — and attributed — by
/// [`rematerialize_inherited_defaults`] instead.
fn seed_tool_fields(
    prov: &mut Provenance,
    key: &str,
    tool: &ToolPolicy,
    origin: (&Path, Option<u32>),
) {
    if tool.fs_explicit
        && let Some(fs) = &tool.fs
    {
        prov.reproject(
            format!("{key}.filesystem.allowed"),
            origin,
            fs.allowed_paths.clone(),
            &[
                "defaults.filesystem.read_only",
                "defaults.filesystem.read_write",
            ],
            |_| false,
        );
        prov.reproject(
            format!("{key}.filesystem.denied"),
            origin,
            fs.denied_paths.clone(),
            &["defaults.filesystem.denied"],
            |_| false,
        );
    }
    if tool.syscalls_explicit
        && let Some(sc) = &tool.syscalls
    {
        prov.reproject(
            format!("{key}.syscalls.allowed"),
            origin,
            sc.allowed.clone(),
            &["defaults.syscalls"],
            |_| false,
        );
        // A tool-declared deny has no defaults source — attribution
        // falls back to the declaration site.
        prov.reproject(
            format!("{key}.syscalls.denied"),
            origin,
            sc.denied.clone(),
            &[],
            |_| false,
        );
    }
    if tool.network_explicit
        && let Some(net) = &tool.network
    {
        prov.reproject(
            format!("{key}.network.allow"),
            origin,
            tool_net_allow_items(net),
            &["defaults.network.allow"],
            |_| false,
        );
        prov.reproject(
            format!("{key}.network.deny"),
            origin,
            tool_net_deny_items(net),
            &["defaults.network.deny"],
            |_| false,
        );
    }
}

/// A bare `allow host="*"` / `deny host="*"` inside `defaults.network`
/// declares the outbound posture; the same spelling carrying `proto=`/
/// `port=` is a scoped rule, not a posture — mirroring the parser's
/// posture test.
fn declares_network_posture(net_children: &KdlDocument) -> bool {
    net_children.nodes().iter().any(|n| {
        matches!(n.name().value(), "allow" | "deny")
            && n.get("host").and_then(|v| v.as_string()) == Some("*")
            && n.get("proto").is_none()
            && n.get("port").is_none()
    })
}

/// The fail-secure settings an overlay application can move in the
/// weakening direction — captured before each merge so the merge can
/// record which postures it relaxed. An overlay applies declared
/// values symmetrically, so a declaration riding an included subtree
/// (an ancestor's or a matching `when` block's) can silently downgrade
/// a posture the including file never asked about: `confused_deputy_
/// protection #false`, `trajectory #false` or dropped trajectory
/// rules, a different non-default `logging level`, `fail_closed
/// #false`, `sandbox allow_degraded=#true`, `secret-overlay #false`,
/// an open `allow host="*"` outbound posture, an `inbound` listener
/// grant, or a relaxed `environment` restriction. The same applies to
/// an extending file's own declarations, which the operator reviewing
/// the parent policy cannot see. Each weakening is surfaced once —
/// deferred and re-validated against the final merged policy (see
/// [`WeakenedPosture::message`]) so a later declaration that restores
/// the posture does not leave a stale warning behind.
#[derive(Debug)]
pub(super) struct SecurityPosture {
    confused_deputy_protection: bool,
    trajectory: bool,
    trajectory_rules: Vec<TrajectoryRule>,
    logging_level: String,
    logging_fail_closed: bool,
    sandbox_allow_degraded: bool,
    secret_overlay: bool,
    deny_all_others: bool,
    allow_listen: bool,
    environment_restrict: bool,
    environment_allowed: Vec<String>,
}

impl SecurityPosture {
    pub(super) fn capture(policy: &Policy) -> Self {
        Self {
            confused_deputy_protection: policy.confused_deputy_protection,
            trajectory: policy.trajectory,
            trajectory_rules: policy.trajectory_rules.clone(),
            logging_level: policy.logging.level.clone(),
            logging_fail_closed: policy.logging.fail_closed,
            sandbox_allow_degraded: policy.sandbox.allow_degraded,
            secret_overlay: policy.fs.secret_overlay,
            deny_all_others: policy.network.outbound.deny_all_others,
            allow_listen: policy.network.inbound.allow_listen,
            environment_restrict: policy.environment.restrict,
            environment_allowed: policy.environment.allowed.clone(),
        }
    }

    /// The weakenings `after` carries relative to this snapshot.
    /// `"info"` as the before-level means the logging level was never
    /// chosen — there is no posture to weaken (mirroring the pre-decl
    /// include clamp, which let only a non-`info` level move an
    /// `info`-level base).
    pub(super) fn weakened(&self, after: &Policy) -> Vec<WeakenedPosture> {
        let mut weakened = Vec::new();
        if self.confused_deputy_protection && !after.confused_deputy_protection {
            weakened.push(WeakenedPosture::ConfusedDeputyProtection);
        }
        if self.trajectory && !after.trajectory {
            weakened.push(WeakenedPosture::Trajectory);
        } else if after.trajectory {
            let dropped: Vec<_> = self
                .trajectory_rules
                .iter()
                .filter(|r| !after.trajectory_rules.contains(r))
                .cloned()
                .collect();
            if !dropped.is_empty() {
                weakened.push(WeakenedPosture::TrajectoryRules(dropped));
            }
        }
        if self.logging_level != "info" && after.logging.level != self.logging_level {
            weakened.push(WeakenedPosture::LoggingLevel(self.logging_level.clone()));
        }
        if self.logging_fail_closed && !after.logging.fail_closed {
            weakened.push(WeakenedPosture::LoggingFailClosed);
        }
        if !self.sandbox_allow_degraded && after.sandbox.allow_degraded {
            weakened.push(WeakenedPosture::SandboxAllowDegraded);
        }
        if self.secret_overlay && !after.fs.secret_overlay {
            weakened.push(WeakenedPosture::SecretOverlay);
        }
        if self.deny_all_others && !after.network.outbound.deny_all_others {
            weakened.push(WeakenedPosture::OutboundPosture);
        }
        if !self.allow_listen && after.network.inbound.allow_listen {
            weakened.push(WeakenedPosture::InboundListen);
        }
        if self.environment_restrict && !after.environment.restrict {
            weakened.push(WeakenedPosture::EnvironmentRestrict);
        } else if self.environment_restrict
            && after.environment.restrict
            && after
                .environment
                .allowed
                .iter()
                .any(|v| !self.environment_allowed.contains(v))
        {
            // An allow list that gained names is a weakening only while
            // the restriction held on both sides — re-imposing
            // restriction on an unrestricted base is a strengthening.
            weakened.push(WeakenedPosture::EnvironmentAllowed(
                self.environment_allowed.clone(),
            ));
        }
        weakened
    }
}

/// One weakening observed across a single overlay application. The
/// variant carries the state needed to re-validate against the final
/// merged policy — a later declaration may have restored the posture,
/// in which case the warning must not fire.
#[derive(Debug, PartialEq)]
pub(super) enum WeakenedPosture {
    ConfusedDeputyProtection,
    /// `trajectory` flag turned off (the rules go with it).
    Trajectory,
    /// Trajectory rules dropped while the flag stayed on — the payload
    /// holds the rules lost at that merge.
    TrajectoryRules(Vec<TrajectoryRule>),
    /// `logging level` moved off an explicitly chosen level — the
    /// payload is the previous level.
    LoggingLevel(String),
    LoggingFailClosed,
    SandboxAllowDegraded,
    SecretOverlay,
    /// `deny host="*"` posture opened to `allow host="*"`.
    OutboundPosture,
    /// `inbound allow=#true` granted where none was.
    InboundListen,
    /// `environment` restriction lifted via `inherit-parent`.
    EnvironmentRestrict,
    /// `environment` allow list widened — the payload is the previous
    /// list, so the message names the variables still gained.
    EnvironmentAllowed(Vec<String>),
}

impl WeakenedPosture {
    /// True when `other` is the same weakening variant — used by
    /// tests to locate a kind regardless of its payload.
    #[cfg(test)]
    pub(super) fn same_kind(&self, other: &Self) -> bool {
        std::mem::discriminant(self) == std::mem::discriminant(other)
    }

    /// Warning text while the weakening is still in effect on the
    /// final merged policy — `None` once a later declaration restored
    /// the posture.
    pub(super) fn message(&self, policy: &Policy) -> Option<String> {
        match self {
            Self::ConfusedDeputyProtection => (!policy.confused_deputy_protection)
                .then(|| "disables 'confused_deputy_protection'".to_string()),
            Self::Trajectory => {
                (!policy.trajectory).then(|| "disables 'trajectory' recording".to_string())
            }
            Self::TrajectoryRules(dropped) => {
                let still = dropped
                    .iter()
                    .filter(|r| !policy.trajectory_rules.contains(r))
                    .count();
                (still > 0).then(|| format!("drops {still} inherited 'trajectory' rule(s)"))
            }
            Self::LoggingLevel(from) => (policy.logging.level != *from).then(|| {
                format!(
                    "moves 'logging level' from '{from}' to '{}'",
                    policy.logging.level
                )
            }),
            Self::LoggingFailClosed => {
                (!policy.logging.fail_closed).then(|| "disables 'logging fail_closed'".to_string())
            }
            Self::SandboxAllowDegraded => (policy.sandbox.allow_degraded)
                .then(|| "enables 'sandbox allow_degraded'".to_string()),
            Self::SecretOverlay => {
                (!policy.fs.secret_overlay).then(|| "disables 'secret-overlay'".to_string())
            }
            Self::OutboundPosture => (!policy.network.outbound.deny_all_others)
                .then(|| "opens the outbound posture to 'allow host=\"*\"'".to_string()),
            Self::InboundListen => (policy.network.inbound.allow_listen)
                .then(|| "grants 'inbound allow=#true' listeners".to_string()),
            Self::EnvironmentRestrict => (!policy.environment.restrict).then(|| {
                "lifts 'defaults.environment' restriction via 'inherit-parent'".to_string()
            }),
            Self::EnvironmentAllowed(before) => {
                let gained: Vec<_> = policy
                    .environment
                    .allowed
                    .iter()
                    .filter(|v| !before.contains(v))
                    .collect();
                (policy.environment.restrict && !gained.is_empty()).then(|| {
                    format!(
                        "widens the 'environment' allow list with {}",
                        gained
                            .iter()
                            .map(|v| format!("'{v}'"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
            }
        }
    }
}

/// Warnings deferred to the end of the whole load. Each subtree
/// returns its pending entries to the caller rather than emitting them
/// against an intermediate merge state, so every warning is evaluated
/// once — against the policy the load actually produced: a later file
/// that restores the posture or closes the listener grant leaves no
/// stale warning behind.
#[derive(Debug, Default)]
pub(super) struct PendingWarnings {
    inbound: Vec<PathBuf>,
    weakened: Vec<(PathBuf, WeakenedPosture)>,
}

impl PendingWarnings {
    /// `path` re-declared `defaults.network` without `inbound` while a
    /// listener grant was live — warn at emit if the final policy
    /// still keeps it.
    pub(super) fn push_inbound(&mut self, path: &Path) {
        if !self.inbound.iter().any(|p| p == path) {
            self.inbound.push(path.to_path_buf());
        }
    }

    /// `path` weakened a fail-secure posture. Each distinct loss is
    /// kept — two merge points in the same file can produce the same
    /// kind with different payloads (the doc merge and a `when` block
    /// each dropping different trajectory rules), and discarding one
    /// would hide a loss the final policy still carries. Only exact
    /// duplicates are dropped here; warnings deduplicate at `emit`,
    /// after every entry has been evaluated.
    pub(super) fn push_weakened(&mut self, path: &Path, weakened: WeakenedPosture) {
        if !self
            .weakened
            .iter()
            .any(|(p, w)| p == path && *w == weakened)
        {
            self.weakened.push((path.to_path_buf(), weakened));
        }
    }

    /// A resolved subtree's pending entries join the caller's.
    pub(super) fn absorb(&mut self, other: Self) {
        for path in other.inbound {
            self.push_inbound(&path);
        }
        for (path, weakened) in other.weakened {
            self.push_weakened(&path, weakened);
        }
    }

    /// The warnings still in effect on the final merged policy —
    /// every retained entry is evaluated first (a restored posture
    /// yields no message), then identical warnings are deduplicated so
    /// a repeated loss reports once without hiding a distinct one.
    /// The load collects them into [`LoadDiagnostics`] so `plan`,
    /// `check` and `policy resolve` carry the same warnings the
    /// enforcing loaders print.
    pub(super) fn collect(&self, policy: &Policy, out: &mut Vec<LoadWarning>) {
        let mut seen = HashSet::new();
        if policy.network.inbound.allow_listen {
            for path in &self.inbound {
                if seen.insert((path.clone(), LoadWarningKind::Inbound, String::new())) {
                    out.push(LoadWarning {
                        kind: LoadWarningKind::Inbound,
                        file: path.clone(),
                        line: None,
                        message: "declares 'defaults.network' without 'inbound' — an \
                                 inherited `inbound allow=#true` grant stays in effect; \
                                 declare `inbound allow=#false` to refuse listeners"
                            .to_string(),
                    });
                }
            }
        }
        for (path, weakened) in &self.weakened {
            if let Some(message) = weakened.message(policy)
                && seen.insert((path.clone(), LoadWarningKind::Posture, message.clone()))
            {
                out.push(LoadWarning {
                    kind: LoadWarningKind::Posture,
                    file: path.clone(),
                    line: None,
                    message,
                });
            }
        }
    }

    /// The warning lines still in effect on the final merged policy —
    /// every retained entry is evaluated first (a restored posture
    /// yields no message), then identical lines are deduplicated so a
    /// repeated loss prints once without hiding a distinct one.
    #[cfg(test)]
    pub(super) fn warning_lines(&self, policy: &Policy) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut lines = Vec::new();
        for (path, weakened) in &self.weakened {
            if let Some(message) = weakened.message(policy) {
                let line = format!("'{}' {message}", path.display());
                if seen.insert(line.clone()) {
                    lines.push(line);
                }
            }
        }
        lines
    }
}

/// Merge `overlay` policy on top of `base` (in place).
///
/// - Scalar fields: overlay wins only when `decl` records the overlay
///   side declaring them. Network posture (`deny_all_others`) and
///   `inbound.allow_listen` are gated the same way — on the posture /
///   `inbound` sub-declaration inside `defaults.network`, never on the
///   block's presence alone, so a rules-only overlay resets neither.
/// - Allow lists: filesystem unions; network and syscalls replace when
///   the overlay specifies an allow side (environment replaces whenever
///   the overlay declared the node, even with an empty list)
/// - Deny lists: accumulated (union, sticky)
/// - Tools: overlay tool overrides specified fields; unspecified fields
///   inherited; deny is sticky. A tool's fs/network merge applies only
///   when the overlay tool declared the block (`fs_explicit`/
///   `network_explicit`/`syscalls_explicit`) — the same gate the
///   `when` path uses — so re-declaring a tool for an unrelated
///   property cannot widen or drop the base's scope.
///
/// Every write the merge performs is logged on `prov` — `file` is the
/// fallback attribution when the decl carries no node origin (e.g. a
/// flag set by an untracked subtree member); the decl's origins name
/// the file and line that actually declared each field.
pub(super) fn merge_into_policy(
    base: &mut Policy,
    overlay: &Policy,
    decl: &OverlayDecl,
    file: &Path,
    prov: &mut Provenance,
) {
    // version: overlay wins — every document declares `policy`.
    base.version = overlay.version;
    let (f, l) = decl.origin("policy", file);
    prov.set("version", f, l);

    // transport: overlay wins if the overlay side declared it
    if decl.transport {
        base.transport = overlay.transport.clone();
        let (f, l) = decl.origin("transport", file);
        prov.set("transport", f, l);
    }

    // fs: extends/include union allow lists; denies stay sticky.
    if overlay.fs.allow_specified {
        let (f, l) = decl.origin("defaults.filesystem", file);
        prov.union(
            "defaults.filesystem.read_only",
            f,
            l,
            overlay.fs.read_only.iter().cloned(),
        );
        prov.union(
            "defaults.filesystem.read_write",
            f,
            l,
            overlay.fs.read_write.iter().cloned(),
        );
        prov.union(
            "defaults.filesystem.executable",
            f,
            l,
            overlay.fs.executable.iter().cloned(),
        );
        for p in &overlay.fs.read_only {
            if !base.fs.read_only.contains(p) {
                base.fs.read_only.push(p.clone());
            }
        }
        for p in &overlay.fs.read_write {
            if !base.fs.read_write.contains(p) {
                base.fs.read_write.push(p.clone());
            }
        }
        for p in &overlay.fs.executable {
            if !base.fs.executable.contains(p) {
                base.fs.executable.push(p.clone());
            }
        }
        base.fs.allow_specified = true;
    }
    {
        let (f, l) = decl.origin("defaults.filesystem", file);
        prov.union(
            "defaults.filesystem.denied",
            f,
            l,
            overlay.fs.denied_paths.iter().cloned(),
        );
    }
    for denied in &overlay.fs.denied_paths {
        if !base.fs.denied_paths.contains(denied) {
            base.fs.denied_paths.push(denied.clone());
        }
    }
    // Deny-wins first: record each allow entry the retains drop with
    // the file that declared the covering deny.
    let denied_now = base.fs.denied_paths.clone();
    for (field, list) in [
        ("defaults.filesystem.read_only", &mut base.fs.read_only),
        ("defaults.filesystem.read_write", &mut base.fs.read_write),
        ("defaults.filesystem.executable", &mut base.fs.executable),
    ] {
        let dropped: Vec<String> = list
            .iter()
            .filter(|p| fs_deny_covers(&denied_now, p))
            .cloned()
            .collect();
        list.retain(|p| !dropped.contains(p));
        if !dropped.is_empty() {
            let (f, l) = decl.origin("defaults.filesystem", file);
            prov.prune(field, f, l, dropped);
        }
    }
    // Then the narrower-grant narrowing: a path spelled `mode="read"`
    // stays read-only even if it was also declared `mode="write"` or
    // `mode="exec"` — the narrower grant wins.
    let read_now = base.fs.read_only.clone();
    for (field, list) in [
        ("defaults.filesystem.read_write", &mut base.fs.read_write),
        ("defaults.filesystem.executable", &mut base.fs.executable),
    ] {
        let dropped: Vec<String> = list
            .iter()
            .filter(|p| read_now.contains(*p))
            .cloned()
            .collect();
        list.retain(|p| !dropped.contains(p));
        if !dropped.is_empty() {
            let (f, l) = decl.origin("defaults.filesystem", file);
            prov.prune(field, f, l, dropped);
        }
    }

    // syscalls: overlay replaces if non-empty
    if !overlay.syscalls.allowed.is_empty() {
        base.syscalls.allowed = overlay.syscalls.allowed.clone();
        let (f, l) = decl.origin("defaults.syscalls", file);
        prov.replace("defaults.syscalls", f, l, overlay.syscalls.allowed.clone());
    }

    // environment: an `environment` node declared on the overlay's side —
    // in this document's `defaults` or resolved from one of its `when`
    // blocks — is authoritative: restriction, the `inherit-parent`
    // downgrade opt-in, and the allow list all replace the base's, even
    // when empty. An overlay with no declared environment touches
    // nothing — restriction is the default, so there is nothing to
    // carry over implicitly. Only an explicit `inherit-parent #true`
    // declaration un-restricts through an overlay.
    if overlay.environment.declared || !overlay.environment.allowed.is_empty() {
        base.environment.restrict = overlay.environment.restrict;
        base.environment.inherit_parent = overlay.environment.inherit_parent;
        base.environment.allowed = overlay.environment.allowed.clone();
        base.environment.declared = true;
        let (f, l) = decl.origin("defaults.environment", file);
        prov.replace(
            "defaults.environment.allowed",
            f,
            l,
            overlay.environment.allowed.clone(),
        );
        prov.set("defaults.environment.restrict", f, l);
        prov.set("defaults.environment.inherit-parent", f, l);
    }

    // network: an overlay allowlist replaces the whole allow side —
    // host (name layer), cidr (IP layer) and the qualified `egress_rules`
    // entries that ride beside them. Materialize the base's stored rule
    // set first so replacement acts on the effective rules even when the
    // field was never parser-populated.
    base.network.outbound.egress_rules = base.network.outbound.egress_rules();
    let overlay_rules = overlay.network.outbound.egress_rules();
    if !overlay.network.outbound.allowed.is_empty()
        || !overlay.network.outbound.allowed_cidrs.is_empty()
        || overlay_rules.iter().any(|r| r.allow)
    {
        base.network.outbound.allowed = overlay.network.outbound.allowed.clone();
        base.network.outbound.allowed_port_qualified =
            overlay.network.outbound.allowed_port_qualified.clone();
        base.network.outbound.allowed_cidrs = overlay.network.outbound.allowed_cidrs.clone();
        base.network.outbound.allowed_cidrs_port_qualified = overlay
            .network
            .outbound
            .allowed_cidrs_port_qualified
            .clone();
        base.network.outbound.egress_rules.retain(|r| !r.allow);
        for r in &overlay_rules {
            if r.allow && !base.network.outbound.egress_rules.contains(r) {
                base.network.outbound.egress_rules.push(r.clone());
            }
        }
        let (f, l) = decl.origin("defaults.network", file);
        let items: Vec<String> = overlay
            .network
            .outbound
            .allowed
            .iter()
            .cloned()
            .chain(overlay.network.outbound.allowed_cidrs.iter().cloned())
            .chain(
                overlay_rules
                    .iter()
                    .filter(|r| r.allow)
                    .map(|r| r.describe()),
            )
            .collect();
        prov.replace("defaults.network.allow", f, l, items);
    }
    {
        let (f, l) = decl.origin("defaults.network", file);
        let deny_items: Vec<String> = overlay
            .network
            .outbound
            .denied_hosts
            .iter()
            .cloned()
            .chain(overlay.network.outbound.denied_cidrs.iter().cloned())
            .chain(
                overlay_rules
                    .iter()
                    .filter(|r| !r.allow)
                    .map(|r| r.describe()),
            )
            .collect();
        prov.union("defaults.network.deny", f, l, deny_items);
    }
    for host in &overlay.network.outbound.denied_hosts {
        if !base.network.outbound.denied_hosts.contains(host) {
            base.network.outbound.denied_hosts.push(host.clone());
        }
    }
    for cidr in &overlay.network.outbound.denied_cidrs {
        if !base.network.outbound.denied_cidrs.contains(cidr) {
            base.network.outbound.denied_cidrs.push(cidr.clone());
        }
    }
    // Structured deny rules are sticky like their flat projections.
    for r in &overlay_rules {
        if !r.allow && !base.network.outbound.egress_rules.contains(r) {
            base.network.outbound.egress_rules.push(r.clone());
        }
    }
    // Posture and inbound move only on their own declarations: a
    // `defaults.network` that merely adds rules must not reset an
    // inherited `allow host="*"` posture or `inbound` grant.
    if decl.network_posture {
        base.network.outbound.deny_all_others = overlay.network.outbound.deny_all_others;
        let (f, l) = decl.origin("defaults.network", file);
        prov.set("defaults.network.posture", f, l);
    }
    if decl.network_inbound {
        base.network.inbound.allow_listen = overlay.network.inbound.allow_listen;
        let (f, l) = decl.origin("defaults.network", file);
        prov.set("defaults.network.inbound", f, l);
    }
    crate::policy::sort_egress_rules(&mut base.network.outbound.egress_rules);
    {
        // Deny precedence can prune allows the union just added — or
        // pre-existing ones — record the entries it drops.
        let before_hosts = base.network.outbound.allowed.clone();
        let before_cidrs = base.network.outbound.allowed_cidrs.clone();
        let before_rules = base.network.outbound.egress_rules.clone();
        crate::policy::apply_outbound_deny_precedence(&mut base.network.outbound);
        let mut dropped: Vec<String> = before_hosts
            .iter()
            .filter(|h| !base.network.outbound.allowed.contains(h))
            .cloned()
            .chain(
                before_cidrs
                    .iter()
                    .filter(|c| !base.network.outbound.allowed_cidrs.contains(c))
                    .cloned(),
            )
            .chain(
                before_rules
                    .iter()
                    .filter(|r| r.allow && !base.network.outbound.egress_rules.contains(r))
                    .map(|r| r.describe()),
            )
            .collect();
        dropped.dedup();
        if !dropped.is_empty() {
            let (f, l) = decl.origin("defaults.network", file);
            prov.prune("defaults.network.allow", f, l, dropped);
        }
    }

    if decl.defaults_filesystem {
        // Omitted secret-overlay stays default-on (fail-secure).
        base.fs.secret_overlay = overlay.fs.secret_overlay;
        let (f, l) = decl.origin("defaults.filesystem", file);
        prov.set("defaults.filesystem.secret-overlay", f, l);
    }

    // logging: overlay wins only if the overlay side declared it
    if decl.logging {
        base.logging = overlay.logging.clone();
        let (f, l) = decl.origin("logging", file);
        prov.set("logging", f, l);
    }

    if decl.sandbox {
        base.sandbox = overlay.sandbox.clone();
        let (f, l) = decl.origin("sandbox", file);
        prov.set("sandbox", f, l);
    }

    // confused_deputy_protection: overlay wins only if the overlay side declared it
    if decl.confused_deputy_protection {
        base.confused_deputy_protection = overlay.confused_deputy_protection;
        let (f, l) = decl.origin("confused_deputy_protection", file);
        prov.set("confused_deputy_protection", f, l);
    }

    // trajectory: overlay wins only if the overlay side declared it
    if decl.trajectory {
        base.trajectory = overlay.trajectory;
        base.trajectory_rules = overlay.trajectory_rules.clone();
        let (f, l) = decl.origin("trajectory", file);
        prov.set("trajectory", f, l);
        prov.replace(
            "trajectory.after",
            f,
            l,
            overlay
                .trajectory_rules
                .iter()
                .map(|r| format!("{:?}->{:?}", r.after_side_effect, r.deny_next))
                .collect(),
        );
    }

    // tools: merge only within the same server identity
    for tool in &overlay.tools {
        let key = tool_key(tool.server.as_deref(), &tool.name);
        let (f, l) = decl.origin(&key, file);
        if let Some(existing) = base
            .tools
            .iter_mut()
            .find(|t| t.name == tool.name && t.server == tool.server)
        {
            // Deny is sticky: if base denied the tool, it stays denied
            if !existing.allowed || !tool.allowed {
                existing.allowed = false;
                if !tool.allowed {
                    prov.set(format!("{key}.deny"), f, l);
                }
            }

            // FS merge — only when the overlay tool declared the
            // `filesystem` block itself (`fs_explicit`), the same gate
            // the `when` path uses. A non-declaring overlay tool's fs
            // is materialized defaults, not a declaration: merging it
            // would replace the base tool's explicit scope with
            // defaults, silently widening or dropping it.
            if tool.fs_explicit {
                merge_tool_fs(&mut existing.fs, tool.fs.as_ref(), prov, &key, f, l);
            }

            // Syscalls merge — the same declaration gate as fs/network
            // (`syscalls_explicit`). A non-declaring overlay tool's
            // syscalls are materialized defaults, not a declaration:
            // merging them would replace the base tool's scope with
            // defaults. (Explicit per-tool syscalls are rejected at
            // load anyway; the gate keeps the merge symmetric.)
            if tool.syscalls_explicit {
                merge_tool_syscalls(
                    &mut existing.syscalls,
                    tool.syscalls.as_ref(),
                    prov,
                    &key,
                    f,
                    l,
                );
            }

            // Network merge — same declaration gate as fs
            // (`network_explicit`): the overlay tool's own `network`
            // block decides, never defaults materialized onto it.
            if tool.network_explicit {
                merge_tool_network(
                    &mut existing.network,
                    tool.network.as_ref(),
                    prov,
                    &key,
                    f,
                    l,
                );
            }

            if tool.args_schema.is_some() {
                existing.args_schema = tool.args_schema.clone();
                prov.set(format!("{key}.args_schema"), f, l);
            }
            if tool.side_effect.is_some() {
                existing.side_effect = tool.side_effect.clone();
                prov.set(format!("{key}.side_effect"), f, l);
            }
            if tool.input_responses_specified {
                existing.input_responses = tool.input_responses;
                existing.input_responses_specified = true;
                prov.set(format!("{key}.input_responses"), f, l);
            }
            // `deputy` replaces whole — an overlay that omits it inherits
            // the base's block; `role="none"` is the explicit opt-out.
            if tool.deputy.is_some() {
                existing.deputy = tool.deputy.clone();
                prov.set(format!("{key}.deputy"), f, l);
            }
            existing.fs_explicit |= tool.fs_explicit;
            existing.network_explicit |= tool.network_explicit;
            existing.syscalls_explicit |= tool.syscalls_explicit;
            if tool.environment_explicit {
                existing.environment_explicit = true;
                prov.set(format!("{key}.environment"), f, l);
            }
            if tool.process_explicit {
                existing.process_exec_allowed = tool.process_exec_allowed;
                existing.process_explicit = true;
                prov.set(format!("{key}.process"), f, l);
            }
        } else {
            base.tools.push(tool.clone());
            prov.set(key.clone(), f, l);
            // Seed the tool's declared list fields so a later overlay's
            // replace can name the contributors it dropped. Fields the
            // tool never declared are materialized defaults — seeded
            // values would go stale the moment a `when` block rewrote
            // them, so rematerialization attributes them instead.
            seed_tool_fields(prov, &key, tool, (f, l));
        }
    }

    // hash_entries: overlay replaces by (server_name, hash_type, target); new entries appended
    for entry in &overlay.hash_entries {
        let (f, l) = decl.origin(&format!("server {:?}", entry.server_name), file);
        prov.union(
            "integrity.hash",
            f,
            l,
            [format!(
                "{}/{:?}:{}",
                entry.server_name, entry.hash_type, entry.target
            )],
        );
        if let Some(existing) = base.hash_entries.iter_mut().find(|e| {
            e.server_name == entry.server_name
                && e.hash_type == entry.hash_type
                && e.target == entry.target
        }) {
            *existing = entry.clone();
        } else {
            base.hash_entries.push(entry.clone());
        }
    }

    // tools_list_hashes: overlay replaces by server_name; new entries appended
    for entry in &overlay.tools_list_hashes {
        let (f, l) = decl.origin(&format!("server {:?}", entry.server_name), file);
        prov.union(
            "integrity.tools-list",
            f,
            l,
            [format!("{}/tools-list-hash", entry.server_name)],
        );
        if let Some(existing) = base
            .tools_list_hashes
            .iter_mut()
            .find(|e| e.server_name == entry.server_name)
        {
            *existing = entry.clone();
        } else {
            base.tools_list_hashes.push(entry.clone());
        }
    }

    // mcp rules: union per server. Atom-level overlaps across documents
    // resolve deny-first when the rules are normalised (`resolve_atoms`).
    for server_rules in &overlay.mcp_rules {
        let (f, l) = decl.origin(
            &format!(
                "server {:?}",
                server_rules.server_name.as_deref().unwrap_or("<unnamed>")
            ),
            file,
        );
        prov.union(
            "mcp.rules",
            f,
            l,
            server_rules
                .rules()
                .iter()
                .map(|r| format!("{:?} {}", r.effect, r.method)),
        );
        if let Some(existing) = base
            .mcp_rules
            .iter_mut()
            .find(|s| s.server_name == server_rules.server_name)
        {
            existing.extend_rules(server_rules.rules().iter().cloned());
        } else {
            base.mcp_rules.push(server_rules.clone());
        }
    }
}

/// Evaluate `when environment="xxx" { ... }` blocks and apply matching
/// overrides. Returns the declarations matching blocks made — an
/// `include` consumer merges on them, so a value set through a `when`
/// propagates like one the file declared outright. Network
/// re-declarations that skip `inbound` while a listener grant is live
/// are recorded on `pending`, not warned immediately: they are
/// evaluated against the load's final merged policy.
#[expect(clippy::too_many_arguments)]
pub(super) fn apply_when_overrides(
    doc: &KdlDocument,
    policy: &mut Policy,
    env_value: &str,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
    path: &Path,
    content: &str,
    pending: &mut PendingWarnings,
    prov: &mut Provenance,
) -> Result<OverlayDecl, PolicyError> {
    let mut decl = OverlayDecl::default();
    for node in doc.nodes() {
        if node.name().to_string() != "when" {
            continue;
        }

        let expected_env = match node.get("environment").and_then(|v| v.as_string()) {
            Some(v) => v,
            None => continue, // unknown condition type, skip
        };

        if expected_env != env_value {
            continue; // condition doesn't match
        }

        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

        // Apply overrides from the when block
        apply_overrides_from_doc(
            children, policy, profiles, base_dir, path, content, pending, prov,
        )?;
        decl.merge(&OverlayDecl::for_when_children(children, path, content));
    }

    Ok(decl)
}

/// Apply override fields parsed from a KdlDocument (used by `when` blocks).
#[expect(clippy::too_many_arguments)]
fn apply_overrides_from_doc(
    doc: &KdlDocument,
    policy: &mut Policy,
    profiles: &HashMap<String, PolicyLayer>,
    base_dir: Option<&Path>,
    path: &Path,
    content: &str,
    pending: &mut PendingWarnings,
    prov: &mut Provenance,
) -> Result<(), PolicyError> {
    // defaults overrides
    if let Some(defaults_node) = unique_child(doc, "defaults", "the override document")?
        && let Some(children) = defaults_node.children()
    {
        if let Some(fs_node) = unique_child(children, "filesystem", "'defaults'")? {
            let line = node_line(content, fs_node);
            // `secret-overlay` rides the declared block; omitted stays
            // default-on (fail-secure), same as the inheritance merge.
            let fs = match fs_node.children() {
                Some(fs_children) => parse_fs_allows(fs_children)?,
                None => FsPolicy::default(),
            };
            policy.fs.secret_overlay = fs.secret_overlay;
            prov.set("defaults.filesystem.secret-overlay", path, line);
            if fs.allow_specified {
                // A matching `when` block replaces the allow lists
                // wholesale — unlike extends/include, which union.
                prov.replace(
                    "defaults.filesystem.read_only",
                    path,
                    line,
                    fs.read_only.clone(),
                );
                prov.replace(
                    "defaults.filesystem.read_write",
                    path,
                    line,
                    fs.read_write.clone(),
                );
                prov.replace(
                    "defaults.filesystem.executable",
                    path,
                    line,
                    fs.executable.clone(),
                );
                policy.fs.read_only = fs.read_only;
                policy.fs.read_write = fs.read_write;
                policy.fs.executable = fs.executable;
                policy.fs.allow_specified = true;
            }
            prov.union(
                "defaults.filesystem.denied",
                path,
                line,
                fs.denied_paths.iter().cloned(),
            );
            for denied in &fs.denied_paths {
                if !policy.fs.denied_paths.contains(denied) {
                    policy.fs.denied_paths.push(denied.clone());
                }
            }
            let denied_now = policy.fs.denied_paths.clone();
            for (field, list) in [
                ("defaults.filesystem.read_only", &mut policy.fs.read_only),
                ("defaults.filesystem.read_write", &mut policy.fs.read_write),
                ("defaults.filesystem.executable", &mut policy.fs.executable),
            ] {
                let dropped: Vec<String> = list
                    .iter()
                    .filter(|p| fs_deny_covers(&denied_now, p))
                    .cloned()
                    .collect();
                list.retain(|p| !dropped.contains(p));
                if !dropped.is_empty() {
                    prov.prune(field, path, line, dropped);
                }
            }
            let read_now = policy.fs.read_only.clone();
            for (field, list) in [
                ("defaults.filesystem.read_write", &mut policy.fs.read_write),
                ("defaults.filesystem.executable", &mut policy.fs.executable),
            ] {
                let dropped: Vec<String> = list
                    .iter()
                    .filter(|p| read_now.contains(*p))
                    .cloned()
                    .collect();
                list.retain(|p| !dropped.contains(p));
                if !dropped.is_empty() {
                    prov.prune(field, path, line, dropped);
                }
            }
        }
        if let Some(sc_node) = unique_child(children, "syscalls", "'defaults'")?
            && let Some(sc_children) = sc_node.children()
        {
            let sc = parse_syscall_allows(sc_children)?;
            if !sc.allowed.is_empty() {
                let line = node_line(content, sc_node);
                prov.replace("defaults.syscalls", path, line, sc.allowed.clone());
                policy.syscalls.allowed = sc.allowed;
            }
        }
        // Node presence in a matching `when` block marks the contract
        // declared; the declared contents — restriction posture, the
        // `inherit-parent` opt-in, and the `allow` list — replace the
        // base's (including an empty list).
        if let Some(env_node) = unique_child(children, "environment", "'defaults'")? {
            let env = parse_environment_node(env_node)?;
            let line = node_line(content, env_node);
            prov.replace(
                "defaults.environment.allowed",
                path,
                line,
                env.allowed.clone(),
            );
            prov.set("defaults.environment.restrict", path, line);
            prov.set("defaults.environment.inherit-parent", path, line);
            policy.environment.restrict = !env.inherit_parent;
            policy.environment.inherit_parent = env.inherit_parent;
            policy.environment.declared = true;
            policy.environment.allowed = env.allowed;
        }
        if let Some(net_node) = unique_child(children, "network", "'defaults'")?
            && let Some(net_children) = net_node.children()
        {
            let net = parse_network_rules(net_children)?;
            let line = node_line(content, net_node);
            // Same allow-replaces / deny-accumulates semantics as the
            // inheritance merge — including the qualified `egress_rules`
            // entries the flat lists cannot carry. Materialize the stored
            // rule set so replacement sees the effective rules.
            policy.network.outbound.egress_rules = policy.network.outbound.egress_rules();
            let net_rules = net.outbound.egress_rules();
            if !net.outbound.allowed.is_empty()
                || !net.outbound.allowed_cidrs.is_empty()
                || !net.outbound.deny_all_others
                || net_rules.iter().any(|r| r.allow)
            {
                let allow_items: Vec<String> = net
                    .outbound
                    .allowed
                    .iter()
                    .cloned()
                    .chain(net.outbound.allowed_cidrs.iter().cloned())
                    .chain(net_rules.iter().filter(|r| r.allow).map(|r| r.describe()))
                    .collect();
                prov.replace("defaults.network.allow", path, line, allow_items);
                policy.network.outbound.allowed = net.outbound.allowed;
                policy.network.outbound.allowed_port_qualified =
                    net.outbound.allowed_port_qualified;
                policy.network.outbound.allowed_cidrs = net.outbound.allowed_cidrs;
                policy.network.outbound.allowed_cidrs_port_qualified =
                    net.outbound.allowed_cidrs_port_qualified;
                policy.network.outbound.egress_rules.retain(|r| !r.allow);
                for r in &net_rules {
                    if r.allow && !policy.network.outbound.egress_rules.contains(r) {
                        policy.network.outbound.egress_rules.push(r.clone());
                    }
                }
            }
            let deny_items: Vec<String> = net
                .outbound
                .denied_hosts
                .iter()
                .cloned()
                .chain(net.outbound.denied_cidrs.iter().cloned())
                .chain(net_rules.iter().filter(|r| !r.allow).map(|r| r.describe()))
                .collect();
            prov.union("defaults.network.deny", path, line, deny_items);
            for host in &net.outbound.denied_hosts {
                if !policy.network.outbound.denied_hosts.contains(host) {
                    policy.network.outbound.denied_hosts.push(host.clone());
                }
            }
            for cidr in &net.outbound.denied_cidrs {
                if !policy.network.outbound.denied_cidrs.contains(cidr) {
                    policy.network.outbound.denied_cidrs.push(cidr.clone());
                }
            }
            for r in &net_rules {
                if !r.allow && !policy.network.outbound.egress_rules.contains(r) {
                    policy.network.outbound.egress_rules.push(r.clone());
                }
            }
            // Posture moves only on a bare `host="*"` posture node — a
            // block that merely adds rules must not reset an inherited
            // open posture. `inbound` likewise moves only when declared.
            if declares_network_posture(net_children) {
                policy.network.outbound.deny_all_others = net.outbound.deny_all_others;
                prov.set("defaults.network.posture", path, line);
            }
            if net_children.get("inbound").is_some() {
                policy.network.inbound.allow_listen = net.inbound.allow_listen;
                prov.set("defaults.network.inbound", path, line);
            } else if policy.network.inbound.allow_listen {
                // Deferred: a later declaration may still close the
                // grant — the warning is evaluated on the load's
                // final merged state.
                pending.push_inbound(path);
            }
            crate::policy::sort_egress_rules(&mut policy.network.outbound.egress_rules);
            {
                let before_hosts = policy.network.outbound.allowed.clone();
                let before_cidrs = policy.network.outbound.allowed_cidrs.clone();
                let before_rules = policy.network.outbound.egress_rules.clone();
                crate::policy::apply_outbound_deny_precedence(&mut policy.network.outbound);
                let mut dropped: Vec<String> = before_hosts
                    .iter()
                    .filter(|h| !policy.network.outbound.allowed.contains(h))
                    .cloned()
                    .chain(
                        before_cidrs
                            .iter()
                            .filter(|c| !policy.network.outbound.allowed_cidrs.contains(c))
                            .cloned(),
                    )
                    .chain(
                        before_rules
                            .iter()
                            .filter(|r| {
                                r.allow && !policy.network.outbound.egress_rules.contains(r)
                            })
                            .map(|r| r.describe()),
                    )
                    .collect();
                dropped.dedup();
                if !dropped.is_empty() {
                    prov.prune("defaults.network.allow", path, line, dropped);
                }
            }
        }
    }

    // logging override (level and fail_closed are independent)
    if let Some(logging_node) = doc.get("logging") {
        let line = node_line(content, logging_node);
        let mut wrote = false;
        if let Some(level_prop) = logging_node.get("level") {
            let level = level_prop
                .as_string()
                .ok_or_else(|| PolicyError::KdlParse("'logging.level' must be a string".into()))?;
            validate_logging_level(level)?;
            policy.logging.level = level.to_string();
            wrote = true;
        }
        if logging_node.get("fail_closed").is_some() {
            policy.logging.fail_closed = parse_logging_fail_closed(logging_node)?;
            wrote = true;
        }
        if wrote {
            prov.set("logging", path, line);
        }
    }

    // sandbox override
    if let Some(sandbox_node) = doc.get("sandbox")
        && let Some(val) = sandbox_node.get("allow_degraded")
    {
        policy.sandbox.allow_degraded = val.as_bool().ok_or_else(|| {
            PolicyError::KdlParse("'sandbox.allow_degraded' must be a boolean".into())
        })?;
        prov.set("sandbox", path, node_line(content, sandbox_node));
    }

    // confused_deputy_protection override
    if let Some(cdp_node) = doc.get("confused_deputy_protection")
        && let Some(arg) = cdp_node.get(0)
    {
        let cdp = arg.as_bool().ok_or_else(|| {
            PolicyError::KdlParse("'confused_deputy_protection' must be a boolean".into())
        })?;
        policy.confused_deputy_protection = cdp;
        prov.set(
            "confused_deputy_protection",
            path,
            node_line(content, cdp_node),
        );
    }

    // trajectory override (flag + ordered after children)
    if doc.get("trajectory").is_some() {
        let line = doc.get("trajectory").and_then(|n| node_line(content, n));
        let (enabled, rules) = parse_trajectory(doc)?;
        policy.trajectory = enabled;
        policy.trajectory_rules = rules;
        prov.set("trajectory", path, line);
        prov.replace(
            "trajectory.after",
            path,
            line,
            policy
                .trajectory_rules
                .iter()
                .map(|r| format!("{:?}->{:?}", r.after_side_effect, r.deny_next))
                .collect(),
        );
    }

    // server/tool overrides
    for node in doc.nodes() {
        if node.name().to_string() != "server" {
            continue;
        }
        let server_name = node.get(0).and_then(|v| v.as_string()).map(String::from);
        let server_ctx = format!("server '{}'", server_name.as_deref().unwrap_or("<unnamed>"));
        let children = match node.children() {
            Some(c) => c,
            None => continue,
        };

        // `environment` is launch-level (`defaults.environment`): inside a
        // `when` block's server-defaults it is only parsed for *new* tools —
        // for existing tools it would be silently dropped, so reject it.
        if unique_child(children, "server-defaults", &server_ctx)?
            .and_then(|sd| sd.children())
            .is_some_and(|sdc| sdc.get("environment").is_some())
        {
            return Err(PolicyError::KdlParse(
                "'environment' is only allowed under 'defaults' — it cannot appear in a server-defaults block inside 'when'".into(),
            ));
        }

        for child in children.nodes() {
            if child.name().to_string() != "tool" {
                continue;
            }
            let tool_name = child
                .get(0)
                .and_then(|v| v.as_string())
                .ok_or_else(|| {
                    PolicyError::KdlParse("tool node must have a name as first argument".into())
                })?
                .to_string();
            let tool_ctx = format!("tool '{tool_name}'");
            let tkey = tool_key(server_name.as_deref(), &tool_name);
            let tline = node_line(content, child);

            // `when` tool overrides obey the same closed v2 tool shape as
            // inline declarations; unknown members must not pass silently
            // here either (a misspelt `deputy` included).
            if policy.version >= 2 {
                validate_tool_shape_v2(child, &tool_name)?;
            }

            if let Some(existing) = policy
                .tools
                .iter_mut()
                .find(|t| t.name == tool_name && t.server == server_name)
            {
                if let Some(val) = child.get("deny") {
                    let d = val.as_bool().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'deny' property on tool '{}' must be a boolean",
                            tool_name
                        ))
                    })?;
                    // Sticky deny: if already denied, cannot be reversed to allowed
                    if d {
                        existing.allowed = false;
                        prov.set(format!("{tkey}.deny"), path, tline);
                    }
                }
                if let Some(val) = child.get("side_effect") {
                    let se = val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'side_effect' property on tool '{}' must be a string",
                            tool_name
                        ))
                    })?;
                    crate::policy::SideEffect::parse(se).map_err(PolicyError::KdlParse)?;
                    existing.side_effect = Some(se.to_string());
                    prov.set(format!("{tkey}.side_effect"), path, tline);
                }
                if let Some(val) = child.get("args_schema") {
                    let s = val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'args_schema' property on tool '{}' must be a string",
                            tool_name
                        ))
                    })?;
                    let resolved = resolve_tool_args_schema(s, base_dir)?;
                    existing.args_schema = Some(resolved);
                    prov.set(format!("{tkey}.args_schema"), path, tline);
                }
                if let Some(val) = child.get("input_responses") {
                    let raw = val.as_string().ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "'input_responses' property on tool '{}' must be a string",
                            tool_name
                        ))
                    })?;
                    existing.input_responses =
                        InputResponsesMode::parse_kdl(raw).map_err(PolicyError::KdlParse)?;
                    existing.input_responses_specified = true;
                    prov.set(format!("{tkey}.input_responses"), path, tline);
                }
                if let Some(tc) = child.children() {
                    if let Some(fs_node) = unique_child(tc, "filesystem", &tool_ctx)?
                        && let Some(fs_children) = fs_node.children()
                    {
                        let over_fs = parse_tool_fs(fs_children)?;
                        if !existing.fs_explicit {
                            // Re-base inherited grants on the current
                            // (post-`when`) defaults so the override folds the
                            // same way as an inline tool block.
                            existing.fs = Some(tool_fs_base(&policy.fs, existing.fs.as_ref()));
                        }
                        existing.fs_explicit = true;
                        merge_tool_fs(&mut existing.fs, Some(&over_fs), prov, &tkey, path, tline);
                    }
                    if let Some(sc_node) = unique_child(tc, "syscalls", &tool_ctx)?
                        && let Some(sc_children) = sc_node.children()
                    {
                        let over_sc = parse_tool_syscalls(sc_children)?;
                        // Per-tool syscalls are not enforced; mark explicit so
                        // rematerialize keeps them and load-time validation
                        // rejects the policy like an inline declaration.
                        existing.syscalls_explicit = true;
                        merge_tool_syscalls(
                            &mut existing.syscalls,
                            Some(&over_sc),
                            prov,
                            &tkey,
                            path,
                            tline,
                        );
                    }
                    if let Some(net_node) = unique_child(tc, "network", &tool_ctx)?
                        && let Some(net_children) = net_node.children()
                    {
                        let over_net = parse_tool_network(net_children)?;
                        if !existing.network_explicit {
                            existing.network = Some(tool_network_base(
                                &policy.network,
                                existing.network.as_ref(),
                            ));
                        }
                        existing.network_explicit = true;
                        merge_tool_network(
                            &mut existing.network,
                            Some(&over_net),
                            prov,
                            &tkey,
                            path,
                            tline,
                        );
                    }
                    if let Some(proc_node) = unique_child(tc, "process", &tool_ctx)? {
                        existing.process_exec_allowed = parse_process_exec_allowed(proc_node)?;
                        existing.process_explicit = true;
                        prov.set(format!("{tkey}.process"), path, tline);
                    }
                    // Per-tool environment is not enforced; flag it so
                    // load-time validation rejects the policy like an
                    // inline declaration.
                    if unique_child(tc, "environment", &tool_ctx)?.is_some() {
                        existing.environment_explicit = true;
                        prov.set(format!("{tkey}.environment"), path, tline);
                    }
                    // `deputy` replaces whole, same as include/extends —
                    // `role="none"` is the opt-out. Under v1 it would be
                    // dropped silently, so it is rejected outright.
                    if let Some(dep_node) = unique_child(tc, "deputy", &tool_ctx)? {
                        if policy.version < 2 {
                            return Err(PolicyError::KdlParse(format!(
                                "'deputy' on tool '{tool_name}' requires 'policy version=2'"
                            )));
                        }
                        existing.deputy = Some(parse_deputy_node(dep_node, &tool_name)?);
                        prov.set(format!("{tkey}.deputy"), path, tline);
                    }
                }
            } else {
                let defaults_layer = defaults_to_layer(&Defaults {
                    fs: policy.fs.clone(),
                    syscalls: policy.syscalls.clone(),
                    network: policy.network.clone(),
                    environment: EnvironmentPolicy::default(),
                });
                let mut dummy_doc = KdlDocument::new();
                let mut s_node = kdl::KdlNode::new("server");
                if let Some(ref s) = server_name {
                    s_node.push(kdl::KdlValue::String(s.clone()));
                }
                let mut s_children = KdlDocument::new();
                if let Some(server_defaults) =
                    unique_child(children, "server-defaults", &server_ctx)?
                {
                    s_children.nodes_mut().push(server_defaults.clone());
                }
                s_children.nodes_mut().push(child.clone());
                s_node.set_children(s_children);
                dummy_doc.nodes_mut().push(s_node);
                let new_tools = parse_servers(
                    &dummy_doc,
                    &defaults_layer,
                    profiles,
                    base_dir,
                    policy.version,
                )?;
                for t in new_tools {
                    prov.set(tkey.clone(), path, tline);
                    seed_tool_fields(prov, &tkey, &t, (path, tline));
                    policy.tools.push(t);
                }
            }
        }
    }

    // mcp rules inside matching `when` blocks union per server, with the
    // same deny-first atom resolution as include/extends.
    let mcp_overrides = parse_server_mcp_rules(doc, policy.version, true)?;
    for server_rules in mcp_overrides {
        // The `server` node's own line is the closest attribution the
        // overrides have (rules carry no per-node spans).
        let line = server_node_line(doc, content, server_rules.server_name.as_deref());
        prov.union(
            "mcp.rules",
            path,
            line,
            server_rules
                .rules()
                .iter()
                .map(|r| format!("{:?} {}", r.effect, r.method)),
        );
        if let Some(existing) = policy
            .mcp_rules
            .iter_mut()
            .find(|s| s.server_name == server_rules.server_name)
        {
            existing.extend_rules(server_rules.into_rules());
        } else {
            policy.mcp_rules.push(server_rules);
        }
    }

    // hash_entries overrides
    let hash_overrides = parse_server_hashes(doc)?;
    for entry in hash_overrides {
        // The `server` node's line is the closest attribution a hash
        // entry has — the override record sits inside it.
        let line = server_node_line(doc, content, Some(entry.server_name.as_str()));
        prov.union(
            "integrity.hash",
            path,
            line,
            [format!(
                "{}/{:?}:{}",
                entry.server_name, entry.hash_type, entry.target
            )],
        );
        if let Some(existing) = policy.hash_entries.iter_mut().find(|e| {
            e.server_name == entry.server_name
                && e.hash_type == entry.hash_type
                && e.target == entry.target
        }) {
            *existing = entry;
        } else {
            policy.hash_entries.push(entry);
        }
    }

    // tools_list_hashes overrides
    let tl_overrides = parse_tools_list_hashes(doc)?;
    for entry in tl_overrides {
        let line = server_node_line(doc, content, Some(entry.server_name.as_str()));
        prov.union(
            "integrity.tools-list",
            path,
            line,
            [format!("{}/tools-list-hash", entry.server_name)],
        );
        if let Some(existing) = policy
            .tools_list_hashes
            .iter_mut()
            .find(|e| e.server_name == entry.server_name)
        {
            *existing = entry;
        } else {
            policy.tools_list_hashes.push(entry);
        }
    }

    Ok(())
}

/// Merge an overlay tool's declared `filesystem` block onto the base
/// tool's: `require_path` replaces when the overlay set it, the allow
/// side replaces when the overlay spelled one, denies accumulate, then
/// deny-wins prunes every allow a deny pattern covers (`fs_deny_covers`
/// — additive OS rulesets have no negative rule to carve a covered
/// allow back out). A missing base adopts the overlay wholesale; a
/// missing overlay leaves the base untouched. Shared by the
/// extends/include merge and `when` overrides so both paths apply the
/// same semantics — callers gate on the tool's own declaration
/// (`fs_explicit`), never on materialized defaults.
fn merge_tool_fs(
    base: &mut Option<FsToolPolicy>,
    over: Option<&FsToolPolicy>,
    prov: &mut Provenance,
    key: &str,
    file: &Path,
    line: Option<u32>,
) {
    let Some(over_fs) = over else { return };
    let allow_key = format!("{key}.filesystem.allowed");
    let deny_key = format!("{key}.filesystem.denied");
    let Some(base_fs) = base.as_mut() else {
        *base = Some(over_fs.clone());
        prov.set(format!("{key}.filesystem"), file, line);
        prov.union(
            &allow_key,
            file,
            line,
            over_fs.allowed_paths.iter().cloned(),
        );
        prov.union(&deny_key, file, line, over_fs.denied_paths.iter().cloned());
        return;
    };
    if over_fs.require_path.is_some() {
        base_fs.require_path = over_fs.require_path;
        prov.set(format!("{key}.filesystem.require-path"), file, line);
    }
    if over_fs.allow_specified {
        prov.replace(&allow_key, file, line, over_fs.allowed_paths.clone());
        base_fs.allowed_paths = over_fs.allowed_paths.clone();
        base_fs.read_only_paths = over_fs.read_only_paths.clone();
        base_fs.read_write_paths = over_fs.read_write_paths.clone();
        base_fs.allow_specified = true;
    }
    prov.union(&deny_key, file, line, over_fs.denied_paths.iter().cloned());
    for denied in &over_fs.denied_paths {
        if !base_fs.denied_paths.contains(denied) {
            base_fs.denied_paths.push(denied.clone());
        }
    }
    for list in [
        &mut base_fs.allowed_paths,
        &mut base_fs.read_only_paths,
        &mut base_fs.read_write_paths,
    ] {
        let dropped: Vec<String> = list
            .iter()
            .filter(|p| fs_deny_covers(&base_fs.denied_paths, p))
            .cloned()
            .collect();
        list.retain(|p| !dropped.contains(p));
        if !dropped.is_empty() {
            prov.prune(&allow_key, file, line, dropped);
        }
    }
}

/// Same shape for a tool's `syscalls` block: a non-empty allow list
/// replaces, denied names accumulate and re-prune the allow side.
fn merge_tool_syscalls(
    base: &mut Option<ToolSyscallPolicy>,
    over: Option<&ToolSyscallPolicy>,
    prov: &mut Provenance,
    key: &str,
    file: &Path,
    line: Option<u32>,
) {
    let Some(over_sc) = over else { return };
    let allow_key = format!("{key}.syscalls.allowed");
    let deny_key = format!("{key}.syscalls.denied");
    let Some(base_sc) = base.as_mut() else {
        *base = Some(over_sc.clone());
        prov.set(format!("{key}.syscalls"), file, line);
        prov.union(&allow_key, file, line, over_sc.allowed.iter().cloned());
        prov.union(&deny_key, file, line, over_sc.denied.iter().cloned());
        return;
    };
    if !over_sc.allowed.is_empty() {
        prov.replace(&allow_key, file, line, over_sc.allowed.clone());
        base_sc.allowed = over_sc.allowed.clone();
    }
    prov.union(&deny_key, file, line, over_sc.denied.iter().cloned());
    for denied in &over_sc.denied {
        if !base_sc.denied.contains(denied) {
            base_sc.denied.push(denied.clone());
        }
    }
    let dropped: Vec<String> = base_sc
        .allowed
        .iter()
        .filter(|s| base_sc.denied.contains(s))
        .cloned()
        .collect();
    base_sc.allowed.retain(|s| !dropped.contains(s));
    if !dropped.is_empty() {
        prov.prune(&allow_key, file, line, dropped);
    }
}

/// And for a tool's `network` block: the allow side (hosts, CIDRs and
/// allow-rules) replaces when the overlay declared one; denied hosts,
/// CIDRs and deny-rules accumulate, then deny precedence reapplies.
fn merge_tool_network(
    base: &mut Option<ToolNetworkPolicy>,
    over: Option<&ToolNetworkPolicy>,
    prov: &mut Provenance,
    key: &str,
    file: &Path,
    line: Option<u32>,
) {
    let Some(over_net) = over else { return };
    let allow_key = format!("{key}.network.allow");
    let deny_key = format!("{key}.network.deny");
    let allow_items = tool_net_allow_items;
    let deny_items = tool_net_deny_items;
    let Some(base_net) = base.as_mut() else {
        *base = Some(over_net.clone());
        prov.set(format!("{key}.network"), file, line);
        prov.union(&allow_key, file, line, allow_items(over_net));
        prov.union(&deny_key, file, line, deny_items(over_net));
        return;
    };
    // Materialize so the allow-side replacement covers rules only the
    // accessor could see.
    base_net.egress_rules = base_net.egress_rule_set();
    if over_net.allow_specified || over_net.egress_rules.iter().any(|r| r.allow) {
        prov.replace(&allow_key, file, line, allow_items(over_net));
        base_net.allowed_hosts = over_net.allowed_hosts.clone();
        base_net.allowed_cidrs = over_net.allowed_cidrs.clone();
        base_net.allow_specified = true;
        base_net.egress_rules.retain(|r| !r.allow);
        for r in &over_net.egress_rules {
            if r.allow && !base_net.egress_rules.contains(r) {
                base_net.egress_rules.push(r.clone());
            }
        }
    }
    prov.union(&deny_key, file, line, deny_items(over_net));
    for denied in &over_net.denied_hosts {
        if !base_net.denied_hosts.contains(denied) {
            base_net.denied_hosts.push(denied.clone());
        }
    }
    for denied in &over_net.denied_cidrs {
        if !base_net.denied_cidrs.contains(denied) {
            base_net.denied_cidrs.push(denied.clone());
        }
    }
    for r in &over_net.egress_rules {
        if !r.allow && !base_net.egress_rules.contains(r) {
            base_net.egress_rules.push(r.clone());
        }
    }
    let before = allow_items(base_net);
    base_net
        .allowed_hosts
        .retain(|h| !base_net.denied_hosts.contains(h));
    crate::policy::sort_egress_rules(&mut base_net.egress_rules);
    crate::policy::apply_tool_network_deny_precedence(base_net);
    let dropped: Vec<String> = before
        .iter()
        .filter(|i| !allow_items(base_net).contains(i))
        .cloned()
        .collect();
    if !dropped.is_empty() {
        prov.prune(&allow_key, file, line, dropped);
    }
}

/// Build a tool's filesystem policy from the current global defaults,
/// preserving denied paths already accumulated on the tool.
pub(crate) fn tool_fs_base(global_fs: &FsPolicy, existing: Option<&FsToolPolicy>) -> FsToolPolicy {
    let mut denied = global_fs.denied_paths.clone();
    if let Some(cur) = existing {
        for d in &cur.denied_paths {
            if !denied.contains(d) {
                denied.push(d.clone());
            }
        }
    }
    let mut fs = FsToolPolicy {
        allowed_paths: global_fs
            .read_only
            .iter()
            .chain(global_fs.read_write.iter())
            .cloned()
            .collect(),
        read_only_paths: global_fs.read_only.clone(),
        read_write_paths: global_fs.read_write.clone(),
        denied_paths: denied,
        allow_specified: global_fs.allow_specified,
        require_path: None,
    };
    fs.allowed_paths
        .retain(|p| !fs_deny_covers(&fs.denied_paths, p));
    fs.read_only_paths
        .retain(|p| !fs_deny_covers(&fs.denied_paths, p));
    fs.read_write_paths
        .retain(|p| !fs_deny_covers(&fs.denied_paths, p));
    fs
}

/// Build a tool's network policy from the current global defaults using flat
/// layer-merge semantics (`allow_specified` only when defaults declared allow
/// rules), preserving denied hosts already accumulated on the tool.
pub(crate) fn tool_network_base(
    global_net: &NetworkPolicy,
    existing: Option<&ToolNetworkPolicy>,
) -> ToolNetworkPolicy {
    let mut denied = global_net.outbound.denied_hosts.clone();
    let mut denied_cidrs = global_net.outbound.denied_cidrs.clone();
    if let Some(cur) = existing {
        for d in &cur.denied_hosts {
            if !denied.contains(d) {
                denied.push(d.clone());
            }
        }
        for d in &cur.denied_cidrs {
            if !denied_cidrs.contains(d) {
                denied_cidrs.push(d.clone());
            }
        }
    }
    // Qualified rules follow the same layering: the defaults' allow rules
    // replace, deny rules accumulate onto the tool's own. `unix=` opt-ins
    // are excluded — they grant a process-wide socket path and the tool
    // grammar has no spelling for them, so inheriting one would emit a
    // `network` node the parser rejects.
    let mut egress_rules: Vec<_> = global_net
        .outbound
        .egress_rules()
        .into_iter()
        .filter(|r| !matches!(r.dest, crate::policy::EgressDest::Unix(_)))
        .collect();
    if let Some(cur) = existing {
        for r in &cur.egress_rules {
            if !r.allow && !egress_rules.contains(r) {
                egress_rules.push(r.clone());
            }
        }
    }
    let mut network = ToolNetworkPolicy {
        allowed_hosts: global_net.outbound.allowed.clone(),
        allowed_cidrs: global_net.outbound.allowed_cidrs.clone(),
        denied_hosts: denied,
        denied_cidrs,
        egress_rules,
        allow_specified: !global_net.outbound.allowed.is_empty()
            || !global_net.outbound.allowed_cidrs.is_empty(),
    };
    crate::policy::apply_tool_network_deny_precedence(&mut network);
    network
}

/// Rebuild per-tool grants from the final global defaults unless the tool
/// declared its own filesystem/network/syscall block — and re-attribute
/// every rebuilt field on `prov`. Materialized entries are the defaults'
/// projection, so their writers are the defaults' own writers (found via
/// the `*_SOURCES` fields); a rewrite is attributed to the declaration
/// that last wrote those sources, with `file` as the fallback when no
/// source write exists. Entries a global deny newly covers leave the
/// field as a `prune` record — the schema's own semantics — while the
/// rest of a replacement is a `replace`, so `dropped_from` keeps naming
/// who actually lost the grant.
pub(crate) fn rematerialize_inherited_defaults(
    policy: &mut Policy,
    prov: &mut Provenance,
    file: &Path,
) {
    /// The defaults fields a tool's materialized allow side derives
    /// from — attribution for entries the rebuild adds, and the record
    /// whose last writer the rewrite itself is attributed to.
    const FS_ALLOW_SOURCES: &[&str] = &[
        "defaults.filesystem.read_only",
        "defaults.filesystem.read_write",
    ];
    const FS_DENY_SOURCES: &[&str] = &["defaults.filesystem.denied"];
    const NET_ALLOW_SOURCES: &[&str] = &["defaults.network.allow"];
    const NET_DENY_SOURCES: &[&str] = &["defaults.network.deny"];
    const SC_SOURCES: &[&str] = &["defaults.syscalls"];

    crate::policy::apply_outbound_deny_precedence(&mut policy.network.outbound);
    let global_fs = policy.fs.clone();
    let global_net = policy.network.clone();
    let global_sc = policy.syscalls.clone();

    for tool in &mut policy.tools {
        let key = tool_key(tool.server.as_deref(), &tool.name);
        if !tool.fs_explicit {
            let fs = tool_fs_base(&global_fs, tool.fs.as_ref());
            let keep = fs.allow_specified
                || !fs.allowed_paths.is_empty()
                || !fs.denied_paths.is_empty()
                || !fs.read_only_paths.is_empty()
                || !fs.read_write_paths.is_empty();
            let allow_origin = prov
                .last_writer_of(FS_ALLOW_SOURCES)
                .unwrap_or_else(|| (file.to_path_buf(), None));
            let denied = fs.denied_paths.clone();
            prov.reproject(
                format!("{key}.filesystem.allowed"),
                (&allow_origin.0, allow_origin.1),
                fs.allowed_paths.clone(),
                FS_ALLOW_SOURCES,
                move |i| fs_deny_covers(&denied, i),
            );
            let deny_origin = prov
                .last_writer_of(FS_DENY_SOURCES)
                .unwrap_or_else(|| (file.to_path_buf(), None));
            prov.reproject(
                format!("{key}.filesystem.denied"),
                (&deny_origin.0, deny_origin.1),
                fs.denied_paths.clone(),
                FS_DENY_SOURCES,
                |_| false,
            );
            tool.fs = keep.then_some(fs);
        } else if let Some(fs) = tool.fs.as_mut() {
            let before: Vec<String> = fs
                .allowed_paths
                .iter()
                .chain(fs.read_only_paths.iter())
                .chain(fs.read_write_paths.iter())
                .cloned()
                .collect();
            for d in &global_fs.denied_paths {
                if !fs.denied_paths.contains(d) {
                    fs.denied_paths.push(d.clone());
                }
            }
            fs.allowed_paths
                .retain(|p| !fs_deny_covers(&fs.denied_paths, p));
            fs.read_only_paths
                .retain(|p| !fs_deny_covers(&fs.denied_paths, p));
            fs.read_write_paths
                .retain(|p| !fs_deny_covers(&fs.denied_paths, p));
            let deny_origin = prov
                .last_writer_of(FS_DENY_SOURCES)
                .unwrap_or_else(|| (file.to_path_buf(), None));
            prov.reproject(
                format!("{key}.filesystem.denied"),
                (&deny_origin.0, deny_origin.1),
                fs.denied_paths.clone(),
                FS_DENY_SOURCES,
                |_| false,
            );
            let mut seen = HashSet::new();
            let dropped: Vec<String> = before
                .into_iter()
                .filter(|p| {
                    !fs.allowed_paths.contains(p)
                        && !fs.read_only_paths.contains(p)
                        && !fs.read_write_paths.contains(p)
                        && seen.insert(p.clone())
                })
                .collect();
            if !dropped.is_empty() {
                prov.prune(
                    format!("{key}.filesystem.allowed"),
                    &deny_origin.0,
                    deny_origin.1,
                    dropped,
                );
            }
        }

        if !tool.network_explicit {
            let mut network = tool_network_base(&global_net, tool.network.as_ref());
            // deny_all_others with an empty allow list is still a closed
            // allow-list: every host must be rejected.
            network.allow_specified |= global_net.outbound.deny_all_others;
            let keep = network.allow_specified
                || !network.allowed_hosts.is_empty()
                || !network.allowed_cidrs.is_empty()
                || !network.denied_hosts.is_empty()
                || !network.denied_cidrs.is_empty();
            let allow_origin = prov
                .last_writer_of(NET_ALLOW_SOURCES)
                .unwrap_or_else(|| (file.to_path_buf(), None));
            let denied_h = network.denied_hosts.clone();
            let denied_c = network.denied_cidrs.clone();
            prov.reproject(
                format!("{key}.network.allow"),
                (&allow_origin.0, allow_origin.1),
                tool_net_allow_items(&network),
                NET_ALLOW_SOURCES,
                move |i| net_item_covered_by_deny(i, &denied_h, &denied_c),
            );
            let deny_origin = prov
                .last_writer_of(NET_DENY_SOURCES)
                .unwrap_or_else(|| (file.to_path_buf(), None));
            prov.reproject(
                format!("{key}.network.deny"),
                (&deny_origin.0, deny_origin.1),
                tool_net_deny_items(&network),
                NET_DENY_SOURCES,
                |_| false,
            );
            tool.network = keep.then_some(network);
        } else if let Some(network) = tool.network.as_mut() {
            let before_allow = tool_net_allow_items(network);
            for d in &global_net.outbound.denied_hosts {
                if !network.denied_hosts.contains(d) {
                    network.denied_hosts.push(d.clone());
                }
            }
            for d in &global_net.outbound.denied_cidrs {
                if !network.denied_cidrs.contains(d) {
                    network.denied_cidrs.push(d.clone());
                }
            }
            crate::policy::apply_tool_network_deny_precedence(network);
            let deny_origin = prov
                .last_writer_of(NET_DENY_SOURCES)
                .unwrap_or_else(|| (file.to_path_buf(), None));
            prov.reproject(
                format!("{key}.network.deny"),
                (&deny_origin.0, deny_origin.1),
                tool_net_deny_items(network),
                NET_DENY_SOURCES,
                |_| false,
            );
            let after_allow = tool_net_allow_items(network);
            let dropped: Vec<String> = before_allow
                .into_iter()
                .filter(|i| !after_allow.contains(i))
                .collect();
            if !dropped.is_empty() {
                prov.prune(
                    format!("{key}.network.allow"),
                    &deny_origin.0,
                    deny_origin.1,
                    dropped,
                );
            }
        }

        if !tool.syscalls_explicit {
            let mut denied = Vec::new();
            if let Some(ref existing) = tool.syscalls {
                denied = existing.denied.clone();
            }
            let denied_check = denied.clone();
            let allowed: Vec<String> = global_sc
                .allowed
                .iter()
                .filter(|s| !denied.contains(s))
                .cloned()
                .collect();
            let keep = !allowed.is_empty() || !denied.is_empty();
            let origin = prov
                .last_writer_of(SC_SOURCES)
                .unwrap_or_else(|| (file.to_path_buf(), None));
            prov.reproject(
                format!("{key}.syscalls.allowed"),
                (&origin.0, origin.1),
                allowed.clone(),
                SC_SOURCES,
                move |i| denied_check.iter().any(|d| d == i),
            );
            prov.reproject(
                format!("{key}.syscalls.denied"),
                (&origin.0, origin.1),
                denied.clone(),
                &[],
                |_| false,
            );
            tool.syscalls = keep.then_some(ToolSyscallPolicy { allowed, denied });
        }
    }
}
