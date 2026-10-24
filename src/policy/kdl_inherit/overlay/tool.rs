use std::collections::HashSet;
use std::path::Path;

use crate::policy::provenance::Provenance;
use crate::policy::{
    FsPolicy, FsToolPolicy, NetworkPolicy, Policy, ToolNetworkPolicy, ToolPolicy, ToolSyscallPolicy,
};

use super::{fs_deny_covers, prune_covered, tool_key};

/// The allow-side spellings a tool `network` block carries — one
/// `describe`d item per declared allow rule. The rules already project
/// every flat `allowed_hosts`/`allowed_cidrs` entry, so listing the
/// flat spellings beside them would count each rule twice and drop
/// the proto/port qualifiers only `describe` preserves. One ordering
/// feeds the merge provenance, the new-tool seed, and
/// rematerialization.
fn tool_net_allow_items(net: &ToolNetworkPolicy) -> Vec<String> {
    net.egress_rule_set()
        .iter()
        .filter(|r| r.allow)
        .map(|r| r.describe())
        .collect()
}

/// The deny-side counterpart of [`tool_net_allow_items`].
fn tool_net_deny_items(net: &ToolNetworkPolicy) -> Vec<String> {
    net.egress_rule_set()
        .iter()
        .filter(|r| !r.allow)
        .map(|r| r.describe())
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

/// Record a newly declared tool's per-field contents — only the
/// fields the tool itself declared (`*_explicit`). Entries the merge
/// materialized from defaults are attributed to the defaults' own
/// writers via `sources`; entries the sources do not know — the tool's
/// own declarations or ones a profile/`server-defaults` layer carried —
/// fall back to `origin` (the tool declaration site). Fields the tool
/// did not declare are materialized — and attributed — by
/// [`rematerialize_inherited_defaults`] instead.
pub(super) fn seed_tool_fields(
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

/// Merge an overlay tool's declared `filesystem` block onto the base
/// tool's: `require_path` replaces when the overlay set it, denies
/// accumulate, then deny-wins prunes every allow a deny pattern covers
/// (`fs_deny_covers` — additive OS rulesets have no negative rule to
/// carve a covered allow back out). The allow side replaces when the
/// overlay spelled one under v1/v2 (`union_allows` false); under v3 it
/// unions unless the overlay's block carried `replace=#true`
/// (`over_replace`) — including an explicit empty allow side, which
/// clears the accumulated list. A missing base adopts the overlay
/// wholesale; a missing overlay leaves the base untouched. Shared by
/// the extends/include merge and `when` overrides so both paths apply
/// the same semantics — callers gate on the tool's own declaration
/// (`fs_explicit`), never on materialized defaults.
#[expect(clippy::too_many_arguments)]
pub(super) fn merge_tool_fs(
    base: &mut Option<FsToolPolicy>,
    over: Option<&FsToolPolicy>,
    prov: &mut Provenance,
    key: &str,
    file: &Path,
    line: Option<u32>,
    union_allows: bool,
    over_replace: bool,
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
    let replaces_allow = over_fs.allow_specified && !(union_allows && !over_replace);
    if replaces_allow {
        prov.replace(&allow_key, file, line, over_fs.allowed_paths.clone());
        base_fs.allowed_paths = over_fs.allowed_paths.clone();
        base_fs.read_only_paths = over_fs.read_only_paths.clone();
        base_fs.read_write_paths = over_fs.read_write_paths.clone();
        base_fs.allow_specified = true;
    } else if over_fs.allow_specified {
        prov.union(
            &allow_key,
            file,
            line,
            over_fs.allowed_paths.iter().cloned(),
        );
        for p in &over_fs.allowed_paths {
            if !base_fs.allowed_paths.contains(p) {
                base_fs.allowed_paths.push(p.clone());
            }
        }
        for p in &over_fs.read_only_paths {
            if !base_fs.read_only_paths.contains(p) {
                base_fs.read_only_paths.push(p.clone());
            }
        }
        for p in &over_fs.read_write_paths {
            if !base_fs.read_write_paths.contains(p) {
                base_fs.read_write_paths.push(p.clone());
            }
        }
        base_fs.allow_specified = true;
    } else if union_allows && over_replace {
        // `filesystem replace=#true` with no allow side declared —
        // clear the inherited allow lists (the `allow none=#true`
        // spelling pairs with `replace` for exactly this).
        prov.replace(&allow_key, file, line, Vec::new());
        base_fs.allowed_paths.clear();
        base_fs.read_only_paths.clear();
        base_fs.read_write_paths.clear();
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
        prune_covered(
            list,
            |p| fs_deny_covers(&base_fs.denied_paths, p),
            prov,
            &allow_key,
            file,
            line,
        );
    }
}

/// Same shape for a tool's `syscalls` block: under v1/v2 a non-empty
/// allow list replaces; under v3 (`union_allows`) it unions unless the
/// overlay block carried `replace=#true` (`over_replace`). Denied
/// names accumulate and re-prune the allow side either way.
#[expect(clippy::too_many_arguments)]
pub(super) fn merge_tool_syscalls(
    base: &mut Option<ToolSyscallPolicy>,
    over: Option<&ToolSyscallPolicy>,
    prov: &mut Provenance,
    key: &str,
    file: &Path,
    line: Option<u32>,
    union_allows: bool,
    over_replace: bool,
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
    if !(over_sc.allowed.is_empty() && !(union_allows && over_replace)) {
        if union_allows && !over_replace {
            prov.union(&allow_key, file, line, over_sc.allowed.iter().cloned());
            for s in &over_sc.allowed {
                if !base_sc.allowed.contains(s) {
                    base_sc.allowed.push(s.clone());
                }
            }
        } else {
            prov.replace(&allow_key, file, line, over_sc.allowed.clone());
            base_sc.allowed = over_sc.allowed.clone();
        }
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

/// And for a tool's `network` block: under v1/v2 the allow side
/// (hosts, CIDRs and allow-rules) replaces when the overlay declared
/// one; under v3 (`union_allows`) it unions unless the overlay block
/// carried `replace=#true` (`over_replace`). Denied hosts, CIDRs and
/// deny-rules accumulate either way, then deny precedence reapplies.
#[expect(clippy::too_many_arguments)]
pub(super) fn merge_tool_network(
    base: &mut Option<ToolNetworkPolicy>,
    over: Option<&ToolNetworkPolicy>,
    prov: &mut Provenance,
    key: &str,
    file: &Path,
    line: Option<u32>,
    union_allows: bool,
    over_replace: bool,
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
    let over_has_allow = over_net.allow_specified || over_net.egress_rules.iter().any(|r| r.allow);
    if over_has_allow && !(union_allows && !over_replace) {
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
    } else if over_has_allow {
        prov.union(&allow_key, file, line, allow_items(over_net));
        for h in &over_net.allowed_hosts {
            if !base_net.allowed_hosts.contains(h) {
                base_net.allowed_hosts.push(h.clone());
            }
        }
        for c in &over_net.allowed_cidrs {
            if !base_net.allowed_cidrs.contains(c) {
                base_net.allowed_cidrs.push(c.clone());
            }
        }
        base_net.allow_specified = true;
        for r in &over_net.egress_rules {
            if r.allow && !base_net.egress_rules.contains(r) {
                base_net.egress_rules.push(r.clone());
            }
        }
    } else if union_allows && over_replace {
        // `network replace=#true` with no allow side — the tool's v3
        // declaration means "clear the inherited allow side" (the
        // `allow none=#true` spelling pairs with `replace` for this).
        prov.replace(&allow_key, file, line, allow_items(over_net));
        base_net.allowed_hosts.clear();
        base_net.allowed_cidrs.clear();
        base_net.allow_specified = true;
        base_net.egress_rules.retain(|r| !r.allow);
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
            // Deny is sticky: defaults-level `deny` entries (v3) and any
            // the tool already carries narrow the materialized grant.
            let mut denied = global_sc.denied.clone();
            if let Some(ref existing) = tool.syscalls {
                for d in &existing.denied {
                    if !denied.contains(d) {
                        denied.push(d.clone());
                    }
                }
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
                SC_SOURCES,
                |_| false,
            );
            tool.syscalls = keep.then_some(ToolSyscallPolicy { allowed, denied });
        } else if let Some(sc) = tool.syscalls.as_mut() {
            // Even a tool with its own `syscalls` block takes the global
            // denies — deny-wins does not stop at a declared scope.
            for d in &global_sc.denied {
                if !sc.denied.contains(d) {
                    sc.denied.push(d.clone());
                }
            }
            let dropped: Vec<String> = sc
                .allowed
                .iter()
                .filter(|s| sc.denied.contains(s))
                .cloned()
                .collect();
            sc.allowed.retain(|s| !dropped.contains(s));
            if !dropped.is_empty() {
                let origin = prov
                    .last_writer_of(SC_SOURCES)
                    .unwrap_or_else(|| (file.to_path_buf(), None));
                prov.prune(
                    format!("{key}.syscalls.allowed"),
                    &origin.0,
                    origin.1,
                    dropped,
                );
            }
        }
    }
}
