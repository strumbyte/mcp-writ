use std::path::Path;

use crate::policy::Policy;
use crate::policy::provenance::Provenance;

use super::tool::{merge_tool_fs, merge_tool_network, merge_tool_syscalls, seed_tool_fields};
use super::{OverlayDecl, fs_deny_covers, prune_covered, tool_key};

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
/// `rules` is the composition-semantics version the overlay document
/// runs under — its declared `policy version`, or the simulated version
/// `policy resolve --version-diff` asks for. Under v3 (`rules >= 3`),
/// allow sides union by default; `replace=#true` on the overlay's
/// `defaults` sub-blocks or tool blocks opts back into replacement.
///
/// Every write the merge performs is logged on `prov` — `file` is the
/// fallback attribution when the decl carries no node origin (e.g. a
/// flag set by an untracked subtree member); the decl's origins name
/// the file and line that actually declared each field.
pub(in crate::policy::kdl_inherit) fn merge_into_policy(
    base: &mut Policy,
    overlay: &Policy,
    decl: &OverlayDecl,
    file: &Path,
    prov: &mut Provenance,
    rules: u32,
) {
    // version: overlay wins — every document declares `policy`. The
    // entry file's version stamps the merged artifact, which is what
    // makes version a feature boundary rather than a max: a v2
    // declaration composing into a v1 document (a `deputy` block
    // through `include`) must keep the effective version at 1 so the
    // validator refuses it — the same fail-closed rule a v3
    // declaration (`defaults.syscalls { deny }` inherited from a v3
    // ancestor into a v2 child) hits. Taking the maximum would let a
    // higher-version ancestor silently upgrade the feature set the
    // entry document opted into.
    base.version = overlay.version;
    let (f, l) = decl.origin("policy", file);
    prov.set("version", f, l);

    // transport: overlay wins if the overlay side declared it
    if decl.transport {
        base.transport = overlay.transport.clone();
        let (f, l) = decl.origin("transport", file);
        prov.set("transport", f, l);
    }

    // fs: extends/include union allow lists; denies stay sticky. Under
    // v3 an explicit `replace=#true` on the overlay's `defaults.filesystem`
    // block opts back into wholesale replacement — including an empty
    // allow side, which clears the accumulated lists — but only when
    // the block declared a value at all: a bare `filesystem` node moves
    // nothing, mirroring the childless-`network` rule.
    let fs_replaces = rules >= 3 && decl.defaults_fs_replace;
    if overlay.fs.allow_specified || (fs_replaces && !overlay.fs.denied_paths.is_empty()) {
        let (f, l) = decl.origin("defaults.filesystem", file);
        if fs_replaces {
            prov.replace(
                "defaults.filesystem.read_only",
                f,
                l,
                overlay.fs.read_only.clone(),
            );
            prov.replace(
                "defaults.filesystem.read_write",
                f,
                l,
                overlay.fs.read_write.clone(),
            );
            prov.replace(
                "defaults.filesystem.executable",
                f,
                l,
                overlay.fs.executable.clone(),
            );
            base.fs.read_only = overlay.fs.read_only.clone();
            base.fs.read_write = overlay.fs.read_write.clone();
            base.fs.executable = overlay.fs.executable.clone();
        } else {
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
    let (f, l) = decl.origin("defaults.filesystem", file);
    for (field, list) in [
        ("defaults.filesystem.read_only", &mut base.fs.read_only),
        ("defaults.filesystem.read_write", &mut base.fs.read_write),
        ("defaults.filesystem.executable", &mut base.fs.executable),
    ] {
        prune_covered(list, |p| fs_deny_covers(&denied_now, p), prov, field, f, l);
    }
    // Then the narrower-grant narrowing: a path spelled `mode="read"`
    // stays read-only even if it was also declared `mode="write"` or
    // `mode="exec"` — the narrower grant wins.
    let read_now = base.fs.read_only.clone();
    for (field, list) in [
        ("defaults.filesystem.read_write", &mut base.fs.read_write),
        ("defaults.filesystem.executable", &mut base.fs.executable),
    ] {
        prune_covered(list, |p| read_now.contains(p), prov, field, f, l);
    }

    // syscalls: under v3 the allow side unions by default (replace only
    // on `replace=#true`, including an explicit empty list); under v2 a
    // non-empty allow list replaces. `deny` entries — a v3 declaration —
    // union like every deny side, then prune the allow side. The grammar
    // has no `allow none=#true` spelling, so a declared `replace=#true`
    // is itself the explicit empty list — it counts as a declaration
    // even when both lists parse empty.
    let sc_origin = decl.origin("defaults.syscalls", file);
    let sc_declared = !overlay.syscalls.allowed.is_empty()
        || !overlay.syscalls.denied.is_empty()
        || (rules >= 3 && decl.defaults_syscalls_replace);
    if sc_declared && rules >= 3 {
        if decl.defaults_syscalls_replace {
            prov.replace(
                "defaults.syscalls",
                sc_origin.0,
                sc_origin.1,
                overlay.syscalls.allowed.clone(),
            );
            base.syscalls.allowed = overlay.syscalls.allowed.clone();
        } else {
            prov.union(
                "defaults.syscalls",
                sc_origin.0,
                sc_origin.1,
                overlay.syscalls.allowed.iter().cloned(),
            );
            for s in &overlay.syscalls.allowed {
                if !base.syscalls.allowed.contains(s) {
                    base.syscalls.allowed.push(s.clone());
                }
            }
        }
    } else if !overlay.syscalls.allowed.is_empty() {
        base.syscalls.allowed = overlay.syscalls.allowed.clone();
        prov.replace(
            "defaults.syscalls",
            sc_origin.0,
            sc_origin.1,
            overlay.syscalls.allowed.clone(),
        );
    }
    if !overlay.syscalls.denied.is_empty() {
        prov.union(
            "defaults.syscalls.denied",
            sc_origin.0,
            sc_origin.1,
            overlay.syscalls.denied.iter().cloned(),
        );
        for s in &overlay.syscalls.denied {
            if !base.syscalls.denied.contains(s) {
                base.syscalls.denied.push(s.clone());
            }
        }
        // Deny-wins: a syscall denied at any layer leaves the allow side.
        let denied_now = base.syscalls.denied.clone();
        prune_covered(
            &mut base.syscalls.allowed,
            |s| denied_now.contains(s),
            prov,
            "defaults.syscalls",
            sc_origin.0,
            sc_origin.1,
        );
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
    let overlay_has_allow = !overlay.network.outbound.allowed.is_empty()
        || !overlay.network.outbound.allowed_cidrs.is_empty()
        || overlay_rules.iter().any(|r| r.allow);
    // Under v3 the allow side unions by default; `replace=#true` on the
    // overlay's `defaults.network` block opts back into replacement —
    // including an empty allow side, which clears the accumulated rules.
    let net_replace = rules < 3 || decl.defaults_network_replace;
    if overlay_has_allow || (rules >= 3 && decl.defaults_network_replace && decl.network) {
        let (f, l) = decl.origin("defaults.network", file);
        // One `describe`d spelling per declared allow rule — the flat
        // lists are the same rules' projections, so chaining them would
        // double-count and lose the proto/port/`unix=` qualifiers.
        let items: Vec<String> = overlay_rules
            .iter()
            .filter(|r| r.allow)
            .map(|r| r.describe())
            .collect();
        if net_replace {
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
            prov.replace("defaults.network.allow", f, l, items);
        } else {
            for h in &overlay.network.outbound.allowed {
                if !base.network.outbound.allowed.contains(h) {
                    base.network.outbound.allowed.push(h.clone());
                }
            }
            for s in &overlay.network.outbound.allowed_port_qualified {
                if !base.network.outbound.allowed_port_qualified.contains(s) {
                    base.network.outbound.allowed_port_qualified.push(s.clone());
                }
            }
            for c in &overlay.network.outbound.allowed_cidrs {
                if !base.network.outbound.allowed_cidrs.contains(c) {
                    base.network.outbound.allowed_cidrs.push(c.clone());
                }
            }
            for s in &overlay.network.outbound.allowed_cidrs_port_qualified {
                if !base
                    .network
                    .outbound
                    .allowed_cidrs_port_qualified
                    .contains(s)
                {
                    base.network
                        .outbound
                        .allowed_cidrs_port_qualified
                        .push(s.clone());
                }
            }
            for r in &overlay_rules {
                if r.allow && !base.network.outbound.egress_rules.contains(r) {
                    base.network.outbound.egress_rules.push(r.clone());
                }
            }
            prov.union("defaults.network.allow", f, l, items);
        }
    }
    {
        let (f, l) = decl.origin("defaults.network", file);
        let deny_items: Vec<String> = overlay_rules
            .iter()
            .filter(|r| !r.allow)
            .map(|r| r.describe())
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
        // pre-existing ones — record the rules it drops: a flat entry
        // and its rule projection move together, and the rule spelling
        // is what the `defaults.network.allow` writers track.
        let before_rules = base.network.outbound.egress_rules.clone();
        crate::policy::apply_outbound_deny_precedence(&mut base.network.outbound);
        let mut dropped: Vec<String> = before_rules
            .iter()
            .filter(|r| r.allow && !base.network.outbound.egress_rules.contains(r))
            .map(|r| r.describe())
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
                merge_tool_fs(
                    &mut existing.fs,
                    tool.fs.as_ref(),
                    prov,
                    &key,
                    f,
                    l,
                    rules >= 3,
                    tool.fs_replace,
                );
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
                    rules >= 3,
                    tool.syscalls_replace,
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
                    rules >= 3,
                    tool.network_replace,
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
