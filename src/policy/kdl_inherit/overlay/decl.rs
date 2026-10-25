use std::collections::HashMap;
use std::path::Path;

use kdl::KdlDocument;

use crate::policy::provenance::DeclOrigin;

use super::{declares_network_posture, node_line, tool_key};

/// Which optional fields the overlay side declared — computed from the
/// overlay document itself for a same-file (`extends`) merge, or
/// accumulated across the included file's whole subtree (its
/// `extends`/`include` ancestors plus matching `when` blocks) for an
/// `include` merge. The subtree view keeps ancestor- and `when`-derived
/// values from silently dropping: node presence in the one included
/// file cannot see them.
#[derive(Debug, Default, Clone)]
pub(in crate::policy::kdl_inherit) struct OverlayDecl {
    pub(in crate::policy::kdl_inherit) transport: bool,
    pub(in crate::policy::kdl_inherit) logging: bool,
    pub(in crate::policy::kdl_inherit) sandbox: bool,
    pub(in crate::policy::kdl_inherit) confused_deputy_protection: bool,
    pub(in crate::policy::kdl_inherit) trajectory: bool,
    /// A `defaults { filesystem { … } }` block — gates `secret-overlay`
    /// (omitted on a declared block stays default-on, fail-secure).
    pub(in crate::policy::kdl_inherit) defaults_filesystem: bool,
    /// A `defaults.network` block carrying children — re-touching
    /// network without restating `inbound` while a listener grant is
    /// in force widens silently, so the merge warns. A childless
    /// `network` node declares nothing (posture and `inbound` both
    /// require children), so it does not flag.
    pub(in crate::policy::kdl_inherit) network: bool,
    /// A bare `allow host="*"` / `deny host="*"` posture node inside
    /// `defaults.network` — the only declaration that moves
    /// `deny_all_others`.
    pub(in crate::policy::kdl_inherit) network_posture: bool,
    /// An `inbound` child inside `defaults.network` — the only
    /// declaration that moves `inbound.allow_listen`.
    pub(in crate::policy::kdl_inherit) network_inbound: bool,
    /// Where each declared field's node lives — file plus the 1-based
    /// line of the declaring node. Keys: `policy`, `transport`,
    /// `logging`, `sandbox`, `confused_deputy_protection`, `trajectory`,
    /// `defaults.filesystem`, `defaults.syscalls`, `defaults.network`,
    /// `defaults.environment`, `server "s"`, `server "s".tool "t"`,
    /// `profile "name"`. Across an include merge the origins travel
    /// with the decl, so a replacement recorded at the boundary names
    /// the file and node that actually wrote the overlay value.
    pub(in crate::policy::kdl_inherit) origins: HashMap<String, DeclOrigin>,
    /// `policy version=3`: the overlay's `defaults.filesystem` block
    /// carried `replace=#true` — its allow side replaces the base's
    /// instead of unioning.
    pub(in crate::policy::kdl_inherit) defaults_fs_replace: bool,
    /// Same for `defaults.syscalls`.
    pub(in crate::policy::kdl_inherit) defaults_syscalls_replace: bool,
    /// Same for `defaults.network`.
    pub(in crate::policy::kdl_inherit) defaults_network_replace: bool,
}

impl OverlayDecl {
    /// Declarations in a top-level policy document. `version` is the
    /// document's declared `policy version=` — the `replace=#true`
    /// properties only count under v3, where the grammar admits them.
    pub(in crate::policy::kdl_inherit) fn for_doc(
        doc: &KdlDocument,
        file: &Path,
        content: &str,
        version: u32,
    ) -> Self {
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
        decl.absorb_shared(doc, file, content, version);
        decl
    }

    /// Declarations inside a matching `when` block's children — the
    /// fields `apply_overrides_from_doc` can apply. `transport` is not
    /// one of them, so it stays unset.
    pub(super) fn for_when_children(
        children: &KdlDocument,
        file: &Path,
        content: &str,
        version: u32,
    ) -> Self {
        let mut decl = Self::default();
        decl.absorb_shared(children, file, content, version);
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
    fn absorb_shared(&mut self, doc: &KdlDocument, file: &Path, content: &str, version: u32) {
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
            // `replace=#true` is a `policy version=3` property — under
            // earlier versions it cannot have parsed, so the flag only
            // reads when this document declared v3.
            if version >= 3 {
                self.defaults_fs_replace |= defaults
                    .get("filesystem")
                    .and_then(|n| n.get("replace"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.defaults_syscalls_replace |= defaults
                    .get("syscalls")
                    .and_then(|n| n.get("replace"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                self.defaults_network_replace |= defaults
                    .get("network")
                    .and_then(|n| n.get("replace"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
            }
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
    pub(in crate::policy::kdl_inherit) fn merge(&mut self, other: &Self) {
        self.transport |= other.transport;
        self.logging |= other.logging;
        self.sandbox |= other.sandbox;
        self.confused_deputy_protection |= other.confused_deputy_protection;
        self.trajectory |= other.trajectory;
        self.defaults_filesystem |= other.defaults_filesystem;
        self.network |= other.network;
        self.network_posture |= other.network_posture;
        self.network_inbound |= other.network_inbound;
        // `replace` applies at the merge boundary of the document that
        // declared it — an ancestor's flag must not re-fire when a
        // descendant is itself overlaid. Like `origins`, each flag
        // tracks the most recent declaration: a scope that did not
        // declare the block leaves the earlier writer's flag alone.
        if other.defaults_filesystem {
            self.defaults_fs_replace = other.defaults_fs_replace;
        }
        if other.origins.contains_key("defaults.syscalls") {
            self.defaults_syscalls_replace = other.defaults_syscalls_replace;
        }
        if other.network {
            self.defaults_network_replace = other.defaults_network_replace;
        }
        self.origins
            .extend(other.origins.iter().map(|(k, v)| (k.clone(), v.clone())));
    }

    /// At a subtree boundary only this file's own `replace` intent may
    /// travel upward: an ancestor's or an included file's flag was
    /// consumed by its own merge inside this subtree — re-exporting it
    /// would re-fire that narrowing at an includer's boundary against
    /// grants the declaring file never saw. `merge` already keeps the
    /// latest writer's flag, so a block this file declared (doc or
    /// `when`) keeps its value; a flag left by anything else clears.
    pub(in crate::policy::kdl_inherit) fn retain_own_replace_flags(
        &mut self,
        doc_decl: &Self,
        when_decl: &Self,
    ) {
        if !doc_decl.defaults_filesystem && !when_decl.defaults_filesystem {
            self.defaults_fs_replace = false;
        }
        if !doc_decl.origins.contains_key("defaults.syscalls")
            && !when_decl.origins.contains_key("defaults.syscalls")
        {
            self.defaults_syscalls_replace = false;
        }
        if !doc_decl.network && !when_decl.network {
            self.defaults_network_replace = false;
        }
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
