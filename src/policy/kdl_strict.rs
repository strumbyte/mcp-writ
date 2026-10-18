//! Version-aware schema checks for KDL policy documents.
//!
//! The parser is deliberately permissive in places — a `policy version=1`
//! document keeps loading even where it spells something the grammar
//! never reads (an unknown top-level node, a second `extends`, extra
//! arguments on `include`, an unrecognized `transport type`, a `when`
//! carrying attributes other than `environment`, an unknown child under
//! `defaults`/`profile`/`server-defaults`, malformed `profile`/`profiles`
//! references on a tool, or duplicate declarations). Under `version=2`
//! every such spelling is a load error; under `version=1` each one
//! produces a `schema` warning that names the node and says it is
//! ignored — the same load result, never silent.
//!
//! Strictness is per file: every document in an `extends`/`include`
//! chain declares its own `policy version`, and each is checked against
//! that declaration as it is loaded.

use std::collections::HashMap;
use std::path::Path;

use kdl::{KdlDocument, KdlNode};

use crate::error::PolicyError;
use crate::policy::kdl_inherit::node_line;
use crate::policy::provenance::{LoadWarning, LoadWarningKind};

/// Nodes a top-level policy document may declare — everything else is
/// silently unread today and is what these checks flag.
const TOP_LEVEL_NODES: &[&str] = &[
    "policy",
    "transport",
    "extends",
    "include",
    "when",
    "defaults",
    "logging",
    "sandbox",
    "confused_deputy_protection",
    "trajectory",
    "server",
    "profile",
];

/// Top-level nodes that may appear at most once — `doc.get` returns
/// the first and drops the rest.
const SINGLETON_NODES: &[&str] = &[
    "policy",
    "transport",
    "extends",
    "defaults",
    "logging",
    "sandbox",
    "confused_deputy_protection",
    "trajectory",
];

/// Nodes a matching `when` block can override — `apply_overrides_from_doc`
/// reads exactly these; every other node inside `when` is dropped.
const WHEN_CHILD_NODES: &[&str] = &[
    "defaults",
    "logging",
    "sandbox",
    "confused_deputy_protection",
    "trajectory",
    "server",
];

/// Children `defaults` may carry — `parse_defaults` reads exactly these.
const DEFAULTS_CHILD_NODES: &[&str] = &["filesystem", "syscalls", "network", "environment"];

/// Children a `profile`/`server-defaults` layer may carry —
/// `parse_layer_children` reads exactly these (`environment` is already
/// rejected by the parser).
const LAYER_CHILD_NODES: &[&str] = &["filesystem", "syscalls", "network"];

/// Children a `tool` may carry — `parse_servers`/`apply_overrides_from_doc`
/// read these; `environment` is already rejected.
const TOOL_CHILD_NODES: &[&str] = &[
    "filesystem",
    "syscalls",
    "network",
    "process",
    "environment",
    "profile",
    "profiles",
    "deputy",
];

/// Properties a `tool` may carry.
const TOOL_PROPS: &[&str] = &[
    "deny",
    "args_schema",
    "side_effect",
    "input_responses",
    "profile",
];

struct Check<'a> {
    file: &'a Path,
    content: &'a str,
    strict: bool,
    warnings: &'a mut Vec<LoadWarning>,
}

impl Check<'_> {
    fn line(&self, node: &KdlNode) -> Option<u32> {
        node_line(self.content, node)
    }

    /// `strict` (`version >= 2`) refuses the declaration; lax
    /// (`version <= 1`) warns and keeps loading.
    fn finding(&mut self, node: &KdlNode, message: String) -> Result<(), PolicyError> {
        if self.strict {
            return Err(PolicyError::KdlParse(format!(
                "'{}': {message}",
                self.file.display()
            )));
        }
        self.warnings.push(LoadWarning {
            kind: LoadWarningKind::Schema,
            file: self.file.to_path_buf(),
            line: self.line(node),
            message,
        });
        Ok(())
    }
}

/// Check one document for declarations the parser drops silently.
/// `version` is the file's own `policy version=` — v2 refuses, v1 warns.
pub(crate) fn check_doc_schema(
    doc: &KdlDocument,
    path: &Path,
    content: &str,
    version: u32,
    warnings: &mut Vec<LoadWarning>,
) -> Result<(), PolicyError> {
    let mut cx = Check {
        file: path,
        content,
        strict: version >= 2,
        warnings,
    };
    let mut singletons: HashMap<String, usize> = HashMap::new();
    let mut server_names: HashMap<String, ()> = HashMap::new();
    let mut profile_names: HashMap<String, ()> = HashMap::new();
    for node in doc.nodes() {
        let name = node.name().value().to_string();
        if !TOP_LEVEL_NODES.contains(&name.as_str()) {
            cx.finding(
                node,
                format!("unknown top-level node '{name}' — it is ignored"),
            )?;
            continue;
        }
        if SINGLETON_NODES.contains(&name.as_str()) {
            let count = singletons.entry(name.clone()).or_insert(0);
            *count += 1;
            if *count > 1 {
                cx.finding(
                    node,
                    format!("duplicate '{name}' — the later declaration is ignored"),
                )?;
            }
        }
        match name.as_str() {
            "policy" => check_policy_node(&mut cx, node)?,
            "transport" => check_transport_node(&mut cx, node)?,
            "extends" => check_extends_node(&mut cx, node)?,
            "include" => check_include_node(&mut cx, node)?,
            "when" => check_when_node(&mut cx, node)?,
            "defaults" => check_defaults_node(&mut cx, node)?,
            "logging" => check_props(
                &mut cx,
                node,
                &["level", "fail_closed"],
                "logging",
                0,
                false,
            )?,
            "sandbox" => check_props(&mut cx, node, &["allow_degraded"], "sandbox", 0, false)?,
            "confused_deputy_protection" => {
                check_props(&mut cx, node, &[], "confused_deputy_protection", 1, false)?
            }
            "trajectory" => check_trajectory_node(&mut cx, node)?,
            "server" => check_server_node(&mut cx, node, Some(&mut server_names))?,
            "profile" => check_profile_def(&mut cx, node, &mut profile_names)?,
            _ => {}
        }
    }
    Ok(())
}

/// A node that takes at most `max_args` positional arguments, only the
/// listed properties, and (when `children` is false) no body — anything
/// else is ignored text.
fn check_props(
    cx: &mut Check<'_>,
    node: &KdlNode,
    props: &[&str],
    ctx: &str,
    max_args: usize,
    children: bool,
) -> Result<(), PolicyError> {
    let args = node.entries().iter().filter(|e| e.name().is_none()).count();
    if args > max_args {
        cx.finding(
            node,
            format!("unexpected extra argument(s) on '{ctx}' — they are ignored"),
        )?;
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name()
            && !props.contains(&prop.value())
        {
            cx.finding(
                node,
                format!(
                    "unknown property '{}' on '{ctx}' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    if !children && node.children().is_some() {
        cx.finding(
            node,
            format!("'{ctx}' takes no children — they are ignored"),
        )?;
    }
    Ok(())
}

fn check_policy_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    check_props(cx, node, &["version"], "policy", 0, false)
}

fn check_transport_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    check_props(cx, node, &["type", "listen_addr"], "transport", 0, false)?;
    if let Some(v) = node.get("type")
        && let Some(t) = v.as_string()
        && !matches!(t, "stdio" | "http")
    {
        cx.finding(
            node,
            format!("unknown transport type '{t}' — it is treated as 'stdio'"),
        )?;
    }
    Ok(())
}

fn check_extends_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    let args = node.entries().iter().filter(|e| e.name().is_none()).count();
    if args > 1 {
        cx.finding(
            node,
            "unexpected extra argument(s) on 'extends' — they are ignored".to_string(),
        )?;
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name() {
            cx.finding(
                node,
                format!(
                    "unexpected property '{}' on 'extends' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    if node.children().is_some() {
        cx.finding(
            node,
            "'extends' takes no children — they are ignored".to_string(),
        )?;
    }
    Ok(())
}

fn check_include_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    let args = node.entries().iter().filter(|e| e.name().is_none()).count();
    if args > 1 {
        cx.finding(
            node,
            "unexpected extra argument(s) on 'include' — only the first is loaded".to_string(),
        )?;
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name() {
            cx.finding(
                node,
                format!(
                    "unexpected property '{}' on 'include' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    if node.children().is_some() {
        cx.finding(
            node,
            "'include' takes no children — they are ignored".to_string(),
        )?;
    }
    Ok(())
}

fn check_when_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    for entry in node.entries() {
        match entry.name() {
            None => cx.finding(
                node,
                "unexpected argument on 'when' — only the 'environment' condition \
                 is supported"
                    .to_string(),
            )?,
            Some(prop) if prop.value() != "environment" => cx.finding(
                node,
                format!(
                    "unknown condition attribute '{}' on 'when' — the attribute is ignored; \
                     the block still applies when its 'environment' condition matches",
                    prop.value()
                ),
            )?,
            _ => {}
        }
    }
    if node
        .get("environment")
        .and_then(|v| v.as_string())
        .is_none()
    {
        cx.finding(
            node,
            "'when' without a string 'environment' condition never matches — the \
             block is ignored"
                .to_string(),
        )?;
    }
    let Some(children) = node.children() else {
        return Ok(());
    };
    let mut seen: HashMap<String, ()> = HashMap::new();
    for child in children.nodes() {
        let name = child.name().value().to_string();
        if !WHEN_CHILD_NODES.contains(&name.as_str()) {
            cx.finding(child, format!("node '{name}' inside 'when' is ignored"))?;
            continue;
        }
        // A second `defaults`/`server` for the same target inside one
        // `when` is rejected by unique_child at apply time; a second
        // logging/sandbox/cdp/trajectory just wins later — same silent
        // shadowing as top-level singletons.
        if !matches!(name.as_str(), "server") {
            let key = name.clone();
            if seen.insert(key.clone(), ()).is_some() {
                cx.finding(
                    child,
                    format!("duplicate '{name}' inside 'when' — the later declaration wins"),
                )?;
            }
        }
        match name.as_str() {
            "defaults" => check_defaults_node(cx, child)?,
            "server" => check_server_node(cx, child, None)?,
            "logging" => check_props(cx, child, &["level", "fail_closed"], "logging", 0, false)?,
            "sandbox" => check_props(cx, child, &["allow_degraded"], "sandbox", 0, false)?,
            "confused_deputy_protection" => {
                check_props(cx, child, &[], "confused_deputy_protection", 1, false)?
            }
            "trajectory" => check_trajectory_node(cx, child)?,
            _ => {}
        }
    }
    Ok(())
}

fn check_defaults_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    check_props(cx, node, &[], "defaults", 0, true)?;
    let Some(children) = node.children() else {
        return Ok(());
    };
    let mut seen: HashMap<String, ()> = HashMap::new();
    for child in children.nodes() {
        let name = child.name().value().to_string();
        if !DEFAULTS_CHILD_NODES.contains(&name.as_str()) {
            cx.finding(
                child,
                format!("unknown node '{name}' under 'defaults' — it is ignored"),
            )?;
            continue;
        }
        if seen.insert(name.clone(), ()).is_some() {
            cx.finding(
                child,
                format!("duplicate '{name}' under 'defaults' — the parser takes the first"),
            )?;
        }
        match name.as_str() {
            "filesystem" => check_fs_entries(cx, child)?,
            "syscalls" => check_list_entries(cx, child, "syscalls")?,
            "network" => check_network_entries(cx, child)?,
            _ => {}
        }
    }
    Ok(())
}

/// Duplicate `allow`/`deny`/`require-path`/`secret-overlay` entries in a
/// `filesystem` block — the parser already rejects unknown members.
fn check_fs_entries(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    let mut seen: HashMap<String, ()> = HashMap::new();
    for child in children.nodes() {
        let name = child.name().value();
        if !matches!(name, "allow" | "deny") {
            continue;
        }
        let key = format!(
            "{name} {}",
            child
                .entries()
                .iter()
                .map(|e| format!("{:?}", e.value()))
                .collect::<Vec<_>>()
                .join(" ")
        );
        if seen.insert(key.clone(), ()).is_some() {
            cx.finding(
                child,
                format!("duplicate '{name}' entry in 'filesystem' — {key}"),
            )?;
        }
    }
    Ok(())
}

/// Duplicate entries in a `syscalls`/`environment`-style `allow`
/// string list. `allow` and `deny` are distinct declarations — a
/// `deny "x"` beside `allow "x"` is the deny-wins rule, not a
/// duplicate — so entries key on the directive name as well as the
/// value (the same keying `check_fs_entries`/`check_network_entries`
/// use).
fn check_list_entries(cx: &mut Check<'_>, node: &KdlNode, ctx: &str) -> Result<(), PolicyError> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    let mut seen: HashMap<String, ()> = HashMap::new();
    for child in children.nodes() {
        let name = child.name().value();
        if !matches!(name, "allow" | "deny") {
            continue;
        }
        for entry in child.entries() {
            if let Some(v) = entry.value().as_string()
                && seen.insert(format!("{name} {v:?}"), ()).is_some()
            {
                cx.finding(
                    child,
                    format!("duplicate '{name} \"{v}\"' entry in '{ctx}' — it is ignored"),
                )?;
            }
        }
    }
    Ok(())
}

/// Duplicate destination declarations in a `network` block —
/// `allow host=`/`cidr=`/`unix=` spelled identically twice.
fn check_network_entries(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    let mut seen: HashMap<String, ()> = HashMap::new();
    for child in children.nodes() {
        let name = child.name().value();
        if !matches!(name, "allow" | "deny") {
            continue;
        }
        let key = format!(
            "{name} {}",
            child
                .entries()
                .iter()
                .map(|e| {
                    format!(
                        "{}={:?}",
                        e.name().map(|n| n.value()).unwrap_or("_"),
                        e.value()
                    )
                })
                .collect::<Vec<_>>()
                .join(" ")
        );
        if seen.insert(key.clone(), ()).is_some() {
            cx.finding(
                child,
                format!("duplicate '{name}' rule in 'network' — {key}"),
            )?;
        }
    }
    Ok(())
}

fn check_trajectory_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    // `trajectory #bool` with `after` children; the parser already
    // refuses unknown children and missing after-properties.
    let args = node.entries().iter().filter(|e| e.name().is_none()).count();
    if args > 1 {
        cx.finding(
            node,
            "unexpected extra argument(s) on 'trajectory' — they are ignored".to_string(),
        )?;
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name() {
            cx.finding(
                node,
                format!(
                    "unexpected property '{}' on 'trajectory' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    Ok(())
}

fn check_server_node(
    cx: &mut Check<'_>,
    node: &KdlNode,
    seen: Option<&mut HashMap<String, ()>>,
) -> Result<(), PolicyError> {
    // Extra positional arguments or properties on `server` are dropped.
    let args: Vec<_> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect();
    if args.len() > 1 {
        cx.finding(
            node,
            "unexpected extra argument(s) on 'server' — they are ignored".to_string(),
        )?;
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name() {
            cx.finding(
                node,
                format!(
                    "unexpected property '{}' on 'server' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    // Duplicate `server` names are only silent shadowing at top level:
    // inside `when`, sibling `server` blocks apply sequentially.
    if let (Some(name), Some(seen)) = (node.get(0).and_then(|v| v.as_string()), seen)
        && seen.insert(name.to_string(), ()).is_some()
    {
        cx.finding(
            node,
            format!("duplicate server '{name}' — a tool declared in both is shadowed by the first"),
        )?;
    }
    let Some(children) = node.children() else {
        return Ok(());
    };
    let mut tool_names: HashMap<String, ()> = HashMap::new();
    for child in children.nodes() {
        match child.name().value() {
            "tool" => {
                if let Some(t) = child.get(0).and_then(|v| v.as_string())
                    && tool_names.insert(t.to_string(), ()).is_some()
                {
                    cx.finding(
                        child,
                        format!(
                            "duplicate tool '{t}' in the same server — the second declaration is dropped"
                        ),
                    )?;
                }
                check_tool_node(cx, child)?;
            }
            "server-defaults" => check_layer_children(cx, child, "server-defaults")?,
            _ => {}
        }
    }
    Ok(())
}

/// `profile`/`server-defaults` layer children beyond the three blocks
/// `parse_layer_children` reads.
fn check_layer_children(cx: &mut Check<'_>, node: &KdlNode, ctx: &str) -> Result<(), PolicyError> {
    let Some(children) = node.children() else {
        return Ok(());
    };
    let mut seen: HashMap<String, ()> = HashMap::new();
    for child in children.nodes() {
        let name = child.name().value().to_string();
        if !LAYER_CHILD_NODES.contains(&name.as_str()) {
            // `environment` is a hard parse error already; flag the rest.
            if name != "environment" {
                cx.finding(
                    child,
                    format!("unknown node '{name}' under '{ctx}' — it is ignored"),
                )?;
            }
            continue;
        }
        if seen.insert(name.clone(), ()).is_some() {
            cx.finding(
                child,
                format!("duplicate '{name}' under '{ctx}' — the parser takes the first"),
            )?;
        }
        match name.as_str() {
            "filesystem" => check_fs_entries(cx, child)?,
            "syscalls" => check_list_entries(cx, child, "syscalls")?,
            "network" => check_network_entries(cx, child)?,
            _ => {}
        }
    }
    Ok(())
}

/// Tool children/properties the parsers drop for v1 — plus the
/// `profile`/`profiles` reference strictness (task: exactly one string
/// argument, no properties, no children).
fn check_tool_node(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    for entry in node.entries() {
        if let Some(prop) = entry.name()
            && !TOOL_PROPS.contains(&prop.value())
        {
            cx.finding(
                node,
                format!(
                    "unknown property '{}' on 'tool' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    let args = node.entries().iter().filter(|e| e.name().is_none()).count();
    if args > 1 {
        cx.finding(
            node,
            "unexpected extra argument(s) on 'tool' — they are ignored".to_string(),
        )?;
    }
    let Some(children) = node.children() else {
        return Ok(());
    };
    for child in children.nodes() {
        let name = child.name().value().to_string();
        if !TOOL_CHILD_NODES.contains(&name.as_str()) {
            cx.finding(
                child,
                format!("unknown node '{name}' on 'tool' — it is ignored"),
            )?;
            continue;
        }
        // Duplicate *blocks* are already hard errors (`unique_child`),
        // so only the entries inside each block need checking —
        // `environment` is rejected by the validator outright, and
        // `process`/`deputy` carry their own parse-time validation.
        match name.as_str() {
            "profile" | "profiles" => check_profile_ref(cx, child)?,
            "filesystem" => check_fs_entries(cx, child)?,
            "syscalls" => check_list_entries(cx, child, "syscalls")?,
            "network" => check_network_entries(cx, child)?,
            _ => {}
        }
    }
    Ok(())
}

/// A `profile "name"` / `profiles "name"` reference on a tool takes
/// exactly one string argument — no properties, no children.
fn check_profile_ref(cx: &mut Check<'_>, node: &KdlNode) -> Result<(), PolicyError> {
    let name = node.name().value();
    let args: Vec<_> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect();
    if args.len() > 1 {
        cx.finding(
            node,
            format!("'{name}' takes exactly one profile name — extra arguments are ignored"),
        )?;
    }
    if let Some(first) = args.first()
        && first.value().as_string().is_none()
    {
        cx.finding(
            node,
            format!("'{name}' argument must be a string profile name"),
        )?;
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name() {
            cx.finding(
                node,
                format!(
                    "unexpected property '{}' on '{name}' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    if node.children().is_some() {
        cx.finding(
            node,
            format!("'{name}' takes no children — they are ignored"),
        )?;
    }
    Ok(())
}

/// A top-level `profile "name" { layer }` definition — exactly one
/// string argument, no properties, layer children only, unique names.
fn check_profile_def(
    cx: &mut Check<'_>,
    node: &KdlNode,
    seen: &mut HashMap<String, ()>,
) -> Result<(), PolicyError> {
    let args: Vec<_> = node
        .entries()
        .iter()
        .filter(|e| e.name().is_none())
        .collect();
    if args.len() > 1 {
        cx.finding(
            node,
            "unexpected extra argument(s) on 'profile' — they are ignored".to_string(),
        )?;
    }
    for entry in node.entries() {
        if let Some(prop) = entry.name() {
            cx.finding(
                node,
                format!(
                    "unexpected property '{}' on 'profile' — it is ignored",
                    prop.value()
                ),
            )?;
        }
    }
    if let Some(name) = node.get(0).and_then(|v| v.as_string())
        && seen.insert(name.to_string(), ()).is_some()
    {
        cx.finding(
            node,
            format!("duplicate profile '{name}' — the later definition replaces the earlier"),
        )?;
    }
    if let Some(children) = node.children() {
        check_layer_children(
            cx,
            node,
            &format!(
                "profile '{}'",
                node.get(0)
                    .and_then(|v| v.as_string())
                    .unwrap_or("<unnamed>")
            ),
        )?;
        // `environment` inside a profile is a hard parse error; the
        // layer-child check above deliberately skips it.
        let _ = children;
    }
    Ok(())
}
