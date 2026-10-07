use kdl::KdlDocument;

use crate::error::PolicyError;
use crate::policy::deputy::{DeputyPolicy, DeputyRole, DeputyRule, ExtractPointer, KnownShape};

/// `deputy` blocks only take effect as direct children of a `tool` node
/// inside a `server` node read by the merger — a document-root `server`,
/// or a `server` inside a top-level `when` body. A `deputy` anywhere else
/// (root, `defaults`, `profile`, `server-defaults`, nested under other
/// tool children, a `when` node's own children) would be silently
/// ignored, so it is a load error instead.
pub(crate) fn reject_misplaced_deputy(
    doc: &KdlDocument,
    in_when_body: bool,
) -> Result<(), PolicyError> {
    fn misplaced() -> PolicyError {
        PolicyError::KdlParse("'deputy' is only valid as a direct child of a 'tool' node".into())
    }
    /// No `deputy` anywhere in this subtree.
    fn no_deputy(node: &kdl::KdlNode) -> Result<(), PolicyError> {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                if child.name().value() == "deputy" {
                    return Err(misplaced());
                }
                no_deputy(child)?;
            }
        }
        Ok(())
    }
    /// One level of nodes that may legitimately reach a `tool` node.
    /// `when` children form another such level only at document root —
    /// inside a `when` body a nested `when` is never evaluated.
    fn level(doc: &KdlDocument, in_when: bool) -> Result<(), PolicyError> {
        for node in doc.nodes() {
            match node.name().value() {
                "deputy" => return Err(misplaced()),
                "server" => {
                    if let Some(children) = node.children() {
                        for child in children.nodes() {
                            match child.name().value() {
                                "deputy" => return Err(misplaced()),
                                "tool" => {
                                    // `deputy` is legal directly under `tool`; deeper is not.
                                    if let Some(tc) = child.children() {
                                        for tc_child in tc.nodes() {
                                            if tc_child.name().value() != "deputy" {
                                                no_deputy(tc_child)?;
                                            }
                                        }
                                    }
                                }
                                _ => no_deputy(child)?,
                            }
                        }
                    }
                }
                "when" if !in_when => {
                    if let Some(children) = node.children() {
                        level(children, true)?;
                    }
                }
                _ => no_deputy(node)?,
            }
        }
        Ok(())
    }
    level(doc, in_when_body)
}

/// Parse one `deputy` block inside `tool` (KDL schema v2).
///
/// Shape: `deputy role="discover"|"use"|"none"` with `extract`
/// (restricted pointer, optional `split="lines"`) and `shape` (named
/// known structure) children. The rule set is closed — arbitrary code
/// or expression evaluation is not representable by construction.
pub(crate) fn parse_deputy_node(
    node: &kdl::KdlNode,
    tool_name: &str,
) -> Result<DeputyPolicy, PolicyError> {
    fn err(msg: impl Into<String>) -> PolicyError {
        PolicyError::KdlParse(msg.into())
    }

    let mut role: Option<DeputyRole> = None;
    for entry in node.entries() {
        match entry.name() {
            None => {
                return Err(err(format!(
                    "'deputy' on tool '{tool_name}' takes no positional arguments"
                )));
            }
            Some(prop) if prop.value() == "role" => {
                if role.is_some() {
                    return Err(err(format!(
                        "duplicate 'role' property on 'deputy' for tool '{tool_name}'"
                    )));
                }
                let raw = entry.value().as_string().ok_or_else(|| {
                    err(format!(
                        "'role' property on 'deputy' for tool '{tool_name}' must be a string"
                    ))
                })?;
                role = Some(DeputyRole::parse(raw).ok_or_else(|| {
                    err(format!(
                        "unknown deputy role '{raw}' on tool '{tool_name}'; \
                         expected discover|use|none"
                    ))
                })?);
            }
            Some(prop) => {
                return Err(err(format!(
                    "unknown property '{}' on 'deputy' for tool '{tool_name}'; expected 'role'",
                    prop.value()
                )));
            }
        }
    }
    let role = role.ok_or_else(|| {
        err(format!(
            "'deputy' on tool '{tool_name}' requires a 'role' property"
        ))
    })?;

    let mut rules = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "extract" => rules.push(DeputyRule::Pointer(parse_deputy_extract_node(
                    child, tool_name, role,
                )?)),
                "shape" => rules.push(DeputyRule::Shape(parse_deputy_shape_node(
                    child, tool_name,
                )?)),
                other => {
                    return Err(err(format!(
                        "unexpected node '{other}' in 'deputy' for tool '{tool_name}'; \
                         expected 'extract' or 'shape'"
                    )));
                }
            }
        }
    }

    let policy = DeputyPolicy { role, rules };
    policy
        .validate()
        .map_err(|e| err(format!("'deputy' on tool '{tool_name}': {e}")))?;
    Ok(policy)
}

/// `extract "<pointer>" [split="lines"]` inside a `deputy` block.
fn parse_deputy_extract_node(
    node: &kdl::KdlNode,
    tool_name: &str,
    role: DeputyRole,
) -> Result<ExtractPointer, PolicyError> {
    fn err(msg: impl Into<String>) -> PolicyError {
        PolicyError::KdlParse(msg.into())
    }
    let Some(root) = role.pointer_root() else {
        return Err(err(format!(
            "'deputy' role \"none\" on tool '{tool_name}' cannot declare 'extract' rules"
        )));
    };
    let positional = node.entries().iter().filter(|e| e.name().is_none()).count();
    if positional != 1 {
        return Err(err(format!(
            "'extract' in 'deputy' for tool '{tool_name}' takes exactly one pointer argument"
        )));
    }
    let source = node.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
        err(format!(
            "'extract' in 'deputy' for tool '{tool_name}' requires a pointer string argument"
        ))
    })?;
    let mut split_lines = false;
    for entry in node.entries() {
        let Some(prop) = entry.name() else {
            continue;
        };
        match prop.value() {
            "split" => {
                let raw = entry.value().as_string().ok_or_else(|| {
                    err(format!(
                        "'split' property on 'extract' in 'deputy' for tool '{tool_name}' \
                         must be a string"
                    ))
                })?;
                if raw != "lines" {
                    return Err(err(format!(
                        "unknown split mode '{raw}' on 'extract' in 'deputy' for tool \
                         '{tool_name}'; expected 'lines'"
                    )));
                }
                split_lines = true;
            }
            other => {
                return Err(err(format!(
                    "unexpected property '{other}' on 'extract' in 'deputy' for tool \
                     '{tool_name}'; expected 'split'"
                )));
            }
        }
    }
    if node.children().is_some() {
        return Err(err(format!(
            "'extract' in 'deputy' for tool '{tool_name}' takes no child nodes"
        )));
    }
    let mut pointer = ExtractPointer::parse(source, root)
        .map_err(|e| err(format!("'extract' in 'deputy' for tool '{tool_name}': {e}")))?;
    pointer.split_lines = split_lines;
    Ok(pointer)
}

/// `shape "<name>"` inside a `deputy` block.
fn parse_deputy_shape_node(
    node: &kdl::KdlNode,
    tool_name: &str,
) -> Result<KnownShape, PolicyError> {
    fn err(msg: impl Into<String>) -> PolicyError {
        PolicyError::KdlParse(msg.into())
    }
    let positional = node.entries().iter().filter(|e| e.name().is_none()).count();
    if positional != 1 || node.entries().len() != 1 || node.children().is_some() {
        return Err(err(format!(
            "'shape' in 'deputy' for tool '{tool_name}' takes exactly one name argument"
        )));
    }
    let raw = node.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
        err(format!(
            "'shape' in 'deputy' for tool '{tool_name}' requires a string name"
        ))
    })?;
    KnownShape::parse(raw).ok_or_else(|| {
        err(format!(
            "unknown shape '{raw}' in 'deputy' for tool '{tool_name}'; \
             expected fs_targets|mcp_list_result"
        ))
    })
}
