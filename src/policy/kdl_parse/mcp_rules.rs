use kdl::KdlDocument;

use crate::error::PolicyError;
use crate::policy::mcp::{McpRule, RuleEffect, ServerMcpRules, method_slots, validate_rule_set};
use crate::protocol::fields::SubscriptionFilter;
use crate::protocol::{MessageDirection, SupportedProtocolVersion};

/// Parse `mcp { allow ... / deny ... }` blocks under each `server` node.
///
/// Schema v2 only — an `mcp` child under `policy version < 2` is a load
/// error. Each rule expands over the method's own rule-key slots
/// (revision × direction × kind from the method ledger); `protocol=` and
/// `direction=` properties only restrict that expansion, never extend it.
/// Two rules covering the same atom — even with the same effect — are a
/// load error; restate them as one rule.
pub(crate) fn parse_server_mcp_rules(
    doc: &KdlDocument,
    version: u32,
    in_when_body: bool,
) -> Result<Vec<ServerMcpRules>, PolicyError> {
    reject_misplaced_mcp(doc, in_when_body)?;
    let mut out: Vec<ServerMcpRules> = Vec::new();
    for node in doc.nodes() {
        if node.name().to_string() != "server" {
            continue;
        }
        let server_name = node.get(0).and_then(|v| v.as_string()).map(String::from);
        let Some(children) = node.children() else {
            continue;
        };
        let mut rules = Vec::new();
        for child in children.nodes() {
            if child.name().to_string() != "mcp" {
                continue;
            }
            if version < 2 {
                return Err(PolicyError::KdlParse(format!(
                    "'mcp' rules in server '{}' require 'policy version=2'",
                    server_name.as_deref().unwrap_or("<unnamed>")
                )));
            }
            if !child.entries().is_empty() {
                return Err(PolicyError::KdlParse(format!(
                    "'mcp' node in server '{}' takes no arguments or properties",
                    server_name.as_deref().unwrap_or("<unnamed>")
                )));
            }
            let Some(mcp_children) = child.children() else {
                continue;
            };
            for rule_node in mcp_children.nodes() {
                rules.push(parse_mcp_rule_node(rule_node)?);
            }
        }
        if rules.is_empty() {
            continue;
        }
        if let Some(existing) = out.iter_mut().find(|s| s.server_name == server_name) {
            existing.extend_rules(rules);
        } else {
            out.push(ServerMcpRules::new(server_name, rules));
        }
    }
    for entry in &out {
        validate_rule_set(entry.server_name.as_deref(), entry.rules())
            .map_err(PolicyError::KdlParse)?;
    }
    Ok(out)
}

/// `mcp` blocks only take effect as direct children of a `server` node
/// this scan actually reads: a top-level `server`, or a `server`
/// directly inside a top-level `when` block (whose body merges when the
/// environment matches). An `mcp` anywhere else — document root,
/// `defaults`, `profile`, `server-defaults`, `tool`, a `when` node's own
/// children, or inside a nested `when` that is never evaluated — would
/// be silently ignored, so it is a load error instead.
fn reject_misplaced_mcp(doc: &KdlDocument, in_when_body: bool) -> Result<(), PolicyError> {
    fn misplaced() -> PolicyError {
        PolicyError::KdlParse("'mcp' is only valid as a direct child of a 'server' node".into())
    }
    /// No `mcp` anywhere in this subtree.
    fn no_mcp(node: &kdl::KdlNode) -> Result<(), PolicyError> {
        if let Some(children) = node.children() {
            for child in children.nodes() {
                if child.name().value() == "mcp" {
                    return Err(misplaced());
                }
                no_mcp(child)?;
            }
        }
        Ok(())
    }
    /// One level of nodes that may legitimately hold `mcp` blocks.
    /// `when` children form another such level only at document root —
    /// inside a `when` body a nested `when` is never evaluated.
    fn level(doc: &KdlDocument, in_when: bool) -> Result<(), PolicyError> {
        for node in doc.nodes() {
            match node.name().value() {
                "mcp" => return Err(misplaced()),
                // `mcp` is legal directly under `server`; deeper is not.
                "server" => {
                    if let Some(children) = node.children() {
                        for child in children.nodes() {
                            if child.name().value() != "mcp" {
                                no_mcp(child)?;
                            }
                        }
                    }
                }
                "when" if !in_when => {
                    if let Some(children) = node.children() {
                        level(children, true)?;
                    }
                }
                _ => no_mcp(node)?,
            }
        }
        Ok(())
    }
    level(doc, in_when_body)
}

/// Strict `uri`/`filter` child shape: exactly one positional argument —
/// extra entries, named properties, or child blocks are load errors
/// rather than silently ignored.
fn takes_single_positional_arg(child: &kdl::KdlNode) -> bool {
    child.entries().len() == 1 && child.entries()[0].name().is_none() && child.children().is_none()
}

/// Parse one `allow "method"` / `deny "method"` node inside an `mcp` block.
fn parse_mcp_rule_node(node: &kdl::KdlNode) -> Result<McpRule, PolicyError> {
    let effect = match node.name().value() {
        "allow" => RuleEffect::Allow,
        "deny" => RuleEffect::Deny,
        other => {
            return Err(PolicyError::KdlParse(format!(
                "unexpected node '{other}' in mcp block; expected 'allow' or 'deny'"
            )));
        }
    };
    let method = node
        .get(0)
        .and_then(|v| v.as_string())
        .ok_or_else(|| {
            PolicyError::KdlParse("mcp rule requires a method string as first argument".into())
        })?
        .to_string();
    if node.entries().iter().filter(|e| e.name().is_none()).count() > 1 {
        return Err(PolicyError::KdlParse(format!(
            "mcp rule for method \"{method}\" takes exactly one method argument"
        )));
    }

    let mut versions = Vec::new();
    let mut direction = None;
    for entry in node.entries() {
        let Some(prop) = entry.name() else {
            continue;
        };
        match prop.value() {
            "protocol" => {
                let raw = entry.value().as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "'protocol' property on mcp rule for method \"{method}\" must be a string"
                    ))
                })?;
                let parsed = SupportedProtocolVersion::parse(raw).ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "unknown protocol revision '{raw}' on mcp rule for method \"{method}\"; \
                         supported: 2025-11-25, 2026-07-28"
                    ))
                })?;
                if !versions.contains(&parsed) {
                    versions.push(parsed);
                }
            }
            "direction" => {
                let raw = entry.value().as_string().ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "'direction' property on mcp rule for method \"{method}\" must be a string"
                    ))
                })?;
                let parsed = MessageDirection::parse(raw).ok_or_else(|| {
                    PolicyError::KdlParse(format!(
                        "unknown direction '{raw}' on mcp rule for method \"{method}\"; \
                         expected c2s or s2c"
                    ))
                })?;
                if direction.replace(parsed).is_some() {
                    // A second `direction` silently overwrote the first —
                    // the same duplicate-key hazard the block-level
                    // `unique_child` checks reject.
                    return Err(PolicyError::KdlParse(format!(
                        "duplicate 'direction' property on mcp rule for method \"{method}\""
                    )));
                }
            }
            other => {
                return Err(PolicyError::KdlParse(format!(
                    "unexpected property '{other}' on mcp rule for method \"{method}\"; \
                     expected protocol= or direction="
                )));
            }
        }
    }

    let mut uris = Vec::new();
    let mut filters = Vec::new();
    if let Some(children) = node.children() {
        for child in children.nodes() {
            match child.name().value() {
                "uri" => {
                    if !takes_single_positional_arg(child) {
                        return Err(PolicyError::KdlParse(format!(
                            "'uri' child of an mcp rule for method \"{method}\" takes exactly one argument"
                        )));
                    }
                    let uri = child.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
                        PolicyError::KdlParse(
                            "'uri' child of an mcp rule requires a string argument".into(),
                        )
                    })?;
                    if uri.trim().is_empty() {
                        return Err(PolicyError::KdlParse(
                            "'uri' child of an mcp rule must not be empty".into(),
                        ));
                    }
                    if uris.iter().any(|u: &String| u == uri) {
                        return Err(PolicyError::KdlParse(format!(
                            "duplicate uri '{uri}' in mcp rule for method \"{method}\""
                        )));
                    }
                    uris.push(uri.to_string());
                }
                "filter" => {
                    if !takes_single_positional_arg(child) {
                        return Err(PolicyError::KdlParse(format!(
                            "'filter' child of an mcp rule for method \"{method}\" takes exactly one argument"
                        )));
                    }
                    let raw = child.get(0).and_then(|v| v.as_string()).ok_or_else(|| {
                        PolicyError::KdlParse(
                            "'filter' child of an mcp rule requires a string argument".into(),
                        )
                    })?;
                    let parsed = SubscriptionFilter::parse(raw).ok_or_else(|| {
                        PolicyError::KdlParse(format!(
                            "unknown filter '{raw}' in mcp rule for method \"{method}\"; \
                             expected toolsListChanged, promptsListChanged, \
                             resourcesListChanged, or resourceSubscriptions"
                        ))
                    })?;
                    if filters.contains(&parsed) {
                        return Err(PolicyError::KdlParse(format!(
                            "duplicate filter '{raw}' in mcp rule for method \"{method}\""
                        )));
                    }
                    filters.push(parsed);
                }
                other => {
                    return Err(PolicyError::KdlParse(format!(
                        "unexpected node '{other}' in mcp rule for method \"{method}\"; \
                         expected 'uri' or 'filter'"
                    )));
                }
            }
        }
    }

    let rule = McpRule {
        effect,
        method,
        versions,
        direction,
        uris,
        filters,
    };
    validate_mcp_rule(&rule)?;
    Ok(rule)
}

/// Shape + reachability checks for one parsed `mcp` rule.
fn validate_mcp_rule(rule: &McpRule) -> Result<(), PolicyError> {
    if method_slots(&rule.method).is_empty() {
        return Err(PolicyError::KdlParse(format!(
            "unknown MCP method \"{}\" in mcp rule — the rule ledger is closed; \
             MCP extensions cannot be targeted until registered",
            rule.method
        )));
    }
    if rule.atoms().is_empty() {
        let slots: Vec<String> = method_slots(&rule.method)
            .iter()
            .map(|s| {
                format!(
                    "{}/{}/{}",
                    s.version.as_str(),
                    s.direction.as_str(),
                    s.kind.as_str()
                )
            })
            .collect();
        return Err(PolicyError::KdlParse(format!(
            "mcp rule for method \"{}\" targets no valid rule-key combination \
             after protocol=/direction= filtering — the method only travels as: {}",
            rule.method,
            slots.join(", ")
        )));
    }
    if rule.effect == RuleEffect::Deny && (!rule.uris.is_empty() || !rule.filters.is_empty()) {
        return Err(PolicyError::KdlParse(format!(
            "deny rule for method \"{}\" cannot carry uri/filter children",
            rule.method
        )));
    }
    if !rule.filters.is_empty() && rule.method != "subscriptions/listen" {
        return Err(PolicyError::KdlParse(format!(
            "filter children are only valid on subscriptions/listen rules, not \"{}\"",
            rule.method
        )));
    }
    if !rule.uris.is_empty()
        && !matches!(
            rule.method.as_str(),
            "resources/read"
                | "resources/subscribe"
                | "resources/unsubscribe"
                | "subscriptions/listen"
        )
    {
        return Err(PolicyError::KdlParse(format!(
            "uri children are only valid on resources/read, resources/subscribe, \
             resources/unsubscribe, and subscriptions/listen rules, not \"{}\"",
            rule.method
        )));
    }
    if rule.method == "subscriptions/listen"
        && !rule.uris.is_empty()
        && !rule
            .filters
            .contains(&SubscriptionFilter::ResourceSubscriptions)
    {
        return Err(PolicyError::KdlParse(
            "uri children on a subscriptions/listen rule require \
             filter \"resourceSubscriptions\""
                .into(),
        ));
    }
    Ok(())
}
