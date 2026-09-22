//! IronContext CC-001〜015 detector bodies for `tools/list` manifests.
//!
//! The public types and the scan/audit entry points live in
//! `verifier::manifest`; this module holds the per-rule detection logic and
//! its constants. See `manifest.rs` for the rule-set policy (CC-001–015 is
//! closed; severities are not raised or lowered).

use std::sync::OnceLock;

use regex_lite::Regex;
use unicode_normalization::UnicodeNormalization;

use crate::secret_paths::{is_env_example_token, secret_overlay_lure_literals};
use crate::tool_def::ToolDefinition;
use crate::verifier::manifest::{ManifestFinding, ManifestRule, ManifestSeverity};
use crate::verifier::schema_walk::{
    MAX_SCHEMA_STRING_DEPTH, collect_json_strings, for_each_schema_property, json_key_name,
    property_key_match, property_schema_has_uri_hint, schema_has_named_property,
    schema_property_keys, schema_string_texts,
};
use crate::verifier::unicode::{
    fold_fullwidth_ascii, fold_name_for_collision, is_invisible_attack_char,
};

fn re_hidden() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)<\s*(important|system|sudo|admin|secret|do[\s_-]*not[\s_-]*tell)\s*>|\bignore\s+(all|previous|prior)\s+(instructions|directives|prompts)\b|\boverride\s+system\s+prompt\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken)\b|\bdo\s+not\s+tell\s+the\s+user\b",
        )
        .expect("CC-001 regex")
    })
}

fn re_cross_tool() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:instead\s+of|in\s+place\s+of|rather\s+than|do\s+not\s+use)\b[^.]{0,40}\b(?:tool|function|the\s+\w+_tool)\b",
        )
        .expect("CC-003 regex")
    })
}

fn re_template() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(\{\{[^}]+\}\}|\$\{[^}]+\}|<%[^%]+%>)").expect("CC-004 regex"))
}

fn re_uri_prefetch() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)(?:first|before\s+(?:you|responding|answering)|always)\b[^.]{0,80}\b(?:fetch|read|load|GET|retrieve|download)\b[^.]{0,80}\b(?:https?://|file://|/etc/|~/|s3://)",
        )
        .expect("CC-009 regex")
    })
}

fn re_http_url() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"(?i)https?://").expect("http url regex"))
}

fn re_exfil() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r"(?i)\b(?:include|return|echo|append|forward|send)\b[^.]{0,40}\b(?:api[\s_-]?key|token|password|secret|credential|\.env|authorization)\b",
        )
        .expect("CC-010 regex")
    })
}

/// True when `description` matches CC-001 hidden-instruction markers.
pub(crate) fn description_has_hidden_instructions(description: &str) -> bool {
    re_hidden().is_match(description)
}

const HTML_COMMENT_INSTRUCTION_WORDS: &[&str] = &[
    "system",
    "ignore",
    "secret",
    "instruction",
    "sudo",
    "admin",
    "override",
];

const WRITE_PROPERTY_KEYS: &[&str] = &["write", "delete", "update", "remove", "create"];
const NET_PROPERTY_KEYS: &[&str] = &["url", "endpoint", "webhook", "callback"];
const DESTRUCTIVE_PROPERTY_KEYS: &[&str] = &["delete", "remove"];
const READ_NAME_STEMS: &[&str] = &["get", "list", "find", "read", "fetch", "search"];

/// Hash-v4 / scanned MCP keys. Only these keys are forwarded after verification.
const HASH_V4_TOOL_KEYS: &[&str] = &[
    "name",
    "description",
    "title",
    "inputSchema",
    "outputSchema",
    "annotations",
    "icons",
    "execution",
    "_meta",
];

/// `name`, `description`, `title`, annotations / outputSchema / `_meta` /
/// `execution` / `icons` strings, string keys/values inside `input_schema`,
/// and string leaves under unknown vendor keys in `raw_json`.
///
/// Schema parse failure scans the raw schema text (fail-closed). CC-004
/// stays description-only and does not use this set.
fn tool_scan_texts(tool: &ToolDefinition) -> Vec<String> {
    let mut texts = vec![tool.name.clone(), tool.description.clone()];
    if let Some(title) = tool.title.as_deref() {
        texts.push(title.to_string());
    }
    if let Some(schema) = tool.input_schema.as_deref() {
        texts.extend(schema_string_texts(schema));
    }
    if let Some(schema) = tool.output_schema.as_deref() {
        texts.extend(schema_string_texts(schema));
    }
    if let Some(raw) = tool.annotations_raw.as_deref() {
        texts.extend(schema_string_texts(raw));
    }
    if let Some(raw) = tool.icons_raw.as_deref() {
        texts.extend(schema_string_texts(raw));
    }
    if let Some(raw) = tool.execution_raw.as_deref() {
        texts.extend(schema_string_texts(raw));
    }
    if let Some(raw) = tool.meta_raw.as_deref() {
        texts.extend(schema_string_texts(raw));
    }
    if let Some(raw) = tool.raw_json.as_deref() {
        texts.extend(unknown_vendor_key_strings(raw));
    }
    texts
}

/// String leaves (and key names) under tool-object keys that are not in the
/// hash-v4 / forwarded field set. Fail-secure: vendor-key poison is still
/// first-seen, even though those keys are dropped on forward.
fn unknown_vendor_key_strings(raw: &str) -> Vec<String> {
    let Ok(json) = nojson::RawJson::parse(raw) else {
        return vec![raw.to_string()];
    };
    let Ok(obj) = json.value().to_object() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (k, v) in obj {
        let Ok(key) = k.to_unquoted_string_str() else {
            continue;
        };
        if HASH_V4_TOOL_KEYS.contains(&key.as_ref()) {
            continue;
        }
        out.push(key.into_owned());
        collect_json_strings(v, &mut out, 0);
    }
    out
}

fn advertised_blob(tool: &ToolDefinition) -> String {
    tool_scan_texts(tool).join("\n")
}

fn html_comment_has_instruction_words(text: &str) -> Option<String> {
    let mut rest = text;
    while let Some(start) = rest.find("<!--") {
        let after = &rest[start + 4..];
        let Some(end) = after.find("-->") else {
            break;
        };
        let body = &after[..end];
        let body_l = body.to_ascii_lowercase();
        if HTML_COMMENT_INSTRUCTION_WORDS
            .iter()
            .any(|w| body_l.contains(w))
        {
            return Some(format!("<!--{body}-->"));
        }
        rest = &after[end + 3..];
    }
    None
}

const FS_PROP_NAMES: &[&str] = &["path", "file", "filepath", "filename"];
const NET_PROP_NAMES: &[&str] = &["url", "endpoint", "webhook", "callback"];
const WRITE_PROP_NAMES: &[&str] = &["write", "delete", "update", "remove", "create"];
const REDIRECT_PROP_NAMES: &[&str] = &["redirect_uri", "redirecturi"];

pub(crate) fn detect_cc005(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let schema = tool.input_schema.as_deref()?;
    let Ok(json) = nojson::RawJson::parse(schema) else {
        return None;
    };
    if schema_is_cc005(json.value(), 0) {
        Some(ManifestFinding::new(
            ManifestRule::Cc005,
            ManifestSeverity::High,
            &tool.name,
            "schema accepts filesystem source and network sink",
        ))
    } else {
        None
    }
}

fn schema_is_cc005(val: nojson::RawJsonValue<'_, '_>, depth: usize) -> bool {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return false;
    }
    let mut names = Vec::new();
    if walk_cc005_schema(val, depth, &mut names) {
        return true;
    }
    cc005_from_names(&names)
}

fn cc005_from_names(names: &[String]) -> bool {
    let has_net = names.iter().any(|n| {
        NET_PROP_NAMES
            .iter()
            .any(|want| n.eq_ignore_ascii_case(want))
    });
    let has_fs = names.iter().any(|n| {
        FS_PROP_NAMES
            .iter()
            .any(|want| n.eq_ignore_ascii_case(want))
    });
    has_net && has_fs
}

fn walk_cc005_schema(
    val: nojson::RawJsonValue<'_, '_>,
    depth: usize,
    names: &mut Vec<String>,
) -> bool {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return false;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            let Ok(obj) = val.to_object() else {
                return false;
            };
            if let Some(props) = val.to_member("properties").ok().and_then(|m| m.optional())
                && let Ok(props_obj) = props.to_object()
            {
                for (k, v) in props_obj {
                    if let Some(name) = json_key_name(k) {
                        names.push(name);
                        if walk_cc005_schema(v, depth + 1, names) {
                            return true;
                        }
                    }
                }
            }
            for (k, v) in obj {
                let Some(key) = json_key_name(k) else {
                    continue;
                };
                if key.eq_ignore_ascii_case("properties") {
                    continue;
                }
                match key.as_str() {
                    "oneOf" => {
                        if let Ok(arr) = v.to_array() {
                            for item in arr {
                                // oneOf branches are alternatives: each is
                                // checked against a clone of the outer names,
                                // so siblings never share an accumulator.
                                let mut branch_names = names.clone();
                                if walk_cc005_schema(item, depth + 1, &mut branch_names)
                                    || cc005_from_names(&branch_names)
                                {
                                    return true;
                                }
                            }
                        }
                    }
                    "anyOf" | "allOf" | "prefixItems" => {
                        if let Ok(arr) = v.to_array() {
                            for item in arr {
                                if walk_cc005_schema(item, depth + 1, names) {
                                    return true;
                                }
                            }
                        }
                    }
                    "$defs"
                    | "definitions"
                    | "items"
                    | "additionalProperties"
                    | "not"
                    | "if"
                    | "then"
                    | "else"
                    | "contains"
                    | "propertyNames"
                    | "unevaluatedProperties" => {
                        if walk_cc005_schema(v, depth + 1, names) {
                            return true;
                        }
                    }
                    "dependentSchemas" => {
                        if let Ok(dep) = v.to_object() {
                            for (_, schema) in dep {
                                if walk_cc005_schema(schema, depth + 1, names) {
                                    return true;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            false
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for item in arr {
                    if walk_cc005_schema(item, depth + 1, names) {
                        return true;
                    }
                }
            }
            false
        }
        nojson::JsonValueKind::String
        | nojson::JsonValueKind::Null
        | nojson::JsonValueKind::Boolean
        | nojson::JsonValueKind::Integer
        | nojson::JsonValueKind::Float => false,
    }
}

pub(crate) fn detect_cc006(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let schema = tool.input_schema.as_deref()?;
    let Ok(json) = nojson::RawJson::parse(schema) else {
        return None;
    };
    let mut saw_redirect = false;
    let mut allowlisted = false;
    for_each_schema_property(json.value(), 0, &mut |name, val| {
        if REDIRECT_PROP_NAMES
            .iter()
            .any(|want| name.eq_ignore_ascii_case(want))
        {
            saw_redirect = true;
            if property_schema_has_uri_hint(val, 0) {
                allowlisted = true;
            }
        }
    });
    if !saw_redirect {
        return None;
    }
    if allowlisted {
        None
    } else {
        Some(ManifestFinding::new(
            ManifestRule::Cc006,
            ManifestSeverity::Medium,
            &tool.name,
            "redirect_uri without https allowlist or URI format hint",
        ))
    }
}

pub(crate) fn detect_cc007(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let schema = tool.input_schema.as_deref()?;
    if !is_read_like_name(&tool.name) {
        return None;
    }
    if schema_has_named_property(schema, WRITE_PROP_NAMES) {
        Some(ManifestFinding::new(
            ManifestRule::Cc007,
            ManifestSeverity::High,
            &tool.name,
            "read-like name with write/delete/update schema keys",
        ))
    } else {
        None
    }
}

pub(crate) fn detect_cc001(tool: &ToolDefinition) -> Option<ManifestFinding> {
    for text in tool_scan_texts(tool) {
        if let Some(m) = re_hidden().find(&text) {
            return Some(ManifestFinding::new(
                ManifestRule::Cc001,
                ManifestSeverity::Critical,
                &tool.name,
                format!("hidden instruction markers: {}", m.as_str()),
            ));
        }
        if let Some(comment) = html_comment_has_instruction_words(&text) {
            return Some(ManifestFinding::new(
                ManifestRule::Cc001,
                ManifestSeverity::Critical,
                &tool.name,
                format!("HTML comment with instruction-like words: {comment}"),
            ));
        }
    }
    None
}

pub(crate) fn detect_cc002(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let bad: String = tool_scan_texts(tool)
        .iter()
        .flat_map(|text| text.chars())
        .filter(|c| is_invisible_attack_char(*c))
        .collect();
    if bad.is_empty() {
        None
    } else {
        Some(ManifestFinding::new(
            ManifestRule::Cc002,
            ManifestSeverity::High,
            &tool.name,
            format!("invisible/bidi/tag characters ({})", bad.escape_unicode()),
        ))
    }
}

pub(crate) fn detect_cc003(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let blob = advertised_blob(tool);
    let m = re_cross_tool().find(&blob)?;
    Some(ManifestFinding::new(
        ManifestRule::Cc003,
        ManifestSeverity::High,
        &tool.name,
        format!("cross-tool shadow: {}", m.as_str()),
    ))
}

pub(crate) fn detect_cc004(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let m = re_template().find(&tool.description)?;
    Some(ManifestFinding::new(
        ManifestRule::Cc004,
        ManifestSeverity::Medium,
        &tool.name,
        format!("template syntax in description: {}", m.as_str()),
    ))
}

fn is_read_like_name(name: &str) -> bool {
    if READ_NAME_STEMS
        .iter()
        .any(|stem| name.eq_ignore_ascii_case(stem))
    {
        return true;
    }
    if read_like_token(name) {
        return true;
    }
    name.split(['.', '-', '_']).any(read_like_token)
}

fn read_like_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    for stem in READ_NAME_STEMS {
        if token.eq_ignore_ascii_case(stem) {
            return true;
        }
        let stem_len = stem.chars().count();
        let mut chars = token.chars();
        let mut prefix = String::new();
        for _ in 0..stem_len {
            match chars.next() {
                Some(c) => prefix.push(c),
                None => break,
            }
        }
        if prefix.chars().count() < stem_len || !prefix.eq_ignore_ascii_case(stem) {
            continue;
        }
        let Some(next) = chars.next() else {
            continue;
        };
        if next == '_' || next == '.' || next == '-' || next.is_ascii_uppercase() {
            return true;
        }
    }
    false
}

pub(crate) fn detect_cc008(tool: &ToolDefinition) -> Option<ManifestFinding> {
    if has_mixed_script(&tool.name) {
        Some(ManifestFinding::new(
            ManifestRule::Cc008,
            ManifestSeverity::High,
            &tool.name,
            format!("mixed-script tool name: {}", tool.name.escape_unicode()),
        ))
    } else {
        None
    }
}

pub(crate) fn detect_cc009(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let blob = advertised_blob(tool);
    let blob_l = blob.to_ascii_lowercase();
    let t7_conjunction = (blob_l.contains("before answering")
        || blob_l.contains("before responding"))
        && re_http_url().is_match(&blob);
    let iron = re_uri_prefetch().find(&blob);
    if t7_conjunction || iron.is_some() {
        let excerpt = iron
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "before answering/responding + URL".to_string());
        Some(ManifestFinding::new(
            ManifestRule::Cc009,
            ManifestSeverity::High,
            &tool.name,
            format!("pre-fetch URI instruction: {excerpt}"),
        ))
    } else {
        None
    }
}

pub(crate) fn detect_cc010(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let blob = advertised_blob(tool);
    let m = re_exfil().find(&blob)?;
    Some(ManifestFinding::new(
        ManifestRule::Cc010,
        ManifestSeverity::Critical,
        &tool.name,
        format!("secret-echo instruction: {}", m.as_str()),
    ))
}

fn has_mixed_script(s: &str) -> bool {
    let mut latin = false;
    let mut cyrillic = false;
    let mut greek = false;
    for c in s.chars() {
        let code = c as u32;
        if c.is_ascii_alphabetic() {
            latin = true;
        } else if (0x0400..=0x04FF).contains(&code) {
            cyrillic = true;
        } else if (0x0370..=0x03FF).contains(&code) {
            greek = true;
        }
    }
    u8::from(latin) + u8::from(cyrillic) + u8::from(greek) >= 2
}

/// Fail-closed annotation hint: JSON bool, case-insensitive `"true"`/`"false"`,
/// or an ill-typed value (number/object/other string) treated as a claimed hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HintClaim {
    Absent,
    True,
    False,
    IllTyped,
}

fn annotation_hint(raw: &str, key: &str) -> HintClaim {
    let Ok(json) = nojson::RawJson::parse(raw) else {
        return HintClaim::IllTyped;
    };
    let Some(member) = json.value().to_member(key).ok().and_then(|m| m.optional()) else {
        return HintClaim::Absent;
    };
    match member.kind() {
        nojson::JsonValueKind::Boolean => {
            if member.as_raw_str() == "true" {
                HintClaim::True
            } else {
                HintClaim::False
            }
        }
        nojson::JsonValueKind::String => match member.to_unquoted_string_str() {
            Ok(s) if s.eq_ignore_ascii_case("true") => HintClaim::True,
            Ok(s) if s.eq_ignore_ascii_case("false") => HintClaim::False,
            _ => HintClaim::IllTyped,
        },
        nojson::JsonValueKind::Null
        | nojson::JsonValueKind::Integer
        | nojson::JsonValueKind::Float
        | nojson::JsonValueKind::Array
        | nojson::JsonValueKind::Object => HintClaim::IllTyped,
    }
}

pub(crate) fn detect_cc011(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let raw = tool.annotations_raw.as_deref()?;
    let keys = schema_property_keys(tool.input_schema.as_deref().unwrap_or(""));
    let read_only = annotation_hint(raw, "readOnlyHint");
    let destructive = annotation_hint(raw, "destructiveHint");
    let claimed_read_only = match read_only {
        HintClaim::True | HintClaim::IllTyped => true,
        HintClaim::Absent | HintClaim::False => false,
    };
    if claimed_read_only
        && (property_key_match(&keys, WRITE_PROPERTY_KEYS)
            || property_key_match(&keys, NET_PROPERTY_KEYS))
    {
        return Some(ManifestFinding::new(
            ManifestRule::Cc011,
            ManifestSeverity::High,
            &tool.name,
            "annotations.readOnlyHint is true but properties include write or network keys",
        ));
    }
    let claimed_non_destructive = match destructive {
        HintClaim::False | HintClaim::IllTyped => true,
        HintClaim::Absent | HintClaim::True => false,
    };
    if claimed_non_destructive && property_key_match(&keys, DESTRUCTIVE_PROPERTY_KEYS) {
        return Some(ManifestFinding::new(
            ManifestRule::Cc011,
            ManifestSeverity::High,
            &tool.name,
            "annotations.destructiveHint is false but properties include delete/remove",
        ));
    }
    None
}

pub(crate) fn detect_cc012(tools: &[ToolDefinition]) -> Vec<ManifestFinding> {
    let mut by_fold: std::collections::HashMap<String, Vec<usize>> =
        std::collections::HashMap::new();
    for (idx, tool) in tools.iter().enumerate() {
        by_fold
            .entry(fold_name_for_collision(&tool.name))
            .or_default()
            .push(idx);
    }
    // Sort collision groups by folded key so findings are deterministic
    // (HashMap iteration order is randomized per run).
    let mut groups: Vec<(String, Vec<usize>)> = by_fold.into_iter().collect();
    groups.sort_by(|a, b| a.0.cmp(&b.0));
    let mut findings = Vec::new();
    for (_folded, idxs) in groups {
        if idxs.len() < 2 {
            continue;
        }
        let names: Vec<&str> = idxs.iter().map(|&i| tools[i].name.as_str()).collect();
        for &i in &idxs {
            findings.push(ManifestFinding::new(
                ManifestRule::Cc012,
                ManifestSeverity::High,
                &tools[i].name,
                format!("intra-list name collision with {}", names.join(", ")),
            ));
        }
    }
    findings
}

pub(crate) fn detect_cc013(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let name = &tool.name;
    let valid_len = (1..=128).contains(&name.chars().count());
    let valid_charset = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
    if valid_len && valid_charset {
        None
    } else {
        Some(ManifestFinding::new(
            ManifestRule::Cc013,
            ManifestSeverity::Medium,
            &tool.name,
            "tool name must be 1–128 chars in [A-Za-z0-9_.-]",
        ))
    }
}

pub(crate) fn detect_cc014(tool: &ToolDefinition) -> Option<ManifestFinding> {
    let raw = tool.icons_raw.as_deref()?;
    let json = match nojson::RawJson::parse(raw) {
        Ok(j) => j,
        Err(_) => {
            return Some(ManifestFinding::new(
                ManifestRule::Cc014,
                ManifestSeverity::High,
                &tool.name,
                "icons field is not valid JSON",
            ));
        }
    };
    let mut high: Vec<String> = Vec::new();
    let mut medium: Vec<String> = Vec::new();
    classify_icons(json.value(), &mut high, &mut medium, 0);
    if let Some(detail) = high.into_iter().next() {
        return Some(ManifestFinding::new(
            ManifestRule::Cc014,
            ManifestSeverity::High,
            &tool.name,
            detail,
        ));
    }
    if let Some(detail) = medium.into_iter().next() {
        return Some(ManifestFinding::new(
            ManifestRule::Cc014,
            ManifestSeverity::Medium,
            &tool.name,
            detail,
        ));
    }
    None
}

fn classify_icons(
    val: nojson::RawJsonValue<'_, '_>,
    high: &mut Vec<String>,
    medium: &mut Vec<String>,
    depth: usize,
) {
    if depth > MAX_SCHEMA_STRING_DEPTH {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for item in arr {
                    classify_icons(item, high, medium, depth + 1);
                }
            }
        }
        nojson::JsonValueKind::Object => {
            if let Ok(obj) = val.to_object() {
                let mut src = None;
                let mut mime = None;
                for (k, v) in obj {
                    let Ok(key) = k.to_unquoted_string_str() else {
                        continue;
                    };
                    if key == "src" {
                        src = v.to_unquoted_string_str().ok().map(|s| s.into_owned());
                    } else if key == "mimeType" {
                        mime = v.to_unquoted_string_str().ok().map(|s| s.into_owned());
                    }
                }
                if let Some(src) = src {
                    match classify_icon_src(&src, mime.as_deref()) {
                        IconClass::High(detail) => high.push(detail),
                        IconClass::Medium(detail) => medium.push(detail),
                        IconClass::Clean => {}
                    }
                }
            }
        }
        _ => {}
    }
}

enum IconClass {
    High(String),
    Medium(String),
    Clean,
}

/// Format / ignorable prefixes that are **not** (all) in CC-002.
/// `str::trim` does not strip these. Soft hyphen, CGJ, ALM, MVS, and
/// interlinear annotation anchors can prefix `javascript:` and fail open
/// if only whitespace + U+FEFF are removed.
///
/// Unicode 15 format characters identified with Python `unicodedata`: assigned
/// Cf outside this list interrupted `icon_scheme` → `None` → Clean when the
/// result was not SVG. Explicit ranges below close those assigned Cf.
/// This is **not** `General_Category=Cf` (future Cf stay residual).
fn is_icon_src_ignorable(c: char) -> bool {
    if c.is_whitespace() || is_invisible_attack_char(c) {
        return true;
    }
    matches!(
        c as u32,
        0x00AD
            | 0x034F
            | 0x061C
            | 0x180E
            | 0xFFF9..=0xFFFB
            // Assigned Cf that interrupted practical schemes.
            | 0x0600..=0x0605
            | 0x06DD
            | 0x070F
            | 0x0890..=0x0891
            | 0x08E2
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
    )
}

/// CC-014 order (locked): strip ignorables → NFKC → strip ignorables →
/// fullwidth ASCII → lowercase. Fail-closed: a remaining script-like scheme
/// is classified as High. Empty after normalize is not Clean.
fn normalize_icon_src(src: &str) -> String {
    let stripped: String = src.chars().filter(|c| !is_icon_src_ignorable(*c)).collect();
    stripped
        .nfkc()
        .filter(|c| !is_icon_src_ignorable(*c))
        .map(fold_fullwidth_ascii)
        .collect::<String>()
        .to_ascii_lowercase()
}

/// RFC 3986 scheme: `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` before `:`.
fn icon_scheme(src_l: &str) -> Option<&str> {
    let bytes = src_l.as_bytes();
    let first = bytes.first()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    let mut i = 1;
    while i < bytes.len() {
        match bytes[i] {
            b'a'..=b'z' | b'0'..=b'9' | b'+' | b'-' | b'.' => i += 1,
            b':' => return Some(&src_l[..i]),
            _ => return None,
        }
    }
    None
}

fn is_dangerous_icon_scheme(scheme: &str) -> bool {
    matches!(
        scheme,
        "javascript" | "vbscript" | "jscript" | "livescript" | "mocha" | "vbs" | "blob" | "file"
    )
}

fn is_remote_transport_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "ftp")
}

/// `http:/host` / `https:/host` — one slash, not `://`.
fn is_single_slash_http_like(src_l: &str, scheme: &str) -> bool {
    if !matches!(scheme, "http" | "https") {
        return false;
    }
    let rest = src_l.get(scheme.len() + 1..).unwrap_or("");
    rest.starts_with('/') && !rest.starts_with("//")
}

fn classify_icon_src(src: &str, mime: Option<&str>) -> IconClass {
    let src_l = normalize_icon_src(src);
    if src_l.is_empty() {
        return IconClass::High("icon src is empty after normalization".into());
    }
    let mime_l = mime.unwrap_or("").to_ascii_lowercase();
    let looks_svg = mime_l.contains("svg")
        || src_l.contains("image/svg")
        || src_l.contains(".svg")
        || src_l.starts_with("data:image/svg");

    if src_l.starts_with("data:") {
        if looks_svg {
            return IconClass::High("icon src is SVG data:".into());
        }
        if is_raster_data_uri(&src_l, &mime_l) {
            return IconClass::Clean;
        }
        return IconClass::High("icon src is a non-image data: URI".into());
    }

    if src_l.starts_with("//") {
        return classify_remote_icon(&src_l, &mime_l, looks_svg);
    }

    if let Some(scheme) = icon_scheme(&src_l) {
        if is_dangerous_icon_scheme(scheme) {
            return IconClass::High(format!("icon src uses {scheme}:"));
        }
        let rest = src_l.get(scheme.len() + 1..).unwrap_or("");
        let has_authority = rest.starts_with("//");
        let single_slash_http = is_single_slash_http_like(&src_l, scheme);
        if has_authority || single_slash_http || is_remote_transport_scheme(scheme) {
            return classify_remote_icon(&src_l, &mime_l, looks_svg);
        }
        // scheme: without an authority — treat as script-like (fail-closed).
        return IconClass::High(format!("icon src uses {scheme}:"));
    }

    if looks_svg {
        return IconClass::High("icon src is a path-only SVG".into());
    }
    IconClass::Clean
}

fn classify_remote_icon(src_l: &str, mime_l: &str, looks_svg: bool) -> IconClass {
    if looks_svg {
        return IconClass::High("icon src is a remote SVG".into());
    }
    if is_remote_raster(src_l, mime_l) {
        return IconClass::Medium("icon src is a remote PNG/JPEG/WebP".into());
    }
    IconClass::Medium("icon src is a remote resource".into())
}

fn is_raster_data_uri(src_l: &str, mime_l: &str) -> bool {
    const RASTER: &[&str] = &["image/png", "image/jpeg", "image/jpg", "image/webp"];
    RASTER
        .iter()
        .any(|t| src_l.contains(t) || mime_l.contains(t))
}

fn is_remote_raster(src_l: &str, mime_l: &str) -> bool {
    if is_raster_data_uri(src_l, mime_l) {
        return true;
    }
    src_l.contains(".png")
        || src_l.contains(".jpg")
        || src_l.contains(".jpeg")
        || src_l.contains(".webp")
}

pub(crate) fn detect_cc015(tool: &ToolDefinition) -> Option<ManifestFinding> {
    for text in tool_scan_texts(tool) {
        if let Some(needle) = secret_path_lure_in_text(&text) {
            return Some(ManifestFinding::new(
                ManifestRule::Cc015,
                ManifestSeverity::Medium,
                &tool.name,
                format!("sensitive path lure in advertised text: {needle}"),
            ));
        }
    }
    None
}

fn secret_path_lure_in_text(text: &str) -> Option<String> {
    let lower = text.to_ascii_lowercase();
    for lit in secret_overlay_lure_literals() {
        if *lit == ".env" {
            continue;
        }
        if lower.contains(&lit.to_ascii_lowercase()) {
            return Some((*lit).to_string());
        }
    }
    env_lure_in_text(&lower)
}

fn env_lure_in_text(text_lower: &str) -> Option<String> {
    let mut start = 0;
    while let Some(rel) = text_lower[start..].find(".env") {
        let abs = start + rel;
        let after = &text_lower[abs..];
        let token_end = after
            .char_indices()
            .find(|(_, c)| !(c.is_ascii_alphanumeric() || *c == '.' || *c == '_' || *c == '-'))
            .map(|(i, _)| i)
            .unwrap_or(after.len());
        let token = &after[..token_end];
        if !is_env_example_token(token) {
            return Some(token.to_string());
        }
        start = abs + 4;
    }
    None
}
