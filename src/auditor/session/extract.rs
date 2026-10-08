//! Discovery-path extraction: pull file identifiers out of list-style
//! JSON-RPC responses under the `deputy` extraction rules snapshotted on
//! each pending request.

use super::MAX_KNOWN_PATHS;
use crate::policy::deputy::{DeputyRule, KnownShape};
/// Extract file identifiers from a list-style JSON-RPC response.
///
/// Only typed fields are accepted:
/// - `result.content[].text` (newline-separated paths)
/// - `result.content[].resource.uri`
/// - `result.resources[].uri`
/// - `result.roots[].uri`
/// - `result.files[].path`
///
/// Object keys and unrelated strings never enter `known_paths`.
pub fn extract_paths_from_response(line: &str) -> Vec<String> {
    let json = match nojson::RawJson::parse(line) {
        Ok(j) => j,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    extract_mcp_list_identifiers(json.value(), &mut out);
    out.truncate(MAX_KNOWN_PATHS);
    out
}

/// The `shape "mcp_list_result"` extractor: reads the typed
/// `result.content`/`resources`/`roots`/`files` fields off a response
/// frame. Callers gate on response success — this helper extracts from
/// whatever `result` member exists.
fn extract_mcp_list_identifiers(frame: nojson::RawJsonValue<'_, '_>, out: &mut Vec<String>) {
    let Some(result) = frame.to_member("result").ok().and_then(|m| m.optional()) else {
        return;
    };
    push_content_identifiers(result, out);
    push_array_string_field(result, "resources", "uri", out);
    push_array_string_field(result, "roots", "uri", out);
    push_array_string_field(result, "files", "path", out);
}

/// Extract discovery paths from a **successful** response frame using the
/// rules snapshotted on the pending request.
///
/// `shape "mcp_list_result"` reads the typed fields above; `extract`
/// pointers resolve their declared `/result/...` locations (line-split
/// per `split="lines"`). A truncated pointer contributes only its
/// bounded prefix — discovery is additive, so overflow narrows the
/// recorded set rather than failing the request (the `known_paths` caps
/// bound it anyway). The caller is responsible for the success gate:
/// JSON-RPC errors, `isError` results, MRTR interim results, and
/// unrelated frames must never reach this.
pub fn extract_paths_for_pending(
    frame: nojson::RawJsonValue<'_, '_>,
    rules: &[DeputyRule],
) -> Vec<String> {
    let mut out = Vec::new();
    for rule in rules {
        match rule {
            DeputyRule::Shape(KnownShape::McpListResult) => {
                extract_mcp_list_identifiers(frame, &mut out);
            }
            // A use-role shape on discovery — the loader rejects this;
            // skip defensively rather than extracting request-side paths.
            DeputyRule::Shape(KnownShape::FsTargets) => {}
            DeputyRule::Pointer(p) => out.extend(p.resolve(frame).values),
        }
        if out.len() >= MAX_KNOWN_PATHS {
            break;
        }
    }
    out.truncate(MAX_KNOWN_PATHS);
    out
}

fn json_string_field(value: nojson::RawJsonValue<'_, '_>, name: &str) -> Option<String> {
    let member = value.to_member(name).ok()?.optional()?;
    member.to_unquoted_string_str().ok().map(|s| s.into_owned())
}

fn push_content_identifiers(result: nojson::RawJsonValue<'_, '_>, out: &mut Vec<String>) {
    let Some(content) = result.to_member("content").ok().and_then(|m| m.optional()) else {
        return;
    };
    let Ok(items) = content.to_array() else {
        return;
    };
    for item in items {
        if let Some(text) = json_string_field(item, "text") {
            for line in text.lines() {
                let trimmed = line.trim();
                if trimmed.len() > 1 {
                    out.push(trimmed.to_string());
                }
            }
        }
        if let Some(resource) = item.to_member("resource").ok().and_then(|m| m.optional())
            && let Some(uri) = json_string_field(resource, "uri")
            && uri.len() > 1
        {
            out.push(uri);
        }
    }
}

fn push_array_string_field(
    result: nojson::RawJsonValue<'_, '_>,
    array_name: &str,
    field: &str,
    out: &mut Vec<String>,
) {
    let Some(arr) = result.to_member(array_name).ok().and_then(|m| m.optional()) else {
        return;
    };
    let Ok(items) = arr.to_array() else {
        return;
    };
    for item in items {
        if let Some(value) = json_string_field(item, field)
            && value.len() > 1
        {
            out.push(value);
        }
    }
}
