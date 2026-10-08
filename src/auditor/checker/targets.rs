//! Request-argument target extraction: the classified walk that turns
//! `params.arguments` / `params.inputResponses` string values into
//! filesystem paths, URLs, and hosts for sub-policy and deputy checks.

use crate::policy::deputy::{DeputyRule, KnownShape};

use super::{MAX_JSON_NESTING, params_member};

pub(super) struct ExtractedTargets {
    pub(super) paths: Vec<String>,
    pub(super) urls: Vec<String>,
    pub(super) hosts: Vec<String>,
}

/// Filesystem targets from `arguments` and `inputResponses` for deputy checks.
pub fn extract_fs_targets(line: &str) -> Vec<String> {
    let Ok(json) = nojson::RawJson::parse(line) else {
        return Vec::new();
    };
    collect_argument_targets(&json).paths
}

/// Resolve a `use`-role tool's configured deputy extraction rules against
/// a `tools/call` request line.
///
/// `shape "fs_targets"` runs the same path-classified walk as
/// [`extract_fs_targets`]; `extract` pointers resolve their declared
/// `/params/...` locations and every matched string counts as a path
/// (normalized the same way, so `file:` URIs and `./` forms join the same
/// namespace). Path-classified values under `params.inputResponses` are
/// always added — a retry's responses are request-side input the tool
/// may consume as paths. `Err` is an extraction failure — the caller must deny:
/// a `use`-role call never passes on an unverifiable path set, and a
/// pointer evaluation that hit its value bound is unknowable.
pub fn extract_deputy_use_targets(line: &str, rules: &[DeputyRule]) -> Result<Vec<String>, String> {
    let json =
        nojson::RawJson::parse(line).map_err(|e| format!("request is not valid JSON: {e}"))?;
    let mut out = Vec::new();
    // `shape "fs_targets"` already covers `params.inputResponses` through
    // the same classified walk — remember it ran so the retry channel is
    // not walked (and its values not duplicated) a second time below.
    let mut input_responses_covered = false;
    for rule in rules {
        match rule {
            DeputyRule::Shape(KnownShape::FsTargets) => {
                input_responses_covered = true;
                out.extend(collect_argument_targets(&json).paths);
            }
            // A discover-role shape on the use side — the loader rejects
            // this; skip defensively.
            DeputyRule::Shape(KnownShape::McpListResult) => {}
            DeputyRule::Pointer(p) => {
                let outcome = p.resolve(json.value());
                if outcome.truncated {
                    return Err(format!(
                        "extraction at \"{}\" exceeded the value bound",
                        p.source
                    ));
                }
                for value in outcome.values {
                    out.push(match crate::pathutil::normalize_fs_argument(&value) {
                        Ok(normalized) => normalized,
                        Err(_) => value,
                    });
                }
            }
        }
    }
    // The MRTR retry channel is request-side input too: path values under
    // `params.inputResponses` must clear the same discovery check even
    // when the configured rules name only `/params/arguments/...`.
    if !input_responses_covered {
        out.extend(input_response_paths(&json));
    }
    Ok(out)
}

/// Path-classified targets from `params.inputResponses` only — the MRTR
/// retry channel — using the same classified walk as
/// [`collect_argument_targets`].
fn input_response_paths(json: &nojson::RawJson<'_>) -> Vec<String> {
    let mut out = ExtractedTargets {
        paths: Vec::new(),
        urls: Vec::new(),
        hosts: Vec::new(),
    };
    if let Some(responses) = params_member(json, "inputResponses") {
        walk_json_targets(responses, "", 0, &mut out);
    }
    out.paths
}

/// True when Auditor host/URL extraction finds a network target in the request.
///
/// Reused by trajectory `deny-next="network"` (same walk as side_effect enforcement).
pub fn request_has_host_or_url(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line) else {
        return false;
    };
    let extracted = collect_argument_targets(&json);
    !extracted.hosts.is_empty() || !extracted.urls.is_empty()
}

pub(super) fn collect_argument_targets(json: &nojson::RawJson<'_>) -> ExtractedTargets {
    let mut out = ExtractedTargets {
        paths: Vec::new(),
        urls: Vec::new(),
        hosts: Vec::new(),
    };
    if let Some(args) = json
        .value()
        .to_member("params")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|p| p.to_member("arguments").ok()?.optional())
    {
        walk_json_targets(args, "", 0, &mut out);
    }
    if let Some(input_responses) = params_member(json, "inputResponses") {
        walk_json_targets(input_responses, "", 0, &mut out);
    }
    out
}

fn walk_json_targets(
    val: nojson::RawJsonValue<'_, '_>,
    key: &str,
    depth: u32,
    out: &mut ExtractedTargets,
) {
    if depth > MAX_JSON_NESTING {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            if let Ok(obj) = val.to_object() {
                for (k, v) in obj {
                    let key_owned = k
                        .to_unquoted_string_str()
                        .map(|s| s.into_owned())
                        .unwrap_or_default();
                    walk_json_targets(v, &key_owned, depth + 1, out);
                }
            }
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for elem in arr {
                    walk_json_targets(elem, key, depth + 1, out);
                }
            }
        }
        _ => {
            if let Ok(s) = val.to_unquoted_string_str() {
                classify_target_string(key, s.as_ref(), out);
            }
        }
    }
}

fn classify_target_string(key: &str, value: &str, out: &mut ExtractedTargets) {
    // Same Auditor-time normalize as overlay (bounded percent-decode + WHATWG
    // C0 strip + file: → path) so `file\t://` / `%66ile%0A://` become paths.
    let normalized = match crate::pathutil::normalize_fs_argument(value) {
        Ok(n) => n,
        Err(_) => {
            out.paths.push(value.to_string());
            return;
        }
    };

    if crate::pathutil::starts_with_file_scheme(&normalized)
        || crate::pathutil::looks_like_path(&normalized)
    {
        out.paths.push(normalized);
        return;
    }
    // URL-shaped values (including on path/target keys) are network targets.
    // Otherwise `path=https://…` would skip the read_only host/URL check.
    if crate::pathutil::looks_like_network_target(&normalized) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.hosts
                .push(crate::policy::canonicalize_policy_host(&normalized));
        } else {
            out.urls.push(value.to_string());
        }
        return;
    }
    if crate::pathutil::is_path_field_value(key, &normalized)
        || crate::pathutil::looks_like_path(value)
    {
        out.paths.push(normalized);
        return;
    }
    if crate::pathutil::is_network_field_name(key) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.hosts
                .push(crate::policy::canonicalize_policy_host(value));
        } else {
            out.urls.push(value.to_string());
        }
    }
}
