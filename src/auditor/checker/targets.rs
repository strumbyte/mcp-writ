//! Request-argument target extraction: the classified walk that turns
//! `params.arguments` / `params.inputResponses` string values into
//! filesystem paths, URLs, and hosts for sub-policy and deputy checks.

use crate::policy::deputy::{DeputyRule, KnownShape};

use super::{MAX_JSON_NESTING, params_member};

/// Aggregate cap on extracted targets across `arguments` and
/// `inputResponses` — one request must not amplify into unbounded
/// filesystem/network authorization work.
pub(super) const MAX_EXTRACTED_TARGETS: usize = 512;
/// Cap on JSON scalar leaves the classifier inspects per request — the
/// walk stops (fail-closed `truncated`) instead of spending unbounded
/// classify/normalize work on a hostile frame.
const MAX_INSPECTED_LEAVES: usize = 4096;

pub(super) struct ExtractedTargets {
    pub(super) paths: Vec<String>,
    pub(super) urls: Vec<String>,
    pub(super) hosts: Vec<String>,
    /// Path-classified argument strings whose normalization changed the
    /// spelling: the check ran on `normalized` but the wire carries
    /// `raw`. On a byte-preserving filesystem those name distinct
    /// directory entries, so a caller that authorizes paths must refuse
    /// rather than forward a representation it did not evaluate.
    pub(super) noncanonical: Vec<NoncanonicalSpelling>,
    /// Normalized spellings of string arguments under no recognized
    /// key — neither the selector vocabularies nor the declared
    /// payload fields. A restricted contract cannot prove what these
    /// select, so restricted callers refuse them rather than forward
    /// an unchecked target.
    pub(super) unclassified: Vec<String>,
    /// The leaf/target budget was exceeded — the collected vectors are a
    /// strict prefix of the real targets. Restricted callers must treat
    /// this as unknowable (fail closed); discovery-side callers narrow.
    pub(super) truncated: bool,
    /// Scalars inspected so far — shared across `arguments` and
    /// `inputResponses` so one frame has a single work budget.
    leaves: usize,
    /// Normalized spellings already retained *per slot* — deduplication
    /// so repeated arguments cost one authorization each, not one per
    /// occurrence. Keyed by slot because the same spelling is a distinct
    /// check in each: a value path-classified under `path` and
    /// host-classified under `host` must reach *both* authorization
    /// passes — dropping the host copy on a value-only key would let a
    /// destination skip the network verdict entirely.
    seen: std::collections::HashSet<(TargetSlot, String)>,
}

impl ExtractedTargets {
    fn new() -> Self {
        Self {
            paths: Vec::new(),
            urls: Vec::new(),
            hosts: Vec::new(),
            noncanonical: Vec::new(),
            unclassified: Vec::new(),
            truncated: false,
            leaves: 0,
            seen: std::collections::HashSet::new(),
        }
    }

    /// Total extracted targets retained so far.
    fn target_count(&self) -> usize {
        self.paths.len() + self.urls.len() + self.hosts.len() + self.unclassified.len()
    }

    /// Budget gate shared by every classified push: identical normalized
    /// spellings are deduplicated (`seen`) and the aggregate count stops
    /// at [`MAX_EXTRACTED_TARGETS`], marking the outcome `truncated`
    /// instead of growing without bound.
    fn push(&mut self, slot: TargetSlot, value: String) {
        if self.truncated {
            return;
        }
        if self.target_count() >= MAX_EXTRACTED_TARGETS {
            self.truncated = true;
            return;
        }
        if !self.seen.insert((slot, value.clone())) {
            return;
        }
        match slot {
            TargetSlot::Path => self.paths.push(value),
            TargetSlot::Url => self.urls.push(value),
            TargetSlot::Host => self.hosts.push(value),
            TargetSlot::Unclassified => self.unclassified.push(value),
        }
    }

    /// Record a raw/normalized divergence — only the first matters; the
    /// deny reason reports a single spelling anyway.
    fn push_noncanonical(&mut self, raw: String, normalized: String) {
        const MAX_NONCANONICAL: usize = 8;
        if self.noncanonical.len() < MAX_NONCANONICAL {
            self.noncanonical
                .push(NoncanonicalSpelling { raw, normalized });
        }
    }
}

/// Which target vector a classified string lands in.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum TargetSlot {
    Path,
    Url,
    Host,
    Unclassified,
}

/// A path-classified argument where `raw` (forwarded) and `normalized`
/// (checked) are different strings.
pub(super) struct NoncanonicalSpelling {
    pub(super) raw: String,
    pub(super) normalized: String,
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
    let mut noncanonical: Vec<NoncanonicalSpelling> = Vec::new();
    for rule in rules {
        match rule {
            DeputyRule::Shape(KnownShape::FsTargets) => {
                input_responses_covered = true;
                let targets = collect_argument_targets(&json);
                // A truncated classified walk leaves unchecked targets —
                // a `use`-role call never passes on a partial path set.
                if targets.truncated {
                    return Err("argument target extraction exceeded the work budget".to_string());
                }
                out.extend(targets.paths);
                noncanonical.extend(targets.noncanonical);
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
                    match crate::pathutil::normalize_fs_argument(&value) {
                        Ok(normalized) => {
                            if normalized != value {
                                noncanonical.push(NoncanonicalSpelling {
                                    raw: value,
                                    normalized: normalized.clone(),
                                });
                            }
                            out.push(normalized);
                        }
                        Err(_) => out.push(value),
                    }
                }
            }
        }
        // Cumulative bound across all rules: each rule's contribution is
        // already capped, so a single overshoot check per rule keeps the
        // collected set at the aggregate bound. A longer tail is a
        // partial path set a `use`-role call must not pass on.
        if out.len() > MAX_EXTRACTED_TARGETS {
            return Err("extracted target set exceeded the count bound".to_string());
        }
    }
    // The MRTR retry channel is request-side input too: path values under
    // `params.inputResponses` must clear the same discovery check even
    // when the configured rules name only `/params/arguments/...`.
    if !input_responses_covered {
        let targets = input_response_targets(&json);
        if targets.truncated {
            return Err("inputResponses target extraction exceeded the work budget".to_string());
        }
        out.extend(targets.paths);
        noncanonical.extend(targets.noncanonical);
        if out.len() > MAX_EXTRACTED_TARGETS {
            return Err("extracted target set exceeded the count bound".to_string());
        }
    }
    // The use-role contract is closed as well: extraction rules name the
    // fields they cover, and the raw request is forwarded whole — a
    // plausible selector under an undeclared field is refused like an
    // extraction failure rather than reaching the child unchecked.
    let classified = collect_argument_targets(&json);
    if classified.truncated {
        return Err("argument target extraction exceeded the work budget".to_string());
    }
    for bad in &classified.unclassified {
        if crate::pathutil::selector_plausible(bad) {
            return Err(format!(
                "unrecognized argument '{bad}' may carry an undeclared resource \
                 selector — restricted tools accept only declared fields"
            ));
        }
    }
    // Discovery credit is checked against the normalized spelling; the
    // server consumes the raw one. When they differ the check would
    // authorize a different object than the call opens — refuse.
    if let Some(nc) = noncanonical.into_iter().next() {
        return Err(format!(
            "path argument '{}' is not in canonical form; resend the canonical spelling '{}'",
            nc.raw, nc.normalized
        ));
    }
    Ok(out)
}

/// Path-classified targets from `params.inputResponses` only — the MRTR
/// retry channel — using the same classified walk as
/// [`collect_argument_targets`].
fn input_response_targets(json: &nojson::RawJson<'_>) -> ExtractedTargets {
    let mut out = ExtractedTargets::new();
    if let Some(responses) = params_member(json, "inputResponses") {
        walk_json_targets(responses, "", 0, &mut out);
    }
    out
}

/// True when Auditor host/URL extraction finds a network target in the request.
///
/// Reused by trajectory `deny-next="network"` (same walk as side_effect enforcement).
pub fn request_has_host_or_url(line: &str) -> bool {
    let Ok(json) = nojson::RawJson::parse(line) else {
        return false;
    };
    let extracted = collect_argument_targets(&json);
    // A truncated walk cannot prove the absence of a network target —
    // report one rather than let an over-budget tail slip a host past
    // the check.
    extracted.truncated || !extracted.hosts.is_empty() || !extracted.urls.is_empty()
}

pub(super) fn collect_argument_targets(json: &nojson::RawJson<'_>) -> ExtractedTargets {
    let mut out = ExtractedTargets::new();
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
    if depth > MAX_JSON_NESTING || out.truncated {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            if let Ok(obj) = val.to_object() {
                for (k, v) in obj {
                    if out.truncated {
                        return;
                    }
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
                    if out.truncated {
                        return;
                    }
                    walk_json_targets(elem, key, depth + 1, out);
                }
            }
        }
        _ => {
            out.leaves += 1;
            if out.leaves > MAX_INSPECTED_LEAVES {
                out.truncated = true;
                return;
            }
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
            out.push(TargetSlot::Path, value.to_string());
            return;
        }
    };

    if crate::pathutil::starts_with_file_scheme(&normalized)
        || crate::pathutil::looks_like_path(&normalized)
    {
        if normalized != value {
            out.push_noncanonical(value.to_string(), normalized.clone());
        }
        out.push(TargetSlot::Path, normalized);
        return;
    }
    // URL-shaped values (including on path/target keys) are network targets.
    // Otherwise `path=https://…` would skip the read_only host/URL check.
    if crate::pathutil::looks_like_network_target(&normalized) {
        let key_l = key.to_ascii_lowercase();
        if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
            out.push(
                TargetSlot::Host,
                crate::policy::canonicalize_policy_host(&normalized),
            );
        } else {
            out.push(TargetSlot::Url, value.to_string());
        }
        return;
    }
    // Unambiguous endpoint spellings are network targets under any key —
    // an IP literal, `[v6]:port`, or `host:port` under `dest`/
    // `destination`/`target` is an address, not a filename.
    if crate::pathutil::looks_like_host_or_socket(&normalized) {
        out.push(
            TargetSlot::Host,
            crate::policy::canonicalize_policy_host(&normalized),
        );
        return;
    }
    if crate::pathutil::is_path_field_value(key, &normalized)
        || crate::pathutil::looks_like_path(value)
    {
        if normalized != value {
            out.push_noncanonical(value.to_string(), normalized.clone());
        }
        out.push(TargetSlot::Path, normalized);
        return;
    }
    if crate::pathutil::is_network_field_name(key) {
        // `scheme://`/`//` spellings are URL arguments. A bare token on a
        // network field names a host (with or without a `:port` — the
        // evaluator folds the qualifier away), so it is checked as a
        // host rather than refused as a malformed URL. Anything else is
        // an unparseable selector and keeps the invalid-URL deny path.
        if value.contains("://") || value.starts_with("//") {
            out.push(TargetSlot::Url, value.to_string());
        } else if crate::pathutil::looks_like_host_or_socket(&normalized)
            || crate::pathutil::dns_name_shape(&normalized)
        {
            out.push(
                TargetSlot::Host,
                crate::policy::canonicalize_policy_host(&normalized),
            );
        } else {
            out.push(TargetSlot::Url, value.to_string());
        }
        return;
    }
    // Reserved secret spellings are filesystem targets under *any* key —
    // an unrecognized field name cannot hide `.env` or `.ssh/…` from the
    // overlay or an fs allow-list.
    if crate::secret_paths::is_secret_path(&normalized) {
        out.push(TargetSlot::Path, normalized);
        return;
    }
    // Declared non-selector payload fields carry opaque content.
    if crate::pathutil::is_known_payload_field_name(key) {
        return;
    }
    // A string under no recognized vocabulary cannot be proven a
    // non-selector — restricted callers refuse it rather than forward
    // an unchecked target.
    out.push(TargetSlot::Unclassified, normalized);
}
