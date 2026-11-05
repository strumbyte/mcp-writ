//! Request-argument target extraction: the classified walk that turns
//! `params.arguments` / `params.inputResponses` string values into
//! filesystem paths, URLs, and hosts for sub-policy and deputy checks.

use std::borrow::{Borrow, Cow};
use std::collections::HashSet;
use std::rc::Rc;

use crate::policy::deputy::{DeputyRule, KnownShape};
use crate::policy::opaque::{OpaqueField, OpaqueMatcher};

use super::{MAX_JSON_NESTING, params_member};

/// Aggregate cap on extracted targets across `arguments` and
/// `inputResponses` — one request must not amplify into unbounded
/// filesystem/network authorization work.
pub(super) const MAX_EXTRACTED_TARGETS: usize = 512;
/// Cap on JSON scalar leaves the classifier inspects per request — the
/// walk stops (fail-closed `truncated`) instead of spending unbounded
/// classify/normalize work on a hostile frame.
const MAX_INSPECTED_LEAVES: usize = 4096;

/// Storage for a retained target spelling. `String` backs the public
/// extraction API (`Vec<String>` out); `Rc<str>` backs the auditor's
/// internal consumers, where the per-slot dedup set shares the vector's
/// allocation so a `clone()` costs a refcount bump, not a copy.
pub(super) trait TargetString:
    Borrow<str> + Eq + std::hash::Hash + Clone + for<'a> From<&'a str>
{
    /// Wrap an already-owned `String`. `Rc<str>` reuses the allocation;
    /// `String` is the move itself.
    fn from_owned(value: String) -> Self;
}

impl TargetString for String {
    fn from_owned(value: String) -> Self {
        value
    }
}

impl TargetString for Rc<str> {
    fn from_owned(value: String) -> Self {
        Rc::from(value)
    }
}

pub(super) struct ExtractedTargets<S = Rc<str>> {
    pub(super) paths: Vec<S>,
    pub(super) urls: Vec<S>,
    pub(super) hosts: Vec<S>,
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
    pub(super) unclassified: Vec<S>,
    /// Bitmask of the tool's `arguments { opaque }` declarations that
    /// exempted at least one scalar leaf from the `unclassified`
    /// bucket — bit *i* is the *i*-th declared field, so the count is
    /// fields exercised, not leaves exempted. Resource-shaped and
    /// secret-path values still classify normally, so a declared field
    /// that carried one contributes a `paths`/`urls`/`hosts` entry and
    /// no bit here.
    pub(super) opaque_mask: u64,
    /// The leaf/target budget was exceeded — the collected vectors are a
    /// strict prefix of the real targets. Restricted callers must treat
    /// this as unknowable (fail closed); discovery-side callers narrow.
    pub(super) truncated: bool,
    /// Scalars inspected so far — shared across `arguments` and
    /// `inputResponses` so one frame has a single work budget. Only the
    /// frozen reference walk still counts leaves here; the live
    /// extractor budgets at leaf-collection time.
    #[cfg(test)]
    leaves: usize,
    /// Normalized spellings already retained *per slot* — deduplication
    /// so repeated arguments cost one authorization each, not one per
    /// occurrence. Keyed by slot because the same spelling is a distinct
    /// check in each: a value path-classified under `path` and
    /// host-classified under `host` must reach *both* authorization
    /// passes — dropping the host copy on a value-only key would let a
    /// destination skip the network verdict entirely. The dedup check
    /// runs on the `&str` itself before any storage is allocated, and a
    /// retained spelling is created once for the set and the vector —
    /// under `Rc` storage that clone is a refcount bump.
    seen: SeenSets<S>,
}

/// Per-slot deduplication sets — four sets sharing storage with the
/// retained vectors (`Rc` shares; `String` keeps the historical copy).
struct SeenSets<S> {
    path: HashSet<S>,
    url: HashSet<S>,
    host: HashSet<S>,
    unclassified: HashSet<S>,
}

impl<S> Default for SeenSets<S> {
    fn default() -> Self {
        Self {
            path: HashSet::new(),
            url: HashSet::new(),
            host: HashSet::new(),
            unclassified: HashSet::new(),
        }
    }
}

impl<S> SeenSets<S> {
    fn slot_mut(&mut self, slot: TargetSlot) -> &mut HashSet<S> {
        match slot {
            TargetSlot::Path => &mut self.path,
            TargetSlot::Url => &mut self.url,
            TargetSlot::Host => &mut self.host,
            TargetSlot::Unclassified => &mut self.unclassified,
        }
    }
}

impl<S: TargetString> ExtractedTargets<S> {
    fn new() -> Self {
        Self {
            paths: Vec::new(),
            urls: Vec::new(),
            hosts: Vec::new(),
            noncanonical: Vec::new(),
            unclassified: Vec::new(),
            opaque_mask: 0,
            truncated: false,
            #[cfg(test)]
            leaves: 0,
            seen: SeenSets::default(),
        }
    }

    /// Total extracted targets retained so far.
    fn target_count(&self) -> usize {
        self.paths.len() + self.urls.len() + self.hosts.len() + self.unclassified.len()
    }

    /// Budget gate shared by every classified push: identical normalized
    /// spellings are deduplicated (`seen`) and the aggregate count stops
    /// at [`MAX_EXTRACTED_TARGETS`], marking the outcome `truncated`
    /// instead of growing without bound. The dedup check runs on the
    /// `&str` itself — storage is only created for a spelling that is
    /// actually retained, and one `S` serves both the set and the
    /// vector.
    fn push(&mut self, slot: TargetSlot, value: &str) {
        if self.truncated {
            return;
        }
        if self.target_count() >= MAX_EXTRACTED_TARGETS {
            self.truncated = true;
            return;
        }
        let set = self.seen.slot_mut(slot);
        if set.contains(value) {
            return;
        }
        let stored = S::from(value);
        set.insert(stored.clone());
        match slot {
            TargetSlot::Path => self.paths.push(stored),
            TargetSlot::Url => self.urls.push(stored),
            TargetSlot::Host => self.hosts.push(stored),
            TargetSlot::Unclassified => self.unclassified.push(stored),
        }
    }

    /// Record that a scalar leaf stayed opaque under a declared field —
    /// bit `decl` marks the declaration that carried it. `decl` is
    /// bounded by `MAX_OPAQUE_FIELDS` on the load path; an unvalidated
    /// programmatically built policy could index past the mask, so a
    /// field beyond bit 63 is dropped rather than panicking.
    fn push_opaque(&mut self, decl: u32) {
        self.opaque_mask |= 1u64.checked_shl(decl).unwrap_or(0);
    }

    /// Count of the declared `arguments { opaque }` fields that carried
    /// at least one exempted value — the `opaque_fields=N` audit
    /// detail's N.
    pub(super) fn opaque_fields(&self) -> usize {
        self.opaque_mask.count_ones() as usize
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
#[derive(Clone)]
pub(super) struct NoncanonicalSpelling {
    pub(super) raw: String,
    pub(super) normalized: String,
}

/// Filesystem targets from `arguments` and `inputResponses` for deputy checks.
pub fn extract_fs_targets(line: &str) -> Vec<String> {
    let Ok(json) = nojson::RawJson::parse(line) else {
        return Vec::new();
    };
    collect_argument_targets_as(&json, None).paths
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
///
/// `opaque_fields` is the tool's effective `arguments { opaque }`
/// declaration set: the closed-contract check at the end exempts those
/// members from the unrecognized-argument refusal, identical to the
/// tool's own sub-policy evaluation.
pub fn extract_deputy_use_targets(
    line: &str,
    rules: &[DeputyRule],
    opaque_fields: &[OpaqueField],
) -> Result<Vec<String>, String> {
    extract_deputy_use_targets_as(line, rules, opaque_fields)
}

/// [`extract_deputy_use_targets`] returning shared `Rc<str>` targets for
/// the auditor's own deputy check. The public entry keeps `Vec<String>`
/// so the external signature (and its `Send`/`Sync`) is unchanged; the
/// shared-storage internals stay crate-internal.
pub(crate) fn extract_deputy_use_targets_rc(
    line: &str,
    rules: &[DeputyRule],
    opaque_fields: &[OpaqueField],
) -> Result<Vec<Rc<str>>, String> {
    extract_deputy_use_targets_as(line, rules, opaque_fields)
}

fn extract_deputy_use_targets_as<S: TargetString>(
    line: &str,
    rules: &[DeputyRule],
    opaque_fields: &[OpaqueField],
) -> Result<Vec<S>, String> {
    let json =
        nojson::RawJson::parse(line).map_err(|e| format!("request is not valid JSON: {e}"))?;
    let mut out: Vec<S> = Vec::new();
    // `shape "fs_targets"` already covers `params.inputResponses` through
    // the same classified walk — remember it ran so the retry channel is
    // not walked (and its values not duplicated) a second time below.
    let mut input_responses_covered = false;
    let mut noncanonical: Vec<NoncanonicalSpelling> = Vec::new();
    // The combined arguments+inputResponses walk runs lazily with its
    // first consumer: key attributes and the `normalize_fs_argument`
    // outcome are pure functions of the request *bytes*, so the leaf
    // prefix the first classify reached is collected as it goes and
    // replayed by every later consumer — a truncated frame keeps only
    // the leaves it actually classified. The filesystem-dependent
    // predicates are NOT shared — each consumer runs its own classify
    // pass over the leaves, so the secret-path overlay's cwd/symlink
    // resolutions happen the same number of times and in the same
    // order as the independent walks this replaces.
    let mut combined: Option<CollectedLeaves> = None;
    // The tool's declared free-form members — built once here so every
    // combined classify applies the same exemption set.
    let opaque = OpaqueMatcher::build(opaque_fields);
    for rule in rules {
        match rule {
            DeputyRule::Shape(KnownShape::FsTargets) => {
                input_responses_covered = true;
                let targets: ExtractedTargets<S> =
                    combined_classify(&json, &mut combined, opaque.as_ref());
                // A truncated classified walk leaves unchecked targets —
                // a `use`-role call never passes on a partial path set.
                if targets.truncated {
                    return Err("argument target extraction exceeded the work budget".to_string());
                }
                // Each `fs_targets` rule contributes a freshly classified
                // path set — a repeated rule contributes its targets
                // again, exactly like a fresh walk would.
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
                            out.push(S::from_owned(normalized));
                        }
                        Err(_) => out.push(S::from_owned(value)),
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
        let targets: ExtractedTargets<S> = input_response_targets_as(&json);
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
    let classified: ExtractedTargets<S> = combined_classify(&json, &mut combined, opaque.as_ref());
    if classified.truncated {
        return Err("argument target extraction exceeded the work budget".to_string());
    }
    for bad in &classified.unclassified {
        let bad: &str = bad.borrow();
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

pub(super) fn collect_argument_targets(json: &nojson::RawJson<'_>) -> ExtractedTargets<Rc<str>> {
    collect_argument_targets_as(json, None)
}

/// [`collect_argument_targets`] with the tool's declared
/// `arguments { opaque }` matcher — `params.arguments` members under a
/// declared field are exempted from the `unclassified` bucket (their
/// other classifications still run). `params.inputResponses` is never
/// opaque: the declaration names `arguments` members only.
pub(super) fn collect_argument_targets_opaque(
    json: &nojson::RawJson<'_>,
    opaque: Option<&OpaqueMatcher>,
) -> ExtractedTargets<Rc<str>> {
    collect_argument_targets_as(json, opaque)
}

fn collect_argument_targets_as<S: TargetString>(
    json: &nojson::RawJson<'_>,
    opaque: Option<&OpaqueMatcher>,
) -> ExtractedTargets<S> {
    // Single consumer — classify inline as the walk emits each scalar;
    // multi-consumer checks use `walk_combined_classified` instead.
    let mut out = ExtractedTargets::new();
    let mut walk = LeafWalk::default();
    if let Some(args) = json
        .value()
        .to_member("params")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|p| p.to_member("arguments").ok()?.optional())
    {
        walk_json_scalars(
            args,
            &KeyAttrs::NONE,
            opaque,
            0,
            &mut walk,
            &mut |attrs, s, leaf_opaque| {
                // The fused walk stopped classifying once the target budget
                // tripped — abort traversal so a truncated frame costs no
                // extra resolutions.
                if out.truncated {
                    return false;
                }
                classify_target_string(attrs, &s, leaf_opaque, &mut out);
                !out.truncated
            },
        );
    }
    if let Some(responses) = params_member(json, "inputResponses") {
        walk_json_scalars(
            responses,
            &KeyAttrs::NONE,
            None,
            0,
            &mut walk,
            &mut |attrs, s, leaf_opaque| {
                if out.truncated {
                    return false;
                }
                classify_target_string(attrs, &s, leaf_opaque, &mut out);
                !out.truncated
            },
        );
    }
    out.truncated |= walk.truncated;
    out
}

/// First combined classify pays for the walk; later consumers replay
/// the collected leaf prefix. `opaque` matters only on the collect —
/// the stored leaves already carry the flag it produced.
fn combined_classify<'a, S: TargetString>(
    json: &'a nojson::RawJson<'a>,
    shared: &mut Option<CollectedLeaves<'a>>,
    opaque: Option<&OpaqueMatcher>,
) -> ExtractedTargets<S> {
    match shared {
        Some(leaves) => leaves.classify(),
        None => {
            let (targets, leaves) = walk_combined_classified(json, opaque);
            *shared = Some(leaves);
            targets
        }
    }
}

/// Path-classified targets from `params.inputResponses` only — the MRTR
/// retry channel — the same fused walk as [`collect_argument_targets`]
/// over the standalone channel's own budget.
fn input_response_targets_as<S: TargetString>(json: &nojson::RawJson<'_>) -> ExtractedTargets<S> {
    let mut out = ExtractedTargets::new();
    let mut walk = LeafWalk::default();
    if let Some(responses) = params_member(json, "inputResponses") {
        walk_json_scalars(
            responses,
            &KeyAttrs::NONE,
            None,
            0,
            &mut walk,
            &mut |attrs, s, leaf_opaque| {
                if out.truncated {
                    return false;
                }
                classify_target_string(attrs, &s, leaf_opaque, &mut out);
                !out.truncated
            },
        );
    }
    out.truncated |= walk.truncated;
    out
}

/// One scalar string leaf's pure parse/normalize outcome. Everything
/// here is a function of the request bytes alone; the
/// filesystem-dependent predicates stay in [`classify_leaf`] and run
/// per consumer.
struct ScalarLeaf<'a> {
    attrs: KeyAttrs,
    raw: Cow<'a, str>,
    norm: LeafNorm<'a>,
    /// Index of the tool's `arguments { opaque }` declaration covering
    /// this leaf — `Some` exempts it from the `unclassified` fallback
    /// and names which declaration did so.
    opaque: Option<u32>,
}

enum LeafNorm<'a> {
    /// `is_plain_ascii_token` — normalization is provably the identity;
    /// the leaf replays through `classify_plain_token`.
    Plain,
    /// `normalize_fs_argument` output, shared by every consumer.
    Normalized(Cow<'a, str>),
    /// Normalization failed closed — the leaf is a filesystem target
    /// under any key, exactly as the inline classifier treated it.
    Failed,
}

impl ScalarLeaf<'_> {
    fn of<'a>(attrs: &KeyAttrs, raw: Cow<'a, str>, opaque: Option<u32>) -> ScalarLeaf<'a> {
        if is_plain_ascii_token(&raw) {
            return ScalarLeaf {
                attrs: *attrs,
                raw,
                norm: LeafNorm::Plain,
                opaque,
            };
        }
        match raw {
            Cow::Borrowed(raw) => ScalarLeaf {
                attrs: *attrs,
                raw: Cow::Borrowed(raw),
                norm: match crate::pathutil::normalize_fs_argument_cow(raw) {
                    Ok(n) => LeafNorm::Normalized(n),
                    Err(_) => LeafNorm::Failed,
                },
                opaque,
            },
            Cow::Owned(raw) => {
                // The normalization must not borrow `raw` — both live
                // in the leaf — so an escaped string's output is
                // materialized even when unchanged.
                let norm = match crate::pathutil::normalize_fs_argument_cow(&raw) {
                    Ok(n) => LeafNorm::Normalized(Cow::Owned(n.into_owned())),
                    Err(_) => LeafNorm::Failed,
                };
                ScalarLeaf {
                    attrs: *attrs,
                    raw: Cow::Owned(raw),
                    norm,
                    opaque,
                }
            }
        }
    }
}

/// Scalar-leaf budget — the per-request cap the classified walk
/// enforced via `leaves`/`truncated`. `done` is a consumer abort (the
/// sink asked the walk to stop): distinct from `truncated`, which is
/// the leaf budget cutting the scalar set short.
#[derive(Default)]
struct LeafWalk {
    count: usize,
    truncated: bool,
    done: bool,
}

/// Shared scalar-leaf prefix collected *during* the first combined
/// classify — the `fs_targets` shape and the closed-contract check
/// replay it, so the frame is parsed and normalized once. Only leaves
/// the classify actually reached are stored: the sink aborts the walk
/// with the first consumer's target budget, so a denied frame never
/// normalizes or retains its tail.
pub(super) struct CollectedLeaves<'a> {
    leaves: Vec<ScalarLeaf<'a>>,
    /// The shared leaf budget tripped during collection — the stored
    /// leaves are a strict prefix of the real scalar set.
    leaf_truncated: bool,
}

impl CollectedLeaves<'_> {
    /// Freshly classify the collected prefix — the same leaf sequence
    /// the first consumer saw. Filesystem-dependent verdicts are
    /// re-evaluated per call, exactly as an independent walk would.
    fn classify<S: TargetString>(&self) -> ExtractedTargets<S> {
        let mut out = ExtractedTargets::new();
        for leaf in &self.leaves {
            // The first classify stopped at the target budget — replay
            // keeps the same early-out so a truncated frame costs no
            // extra resolutions.
            if out.truncated {
                break;
            }
            classify_leaf(leaf, &mut out);
        }
        if self.leaf_truncated {
            out.truncated = true;
        }
        out
    }

    /// Test-only peek at the collected prefix size — evidence that a
    /// denied frame retained only the leaves its classify reached.
    #[cfg(test)]
    pub(super) fn collected_len(&self) -> usize {
        self.leaves.len()
    }
}

/// Walk `params.arguments` then `params.inputResponses` under one leaf
/// budget — the fused combined traversal — classifying each reached
/// scalar inline and collecting it for replay. Later combined
/// consumers use [`CollectedLeaves::classify`] on the same prefix.
///
/// `opaque` descends the `arguments` tree only — the declaration names
/// `params.arguments` members, so `inputResponses` values classify
/// under their own vocabulary as before.
pub(super) fn walk_combined_classified<'a, S: TargetString>(
    json: &'a nojson::RawJson<'a>,
    opaque: Option<&OpaqueMatcher>,
) -> (ExtractedTargets<S>, CollectedLeaves<'a>) {
    let mut out = ExtractedTargets::new();
    let mut leaves = Vec::new();
    let mut walk = LeafWalk::default();
    let mut sink = |attrs: &KeyAttrs, s: Cow<'a, str>, leaf_opaque: Option<u32>| -> bool {
        // The fused walk stopped once the classify's own budget tripped
        // — stop emitting (and stop collecting) the same way.
        if out.truncated {
            return false;
        }
        let leaf = ScalarLeaf::of(attrs, s, leaf_opaque);
        classify_leaf(&leaf, &mut out);
        leaves.push(leaf);
        !out.truncated
    };
    if let Some(args) = json
        .value()
        .to_member("params")
        .ok()
        .and_then(|m| m.optional())
        .and_then(|p| p.to_member("arguments").ok()?.optional())
    {
        walk_json_scalars(args, &KeyAttrs::NONE, opaque, 0, &mut walk, &mut sink);
    }
    if let Some(responses) = params_member(json, "inputResponses") {
        walk_json_scalars(responses, &KeyAttrs::NONE, None, 0, &mut walk, &mut sink);
    }
    if walk.truncated {
        out.truncated = true;
    }
    (
        out,
        CollectedLeaves {
            leaves,
            leaf_truncated: walk.truncated,
        },
    )
}

/// The classified walk's traversal — member-key attribute inheritance,
/// depth cap, and the leaf budget — emitting every string scalar in
/// visit order to `sink`, which returns `false` to abort traversal
/// early (e.g. its classify tripped the target budget).
///
/// `opaque` is the tool's `arguments { opaque }` matcher cursor,
/// descending member by member alongside `val`: a member name consumes
/// one declared segment, arrays stay transparent, and a scalar emits
/// `leaf_opaque = Some(index)` when its position reached a declared
/// (terminal) field. `None` disables the tracking entirely — the walk
/// then costs exactly what it did before the feature existed.
fn walk_json_scalars<'a>(
    val: nojson::RawJsonValue<'a, '_>,
    key_attrs: &KeyAttrs,
    opaque: Option<&OpaqueMatcher>,
    depth: u32,
    walk: &mut LeafWalk,
    sink: &mut impl FnMut(&KeyAttrs, Cow<'a, str>, Option<u32>) -> bool,
) {
    if depth > MAX_JSON_NESTING || walk.truncated || walk.done {
        return;
    }
    match val.kind() {
        nojson::JsonValueKind::Object => {
            if let Ok(obj) = val.to_object() {
                for (k, v) in obj {
                    if walk.truncated || walk.done {
                        return;
                    }
                    // Object members carry their own key vocabulary —
                    // the parent's attributes are inherited only
                    // through arrays and scalar leaves.
                    let member_name = k.to_unquoted_string_str().unwrap_or_default();
                    let member_attrs = if v.kind() == nojson::JsonValueKind::Object {
                        KeyAttrs::NONE
                    } else {
                        KeyAttrs::of(&member_name)
                    };
                    // The opaque cursor descends on the member name
                    // regardless of value kind — a declared path's
                    // intermediate members continue it. A terminal node
                    // marks its whole subtree: once reached, the cursor
                    // stays instead of consuming further segments.
                    let member_opaque = match opaque {
                        Some(c) if c.declaration().is_some() => Some(c),
                        Some(c) => c.child(member_name.as_ref()),
                        None => None,
                    };
                    walk_json_scalars(v, &member_attrs, member_opaque, depth + 1, walk, sink);
                }
            }
        }
        nojson::JsonValueKind::Array => {
            if let Ok(arr) = val.to_array() {
                for elem in arr {
                    if walk.truncated || walk.done {
                        return;
                    }
                    // Array elements carry the parent's opaque cursor —
                    // indices are not member names, so a declared path
                    // covers every element.
                    walk_json_scalars(elem, key_attrs, opaque, depth + 1, walk, sink);
                }
            }
        }
        _ => {
            walk.count += 1;
            if walk.count > MAX_INSPECTED_LEAVES {
                walk.truncated = true;
                return;
            }
            if let Ok(s) = val.to_unquoted_string_str()
                && !sink(key_attrs, s, opaque.and_then(|c| c.declaration()))
            {
                walk.done = true;
            }
        }
    }
}

/// Key-side classification attributes computed once per member and
/// shared across every leaf it governs — array elements included.
/// Each vocabulary test otherwise re-lowercased and re-matched the
/// same key per element; the value-dependent JSONPath exemption and
/// the shape tests still run per value.
#[derive(Clone, Copy)]
struct KeyAttrs {
    /// `is_exact_path_field_name(key)` — every value is a path.
    exact_path: bool,
    /// `is_suffixed_path_field_name(key)` — path unless the value
    /// spells a JSONPath expression.
    suffixed_path: bool,
    /// `is_network_field_name(key)`.
    network: bool,
    /// `is_known_payload_field_name(key)`.
    payload: bool,
    /// `host` / `hosts` / `hostname`, ASCII case-insensitive — the
    /// network-target branch's host-vs-URL call.
    host_named: bool,
}

impl KeyAttrs {
    /// All-false attributes — for a position with no governing key
    /// (`arguments` / `inputResponses` roots) and for a member whose
    /// value is an object: object members carry their own key
    /// vocabulary, so the parent's attributes are never consulted
    /// under one.
    const NONE: Self = Self {
        exact_path: false,
        suffixed_path: false,
        network: false,
        payload: false,
        host_named: false,
    };

    fn of(key: &str) -> Self {
        // One lowercase serves every vocabulary test — per value each
        // test re-lowercased the same key.
        let key_l = key.to_ascii_lowercase();
        Self {
            exact_path: crate::pathutil::is_exact_path_field_name_lowered(&key_l),
            suffixed_path: crate::pathutil::is_suffixed_path_field_name_lowered(key, &key_l),
            network: crate::pathutil::is_network_field_name_lowered(&key_l),
            payload: crate::pathutil::is_known_payload_field_name_lowered(&key_l),
            host_named: matches!(key_l.as_str(), "host" | "hosts" | "hostname"),
        }
    }

    /// `is_path_field_value(key, value)` with the name-side tests
    /// precomputed — only the value's JSONPath exemption is per value.
    fn is_path_value(&self, value: &str) -> bool {
        self.exact_path
            || (self.suffixed_path && !crate::pathutil::looks_like_jsonpath_expression(value))
    }
}

/// Inline-classify one emitted scalar — the single-consumer path
/// (`collect_argument_targets`, `extract_fs_targets`, host/URL
/// presence). Multi-consumer checks replay collected leaves through
/// [`classify_leaf`] instead; both reach the same predicate bodies.
/// `opaque` carries the index of the `arguments { opaque }` declaration
/// covering this leaf — only the `unclassified` fallback waives; every
/// target-shaped or secret-path classification still applies.
fn classify_target_string<S: TargetString>(
    key_attrs: &KeyAttrs,
    value: &str,
    opaque: Option<u32>,
    out: &mut ExtractedTargets<S>,
) {
    // A plain ASCII token carries no encoding the normalizer could
    // rewrite and no punctuation the shape tests could key on — skip
    // straight to the key-driven and overlay checks.
    if is_plain_ascii_token(value) {
        return classify_plain_token(key_attrs, value, opaque, out);
    }
    match crate::pathutil::normalize_fs_argument_cow(value) {
        Ok(normalized) => classify_normalized_value(key_attrs, value, &normalized, opaque, out),
        Err(_) => out.push(TargetSlot::Path, value),
    }
}

/// Replay one collected leaf through the classifier. The leaf carries
/// only pure parse/normalize results; every filesystem-dependent
/// predicate below (`is_secret_path_pre_normalized` resolves against
/// cwd/symlinks) is evaluated here, so a consumer sees the same
/// resolutions as an independent classified walk.
fn classify_leaf<S: TargetString>(leaf: &ScalarLeaf<'_>, out: &mut ExtractedTargets<S>) {
    match &leaf.norm {
        LeafNorm::Plain => classify_plain_token(&leaf.attrs, &leaf.raw, leaf.opaque, out),
        LeafNorm::Failed => out.push(TargetSlot::Path, &leaf.raw),
        LeafNorm::Normalized(normalized) => {
            classify_normalized_value(&leaf.attrs, &leaf.raw, normalized, leaf.opaque, out)
        }
    }
}

/// Printable-ASCII value carrying none of the selector punctuation
/// (`/` `\` `:` `~` `$` `%` `@` `.`) that [`crate::pathutil::selector_plausible`]
/// keys on. Such a token provably normalizes to itself — no `%` to
/// decode, no strippable control byte, no `:` to form a `file:` scheme,
/// and NFKC is the ASCII identity — and none of the value-shape tests
/// (`starts_with_file_scheme`, `looks_like_path`,
/// `looks_like_network_target`, `looks_like_host_or_socket`) can match
/// it, so classification reduces to the key vocabulary and the
/// secret-path overlay.
fn is_plain_ascii_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|b| {
            (0x20..=0x7E).contains(&b)
                && !matches!(b, b'/' | b'\\' | b':' | b'~' | b'$' | b'%' | b'@' | b'.')
        })
}

/// [`classify_target_string`] for values [`is_plain_ascii_token`]
/// cleared: normalization is the identity and every shape test is
/// provably false, so `normalized` is `value` itself and only the
/// key-driven checks and the secret-path overlay remain — applied in
/// the same order as the general path.
fn classify_plain_token<S: TargetString>(
    key_attrs: &KeyAttrs,
    value: &str,
    opaque: Option<u32>,
    out: &mut ExtractedTargets<S>,
) {
    if key_attrs.is_path_value(value) {
        out.push(TargetSlot::Path, value);
        return;
    }
    if key_attrs.network {
        // The general path's `://` / `//` and host-or-socket branches
        // are unreachable without `:` or a separator; `dns_name_shape`
        // makes the same host-vs-URL call it makes there.
        if crate::pathutil::dns_name_shape(value) {
            out.push(
                TargetSlot::Host,
                &crate::policy::canonicalize_policy_host(value),
            );
        } else {
            out.push(TargetSlot::Url, value);
        }
        return;
    }
    // Reserved secret spellings are filesystem targets under *any* key —
    // the overlay still runs on a plain token because resolution can
    // pull a `.ssh`/`etc` segment in from the cwd or a symlinked parent.
    // A plain token is its own `normalize_fs_argument` output, so the
    // pre-normalized entry applies.
    if crate::secret_paths::is_secret_path_pre_normalized(value) {
        out.push(TargetSlot::Path, value);
        return;
    }
    if key_attrs.payload {
        return;
    }
    if let Some(decl) = opaque {
        out.push_opaque(decl);
        return;
    }
    out.push(TargetSlot::Unclassified, value);
}

/// [`classify_leaf`] for a leaf whose `normalize_fs_argument` result is
/// `normalized` — the post-normalize predicate sequence, unchanged from
/// the inline classifier. It is replayed per consumer so the
/// filesystem-dependent verdicts are re-evaluated exactly as an
/// independent classified walk would evaluate them.
fn classify_normalized_value<S: TargetString>(
    key_attrs: &KeyAttrs,
    value: &str,
    normalized: &str,
    opaque: Option<u32>,
    out: &mut ExtractedTargets<S>,
) {
    if crate::pathutil::starts_with_file_scheme(normalized)
        || crate::pathutil::looks_like_path(normalized)
    {
        if normalized != value {
            out.push_noncanonical(value.to_string(), normalized.to_string());
        }
        out.push(TargetSlot::Path, normalized);
        return;
    }
    // URL-shaped values (including on path/target keys) are network targets.
    // Otherwise `path=https://…` would skip the read_only host/URL check.
    // `normalized` is already normalized — the normalized-input variant
    // skips the check's embedded decode round unless NFKC left a fresh
    // `%` escape behind (fullwidth `％`), where it keeps the second pass.
    if crate::pathutil::looks_like_network_target_normalized(normalized) {
        if key_attrs.host_named {
            out.push(
                TargetSlot::Host,
                &crate::policy::canonicalize_policy_host(normalized),
            );
        } else {
            out.push(TargetSlot::Url, value);
        }
        return;
    }
    // Unambiguous endpoint spellings are network targets under any key —
    // an IP literal, `[v6]:port`, or `host:port` under `dest`/
    // `destination`/`target` is an address, not a filename.
    if crate::pathutil::looks_like_host_or_socket(normalized) {
        out.push(
            TargetSlot::Host,
            &crate::policy::canonicalize_policy_host(normalized),
        );
        return;
    }
    if key_attrs.is_path_value(normalized) || crate::pathutil::looks_like_path(value) {
        if normalized != value {
            out.push_noncanonical(value.to_string(), normalized.to_string());
        }
        out.push(TargetSlot::Path, normalized);
        return;
    }
    if key_attrs.network {
        // `scheme://`/`//` spellings are URL arguments. A bare token on a
        // network field names a host (with or without a `:port` — the
        // evaluator folds the qualifier away), so it is checked as a
        // host rather than refused as a malformed URL. Anything else is
        // an unparseable selector and keeps the invalid-URL deny path.
        if value.contains("://") || value.starts_with("//") {
            out.push(TargetSlot::Url, value);
        } else if crate::pathutil::looks_like_host_or_socket(normalized)
            || crate::pathutil::dns_name_shape(normalized)
        {
            out.push(
                TargetSlot::Host,
                &crate::policy::canonicalize_policy_host(normalized),
            );
        } else {
            out.push(TargetSlot::Url, value);
        }
        return;
    }
    // Reserved secret spellings are filesystem targets under *any* key —
    // an unrecognized field name cannot hide `.env` or `.ssh/…` from the
    // overlay or an fs allow-list. `normalized` is already the
    // `normalize_fs_argument` output, so the pre-normalized entry is
    // used; the overlay still runs the value's own second decode round
    // for spellings where NFKC left a fresh `%` escape (fullwidth `％`).
    if crate::secret_paths::is_secret_path_pre_normalized(normalized) {
        out.push(TargetSlot::Path, normalized);
        return;
    }
    // Declared non-selector payload fields carry opaque content.
    if key_attrs.payload {
        return;
    }
    // A member declared `opaque` for this tool carries free-form text —
    // the declaration is what proves the value is not a selector, so it
    // stays out of the unclassified bucket. Every earlier branch still
    // ran: a resource-shaped or secret-path value classified above.
    if let Some(decl) = opaque {
        out.push_opaque(decl);
        return;
    }
    // A string under no recognized vocabulary cannot be proven a
    // non-selector — restricted callers refuse it rather than forward
    // an unchecked target.
    out.push(TargetSlot::Unclassified, normalized);
}

/// Pre-PR-03 argument classification, frozen for the differential test
/// in `tests::targets` — proves the plain-token fast path and the
/// shared normalization plumbing change no extracted-target outcome.
/// Bodies are verbatim HEAD except for module qualification, and they
/// call the `reference` (HEAD) normalization/overlay implementations
/// so the comparison is independent of every PR-03 code path. The
/// frozen bodies are the contract under test — an intentional
/// classification change must re-baseline them (or retire the
/// differential tests), never edit them to track the new behavior.
#[cfg(test)]
pub(crate) mod reference {
    use super::*;

    /// Same driver as [`collect_argument_targets`], classifying through
    /// the frozen HEAD body.
    pub(crate) fn collect<S: TargetString>(json: &nojson::RawJson<'_>) -> ExtractedTargets<S> {
        let mut out = ExtractedTargets::new();
        if let Some(args) = json
            .value()
            .to_member("params")
            .ok()
            .and_then(|m| m.optional())
            .and_then(|p| p.to_member("arguments").ok()?.optional())
        {
            walk(args, "", 0, &mut out);
        }
        if let Some(input_responses) = params_member(json, "inputResponses") {
            walk(input_responses, "", 0, &mut out);
        }
        out
    }

    fn walk<S: TargetString>(
        val: nojson::RawJsonValue<'_, '_>,
        key: &str,
        depth: u32,
        out: &mut ExtractedTargets<S>,
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
                        walk(v, &key_owned, depth + 1, out);
                    }
                }
            }
            nojson::JsonValueKind::Array => {
                if let Ok(arr) = val.to_array() {
                    for elem in arr {
                        if out.truncated {
                            return;
                        }
                        walk(elem, key, depth + 1, out);
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
                    classify_reference(key, s.as_ref(), out);
                }
            }
        }
    }

    /// Verbatim pre-PR-03 [`classify_normalized_value`].
    fn classify_reference<S: TargetString>(key: &str, value: &str, out: &mut ExtractedTargets<S>) {
        // Same Auditor-time normalize as overlay (bounded percent-decode +
        // WHATWG C0 strip + file: → path) so `file\t://` / `%66ile%0A://`
        // become paths.
        let normalized = match crate::pathutil::reference::normalize_fs_argument(value) {
            Ok(n) => n,
            Err(_) => {
                out.push(TargetSlot::Path, value);
                return;
            }
        };

        if crate::pathutil::starts_with_file_scheme(&normalized)
            || crate::pathutil::looks_like_path(&normalized)
        {
            if normalized != value {
                out.push_noncanonical(value.to_string(), normalized.clone());
            }
            out.push(TargetSlot::Path, &normalized);
            return;
        }
        // URL-shaped values (including on path/target keys) are network
        // targets. Otherwise `path=https://…` would skip the read_only
        // host/URL check.
        if crate::pathutil::reference::looks_like_network_target(&normalized) {
            let key_l = key.to_ascii_lowercase();
            if key_l == "host" || key_l == "hosts" || key_l == "hostname" {
                out.push(
                    TargetSlot::Host,
                    &crate::policy::canonicalize_policy_host(&normalized),
                );
            } else {
                out.push(TargetSlot::Url, value);
            }
            return;
        }
        // Unambiguous endpoint spellings are network targets under any
        // key — an IP literal, `[v6]:port`, or `host:port` under
        // `dest`/`destination`/`target` is an address, not a filename.
        if crate::pathutil::looks_like_host_or_socket(&normalized) {
            out.push(
                TargetSlot::Host,
                &crate::policy::canonicalize_policy_host(&normalized),
            );
            return;
        }
        if crate::pathutil::is_path_field_value(key, &normalized)
            || crate::pathutil::looks_like_path(value)
        {
            if normalized != value {
                out.push_noncanonical(value.to_string(), normalized.clone());
            }
            out.push(TargetSlot::Path, &normalized);
            return;
        }
        if crate::pathutil::is_network_field_name(key) {
            // `scheme://`/`//` spellings are URL arguments. A bare token
            // on a network field names a host (with or without a `:port`
            // — the evaluator folds the qualifier away), so it is
            // checked as a host rather than refused as a malformed URL.
            // Anything else is an unparseable selector and keeps the
            // invalid-URL deny path.
            if value.contains("://") || value.starts_with("//") {
                out.push(TargetSlot::Url, value);
            } else if crate::pathutil::looks_like_host_or_socket(&normalized)
                || crate::pathutil::dns_name_shape(&normalized)
            {
                out.push(
                    TargetSlot::Host,
                    &crate::policy::canonicalize_policy_host(&normalized),
                );
            } else {
                out.push(TargetSlot::Url, value);
            }
            return;
        }
        // Reserved secret spellings are filesystem targets under *any*
        // key — an unrecognized field name cannot hide `.env` or
        // `.ssh/…` from the overlay or an fs allow-list.
        if crate::secret_paths::reference::is_secret_path(&normalized) {
            out.push(TargetSlot::Path, &normalized);
            return;
        }
        // Declared non-selector payload fields carry opaque content.
        if crate::pathutil::is_known_payload_field_name(key) {
            return;
        }
        // A string under no recognized vocabulary cannot be proven a
        // non-selector — restricted callers refuse it rather than
        // forward an unchecked target.
        out.push(TargetSlot::Unclassified, &normalized);
    }
}
