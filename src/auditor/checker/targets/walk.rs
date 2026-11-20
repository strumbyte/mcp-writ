//! The classified-walk engine behind `targets`: member-key attribute
//! inheritance, the scalar-leaf budget, opaque-cursor descent, and the
//! per-consumer classification of emitted scalars.

use std::borrow::Cow;

use super::super::{MAX_JSON_NESTING, params_member};
use super::{ExtractedTargets, MAX_INSPECTED_LEAVES, TargetSlot, TargetString};
use crate::policy::opaque::OpaqueMatcher;

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
    /// Build a leaf's pure parse/normalize outcome: a plain ASCII
    /// token stays [`LeafNorm::Plain`]; anything else runs
    /// `normalize_fs_argument_cow` once here so every consumer replays
    /// the result instead of re-normalizing. `opaque` is the index of
    /// the `arguments { opaque }` declaration covering this leaf, when
    /// the walk found one.
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
pub(super) struct LeafWalk {
    count: usize,
    pub(super) truncated: bool,
    done: bool,
}

/// Shared scalar-leaf prefix collected *during* the first combined
/// classify — the `fs_targets` shape and the closed-contract check
/// replay it, so the frame is parsed and normalized once. Only leaves
/// the classify actually reached are stored: the sink aborts the walk
/// with the first consumer's target budget, so a denied frame never
/// normalizes or retains its tail.
pub(in crate::auditor::checker) struct CollectedLeaves<'a> {
    leaves: Vec<ScalarLeaf<'a>>,
    /// The collection stopped before the scalar set ran out — either
    /// the shared leaf budget or the first classify's own target
    /// budget tripped — so the stored leaves are a strict prefix.
    leaf_truncated: bool,
}

impl CollectedLeaves<'_> {
    /// Freshly classify the collected prefix — the same leaf sequence
    /// the first consumer saw. Filesystem-dependent verdicts are
    /// re-evaluated per call, exactly as an independent walk would.
    pub(super) fn classify<S: TargetString>(&self) -> ExtractedTargets<S> {
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
    pub(in crate::auditor::checker) fn collected_len(&self) -> usize {
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
pub(in crate::auditor::checker) fn walk_combined_classified<'a, S: TargetString>(
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
    // The merged cutoff — a classify-side budget trip aborts the walk
    // via `done` without setting `walk.truncated`, yet the stored
    // leaves are still a strict prefix of the real scalar set, so
    // replays must propagate truncated.
    let leaf_truncated = out.truncated;
    (
        out,
        CollectedLeaves {
            leaves,
            leaf_truncated,
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
pub(super) fn walk_json_scalars<'a>(
    val: nojson::RawJsonValue<'a, '_>,
    key_attrs: &KeyAttrs,
    opaque: Option<&OpaqueMatcher>,
    depth: u32,
    walk: &mut LeafWalk,
    sink: &mut impl FnMut(&KeyAttrs, Cow<'a, str>, Option<u32>) -> bool,
) {
    if depth > MAX_JSON_NESTING {
        // The subtree below the cap is unchecked — mark the walk
        // incomplete so consumers treat its target set as a strict
        // prefix (fail-closed) rather than proof of absence. Verified
        // frames never reach this: the duplicate-key walk bounds the
        // same nesting before any consumer runs. Standalone `RawJson`
        // input (parse accepts 128 levels) can.
        walk.truncated = true;
        return;
    }
    if walk.truncated || walk.done {
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
pub(super) struct KeyAttrs {
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
    pub(super) const NONE: Self = Self {
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
pub(super) fn classify_target_string<S: TargetString>(
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
